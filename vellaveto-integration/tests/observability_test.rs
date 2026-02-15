//! Integration tests for observability exporters, trace context, and redaction behavior.

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use serde_json::{json, Value};
use std::{collections::HashMap, io::Read, sync::Arc, time::Duration};
use tokio::{
    sync::{oneshot, Mutex},
    time::timeout,
};
use vellaveto_audit::observability::{
    arize::{ArizeExporter, ArizeExporterConfig},
    helicone::{HeliconeExporter, HeliconeExporterConfig},
    langfuse::{LangfuseExporter, LangfuseExporterConfig},
    webhook::{WebhookExporter, WebhookExporterConfig},
    ActionSummary, DetectionType, ObservabilityError, ObservabilityExporter, RedactionConfig,
    SamplingConfig, SecurityDetection, SecuritySpan, SpanKind, SpanSampler, TraceContext,
    VerdictSummary,
};
use vellaveto_config::ObservabilityConfig;

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct CaptureState {
    sender: Arc<Mutex<Option<oneshot::Sender<CapturedRequest>>>>,
}

async fn capture_request(
    State(state): State<CaptureState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024).await.unwrap_or_default();

    let headers = parts
        .headers
        .iter()
        .map(|(key, value)| {
            (
                key.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<HashMap<_, _>>();

    if let Some(sender) = state.sender.lock().await.take() {
        let _ = sender.send(CapturedRequest {
            method: parts.method.as_str().to_string(),
            path: parts.uri.path().to_string(),
            headers,
            body: body.to_vec(),
        });
    }

    StatusCode::OK
}

async fn spawn_capture_server() -> (
    String,
    oneshot::Receiver<CapturedRequest>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind capture server");
    let address = listener.local_addr().expect("capture server local addr");
    let (sender, receiver) = oneshot::channel();

    let state = CaptureState {
        sender: Arc::new(Mutex::new(Some(sender))),
    };
    let app = Router::new()
        .fallback(any(capture_request))
        .with_state(state);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}", address), receiver, handle)
}

#[derive(Clone)]
struct PlannedResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    delay: Option<Duration>,
}

impl PlannedResponse {
    fn ok() -> Self {
        Self {
            status: StatusCode::OK,
            headers: Vec::new(),
            delay: None,
        }
    }
}

#[derive(Clone)]
struct PlannedCaptureState {
    expected_requests: usize,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    sender: Arc<Mutex<Option<oneshot::Sender<Vec<CapturedRequest>>>>>,
    responses: Arc<Vec<PlannedResponse>>,
}

async fn capture_planned_request(
    State(state): State<PlannedCaptureState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024).await.unwrap_or_default();

    let headers = parts
        .headers
        .iter()
        .map(|(key, value)| {
            (
                key.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<HashMap<_, _>>();

    let captured = CapturedRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        headers,
        body: body.to_vec(),
    };

    let (index, maybe_complete) = {
        let mut requests = state.requests.lock().await;
        let index = requests.len();
        requests.push(captured);
        let completed = if requests.len() == state.expected_requests {
            Some(requests.clone())
        } else {
            None
        };
        (index, completed)
    };

    if let Some(completed) = maybe_complete {
        if let Some(sender) = state.sender.lock().await.take() {
            let _ = sender.send(completed);
        }
    }

    let plan = state
        .responses
        .get(index)
        .cloned()
        .or_else(|| state.responses.last().cloned())
        .unwrap_or_else(PlannedResponse::ok);

    if let Some(delay) = plan.delay {
        tokio::time::sleep(delay).await;
    }

    let mut response = axum::response::Response::builder().status(plan.status);
    for (key, value) in &plan.headers {
        response = response.header(key, value);
    }
    response
        .body(Body::from("ok"))
        .expect("planned response body")
}

async fn spawn_planned_capture_server(
    expected_requests: usize,
    responses: Vec<PlannedResponse>,
) -> (
    String,
    oneshot::Receiver<Vec<CapturedRequest>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind planned capture server");
    let address = listener.local_addr().expect("planned capture local addr");
    let (sender, receiver) = oneshot::channel();

    let state = PlannedCaptureState {
        expected_requests,
        requests: Arc::new(Mutex::new(Vec::with_capacity(expected_requests.max(1)))),
        sender: Arc::new(Mutex::new(Some(sender))),
        responses: Arc::new(responses),
    };

    let app = Router::new()
        .fallback(any(capture_planned_request))
        .with_state(state);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}", address), receiver, handle)
}

fn sample_span() -> SecuritySpan {
    let mut attributes = HashMap::new();
    attributes.insert("session_id".to_string(), json!("sess-123"));

    SecuritySpan {
        span_id: "b7ad6b7169203331".to_string(),
        parent_span_id: None,
        trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
        span_kind: SpanKind::Tool,
        name: "policy_evaluation".to_string(),
        start_time: "2024-01-01T00:00:00Z".to_string(),
        end_time: "2024-01-01T00:00:00.250Z".to_string(),
        duration_ms: 250,
        action: ActionSummary {
            tool: "filesystem".to_string(),
            function: "read_file".to_string(),
            target_paths: vec!["/etc/shadow".to_string()],
            target_domains: vec![],
            parameter_count: 2,
            agent_id: Some("agent-1".to_string()),
        },
        verdict: VerdictSummary {
            outcome: "deny".to_string(),
            reason: Some("blocked sensitive file".to_string()),
        },
        matched_policy: Some("block-sensitive-files".to_string()),
        detections: vec![
            SecurityDetection::new(DetectionType::Dlp, 8, "secret detected")
                .with_pattern("sk-[a-zA-Z0-9]+"),
        ],
        request_body: Some(json!({"path": "/etc/shadow", "token": "secret"})),
        response_body: Some(json!({"error": "denied"})),
        attributes,
    }
}

fn sample_spans(count: usize) -> Vec<SecuritySpan> {
    (0..count)
        .map(|i| {
            let mut span = sample_span();
            let value = i as u128 + 1;
            span.trace_id = format!("{:032x}", value);
            span.span_id = format!("{:016x}", value as u64);
            span
        })
        .collect()
}

#[tokio::test]
async fn test_langfuse_exporter_serialization() {
    let (base_url, receiver, server_handle) = spawn_capture_server().await;

    let config = LangfuseExporterConfig::new(base_url, "pk-test", "sk-test");
    let exporter = LangfuseExporter::new(config).expect("langfuse exporter");

    exporter
        .export_batch(&[sample_span()])
        .await
        .expect("export langfuse span");

    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for captured request")
        .expect("capture channel closed");
    server_handle.abort();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/public/ingestion");
    assert!(request
        .headers
        .get("authorization")
        .is_some_and(|v| v.starts_with("Basic ")));

    let payload: Value = serde_json::from_slice(&request.body).expect("langfuse JSON payload");
    let events = payload["batch"].as_array().expect("batch must be an array");
    assert_eq!(events.len(), 2);

    let trace_event = events
        .iter()
        .find(|event| event["type"] == "trace-create")
        .expect("trace-create event");
    assert_eq!(
        trace_event["body"]["id"],
        "0af7651916cd43dd8448eb211c80319c"
    );

    let observation_event = events
        .iter()
        .find(|event| event["type"] == "observation-create")
        .expect("observation-create event");
    assert_eq!(
        observation_event["body"]["traceId"],
        "0af7651916cd43dd8448eb211c80319c"
    );
    assert_eq!(observation_event["body"]["name"], "policy_evaluation");
    assert_eq!(observation_event["body"]["type"], "SPAN");
}

#[tokio::test]
async fn test_arize_otlp_format() {
    let (base_url, receiver, server_handle) = spawn_capture_server().await;

    let config = ArizeExporterConfig::new(base_url, "space-123", "api-456");
    let exporter = ArizeExporter::new(config).expect("arize exporter");

    exporter
        .export_batch(&[sample_span()])
        .await
        .expect("export arize span");

    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for captured request")
        .expect("capture channel closed");
    server_handle.abort();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/traces");
    assert_eq!(
        request.headers.get("space_key").map(String::as_str),
        Some("space-123")
    );
    assert_eq!(
        request.headers.get("api_key").map(String::as_str),
        Some("api-456")
    );

    let payload: Value = serde_json::from_slice(&request.body).expect("arize JSON payload");
    let resource_spans = payload["resourceSpans"]
        .as_array()
        .expect("resourceSpans array");
    assert_eq!(resource_spans.len(), 1);

    let spans = resource_spans[0]["scopeSpans"][0]["spans"]
        .as_array()
        .expect("spans array");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0]["name"], "policy_evaluation");
    assert!(spans[0]["traceId"].is_string());

    let attributes = spans[0]["attributes"].as_array().expect("attributes array");
    let has_verdict = attributes
        .iter()
        .any(|attr| attr["key"] == "vellaveto.verdict");
    let has_kind = attributes
        .iter()
        .any(|attr| attr["key"] == "openinference.span.kind");
    assert!(has_verdict);
    assert!(has_kind);
}

#[tokio::test]
async fn test_helicone_log_format() {
    let (base_url, receiver, server_handle) = spawn_capture_server().await;

    let config = HeliconeExporterConfig::new(format!("{}/v1/log", base_url), "helicone-key");
    let exporter = HeliconeExporter::new(config).expect("helicone exporter");

    exporter
        .export_batch(&[sample_span()])
        .await
        .expect("export helicone span");

    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for captured request")
        .expect("capture channel closed");
    server_handle.abort();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/log");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer helicone-key")
    );

    let payload: Value = serde_json::from_slice(&request.body).expect("helicone JSON payload");
    let logs = payload["logs"].as_array().expect("logs array");
    assert_eq!(logs.len(), 1);

    let log = &logs[0];
    assert_eq!(log["traceId"], "0af7651916cd43dd8448eb211c80319c");
    assert_eq!(log["status"], "error");
    assert_eq!(log["properties"]["vellaveto_tool"], "filesystem");
}

#[tokio::test]
async fn test_webhook_gzip_compression() {
    let (base_url, receiver, server_handle) = spawn_capture_server().await;

    let config = WebhookExporterConfig::new(format!("{}/webhook", base_url)).with_compression(true);
    let exporter = WebhookExporter::new(config).expect("webhook exporter");

    let spans = vec![sample_span(), sample_span()];
    exporter
        .export_batch(&spans)
        .await
        .expect("export webhook spans");

    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for captured request")
        .expect("capture channel closed");
    server_handle.abort();

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/webhook");
    assert_eq!(
        request.headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );

    let mut decoder = flate2::read::GzDecoder::new(request.body.as_slice());
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("decompress gzip payload");

    let payload: Value =
        serde_json::from_slice(&decompressed).expect("decoded webhook payload must be JSON");
    assert_eq!(payload["spans"].as_array().expect("spans array").len(), 2);
}

#[tokio::test]
async fn test_export_batch_various_span_counts() {
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        3,
        vec![
            PlannedResponse::ok(),
            PlannedResponse::ok(),
            PlannedResponse::ok(),
        ],
    )
    .await;

    let mut config = WebhookExporterConfig::new(format!("{}/webhook", base_url))
        .with_compression(false)
        .with_auth("Bearer test");
    config.common.batch_size = 500;

    let exporter = WebhookExporter::new(config).expect("webhook exporter");
    for count in [1usize, 10, 100] {
        exporter
            .export_batch(&sample_spans(count))
            .await
            .expect("webhook export_batch");
    }

    let requests = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for 3 captured requests")
        .expect("capture channel closed");
    server_handle.abort();

    let observed_counts = requests
        .iter()
        .map(|request| {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/webhook");
            let payload: Value = serde_json::from_slice(&request.body).expect("webhook payload");
            payload["spans"].as_array().expect("spans array").len()
        })
        .collect::<Vec<_>>();
    assert_eq!(observed_counts, vec![1, 10, 100]);
}

#[tokio::test]
async fn test_health_check_failures_propagate_auth_errors() {
    // Langfuse
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        1,
        vec![PlannedResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            delay: None,
        }],
    )
    .await;
    let exporter =
        LangfuseExporter::new(LangfuseExporterConfig::new(base_url, "pk-test", "sk-test"))
            .expect("langfuse exporter");
    let result = exporter.health_check().await;
    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("langfuse health_check request timeout")
        .expect("langfuse capture channel closed");
    server_handle.abort();
    assert_eq!(request[0].path, "/api/public/ingestion");
    assert!(matches!(result, Err(ObservabilityError::AuthError(_))));

    // Arize
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        1,
        vec![PlannedResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            delay: None,
        }],
    )
    .await;
    let exporter = ArizeExporter::new(ArizeExporterConfig::new(base_url, "space", "api"))
        .expect("arize exporter");
    let result = exporter.health_check().await;
    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("arize health_check request timeout")
        .expect("arize capture channel closed");
    server_handle.abort();
    assert_eq!(request[0].path, "/v1/traces");
    assert!(matches!(result, Err(ObservabilityError::AuthError(_))));

    // Helicone
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        1,
        vec![PlannedResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            delay: None,
        }],
    )
    .await;
    let exporter = HeliconeExporter::new(HeliconeExporterConfig::new(
        format!("{}/v1/log", base_url),
        "helicone-key",
    ))
    .expect("helicone exporter");
    let result = exporter.health_check().await;
    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("helicone health_check request timeout")
        .expect("helicone capture channel closed");
    server_handle.abort();
    assert_eq!(request[0].path, "/v1/log");
    assert!(matches!(result, Err(ObservabilityError::AuthError(_))));

    // Webhook
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        1,
        vec![PlannedResponse {
            status: StatusCode::UNAUTHORIZED,
            headers: Vec::new(),
            delay: None,
        }],
    )
    .await;
    let exporter =
        WebhookExporter::new(WebhookExporterConfig::new(format!("{}/webhook", base_url)))
            .expect("webhook exporter");
    let result = exporter.health_check().await;
    let request = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("webhook health_check request timeout")
        .expect("webhook capture channel closed");
    server_handle.abort();
    assert_eq!(request[0].path, "/webhook");
    assert!(matches!(result, Err(ObservabilityError::AuthError(_))));
}

#[tokio::test]
async fn test_export_retry_on_rate_limit() {
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        2,
        vec![
            PlannedResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                headers: vec![("retry-after".to_string(), "0".to_string())],
                delay: None,
            },
            PlannedResponse::ok(),
        ],
    )
    .await;

    let mut config = LangfuseExporterConfig::new(base_url, "pk-test", "sk-test");
    config.common.max_retries = 1;
    config.common.retry_backoff_secs = 0;

    let exporter = LangfuseExporter::new(config).expect("langfuse exporter");
    exporter
        .export_batch(&sample_spans(1))
        .await
        .expect("langfuse retry should succeed");

    let requests = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for retry requests")
        .expect("retry capture channel closed");
    server_handle.abort();

    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.path == "/api/public/ingestion"));
}

#[tokio::test]
async fn test_concurrent_batch_chunk_processing() {
    let concurrent_calls = 4usize;
    let spans_per_call = 25usize;
    let batch_size = 10usize;
    let expected_requests = concurrent_calls * spans_per_call.div_ceil(batch_size);

    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        expected_requests,
        vec![PlannedResponse::ok(); expected_requests],
    )
    .await;

    let mut config = WebhookExporterConfig::new(format!("{}/webhook", base_url))
        .with_compression(false)
        .with_auth("Bearer concurrent");
    config.common.batch_size = batch_size;
    let exporter = Arc::new(WebhookExporter::new(config).expect("webhook exporter"));

    let mut tasks = Vec::new();
    for _ in 0..concurrent_calls {
        let exporter = Arc::clone(&exporter);
        tasks.push(tokio::spawn(async move {
            exporter
                .export_batch(&sample_spans(spans_per_call))
                .await
                .expect("concurrent webhook export");
        }));
    }
    for task in tasks {
        task.await.expect("task join");
    }

    let requests = timeout(Duration::from_secs(5), receiver)
        .await
        .expect("timed out waiting for chunked requests")
        .expect("chunked capture channel closed");
    server_handle.abort();

    assert_eq!(requests.len(), expected_requests);
    for request in requests {
        let payload: Value = serde_json::from_slice(&request.body).expect("webhook payload");
        let batch_size = payload["metadata"]["batch_size"]
            .as_u64()
            .expect("metadata.batch_size") as usize;
        assert!((1..=10).contains(&batch_size));
    }
}

#[tokio::test]
async fn test_export_timeout_on_slow_endpoint() {
    let (base_url, receiver, server_handle) = spawn_planned_capture_server(
        1,
        vec![PlannedResponse {
            status: StatusCode::OK,
            headers: Vec::new(),
            delay: Some(Duration::from_secs(2)),
        }],
    )
    .await;

    let mut config = WebhookExporterConfig::new(format!("{}/webhook", base_url))
        .with_compression(false)
        .with_auth("Bearer timeout");
    config.common.timeout_secs = 1;
    let exporter = WebhookExporter::new(config).expect("webhook exporter");

    let result = exporter.export_batch(&sample_spans(1)).await;
    assert!(matches!(result, Err(ObservabilityError::HttpError(_))));

    let _ = timeout(Duration::from_secs(3), receiver)
        .await
        .expect("timed out waiting for slow request capture")
        .expect("slow capture channel closed");
    server_handle.abort();
}

#[test]
fn test_span_sampler_deterministic() {
    let sampler = SpanSampler::new(SamplingConfig {
        sample_rate: 0.45,
        always_sample_denies: false,
        always_sample_detections: false,
        ..SamplingConfig::default()
    });

    let span_a = SecuritySpan::builder("trace-deterministic", SpanKind::Tool)
        .span_id("1111111111111111")
        .action(ActionSummary::new("tool", "fn"))
        .verdict(VerdictSummary {
            outcome: "allow".to_string(),
            reason: None,
        })
        .build()
        .expect("span a");

    let span_b = SecuritySpan::builder("trace-deterministic", SpanKind::Guardrail)
        .span_id("2222222222222222")
        .action(ActionSummary::new("tool", "fn"))
        .verdict(VerdictSummary {
            outcome: "allow".to_string(),
            reason: None,
        })
        .build()
        .expect("span b");

    assert_eq!(
        sampler.should_sample(&span_a),
        sampler.should_sample(&span_b)
    );
}

#[test]
fn test_trace_context_propagation() {
    let input = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let context = TraceContext::parse_traceparent(input)
        .expect("traceparent should parse")
        .with_tracestate("vendor=value");

    assert!(context.is_sampled());

    let round_trip = context
        .to_traceparent()
        .expect("traceparent round-trip output");
    assert_eq!(round_trip, input);

    let reparsed =
        TraceContext::parse_traceparent(&round_trip).expect("round-tripped traceparent parses");
    assert_eq!(reparsed.trace_id, context.trace_id);
    assert_eq!(reparsed.parent_span_id, context.parent_span_id);
}

#[test]
fn test_redaction_recursive() {
    let config = RedactionConfig {
        redacted_fields: vec!["secret".to_string(), "token".to_string()],
        ..RedactionConfig::default()
    };

    let input = json!({
        "safe": "keep",
        "nested": {
            "secret_value": "should-hide",
            "array": [
                {"api_token": "abc"},
                {"normal": "ok"}
            ]
        }
    });

    let redacted = config.redact(&input);
    assert_eq!(redacted["safe"], "keep");
    assert_eq!(redacted["nested"]["secret_value"], "[REDACTED]");
    assert_eq!(redacted["nested"]["array"][0]["api_token"], "[REDACTED]");
    assert_eq!(redacted["nested"]["array"][1]["normal"], "ok");
}

#[test]
fn test_observability_config_validation() {
    let mut config = ObservabilityConfig {
        enabled: true,
        sample_rate: 1.25,
        ..ObservabilityConfig::default()
    };

    let err = config
        .validate()
        .expect_err("sample_rate outside range must fail validation");
    assert!(err.contains("sample_rate"));

    config.sample_rate = 0.5;
    config.webhook.enabled = true;
    config.webhook.endpoint = "https://localhost/webhook".to_string();

    let err = config
        .validate()
        .expect_err("localhost webhook must fail SSRF validation");
    assert!(err.contains("must not target localhost"));

    config.webhook.endpoint = "https://example.com/webhook".to_string();
    assert!(config.validate().is_ok());
}
