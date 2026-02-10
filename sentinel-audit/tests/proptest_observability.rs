use proptest::prelude::*;
use sentinel_audit::observability::{
    ActionSummary, SamplingConfig, SecuritySpan, SpanKind, SpanSampler, TraceContext,
    VerdictSummary,
};

fn hex_string(len: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!("[0-9a-f]{{{}}}", len)).expect("valid regex")
}

fn low_ascii_string(max_len: usize) -> impl Strategy<Value = String> {
    prop::string::string_regex(&format!(
        "[a-z_][a-z0-9_]{{0,{}}}",
        max_len.saturating_sub(1)
    ))
    .expect("valid regex")
}

fn make_allow_span(
    trace_id: String,
    span_id: String,
    tool: String,
    function: String,
) -> SecuritySpan {
    SecuritySpan {
        span_id,
        parent_span_id: None,
        trace_id,
        span_kind: SpanKind::Tool,
        name: "policy_evaluation".to_string(),
        start_time: "2024-01-01T00:00:00Z".to_string(),
        end_time: "2024-01-01T00:00:00.010Z".to_string(),
        duration_ms: 10,
        action: ActionSummary {
            tool,
            function,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            parameter_count: 0,
            agent_id: None,
        },
        verdict: VerdictSummary {
            outcome: "allow".to_string(),
            reason: None,
        },
        matched_policy: None,
        detections: Vec::new(),
        request_body: None,
        response_body: None,
        attributes: std::collections::HashMap::new(),
    }
}

proptest! {
    #[test]
    fn test_security_span_round_trip_preserves_core_fields(
        trace_id in hex_string(32),
        span_id in hex_string(16),
        tool in low_ascii_string(16),
        function in low_ascii_string(16),
        duration_ms in 0u64..10_000,
    ) {
        let mut span = make_allow_span(trace_id.clone(), span_id.clone(), tool.clone(), function.clone());
        span.duration_ms = duration_ms;

        let serialized = serde_json::to_string(&span).expect("serialize span");
        let decoded: SecuritySpan = serde_json::from_str(&serialized).expect("deserialize span");

        prop_assert_eq!(decoded.trace_id, trace_id);
        prop_assert_eq!(decoded.span_id, span_id);
        prop_assert_eq!(decoded.action.tool, tool);
        prop_assert_eq!(decoded.action.function, function);
        prop_assert_eq!(decoded.duration_ms, duration_ms);
        prop_assert_eq!(decoded.verdict.outcome, "allow");
    }

    #[test]
    fn test_sampler_is_deterministic_for_same_trace_id(
        trace_id in low_ascii_string(32),
        sample_rate in 0.0f64..1.0f64,
        tool in low_ascii_string(16),
        function in low_ascii_string(16),
    ) {
        let sampler = SpanSampler::new(SamplingConfig {
            sample_rate,
            always_sample_denies: false,
            always_sample_detections: false,
            ..SamplingConfig::default()
        });

        let span_a = make_allow_span(
            trace_id.clone(),
            "aaaaaaaaaaaaaaaa".to_string(),
            tool.clone(),
            function.clone(),
        );
        let span_b = make_allow_span(
            trace_id,
            "bbbbbbbbbbbbbbbb".to_string(),
            tool,
            function,
        );

        prop_assert_eq!(sampler.should_sample(&span_a), sampler.should_sample(&span_b));
    }

    #[test]
    fn test_trace_context_round_trip_preserves_valid_traceparent(
        trace_id in hex_string(32),
        parent_span_id in hex_string(16),
        trace_flags in any::<u8>(),
    ) {
        let traceparent = format!("00-{}-{}-{:02x}", trace_id, parent_span_id, trace_flags);
        let parsed = TraceContext::parse_traceparent(&traceparent);
        prop_assert!(parsed.is_some());
        let parsed = parsed.expect("valid traceparent");

        prop_assert_eq!(parsed.trace_id.as_deref(), Some(trace_id.as_str()));
        prop_assert_eq!(parsed.parent_span_id.as_deref(), Some(parent_span_id.as_str()));
        prop_assert_eq!(parsed.trace_flags, trace_flags);

        let round_trip = parsed.to_traceparent();
        prop_assert!(round_trip.is_some());
        let round_trip = round_trip.expect("traceparent formatting");
        prop_assert_eq!(round_trip.as_str(), traceparent.as_str());

        let reparsed = TraceContext::parse_traceparent(&round_trip);
        prop_assert!(reparsed.is_some());
        let reparsed = reparsed.expect("traceparent parse after round trip");

        prop_assert_eq!(reparsed.trace_id.as_deref(), Some(trace_id.as_str()));
        prop_assert_eq!(reparsed.parent_span_id.as_deref(), Some(parent_span_id.as_str()));
        prop_assert_eq!(reparsed.trace_flags, trace_flags);
    }
}
