//! Sentinel MCP HTTP Proxy — Streamable HTTP reverse proxy.
//!
//! This binary runs an HTTP reverse proxy that sits between MCP clients and
//! an upstream MCP server. It intercepts JSON-RPC messages over the Streamable
//! HTTP transport, evaluates tool calls against loaded policies, and forwards
//! allowed requests.

use anyhow::{Context, Result};
use axum::{
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use clap::Parser;
use governor::{Quota, RateLimiter};
use sentinel_audit::AuditLogger;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_http_proxy::oauth::{OAuthConfig, OAuthValidator};
use sentinel_http_proxy::proxy::{self, ProxyState};
use sentinel_http_proxy::session::SessionStore;
use sentinel_mcp::output_validation::OutputSchemaRegistry;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "sentinel-http-proxy",
    about = "Sentinel MCP Streamable HTTP reverse proxy"
)]
struct Args {
    /// Upstream MCP server URL (e.g., http://localhost:8000/mcp)
    #[arg(long)]
    upstream: String,

    /// Listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:3001")]
    listen: String,

    /// Policy config file path (JSON or TOML)
    #[arg(short, long)]
    config: String,

    /// Audit log file path
    #[arg(long, default_value = "audit.log")]
    audit_log: String,

    /// Session timeout in seconds
    #[arg(long, default_value_t = 1800)]
    session_timeout: u64,

    /// Maximum concurrent sessions
    #[arg(long, default_value_t = 1000)]
    max_sessions: usize,

    /// Strict policy evaluation mode
    #[arg(long)]
    strict: bool,

    /// OAuth 2.1 issuer URL (enables OAuth token validation)
    #[arg(long)]
    oauth_issuer: Option<String>,

    /// OAuth 2.1 expected audience claim
    #[arg(long, default_value = "mcp-server")]
    oauth_audience: String,

    /// OAuth 2.1 JWKS endpoint URL (defaults to {issuer}/.well-known/jwks.json)
    #[arg(long)]
    oauth_jwks_uri: Option<String>,

    /// Required OAuth scopes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    oauth_scopes: Vec<String>,

    /// Forward the OAuth Bearer token to the upstream MCP server
    #[arg(long)]
    oauth_pass_through: bool,

    /// Expected RFC 8707 resource indicator for OAuth token validation.
    /// When set, JWT tokens must contain a matching `resource` claim.
    #[arg(long)]
    oauth_expected_resource: Option<String>,

    /// Allow starting without SENTINEL_API_KEY (unauthenticated mode).
    /// WARNING: All MCP endpoints will have no access control beyond OAuth (if configured).
    #[arg(long, default_value_t = false)]
    allow_anonymous: bool,

    /// Absolute session lifetime in seconds. Sessions older than this are
    /// expired regardless of activity. 0 = no absolute limit (default: 86400 = 24h).
    #[arg(long, default_value_t = 86400)]
    session_max_lifetime: u64,

    /// Disable re-serialization of JSON-RPC messages before forwarding to upstream.
    /// By default, messages are re-serialized (canonicalized) to close the TOCTOU gap
    /// where the proxy evaluates a parsed representation but forwards original bytes.
    /// Use --no-canonicalize only if upstream requires exact byte-for-byte forwarding.
    #[arg(long)]
    no_canonicalize: bool,

    /// Maximum requests per second (global rate limit). 0 = no limit.
    #[arg(long, default_value_t = 200)]
    rate_limit: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // SECURITY: Warn if upstream does not use TLS
    if args.upstream.starts_with("http://") {
        tracing::warn!(
            "SECURITY: Upstream URL uses plaintext HTTP ({}). \
             Tool-call payloads and credentials will be transmitted unencrypted. \
             Use https:// in production.",
            args.upstream
        );
    }

    // Load and compile policies
    let policy_config = PolicyConfig::load_file(&args.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), args.config);

    let engine = match PolicyEngine::with_policies(args.strict, &policies) {
        Ok(mut engine) => {
            if let Some(max_iter) = policy_config.max_path_decode_iterations {
                engine.set_max_path_decode_iterations(max_iter);
                tracing::info!(
                    max_path_decode_iterations = max_iter,
                    "custom path decode iteration limit"
                );
            }
            tracing::info!(
                "Compiled {} policies (pre-compiled evaluation path active)",
                policies.len()
            );
            engine
        }
        Err(errors) => {
            for err in &errors {
                tracing::error!("Policy compilation error: {}", err);
            }
            anyhow::bail!(
                "Failed to compile {} policies — fix config and retry",
                errors.len()
            );
        }
    };

    // Exploit #7 fix: require SENTINEL_API_KEY unless --allow-anonymous is set.
    // Matches the pattern from sentinel-server — a security product must not ship
    // with zero access control by default.
    let api_key = std::env::var("SENTINEL_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(Arc::new);

    if api_key.is_some() {
        tracing::info!("API key authentication enabled for MCP endpoints");
    } else if args.allow_anonymous {
        tracing::warn!(
            "No SENTINEL_API_KEY set and --allow-anonymous specified — MCP endpoints are UNAUTHENTICATED"
        );
    } else {
        anyhow::bail!(
            "SENTINEL_API_KEY environment variable is required.\n\
             Set it to enable authentication for MCP endpoints, or pass \
             --allow-anonymous to explicitly opt in to unauthenticated mode.\n\
             Example: SENTINEL_API_KEY=your-secret-key sentinel-http-proxy --upstream http://localhost:8000/mcp --config policy.toml"
        );
    }

    // FIND-015: Load HMAC key for call chain signing/verification.
    // Read from SENTINEL_CHAIN_HMAC_KEY env var (hex-encoded 32-byte key).
    // When set, Sentinel signs its own call chain entries and verifies incoming ones.
    let call_chain_hmac_key: Option<[u8; 32]> = std::env::var("SENTINEL_CHAIN_HMAC_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|hex_str| {
            match hex::decode(&hex_str) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    tracing::info!("FIND-015: Call chain HMAC signing/verification enabled");
                    Some(key)
                }
                Ok(bytes) => {
                    tracing::warn!(
                        "SENTINEL_CHAIN_HMAC_KEY must be exactly 32 bytes (64 hex chars), got {} bytes — chain signing disabled",
                        bytes.len()
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        "SENTINEL_CHAIN_HMAC_KEY is not valid hex — chain signing disabled: {}",
                        e
                    );
                    None
                }
            }
        });

    // Initialize audit logger
    let audit_path = PathBuf::from(&args.audit_log);
    let mut audit_logger = AuditLogger::new(audit_path.clone());

    // Wire custom PII patterns from config into audit logger
    if !policy_config.audit.custom_pii_patterns.is_empty() {
        let pii_patterns: Vec<sentinel_audit::CustomPiiPattern> = policy_config
            .audit
            .custom_pii_patterns
            .iter()
            .map(|p| sentinel_audit::CustomPiiPattern {
                name: p.name.clone(),
                pattern: p.pattern.clone(),
            })
            .collect();
        tracing::info!(
            "Custom PII patterns loaded: {} patterns",
            pii_patterns.len()
        );
        audit_logger = audit_logger.with_custom_pii_patterns(pii_patterns);
    }

    let audit = Arc::new(audit_logger);

    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }

    tracing::info!("Audit log: {}", audit_path.display());

    // Session store
    let session_store =
        SessionStore::new(Duration::from_secs(args.session_timeout), args.max_sessions);
    let session_store = if args.session_max_lifetime > 0 {
        session_store.with_max_lifetime(Duration::from_secs(args.session_max_lifetime))
    } else {
        session_store
    };
    let sessions = Arc::new(session_store);

    tracing::info!(
        "Session store: timeout={}s, max={}, max_lifetime={}s",
        args.session_timeout,
        args.max_sessions,
        args.session_max_lifetime
    );

    // HTTP client for upstream
    // SECURITY (R11-RESP-9): Disable automatic redirect following to prevent SSRF.
    // A malicious upstream could return 3xx redirects to internal services (e.g.,
    // http://169.254.169.254 for cloud metadata). The proxy should not blindly
    // follow redirects — it should treat them as errors.
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to create HTTP client")?;

    // OAuth 2.1 validator (optional)
    let oauth = if let Some(ref issuer) = args.oauth_issuer {
        let config = OAuthConfig {
            issuer: issuer.clone(),
            audience: args.oauth_audience.clone(),
            jwks_uri: args.oauth_jwks_uri.clone(),
            required_scopes: args.oauth_scopes.clone(),
            pass_through: args.oauth_pass_through,
            allowed_algorithms: sentinel_http_proxy::oauth::default_allowed_algorithms(),
            expected_resource: args.oauth_expected_resource.clone(),
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
        };
        tracing::info!(
            "OAuth 2.1 enabled: issuer={}, audience={}, scopes={:?}, pass_through={}",
            config.issuer,
            config.audience,
            config.required_scopes,
            config.pass_through,
        );
        Some(Arc::new(OAuthValidator::new(config, http_client.clone())))
    } else {
        tracing::info!("OAuth 2.1 not configured — all requests accepted without token validation");
        None
    };

    // Build injection scanner from config (supports extra/disabled patterns)
    let injection_disabled = !policy_config.injection.enabled;
    let injection_scanner = {
        let ic = &policy_config.injection;
        if ic.enabled {
            if !ic.extra_patterns.is_empty() || !ic.disabled_patterns.is_empty() {
                match sentinel_mcp::inspection::InjectionScanner::from_config(
                    &ic.extra_patterns,
                    &ic.disabled_patterns,
                ) {
                    Some(scanner) => {
                        tracing::info!(
                            "Injection scanner: {} active patterns ({} extra, {} disabled)",
                            scanner.patterns().len(),
                            ic.extra_patterns.len(),
                            ic.disabled_patterns.len(),
                        );
                        Some(Arc::new(scanner))
                    }
                    None => {
                        tracing::warn!(
                            "Injection scanner: failed to compile custom patterns, using defaults"
                        );
                        None
                    }
                }
            } else {
                tracing::info!("Injection scanner: default patterns");
                None
            }
        } else {
            tracing::info!("Injection scanner: DISABLED by configuration");
            None
        }
    };

    // SECURITY (R9-9): Warn when injection detection is active but blocking
    // is disabled. This means injections are detected and logged but the
    // malicious response is still forwarded to the agent.
    if policy_config.injection.enabled && !policy_config.injection.block_on_injection {
        tracing::warn!(
            "Injection scanning is enabled but block_on_injection=false — \
             injections will be DETECTED but NOT BLOCKED. Set \
             [injection] block_on_injection=true in config to enforce blocking."
        );
    }

    // Keep a reference for post-shutdown audit flush (Challenge 15 fix)
    let shutdown_audit = audit.clone();

    // Parse bind address for DNS rebinding defense (TASK-015).
    // validate_origin uses this to automatically restrict origins on loopback binds.
    let bind_addr: std::net::SocketAddr = args
        .listen
        .parse()
        .context(format!("Invalid listen address: {}", args.listen))?;

    // Build shared state
    let state = ProxyState {
        engine: Arc::new(engine),
        policies: Arc::new(policies),
        audit,
        sessions: sessions.clone(),
        upstream_url: args.upstream.clone(),
        http_client,
        oauth,
        injection_scanner,
        injection_disabled,
        injection_blocking: policy_config.injection.block_on_injection,
        api_key,
        approval_store: None,
        manifest_config: None,
        allowed_origins: policy_config.allowed_origins.clone(),
        bind_addr,
        // SECURITY (R10-FRAME-2): Default to canonicalize=true (safe mode).
        // The env var SENTINEL_NO_CANONICALIZE=true or --no-canonicalize opt out.
        canonicalize: !args.no_canonicalize
            && !std::env::var("SENTINEL_NO_CANONICALIZE")
                .ok()
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        output_schema_registry: Arc::new(OutputSchemaRegistry::new()),
        response_dlp_enabled: true,
        response_dlp_blocking: std::env::var("SENTINEL_DLP_BLOCKING")
            .ok()
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        known_tools: sentinel_mcp::rug_pull::build_known_tools(&[]),
        elicitation_config: policy_config.elicitation.clone(),
        sampling_config: policy_config.sampling.clone(),
        tool_registry: None,
        call_chain_hmac_key,
        // SECURITY: Trace output is opt-in via env var. When disabled (default),
        // the ?trace=true query parameter is silently ignored. This prevents
        // leaking internal policy names, patterns, and constraint configurations
        // to authenticated clients.
        trace_enabled: std::env::var("SENTINEL_TRACE_ENABLED")
            .ok()
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),

        // Phase 3.1 Security Managers - disabled by default in HTTP proxy
        // These are initialized via sentinel-server when running in server mode
        circuit_breaker: None,
        shadow_agent: None,
        deputy: None,
        schema_lineage: None,
        auth_level: None,
        sampling_detector: None,
    };

    if state.canonicalize {
        tracing::info!("TOCTOU canonicalization enabled — forwarding re-serialized JSON");
    }

    // TASK-015: Log DNS rebinding defense configuration
    if state.allowed_origins.is_empty() {
        if bind_addr.ip().is_loopback() {
            tracing::info!(
                bind_addr = %bind_addr,
                "DNS rebinding defense: auto-restricting origins to localhost variants"
            );
        } else {
            tracing::info!(
                bind_addr = %bind_addr,
                "Origin validation: same-origin check (non-loopback bind)"
            );
        }
    } else {
        tracing::info!(
            allowed_origins = ?state.allowed_origins,
            "Origin validation: using explicit allowlist"
        );
    }

    // Build rate limiter (global, token-bucket)
    let global_rate_limiter = if args.rate_limit > 0 {
        let quota = Quota::per_second(std::num::NonZeroU32::new(args.rate_limit).unwrap());
        let limiter = Arc::new(RateLimiter::direct(quota));
        tracing::info!(rps = args.rate_limit, "Global rate limiting enabled");
        Some(limiter)
    } else {
        tracing::info!("Rate limiting disabled");
        None
    };

    // Build router
    // SECURITY (R8-HTTP-1): Apply a 1 MB request body limit to prevent
    // resource exhaustion from oversized payloads. Matches sentinel-server.
    let mut app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(proxy::handle_mcp_post).delete(proxy::handle_mcp_delete),
        )
        .route("/health", axum::routing::get(health))
        // RFC 9728: Protected Resource Metadata endpoint for OAuth discovery
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(proxy::handle_protected_resource_metadata),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(request_id))
        .with_state(state);

    if let Some(limiter) = global_rate_limiter {
        app = app.layer(axum::middleware::from_fn(move |request, next: Next| {
            let limiter = limiter.clone();
            async move {
                if limiter.check().is_err() {
                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                }
                next.run(request).await
            }
        }));
    }

    // Spawn background session cleanup task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sessions.evict_expired();
        }
    });

    // Spawn periodic audit heartbeat task.
    // IMPROVEMENT_PLAN 10.6: Heartbeat entries enable detection of log truncation/gaps.
    let heartbeat_interval: u64 = std::env::var("SENTINEL_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if heartbeat_interval > 0 {
        let heartbeat_audit = shutdown_audit.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(heartbeat_interval));
            let mut sequence: u64 = 0;
            // Skip the first immediate tick — heartbeat starts after first interval
            interval.tick().await;
            loop {
                interval.tick().await;
                sequence += 1;
                if let Err(e) = heartbeat_audit
                    .log_heartbeat(heartbeat_interval, sequence)
                    .await
                {
                    tracing::warn!("Failed to log audit heartbeat: {}", e);
                }
            }
        });
        tracing::info!(
            "Audit heartbeat task enabled (every {}s)",
            heartbeat_interval
        );
    }

    // Start server
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context(format!("Failed to bind to {}", bind_addr))?;

    tracing::info!(
        "Sentinel HTTP proxy listening on {} → upstream {}",
        args.listen,
        args.upstream
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    // Challenge 15 fix: Flush audit log before exit.
    // Matches the pattern from sentinel-server/src/main.rs.
    tracing::info!("Flushing audit log...");
    if let Err(e) = shutdown_audit.sync().await {
        tracing::error!("Failed to flush audit log on shutdown: {}", e);
    }
    // Create a final checkpoint to capture entries since the last periodic checkpoint
    match shutdown_audit.create_checkpoint().await {
        Ok(cp) => tracing::info!(
            "Shutdown checkpoint created: {} ({} entries)",
            cp.id,
            cp.entry_count
        ),
        Err(e) => tracing::debug!("Shutdown checkpoint skipped: {}", e),
    }

    tracing::info!("Proxy shut down gracefully");
    Ok(())
}

/// Middleware that adds standard security headers to all proxy responses.
async fn security_headers(request: Request, next: Next) -> Response {
    let is_https = request.uri().scheme_str() == Some("https")
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    if is_https {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Middleware that adds a unique request ID to every response.
async fn request_id(request: Request, next: Next) -> Response {
    let incoming_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128)
        .map(|s| s.to_string());

    let mut response = next.run(request).await;
    let id = incoming_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Ok(val) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("x-request-id"), val);
    }
    response
}

async fn health() -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        },
    }
}
