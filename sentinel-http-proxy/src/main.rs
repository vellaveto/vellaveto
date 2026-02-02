//! Sentinel MCP HTTP Proxy — Streamable HTTP reverse proxy.
//!
//! This binary runs an HTTP reverse proxy that sits between MCP clients and
//! an upstream MCP server. It intercepts JSON-RPC messages over the Streamable
//! HTTP transport, evaluates tool calls against loaded policies, and forwards
//! allowed requests.

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_audit::AuditLogger;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_http_proxy::proxy::{self, ProxyState};
use sentinel_http_proxy::session::SessionStore;
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

    // Load and compile policies
    let policy_config = PolicyConfig::load_file(&args.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), args.config);

    let engine = match PolicyEngine::with_policies(args.strict, &policies) {
        Ok(engine) => {
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

    // Initialize audit logger
    let audit_path = PathBuf::from(&args.audit_log);
    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }

    tracing::info!("Audit log: {}", audit_path.display());

    // Session store
    let sessions = Arc::new(SessionStore::new(
        Duration::from_secs(args.session_timeout),
        args.max_sessions,
    ));

    tracing::info!(
        "Session store: timeout={}s, max={}",
        args.session_timeout,
        args.max_sessions
    );

    // HTTP client for upstream
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .context("Failed to create HTTP client")?;

    // Build shared state
    let state = ProxyState {
        engine: Arc::new(engine),
        policies: Arc::new(policies),
        audit,
        sessions: sessions.clone(),
        upstream_url: args.upstream.clone(),
        http_client,
    };

    // Build router
    let app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(proxy::handle_mcp_post).delete(proxy::handle_mcp_delete),
        )
        .route("/health", axum::routing::get(health))
        .with_state(state);

    // Spawn background session cleanup task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sessions.evict_expired();
        }
    });

    // Start server
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .context(format!("Failed to bind to {}", args.listen))?;

    tracing::info!(
        "Sentinel HTTP proxy listening on {} → upstream {}",
        args.listen,
        args.upstream
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    tracing::info!("Proxy shut down gracefully");
    Ok(())
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
