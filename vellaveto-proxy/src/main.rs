//! Vellaveto MCP Stdio Proxy
//!
//! Transparent proxy that sits between an agent and an MCP server,
//! intercepting `tools/call` requests and evaluating them against policies.
//!
//! Usage:
//! ```sh
//! vellaveto-proxy --config policy.toml -- /path/to/mcp-server [args...]
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tokio::process::Command;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::proxy::ProxyBridge;

#[derive(Parser)]
#[command(
    name = "vellaveto-proxy",
    about = "MCP stdio proxy with policy enforcement"
)]
struct Cli {
    /// Path to the policy configuration file (TOML)
    #[arg(short, long)]
    config: String,

    /// Enable strict mode for policy evaluation
    #[arg(long, default_value_t = false)]
    strict: bool,

    /// Request timeout in seconds (default: 30). Requests forwarded to the child
    /// server that don't receive a response within this time will be timed out.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Enable evaluation trace logging. Traces include per-policy evaluation
    /// details and are emitted at DEBUG level.
    #[arg(long, default_value_t = false)]
    trace: bool,

    /// The MCP server command and arguments (after --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.command.is_empty() {
        anyhow::bail!("No MCP server command specified. Usage: vellaveto-proxy --config policy.toml -- /path/to/mcp-server [args...]");
    }

    // Load policies
    let policy_config = PolicyConfig::load_file(&cli.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config '{}': {}", cli.config, e))?;
    let policies = policy_config.to_policies();
    tracing::info!("Loaded {} policies from {}", policies.len(), cli.config);

    // Set up audit logging next to config
    let config_dir = std::path::Path::new(&cli.config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("proxy-audit.log");
    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }
    tracing::info!("Audit log: {}", audit_path.display());

    // Verify child binary integrity before spawn (supply chain protection)
    let (child_cmd, child_args) = cli
        .command
        .split_first()
        .context("Command list is empty after validation")?;

    if let Err(reason) = policy_config.supply_chain.verify_binary(child_cmd) {
        tracing::error!("Supply chain verification FAILED: {}", reason);
        anyhow::bail!(
            "Refusing to spawn MCP server: supply chain verification failed — {}",
            reason
        );
    } else if policy_config.supply_chain.enabled {
        tracing::info!("Supply chain verification passed for '{}'", child_cmd);
    }

    // Spawn child MCP server
    // SECURITY (FIND-GAP-011): Clear the environment of the child process to
    // prevent accidental leakage of secrets (e.g., API keys, tokens) from the
    // proxy's environment into the child. Only forward minimal required variables.
    let mut cmd = Command::new(child_cmd);
    cmd.args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env_clear();

    // Forward only minimal required environment variables
    for key in &["PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR", "TZ"] {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }

    let mut child = cmd
        .spawn()
        .context(format!("Failed to spawn child MCP server: {}", child_cmd))?;

    // FIND-R56-PROXY-002: Use descriptive string instead of PID 0 when child.id()
    // returns None (possible on some platforms before the child has started).
    let child_pid_display = child
        .id()
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    tracing::info!(
        "Spawned child MCP server (PID {}): {} {:?}",
        child_pid_display,
        child_cmd,
        child_args
    );

    // Fix #25: Brief startup check — detect immediate crashes (bad binary, missing
    // deps, wrong architecture) before entering the proxy loop.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    match child.try_wait() {
        Ok(Some(status)) => {
            anyhow::bail!(
                "Child MCP server exited immediately (PID {}, status: {}). \
                 Check that '{}' is a valid executable.",
                child_pid_display,
                status,
                child_cmd
            );
        }
        Ok(None) => {
            // Still running — good
            tracing::debug!("Child process {} is running", child_pid_display);
        }
        Err(e) => {
            tracing::warn!("Could not check child process status: {}", e);
        }
    }

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Create proxy bridge with pre-compiled policies and configurable timeout
    let mut engine = PolicyEngine::with_policies(cli.strict, &policies).map_err(|errors| {
        for e in &errors {
            tracing::error!("Policy validation error: {}", e);
        }
        anyhow::anyhow!("{} policy validation errors", errors.len())
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
        tracing::info!(
            max_path_decode_iterations = max_iter,
            "custom path decode iteration limit"
        );
    }
    let timeout = std::time::Duration::from_secs(cli.timeout);
    let mut bridge = ProxyBridge::new(engine, policies, audit)
        .with_timeout(timeout)
        .with_trace(cli.trace);

    // Build injection scanner from config (supports extra/disabled patterns)
    let injection_config = &policy_config.injection;
    if injection_config.enabled {
        if !injection_config.extra_patterns.is_empty()
            || !injection_config.disabled_patterns.is_empty()
        {
            if let Some(scanner) = vellaveto_mcp::inspection::InjectionScanner::from_config(
                &injection_config.extra_patterns,
                &injection_config.disabled_patterns,
            ) {
                tracing::info!(
                    "Injection scanner: {} active patterns ({} extra, {} disabled)",
                    scanner.patterns().len(),
                    injection_config.extra_patterns.len(),
                    injection_config.disabled_patterns.len(),
                );
                bridge = bridge.with_injection_scanner(scanner);
            }
        } else {
            tracing::info!("Injection scanner: default patterns");
        }
    } else {
        tracing::info!("Injection scanner: DISABLED by configuration");
        bridge = bridge.with_injection_disabled(true);
    }

    tracing::info!("Request timeout: {}s, trace: {}", cli.timeout, cli.trace);

    // Run the proxy
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let proxy_result = bridge
        .run(agent_stdin, agent_stdout, child_stdin, child_stdout)
        .await;

    // Clean up child process — kill and then reap to prevent zombies
    let _ = child.kill().await;
    let _ = child.wait().await;

    match proxy_result {
        Ok(()) => {
            tracing::info!("Proxy shut down cleanly");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Proxy error: {}", e);
            Err(anyhow::anyhow!("Proxy error: {}", e))
        }
    }
}
