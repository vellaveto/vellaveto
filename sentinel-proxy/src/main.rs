//! Sentinel MCP Stdio Proxy
//!
//! Transparent proxy that sits between an agent and an MCP server,
//! intercepting `tools/call` requests and evaluating them against policies.
//!
//! Usage:
//! ```sh
//! sentinel-proxy --config policy.toml -- /path/to/mcp-server [args...]
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_audit::AuditLogger;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_mcp::proxy::ProxyBridge;
use std::sync::Arc;
use tokio::process::Command;

#[derive(Parser)]
#[command(
    name = "sentinel-proxy",
    about = "MCP stdio proxy with policy enforcement"
)]
struct Cli {
    /// Path to the policy configuration file (TOML)
    #[arg(short, long)]
    config: String,

    /// Enable strict mode for policy evaluation
    #[arg(long, default_value_t = false)]
    strict: bool,

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
        anyhow::bail!("No MCP server command specified. Usage: sentinel-proxy --config policy.toml -- /path/to/mcp-server [args...]");
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

    // Spawn child MCP server
    let (child_cmd, child_args) = cli
        .command
        .split_first()
        .context("Command list is empty after validation")?;
    let mut child = Command::new(child_cmd)
        .args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context(format!("Failed to spawn child MCP server: {}", child_cmd))?;

    tracing::info!("Spawned child MCP server: {} {:?}", child_cmd, child_args);

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Create proxy bridge
    let engine = PolicyEngine::new(cli.strict);
    let bridge = ProxyBridge::new(engine, policies, audit);

    // Run the proxy
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let proxy_result = bridge
        .run(agent_stdin, agent_stdout, child_stdin, child_stdout)
        .await;

    // Clean up child process
    let _ = child.kill().await;

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
