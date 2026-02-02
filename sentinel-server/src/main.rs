use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_audit::AuditLogger;
use sentinel_canonical::CanonicalPolicies;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy};
use sentinel_server::{AppState, routes};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(name = "sentinel", about = "Sentinel policy engine — CLI and HTTP server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server
    Serve {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        #[arg(short, long)]
        config: String,
    },
    /// One-shot action evaluation
    Evaluate {
        #[arg(long)]
        tool: String,
        #[arg(long)]
        function: String,
        #[arg(long, default_value = "{}")]
        params: String,
        #[arg(short, long)]
        config: String,
    },
    /// Validate a config file
    Check {
        #[arg(short, long)]
        config: String,
    },
    /// List canonical policies as TOML
    Policies {
        #[arg(long)]
        preset: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { port, config } => cmd_serve(port, config).await,
        Commands::Evaluate {
            tool,
            function,
            params,
            config,
        } => cmd_evaluate(tool, function, params, config).await,
        Commands::Check { config } => cmd_check(config).await,
        Commands::Policies { preset } => cmd_policies(preset),
    }
}

async fn cmd_serve(port: u16, config: String) -> Result<()> {
    let policy_config =
        PolicyConfig::load_file(&config).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let policies = policy_config.to_policies();

    tracing::info!(
        "Loaded {} policies from {}",
        policies.len(),
        config
    );

    let config_dir = std::path::Path::new(&config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("audit.log");

    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(RwLock::new(policies)),
        audit: Arc::new(AuditLogger::new(audit_path.clone())),
        config_path: Arc::new(config),
    };

    tracing::info!("Audit log: {}", audit_path.display());

    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .context("Failed to bind to port")?;

    tracing::info!("Sentinel server listening on 0.0.0.0:{}", port);

    axum::serve(listener, app)
        .await
        .context("Server error")?;

    Ok(())
}

async fn cmd_evaluate(tool: String, function: String, params: String, config: String) -> Result<()> {
    let parameters: serde_json::Value =
        serde_json::from_str(&params).context("Invalid JSON in --params")?;

    let action = Action {
        tool,
        function,
        parameters,
    };

    let policy_config =
        PolicyConfig::load_file(&config).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let policies = policy_config.to_policies();

    let engine = PolicyEngine::new(false);
    let verdict = engine
        .evaluate_action(&action, &policies)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let output = serde_json::to_string_pretty(&json!({
        "action": action,
        "verdict": verdict,
        "policies_loaded": policies.len(),
    }))?;

    println!("{}", output);
    Ok(())
}

async fn cmd_check(config: String) -> Result<()> {
    let policy_config =
        PolicyConfig::load_file(&config).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let policies = policy_config.to_policies();

    println!("Config OK: {} policies loaded", policies.len());
    for (i, p) in policies.iter().enumerate() {
        println!(
            "  [{}] id={:?} name={:?} type={} priority={}",
            i,
            p.id,
            p.name,
            match &p.policy_type {
                sentinel_types::PolicyType::Allow => "Allow".to_string(),
                sentinel_types::PolicyType::Deny => "Deny".to_string(),
                sentinel_types::PolicyType::Conditional { .. } => "Conditional".to_string(),
            },
            p.priority
        );
    }
    Ok(())
}

fn cmd_policies(preset: String) -> Result<()> {
    let policies: Vec<Policy> = match preset.as_str() {
        "dangerous" => CanonicalPolicies::block_dangerous_tools(),
        "network" => CanonicalPolicies::network_security(),
        "development" => CanonicalPolicies::development_environment(),
        "deny-all" => vec![CanonicalPolicies::deny_all()],
        "allow-all" => vec![CanonicalPolicies::allow_all()],
        _ => {
            anyhow::bail!(
                "Unknown preset: '{}'. Available: dangerous, network, development, deny-all, allow-all",
                preset
            );
        }
    };

    let rules: Vec<sentinel_config::PolicyRule> = policies
        .iter()
        .map(|p| sentinel_config::PolicyRule {
            name: p.name.clone(),
            tool_pattern: extract_tool_pattern(&p.id),
            function_pattern: extract_function_pattern(&p.id),
            policy_type: p.policy_type.clone(),
            priority: Some(p.priority),
            id: Some(p.id.clone()),
        })
        .collect();

    let config = PolicyConfig { policies: rules };
    let toml_str = toml::to_string_pretty(&config)
        .context("Failed to serialize policies to TOML")?;

    println!("{}", toml_str);
    Ok(())
}

fn extract_tool_pattern(id: &str) -> String {
    if let Some((tool, _)) = id.split_once(':') {
        tool.to_string()
    } else {
        id.to_string()
    }
}

fn extract_function_pattern(id: &str) -> String {
    if let Some((_, func)) = id.split_once(':') {
        func.to_string()
    } else {
        "*".to_string()
    }
}