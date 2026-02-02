use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_canonical::CanonicalPolicies;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState};
use sentinel_types::{Action, Policy};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(
    name = "sentinel",
    about = "Sentinel policy engine — CLI and HTTP server"
)]
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
        /// Bind address (default: 127.0.0.1). Use 0.0.0.0 to listen on all interfaces.
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
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
        Commands::Serve { port, config, bind } => cmd_serve(port, config, bind).await,
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

async fn cmd_serve(port: u16, config: String, bind: String) -> Result<()> {
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), config);

    let config_dir = std::path::Path::new(&config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("audit.log");

    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    // Initialize hash chain from existing log
    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }

    let approval_path = config_dir.join("approvals.jsonl");
    let approvals = Arc::new(ApprovalStore::new(
        approval_path.clone(),
        std::time::Duration::from_secs(900),
    ));

    // Load existing approvals from persistence file
    match approvals.load_from_file().await {
        Ok(count) if count > 0 => tracing::info!(
            "Loaded {} approval records from {}",
            count,
            approval_path.display()
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            "Failed to load approvals from {}: {}",
            approval_path.display(),
            e
        ),
    }

    // Read API key from environment variable for auth middleware
    let api_key = std::env::var("SENTINEL_API_KEY").ok().map(Arc::new);

    if api_key.is_some() {
        tracing::info!("API key authentication enabled for mutating endpoints");
    } else {
        tracing::warn!("No SENTINEL_API_KEY set — mutating endpoints are unauthenticated");
    }

    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(RwLock::new(policies)),
        audit,
        config_path: Arc::new(config),
        approvals: approvals.clone(),
        api_key,
    };

    tracing::info!("Audit log: {}", audit_path.display());
    tracing::info!("Approvals log: {}", approval_path.display());

    // Spawn periodic expiry task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let expired = approvals.expire_stale().await;
            if expired > 0 {
                tracing::info!("Expired {} stale approvals", expired);
            }
        }
    });

    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind, port))
        .await
        .context("Failed to bind to address")?;

    tracing::info!("Sentinel server listening on {}:{}", bind, port);

    axum::serve(listener, app).await.context("Server error")?;

    Ok(())
}

async fn cmd_evaluate(
    tool: String,
    function: String,
    params: String,
    config: String,
) -> Result<()> {
    let parameters: serde_json::Value =
        serde_json::from_str(&params).context("Invalid JSON in --params")?;

    let action = Action {
        tool,
        function,
        parameters,
    };

    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

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
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
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
    let toml_str =
        toml::to_string_pretty(&config).context("Failed to serialize policies to TOML")?;

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
