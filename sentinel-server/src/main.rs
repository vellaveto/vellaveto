use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_canonical::CanonicalPolicies;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState, RateLimits};
use sentinel_types::{Action, Policy};
use serde_json::json;
use std::sync::Arc;

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
        /// Allow starting without SENTINEL_API_KEY (unauthenticated mode).
        /// WARNING: Mutating endpoints will have no access control.
        #[arg(long, default_value_t = false)]
        allow_anonymous: bool,
        /// Watch the policy config file for changes and auto-reload.
        #[arg(long, default_value_t = false)]
        watch: bool,
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
    /// Verify audit log integrity (hash chain + checkpoint signatures)
    Verify {
        /// Path to the audit log file (e.g., audit.log)
        #[arg(short, long)]
        audit: String,
        /// Trusted Ed25519 verifying key (hex-encoded 32-byte public key).
        /// When set, rejects checkpoints signed by any other key.
        #[arg(long)]
        trusted_key: Option<String>,
        /// Also list rotated audit log files and their sizes.
        #[arg(long, default_value_t = false)]
        list_rotated: bool,
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
        Commands::Serve {
            port,
            config,
            bind,
            allow_anonymous,
            watch,
        } => cmd_serve(port, config, bind, allow_anonymous, watch).await,
        Commands::Evaluate {
            tool,
            function,
            params,
            config,
        } => cmd_evaluate(tool, function, params, config).await,
        Commands::Check { config } => cmd_check(config).await,
        Commands::Policies { preset } => cmd_policies(preset),
        Commands::Verify {
            audit,
            trusted_key,
            list_rotated,
        } => cmd_verify(audit, trusted_key, list_rotated).await,
    }
}

async fn cmd_serve(
    port: u16,
    config: String,
    bind: String,
    allow_anonymous: bool,
    watch: bool,
) -> Result<()> {
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), config);

    let config_dir = std::path::Path::new(&config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("audit.log");

    // Load or generate Ed25519 signing key for audit checkpoints.
    // SENTINEL_SIGNING_KEY: hex-encoded 32-byte Ed25519 seed.
    // If unset, a key is auto-generated (logged public key for verification).
    let signing_key = match std::env::var("SENTINEL_SIGNING_KEY") {
        Ok(hex_key) if !hex_key.is_empty() => {
            let bytes = hex::decode(&hex_key)
                .map_err(|e| anyhow::anyhow!("Invalid SENTINEL_SIGNING_KEY hex: {}", e))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "SENTINEL_SIGNING_KEY must be exactly 32 bytes (64 hex chars), got {}",
                    bytes.len()
                );
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            tracing::info!("Loaded Ed25519 signing key from SENTINEL_SIGNING_KEY");
            AuditLogger::signing_key_from_bytes(&key_bytes)
        }
        _ => {
            let key = AuditLogger::generate_signing_key();
            let vk = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&key.to_bytes())
                    .verifying_key()
                    .as_bytes(),
            );
            tracing::info!("Auto-generated Ed25519 signing key (verifying key: {})", vk);
            key
        }
    };

    // Optional trusted verifying key for checkpoint verification.
    // SENTINEL_TRUSTED_KEY: hex-encoded 32-byte Ed25519 public key.
    // When set, verify_checkpoints() rejects checkpoints signed by any other key,
    // preventing an attacker with file write access from forging checkpoints.
    let mut audit_logger = AuditLogger::new(audit_path.clone()).with_signing_key(signing_key);

    // Configurable audit log rotation size.
    // SENTINEL_LOG_MAX_SIZE: max bytes before rotating (default: 100MB). Set to 0 to disable.
    if let Ok(max_size_str) = std::env::var("SENTINEL_LOG_MAX_SIZE") {
        if let Ok(max_size) = max_size_str.parse::<u64>() {
            audit_logger = audit_logger.with_max_file_size(max_size);
            if max_size == 0 {
                tracing::info!("Audit log rotation disabled (SENTINEL_LOG_MAX_SIZE=0)");
            } else {
                tracing::info!("Audit log rotation threshold: {} bytes", max_size);
            }
        } else {
            tracing::warn!(
                "Invalid SENTINEL_LOG_MAX_SIZE '{}', using default (100 MB)",
                max_size_str
            );
        }
    }

    if let Ok(trusted_key) = std::env::var("SENTINEL_TRUSTED_KEY") {
        if !trusted_key.is_empty() {
            // Validate the key format early
            let key_bytes = hex::decode(&trusted_key)
                .map_err(|e| anyhow::anyhow!("Invalid SENTINEL_TRUSTED_KEY hex: {}", e))?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "SENTINEL_TRUSTED_KEY must be exactly 32 bytes (64 hex chars), got {}",
                    key_bytes.len()
                );
            }
            tracing::info!("Checkpoint trust anchor pinned to key: {}", trusted_key);
            audit_logger = audit_logger.with_trusted_key(trusted_key);
        }
    }

    let audit = Arc::new(audit_logger);

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

    // Read API key from environment variable for auth middleware.
    // Exploit #7 fix: require SENTINEL_API_KEY unless --allow-anonymous is set.
    // A security product must not ship with zero access control by default.
    let api_key = std::env::var("SENTINEL_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(Arc::new);

    if api_key.is_some() {
        tracing::info!("API key authentication enabled for mutating endpoints");
    } else if allow_anonymous {
        tracing::warn!(
            "No SENTINEL_API_KEY set and --allow-anonymous specified — mutating endpoints are UNAUTHENTICATED"
        );
    } else {
        anyhow::bail!(
            "SENTINEL_API_KEY environment variable is required.\n\
             Set it to enable authentication for mutating endpoints, or pass \
             --allow-anonymous to explicitly opt in to unauthenticated mode.\n\
             Example: SENTINEL_API_KEY=your-secret-key sentinel serve --config policy.toml"
        );
    }

    // Configure per-category rate limits from environment variables.
    // Set to 0 or omit to disable rate limiting for a category.
    let mut rate_limits_val = RateLimits::new(
        std::env::var("SENTINEL_RATE_EVALUATE")
            .ok()
            .and_then(|s| s.parse().ok()),
        std::env::var("SENTINEL_RATE_ADMIN")
            .ok()
            .and_then(|s| s.parse().ok()),
        std::env::var("SENTINEL_RATE_READONLY")
            .ok()
            .and_then(|s| s.parse().ok()),
    );

    // Per-IP rate limiting: independent bucket per client IP address.
    // SENTINEL_RATE_PER_IP: requests per second allowed per unique IP.
    if let Some(rps) = std::env::var("SENTINEL_RATE_PER_IP")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .and_then(std::num::NonZeroU32::new)
    {
        rate_limits_val = rate_limits_val.with_per_ip(rps);
        tracing::info!("Per-IP rate limiting enabled: {} req/s per IP", rps);
    }

    let rate_limits = Arc::new(rate_limits_val);

    if rate_limits.evaluate.is_some()
        || rate_limits.admin.is_some()
        || rate_limits.readonly.is_some()
    {
        tracing::info!(
            "Rate limiting enabled — evaluate: {}, admin: {}, readonly: {}",
            rate_limits
                .evaluate
                .as_ref()
                .map_or("off".to_string(), |_| std::env::var(
                    "SENTINEL_RATE_EVALUATE"
                )
                .unwrap_or_default()),
            rate_limits
                .admin
                .as_ref()
                .map_or("off".to_string(), |_| std::env::var("SENTINEL_RATE_ADMIN")
                    .unwrap_or_default()),
            rate_limits
                .readonly
                .as_ref()
                .map_or("off".to_string(), |_| std::env::var(
                    "SENTINEL_RATE_READONLY"
                )
                .unwrap_or_default()),
        );
    }

    // Parse CORS allowed origins from environment variable.
    // Default (unset or empty): localhost only. Set to "*" for any origin.
    // Comma-separated list: "https://app.example.com,https://admin.example.com"
    let cors_origins: Vec<String> = std::env::var("SENTINEL_CORS_ORIGINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if cors_origins.is_empty() {
        tracing::info!("CORS: localhost only (strict default)");
    } else if cors_origins.iter().any(|o| o == "*") {
        tracing::warn!("CORS: allowing ANY origin (SENTINEL_CORS_ORIGINS=*)");
    } else {
        tracing::info!("CORS: allowed origins: {:?}", cors_origins);
    }

    // Parse trusted proxy IPs for secure X-Forwarded-For handling.
    // When configured, per-IP rate limiting uses the rightmost untrusted XFF entry.
    // When empty (default), proxy headers are ignored and connection IP is used directly.
    let trusted_proxies: Vec<std::net::IpAddr> = std::env::var("SENTINEL_TRUSTED_PROXIES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|ip| {
                    let trimmed = ip.trim();
                    match trimmed.parse::<std::net::IpAddr>() {
                        Ok(ip) => Some(ip),
                        Err(_) => {
                            if !trimmed.is_empty() {
                                tracing::warn!("Invalid trusted proxy IP: {:?}", trimmed);
                            }
                            None
                        }
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if !trusted_proxies.is_empty() {
        tracing::info!(
            "Trusted proxies configured: {:?} — X-Forwarded-For headers will be trusted from these IPs",
            trusted_proxies
        );
    }

    // Pre-compile policies for zero-Mutex evaluation on the hot path.
    // Falls back to legacy (per-call compilation) if any pattern is invalid.
    let engine = match PolicyEngine::with_policies(false, &policies) {
        Ok(compiled) => {
            tracing::info!(
                "Pre-compiled {} policies — zero-Mutex evaluation enabled",
                policies.len()
            );
            compiled
        }
        Err(errors) => {
            for e in &errors {
                tracing::warn!("Policy compilation error: {}", e);
            }
            tracing::warn!("Falling back to legacy evaluation (per-call pattern compilation)");
            PolicyEngine::new(false)
        }
    };

    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(engine)),
        policies: Arc::new(ArcSwap::from_pointee(policies)),
        audit,
        config_path: Arc::new(config),
        approvals: approvals.clone(),
        api_key,
        rate_limits,
        cors_origins,
        metrics: Arc::new(sentinel_server::Metrics::default()),
        trusted_proxies: Arc::new(trusted_proxies),
    };

    tracing::info!("Audit log: {}", audit_path.display());
    tracing::info!("Approvals log: {}", approval_path.display());

    // Spawn periodic approval expiry task
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

    // Spawn periodic audit checkpoint task.
    // Creates a signed Ed25519 checkpoint every SENTINEL_CHECKPOINT_INTERVAL seconds (default: 300).
    let checkpoint_interval: u64 = std::env::var("SENTINEL_CHECKPOINT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if checkpoint_interval > 0 {
        let checkpoint_audit = state.audit.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(checkpoint_interval));
            // Skip the first immediate tick — no point checkpointing an empty/just-loaded log
            interval.tick().await;
            loop {
                interval.tick().await;
                match checkpoint_audit.create_checkpoint().await {
                    Ok(cp) => tracing::info!(
                        "Audit checkpoint created: {} ({} entries)",
                        cp.id,
                        cp.entry_count
                    ),
                    Err(e) => tracing::warn!("Failed to create audit checkpoint: {}", e),
                }
            }
        });
        tracing::info!(
            "Audit checkpoint task enabled (every {}s)",
            checkpoint_interval
        );
    }

    // Spawn periodic per-IP rate limit bucket cleanup (every 10 minutes)
    if state.rate_limits.per_ip.is_some() {
        let cleanup_limits = state.rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            interval.tick().await; // Skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(ref per_ip) = cleanup_limits.per_ip {
                    let before = per_ip.len();
                    per_ip.cleanup(std::time::Duration::from_secs(3600));
                    let removed = before.saturating_sub(per_ip.len());
                    if removed > 0 {
                        tracing::debug!(
                            "Cleaned up {} stale per-IP rate limit buckets ({} remaining)",
                            removed,
                            per_ip.len()
                        );
                    }
                }
            }
        });
    }

    // Optionally watch the config file for changes and auto-reload
    if watch {
        if let Err(e) = sentinel_server::spawn_config_watcher(state.clone()) {
            tracing::warn!("Failed to start config file watcher: {}", e);
        }
    }

    // Keep a reference to audit for shutdown flush
    let shutdown_audit = state.audit.clone();

    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind, port))
        .await
        .context("Failed to bind to address")?;

    tracing::info!("Sentinel server listening on {}:{}", bind, port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("Server error")?;

    // Flush audit log with a 30-second timeout to prevent hanging on shutdown.
    let shutdown_deadline = std::time::Duration::from_secs(30);
    let cleanup = async {
        // This ensures Allow/RequireApproval entries (which skip per-write fsync)
        // are not lost on graceful shutdown.
        if let Err(e) = shutdown_audit.sync().await {
            tracing::warn!("Failed to sync audit log during shutdown: {}", e);
        }
        // Create a final checkpoint to capture any entries since the last periodic checkpoint
        match shutdown_audit.create_checkpoint().await {
            Ok(cp) => tracing::info!(
                "Shutdown checkpoint created: {} ({} entries)",
                cp.id,
                cp.entry_count
            ),
            Err(e) => tracing::debug!("Shutdown checkpoint skipped: {}", e),
        }
    };
    if tokio::time::timeout(shutdown_deadline, cleanup)
        .await
        .is_err()
    {
        tracing::warn!("Shutdown cleanup timed out after 30s — exiting without full flush");
    }

    tracing::info!("Server shut down gracefully");
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

    let engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        anyhow::anyhow!("Policy compilation errors: {}", msgs.join("; "))
    })?;
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

    let config = PolicyConfig {
        policies: rules,
        injection: Default::default(),
    };
    let toml_str =
        toml::to_string_pretty(&config).context("Failed to serialize policies to TOML")?;

    println!("{}", toml_str);
    Ok(())
}

async fn cmd_verify(audit: String, trusted_key: Option<String>, list_rotated: bool) -> Result<()> {
    let audit_path = std::path::PathBuf::from(&audit);
    if !audit_path.exists() {
        anyhow::bail!("Audit log not found: {}", audit);
    }

    let mut logger = AuditLogger::new(audit_path);
    if let Some(ref key) = trusted_key {
        // Validate key format early
        let key_bytes =
            hex::decode(key).map_err(|e| anyhow::anyhow!("Invalid --trusted-key hex: {}", e))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "--trusted-key must be exactly 32 bytes (64 hex chars), got {}",
                key_bytes.len()
            );
        }
        logger = logger.with_trusted_key(key.clone());
    }

    // Phase 1: Verify hash chain
    println!("Verifying hash chain...");
    let chain_result = logger
        .verify_chain()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify chain: {}", e))?;

    if chain_result.valid {
        println!(
            "  Hash chain: OK ({} entries verified)",
            chain_result.entries_checked
        );
    } else {
        println!(
            "  Hash chain: BROKEN at entry {}",
            chain_result
                .first_broken_at
                .map_or("unknown".to_string(), |i| i.to_string())
        );
    }

    // Phase 2: Verify checkpoints
    println!("Verifying checkpoints...");
    let cp_result = logger
        .verify_checkpoints()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify checkpoints: {}", e))?;

    if cp_result.checkpoints_checked == 0 {
        println!("  Checkpoints: none found (skipped)");
    } else if cp_result.valid {
        println!(
            "  Checkpoints: OK ({} verified{})",
            cp_result.checkpoints_checked,
            if trusted_key.is_some() {
                ", key pinned"
            } else {
                ""
            }
        );
    } else {
        println!(
            "  Checkpoints: INVALID at checkpoint {}",
            cp_result
                .first_invalid_at
                .map_or("unknown".to_string(), |i| i.to_string())
        );
        if let Some(ref reason) = cp_result.failure_reason {
            println!("  Reason: {}", reason);
        }
    }

    // Phase 3: Check for duplicate entry IDs
    println!("Checking for duplicate entry IDs...");
    let has_duplicates = match logger.detect_duplicate_ids().await {
        Ok(duplicates) if duplicates.is_empty() => {
            println!("  Duplicates: none");
            false
        }
        Ok(duplicates) => {
            println!(
                "  WARNING: {} duplicate entry ID(s) found:",
                duplicates.len()
            );
            for (id, count) in &duplicates {
                println!("    {} (appears {} times)", id, count);
            }
            true
        }
        Err(e) => {
            println!("  Failed to check for duplicates: {}", e);
            false
        }
    };

    // Phase 4: List rotated files if requested
    if list_rotated {
        println!("Rotated log files:");
        match logger.list_rotated_files() {
            Ok(files) if files.is_empty() => {
                println!("  (none)");
            }
            Ok(files) => {
                for path in &files {
                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    println!("  {} ({} bytes)", path.display(), size);
                }
                println!("  Total rotated files: {}", files.len());
            }
            Err(e) => {
                println!("  Failed to list rotated files: {}", e);
            }
        }
    }

    // Summary
    let all_valid = chain_result.valid && cp_result.valid && !has_duplicates;
    println!();
    if all_valid {
        println!("Audit log integrity: VERIFIED");
    } else if chain_result.valid && cp_result.valid && has_duplicates {
        println!(
            "Audit log integrity: FAILED (duplicate entry IDs detected — possible replay attack)"
        );
        std::process::exit(2);
    } else {
        println!("Audit log integrity: FAILED");
        std::process::exit(1);
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl+C) for graceful shutdown.
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
