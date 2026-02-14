use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_canonical::CanonicalPolicies;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState, RateLimits};
use sentinel_types::{Action, Policy, Verdict};
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
        #[arg(short, long, default_value_t = 3000)]
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
    /// Validate a config file with comprehensive checks
    Check {
        /// Path to the configuration file
        #[arg(short, long)]
        config: String,
        /// Strict mode: treat warnings as errors
        #[arg(long, default_value_t = false)]
        strict: bool,
        /// Output format (text or json)
        #[arg(long, default_value = "text")]
        format: String,
        /// Skip best practice checks
        #[arg(long, default_value_t = false)]
        no_best_practices: bool,
        /// Skip security checks
        #[arg(long, default_value_t = false)]
        no_security_checks: bool,
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
    /// Compute SHA-256 hash of a binary (for supply_chain.allowed_servers config)
    HashBinary {
        /// Path to the binary to hash
        path: String,
    },
    // ═══════════════════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Cryptographic Tool Security Commands
    // ═══════════════════════════════════════════════════════════════════════════════
    /// Generate an Ed25519 keypair for signing tool definitions (ETDI)
    GenerateKey {
        /// Path to write the private key (hex-encoded)
        #[arg(long)]
        private_key: std::path::PathBuf,
        /// Path to write the public key (hex-encoded)
        #[arg(long)]
        public_key: std::path::PathBuf,
    },
    /// Sign a tool definition (ETDI)
    SignTool {
        /// Tool name
        #[arg(long)]
        tool: String,
        /// Path to the tool definition JSON file
        #[arg(long)]
        definition: std::path::PathBuf,
        /// Path to the private key file
        #[arg(long)]
        key: std::path::PathBuf,
        /// Signer identity (optional, e.g., SPIFFE ID)
        #[arg(long)]
        signer: Option<String>,
        /// Path to write the signature JSON
        #[arg(long)]
        output: std::path::PathBuf,
        /// Signature expiry in days (optional)
        #[arg(long)]
        expires_in_days: Option<u32>,
    },
    /// Verify a tool signature (ETDI)
    VerifySignature {
        /// Tool name
        #[arg(long)]
        tool: String,
        /// Path to the tool definition JSON file
        #[arg(long)]
        definition: std::path::PathBuf,
        /// Path to the signature JSON file
        #[arg(long)]
        signature: std::path::PathBuf,
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
        Commands::Check {
            config,
            strict,
            format,
            no_best_practices,
            no_security_checks,
        } => {
            cmd_check(
                config,
                strict,
                format,
                no_best_practices,
                no_security_checks,
            )
            .await
        }
        Commands::Policies { preset } => cmd_policies(preset),
        Commands::Verify {
            audit,
            trusted_key,
            list_rotated,
        } => cmd_verify(audit, trusted_key, list_rotated).await,
        Commands::HashBinary { path } => cmd_hash_binary(path),
        Commands::GenerateKey {
            private_key,
            public_key,
        } => cmd_generate_key(private_key, public_key),
        Commands::SignTool {
            tool,
            definition,
            key,
            signer,
            output,
            expires_in_days,
        } => cmd_sign_tool(tool, definition, key, signer, output, expires_in_days).await,
        Commands::VerifySignature {
            tool,
            definition,
            signature,
        } => cmd_verify_signature(tool, definition, signature).await,
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
    sentinel_server::opa::configure_runtime_client(&policy_config.opa)
        .map_err(|e| anyhow::anyhow!("Failed to initialize OPA runtime: {}", e))?;

    // SEC-006: Validate DLP patterns compile at startup (fail-closed).
    // If any pattern is invalid, fail immediately rather than silently skipping
    // secret detection for that pattern at runtime.
    if let Err(failures) = sentinel_mcp::inspection::validate_dlp_patterns() {
        for (name, error) in &failures {
            tracing::error!("DLP pattern '{}' failed to compile: {}", name, error);
        }
        anyhow::bail!(
            "DLP pattern validation failed: {} pattern(s) could not compile. \
             Fix the patterns or disable DLP scanning.",
            failures.len()
        );
    }

    // Validate injection patterns compile at startup (fail-closed).
    if let Err(error) = sentinel_mcp::inspection::validate_injection_patterns() {
        tracing::error!("Injection pattern compilation failed: {}", error);
        anyhow::bail!(
            "Injection pattern validation failed: {}. Injection detection unavailable.",
            error
        );
    }

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
        audit_logger = audit_logger.with_custom_pii_patterns(&pii_patterns);
    }

    // Apply audit redaction level from config
    if let Some(ref level_str) = policy_config.audit.redaction_level {
        match level_str.as_str() {
            "Off" | "off" => {
                audit_logger =
                    audit_logger.with_redaction_level(sentinel_audit::RedactionLevel::Off);
                tracing::info!("Audit redaction: OFF (raw values logged)");
            }
            "KeysOnly" | "keys_only" => {
                audit_logger =
                    audit_logger.with_redaction_level(sentinel_audit::RedactionLevel::KeysOnly);
                tracing::info!("Audit redaction: KeysOnly (sensitive keys redacted)");
            }
            "KeysAndPatterns" | "keys_and_patterns" => {
                tracing::info!("Audit redaction: KeysAndPatterns (keys + PII patterns redacted)");
            }
            other => {
                tracing::warn!(
                    "Unknown audit redaction_level '{}', using default (KeysAndPatterns)",
                    other
                );
            }
        }
    }

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

    // Configure per-category rate limits.
    // Config file values are the base; environment variables override them.
    // Set to 0 or omit to disable rate limiting for a category.
    let rl_cfg = &policy_config.rate_limit;

    let env_or = |env_name: &str, config_val: Option<u32>| -> Option<u32> {
        std::env::var(env_name)
            .ok()
            .and_then(|s| s.parse().ok())
            .or(config_val)
    };

    let eff_evaluate_rps = env_or("SENTINEL_RATE_EVALUATE", rl_cfg.evaluate_rps);
    let eff_evaluate_burst = env_or("SENTINEL_RATE_EVALUATE_BURST", rl_cfg.evaluate_burst);
    let eff_admin_rps = env_or("SENTINEL_RATE_ADMIN", rl_cfg.admin_rps);
    let eff_admin_burst = env_or("SENTINEL_RATE_ADMIN_BURST", rl_cfg.admin_burst);
    let eff_readonly_rps = env_or("SENTINEL_RATE_READONLY", rl_cfg.readonly_rps);
    let eff_readonly_burst = env_or("SENTINEL_RATE_READONLY_BURST", rl_cfg.readonly_burst);
    let eff_per_ip_rps = env_or("SENTINEL_RATE_PER_IP", rl_cfg.per_ip_rps);
    let eff_per_ip_burst = env_or("SENTINEL_RATE_PER_IP_BURST", rl_cfg.per_ip_burst);
    let eff_per_ip_max_capacity: Option<usize> = std::env::var("SENTINEL_RATE_PER_IP_MAX_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(rl_cfg.per_ip_max_capacity);

    let mut rate_limits_val = RateLimits::new_with_burst(
        eff_evaluate_rps,
        eff_evaluate_burst,
        eff_admin_rps,
        eff_admin_burst,
        eff_readonly_rps,
        eff_readonly_burst,
    );

    // Per-IP rate limiting: independent bucket per client IP address.
    if let Some(rps) = eff_per_ip_rps.and_then(std::num::NonZeroU32::new) {
        let burst = eff_per_ip_burst.and_then(std::num::NonZeroU32::new);
        rate_limits_val = rate_limits_val.with_per_ip_config(rps, burst, eff_per_ip_max_capacity);
        tracing::info!(
            "Per-IP rate limiting enabled: {} req/s per IP{}{}",
            rps,
            burst.map_or(String::new(), |b| format!(", burst {}", b)),
            eff_per_ip_max_capacity.map_or(String::new(), |c| format!(", max {} IPs", c)),
        );
    }

    // Per-principal rate limiting: independent bucket per principal key.
    // Principal is identified by X-Principal header, Bearer token, or client IP fallback.
    let eff_per_principal_rps = env_or("SENTINEL_RATE_PER_PRINCIPAL", rl_cfg.per_principal_rps);
    let eff_per_principal_burst = env_or(
        "SENTINEL_RATE_PER_PRINCIPAL_BURST",
        rl_cfg.per_principal_burst,
    );
    if let Some(rps) = eff_per_principal_rps.and_then(std::num::NonZeroU32::new) {
        let burst = eff_per_principal_burst.and_then(std::num::NonZeroU32::new);
        rate_limits_val = rate_limits_val.with_per_principal_config(rps, burst, None);
        tracing::info!(
            "Per-principal rate limiting enabled: {} req/s per principal{}",
            rps,
            burst.map_or(String::new(), |b| format!(", burst {}", b)),
        );
    }

    let rate_limits = Arc::new(rate_limits_val);

    if rate_limits.evaluate.is_some()
        || rate_limits.admin.is_some()
        || rate_limits.readonly.is_some()
    {
        let fmt_cat = |rps: Option<u32>, burst: Option<u32>| -> String {
            match rps.filter(|&r| r > 0) {
                Some(r) => match burst.filter(|&b| b > 0) {
                    Some(b) => format!("{} rps (burst {})", r, b),
                    None => format!("{} rps", r),
                },
                None => "off".to_string(),
            }
        };
        tracing::info!(
            "Rate limiting enabled — evaluate: {}, admin: {}, readonly: {}",
            fmt_cat(eff_evaluate_rps, eff_evaluate_burst),
            fmt_cat(eff_admin_rps, eff_admin_burst),
            fmt_cat(eff_readonly_rps, eff_readonly_burst),
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

    // SECURITY (R13-LEG-4): Pre-compile policies and REFUSE to start on
    // compilation failure. The legacy evaluation path bypasses path_rules,
    // network_rules, and context_conditions — silently degrading to it would
    // drop all advanced security constraints. Matches sentinel-http-proxy behavior.
    let engine = match PolicyEngine::with_policies(false, &policies) {
        Ok(mut compiled) => {
            if let Some(max_iter) = policy_config.max_path_decode_iterations {
                compiled.set_max_path_decode_iterations(max_iter);
                tracing::info!(
                    max_path_decode_iterations = max_iter,
                    "custom path decode iteration limit"
                );
            }
            tracing::info!(
                "Pre-compiled {} policies — zero-Mutex evaluation enabled",
                policies.len()
            );
            compiled
        }
        Err(errors) => {
            for e in &errors {
                tracing::error!("Policy compilation error: {}", e);
            }
            anyhow::bail!(
                "Failed to compile {} policies — fix config and retry. \
                 The server refuses to start with invalid policies to prevent \
                 silent degradation to the legacy evaluation path.",
                errors.len()
            );
        }
    };

    // Initialize Prometheus metrics recorder.
    let prometheus_handle = sentinel_server::metrics::init_prometheus();

    // Set initial gauge values
    sentinel_server::metrics::set_policies_loaded(policies.len() as f64);

    // Initialize tool registry if enabled (P2.1)
    let tool_registry: Option<Arc<sentinel_mcp::tool_registry::ToolRegistry>> =
        if policy_config.tool_registry.enabled {
            let registry_path = if policy_config.tool_registry.persistence_path.is_empty() {
                config_dir.join("tool_registry.jsonl")
            } else {
                std::path::PathBuf::from(&policy_config.tool_registry.persistence_path)
            };
            let registry = sentinel_mcp::tool_registry::ToolRegistry::with_threshold(
                &registry_path,
                policy_config.tool_registry.trust_threshold,
            );
            // Load existing entries
            match registry.load().await {
                Ok(count) if count > 0 => {
                    tracing::info!(
                        "Loaded {} tool registry entries from {}",
                        count,
                        registry_path.display()
                    );
                }
                Ok(_) => {
                    tracing::info!(
                        "Tool registry initialized (empty) at {}",
                        registry_path.display()
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load tool registry from {}: {}",
                        registry_path.display(),
                        e
                    );
                }
            }
            tracing::info!(
                "Tool registry enabled with trust threshold {}",
                policy_config.tool_registry.trust_threshold
            );
            Some(Arc::new(registry))
        } else {
            None
        };

    // Initialize cluster backend (P3.4) if enabled.
    let cluster: Option<Arc<dyn sentinel_cluster::ClusterBackend>> =
        if policy_config.cluster.enabled && policy_config.cluster.backend == "redis" {
            #[cfg(feature = "redis-backend")]
            {
                let backend = sentinel_cluster::redis_backend::RedisBackend::new(
                    &policy_config.cluster.redis_url,
                    policy_config.cluster.redis_pool_size,
                    &policy_config.cluster.key_prefix,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to initialize Redis cluster backend: {}", e)
                })?;
                // SECURITY (FIND-044): Redact credentials from Redis URL before logging.
                // Redis URLs commonly embed passwords (redis://:pass@host:6379).
                let redacted_url = {
                    let raw = &policy_config.cluster.redis_url;
                    match url::Url::parse(raw) {
                        Ok(mut parsed) => {
                            if parsed.password().is_some() {
                                let _ = parsed.set_password(Some("***"));
                            }
                            parsed.to_string()
                        }
                        Err(_) => "***invalid-url***".to_string(),
                    }
                };
                tracing::info!(
                    "Cluster backend: Redis (url={}, pool_size={}, prefix={})",
                    redacted_url,
                    policy_config.cluster.redis_pool_size,
                    policy_config.cluster.key_prefix,
                );
                Some(Arc::new(backend))
            }
            #[cfg(not(feature = "redis-backend"))]
            {
                anyhow::bail!(
                    "Cluster backend 'redis' requires the 'redis-backend' feature. \
                     Build with: cargo build --features sentinel-cluster/redis-backend"
                );
            }
        } else if policy_config.cluster.enabled {
            // "local" backend with clustering enabled — use LocalBackend wrapper
            let backend = sentinel_cluster::local::LocalBackend::new(approvals.clone());
            tracing::info!("Cluster backend: local (single-instance mode)");
            Some(Arc::new(backend))
        } else {
            None
        };

    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(sentinel_server::PolicySnapshot {
            engine,
            policies,
            compliance_config: policy_config.compliance.clone(),
        })),
        audit,
        config_path: Arc::new(config),
        approvals: approvals.clone(),
        api_key,
        rate_limits,
        cors_origins,
        metrics: Arc::new(sentinel_server::Metrics::default()),
        trusted_proxies: Arc::new(trusted_proxies),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle,
        tool_registry,
        cluster,
        // RBAC configuration (Phase 2) — default: disabled, all requests get Admin
        // To enable: set rbac.enabled = true in config and optionally configure JWT
        rbac_config: sentinel_server::rbac::RbacConfig::default(),
        // Tenant configuration (Phase 3) — default: disabled, single-tenant mode
        // To enable: set tenant.enabled = true in config
        tenant_config: sentinel_server::tenant::TenantConfig::default(),
        tenant_store: None,
        // Idempotency key store (Phase 5) — default: disabled
        // To enable: set idempotency.enabled = true in config
        idempotency: sentinel_server::idempotency::IdempotencyStore::new(
            sentinel_server::idempotency::IdempotencyConfig::default(),
        ),

        // Phase 1 & 2 Security Managers — initialized from PolicyConfig
        task_state: if policy_config.async_tasks.enabled {
            Some(Arc::new(
                sentinel_mcp::task_state::TaskStateManager::with_config(
                    policy_config.async_tasks.max_concurrent_tasks,
                    policy_config.async_tasks.max_task_duration_secs,
                    policy_config.async_tasks.require_self_cancel,
                    policy_config.async_tasks.allow_cancellation.clone(),
                ),
            ))
        } else {
            None
        },
        auth_level: if policy_config.step_up_auth.enabled {
            Some(Arc::new(
                sentinel_mcp::auth_level::AuthLevelTracker::with_default_expiry(
                    std::time::Duration::from_secs(policy_config.step_up_auth.step_up_expiry_secs),
                ),
            ))
        } else {
            None
        },
        circuit_breaker: if policy_config.circuit_breaker.enabled {
            Some(Arc::new(
                sentinel_engine::circuit_breaker::CircuitBreakerManager::with_config(
                    policy_config.circuit_breaker.failure_threshold,
                    policy_config.circuit_breaker.success_threshold,
                    policy_config.circuit_breaker.open_duration_secs,
                    policy_config.circuit_breaker.half_open_max_requests,
                ),
            ))
        } else {
            None
        },
        deputy: if policy_config.deputy.enabled {
            Some(Arc::new(sentinel_engine::deputy::DeputyValidator::new(
                policy_config.deputy.max_delegation_depth,
            )))
        } else {
            None
        },
        shadow_agent: if policy_config.shadow_agent.enabled {
            Some(Arc::new(
                sentinel_mcp::shadow_agent::ShadowAgentDetector::new(
                    policy_config.shadow_agent.max_known_agents,
                ),
            ))
        } else {
            None
        },
        schema_lineage: if policy_config.schema_poisoning.enabled {
            Some(Arc::new(
                sentinel_mcp::schema_poisoning::SchemaLineageTracker::new(
                    policy_config.schema_poisoning.mutation_threshold,
                    policy_config.schema_poisoning.min_observations,
                    policy_config.schema_poisoning.max_tracked_schemas,
                ),
            ))
        } else {
            None
        },
        sampling_detector: if policy_config.sampling_detection.enabled {
            Some(Arc::new(
                sentinel_mcp::sampling_detector::SamplingDetector::with_config(
                    policy_config.sampling_detection.max_requests_per_window,
                    policy_config.sampling_detection.window_secs,
                    policy_config.sampling_detection.max_prompt_length,
                    policy_config.sampling_detection.allowed_models.clone(),
                    policy_config.sampling_detection.block_sensitive_patterns,
                ),
            ))
        } else {
            None
        },
        // Phase 6: Observability
        exec_graph_store: None,
        // Phase 8: ETDI Cryptographic Tool Security — initialized from PolicyConfig
        etdi_store: if policy_config.etdi.enabled {
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            Some(Arc::new(sentinel_mcp::etdi::EtdiStore::new(data_path)))
        } else {
            None
        },
        etdi_verifier: if policy_config.etdi.enabled {
            Some(Arc::new(sentinel_mcp::etdi::ToolSignatureVerifier::new(
                policy_config.etdi.allowed_signers.clone(),
            )))
        } else {
            None
        },
        etdi_attestations: if policy_config.etdi.enabled && policy_config.etdi.attestation.enabled {
            // AttestationChain requires the store, but we can't reference etdi_store here
            // because struct initialization is unordered. We create a new store Arc.
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            let store = Arc::new(sentinel_mcp::etdi::EtdiStore::new(data_path));
            Some(Arc::new(sentinel_mcp::etdi::AttestationChain::new(store)))
        } else {
            None
        },
        etdi_version_pins: if policy_config.etdi.enabled
            && policy_config.etdi.version_pinning.enabled
        {
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            let store = Arc::new(sentinel_mcp::etdi::EtdiStore::new(data_path));
            let blocking = policy_config.etdi.version_pinning.enforcement == "block";
            Some(Arc::new(sentinel_mcp::etdi::VersionPinManager::new(
                store, blocking,
            )))
        } else {
            None
        },
        // Phase 9: Memory Injection Defense (MINJA) — initialized from PolicyConfig
        memory_security: if policy_config.memory_security.enabled {
            Some(Arc::new(
                sentinel_mcp::memory_security::MemorySecurityManager::new(
                    policy_config.memory_security.clone(),
                ),
            ))
        } else {
            None
        },
        // Phase 10: Non-Human Identity (NHI) Lifecycle — initialized from PolicyConfig
        nhi: if policy_config.nhi.enabled {
            Some(Arc::new(sentinel_mcp::nhi::NhiManager::new(
                policy_config.nhi.clone(),
            )))
        } else {
            None
        },

        // Phase 15: AI Observability Platform Integration
        #[cfg(feature = "observability-exporters")]
        observability: match sentinel_server::observability::ObservabilityManager::new(
            &policy_config.observability,
        ) {
            Ok(Some(mgr)) => Some(Arc::new(mgr)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Failed to initialize observability: {}", e);
                None
            }
        },
        #[cfg(not(feature = "observability-exporters"))]
        observability: None,

        // Server Configuration (FIND-004, FIND-005)
        metrics_require_auth: policy_config.metrics_require_auth,
        audit_strict_mode: policy_config.audit.strict_mode,
    };

    tracing::info!("Audit log: {}", audit_path.display());
    tracing::info!("Approvals log: {}", approval_path.display());

    // Spawn periodic approval expiry task.
    // When clustering is enabled, uses the cluster backend (e.g., Redis TTL-based expiry).
    // Otherwise, uses the local ApprovalStore directly.
    let expiry_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let expired = match expiry_state.expire_stale_approvals().await {
                Ok(count) => count,
                Err(e) => {
                    tracing::warn!("Failed to expire stale approvals: {:?}", e);
                    0
                }
            };
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

    // Spawn periodic audit heartbeat task.
    // Logs heartbeat entries every SENTINEL_HEARTBEAT_INTERVAL seconds (default: 300).
    // IMPROVEMENT_PLAN 10.6: Heartbeat entries enable detection of log truncation/gaps.
    let heartbeat_interval: u64 = std::env::var("SENTINEL_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if heartbeat_interval > 0 {
        let heartbeat_audit = state.audit.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
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

    // Spawn periodic per-principal rate limit bucket cleanup (every 10 minutes)
    if state.rate_limits.per_principal.is_some() {
        let cleanup_limits = state.rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            interval.tick().await; // Skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(ref per_principal) = cleanup_limits.per_principal {
                    let before = per_principal.len();
                    per_principal.cleanup(std::time::Duration::from_secs(3600));
                    let removed = before.saturating_sub(per_principal.len());
                    if removed > 0 {
                        tracing::debug!(
                            "Cleaned up {} stale per-principal rate limit buckets ({} remaining)",
                            removed,
                            per_principal.len()
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

    // SIGHUP handler: reload policies from the config file without restarting.
    // This provides an operator-friendly mechanism for hot policy reload via
    // `kill -HUP <pid>` in addition to the existing file watcher and API endpoint.
    #[cfg(unix)]
    {
        let sighup_state = state.clone();
        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Failed to install SIGHUP handler: {}", e);
                        return;
                    }
                };
            tracing::info!("SIGHUP handler installed — send HUP to reload policies");
            loop {
                sighup.recv().await;
                tracing::info!("Received SIGHUP, reloading policies...");
                match sentinel_server::reload_policies_from_file(&sighup_state, "sighup").await {
                    Ok(count) => {
                        tracing::info!("SIGHUP: reloaded {} policies", count);
                        sentinel_server::metrics::set_policies_loaded(count as f64);
                    }
                    Err(e) => {
                        tracing::error!("SIGHUP: policy reload failed: {}", e);
                    }
                }
            }
        });
    }

    // SECURITY (FIND-033): Warn loudly when RBAC is disabled.
    // In the default config, all requests receive the Admin role, which grants
    // unrestricted access to all endpoints. This is intentional for development
    // but dangerous in production.
    if !state.rbac_config.enabled {
        tracing::warn!(
            "RBAC is DISABLED — all requests receive Admin privileges. \
             Set rbac.enabled=true in production to enforce access control."
        );
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

    let action = Action::new(tool, function, parameters);

    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;

    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    let mut engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        anyhow::anyhow!("Policy compilation errors: {}", msgs.join("; "))
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
    }
    let verdict = engine
        .evaluate_action(&action, &policies)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let (final_verdict, opa_decision) = if matches!(verdict, Verdict::Allow) {
        match sentinel_server::opa::OpaClient::new(&policy_config.opa)
            .map_err(|e| anyhow::anyhow!("Failed to initialize OPA client: {}", e))?
        {
            Some(opa_client) => {
                let input = sentinel_server::opa::OpaInput {
                    tool: action.tool.clone(),
                    function: action.function.clone(),
                    parameters: action.parameters.clone(),
                    principal: None,
                    session_id: None,
                    context: json!({
                        "source": "cli",
                        "sentinel_verdict": verdict.clone(),
                    }),
                };

                match opa_client.evaluate(&input).await {
                    Ok(decision) if decision.allow => (verdict, Some(decision)),
                    Ok(decision) => (
                        Verdict::Deny {
                            reason: decision
                                .reason
                                .clone()
                                .unwrap_or_else(|| "Denied by OPA policy".to_string()),
                        },
                        Some(decision),
                    ),
                    Err(e) if opa_client.fail_open() => {
                        tracing::warn!("OPA evaluation failed in fail-open mode: {}", e);
                        (verdict, None)
                    }
                    Err(e) => (
                        Verdict::Deny {
                            reason: format!("OPA evaluation failed (fail-closed): {}", e),
                        },
                        None,
                    ),
                }
            }
            None => (verdict, None),
        }
    } else {
        (verdict, None)
    };

    let output = serde_json::to_string_pretty(&json!({
        "action": action,
        "verdict": final_verdict,
        "opa_decision": opa_decision,
        "policies_loaded": policies.len(),
    }))?;

    println!("{}", output);
    Ok(())
}

async fn cmd_check(
    config: String,
    strict: bool,
    format: String,
    no_best_practices: bool,
    no_security_checks: bool,
) -> Result<()> {
    use sentinel_config::validation::PolicyValidator;

    // Load the configuration
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;

    // Build the validator with options
    let mut validator = PolicyValidator::new();
    if strict {
        validator = validator.strict();
    }
    if no_best_practices {
        validator = validator.with_best_practices(false);
    }
    if no_security_checks {
        validator = validator.with_security_checks(false);
    }

    // Run validation
    let result = validator.validate(&policy_config);

    // Output results
    if format == "json" {
        let output = serde_json::to_string_pretty(&result)?;
        println!("{}", output);
    } else {
        // Text format
        println!("{}", result.to_text());

        // Also show policy summary
        let policies = policy_config.to_policies();
        println!("\nPolicies loaded: {}", policies.len());
        for (i, p) in policies.iter().enumerate() {
            println!(
                "  [{}] id={:?} name={:?} type={} priority={}",
                i,
                p.id,
                p.name,
                match &p.policy_type {
                    sentinel_types::PolicyType::Allow => "Allow",
                    sentinel_types::PolicyType::Deny => "Deny",
                    sentinel_types::PolicyType::Conditional { .. } => "Conditional",
                    _ => "Unknown",
                },
                p.priority
            );
        }
    }

    // Exit with error code if invalid
    if result.has_errors() {
        anyhow::bail!(
            "Configuration validation failed with {} errors",
            result.summary.errors
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
            path_rules: p.path_rules.clone(),
            network_rules: p.network_rules.clone(),
        })
        .collect();

    let config = PolicyConfig {
        policies: rules,
        injection: Default::default(),
        dlp: Default::default(),
        rate_limit: Default::default(),
        audit: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        memory_tracking: Default::default(),
        elicitation: Default::default(),
        sampling: Default::default(),
        audit_export: Default::default(),
        max_path_decode_iterations: None,
        known_tool_names: Default::default(),
        tool_registry: Default::default(),
        allowed_origins: Default::default(),
        behavioral: Default::default(),
        data_flow: Default::default(),
        semantic_detection: Default::default(),
        cluster: Default::default(),
        async_tasks: Default::default(),
        resource_indicator: Default::default(),
        cimd: Default::default(),
        step_up_auth: Default::default(),
        circuit_breaker: Default::default(),
        deputy: Default::default(),
        shadow_agent: Default::default(),
        schema_poisoning: Default::default(),
        sampling_detection: Default::default(),
        cross_agent: Default::default(),
        advanced_threat: Default::default(),
        tls: Default::default(),
        spiffe: Default::default(),
        opa: Default::default(),
        threat_intel: Default::default(),
        jit_access: Default::default(),
        etdi: Default::default(),
        memory_security: Default::default(),
        nhi: Default::default(),
        rag_defense: Default::default(),
        a2a: Default::default(),
        observability: Default::default(),
        metrics_require_auth: true,
        limits: Default::default(),
        compliance: Default::default(),
        extension: Default::default(),
        transport: Default::default(),
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

    // Summary — exit codes:
    //   0 = all valid
    //   1 = chain or checkpoint integrity failure
    //   2 = duplicate entry IDs detected (possible replay attack)
    // Duplicates are checked first because they indicate a specific attack
    // vector (replay) that is actionable regardless of chain status.
    let chain_ok = chain_result.valid && cp_result.valid;
    println!();
    if has_duplicates {
        if chain_ok {
            println!(
                "Audit log integrity: FAILED (duplicate entry IDs detected — possible replay attack)"
            );
        } else {
            println!(
                "Audit log integrity: FAILED (chain/checkpoint invalid + duplicate entry IDs)"
            );
        }
        std::process::exit(2);
    } else if chain_ok {
        println!("Audit log integrity: VERIFIED");
    } else {
        println!("Audit log integrity: FAILED");
        std::process::exit(1);
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT (Ctrl+C) for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Failed to install Ctrl+C handler; SIGINT shutdown disabled"
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Failed to install SIGTERM handler; SIGTERM shutdown disabled"
                );
                std::future::pending::<()>().await;
            }
        }
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

fn cmd_hash_binary(path: String) -> Result<()> {
    let hash = sentinel_config::SupplyChainConfig::compute_hash(&path)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("\"{}\" = \"{}\"", path, hash);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ETDI Cryptographic Tool Security Commands
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_generate_key(
    private_key_path: std::path::PathBuf,
    public_key_path: std::path::PathBuf,
) -> Result<()> {
    use sentinel_mcp::etdi::ToolSigner;

    let signer =
        ToolSigner::generate().map_err(|e| anyhow::anyhow!("Key generation failed: {}", e))?;

    let private_key = signer.private_key_hex();
    let public_key = signer.public_key_hex();
    let fingerprint = signer.fingerprint();

    std::fs::write(&private_key_path, &private_key).context("Failed to write private key")?;
    std::fs::write(&public_key_path, public_key).context("Failed to write public key")?;

    println!("Generated Ed25519 keypair:");
    println!("  Private key: {}", private_key_path.display());
    println!("  Public key:  {}", public_key_path.display());
    println!("  Fingerprint: {}", fingerprint);
    println!();
    println!("Add the fingerprint to your config:");
    println!("  [etdi.allowed_signers]");
    println!("  fingerprints = [\"{}\"]", fingerprint);

    Ok(())
}

async fn cmd_sign_tool(
    tool: String,
    definition_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    signer_identity: Option<String>,
    output_path: std::path::PathBuf,
    expires_in_days: Option<u32>,
) -> Result<()> {
    use sentinel_mcp::etdi::ToolSigner;

    // Read private key
    let key_hex = std::fs::read_to_string(&key_path)
        .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;
    let key_hex = key_hex.trim();

    // Read definition
    let definition_json = std::fs::read_to_string(&definition_path)
        .with_context(|| format!("Failed to read definition: {}", definition_path.display()))?;
    let schema: serde_json::Value = serde_json::from_str(&definition_json)
        .with_context(|| format!("Invalid JSON in definition: {}", definition_path.display()))?;

    // Create signer
    let signer = ToolSigner::from_private_key_hex(key_hex, signer_identity)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    // Sign the tool
    let signature = signer.sign_tool(&tool, &schema, expires_in_days);

    // Write signature
    let signature_json = serde_json::to_string_pretty(&signature)?;
    std::fs::write(&output_path, &signature_json)
        .with_context(|| format!("Failed to write signature: {}", output_path.display()))?;

    println!("Signed tool '{}'", tool);
    println!("  Signature ID: {}", signature.signature_id);
    println!("  Algorithm:    {}", signature.algorithm);
    println!("  Signed at:    {}", signature.signed_at);
    if let Some(ref exp) = signature.expires_at {
        println!("  Expires at:   {}", exp);
    }
    println!("  Output:       {}", output_path.display());

    Ok(())
}

async fn cmd_verify_signature(
    tool: String,
    definition_path: std::path::PathBuf,
    signature_path: std::path::PathBuf,
) -> Result<()> {
    use sentinel_config::AllowedSignersConfig;
    use sentinel_mcp::etdi::ToolSignatureVerifier;

    // Read definition
    let definition_json = std::fs::read_to_string(&definition_path)
        .with_context(|| format!("Failed to read definition: {}", definition_path.display()))?;
    let schema: serde_json::Value = serde_json::from_str(&definition_json)
        .with_context(|| format!("Invalid JSON in definition: {}", definition_path.display()))?;

    // Read signature
    let sig_json = std::fs::read_to_string(&signature_path)
        .with_context(|| format!("Failed to read signature: {}", signature_path.display()))?;
    let signature: sentinel_types::ToolSignature = serde_json::from_str(&sig_json)
        .with_context(|| format!("Invalid signature JSON: {}", signature_path.display()))?;

    // Verify (trust all signers for CLI verification)
    let allowed = AllowedSignersConfig {
        fingerprints: signature.key_fingerprint.clone().into_iter().collect(),
        spiffe_ids: signature.signer_spiffe_id.clone().into_iter().collect(),
    };
    let verifier = ToolSignatureVerifier::new(allowed);
    let result = verifier.verify_tool_signature(&tool, &schema, &signature);

    println!("Verification result for tool '{}':", tool);
    println!("  Valid:         {}", result.valid);
    println!("  Signer trusted: {}", result.signer_trusted);
    println!("  Expired:       {}", result.expired);
    println!("  Message:       {}", result.message);

    if result.is_fully_verified() {
        println!();
        println!("VERIFICATION PASSED");
        Ok(())
    } else {
        println!();
        println!("VERIFICATION FAILED");
        anyhow::bail!("Signature verification failed: {}", result.message)
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
