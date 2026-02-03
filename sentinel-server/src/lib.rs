pub mod routes;

use arc_swap::ArcSwap;
use governor::{Quota, RateLimiter};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Policy, Verdict};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Per-category rate limiters using governor.
///
/// Each category can independently be enabled (Some) or disabled (None).
/// When enabled, the limiter enforces a global requests-per-second cap.
pub struct RateLimits {
    pub evaluate: Option<governor::DefaultDirectRateLimiter>,
    pub admin: Option<governor::DefaultDirectRateLimiter>,
    pub readonly: Option<governor::DefaultDirectRateLimiter>,
}

impl RateLimits {
    /// Create rate limiters from optional requests-per-second values.
    /// A value of None or 0 disables rate limiting for that category.
    pub fn new(
        evaluate_rps: Option<u32>,
        admin_rps: Option<u32>,
        readonly_rps: Option<u32>,
    ) -> Self {
        Self {
            evaluate: evaluate_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            admin: admin_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            readonly: readonly_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
        }
    }

    /// Create rate limits with all categories disabled (no rate limiting).
    pub fn disabled() -> Self {
        Self {
            evaluate: None,
            admin: None,
            readonly: None,
        }
    }
}

/// Operational metrics with atomic counters for lock-free updates.
pub struct Metrics {
    pub start_time: Instant,
    pub evaluations_total: AtomicU64,
    pub evaluations_allow: AtomicU64,
    pub evaluations_deny: AtomicU64,
    pub evaluations_require_approval: AtomicU64,
    pub evaluations_error: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            evaluations_total: AtomicU64::new(0),
            evaluations_allow: AtomicU64::new(0),
            evaluations_deny: AtomicU64::new(0),
            evaluations_require_approval: AtomicU64::new(0),
            evaluations_error: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn record_evaluation(&self, verdict: &sentinel_types::Verdict) {
        self.evaluations_total.fetch_add(1, Ordering::Relaxed);
        match verdict {
            sentinel_types::Verdict::Allow => {
                self.evaluations_allow.fetch_add(1, Ordering::Relaxed);
            }
            sentinel_types::Verdict::Deny { .. } => {
                self.evaluations_deny.fetch_add(1, Ordering::Relaxed);
            }
            sentinel_types::Verdict::RequireApproval { .. } => {
                self.evaluations_require_approval
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_error(&self) {
        self.evaluations_total.fetch_add(1, Ordering::Relaxed);
        self.evaluations_error.fetch_add(1, Ordering::Relaxed);
    }
}

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<ArcSwap<PolicyEngine>>,
    pub policies: Arc<ArcSwap<Vec<Policy>>>,
    pub audit: Arc<AuditLogger>,
    pub config_path: Arc<String>,
    pub approvals: Arc<ApprovalStore>,
    /// API key for authenticating mutating requests. None disables auth.
    pub api_key: Option<Arc<String>>,
    /// Per-category rate limiters. Arc-wrapped for Clone.
    pub rate_limits: Arc<RateLimits>,
    /// Allowed CORS origins. Empty vec means localhost only (strict default).
    /// Use `vec!["*".to_string()]` to allow any origin.
    pub cors_origins: Vec<String>,
    /// Operational metrics counters.
    pub metrics: Arc<Metrics>,
}

/// Reload policies from the config file and recompile the engine.
///
/// This is the shared reload logic used by both the HTTP `/reload` endpoint
/// and the file watcher. Returns the number of policies loaded on success.
pub async fn reload_policies_from_file(state: &AppState, source: &str) -> Result<usize, String> {
    let config_path = state.config_path.as_str();

    let policy_config = PolicyConfig::load_file(config_path)
        .map_err(|e| format!("Failed to load config from {}: {}", config_path, e))?;

    let mut new_policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut new_policies);
    let count = new_policies.len();

    // Update policies via ArcSwap (lock-free)
    state.policies.store(Arc::new(new_policies));

    // Recompile engine
    let policies = state.policies.load();
    match PolicyEngine::with_policies(false, &policies) {
        Ok(engine) => {
            state.engine.store(Arc::new(engine));
        }
        Err(errors) => {
            for e in &errors {
                tracing::warn!("Policy recompilation error: {}", e);
            }
            tracing::warn!("Keeping previous compiled engine due to errors");
        }
    }

    tracing::info!(
        "Reloaded {} policies from {} (source: {})",
        count,
        config_path,
        source
    );

    // Audit trail
    let action = sentinel_types::Action {
        tool: "sentinel".to_string(),
        function: "reload_policies".to_string(),
        parameters: serde_json::json!({
            "config_path": config_path,
            "policy_count": count,
            "source": source,
        }),
    };
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            serde_json::json!({"event": "policies_reloaded", "source": source}),
        )
        .await
    {
        tracing::warn!("Failed to audit policy reload: {}", e);
    }

    Ok(count)
}

/// Spawn a file watcher that reloads policies when the config file changes.
///
/// Uses the `notify` crate with debouncing (1 second) to avoid rapid reloads
/// from editors that write files in multiple steps (e.g., write temp + rename).
pub fn spawn_config_watcher(state: AppState) -> Result<(), String> {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let config_path = std::path::PathBuf::from(state.config_path.as_str());
    let watch_dir = config_path
        .parent()
        .ok_or_else(|| "Cannot determine parent directory of config file".to_string())?
        .to_path_buf();
    let config_filename = config_path
        .file_name()
        .ok_or_else(|| "Cannot determine config filename".to_string())?
        .to_os_string();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

    // Create the watcher on a std thread since notify's watcher
    // needs to live on a thread with an event loop
    let tx_clone = tx.clone();
    let config_filename_clone = config_filename.clone();
    std::thread::spawn(move || {
        let _rt = tokio::runtime::Handle::current();
        let tx = tx_clone;
        let config_filename = config_filename_clone;
        let config_filename_for_closure = config_filename.clone();

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            // Check if the event is for our config file
                            let is_config = event.paths.iter().any(|p| {
                                p.file_name() == Some(config_filename_for_closure.as_os_str())
                            });
                            if is_config {
                                let _ = tx.blocking_send(());
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch directory {:?}: {}", watch_dir, e);
            return;
        }

        tracing::info!(
            "Watching {:?} for changes to {:?}",
            watch_dir,
            config_filename
        );

        // Park this thread forever to keep the watcher alive
        loop {
            std::thread::park();
        }
    });

    // Spawn async task to receive change events and debounce reloads
    tokio::spawn(async move {
        let debounce = tokio::time::Duration::from_secs(1);
        let mut last_reload = tokio::time::Instant::now() - debounce;

        while rx.recv().await.is_some() {
            // Debounce: skip if we reloaded within the last second
            let now = tokio::time::Instant::now();
            if now.duration_since(last_reload) < debounce {
                continue;
            }

            // Small delay to let editors finish writing
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            // Drain any queued events
            while rx.try_recv().is_ok() {}

            match reload_policies_from_file(&state, "file_watcher").await {
                Ok(count) => {
                    tracing::info!("File watcher: reloaded {} policies", count);
                }
                Err(e) => {
                    tracing::warn!("File watcher: reload failed: {}", e);
                }
            }
            last_reload = tokio::time::Instant::now();
        }
    });

    Ok(())
}
