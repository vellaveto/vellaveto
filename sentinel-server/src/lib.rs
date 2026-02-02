pub mod routes;

use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::Policy;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<PolicyEngine>,
    pub policies: Arc<RwLock<Vec<Policy>>>,
    pub audit: Arc<AuditLogger>,
    pub config_path: Arc<String>,
}