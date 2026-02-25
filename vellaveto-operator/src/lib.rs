//! Vellaveto Kubernetes Operator
//!
//! Watches three Custom Resource Definitions and reconciles them against
//! the Vellaveto server REST API:
//!
//! - `VellavetoCluster` — manages server deployments (StatefulSet, Service, ConfigMap)
//! - `VellavetoPolicy` — declarative policy management with optional lifecycle versioning
//! - `VellavetoTenant` — declarative tenant management with quotas

pub mod client;
pub mod crd;
pub mod error;
pub mod reconciler;
