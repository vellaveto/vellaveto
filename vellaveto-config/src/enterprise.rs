use serde::{Deserialize, Serialize};

use crate::default_true;

// =============================================================================
// PHASE 5: ENTERPRISE HARDENING CONFIGURATION TYPES
// =============================================================================

/// TLS mode for the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// No TLS (plain HTTP).
    #[default]
    None,
    /// Server-side TLS only.
    Tls,
    /// Mutual TLS (client certificate required).
    Mtls,
}

/// TLS key exchange policy for post-quantum migration posture.
///
/// Controls how aggressively Vellaveto prefers or requires post-quantum/hybrid
/// key exchange groups during TLS negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsKexPolicy {
    /// Classical-only key exchange groups. Disables hybrid/PQ groups.
    #[default]
    ClassicalOnly,
    /// Prefer hybrid/PQ groups when supported by the TLS provider, but allow
    /// classical fallback for compatibility.
    HybridPreferred,
    /// Require hybrid/PQ groups when the provider exposes them. If the current
    /// provider has no hybrid/PQ support, Vellaveto falls back to classical and
    /// emits an explicit warning at runtime.
    HybridRequiredWhenSupported,
}

/// TLS/mTLS configuration for secure transport.
///
/// Enables server-side TLS or mutual TLS (mTLS) where clients must present
/// valid certificates signed by a trusted CA.
///
/// # TOML Example
///
/// ```toml
/// [tls]
/// mode = "mtls"
/// cert_path = "/etc/vellaveto/server.crt"
/// key_path = "/etc/vellaveto/server.key"
/// client_ca_path = "/etc/vellaveto/client-ca.pem"
/// require_client_cert = true
/// verify_client_cert = true
/// min_version = "1.3"
/// kex_policy = "hybrid_preferred"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// TLS mode: none, tls, or mtls. Default: none.
    #[serde(default)]
    pub mode: TlsMode,

    /// Path to the server certificate (PEM format).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,

    /// Path to the server private key (PEM format).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,

    /// Path to the CA certificate for verifying client certificates (mTLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ca_path: Option<String>,

    /// Require clients to present a certificate (mTLS). Default: false.
    #[serde(default)]
    pub require_client_cert: bool,

    /// Verify client certificates against the CA. Default: true when mTLS enabled.
    #[serde(default = "default_true")]
    pub verify_client_cert: bool,

    /// Minimum TLS version. Default: "1.2".
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,

    /// Key exchange policy for post-quantum migration.
    /// Default: `classical_only`.
    #[serde(default)]
    pub kex_policy: TlsKexPolicy,

    /// Allowed cipher suites (empty = use defaults).
    #[serde(default)]
    pub cipher_suites: Vec<String>,

    /// Enable OCSP stapling for certificate revocation checking. Default: false.
    #[serde(default)]
    pub ocsp_stapling: bool,

    /// CRL (Certificate Revocation List) path for revocation checking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_path: Option<String>,
}

/// Maximum number of cipher suites.
const MAX_CIPHER_SUITES: usize = 64;

fn default_min_tls_version() -> String {
    "1.2".to_string()
}

impl TlsConfig {
    /// Validate TLS configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cipher_suites.len() > MAX_CIPHER_SUITES {
            return Err(format!(
                "tls.cipher_suites count {} exceeds maximum {}",
                self.cipher_suites.len(),
                MAX_CIPHER_SUITES
            ));
        }
        let valid_versions = ["1.2", "1.3"];
        if !valid_versions.contains(&self.min_version.as_str()) {
            return Err(format!(
                "tls.min_version must be \"1.2\" or \"1.3\" (got: \"{}\")",
                self.min_version.chars().take(16).collect::<String>()
            ));
        }
        if self.mode == TlsMode::Mtls && self.client_ca_path.is_none() {
            return Err(
                "tls.mode = mtls requires tls.client_ca_path to be set".to_string(),
            );
        }
        if self.mode != TlsMode::None && self.cert_path.is_none() {
            return Err("tls.cert_path required when TLS is enabled".to_string());
        }
        if self.mode != TlsMode::None && self.key_path.is_none() {
            return Err("tls.key_path required when TLS is enabled".to_string());
        }
        for suite in &self.cipher_suites {
            if suite.chars().any(|c| c.is_control()) {
                return Err("tls.cipher_suites contains control characters".to_string());
            }
        }
        Ok(())
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::None,
            cert_path: None,
            key_path: None,
            client_ca_path: None,
            require_client_cert: false,
            verify_client_cert: default_true(),
            min_version: default_min_tls_version(),
            kex_policy: TlsKexPolicy::ClassicalOnly,
            cipher_suites: Vec::new(),
            ocsp_stapling: false,
            crl_path: None,
        }
    }
}

/// SPIFFE/SPIRE workload identity configuration.
///
/// Integrates with SPIFFE (Secure Production Identity Framework for Everyone)
/// for zero-trust workload identity. When enabled, client identities are
/// extracted from X.509 SVIDs (SPIFFE Verifiable Identity Documents).
///
/// # TOML Example
///
/// ```toml
/// [spiffe]
/// enabled = true
/// trust_domain = "example.org"
/// workload_socket = "unix:///var/run/spire/agent.sock"
/// allowed_spiffe_ids = [
///     "spiffe://example.org/agent/frontend",
///     "spiffe://example.org/agent/backend",
/// ]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpiffeConfig {
    /// Enable SPIFFE identity extraction. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// SPIFFE trust domain (e.g., "example.org").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

    /// Path to SPIRE agent workload API socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_socket: Option<String>,

    /// Allowed SPIFFE IDs. If non-empty, only these identities are permitted.
    #[serde(default)]
    pub allowed_spiffe_ids: Vec<String>,

    /// Map SPIFFE IDs to Vellaveto roles for RBAC.
    #[serde(default)]
    pub id_to_role: std::collections::HashMap<String, String>,

    /// Cache SVID validation results. Default: 60 seconds.
    #[serde(default = "default_svid_cache_ttl")]
    pub svid_cache_ttl_secs: u64,
}

/// Maximum number of allowed SPIFFE IDs.
const MAX_SPIFFE_IDS: usize = 1000;

/// Maximum number of SPIFFE ID-to-role mappings.
const MAX_SPIFFE_ROLE_MAPPINGS: usize = 1000;

impl SpiffeConfig {
    /// Validate SPIFFE configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_spiffe_ids.len() > MAX_SPIFFE_IDS {
            return Err(format!(
                "spiffe.allowed_spiffe_ids count {} exceeds maximum {}",
                self.allowed_spiffe_ids.len(),
                MAX_SPIFFE_IDS
            ));
        }
        if self.id_to_role.len() > MAX_SPIFFE_ROLE_MAPPINGS {
            return Err(format!(
                "spiffe.id_to_role count {} exceeds maximum {}",
                self.id_to_role.len(),
                MAX_SPIFFE_ROLE_MAPPINGS
            ));
        }
        for sid in &self.allowed_spiffe_ids {
            if sid.chars().any(|c| c.is_control()) {
                return Err("spiffe.allowed_spiffe_ids contains control characters".to_string());
            }
        }
        if let Some(ref domain) = self.trust_domain {
            if domain.chars().any(|c| c.is_control()) {
                return Err("spiffe.trust_domain contains control characters".to_string());
            }
        }
        // SECURITY (BUG-R110-003): Fail-closed when enabled without trust_domain
        if self.enabled && self.trust_domain.is_none() {
            return Err(
                "spiffe.trust_domain is required when spiffe.enabled is true".to_string(),
            );
        }
        Ok(())
    }
}

fn default_svid_cache_ttl() -> u64 {
    60
}

/// OPA (Open Policy Agent) integration configuration.
///
/// Delegates complex policy decisions to an external OPA server. Vellaveto
/// sends evaluation context to OPA and uses the response to inform verdicts.
///
/// # TOML Example
///
/// ```toml
/// [opa]
/// enabled = true
/// endpoint = "http://opa:8181/v1/data/vellaveto/allow"
/// decision_path = "result.allow"
/// cache_ttl_secs = 60
/// timeout_ms = 100
/// fail_open = false
/// require_https = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpaConfig {
    /// Enable OPA integration. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// OPA server endpoint URL (e.g., "http://opa:8181/v1/data/vellaveto/allow").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Require HTTPS for remote OPA endpoint connections.
    /// When true, `opa.endpoint` must use `https://`.
    /// Default: true for security. Set to false only for localhost testing.
    #[serde(default = "default_true")]
    pub require_https: bool,

    /// JSON path to extract the decision from OPA response. Default: "result".
    #[serde(default = "default_opa_decision_path")]
    pub decision_path: String,

    /// Cache OPA decisions for this many seconds. Default: 60.
    /// Set to 0 to disable caching.
    #[serde(default = "default_opa_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Timeout for OPA requests in milliseconds. Default: 100.
    #[serde(default = "default_opa_timeout")]
    pub timeout_ms: u64,

    /// Fail-open if OPA is unreachable. Default: false (fail-closed).
    /// WARNING: Setting to true may allow requests when OPA is down.
    /// SECURITY: Requires `fail_open_acknowledged = true` to take effect.
    #[serde(default)]
    pub fail_open: bool,

    /// Explicit acknowledgment required to enable fail_open.
    /// This forces operators to consciously accept the security risk.
    /// Set to true only if you understand that OPA unavailability will
    /// allow ALL requests when fail_open is also true.
    #[serde(default)]
    pub fail_open_acknowledged: bool,

    /// Maximum number of retry attempts for transient failures. Default: 3.
    /// Set to 0 to disable retries.
    #[serde(default = "default_opa_max_retries")]
    pub max_retries: u32,

    /// Initial backoff duration in milliseconds for retries. Default: 50.
    /// Backoff doubles on each retry (exponential backoff).
    #[serde(default = "default_opa_retry_backoff_ms")]
    pub retry_backoff_ms: u64,

    /// Additional headers to send with OPA requests.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Path to OPA policy bundle for local evaluation (alternative to remote OPA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<String>,

    /// Include full evaluation trace in audit log. Default: false.
    #[serde(default)]
    pub audit_decisions: bool,

    /// Maximum number of decisions to cache. Default: 1000.
    /// Higher values improve hit rate but use more memory.
    #[serde(default = "default_opa_cache_size")]
    pub cache_size: usize,
}

/// Maximum number of OPA headers.
const MAX_OPA_HEADERS: usize = 50;

/// Maximum OPA cache size.
const MAX_OPA_CACHE_SIZE: usize = 1_000_000;

impl OpaConfig {
    /// Validate OPA configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.headers.len() > MAX_OPA_HEADERS {
            return Err(format!(
                "opa.headers count {} exceeds maximum {}",
                self.headers.len(),
                MAX_OPA_HEADERS
            ));
        }
        if self.cache_size > MAX_OPA_CACHE_SIZE {
            return Err(format!(
                "opa.cache_size {} exceeds maximum {}",
                self.cache_size, MAX_OPA_CACHE_SIZE
            ));
        }
        if let Some(ref endpoint) = self.endpoint {
            if endpoint.chars().any(|c| c.is_control()) {
                return Err("opa.endpoint contains control characters".to_string());
            }
            // SECURITY (BUG-R110-004, FIND-R114-005): Use proper URL parsing for localhost check.
            // starts_with("http://localhost") would match http://localhost.evil.com.
            // is_http_localhost_url rejects non-HTTP schemes like ftp://localhost.
            if self.require_https
                && !endpoint.starts_with("https://")
                && !crate::validation::is_http_localhost_url(endpoint)
            {
                return Err(format!(
                    "opa.endpoint must use https:// when require_https is true (got: {})",
                    endpoint.chars().take(64).collect::<String>()
                ));
            }
        }
        if self.decision_path.chars().any(|c| c.is_control()) {
            return Err("opa.decision_path contains control characters".to_string());
        }
        if self.fail_open && !self.fail_open_acknowledged {
            tracing::warn!("SECURITY: opa.fail_open=true without fail_open_acknowledged — fail_open will be ignored");
        }
        // SECURITY (BUG-R110-002): Fail-closed when enabled without endpoint or bundle
        if self.enabled && self.endpoint.is_none() && self.bundle_path.is_none() {
            return Err(
                "opa.endpoint or opa.bundle_path is required when opa.enabled is true".to_string(),
            );
        }
        Ok(())
    }
}

fn default_opa_cache_size() -> usize {
    1000
}

impl Default for OpaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            // SECURITY: Default to true for production safety.
            // Policy decisions should be encrypted in transit.
            require_https: true,
            decision_path: default_opa_decision_path(),
            cache_ttl_secs: default_opa_cache_ttl(),
            timeout_ms: default_opa_timeout(),
            fail_open: false,
            fail_open_acknowledged: false,
            max_retries: default_opa_max_retries(),
            retry_backoff_ms: default_opa_retry_backoff_ms(),
            headers: std::collections::HashMap::new(),
            bundle_path: None,
            audit_decisions: false,
            cache_size: default_opa_cache_size(),
        }
    }
}

fn default_opa_decision_path() -> String {
    "result".to_string()
}

fn default_opa_cache_ttl() -> u64 {
    60
}

fn default_opa_timeout() -> u64 {
    100
}

fn default_opa_max_retries() -> u32 {
    3
}

fn default_opa_retry_backoff_ms() -> u64 {
    50
}

/// Threat intelligence feed provider type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatIntelProvider {
    /// STIX/TAXII feed.
    Taxii,
    /// MISP (Malware Information Sharing Platform).
    Misp,
    /// Custom HTTP endpoint returning IOCs in JSON.
    Custom,
}

/// Threat intelligence feed configuration.
///
/// Enriches security decisions with external threat intelligence feeds.
/// Supports STIX/TAXII, MISP, and custom providers.
///
/// # TOML Example
///
/// ```toml
/// [threat_intel]
/// enabled = true
/// provider = "taxii"
/// endpoint = "https://taxii.example.com/taxii2/"
/// collection_id = "indicators"
/// api_key = "${TAXII_API_KEY}"
/// refresh_interval_secs = 3600
/// cache_ttl_secs = 86400
/// ```
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence integration. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Provider type (taxii, misp, custom).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ThreatIntelProvider>,

    /// Feed endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// TAXII collection ID or MISP event filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<String>,

    /// API key for authentication (supports ${ENV_VAR} expansion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// How often to refresh the feed in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_threat_refresh")]
    pub refresh_interval_secs: u64,

    /// Cache IOCs for this many seconds. Default: 86400 (24 hours).
    #[serde(default = "default_threat_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// IOC types to match against (ip, domain, url, hash). Empty = all.
    #[serde(default)]
    pub ioc_types: Vec<String>,

    /// Action when IOC matched: "deny", "alert", "require_approval".
    #[serde(default = "default_threat_action")]
    pub on_match: String,

    /// Minimum confidence score (0-100) for IOC to be actionable. Default: 70.
    #[serde(default = "default_threat_confidence")]
    pub min_confidence: u8,
}

/// SECURITY (IMP-R102-003): Custom Debug impl to redact api_key.
impl std::fmt::Debug for ThreatIntelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreatIntelConfig")
            .field("enabled", &self.enabled)
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("collection_id", &self.collection_id)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("refresh_interval_secs", &self.refresh_interval_secs)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .field("ioc_types", &self.ioc_types)
            .field("on_match", &self.on_match)
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

/// Maximum number of IOC types.
const MAX_IOC_TYPES: usize = 100;

impl ThreatIntelConfig {
    /// Validate threat intelligence configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.ioc_types.len() > MAX_IOC_TYPES {
            return Err(format!(
                "threat_intel.ioc_types count {} exceeds maximum {}",
                self.ioc_types.len(),
                MAX_IOC_TYPES
            ));
        }
        let valid_actions = ["deny", "alert", "require_approval"];
        if !valid_actions.contains(&self.on_match.to_lowercase().as_str()) {
            return Err(format!(
                "threat_intel.on_match must be one of {:?} (got: \"{}\")",
                valid_actions,
                self.on_match.chars().take(64).collect::<String>()
            ));
        }
        if let Some(ref endpoint) = self.endpoint {
            if endpoint.chars().any(|c| c.is_control()) {
                return Err(
                    "threat_intel.endpoint contains control characters".to_string(),
                );
            }
        }
        for ioc in &self.ioc_types {
            if ioc.chars().any(|c| c.is_control()) {
                return Err(
                    "threat_intel.ioc_types contains control characters".to_string(),
                );
            }
        }
        // SECURITY (BUG-R110-012): Fail-closed when enabled without endpoint
        if self.enabled && self.endpoint.is_none() {
            return Err(
                "threat_intel.endpoint is required when threat_intel.enabled is true".to_string(),
            );
        }
        Ok(())
    }
}

fn default_threat_refresh() -> u64 {
    3600
}

fn default_threat_cache_ttl() -> u64 {
    86400
}

fn default_threat_action() -> String {
    "deny".to_string()
}

fn default_threat_confidence() -> u8 {
    70
}

/// Just-In-Time (JIT) access configuration.
///
/// Enables temporary elevated permissions with automatic expiry. JIT access
/// integrates with the human-in-the-loop approval flow.
///
/// # TOML Example
///
/// ```toml
/// [jit_access]
/// enabled = true
/// default_ttl_secs = 3600
/// max_ttl_secs = 86400
/// require_approval = true
/// require_reason = true
/// allowed_elevations = ["admin", "operator"]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JitAccessConfig {
    /// Enable JIT access. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Default TTL for JIT tokens in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_jit_ttl")]
    pub default_ttl_secs: u64,

    /// Maximum TTL for JIT tokens in seconds. Default: 86400 (24 hours).
    #[serde(default = "default_jit_max_ttl")]
    pub max_ttl_secs: u64,

    /// Require human approval for JIT access requests. Default: true.
    #[serde(default = "default_true")]
    pub require_approval: bool,

    /// Require a reason/justification for JIT access. Default: true.
    #[serde(default = "default_true")]
    pub require_reason: bool,

    /// Allowed elevation levels that can be requested.
    #[serde(default)]
    pub allowed_elevations: Vec<String>,

    /// Maximum concurrent JIT sessions per principal. Default: 3.
    #[serde(default = "default_jit_max_sessions")]
    pub max_sessions_per_principal: u32,

    /// Automatically revoke JIT access on security events. Default: true.
    #[serde(default = "default_true")]
    pub auto_revoke_on_alert: bool,

    /// Notification webhook for JIT access events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_webhook: Option<String>,

    /// Require re-authentication for JIT elevation. Default: false.
    #[serde(default)]
    pub require_reauth: bool,
}

/// Maximum number of allowed JIT elevations.
const MAX_JIT_ELEVATIONS: usize = 50;

impl JitAccessConfig {
    /// Validate JIT access configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_elevations.len() > MAX_JIT_ELEVATIONS {
            return Err(format!(
                "jit_access.allowed_elevations count {} exceeds maximum {}",
                self.allowed_elevations.len(),
                MAX_JIT_ELEVATIONS
            ));
        }
        if self.default_ttl_secs > self.max_ttl_secs {
            return Err(format!(
                "jit_access.default_ttl_secs ({}) exceeds max_ttl_secs ({})",
                self.default_ttl_secs, self.max_ttl_secs
            ));
        }
        if let Some(ref webhook) = self.notification_webhook {
            // SECURITY (BUG-R110-006, FIND-R114-005): Use proper URL parsing for localhost check.
            // is_http_localhost_url rejects non-HTTP schemes like ftp://localhost.
            if !webhook.starts_with("https://") && !crate::validation::is_http_localhost_url(webhook) {
                return Err(format!(
                    "jit_access.notification_webhook must use https:// (got: {})",
                    webhook.chars().take(64).collect::<String>()
                ));
            }
            if webhook.chars().any(|c| c.is_control()) {
                return Err(
                    "jit_access.notification_webhook contains control characters".to_string(),
                );
            }
        }
        for elev in &self.allowed_elevations {
            if elev.chars().any(|c| c.is_control()) {
                return Err(
                    "jit_access.allowed_elevations contains control characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

fn default_jit_ttl() -> u64 {
    3600
}

fn default_jit_max_ttl() -> u64 {
    86400
}

fn default_jit_max_sessions() -> u32 {
    3
}
