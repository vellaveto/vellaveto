use serde::{Deserialize, Serialize};

use crate::default_true;

/// Elicitation interception configuration (MCP 2025-06-18, P2.2).
///
/// Controls whether server-initiated user prompts (`elicitation/create`)
/// are allowed, and what constraints apply. Elicitation can be used for
/// social engineering — servers may request passwords, API keys, or other
/// sensitive data via user prompts.
///
/// # TOML Example
///
/// ```toml
/// [elicitation]
/// enabled = true
/// blocked_field_types = ["password", "ssn", "secret"]
/// max_per_session = 5
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ElicitationConfig {
    /// Master toggle. Default: false (block all elicitation requests).
    #[serde(default)]
    pub enabled: bool,
    /// Field types that should be blocked (e.g. "password", "ssn").
    /// Matched case-insensitively against `type` and `format` fields
    /// in the elicitation schema.
    #[serde(default)]
    pub blocked_field_types: Vec<String>,
    /// Maximum elicitation requests per session. Default: 5.
    #[serde(default = "default_max_elicitation")]
    pub max_per_session: u32,
}

fn default_max_elicitation() -> u32 {
    5
}

impl Default for ElicitationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocked_field_types: Vec::new(),
            max_per_session: default_max_elicitation(),
        }
    }
}

/// Maximum number of blocked field types for elicitation config.
pub const MAX_BLOCKED_FIELD_TYPES: usize = 100;

/// Maximum length of a single blocked field type entry.
///
/// SECURITY (FIND-R125-002): Unbounded entries could waste memory during
/// case-insensitive matching in `schema_contains_field_type()`.
pub const MAX_BLOCKED_FIELD_TYPE_LENGTH: usize = 128;

impl ElicitationConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.blocked_field_types.len() > MAX_BLOCKED_FIELD_TYPES {
            return Err(format!(
                "elicitation.blocked_field_types exceeds {} entries",
                MAX_BLOCKED_FIELD_TYPES
            ));
        }
        // SECURITY (FIND-R125-002): Validate individual entry content.
        for (i, entry) in self.blocked_field_types.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "elicitation.blocked_field_types[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_BLOCKED_FIELD_TYPE_LENGTH {
                return Err(format!(
                    "elicitation.blocked_field_types[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_BLOCKED_FIELD_TYPE_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Use canonical has_dangerous_chars() to reject
            // both control chars AND Unicode format chars (zero-width, bidi, BOM).
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "elicitation.blocked_field_types[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

/// Sampling request policy configuration (P2.3).
///
/// Controls whether `sampling/createMessage` requests are allowed and
/// what constraints apply. Sampling allows MCP servers to request the
/// LLM to generate text, which can be an exfiltration vector if tool
/// output is included in the prompt.
///
/// # TOML Example
///
/// ```toml
/// [sampling]
/// enabled = true
/// allowed_models = ["claude-3-opus", "claude-3-sonnet"]
/// block_if_contains_tool_output = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SamplingConfig {
    /// Master toggle. Default: false (block all sampling requests).
    #[serde(default)]
    pub enabled: bool,
    /// Allowed model name prefixes. Empty = any model allowed.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Block if the prompt contains tool output. Default: true.
    /// This prevents data laundering where a malicious tool response
    /// plants instructions that get fed back to the LLM via sampling.
    #[serde(default = "default_true")]
    pub block_if_contains_tool_output: bool,
    /// Maximum sampling requests per session. Default: 10.
    ///
    /// SECURITY (FIND-R125-001): Without per-session rate limiting, a malicious
    /// MCP server can issue unlimited `sampling/createMessage` requests, unlike
    /// elicitation which has `max_per_session`.
    #[serde(default = "default_max_sampling")]
    pub max_per_session: u32,
}

fn default_max_sampling() -> u32 {
    10
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: true,
            max_per_session: default_max_sampling(),
        }
    }
}

/// Maximum number of allowed models for sampling config.
pub const MAX_ALLOWED_MODELS: usize = 100;

/// Maximum length of a single allowed model entry.
///
/// SECURITY (FIND-R125-003): Unbounded entries could waste memory during
/// model name matching in `inspect_sampling()`.
pub const MAX_ALLOWED_MODEL_LENGTH: usize = 256;

impl SamplingConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_models.len() > MAX_ALLOWED_MODELS {
            return Err(format!(
                "sampling.allowed_models exceeds {} entries",
                MAX_ALLOWED_MODELS
            ));
        }
        // SECURITY (FIND-R125-003): Validate individual entry content.
        for (i, entry) in self.allowed_models.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "sampling.allowed_models[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_ALLOWED_MODEL_LENGTH {
                return Err(format!(
                    "sampling.allowed_models[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_ALLOWED_MODEL_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "sampling.allowed_models[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 CONFIGURATION
// ═══════════════════════════════════════════════════

/// Default maximum concurrent async tasks.
fn default_max_concurrent_tasks() -> usize {
    100
}

/// Default maximum task duration (1 hour in seconds).
fn default_max_task_duration_secs() -> u64 {
    3600
}

/// Async task lifecycle configuration (MCP 2025-11-25).
///
/// Controls policies for async task creation, duration limits, and cancellation.
///
/// # TOML Example
///
/// ```toml
/// [async_tasks]
/// enabled = true
/// max_concurrent_tasks = 100
/// max_task_duration_secs = 3600
/// require_self_cancel = true
/// allow_cancellation = ["admin", "operator"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AsyncTaskConfig {
    /// Master toggle for async task policies. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum concurrent active tasks per session. Default: 100.
    /// Set to 0 for unlimited.
    #[serde(default = "default_max_concurrent_tasks")]
    pub max_concurrent_tasks: usize,

    /// Maximum task duration in seconds. Default: 3600 (1 hour).
    /// Set to 0 for unlimited.
    #[serde(default = "default_max_task_duration_secs")]
    pub max_task_duration_secs: u64,

    /// When true, only the agent that created a task can cancel it.
    /// When false, any agent in allow_cancellation can cancel.
    /// Default: true.
    #[serde(default = "default_true")]
    pub require_self_cancel: bool,

    /// Agent IDs or roles allowed to cancel any task.
    /// Only applies when require_self_cancel is false.
    #[serde(default)]
    pub allow_cancellation: Vec<String>,

    // ═══════════════════════════════════════════════════
    // Phase 11: Task Security Configuration
    // ═══════════════════════════════════════════════════
    /// Enable task state encryption (ChaCha20-Poly1305). Default: true.
    #[serde(default = "default_true")]
    pub encrypt_state: bool,

    /// Enable hash chain integrity tracking. Default: true.
    #[serde(default = "default_true")]
    pub enable_hash_chain: bool,

    /// Enable resume token authentication. Default: true.
    #[serde(default = "default_true")]
    pub require_resume_token: bool,

    /// Enable replay protection via nonce tracking. Default: true.
    #[serde(default = "default_true")]
    pub replay_protection: bool,

    /// Maximum nonces to track per task (FIFO eviction). Default: 1000.
    #[serde(default = "default_max_nonces")]
    pub max_nonces: usize,

    /// Enable checkpoint creation for long-running tasks. Default: false.
    #[serde(default)]
    pub enable_checkpoints: bool,

    /// Create checkpoint after this many state transitions. Default: 10.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: usize,

    /// Retention period for completed tasks in seconds. Default: 3600.
    #[serde(default = "default_task_retention_secs")]
    pub task_retention_secs: u64,
}

fn default_max_nonces() -> usize {
    1000
}

fn default_checkpoint_interval() -> usize {
    10
}

fn default_task_retention_secs() -> u64 {
    3600
}

impl Default for AsyncTaskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_tasks: default_max_concurrent_tasks(),
            max_task_duration_secs: default_max_task_duration_secs(),
            require_self_cancel: true,
            allow_cancellation: Vec::new(),
            encrypt_state: true,
            enable_hash_chain: true,
            require_resume_token: true,
            replay_protection: true,
            max_nonces: default_max_nonces(),
            enable_checkpoints: false,
            checkpoint_interval: default_checkpoint_interval(),
            task_retention_secs: default_task_retention_secs(),
        }
    }
}

/// Maximum number of allow_cancellation entries.
pub const MAX_ALLOW_CANCELLATION: usize = 100;

impl AsyncTaskConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_cancellation.len() > MAX_ALLOW_CANCELLATION {
            return Err(format!(
                "async_tasks.allow_cancellation exceeds {} entries",
                MAX_ALLOW_CANCELLATION
            ));
        }
        // SECURITY (FIND-R60-006, FIND-R158-001): Reject control + Unicode format
        // characters in allow_cancellation entries to prevent log injection and
        // policy bypass via invisible chars.
        for (i, entry) in self.allow_cancellation.iter().enumerate() {
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "async_tasks.allow_cancellation[{}] contains control or format characters",
                    i
                ));
            }
            if entry.is_empty() {
                return Err(format!("async_tasks.allow_cancellation[{}] is empty", i));
            }
        }
        // SECURITY (FIND-R137-006): Reject max_nonces=0 when replay_protection
        // is enabled — a zero-capacity nonce FIFO silently disables replay defense.
        if self.replay_protection && self.max_nonces == 0 {
            return Err(
                "async_tasks.max_nonces must be > 0 when replay_protection is enabled".to_string(),
            );
        }
        Ok(())
    }
}

/// RFC 8707 Resource Indicator configuration.
///
/// Validates OAuth tokens include the expected resource indicators.
/// Resource indicators bind tokens to specific API endpoints.
///
/// # TOML Example
///
/// ```toml
/// [resource_indicator]
/// enabled = true
/// allowed_resources = ["urn:vellaveto:*", "https://api.example.com/*"]
/// require_resource = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceIndicatorConfig {
    /// Enable resource indicator validation. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Patterns for allowed resource URIs (glob patterns supported).
    /// If non-empty, at least one pattern must match the token's resource.
    #[serde(default)]
    pub allowed_resources: Vec<String>,

    /// When true, deny if the token has no resource indicator.
    /// Default: false.
    #[serde(default)]
    pub require_resource: bool,
}

/// Maximum number of allowed resource patterns.
pub const MAX_ALLOWED_RESOURCES: usize = 100;

/// Maximum per-entry length for resource indicator patterns.
pub const MAX_RESOURCE_ENTRY_LENGTH: usize = 256;

impl ResourceIndicatorConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_resources.len() > MAX_ALLOWED_RESOURCES {
            return Err(format!(
                "resource_indicator.allowed_resources exceeds {} entries",
                MAX_ALLOWED_RESOURCES
            ));
        }
        // SECURITY (FIND-R137-003): Per-entry validation — empty string matches
        // everything, effectively disabling resource indicator enforcement.
        for (i, entry) in self.allowed_resources.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "resource_indicator.allowed_resources[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_RESOURCE_ENTRY_LENGTH {
                return Err(format!(
                    "resource_indicator.allowed_resources[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_RESOURCE_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "resource_indicator.allowed_resources[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

/// CIMD (Capability-Indexed Message Dispatch) configuration.
///
/// Controls capability requirements for MCP 2025-11-25 sessions.
///
/// # TOML Example
///
/// ```toml
/// [cimd]
/// enabled = true
/// required_capabilities = ["tools"]
/// blocked_capabilities = ["admin.dangerous"]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CimdConfig {
    /// Enable capability-based routing. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Capabilities that must be declared by the client.
    #[serde(default)]
    pub required_capabilities: Vec<String>,

    /// Capabilities that must NOT be declared by the client.
    #[serde(default)]
    pub blocked_capabilities: Vec<String>,
}

/// Maximum number of capability entries per list.
pub const MAX_CAPABILITIES: usize = 100;

/// Maximum per-entry length for capability strings.
pub const MAX_CAPABILITY_ENTRY_LENGTH: usize = 128;

impl CimdConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.required_capabilities.len() > MAX_CAPABILITIES {
            return Err(format!(
                "cimd.required_capabilities exceeds {} entries",
                MAX_CAPABILITIES
            ));
        }
        if self.blocked_capabilities.len() > MAX_CAPABILITIES {
            return Err(format!(
                "cimd.blocked_capabilities exceeds {} entries",
                MAX_CAPABILITIES
            ));
        }
        // SECURITY (FIND-R137-004): Per-entry validation — empty required
        // capability always matches; empty blocked capability blocks all.
        for (i, entry) in self.required_capabilities.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "cimd.required_capabilities[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_CAPABILITY_ENTRY_LENGTH {
                return Err(format!(
                    "cimd.required_capabilities[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_CAPABILITY_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "cimd.required_capabilities[{}] contains control or format characters",
                    i
                ));
            }
        }
        for (i, entry) in self.blocked_capabilities.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "cimd.blocked_capabilities[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_CAPABILITY_ENTRY_LENGTH {
                return Err(format!(
                    "cimd.blocked_capabilities[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_CAPABILITY_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "cimd.blocked_capabilities[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 STREAMABLE HTTP CONFIGURATION (Phase 30)
// ═══════════════════════════════════════════════════

/// Default maximum event ID length (bytes).
fn default_max_event_id_length() -> usize {
    128
}

/// Streamable HTTP configuration for MCP 2025-11-25 compliance.
///
/// Controls SSE resumability (GET /mcp + Last-Event-ID), strict tool name
/// validation, and retry directive overrides.
///
/// # TOML Example
///
/// ```toml
/// [streamable_http]
/// resumability_enabled = true
/// strict_tool_name_validation = false
/// max_event_id_length = 128
/// sse_retry_ms = 3000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamableHttpConfig {
    /// Enable SSE resumability (GET /mcp with Last-Event-ID). Default: false.
    #[serde(default)]
    pub resumability_enabled: bool,

    /// Enable strict MCP 2025-11-25 tool name validation. Default: false.
    /// When true, tool names must match `[a-zA-Z0-9_\-./]{1,64}` with no
    /// leading/trailing dots/slashes and no consecutive dots.
    #[serde(default)]
    pub strict_tool_name_validation: bool,

    /// Maximum length for SSE event IDs (bytes). Default: 128, max: 512.
    /// Event IDs exceeding this length are rejected (fail-closed).
    #[serde(default = "default_max_event_id_length")]
    pub max_event_id_length: usize,

    /// Override SSE `retry:` directive (milliseconds). Default: None.
    /// When Some, the proxy injects a `retry:` field on SSE responses.
    /// Range: 100–60000 ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_retry_ms: Option<u64>,
}

impl Default for StreamableHttpConfig {
    fn default() -> Self {
        Self {
            resumability_enabled: false,
            strict_tool_name_validation: false,
            max_event_id_length: default_max_event_id_length(),
            sse_retry_ms: None,
        }
    }
}

impl StreamableHttpConfig {
    /// Validate configuration values.
    ///
    /// - `max_event_id_length` must be in [1, 512]
    /// - `sse_retry_ms` must be in [100, 60000] when Some
    pub fn validate(&self) -> Result<(), String> {
        if self.max_event_id_length == 0 || self.max_event_id_length > 512 {
            return Err(format!(
                "max_event_id_length must be in [1, 512], got {}",
                self.max_event_id_length
            ));
        }
        if let Some(retry) = self.sse_retry_ms {
            if !(100..=60_000).contains(&retry) {
                return Err(format!(
                    "sse_retry_ms must be in [100, 60000], got {}",
                    retry
                ));
            }
        }
        Ok(())
    }
}

/// Default step-up auth expiry (30 minutes in seconds).
fn default_step_up_expiry_secs() -> u64 {
    1800
}

/// Step-up authentication configuration.
///
/// Allows policies to require stronger authentication for sensitive operations.
///
/// # TOML Example
///
/// ```toml
/// [step_up_auth]
/// enabled = true
/// step_up_expiry_secs = 1800
/// trigger_tools = ["delete_*", "transfer_*", "admin_*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StepUpAuthConfig {
    /// Enable step-up authentication. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// How long a step-up auth session is valid in seconds. Default: 1800 (30 min).
    #[serde(default = "default_step_up_expiry_secs")]
    pub step_up_expiry_secs: u64,

    /// Tool patterns that trigger step-up auth challenges.
    /// Supports glob patterns like "delete_*".
    #[serde(default)]
    pub trigger_tools: Vec<String>,

    /// Required auth level for triggered tools. Default: 3 (OAuthMfa).
    /// 0=None, 1=Basic, 2=OAuth, 3=OAuthMfa, 4=HardwareKey
    #[serde(default = "default_step_up_level")]
    pub required_level: u8,
}

fn default_step_up_level() -> u8 {
    3 // OAuthMfa
}

impl Default for StepUpAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            step_up_expiry_secs: default_step_up_expiry_secs(),
            trigger_tools: Vec::new(),
            required_level: default_step_up_level(),
        }
    }
}

/// Maximum number of trigger tools for step-up auth.
pub const MAX_TRIGGER_TOOLS: usize = 100;

/// Maximum per-entry length for trigger tool patterns.
pub const MAX_TRIGGER_TOOL_LENGTH: usize = 256;

impl StepUpAuthConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.trigger_tools.len() > MAX_TRIGGER_TOOLS {
            return Err(format!(
                "step_up_auth.trigger_tools exceeds {} entries",
                MAX_TRIGGER_TOOLS
            ));
        }
        if self.required_level > 4 {
            return Err(format!(
                "step_up_auth.required_level must be 0-4, got {}",
                self.required_level
            ));
        }
        // SECURITY (FIND-R137-005): Per-entry validation on trigger_tools.
        for (i, entry) in self.trigger_tools.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "step_up_auth.trigger_tools[{}] is empty",
                    i
                ));
            }
            if entry.len() > MAX_TRIGGER_TOOL_LENGTH {
                return Err(format!(
                    "step_up_auth.trigger_tools[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_TRIGGER_TOOL_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "step_up_auth.trigger_tools[{}] contains control or format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}
