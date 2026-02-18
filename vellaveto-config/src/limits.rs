//! Runtime limits configuration — memory bounds, timeouts, and chain lengths.

use serde::{Deserialize, Serialize};

/// Runtime limits configuration for proxy and MCP processing.
///
/// Makes previously hardcoded constants configurable, allowing operators to
/// tune memory bounds, timeouts, and chain lengths for their deployment.
///
/// # TOML Example
///
/// ```toml
/// [limits]
/// max_response_body_bytes = 10485760   # 10 MB
/// max_sse_event_bytes = 1048576        # 1 MB
/// max_jsonrpc_line_bytes = 1048576     # 1 MB
/// max_call_chain_length = 20
/// call_chain_max_age_secs = 300        # 5 minutes
/// request_timeout_secs = 30
/// max_action_history = 100
/// max_pending_tool_calls = 256
/// max_call_chain_header_bytes = 8192   # 8 KB
/// max_trace_header_bytes = 4096        # 4 KB
/// max_jsonrpc_id_key_len = 256
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum response body size in bytes. Default: 10 MB.
    /// Responses exceeding this are rejected to prevent OOM.
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,

    /// Maximum size of a single SSE event's data payload. Default: 1 MB.
    /// Events larger than this are flagged as suspicious (R18-SSE-OVERSIZE).
    #[serde(default = "default_max_sse_event_bytes")]
    pub max_sse_event_bytes: usize,

    /// Maximum JSON-RPC line size in bytes for framing. Default: 1 MB.
    /// Lines exceeding this are truncated with an error logged.
    #[serde(default = "default_max_jsonrpc_line_bytes")]
    pub max_jsonrpc_line_bytes: usize,

    /// Maximum call chain length for FIND-015 protection. Default: 20.
    /// Requests with longer chains are rejected as potential attack indicators.
    #[serde(default = "default_max_call_chain_length")]
    pub max_call_chain_length: usize,

    /// Maximum age of call chain entries in seconds. Default: 300 (5 minutes).
    /// Entries older than this are evicted to prevent stale chain accumulation.
    #[serde(default = "default_call_chain_max_age_secs")]
    pub call_chain_max_age_secs: u64,

    /// Request timeout in seconds for upstream requests. Default: 30.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    /// Maximum action history per session. Default: 100.
    /// Older actions are evicted when the limit is reached.
    #[serde(default = "default_max_action_history")]
    pub max_action_history: usize,

    /// Maximum pending tool call IDs tracked per session. Default: 256.
    /// Prevents memory exhaustion from malicious tool call floods.
    #[serde(default = "default_max_pending_tool_calls")]
    pub max_pending_tool_calls: usize,

    /// Maximum call chain header size in bytes. Default: 8192.
    /// Headers exceeding this are rejected.
    #[serde(default = "default_max_call_chain_header_bytes")]
    pub max_call_chain_header_bytes: usize,

    /// Maximum trace header size in bytes. Default: 4096.
    #[serde(default = "default_max_trace_header_bytes")]
    pub max_trace_header_bytes: usize,

    /// Maximum JSON-RPC ID key length. Default: 256.
    /// IDs longer than this are rejected.
    #[serde(default = "default_max_jsonrpc_id_key_len")]
    pub max_jsonrpc_id_key_len: usize,
}

fn default_max_response_body_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_max_sse_event_bytes() -> usize {
    1024 * 1024 // 1 MB
}

fn default_max_jsonrpc_line_bytes() -> usize {
    1024 * 1024 // 1 MB
}

fn default_max_call_chain_length() -> usize {
    20
}

fn default_call_chain_max_age_secs() -> u64 {
    300 // 5 minutes
}

fn default_request_timeout_secs() -> u64 {
    30
}

fn default_max_action_history() -> usize {
    100
}

fn default_max_pending_tool_calls() -> usize {
    256
}

fn default_max_call_chain_header_bytes() -> usize {
    8192
}

fn default_max_trace_header_bytes() -> usize {
    4096
}

fn default_max_jsonrpc_id_key_len() -> usize {
    256
}

/// 1 GB -- generous upper bound for any byte-size limit.
pub const MAX_BYTES_LIMIT: usize = 1024 * 1024 * 1024;

/// 1 hour -- generous upper bound for timeout/age fields.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// 1 million -- generous upper bound for count limits.
pub const MAX_COUNT_LIMIT: usize = 1_000_000;

impl LimitsConfig {
    /// Validate that limits are within safe bounds.
    ///
    /// SECURITY (FIND-032): Zero values could disable safety constraints (e.g.,
    /// `max_response_body_bytes = 0` rejects all responses, `request_timeout_secs = 0`
    /// could break timeout logic).
    ///
    /// SECURITY (FIND-036): Excessively large values could cause OOM via
    /// `Vec::with_capacity()` or disable rate protections.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_response_body_bytes == 0 || self.max_response_body_bytes > MAX_BYTES_LIMIT {
            return Err(format!(
                "limits.max_response_body_bytes must be between 1 and {} (1 GB)",
                MAX_BYTES_LIMIT
            ));
        }
        if self.max_sse_event_bytes == 0 || self.max_sse_event_bytes > MAX_BYTES_LIMIT {
            return Err(format!(
                "limits.max_sse_event_bytes must be between 1 and {} (1 GB)",
                MAX_BYTES_LIMIT
            ));
        }
        if self.max_jsonrpc_line_bytes == 0 || self.max_jsonrpc_line_bytes > MAX_BYTES_LIMIT {
            return Err(format!(
                "limits.max_jsonrpc_line_bytes must be between 1 and {} (1 GB)",
                MAX_BYTES_LIMIT
            ));
        }
        if self.max_call_chain_length == 0 || self.max_call_chain_length > MAX_COUNT_LIMIT {
            return Err(format!(
                "limits.max_call_chain_length must be between 1 and {}",
                MAX_COUNT_LIMIT
            ));
        }
        if self.call_chain_max_age_secs == 0 || self.call_chain_max_age_secs > MAX_TIMEOUT_SECS {
            return Err(format!(
                "limits.call_chain_max_age_secs must be between 1 and {} (1 hour)",
                MAX_TIMEOUT_SECS
            ));
        }
        if self.request_timeout_secs == 0 || self.request_timeout_secs > MAX_TIMEOUT_SECS {
            return Err(format!(
                "limits.request_timeout_secs must be between 1 and {} (1 hour)",
                MAX_TIMEOUT_SECS
            ));
        }
        if self.max_action_history == 0 || self.max_action_history > MAX_COUNT_LIMIT {
            return Err(format!(
                "limits.max_action_history must be between 1 and {}",
                MAX_COUNT_LIMIT
            ));
        }
        if self.max_pending_tool_calls == 0 || self.max_pending_tool_calls > MAX_COUNT_LIMIT {
            return Err(format!(
                "limits.max_pending_tool_calls must be between 1 and {}",
                MAX_COUNT_LIMIT
            ));
        }
        if self.max_call_chain_header_bytes == 0
            || self.max_call_chain_header_bytes > MAX_BYTES_LIMIT
        {
            return Err(format!(
                "limits.max_call_chain_header_bytes must be between 1 and {} (1 GB)",
                MAX_BYTES_LIMIT
            ));
        }
        if self.max_trace_header_bytes == 0 || self.max_trace_header_bytes > MAX_BYTES_LIMIT {
            return Err(format!(
                "limits.max_trace_header_bytes must be between 1 and {} (1 GB)",
                MAX_BYTES_LIMIT
            ));
        }
        if self.max_jsonrpc_id_key_len == 0 || self.max_jsonrpc_id_key_len > MAX_COUNT_LIMIT {
            return Err(format!(
                "limits.max_jsonrpc_id_key_len must be between 1 and {}",
                MAX_COUNT_LIMIT
            ));
        }
        Ok(())
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_response_body_bytes: default_max_response_body_bytes(),
            max_sse_event_bytes: default_max_sse_event_bytes(),
            max_jsonrpc_line_bytes: default_max_jsonrpc_line_bytes(),
            max_call_chain_length: default_max_call_chain_length(),
            call_chain_max_age_secs: default_call_chain_max_age_secs(),
            request_timeout_secs: default_request_timeout_secs(),
            max_action_history: default_max_action_history(),
            max_pending_tool_calls: default_max_pending_tool_calls(),
            max_call_chain_header_bytes: default_max_call_chain_header_bytes(),
            max_trace_header_bytes: default_max_trace_header_bytes(),
            max_jsonrpc_id_key_len: default_max_jsonrpc_id_key_len(),
        }
    }
}
