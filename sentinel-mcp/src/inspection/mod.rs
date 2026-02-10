//! Shared response inspection for prompt injection detection and DLP scanning.
//!
//! This module provides pattern-based detection of:
//! - **Prompt injection attempts** in MCP tool responses (OWASP MCP06)
//! - **Secret exfiltration** via tool call parameters and responses (OWASP ASI03)
//! - **Tool description attacks** in `tools/list` responses (OWASP ASI02)
//! - **Multimodal injection** via images and documents (requires `multimodal` feature)
//!
//! Both the stdio proxy and HTTP proxy use these functions to scan content
//! before relaying it to/from the agent.
//!
//! # Modules
//!
//! - [`injection`] - Prompt injection pattern detection
//! - [`dlp`] - Data Loss Prevention / secret scanning
//! - [`tool_description`] - Tool description injection scanning
//! - [`multimodal`] - Image/document injection detection (feature-gated)

pub mod dlp;
pub mod injection;
pub mod multimodal;
pub mod tool_description;

// Re-export all public items from submodules for backwards compatibility
pub use dlp::{
    active_pattern_count, is_dlp_available, scan_notification_for_secrets,
    scan_parameters_for_secrets, scan_response_for_secrets, scan_text_for_secrets,
    validate_dlp_patterns, DlpFinding, DLP_PATTERNS,
};
pub use injection::{
    inspect_for_injection, sanitize_for_injection_scan, scan_notification_for_injection,
    scan_response_for_injection, InjectionScanner, DEFAULT_INJECTION_PATTERNS,
    INJECTION_DETECTION_UNAVAILABLE,
};
pub use tool_description::{
    collect_schema_descriptions, scan_tool_descriptions, scan_tool_descriptions_with_scanner,
    ToolDescriptionFinding,
};

// Multimodal content safety
pub use multimodal::{
    scan_blob_for_injection, ContentType, MultimodalConfig, MultimodalError,
    MultimodalInjectionFinding, MultimodalScanResult, MultimodalScanner, StegoIndicator,
};
