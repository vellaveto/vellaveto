//! Sampling attack detection.
//!
//! Rate limits and inspects sampling/createMessage requests to prevent
//! abuse of LLM inference capabilities through MCP.
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::sampling_detector::SamplingDetector;
//!
//! let detector = SamplingDetector::new(10, 60, 10000);
//!
//! // Check a sampling request
//! let result = detector.check_request("session-1", "claude-3", "Hello, world!");
//! assert!(result.is_ok());
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use vellaveto_types::SamplingStats;

/// Reason for denying a sampling request.
#[derive(thiserror::Error, Debug, Clone)]
pub enum SamplingDenied {
    /// Rate limit exceeded.
    #[error("Rate limit exceeded: {count} requests (limit: {limit})")]
    RateLimitExceeded { count: u32, limit: u32 },
    /// Prompt is too long.
    #[error("Prompt too long: {length} characters (max: {max})")]
    PromptTooLong { length: usize, max: usize },
    /// Sensitive content detected.
    #[error("Sensitive content detected: {patterns:?}")]
    SensitiveContent { patterns: Vec<String> },
    /// Model is not in the allowed list.
    #[error("Model not allowed: {model}")]
    ModelNotAllowed { model: String },
}

/// DLP match in sampling content.
#[derive(Debug, Clone)]
pub struct DlpMatch {
    /// Pattern that matched.
    pub pattern: String,
    /// Position in the content.
    pub position: usize,
    /// Length of the match.
    pub length: usize,
}

/// Maximum tracked sessions before new insertions are rejected (fail-closed).
/// SECURITY (FIND-R56-MCP-011): Prevents unbounded HashMap growth from many
/// unique session IDs, which could cause OOM.
const MAX_SESSIONS: usize = 100_000;

/// Detects and prevents sampling request abuse.
#[derive(Debug)]
pub struct SamplingDetector {
    /// Stats by session ID.
    stats: RwLock<HashMap<String, SamplingStats>>,
    /// Maximum requests per window.
    max_requests: u32,
    /// Window duration in seconds.
    window_secs: u64,
    /// Maximum prompt length.
    max_prompt_length: usize,
    /// Allowed model patterns (empty = all allowed).
    allowed_models: Vec<String>,
    /// Whether to scan for sensitive patterns.
    scan_sensitive: bool,
    /// Sensitive patterns to block.
    sensitive_patterns: Vec<String>,
}

impl SamplingDetector {
    /// Create a new sampling detector.
    ///
    /// # Arguments
    /// * `max_requests` - Maximum requests per window
    /// * `window_secs` - Window duration in seconds
    /// * `max_prompt_length` - Maximum prompt length in characters
    pub fn new(max_requests: u32, window_secs: u64, max_prompt_length: usize) -> Self {
        Self {
            stats: RwLock::new(HashMap::new()),
            max_requests,
            window_secs,
            max_prompt_length,
            allowed_models: Vec::new(),
            scan_sensitive: false,
            sensitive_patterns: Vec::new(),
        }
    }

    /// Create with full configuration.
    pub fn with_config(
        max_requests: u32,
        window_secs: u64,
        max_prompt_length: usize,
        allowed_models: Vec<String>,
        scan_sensitive: bool,
    ) -> Self {
        Self {
            stats: RwLock::new(HashMap::new()),
            max_requests,
            window_secs,
            max_prompt_length,
            allowed_models,
            scan_sensitive,
            sensitive_patterns: default_sensitive_patterns(),
        }
    }

    /// Create a shareable reference to this detector.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current timestamp as Unix seconds.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Check if a sampling request should be allowed.
    ///
    /// # Arguments
    /// * `session_id` - The session making the request
    /// * `model` - The model being requested
    /// * `prompt` - The prompt content
    ///
    /// # Returns
    /// `Ok(())` if allowed, `Err(SamplingDenied)` if blocked.
    ///
    /// # Known Limitation: TOCTOU Rate-Limit Gap (FIND-R110-MCP-001)
    ///
    /// The rate limit check (`check_request`) and the increment (`record_request`)
    /// are two separate operations, each acquiring the write lock independently.
    /// A concurrent caller can therefore pass the check and record a request between
    /// another caller's check and record, allowing a short burst above the configured
    /// limit before both increments are committed.
    ///
    /// Merging check and record into a single atomic operation would require callers
    /// to always decrement on downstream failure, complicating the public API. The
    /// current split design is therefore intentional and documented.
    ///
    /// **Actual ReDoS risk: none.** The `regex` crate's DFA/NFA engine is immune to
    /// catastrophic backtracking regardless of pattern content — the TOCTOU window
    /// only affects rate-limit precision, not correctness or safety.
    pub fn check_request(
        &self,
        session_id: &str,
        model: &str,
        prompt: &str,
    ) -> Result<(), SamplingDenied> {
        // Check model allowlist
        if !self.allowed_models.is_empty() && !self.validate_model(model) {
            return Err(SamplingDenied::ModelNotAllowed {
                model: model.to_string(),
            });
        }

        // Check prompt length
        if prompt.len() > self.max_prompt_length {
            return Err(SamplingDenied::PromptTooLong {
                length: prompt.len(),
                max: self.max_prompt_length,
            });
        }

        // Check for sensitive patterns
        if self.scan_sensitive {
            let matches = self.scan_content(prompt);
            if !matches.is_empty() {
                return Err(SamplingDenied::SensitiveContent {
                    patterns: matches.into_iter().map(|m| m.pattern).collect(),
                });
            }
        }

        // Check rate limit
        let now = Self::now();
        let mut stats = match self.stats.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::check_request");
                return Err(SamplingDenied::RateLimitExceeded {
                    count: self.max_requests,
                    limit: self.max_requests,
                });
            }
        };

        // SECURITY (FIND-R56-MCP-011): If at capacity and session is new, try
        // to evict expired sessions first; if still at capacity, fail-closed.
        if !stats.contains_key(session_id) && stats.len() >= MAX_SESSIONS {
            // Evict expired sessions to reclaim capacity
            let cutoff = now.saturating_sub(self.window_secs * 2);
            stats.retain(|_, s| s.last_request >= cutoff);

            if stats.len() >= MAX_SESSIONS {
                tracing::warn!(
                    "SamplingDetector: session capacity reached ({}) — denying new session (fail-closed)",
                    MAX_SESSIONS
                );
                return Err(SamplingDenied::RateLimitExceeded {
                    count: self.max_requests,
                    limit: self.max_requests,
                });
            }
        }

        let session_stats = stats
            .entry(session_id.to_string())
            .or_insert_with(|| SamplingStats::new(now));

        // Reset window if expired
        if now >= session_stats.window_start.saturating_add(self.window_secs) {
            session_stats.reset_window(now);
        }

        // Check limit
        if session_stats.request_count >= self.max_requests {
            return Err(SamplingDenied::RateLimitExceeded {
                count: session_stats.request_count,
                limit: self.max_requests,
            });
        }

        Ok(())
    }

    /// Record a sampling request.
    ///
    /// Call this after check_request succeeds.
    pub fn record_request(&self, session_id: &str) {
        let now = Self::now();
        let mut stats = match self.stats.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::record_request");
                return;
            }
        };

        // SECURITY (FIND-R56-MCP-011): Skip recording if at capacity and session is new.
        if !stats.contains_key(session_id) && stats.len() >= MAX_SESSIONS {
            tracing::warn!(
                "SamplingDetector: session capacity reached ({}) — skipping record for new session",
                MAX_SESSIONS
            );
            return;
        }

        let session_stats = stats
            .entry(session_id.to_string())
            .or_insert_with(|| SamplingStats::new(now));

        // Reset window if expired
        if now >= session_stats.window_start.saturating_add(self.window_secs) {
            session_stats.reset_window(now);
        }

        session_stats.record_request(now);
    }

    /// Scan content for sensitive patterns.
    pub fn scan_content(&self, content: &str) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        let content_lower = content.to_lowercase();

        for pattern in &self.sensitive_patterns {
            let pattern_lower = pattern.to_lowercase();
            let mut pos = 0;
            while let Some(found) = content_lower[pos..].find(&pattern_lower) {
                matches.push(DlpMatch {
                    pattern: pattern.clone(),
                    position: pos + found,
                    length: pattern.len(),
                });
                pos += found + 1;
            }
        }

        matches
    }

    /// Validate that a model is allowed.
    pub fn validate_model(&self, model: &str) -> bool {
        if self.allowed_models.is_empty() {
            return true;
        }

        let model_lower = model.to_lowercase();
        self.allowed_models.iter().any(|allowed| {
            let allowed_lower = allowed.to_lowercase();
            if allowed.contains('*') {
                // Simple wildcard matching
                let parts: Vec<&str> = allowed_lower.split('*').collect();
                if parts.len() == 2 {
                    let (prefix, suffix) = (parts[0], parts[1]);
                    model_lower.starts_with(prefix) && model_lower.ends_with(suffix)
                } else {
                    model_lower == allowed_lower
                }
            } else {
                model_lower == allowed_lower
            }
        })
    }

    /// Get stats for a session.
    pub fn get_stats(&self, session_id: &str) -> Option<SamplingStats> {
        let stats = match self.stats.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::get_stats");
                return None;
            }
        };
        stats.get(session_id).cloned()
    }

    /// Get remaining requests for a session in current window.
    pub fn remaining_requests(&self, session_id: &str) -> u32 {
        let now = Self::now();
        let stats = match self.stats.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::remaining_requests");
                return 0;
            }
        };

        match stats.get(session_id) {
            Some(s) => {
                if now >= s.window_start.saturating_add(self.window_secs) {
                    self.max_requests // Window expired, full quota
                } else {
                    self.max_requests.saturating_sub(s.request_count)
                }
            }
            None => self.max_requests,
        }
    }

    /// Clear stats for a session.
    pub fn clear_session(&self, session_id: &str) {
        let mut stats = match self.stats.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::clear_session");
                return;
            }
        };
        stats.remove(session_id);
    }

    /// Clean up old sessions (expired windows).
    ///
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_expired(&self) -> usize {
        let now = Self::now();
        let mut stats = match self.stats.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::cleanup_expired");
                return 0;
            }
        };

        let old_len = stats.len();
        // Keep sessions that have activity within 2 window periods
        let cutoff = now.saturating_sub(self.window_secs * 2);
        stats.retain(|_, s| s.last_request >= cutoff);

        old_len - stats.len()
    }

    /// Get the number of tracked sessions.
    pub fn session_count(&self) -> usize {
        let stats = match self.stats.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in SamplingDetector::session_count");
                return 0;
            }
        };
        stats.len()
    }

    /// Add a sensitive pattern to scan for.
    pub fn add_sensitive_pattern(&mut self, pattern: String) {
        self.sensitive_patterns.push(pattern);
    }

    /// Enable or disable sensitive pattern scanning.
    pub fn set_scan_sensitive(&mut self, enabled: bool) {
        self.scan_sensitive = enabled;
    }
}

impl Default for SamplingDetector {
    fn default() -> Self {
        Self::new(10, 60, 10_000)
    }
}

/// Default sensitive patterns to scan for.
fn default_sensitive_patterns() -> Vec<String> {
    vec![
        // Common sensitive keywords
        "password".to_string(),
        "api_key".to_string(),
        "api key".to_string(),
        "apikey".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "credential".to_string(),
        "private_key".to_string(),
        "ssh_key".to_string(),
        // Injection attempts
        "ignore previous".to_string(),
        "ignore all".to_string(),
        "disregard".to_string(),
        "system prompt".to_string(),
        "jailbreak".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_within_limit() {
        let detector = SamplingDetector::new(10, 60, 10000);

        let result = detector.check_request("session-1", "claude-3", "Hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let detector = SamplingDetector::new(2, 60, 10000);

        // First two requests OK
        detector
            .check_request("session-1", "claude-3", "Hello")
            .unwrap();
        detector.record_request("session-1");

        detector
            .check_request("session-1", "claude-3", "Hello")
            .unwrap();
        detector.record_request("session-1");

        // Third request exceeds limit
        let result = detector.check_request("session-1", "claude-3", "Hello");
        assert!(matches!(
            result,
            Err(SamplingDenied::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_prompt_too_long() {
        let detector = SamplingDetector::new(10, 60, 10);

        let long_prompt = "a".repeat(20);
        let result = detector.check_request("session-1", "claude-3", &long_prompt);

        assert!(matches!(result, Err(SamplingDenied::PromptTooLong { .. })));
    }

    #[test]
    fn test_model_not_allowed() {
        let detector =
            SamplingDetector::with_config(10, 60, 10000, vec!["claude-*".to_string()], false);

        let result = detector.check_request("session-1", "gpt-4", "Hello");
        assert!(matches!(
            result,
            Err(SamplingDenied::ModelNotAllowed { .. })
        ));

        let result = detector.check_request("session-1", "claude-3", "Hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sensitive_content_blocked() {
        let detector = SamplingDetector::with_config(
            10,
            60,
            10000,
            vec![],
            true, // Enable scanning
        );

        let result = detector.check_request("session-1", "claude-3", "What is my password?");
        assert!(matches!(
            result,
            Err(SamplingDenied::SensitiveContent { .. })
        ));
    }

    #[test]
    fn test_validate_model_wildcard() {
        let detector = SamplingDetector::with_config(
            10,
            60,
            10000,
            vec!["claude-*".to_string(), "gpt-4*".to_string()],
            false,
        );

        assert!(detector.validate_model("claude-3"));
        assert!(detector.validate_model("claude-3-sonnet"));
        assert!(detector.validate_model("gpt-4"));
        assert!(detector.validate_model("gpt-4-turbo"));
        assert!(!detector.validate_model("gemini-pro"));
    }

    #[test]
    fn test_remaining_requests() {
        let detector = SamplingDetector::new(10, 60, 10000);

        assert_eq!(detector.remaining_requests("session-1"), 10);

        detector
            .check_request("session-1", "model", "prompt")
            .unwrap();
        detector.record_request("session-1");

        assert_eq!(detector.remaining_requests("session-1"), 9);
    }

    #[test]
    fn test_scan_content() {
        let detector = SamplingDetector::with_config(10, 60, 10000, vec![], true);

        let matches = detector.scan_content("What is my password and api_key?");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_clear_session() {
        let detector = SamplingDetector::new(10, 60, 10000);

        detector
            .check_request("session-1", "model", "prompt")
            .unwrap();
        detector.record_request("session-1");
        assert_eq!(detector.session_count(), 1);

        detector.clear_session("session-1");
        assert_eq!(detector.session_count(), 0);
    }

    #[test]
    fn test_different_sessions_independent() {
        let detector = SamplingDetector::new(2, 60, 10000);

        // Session 1 uses quota
        detector
            .check_request("session-1", "model", "prompt")
            .unwrap();
        detector.record_request("session-1");
        detector
            .check_request("session-1", "model", "prompt")
            .unwrap();
        detector.record_request("session-1");

        // Session 1 is now limited
        assert!(detector
            .check_request("session-1", "model", "prompt")
            .is_err());

        // Session 2 still has quota
        assert!(detector
            .check_request("session-2", "model", "prompt")
            .is_ok());
    }
}
