//! A2A Agent Card handling.
//!
//! Agent Cards are JSON documents published at `/.well-known/agent.json` that
//! describe an agent's capabilities, authentication requirements, and skills.
//!
//! This module provides:
//! - Agent Card type definitions matching the A2A specification
//! - Agent Card cache with TTL-based expiration
//! - Validation of incoming requests against agent capabilities

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::error::A2aError;

/// A2A Agent Card (from specification).
///
/// Describes an agent's identity, capabilities, and how to interact with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Human-readable name of the agent.
    pub name: String,

    /// Description of the agent's purpose and capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL of the agent endpoint.
    pub url: String,

    /// Information about the agent provider/organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderInfo>,

    /// Version of the agent.
    pub version: String,

    /// Agent capabilities (streaming, push notifications, etc.).
    pub capabilities: AgentCapabilities,

    /// Authentication requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationInfo>,

    /// Default input modes supported by the agent.
    #[serde(default)]
    pub default_input_modes: Vec<String>,

    /// Default output modes supported by the agent.
    #[serde(default)]
    pub default_output_modes: Vec<String>,

    /// Skills/functions the agent can perform.
    #[serde(default)]
    pub skills: Vec<AgentSkill>,
}

/// Information about the agent provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Organization name.
    pub organization: String,

    /// Organization URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Agent capability flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Supports streaming responses (SSE).
    #[serde(default)]
    pub streaming: bool,

    /// Supports push notifications.
    #[serde(default)]
    pub push_notifications: bool,

    /// Supports state transition history.
    #[serde(default)]
    pub state_transition_history: bool,
}

/// Authentication information for the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationInfo {
    /// Supported authentication schemes.
    pub schemes: Vec<AuthScheme>,
}

/// Authentication scheme definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthScheme {
    /// Scheme type: "apiKeyAuth", "httpAuth", "oauth2", "openIdConnect"
    pub scheme: String,

    /// Additional scheme-specific details.
    #[serde(flatten)]
    pub details: HashMap<String, Value>,
}

/// A skill/function that an agent can perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    /// Unique identifier for the skill.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Description of what the skill does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Example prompts/usage.
    #[serde(default)]
    pub examples: Vec<String>,

    /// Input modes this skill accepts (overrides agent default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,

    /// Output modes this skill produces (overrides agent default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
}

/// Cached agent card entry.
struct CachedCard {
    card: AgentCard,
    fetched_at: Instant,
}

/// Agent card cache with TTL-based expiration.
///
/// Caches agent cards to avoid repeated fetches for each request.
/// Entries expire after the configured TTL.
pub struct AgentCardCache {
    cache: RwLock<HashMap<String, CachedCard>>,
    ttl: Duration,
}

impl AgentCardCache {
    /// Create a new agent card cache with the specified TTL in seconds.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get a cached agent card if available and not expired.
    pub fn get_cached(&self, base_url: &str) -> Option<AgentCard> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(base_url)?;

        if entry.fetched_at.elapsed() < self.ttl {
            Some(entry.card.clone())
        } else {
            None
        }
    }

    /// Store an agent card in the cache.
    pub fn store(&self, base_url: &str, card: AgentCard) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                base_url.to_string(),
                CachedCard {
                    card,
                    fetched_at: Instant::now(),
                },
            );
        }
    }

    /// Remove an agent card from the cache.
    pub fn invalidate(&self, base_url: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(base_url);
        }
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AgentCardCache {
    fn default() -> Self {
        Self::new(3600) // 1 hour default TTL
    }
}

/// Build the well-known URL for an agent card from a base URL.
///
/// # Example
///
/// ```rust,ignore
/// let url = build_agent_card_url("https://agent.example.com");
/// assert_eq!(url, "https://agent.example.com/.well-known/agent.json");
/// ```
pub fn build_agent_card_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{}/.well-known/agent.json", base)
}

/// Parse an agent card from JSON.
pub fn parse_agent_card(json: &str) -> Result<AgentCard, A2aError> {
    serde_json::from_str(json).map_err(|e| A2aError::AgentCardInvalid(e.to_string()))
}

/// Validate that an agent card has required fields.
pub fn validate_agent_card(card: &AgentCard) -> Result<(), A2aError> {
    if card.name.is_empty() {
        return Err(A2aError::AgentCardInvalid("name is required".to_string()));
    }
    if card.url.is_empty() {
        return Err(A2aError::AgentCardInvalid("url is required".to_string()));
    }
    if card.version.is_empty() {
        return Err(A2aError::AgentCardInvalid(
            "version is required".to_string(),
        ));
    }
    Ok(())
}

/// Check if an agent supports a specific authentication scheme.
pub fn supports_auth_scheme(card: &AgentCard, scheme: &str) -> bool {
    match &card.authentication {
        Some(auth) => auth
            .schemes
            .iter()
            .any(|s| s.scheme.eq_ignore_ascii_case(scheme)),
        None => false,
    }
}

/// Check if an agent supports streaming responses.
pub fn supports_streaming(card: &AgentCard) -> bool {
    card.capabilities.streaming
}

/// Validate that a request method is supported by the agent's capabilities.
pub fn validate_request_method(
    card: &AgentCard,
    method: &str,
) -> Result<(), A2aError> {
    match method {
        "message/stream" if !card.capabilities.streaming => {
            Err(A2aError::AgentCardInvalid(
                "Agent does not support streaming".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::thread::sleep;

    fn sample_agent_card() -> AgentCard {
        AgentCard {
            name: "Test Agent".to_string(),
            description: Some("A test agent".to_string()),
            url: "https://agent.example.com".to_string(),
            provider: Some(ProviderInfo {
                organization: "Test Org".to_string(),
                url: Some("https://example.com".to_string()),
            }),
            version: "1.0.0".to_string(),
            capabilities: AgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: true,
            },
            authentication: Some(AuthenticationInfo {
                schemes: vec![
                    AuthScheme {
                        scheme: "httpAuth".to_string(),
                        details: HashMap::new(),
                    },
                    AuthScheme {
                        scheme: "oauth2".to_string(),
                        details: HashMap::new(),
                    },
                ],
            }),
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: vec![AgentSkill {
                id: "chat".to_string(),
                name: "Chat".to_string(),
                description: Some("General conversation".to_string()),
                tags: vec!["general".to_string()],
                examples: vec!["Hello".to_string()],
                input_modes: None,
                output_modes: None,
            }],
        }
    }

    #[test]
    fn test_agent_card_serde() {
        let card = sample_agent_card();
        let json = serde_json::to_string(&card).unwrap();
        let parsed: AgentCard = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "Test Agent");
        assert_eq!(parsed.version, "1.0.0");
        assert!(parsed.capabilities.streaming);
    }

    #[test]
    fn test_agent_card_from_json() {
        let json = json!({
            "name": "My Agent",
            "url": "https://agent.test.com",
            "version": "2.0.0",
            "capabilities": {
                "streaming": true,
                "pushNotifications": false,
                "stateTransitionHistory": false
            }
        });

        let card: AgentCard = serde_json::from_value(json).unwrap();
        assert_eq!(card.name, "My Agent");
        assert!(card.capabilities.streaming);
        assert!(!card.capabilities.push_notifications);
    }

    #[test]
    fn test_cache_basic() {
        let cache = AgentCardCache::new(60);
        assert!(cache.is_empty());

        let card = sample_agent_card();
        cache.store("https://example.com", card.clone());

        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);

        let cached = cache.get_cached("https://example.com").unwrap();
        assert_eq!(cached.name, "Test Agent");
    }

    #[test]
    fn test_cache_expiration() {
        let cache = AgentCardCache::new(0); // Immediate expiration
        let card = sample_agent_card();

        cache.store("https://example.com", card);
        sleep(Duration::from_millis(10));

        assert!(cache.get_cached("https://example.com").is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = AgentCardCache::new(60);
        let card = sample_agent_card();

        cache.store("https://example.com", card);
        assert!(cache.get_cached("https://example.com").is_some());

        cache.invalidate("https://example.com");
        assert!(cache.get_cached("https://example.com").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = AgentCardCache::new(60);
        let card = sample_agent_card();

        cache.store("https://a.com", card.clone());
        cache.store("https://b.com", card);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_build_agent_card_url() {
        assert_eq!(
            build_agent_card_url("https://example.com"),
            "https://example.com/.well-known/agent.json"
        );
        assert_eq!(
            build_agent_card_url("https://example.com/"),
            "https://example.com/.well-known/agent.json"
        );
        assert_eq!(
            build_agent_card_url("https://example.com/api"),
            "https://example.com/api/.well-known/agent.json"
        );
    }

    #[test]
    fn test_parse_agent_card() {
        let json = r#"{"name":"Test","url":"https://test.com","version":"1.0","capabilities":{}}"#;
        let card = parse_agent_card(json).unwrap();
        assert_eq!(card.name, "Test");
    }

    #[test]
    fn test_parse_agent_card_invalid() {
        let json = "not valid json";
        assert!(parse_agent_card(json).is_err());
    }

    #[test]
    fn test_validate_agent_card() {
        let card = sample_agent_card();
        assert!(validate_agent_card(&card).is_ok());

        let mut invalid = card.clone();
        invalid.name = String::new();
        assert!(validate_agent_card(&invalid).is_err());

        let mut invalid = card.clone();
        invalid.url = String::new();
        assert!(validate_agent_card(&invalid).is_err());

        let mut invalid = card;
        invalid.version = String::new();
        assert!(validate_agent_card(&invalid).is_err());
    }

    #[test]
    fn test_supports_auth_scheme() {
        let card = sample_agent_card();
        assert!(supports_auth_scheme(&card, "httpAuth"));
        assert!(supports_auth_scheme(&card, "oauth2"));
        assert!(supports_auth_scheme(&card, "OAUTH2")); // Case insensitive
        assert!(!supports_auth_scheme(&card, "apiKeyAuth"));

        let mut no_auth = card;
        no_auth.authentication = None;
        assert!(!supports_auth_scheme(&no_auth, "httpAuth"));
    }

    #[test]
    fn test_supports_streaming() {
        let mut card = sample_agent_card();
        assert!(supports_streaming(&card));

        card.capabilities.streaming = false;
        assert!(!supports_streaming(&card));
    }

    #[test]
    fn test_validate_request_method() {
        let mut card = sample_agent_card();

        // Streaming supported
        assert!(validate_request_method(&card, "message/stream").is_ok());
        assert!(validate_request_method(&card, "message/send").is_ok());

        // Streaming not supported
        card.capabilities.streaming = false;
        assert!(validate_request_method(&card, "message/stream").is_err());
        assert!(validate_request_method(&card, "message/send").is_ok());
    }
}
