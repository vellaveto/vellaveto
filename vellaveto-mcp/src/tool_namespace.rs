//! Tool Namespace Security
//!
//! Prevents tool shadowing and namespace collisions where an attacker registers
//! a malicious tool with a name that collides with or shadows a legitimate tool.
//!
//! Mitigates: ASI03 (Tool Poisoning), ASI07 (Insecure Plugins)
//!
//! Features:
//! - Register tools with source attestation
//! - Detect namespace collisions
//! - Validate tool selection matches expected source
//! - Track tool source lineage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

/// Source attestation for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSource {
    /// Server or provider name.
    pub server: String,
    /// Tool version.
    pub version: String,
    /// SHA-256 hash of tool definition.
    pub definition_hash: String,
    /// When the tool was registered.
    #[serde(skip)]
    pub registered_at: Option<SystemTime>,
    /// Is this a trusted source.
    pub trusted: bool,
}

/// Alert for namespace collision.
#[derive(Debug, Clone)]
pub struct CollisionAlert {
    /// Tool name that has collision.
    pub tool_name: String,
    /// Existing source.
    pub existing_source: ToolSource,
    /// Conflicting source.
    pub conflicting_source: ToolSource,
    /// Type of collision.
    pub collision_type: CollisionType,
    /// Human-readable description.
    pub description: String,
}

/// Types of namespace collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionType {
    /// Exact name collision from different servers.
    ExactMatch,
    /// Similar name (potential shadowing).
    SimilarName,
    /// Same server, different version.
    VersionConflict,
    /// Untrusted source trying to register trusted name.
    TrustViolation,
}

/// Error for tool selection validation.
#[derive(Debug, Clone)]
pub struct SelectionError {
    /// Tool that was selected.
    pub tool_name: String,
    /// Expected source.
    pub expected_source: String,
    /// Actual source that was selected.
    pub actual_source: String,
    /// Human-readable description.
    pub description: String,
}

/// Error for registration.
#[derive(thiserror::Error, Debug, Clone)]
pub enum NamespaceError {
    /// Name collision detected.
    #[error("Namespace collision: {}", .0.description)]
    Collision(Box<CollisionAlert>),
    /// Maximum tools exceeded.
    #[error("Maximum tool capacity exceeded")]
    CapacityExceeded,
    /// Invalid tool name.
    #[error("Invalid tool name: {0}")]
    InvalidName(String),
}

/// Configuration for namespace registry.
#[derive(Debug, Clone)]
pub struct NamespaceRegistryConfig {
    /// Maximum tools to track.
    pub max_tools: usize,
    /// Allow same-name tools from different servers.
    pub allow_multi_source: bool,
    /// Levenshtein distance threshold for similar name detection.
    pub similarity_threshold: usize,
    /// Require source attestation for registration.
    pub require_attestation: bool,
    /// Tool entry TTL (None = never expire).
    pub entry_ttl: Option<Duration>,
}

impl Default for NamespaceRegistryConfig {
    fn default() -> Self {
        Self {
            max_tools: 10_000,
            allow_multi_source: false,
            similarity_threshold: 2,
            require_attestation: true,
            entry_ttl: None,
        }
    }
}

/// Entry in the namespace registry.
#[derive(Debug)]
struct NamespaceEntry {
    /// Primary source for this tool.
    primary_source: ToolSource,
    /// Alternative sources (if multi-source allowed).
    alternative_sources: Vec<ToolSource>,
    /// When this entry was created (for audit/debugging purposes).
    #[allow(dead_code)] // Retained for audit trail and future namespace expiry
    created_at: Instant,
    /// Last access time.
    last_accessed: Instant,
    /// Access count.
    access_count: u64,
}

/// Registry for tool namespace management.
pub struct ToolNamespaceRegistry {
    /// Tool name -> entry mapping.
    tools: RwLock<HashMap<String, NamespaceEntry>>,
    /// Configuration.
    config: NamespaceRegistryConfig,
    /// Reserved/protected names that cannot be registered by untrusted sources.
    protected_names: RwLock<Vec<String>>,
}

impl ToolNamespaceRegistry {
    /// Create a new namespace registry.
    pub fn new() -> Self {
        Self::with_config(NamespaceRegistryConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: NamespaceRegistryConfig) -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            config,
            protected_names: RwLock::new(default_protected_names()),
        }
    }

    /// Register a tool with source attestation.
    pub fn register(&self, tool_name: &str, source: ToolSource) -> Result<(), NamespaceError> {
        // Validate tool name
        if tool_name.is_empty() || tool_name.len() > 256 {
            return Err(NamespaceError::InvalidName(tool_name.to_string()));
        }

        // SECURITY (IMP-R130-007): Check for control and format characters.
        // Previous check was redundant (null is control) and missed Unicode
        // format chars. Delegate to canonical predicate.
        if vellaveto_types::has_dangerous_chars(tool_name) {
            return Err(NamespaceError::InvalidName(tool_name.to_string()));
        }

        let normalized_name = tool_name.to_lowercase();
        let mut tools = match self.tools.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::register (tools)");
                return Err(NamespaceError::InvalidName(
                    "internal error: lock poisoned".to_string(),
                ));
            }
        };

        // Check capacity
        if tools.len() >= self.config.max_tools && !tools.contains_key(&normalized_name) {
            return Err(NamespaceError::CapacityExceeded);
        }

        // Check for exact collision
        if let Some(existing) = tools.get(&normalized_name) {
            if existing.primary_source.server != source.server {
                if !self.config.allow_multi_source {
                    return Err(NamespaceError::Collision(Box::new(CollisionAlert {
                        tool_name: tool_name.to_string(),
                        existing_source: existing.primary_source.clone(),
                        conflicting_source: source,
                        collision_type: CollisionType::ExactMatch,
                        description: format!(
                            "Tool '{}' already registered by server '{}'",
                            tool_name, existing.primary_source.server
                        ),
                    })));
                }
            } else if existing.primary_source.version != source.version {
                let new_version = source.version.clone();
                return Err(NamespaceError::Collision(Box::new(CollisionAlert {
                    tool_name: tool_name.to_string(),
                    existing_source: existing.primary_source.clone(),
                    conflicting_source: source,
                    collision_type: CollisionType::VersionConflict,
                    description: format!(
                        "Tool '{}' version conflict: existing={}, new={}",
                        tool_name, existing.primary_source.version, new_version
                    ),
                })));
            }
        }

        // Check for trust violation on protected names
        let protected = match self.protected_names.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::register (protected_names)");
                return Err(NamespaceError::InvalidName(
                    "internal error: lock poisoned".to_string(),
                ));
            }
        };
        if !source.trusted && protected.iter().any(|p| normalized_name.contains(p)) {
            return Err(NamespaceError::Collision(Box::new(CollisionAlert {
                tool_name: tool_name.to_string(),
                existing_source: ToolSource {
                    server: "protected".to_string(),
                    version: "".to_string(),
                    definition_hash: "".to_string(),
                    registered_at: None,
                    trusted: true,
                },
                conflicting_source: source,
                collision_type: CollisionType::TrustViolation,
                description: format!("Tool '{}' matches protected name pattern", tool_name),
            })));
        }
        drop(protected);

        // Check for similar names (potential shadowing)
        if let Some(collision) = self.check_similar_names(&normalized_name, &source, &tools) {
            return Err(NamespaceError::Collision(Box::new(collision)));
        }

        // Register the tool
        let mut source_with_time = source;
        source_with_time.registered_at = Some(SystemTime::now());

        let entry = NamespaceEntry {
            primary_source: source_with_time,
            alternative_sources: Vec::new(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 0,
        };

        tools.insert(normalized_name, entry);
        Ok(())
    }

    /// Check for similar names that might indicate shadowing.
    fn check_similar_names(
        &self,
        name: &str,
        source: &ToolSource,
        tools: &HashMap<String, NamespaceEntry>,
    ) -> Option<CollisionAlert> {
        for (existing_name, entry) in tools.iter() {
            if existing_name == name {
                continue;
            }

            // Check Levenshtein distance
            let distance = levenshtein_distance(name, existing_name);
            if distance > 0 && distance <= self.config.similarity_threshold {
                // Different source trying to register similar name
                if entry.primary_source.server != source.server {
                    return Some(CollisionAlert {
                        tool_name: name.to_string(),
                        existing_source: entry.primary_source.clone(),
                        conflicting_source: source.clone(),
                        collision_type: CollisionType::SimilarName,
                        description: format!(
                            "Tool '{}' is similar to existing tool '{}' (distance={})",
                            name, existing_name, distance
                        ),
                    });
                }
            }
        }

        None
    }

    /// Check for namespace collision without registering.
    pub fn check_collision(&self, tool_name: &str, source: &ToolSource) -> Option<CollisionAlert> {
        let normalized_name = tool_name.to_lowercase();
        let tools = match self.tools.read() {
            Ok(g) => g,
            Err(_) => {
                // SECURITY (FIND-R180-008): Fail-closed on poisoned lock — report
                // a collision rather than silently allowing potentially conflicting tools.
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::check_collision — fail-closed");
                return Some(CollisionAlert {
                    tool_name: tool_name.to_string(),
                    existing_source: source.clone(),
                    conflicting_source: source.clone(),
                    collision_type: CollisionType::ExactMatch,
                    description: "Tool namespace registry lock poisoned — fail-closed collision"
                        .to_string(),
                });
            }
        };

        // Check exact collision
        if let Some(existing) = tools.get(&normalized_name) {
            if existing.primary_source.server != source.server && !self.config.allow_multi_source {
                return Some(CollisionAlert {
                    tool_name: tool_name.to_string(),
                    existing_source: existing.primary_source.clone(),
                    conflicting_source: source.clone(),
                    collision_type: CollisionType::ExactMatch,
                    description: format!(
                        "Tool '{}' already registered by server '{}'",
                        tool_name, existing.primary_source.server
                    ),
                });
            }
        }

        // Check similar names
        self.check_similar_names(&normalized_name, source, &tools)
    }

    /// Validate that tool selection matches expected source.
    pub fn validate_selection(
        &self,
        tool_name: &str,
        selected_source: &str,
    ) -> Result<(), SelectionError> {
        let normalized_name = tool_name.to_lowercase();
        let mut tools = match self.tools.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::validate_selection");
                return Err(SelectionError {
                    tool_name: tool_name.to_string(),
                    expected_source: "unknown".to_string(),
                    actual_source: selected_source.to_string(),
                    description: "Lock poisoned — cannot validate tool selection".to_string(),
                });
            }
        };

        let entry = match tools.get_mut(&normalized_name) {
            Some(e) => e,
            None => {
                // Tool not registered - could be new or unknown
                return Ok(());
            }
        };

        // Update access stats
        entry.last_accessed = Instant::now();
        // SECURITY (FIND-R56-MCP-008): Use saturating_add to prevent wrapping
        // overflow on the access counter, which could reset rate-limit tracking.
        entry.access_count = entry.access_count.saturating_add(1);

        // Check if selection matches primary source
        if entry.primary_source.server == selected_source {
            return Ok(());
        }

        // Check alternative sources
        if entry
            .alternative_sources
            .iter()
            .any(|s| s.server == selected_source)
        {
            return Ok(());
        }

        Err(SelectionError {
            tool_name: tool_name.to_string(),
            expected_source: entry.primary_source.server.clone(),
            actual_source: selected_source.to_string(),
            description: format!(
                "Tool '{}' expected from '{}' but got '{}'",
                tool_name, entry.primary_source.server, selected_source
            ),
        })
    }

    /// Get the registered source for a tool.
    pub fn get_source(&self, tool_name: &str) -> Option<ToolSource> {
        let normalized_name = tool_name.to_lowercase();
        let tools = match self.tools.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::get_source");
                return None;
            }
        };
        tools
            .get(&normalized_name)
            .map(|e| e.primary_source.clone())
    }

    /// Remove a tool from the registry.
    pub fn remove(&self, tool_name: &str) -> bool {
        let normalized_name = tool_name.to_lowercase();
        let mut tools = match self.tools.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::remove");
                return false;
            }
        };
        tools.remove(&normalized_name).is_some()
    }

    /// Add a protected name pattern.
    pub fn add_protected_name(&self, pattern: &str) {
        let mut protected = match self.protected_names.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::add_protected_name");
                return;
            }
        };
        protected.push(pattern.to_lowercase());
    }

    /// List all registered tools.
    pub fn list_tools(&self) -> Vec<(String, ToolSource)> {
        let tools = match self.tools.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::list_tools");
                return vec![];
            }
        };
        tools
            .iter()
            .map(|(name, entry)| (name.clone(), entry.primary_source.clone()))
            .collect()
    }

    /// Get tool count.
    pub fn tool_count(&self) -> usize {
        let tools = match self.tools.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::tool_count");
                return 0;
            }
        };
        tools.len()
    }

    /// Clear all tools.
    pub fn clear(&self) {
        let mut tools = match self.tools.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ToolNamespaceRegistry::clear");
                return;
            }
        };
        tools.clear();
    }
}

impl Default for ToolNamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Default protected name patterns.
fn default_protected_names() -> Vec<String> {
    vec![
        "bash".to_string(),
        "shell".to_string(),
        "exec".to_string(),
        "system".to_string(),
        "admin".to_string(),
        "sudo".to_string(),
        "root".to_string(),
    ]
}

/// Calculate Levenshtein distance between two strings.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Use two rows instead of full matrix
    let mut prev_row: Vec<usize> = (0..=n).collect();
    let mut curr_row: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr_row[0] = i;

        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };

            curr_row[j] = (prev_row[j] + 1)
                .min(curr_row[j - 1] + 1)
                .min(prev_row[j - 1] + cost);
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_source(server: &str, version: &str, trusted: bool) -> ToolSource {
        ToolSource {
            server: server.to_string(),
            version: version.to_string(),
            definition_hash: format!("hash_{}", server),
            registered_at: None,
            trusted,
        }
    }

    #[test]
    fn test_register_tool() {
        let registry = ToolNamespaceRegistry::new();

        let source = create_source("server1", "1.0.0", true);
        assert!(registry.register("my_tool", source).is_ok());

        assert_eq!(registry.tool_count(), 1);
    }

    #[test]
    fn test_exact_collision() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server2", "1.0.0", true);

        registry.register("my_tool", source1).unwrap();

        let result = registry.register("my_tool", source2);
        assert!(result.is_err());

        if let Err(NamespaceError::Collision(alert)) = result {
            assert_eq!(alert.collision_type, CollisionType::ExactMatch);
        } else {
            panic!("Expected collision error");
        }
    }

    #[test]
    fn test_version_conflict() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server1", "2.0.0", true);

        registry.register("my_tool", source1).unwrap();

        let result = registry.register("my_tool", source2);
        assert!(result.is_err());

        if let Err(NamespaceError::Collision(alert)) = result {
            assert_eq!(alert.collision_type, CollisionType::VersionConflict);
        } else {
            panic!("Expected version conflict");
        }
    }

    #[test]
    fn test_similar_name_detection() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server2", "1.0.0", true);

        registry.register("file_read", source1).unwrap();

        // "file_raed" is similar (typo)
        let result = registry.register("file_raed", source2);
        assert!(result.is_err());

        if let Err(NamespaceError::Collision(alert)) = result {
            assert_eq!(alert.collision_type, CollisionType::SimilarName);
        } else {
            panic!("Expected similar name collision");
        }
    }

    #[test]
    fn test_trust_violation() {
        let registry = ToolNamespaceRegistry::new();

        // Try to register "bash_helper" from untrusted source
        let source = create_source("untrusted_server", "1.0.0", false);
        let result = registry.register("bash_helper", source);

        assert!(result.is_err());
        if let Err(NamespaceError::Collision(alert)) = result {
            assert_eq!(alert.collision_type, CollisionType::TrustViolation);
        } else {
            panic!("Expected trust violation");
        }
    }

    #[test]
    fn test_validate_selection() {
        let registry = ToolNamespaceRegistry::new();

        let source = create_source("server1", "1.0.0", true);
        registry.register("my_tool", source).unwrap();

        // Valid selection
        assert!(registry.validate_selection("my_tool", "server1").is_ok());

        // Invalid selection
        let result = registry.validate_selection("my_tool", "wrong_server");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_collision() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        registry.register("my_tool", source1).unwrap();

        let source2 = create_source("server2", "1.0.0", true);
        let collision = registry.check_collision("my_tool", &source2);

        assert!(collision.is_some());
        assert_eq!(collision.unwrap().collision_type, CollisionType::ExactMatch);
    }

    #[test]
    fn test_get_source() {
        let registry = ToolNamespaceRegistry::new();

        let source = create_source("server1", "1.0.0", true);
        registry.register("my_tool", source.clone()).unwrap();

        let retrieved = registry.get_source("my_tool").unwrap();
        assert_eq!(retrieved.server, source.server);
        assert_eq!(retrieved.version, source.version);
    }

    #[test]
    fn test_remove_tool() {
        let registry = ToolNamespaceRegistry::new();

        let source = create_source("server1", "1.0.0", true);
        registry.register("my_tool", source).unwrap();

        assert!(registry.remove("my_tool"));
        assert_eq!(registry.tool_count(), 0);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "ab"), 1);
        assert_eq!(levenshtein_distance("abc", "abcd"), 1);
        assert_eq!(levenshtein_distance("abc", "adc"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_case_insensitivity() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server2", "1.0.0", true);

        registry.register("MyTool", source1).unwrap();

        // Should collide due to case-insensitive comparison
        let result = registry.register("mytool", source2);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tool_name() {
        let registry = ToolNamespaceRegistry::new();
        let source = create_source("server1", "1.0.0", true);

        // Empty name
        assert!(registry.register("", source.clone()).is_err());

        // Name with null byte
        assert!(registry.register("tool\0name", source).is_err());
    }

    #[test]
    fn test_capacity_exceeded() {
        let registry = ToolNamespaceRegistry::with_config(NamespaceRegistryConfig {
            max_tools: 2,
            ..Default::default()
        });

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server1", "1.0.0", true);
        let source3 = create_source("server1", "1.0.0", true);

        registry.register("tool1", source1).unwrap();
        registry.register("tool2", source2).unwrap();

        let result = registry.register("tool3", source3);
        assert!(matches!(result, Err(NamespaceError::CapacityExceeded)));
    }

    #[test]
    fn test_list_tools() {
        let registry = ToolNamespaceRegistry::new();

        let source1 = create_source("server1", "1.0.0", true);
        let source2 = create_source("server1", "1.0.0", true);

        registry.register("tool1", source1).unwrap();
        registry.register("tool2", source2).unwrap();

        let tools = registry.list_tools();
        assert_eq!(tools.len(), 2);
    }
}
