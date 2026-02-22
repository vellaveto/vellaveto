//! TF-IDF inverted index for tool discovery (Phase 34.1).
//!
//! Pure Rust, zero external dependencies. Follows the `SemanticScanner` pattern
//! from `semantic_detection.rs`: keyword tokenization, TF-IDF weighting, cosine
//! similarity scoring.
//!
//! # Design
//!
//! - **Tokenization**: Lowercase, split on whitespace + punctuation, minimum 2 chars.
//! - **Inverted index**: Maps each token to a set of tool_ids that contain it.
//! - **TF-IDF scoring**: Term frequency × inverse document frequency for relevance.
//! - **Bonuses**: Exact tool name match (+0.3), domain tag match (+0.2).
//! - **Bounded**: Maximum `max_entries` tools; ingest fails-closed when full.
//! - **Thread-safe**: All state behind `RwLock` for concurrent read access.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use vellaveto_types::ToolMetadata;

use super::DiscoveryError;

// ═══════════════════════════════════════════════════════════════════════════════
// INDEXED TOOL (internal representation)
// ═══════════════════════════════════════════════════════════════════════════════

/// Internal indexed representation of a tool's text features.
#[derive(Debug, Clone)]
struct IndexedTool {
    metadata: ToolMetadata,
    /// Token -> term frequency (normalized by document length).
    tf: HashMap<String, f64>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL INDEX
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory TF-IDF index over tool metadata.
///
/// Thread-safe: all internal state is behind `RwLock`. Lock poisoning
/// is handled fail-closed (returns `DiscoveryError::LockPoisoned`).
pub struct ToolIndex {
    /// Maximum number of indexed tools.
    max_entries: usize,
    /// tool_id -> indexed tool data.
    entries: RwLock<HashMap<String, IndexedTool>>,
    /// token -> inverse document frequency (recomputed on rebuild).
    idf: RwLock<HashMap<String, f64>>,
    /// token -> set of tool_ids containing that token (inverted index).
    token_index: RwLock<HashMap<String, HashSet<String>>>,
}

impl ToolIndex {
    /// Create a new empty index with the given capacity bound.
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: RwLock::new(HashMap::new()),
            idf: RwLock::new(HashMap::new()),
            token_index: RwLock::new(HashMap::new()),
        }
    }

    /// Ingest a tool's metadata into the index.
    ///
    /// If the tool_id already exists, it is updated in place.
    /// If the index is at capacity and this is a new tool, returns `IndexFull`.
    pub fn ingest(&self, metadata: &ToolMetadata) -> Result<(), DiscoveryError> {
        // SECURITY (FIND-R126-004): Validate metadata bounds before indexing.
        // Defense-in-depth: enforces limits even when called directly instead
        // of via DiscoveryEngine::ingest_tools_list().
        metadata
            .validate()
            .map_err(DiscoveryError::InvalidMetadata)?;

        // Legacy checks kept for clarity (now redundant with validate())
        if metadata.tool_id.is_empty() {
            return Err(DiscoveryError::InvalidMetadata(
                "tool_id must not be empty".to_string(),
            ));
        }
        if metadata.name.is_empty() {
            return Err(DiscoveryError::InvalidMetadata(
                "name must not be empty".to_string(),
            ));
        }

        // Build searchable text: name + description + domain tags
        let searchable_text = build_searchable_text(metadata);
        let tokens = tokenize(&searchable_text);
        if tokens.is_empty() {
            return Err(DiscoveryError::InvalidMetadata(
                "tool produces no searchable tokens".to_string(),
            ));
        }

        // Compute term frequency (TF) for this document
        let doc_len = tokens.len() as f64;
        let mut token_counts: HashMap<String, usize> = HashMap::new();
        for token in &tokens {
            *token_counts.entry(token.clone()).or_insert(0) += 1;
        }
        let tf: HashMap<String, f64> = token_counts
            .into_iter()
            .map(|(token, count)| (token, count as f64 / doc_len))
            .collect();

        let indexed = IndexedTool {
            metadata: metadata.clone(),
            tf,
        };

        // Acquire write locks — fail-closed on poison
        let mut entries = self
            .entries
            .write()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        let mut token_idx = self
            .token_index
            .write()
            .map_err(|_| DiscoveryError::LockPoisoned)?;

        // Check capacity (only for new tools, updates are always allowed)
        let is_update = entries.contains_key(&metadata.tool_id);
        if !is_update && entries.len() >= self.max_entries {
            return Err(DiscoveryError::IndexFull(self.max_entries));
        }

        // Remove old token index entries if updating
        if is_update {
            if let Some(old) = entries.get(&metadata.tool_id) {
                for old_token in old.tf.keys() {
                    if let Some(set) = token_idx.get_mut(old_token) {
                        set.remove(&metadata.tool_id);
                        if set.is_empty() {
                            token_idx.remove(old_token);
                        }
                    }
                }
            }
        }

        // Insert into inverted index
        let unique_tokens: HashSet<&String> = indexed.tf.keys().collect();
        for token in unique_tokens {
            token_idx
                .entry(token.clone())
                .or_default()
                .insert(metadata.tool_id.clone());
        }

        // Insert tool entry
        entries.insert(metadata.tool_id.clone(), indexed);

        Ok(())
    }

    /// Remove a tool from the index by its tool_id.
    ///
    /// No-op if the tool_id does not exist. Fails closed on lock poison.
    pub fn remove(&self, tool_id: &str) -> Result<(), DiscoveryError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        let mut token_idx = self
            .token_index
            .write()
            .map_err(|_| DiscoveryError::LockPoisoned)?;

        if let Some(old) = entries.remove(tool_id) {
            for old_token in old.tf.keys() {
                if let Some(set) = token_idx.get_mut(old_token) {
                    set.remove(tool_id);
                    if set.is_empty() {
                        token_idx.remove(old_token);
                    }
                }
            }
        }

        Ok(())
    }

    /// Search the index for tools matching the query.
    ///
    /// Returns `(tool_id, relevance_score)` pairs sorted by descending score,
    /// limited to `max_results`.
    ///
    /// # Scoring
    ///
    /// 1. TF-IDF cosine similarity on description + name tokens.
    /// 2. Bonus +0.3 for exact tool name match.
    /// 3. Bonus +0.2 for each domain tag match.
    /// 4. Scores clamped to [0.0, 1.0].
    pub fn search(
        &self,
        query: &str,
        max_results: usize,
    ) -> Result<Vec<(String, f64)>, DiscoveryError> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }

        let entries = self
            .entries
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        let idf = self.idf.read().map_err(|_| DiscoveryError::LockPoisoned)?;
        let token_idx = self
            .token_index
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;

        // Find candidate tool_ids from inverted index
        let mut candidates: HashSet<String> = HashSet::new();
        for token in &query_tokens {
            if let Some(tool_ids) = token_idx.get(token) {
                candidates.extend(tool_ids.iter().cloned());
            }
        }

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Build query TF vector
        let q_len = query_tokens.len() as f64;
        let mut query_tf: HashMap<&str, f64> = HashMap::new();
        for token in &query_tokens {
            *query_tf.entry(token.as_str()).or_insert(0.0) += 1.0 / q_len;
        }

        // Score each candidate via TF-IDF cosine similarity
        let query_lower = query.to_lowercase();
        let mut scored: Vec<(String, f64)> = candidates
            .into_iter()
            .filter_map(|tool_id| {
                let entry = entries.get(&tool_id)?;
                let score = cosine_similarity_tfidf(&query_tf, &entry.tf, &idf);

                // Bonus for exact name match
                let name_bonus = if entry.metadata.name.to_lowercase() == query_lower {
                    0.3
                } else if query_lower.contains(&entry.metadata.name.to_lowercase())
                    || entry.metadata.name.to_lowercase().contains(&query_lower)
                {
                    0.15
                } else {
                    0.0
                };

                // Bonus for domain tag match
                let tag_bonus: f64 = entry
                    .metadata
                    .domain_tags
                    .iter()
                    .filter(|tag| query_lower.contains(&tag.to_lowercase()))
                    .count() as f64
                    * 0.2;

                let total = (score + name_bonus + tag_bonus).min(1.0);
                Some((tool_id, total))
            })
            .collect();

        // Sort by score descending, then by tool_id for determinism
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        scored.truncate(max_results);
        Ok(scored)
    }

    /// Rebuild IDF (inverse document frequency) values from current index state.
    ///
    /// Must be called after batch ingestion to ensure accurate scoring.
    /// Individual ingests do NOT automatically rebuild IDF for performance —
    /// call this explicitly after bulk operations.
    pub fn rebuild_idf(&self) -> Result<(), DiscoveryError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        let token_idx = self
            .token_index
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        let mut idf = self.idf.write().map_err(|_| DiscoveryError::LockPoisoned)?;

        let n = entries.len() as f64;
        if n == 0.0 {
            idf.clear();
            return Ok(());
        }

        let mut new_idf = HashMap::with_capacity(token_idx.len());
        for (token, tool_ids) in token_idx.iter() {
            let df = tool_ids.len() as f64;
            // Standard IDF: ln(N / df) + 1 (smoothed to avoid zero)
            new_idf.insert(token.clone(), (n / df).ln() + 1.0);
        }

        *idf = new_idf;
        Ok(())
    }

    /// Return the number of indexed tools.
    pub fn len(&self) -> Result<usize, DiscoveryError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        Ok(entries.len())
    }

    /// Return whether the index is empty.
    pub fn is_empty(&self) -> Result<bool, DiscoveryError> {
        Ok(self.len()? == 0)
    }

    /// Retrieve metadata for a specific tool by ID.
    pub fn get(&self, tool_id: &str) -> Result<Option<ToolMetadata>, DiscoveryError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        Ok(entries.get(tool_id).map(|e| e.metadata.clone()))
    }

    /// Return all indexed tool IDs.
    pub fn tool_ids(&self) -> Result<Vec<String>, DiscoveryError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| DiscoveryError::LockPoisoned)?;
        Ok(entries.keys().cloned().collect())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOKENIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Tokenize text for indexing/search: lowercase, split on non-alphanumeric,
/// filter tokens shorter than 2 characters.
///
/// SECURITY (FIND-R182-004): Caps at `MAX_TOKENS_PER_TEXT` to prevent
/// excessive per-tool token allocations when ingesting many tools.
fn tokenize(text: &str) -> Vec<String> {
    const MAX_TOKENS_PER_TEXT: usize = 512;
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| s.len() >= 2)
        .take(MAX_TOKENS_PER_TEXT)
        .map(|s| s.to_string())
        .collect()
}

/// Maximum length of searchable text blob (defense-in-depth).
///
/// SECURITY (FIND-R121-001): Even with upstream validation in
/// `ToolMetadata::validate()`, cap the searchable text to prevent
/// memory exhaustion if validation is bypassed via direct `ingest()`.
const MAX_SEARCHABLE_TEXT_SIZE: usize = 16_384; // 16 KiB

/// Build a single searchable text blob from tool metadata.
fn build_searchable_text(metadata: &ToolMetadata) -> String {
    let cap = (metadata.name.len() * 2
        + metadata.description.len()
        + metadata.domain_tags.len() * 16
        + 16)
        .min(MAX_SEARCHABLE_TEXT_SIZE);
    let mut text = String::with_capacity(cap);
    // Name is repeated to give it higher weight
    text.push_str(&metadata.name);
    text.push(' ');
    text.push_str(&metadata.name);
    text.push(' ');
    text.push_str(&metadata.description);
    for tag in &metadata.domain_tags {
        text.push(' ');
        text.push_str(tag);
    }
    // SECURITY (FIND-R121-001): Truncate to prevent memory exhaustion
    // in tokenization if metadata validation was bypassed.
    if text.len() > MAX_SEARCHABLE_TEXT_SIZE {
        // Truncate at a char boundary
        let mut end = MAX_SEARCHABLE_TEXT_SIZE;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

// ═══════════════════════════════════════════════════════════════════════════════
// TF-IDF COSINE SIMILARITY
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute TF-IDF weighted cosine similarity between a query and a document.
fn cosine_similarity_tfidf(
    query_tf: &HashMap<&str, f64>,
    doc_tf: &HashMap<String, f64>,
    idf: &HashMap<String, f64>,
) -> f64 {
    let mut dot_product = 0.0;
    let mut query_norm_sq = 0.0;
    let mut doc_norm_sq = 0.0;

    // Compute query vector magnitude and dot product with document
    for (token, &q_tf) in query_tf {
        let token_idf = idf.get(*token).copied().unwrap_or(1.0);
        let q_weight = q_tf * token_idf;
        query_norm_sq += q_weight * q_weight;

        if let Some(&d_tf) = doc_tf.get(*token) {
            let d_weight = d_tf * token_idf;
            dot_product += q_weight * d_weight;
        }
    }

    // Compute document vector magnitude (over all doc tokens)
    for (token, &d_tf) in doc_tf {
        let token_idf = idf.get(token).copied().unwrap_or(1.0);
        let d_weight = d_tf * token_idf;
        doc_norm_sq += d_weight * d_weight;
    }

    let denom = query_norm_sq.sqrt() * doc_norm_sq.sqrt();
    if denom < f64::EPSILON {
        0.0
    } else {
        (dot_product / denom).clamp(0.0, 1.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_types::ToolSensitivity;

    fn make_tool(name: &str, description: &str, tags: &[&str]) -> ToolMetadata {
        ToolMetadata {
            tool_id: format!("test_server:{}", name),
            name: name.to_string(),
            description: description.to_string(),
            server_id: "test_server".to_string(),
            input_schema: json!({"type": "object"}),
            schema_hash: format!("hash_{}", name),
            sensitivity: ToolSensitivity::Low,
            domain_tags: tags.iter().map(|s| s.to_string()).collect(),
            token_cost: 100,
        }
    }

    // ── Tokenization tests ──────────────────────────────────────────────

    #[test]
    fn test_tokenize_basic() {
        let tokens = tokenize("Read a file from disk");
        assert_eq!(tokens, vec!["read", "file", "from", "disk"]);
    }

    #[test]
    fn test_tokenize_empty() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn test_tokenize_single_char_filtered() {
        let tokens = tokenize("a b cd ef");
        assert_eq!(tokens, vec!["cd", "ef"]);
    }

    #[test]
    fn test_tokenize_underscores_preserved() {
        let tokens = tokenize("read_file write_data");
        assert_eq!(tokens, vec!["read_file", "write_data"]);
    }

    #[test]
    fn test_tokenize_punctuation_splits() {
        let tokens = tokenize("file.read, data-write! network:connect");
        assert_eq!(
            tokens,
            vec!["file", "read", "data", "write", "network", "connect"]
        );
    }

    #[test]
    fn test_tokenize_mixed_case() {
        let tokens = tokenize("ReadFile WriteData");
        assert_eq!(tokens, vec!["readfile", "writedata"]);
    }

    // ── Searchable text building ────────────────────────────────────────

    #[test]
    fn test_build_searchable_text_includes_all_fields() {
        let tool = make_tool("read_file", "Read contents of a file", &["filesystem"]);
        let text = build_searchable_text(&tool);
        assert!(text.contains("read_file"));
        assert!(text.contains("Read contents of a file"));
        assert!(text.contains("filesystem"));
    }

    #[test]
    fn test_build_searchable_text_name_repeated() {
        let tool = make_tool("fetch", "Fetch URL", &[]);
        let text = build_searchable_text(&tool);
        // Name appears twice for higher weight
        let count = text.matches("fetch").count();
        assert!(count >= 2);
    }

    // ── Index ingest tests ──────────────────────────────────────────────

    #[test]
    fn test_ingest_single_tool() {
        let index = ToolIndex::new(100);
        let tool = make_tool(
            "read_file",
            "Read a file from the filesystem",
            &["filesystem"],
        );
        index.ingest(&tool).unwrap();
        assert_eq!(index.len().unwrap(), 1);
    }

    #[test]
    fn test_ingest_multiple_tools() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("read_file", "Read a file", &["filesystem"]))
            .unwrap();
        index
            .ingest(&make_tool("write_file", "Write a file", &["filesystem"]))
            .unwrap();
        index
            .ingest(&make_tool(
                "http_get",
                "Make an HTTP GET request",
                &["network"],
            ))
            .unwrap();
        assert_eq!(index.len().unwrap(), 3);
    }

    #[test]
    fn test_ingest_update_existing() {
        let index = ToolIndex::new(100);
        let tool1 = make_tool("read_file", "Read a file", &["filesystem"]);
        let tool2 = make_tool(
            "read_file",
            "Read file contents from disk",
            &["filesystem", "io"],
        );

        index.ingest(&tool1).unwrap();
        assert_eq!(index.len().unwrap(), 1);

        // Update with same tool_id
        // Note: tool_id is "test_server:read_file" in both cases
        index.ingest(&tool2).unwrap();
        assert_eq!(index.len().unwrap(), 1);

        // Check it was updated
        let meta = index.get("test_server:read_file").unwrap().unwrap();
        assert_eq!(meta.description, "Read file contents from disk");
    }

    #[test]
    fn test_ingest_rejects_empty_tool_id() {
        let index = ToolIndex::new(100);
        let mut tool = make_tool("read_file", "Read a file", &[]);
        tool.tool_id = String::new();
        let err = index.ingest(&tool).unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidMetadata(_)));
    }

    #[test]
    fn test_ingest_rejects_empty_name() {
        let index = ToolIndex::new(100);
        let mut tool = make_tool("", "Read a file", &[]);
        tool.tool_id = "test:empty".to_string();
        let err = index.ingest(&tool).unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidMetadata(_)));
    }

    #[test]
    fn test_ingest_capacity_limit() {
        let index = ToolIndex::new(2);
        index
            .ingest(&make_tool("tool1", "First tool description", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool2", "Second tool description", &[]))
            .unwrap();
        let err = index
            .ingest(&make_tool("tool3", "Third tool description", &[]))
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::IndexFull(2)));
    }

    #[test]
    fn test_ingest_capacity_allows_update_at_limit() {
        let index = ToolIndex::new(2);
        index
            .ingest(&make_tool("tool1", "First tool", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool2", "Second tool", &[]))
            .unwrap();
        // Update existing should work even at capacity
        index
            .ingest(&make_tool("tool1", "Updated first tool", &[]))
            .unwrap();
        assert_eq!(index.len().unwrap(), 2);
    }

    // ── Remove tests ────────────────────────────────────────────────────

    #[test]
    fn test_remove_existing() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("read_file", "Read a file", &["filesystem"]))
            .unwrap();
        assert_eq!(index.len().unwrap(), 1);

        index.remove("test_server:read_file").unwrap();
        assert_eq!(index.len().unwrap(), 0);
    }

    #[test]
    fn test_remove_nonexistent_is_noop() {
        let index = ToolIndex::new(100);
        index.remove("nonexistent").unwrap();
        assert_eq!(index.len().unwrap(), 0);
    }

    #[test]
    fn test_remove_cleans_inverted_index() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("unique_tool", "Unique special description", &[]))
            .unwrap();
        index.rebuild_idf().unwrap();

        // Search finds it
        let results = index.search("unique special", 10).unwrap();
        assert!(!results.is_empty());

        // Remove it
        index.remove("test_server:unique_tool").unwrap();
        index.rebuild_idf().unwrap();

        // Search no longer finds it
        let results = index.search("unique special", 10).unwrap();
        assert!(results.is_empty());
    }

    // ── Search tests ────────────────────────────────────────────────────

    #[test]
    fn test_search_empty_query() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("read_file", "Read a file", &[]))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_no_matches() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("read_file", "Read a file", &["filesystem"]))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("quantum entanglement", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_basic_match() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool(
                "read_file",
                "Read the contents of a file from the filesystem",
                &["filesystem"],
            ))
            .unwrap();
        index
            .ingest(&make_tool(
                "http_get",
                "Make an HTTP GET request to a URL",
                &["network"],
            ))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("read file", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "test_server:read_file");
    }

    #[test]
    fn test_search_relevance_ranking() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool(
                "read_file",
                "Read file contents from the filesystem",
                &["filesystem"],
            ))
            .unwrap();
        index
            .ingest(&make_tool(
                "write_file",
                "Write data to a file on the filesystem",
                &["filesystem"],
            ))
            .unwrap();
        index
            .ingest(&make_tool(
                "http_get",
                "Make an HTTP GET request to a remote server",
                &["network"],
            ))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("read file contents", 10).unwrap();
        assert!(!results.is_empty());
        // read_file should rank higher than write_file for "read file contents"
        if results.len() >= 2 {
            let read_pos = results.iter().position(|r| r.0 == "test_server:read_file");
            let write_pos = results.iter().position(|r| r.0 == "test_server:write_file");
            if let (Some(rp), Some(wp)) = (read_pos, write_pos) {
                assert!(rp < wp, "read_file should rank higher than write_file");
            }
        }
    }

    #[test]
    fn test_search_max_results_limit() {
        let index = ToolIndex::new(100);
        for i in 0..10 {
            index
                .ingest(&make_tool(
                    &format!("tool_{}", i),
                    &format!("Tool number {} for file operations", i),
                    &["filesystem"],
                ))
                .unwrap();
        }
        index.rebuild_idf().unwrap();

        let results = index.search("file operations", 3).unwrap();
        assert!(results.len() <= 3);
    }

    #[test]
    fn test_search_name_bonus() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool(
                "grep",
                "Search for patterns in text content",
                &[],
            ))
            .unwrap();
        index
            .ingest(&make_tool(
                "find_pattern",
                "Find a grep-like pattern in files",
                &[],
            ))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("grep", 10).unwrap();
        assert!(!results.is_empty());
        // The tool named "grep" should get a name bonus
        assert_eq!(results[0].0, "test_server:grep");
    }

    #[test]
    fn test_search_domain_tag_bonus() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool(
                "list_connections",
                "List active connections",
                &["network"],
            ))
            .unwrap();
        index
            .ingest(&make_tool(
                "list_files",
                "List files in a directory",
                &["filesystem"],
            ))
            .unwrap();
        index.rebuild_idf().unwrap();

        // Query mentioning "network" should boost the network-tagged tool
        let results = index.search("list network", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "test_server:list_connections");
    }

    #[test]
    fn test_search_scores_bounded() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("test", "test test test test", &["test"]))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results = index.search("test", 10).unwrap();
        for (_id, score) in &results {
            assert!(
                *score >= 0.0 && *score <= 1.0,
                "Score out of bounds: {}",
                score
            );
        }
    }

    // ── IDF rebuild tests ───────────────────────────────────────────────

    #[test]
    fn test_rebuild_idf_empty_index() {
        let index = ToolIndex::new(100);
        index.rebuild_idf().unwrap();
    }

    #[test]
    fn test_rebuild_idf_single_doc() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("tool1", "description of tool", &[]))
            .unwrap();
        index.rebuild_idf().unwrap();

        // With 1 document, IDF of any token = ln(1/1) + 1 = 1.0
        let idf = index.idf.read().unwrap();
        for (_token, &idf_val) in idf.iter() {
            assert!(
                (idf_val - 1.0).abs() < f64::EPSILON,
                "Single doc IDF should be 1.0, got {}",
                idf_val
            );
        }
    }

    #[test]
    fn test_rebuild_idf_rare_token_higher() {
        let index = ToolIndex::new(100);
        // "common" appears in both; "unique_alpha" only in tool1
        index
            .ingest(&make_tool("tool1", "common unique_alpha", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool2", "common shared", &[]))
            .unwrap();
        index.rebuild_idf().unwrap();

        let idf = index.idf.read().unwrap();
        let common_idf = idf.get("common").copied().unwrap_or(0.0);
        let unique_idf = idf.get("unique_alpha").copied().unwrap_or(0.0);
        assert!(
            unique_idf > common_idf,
            "Rare token IDF ({}) should be > common token IDF ({})",
            unique_idf,
            common_idf
        );
    }

    // ── get / tool_ids / is_empty ───────────────────────────────────────

    #[test]
    fn test_get_existing() {
        let index = ToolIndex::new(100);
        let tool = make_tool("read_file", "Read a file", &[]);
        index.ingest(&tool).unwrap();

        let result = index.get("test_server:read_file").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "read_file");
    }

    #[test]
    fn test_get_nonexistent() {
        let index = ToolIndex::new(100);
        let result = index.get("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_tool_ids() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool("tool_a", "Description A", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool_b", "Description B", &[]))
            .unwrap();

        let mut ids = index.tool_ids().unwrap();
        ids.sort();
        assert_eq!(ids, vec!["test_server:tool_a", "test_server:tool_b"]);
    }

    #[test]
    fn test_is_empty() {
        let index = ToolIndex::new(100);
        assert!(index.is_empty().unwrap());

        index
            .ingest(&make_tool("tool1", "Description", &[]))
            .unwrap();
        assert!(!index.is_empty().unwrap());
    }

    // ── Cosine similarity unit tests ────────────────────────────────────

    #[test]
    fn test_cosine_similarity_identical() {
        let idf: HashMap<String, f64> = [("hello".to_string(), 1.0)].into_iter().collect();
        let query: HashMap<&str, f64> = [("hello", 1.0)].into_iter().collect();
        let doc: HashMap<String, f64> = [("hello".to_string(), 1.0)].into_iter().collect();
        let sim = cosine_similarity_tfidf(&query, &doc, &idf);
        assert!(
            (sim - 1.0).abs() < 0.01,
            "Identical vectors should have similarity ~1.0"
        );
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let idf: HashMap<String, f64> = [("hello".to_string(), 1.0), ("world".to_string(), 1.0)]
            .into_iter()
            .collect();
        let query: HashMap<&str, f64> = [("hello", 1.0)].into_iter().collect();
        let doc: HashMap<String, f64> = [("world".to_string(), 1.0)].into_iter().collect();
        let sim = cosine_similarity_tfidf(&query, &doc, &idf);
        assert!(
            sim.abs() < 0.01,
            "Orthogonal vectors should have similarity ~0.0"
        );
    }

    #[test]
    fn test_cosine_similarity_empty() {
        let idf: HashMap<String, f64> = HashMap::new();
        let query: HashMap<&str, f64> = HashMap::new();
        let doc: HashMap<String, f64> = HashMap::new();
        let sim = cosine_similarity_tfidf(&query, &doc, &idf);
        assert!(sim.abs() < f64::EPSILON);
    }

    // ── Integration-style tests ─────────────────────────────────────────

    #[test]
    fn test_full_workflow_ingest_rebuild_search() {
        let index = ToolIndex::new(1000);

        // Ingest a set of tools
        let tools = vec![
            make_tool(
                "read_file",
                "Read the contents of a text file from the local filesystem",
                &["filesystem", "io"],
            ),
            make_tool(
                "write_file",
                "Write text data to a file on the local filesystem",
                &["filesystem", "io"],
            ),
            make_tool(
                "http_get",
                "Make an HTTP GET request to fetch data from a remote URL",
                &["network", "http"],
            ),
            make_tool(
                "http_post",
                "Send an HTTP POST request with a JSON body to a remote API",
                &["network", "http"],
            ),
            make_tool(
                "sql_query",
                "Execute a SQL query against a PostgreSQL database",
                &["database", "sql"],
            ),
            make_tool(
                "list_dir",
                "List files and directories in a given path",
                &["filesystem"],
            ),
        ];

        for tool in &tools {
            index.ingest(tool).unwrap();
        }
        index.rebuild_idf().unwrap();
        assert_eq!(index.len().unwrap(), 6);

        // Search for filesystem tools
        let results = index.search("read file from filesystem", 3).unwrap();
        assert!(!results.is_empty());
        // read_file should be top result
        assert_eq!(results[0].0, "test_server:read_file");

        // Search for network tools
        let results = index.search("http request network", 3).unwrap();
        assert!(!results.is_empty());
        // One of the http tools should be top
        assert!(results[0].0 == "test_server:http_get" || results[0].0 == "test_server:http_post");

        // Search for database tools
        let results = index.search("sql database query", 3).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "test_server:sql_query");
    }

    #[test]
    fn test_remove_and_reingest_frees_capacity() {
        let index = ToolIndex::new(2);
        index
            .ingest(&make_tool("tool1", "First tool", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool2", "Second tool", &[]))
            .unwrap();

        // At capacity — new tool rejected
        assert!(index
            .ingest(&make_tool("tool3", "Third tool", &[]))
            .is_err());

        // Remove one, freeing capacity
        index.remove("test_server:tool1").unwrap();
        assert_eq!(index.len().unwrap(), 1);

        // Now ingest should work
        index
            .ingest(&make_tool("tool3", "Third tool", &[]))
            .unwrap();
        assert_eq!(index.len().unwrap(), 2);
    }

    #[test]
    fn test_search_case_insensitive() {
        let index = ToolIndex::new(100);
        index
            .ingest(&make_tool(
                "ReadFile",
                "Read File Contents",
                &["FileSystem"],
            ))
            .unwrap();
        index.rebuild_idf().unwrap();

        // Lowercase query should match uppercase-containing entries
        let results = index.search("read file", 10).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_deterministic_ordering() {
        let index = ToolIndex::new(100);
        // Two tools with identical descriptions
        index
            .ingest(&make_tool("tool_b", "identical description", &[]))
            .unwrap();
        index
            .ingest(&make_tool("tool_a", "identical description", &[]))
            .unwrap();
        index.rebuild_idf().unwrap();

        let results1 = index.search("identical description", 10).unwrap();
        let results2 = index.search("identical description", 10).unwrap();

        assert_eq!(results1.len(), results2.len());
        for (r1, r2) in results1.iter().zip(results2.iter()) {
            assert_eq!(r1.0, r2.0);
        }
        // When scores are equal, should sort by tool_id alphabetically
        if results1.len() >= 2 && (results1[0].1 - results1[1].1).abs() < f64::EPSILON {
            assert!(results1[0].0 < results1[1].0);
        }
    }

    // ── Metadata serde roundtrip ────────────────────────────────────────

    #[test]
    fn test_tool_metadata_serde_roundtrip() {
        let tool = make_tool("read_file", "Read a file", &["filesystem", "io"]);
        let json = serde_json::to_string(&tool).unwrap();
        let deserialized: ToolMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(tool, deserialized);
    }

    #[test]
    fn test_tool_sensitivity_serde_roundtrip() {
        for sensitivity in [
            ToolSensitivity::Low,
            ToolSensitivity::Medium,
            ToolSensitivity::High,
        ] {
            let json = serde_json::to_string(&sensitivity).unwrap();
            let deserialized: ToolSensitivity = serde_json::from_str(&json).unwrap();
            assert_eq!(sensitivity, deserialized);
        }
    }

    #[test]
    fn test_tool_sensitivity_default() {
        // SECURITY (FIND-R46-013): Default changed to High (fail-closed).
        assert_eq!(ToolSensitivity::default(), ToolSensitivity::High);
    }

    #[test]
    fn test_discovery_result_serde_roundtrip() {
        use vellaveto_types::{DiscoveredTool, DiscoveryResult};

        let result = DiscoveryResult {
            tools: vec![DiscoveredTool {
                metadata: make_tool("test", "Test tool", &["test"]),
                relevance_score: 0.85,
                ttl_secs: 300,
            }],
            query: "test query".to_string(),
            total_candidates: 10,
            policy_filtered: 3,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DiscoveryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.query, "test query");
        assert_eq!(deserialized.total_candidates, 10);
        assert_eq!(deserialized.policy_filtered, 3);
        assert_eq!(deserialized.tools.len(), 1);
        assert_eq!(deserialized.tools[0].metadata.name, "test");
    }
}
