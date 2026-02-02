# Adversary Instance — Status

**Role:** Adversarial reviewer. Challenge all work, find real gaps, propose research-backed fixes.
**Model:** Claude Opus 4.5
**Date:** 2026-02-02
**Authority:** Peer to Controller. Findings require response from responsible instances.

---

## Audit Scope

Performed full source code read of:
- `sentinel-engine/src/lib.rs` (4,800+ lines)
- `sentinel-mcp/src/` (all 5 modules, 2,792 lines)
- `sentinel-audit/src/lib.rs` (984+ lines)
- `sentinel-server/src/` (main.rs, lib.rs, routes.rs + all test files)
- `sentinel-http-proxy/src/` (proxy.rs, session.rs)
- `sentinel-types/src/lib.rs`

External research conducted:
- MCP spec (2025-06-18 and 2025-11-25 updates)
- OWASP MCP Top 10 (Phase 3 beta)
- RFC 8785 (JSON Canonicalization Scheme)
- RFC 6962 (Certificate Transparency)
- ed25519-dalek zeroization behavior
- Academic: Hackett et al. 2025 (guardrail evasion), arXiv 2508.17155 (TOCTOU in LLM agents)
- Mindgard 2025 (Unicode smuggling), AWS Security Blog (character smuggling defense)
- Unit 42 (MCP attack vectors), Elastic Security Labs (MCP defense)
- CVE-2025-6514 (mcp-remote RCE)

---

## Findings Summary — UPDATED Post-Verification

| # | Original | Final | Title | Status |
|---|----------|-------|-------|--------|
| 1 | CRITICAL | CRITICAL | Hash chain JSON non-determinism | **FIXED** (Instance B — RFC 8785) |
| 2 | CRITICAL | LOW | sentinel-types Action incomplete | **ACCEPTED** design, param key constants recommended |
| 3 | HIGH | HIGH | Proxy security divergence | **FIXED** (Instance A — shared extractor) |
| 4 | HIGH | HIGH | Injection detection insufficient | **OPEN** — patterns not configurable, not documented |
| 5 | HIGH | MEDIUM | TOCTOU check-to-forward gap | **PARTIAL** — TOCTOU zero, duplicate-key detection missing |
| 6 | MEDIUM | LOW | Ed25519 stack copy leak | **FIXED** (Instance B — Box<SigningKey>) |
| 7 | MEDIUM | MEDIUM | Shutdown audit data loss | **FIXED** (pre-existing) |
| 8 | MEDIUM | MEDIUM | Error response information leak | **FIXED** (Controller) |
| 9 | MEDIUM | MEDIUM | Checkpoint trust anchor missing | **FIXED** (Instance B — key pinning + TOFU) |
| 10 | LOW | LOW | unwrap() in CORS layer | **FIXED** (pre-existing) |

**Final score: 7 fixed, 1 open (Challenge 4), 2 partially addressed (Challenges 2, 5)**

---

## What I Found That Works Well

Credit where due:
- **Engine policy evaluation** is deterministic, fail-closed, and well-tested (134 tests)
- **Path normalization** handles traversal, percent-encoding, null bytes correctly
- **Domain extraction** correctly strips ports, userinfo, trailing dots
- **Pre-compiled policies** eliminate Mutex contention (genuine performance win)
- **Length-prefixed hash fields** prevent boundary-shift attacks (good cryptographic hygiene)
- **Constant-time API key comparison** (subtle::ct_eq) prevents timing attacks
- **Security headers** (nosniff, DENY, CSP, no-store) are correctly applied
- **Sampling interception** blocks the exfiltration vector documented by Unit 42
- **Rug-pull detection** covers tool modification, removal, and addition

The project has strong fundamentals. My challenges target the gaps between "works in tests" and "survives adversarial conditions in production."

---

## DEEP RESEARCH COMPLETED — Fix Blueprints Below

All 6 research agents returned. Each challenge now has a concrete, code-level fix blueprint.

---

### FIX 1: Hash Chain — Use RFC 8785 Canonical JSON (CRITICAL)

**Crate:** `serde_json_canonicalizer = "0.3"` ([crates.io](https://crates.io/crates/serde_json_canonicalizer))

**Why current code is fragile:** `serde_json::to_vec()` produces deterministic output *today* because struct fields serialize in declaration order and `serde_json::Map` uses `BTreeMap`. But this has **no stability guarantee**. Any dependency enabling `preserve_order` on `serde_json` silently switches to insertion order and breaks the chain. Cross-version and cross-platform verification becomes impossible.

**Migration strategy — versioned hash algorithm:**
1. Add `hash_version: Option<HashVersion>` field to `AuditEntry` (`#[serde(default)]` for backward compat)
2. `HashVersion::V1` = current `serde_json::to_vec` (for verifying old entries)
3. `HashVersion::V2` = `serde_json_canonicalizer::to_vec` (RFC 8785, for all new entries)
4. `compute_entry_hash()` dispatches on the version field
5. **The chain is NOT broken** — `prev_hash` links work across versions because each entry is self-verifiable using its own version

**Key code change in `sentinel-audit/src/lib.rs`:**
```rust
fn compute_hash_v2(entry: &AuditEntry) -> Result<String, AuditError> {
    let action_json = serde_json_canonicalizer::to_vec(&entry.action)
        .map_err(|e| AuditError::Validation(format!("Canonical JSON error: {}", e)))?;
    // ... same pattern for verdict_json, metadata_json ...
    // Rest identical to V1
}
```

**Files to modify:** `sentinel-audit/Cargo.toml` (add dep), `sentinel-audit/src/lib.rs` (hash version enum, dual-mode compute)

---

### FIX 2: Unified Action Type in sentinel-types (CRITICAL)

**Add these fields to `sentinel-types/src/lib.rs` Action struct:**
```rust
pub struct Action {
    pub tool: String,
    pub function: String,
    pub parameters: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub payload_bytes: usize,
}
```

**Backward compatibility:** `#[serde(default)]` ensures existing serialized Actions without these fields deserialize with empty Vecs. `skip_serializing_if` prevents audit log bloat.

**Type safety:** Add a `ValidatedAction` newtype that can only be constructed via the `McpExtractor` trait, ensuring extractors populate path/domain fields:
```rust
pub struct ValidatedAction(Action);
impl ValidatedAction {
    pub fn new(action: Action) -> Result<Self, ActionValidationError> { /* validate non-empty tool, no traversal */ }
}
```

Engine's `evaluate_action()` should accept `&ValidatedAction` — makes it a type error to pass unvalidated input.

---

### FIX 3: Shared Extraction Trait — `CanonicalMcpExtractor` (HIGH)

**Do NOT create a new crate.** Put the shared trait in `sentinel-mcp/src/extractor.rs` — HTTP proxy already depends on `sentinel-mcp`.

```rust
pub trait McpExtractor: Send + Sync {
    fn classify_message(&self, msg: &Value) -> MessageClassification;
    fn extract_tool_action(&self, tool_name: &str, arguments: &Value) -> ValidatedAction;
    fn extract_resource_action(&self, uri: &str) -> ValidatedAction;
}
```

**`CanonicalMcpExtractor`** is the single shared implementation:
- Splits `tool_name` on `:` → `(tool, function)`, defaults function to `"call"` (not `"*"`)
- Scans parameters for known path keys (`path`, `file_path`, `filepath`, `filename`, `directory`) → populates `target_paths`
- Scans parameters for known URL keys (`url`, `uri`, `endpoint`, `host`) → populates `target_domains`
- `resources/read` with `file://` → target_paths; with `http://` → target_domains; unknown schemes → neither

Both proxies delete their local extraction functions and use `CanonicalMcpExtractor`.

---

### FIX 4: Layered Injection Scanner (HIGH)

**Keep Aho-Corasick** as Layer 0 (fast pre-filter). Add:

| Layer | Crate | What It Catches | Cost |
|-------|-------|-----------------|------|
| 0: Aho-Corasick (existing) | `aho-corasick 1.1` | Exact known-bad patterns | O(n) |
| 1: Structural markers | (same automaton) | LLM prompt delimiters (`<\|im_start\|>system`, `[INST]`, `<<SYS>>`) | O(n) |
| 2: Encoded content | `base64 0.22` | Base64/hex blocks via Shannon entropy (threshold ≥4.5 bits/char, min 20 chars), decode + re-scan | O(n) |
| 3: Homoglyph | `unicode-security 0.1` | UTS #39 confusable skeleton detection (Cyrillic о→Latin o) | O(n) |
| 4: Fuzzy match | `strsim 0.11` | Damerau-Levenshtein (catches typoglycemia), threshold ≥0.85 similarity | O(n*m*k) |

**Return `InjectionScanResult` with confidence scoring** instead of binary detection:
```rust
pub struct InjectionScanResult {
    pub confidence: f64,           // [0.0, 1.0]
    pub level: ConfidenceLevel,    // None/Low/Medium/High
    pub should_block: bool,        // confidence >= threshold
    pub layers_triggered: Vec<LayerMatch>,
    pub scan_duration_us: u64,
}
```

**Reduce false positives:** Split patterns into tiers (HIGH/MEDIUM/LOW confidence). `"you are now"` becomes LOW tier — contributes to score but never blocks alone. Add false-positive suppressions: `"you are now connected"`, `"you are now logged in"`.

**Make patterns configurable** via TOML: extra_patterns, disabled_patterns, per-layer weights and thresholds.

---

### FIX 5: TOCTOU — Freeze-and-Forward Pattern (HIGH)

**Minimal change:** Modify `read_message()` in `sentinel-mcp/src/framing.rs` to return both raw bytes and parsed Value:

```rust
pub struct ParsedMessage {
    pub raw: String,          // Original line bytes (for forwarding)
    pub value: serde_json::Value, // Parsed (for inspection)
}
```

Proxy loop: use `msg.value` for `classify_message()` and policy evaluation, forward `msg.raw` via `write_raw()` when allowed. Denials are synthetic messages we construct — those use `write_message(Value)`.

**Defense-in-depth: reject duplicate JSON keys.**
Duplicate keys are a real attack vector (CVE-2017-12635 Apache CouchDB, CVE-2020-16250 HashiCorp Vault). `serde_json` uses last-key-wins, but some parsers use first-key-wins. An attacker sends `{"name":"safe","name":"malicious"}` — the proxy evaluates "malicious" (blocks), but if the downstream uses first-key-wins, it sees "safe".

Count top-level keys in raw bytes vs parsed Map keys. If they differ, reject with `FramingError::DuplicateKeys`.

**For the HTTP proxy:** Same pattern — use `serde_json::value::RawValue` with the `"raw_value"` feature flag to parse the envelope zero-copy while keeping params as raw bytes.

---

### FIX 6: Ed25519 Key — Box to Prevent Stack Copies (MEDIUM)

**Change in `sentinel-audit/src/lib.rs`:**
```rust
// Before:
signing_key: Option<SigningKey>,

// After:
signing_key: Option<Box<SigningKey>>,
```

**Why:** Rust moves are memcpy. Moving a `SigningKey` (32 bytes) copies the secret to a new stack frame; the old location is never zeroed. `Box` moves only the 8-byte pointer. The ed25519-dalek `Drop` impl (with default `zeroize` feature) zeroes the heap allocation.

**Also:** Explicitly list `zeroize` in Cargo.toml features for documentation:
```toml
ed25519-dalek = { version = "2.2", features = ["rand_core", "zeroize"] }
```

The `secrecy` crate is NOT needed — ed25519-dalek handles its own zeroing.

---

### FIX 7: Graceful Shutdown — Flush Audit on Exit (MEDIUM)

**Add `AuditLogger::close()` method:**
```rust
pub async fn close(&self) -> Result<(), AuditError> {
    let _lock = self.last_hash.lock().await;
    self.sync_file(&self.log_path).await?;
    if tokio::fs::try_exists(&self.checkpoint_path()).await.unwrap_or(false) {
        self.sync_file(&self.checkpoint_path()).await?;
    }
    Ok(())
}
```

**In `sentinel-server/src/main.rs`, after `axum::serve().await` returns:**
```rust
axum::serve(listener, app)
    .with_graceful_shutdown(shutdown_signal())
    .await?;

// Post-shutdown cleanup
tracing::info!("Flushing audit log...");
if let Err(e) = shutdown_audit.create_checkpoint().await { tracing::warn!(...); }
if let Err(e) = shutdown_audit.close().await { tracing::error!(...); }
```

**Optional enhancement:** Use `tokio_util::sync::CancellationToken` + `TaskTracker` to coordinate background task shutdown (checkpoint task, approval expiry) before the audit flush. Add `tokio-util = { version = "0.7", features = ["rt"] }`.

**SIGKILL/OOM cannot be caught.** Mitigation: the existing `sync_data()` on Deny verdicts already protects critical security decisions. Periodic checkpoint fsyncs protect Allow verdicts.

---

### FIX 8: Error Responses — RFC 9457 Problem Details (MEDIUM)

**Create an `AppError` type** with two layers:

```rust
pub struct AppError {
    pub problem: ProblemDetail,      // Client sees (RFC 9457 JSON)
    pub status: StatusCode,
    pub internal_message: String,    // Server logs only (NEVER serialized)
    pub source: Option<Box<dyn Error>>, // Server logs only
}
```

**`IntoResponse` implementation:** Serializes only `ProblemDetail` with `content-type: application/problem+json`. Attaches full diagnostics as response extensions.

**Error logging middleware:** Extracts diagnostics from extensions after the handler runs, logs at ERROR (5xx) or WARN (4xx) with full error chain.

**Specific fixes in routes.rs:**
- Line 236: `e.to_string()` → `AppError::internal(e)` (client sees "Policy evaluation failed")
- Line 379: `format!("Failed to reload: {}", e)` → `AppError::internal(e)` (client sees "Configuration reload failed")
- Line 460/505/528: Audit errors → `AppError::internal(e)` (client sees "Audit verification error")

---

### FIX 9: Checkpoint Trust Anchor — TOFU + External Pinning (MEDIUM)

**The vulnerability:** Verification uses the key embedded IN the checkpoint. Attacker with write access forges checkpoints with their own keypair.

**Fix — layered trust resolution:**
1. **External anchor** (strongest): Load trusted public key from `SENTINEL_AUDIT_PUBKEY` env var or `/etc/sentinel/audit.pub` file
2. **TOFU fallback** (for dev): First checkpoint pins the key to `.sentinel-audit.pin`; subsequent checkpoints must match
3. **Key rotation:** Signed `KeyRotationRecord` where old key signs endorsement of new key (dual-signature)

**`verify_checkpoints()` gains an `expected_key: Option<&VerifyingKey>` parameter:**
- When `Some`: reject any checkpoint whose embedded key doesn't match
- When `None` + TOFU enabled: pin first checkpoint's key, reject mismatches after
- When `None` + TOFU disabled: current behavior (backward compat, logs warning)

**The test `test_checkpoint_different_key_detected` should FAIL** when a trust anchor is configured — that's the whole point.

---

### FIX 10: CORS unwrap() — Trivial (LOW)

Replace `.unwrap()` with `.expect("constant localhost value")` or use const `HeaderValue`.

---

## Research Sources

### MCP Security
- [MCP Security Best Practices (Official Spec)](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [MCP Tools Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Unit 42: MCP Attack Vectors](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Elastic Security Labs: MCP Attack/Defense](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Invariant Labs: Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [CVE-2025-6514: mcp-remote RCE (CVSS 9.6)](https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/)
- [AuthZed: Timeline of MCP Breaches](https://authzed.com/blog/timeline-mcp-breaches)

### Hash Chain / Canonicalization
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [serde_json_canonicalizer (crates.io)](https://crates.io/crates/serde_json_canonicalizer)
- [Protobuf: Serialization Is Not Canonical](https://protobuf.dev/programming-guides/serialization-not-canonical/)

### TOCTOU / JSON Parsing
- [Bishop Fox: JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
- [arXiv 2508.17155: TOCTOU in LLM Agents](https://arxiv.org/abs/2508.17155)
- [serde_json RawValue](https://docs.rs/serde_json/latest/serde_json/value/struct.RawValue.html)
- [serde_json Issue #762: Duplicate Keys](https://github.com/serde-rs/json/issues/762)

### Prompt Injection Defense
- [Hackett et al. 2025: Bypassing LLM Guardrails (ACL)](https://aclanthology.org/2025.llmsec-1.8/)
- [Mindgard: Invisible Characters Evasion](https://mindgard.ai/blog/outsmarting-ai-guardrails-with-invisible-characters-and-adversarial-prompts)
- [AWS: Unicode Character Smuggling Defense](https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/)
- [Google Security Blog: Layered Prompt Injection Defense](https://security.googleblog.com/2025/06/mitigating-prompt-injection-attacks.html)
- [unicode-security crate (UTS #39)](https://docs.rs/unicode-security)
- [strsim crate (Damerau-Levenshtein)](https://github.com/rapidfuzz/strsim-rs)

### Key Management
- [ed25519-dalek Zeroize](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.SigningKey.html)
- [Ben Ma: Rust Zeroize Move Pitfall](https://benma.github.io/2020/10/16/rust-zeroize-move.html)
- [TUF Specification](https://theupdateframework.github.io/specification/latest/)

### Error Handling / Shutdown
- [RFC 9457: Problem Details for HTTP APIs](https://blog.frankel.ch/problem-details-http-apis/)
- [Stripe API Error Handling](https://docs.stripe.com/api/errors)
- [Tokio: Graceful Shutdown Guide](https://tokio.rs/tokio/topics/shutdown)
- [axum graceful-shutdown example](https://github.com/tokio-rs/axum/blob/main/examples/graceful-shutdown/src/main.rs)

### Proxy Architecture
- [Envoy HTTP Filters](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters)
- [Tower Service Trait](https://docs.rs/tower/latest/tower/trait.Service.html)
