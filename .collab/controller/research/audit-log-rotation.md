# Tamper-Evident Audit Log Rotation: Research Report

**Date:** 2026-02-02
**Author:** Controller Instance (Research Agent a417aad)
**Sources:** RFC 6962 (Certificate Transparency), Sigstore/Rekor, NIST SP 800-92, tracing-appender

---

## Current State of Sentinel's Audit System

`sentinel-audit/src/lib.rs`:
- **JSONL format** with one JSON object per line
- **SHA-256 hash chain**: each entry contains `entry_hash` and `prev_hash`, with length-prefixed field hashing
- **Single-file design**: all entries to one file (`log_path`)
- **Chain initialization**: `initialize_chain()` verifies existing chain before trusting last hash
- **Tamper detection**: `verify_chain()` walks all entries linearly
- No rotation, sharding, or archival support

---

## 1. Hash Chain Log Rotation Strategies

### Option A: Bridge Entry (Recommended for Sentinel)

Store the final hash of the previous file as `prev_hash` in the first entry of the new file.

```rust
struct RotationBridge {
    segment_id: u64,
    previous_segment: PathBuf,
    previous_segment_final_hash: String,
    previous_segment_file_hash: String,   // SHA-256 of entire file
    previous_segment_entry_count: usize,
}
```

**How it works:**
1. When current log exceeds size/age threshold, trigger rotation
2. Compute `SHA-256(entire_file_contents)` of the closing segment
3. Rename `audit.jsonl` to `audit-{segment_id}-{timestamp}.jsonl`
4. Create new `audit.jsonl` with a rotation sentinel entry as first line
5. First real audit entry chains from the rotation sentinel's hash

**Advantages:** Simple, linear verification works across segments, self-contained.

### Option B: Separate Chain Metadata File

A `chain-manifest.jsonl` recording each segment's boundary hashes:

```json
{"segment": 0, "file": "audit-0001.jsonl", "first_hash": null, "last_hash": "abc123...", "entries": 50000, "file_sha256": "def456..."}
{"segment": 1, "file": "audit-0002.jsonl", "first_hash": "abc123...", "last_hash": "789xyz...", "entries": 48231, "file_sha256": "fed987..."}
```

**Advantages:** Fast cross-segment verification. **Disadvantages:** Two files to protect.

### Option C: Merkle Tree

Overkill for Sentinel's scale. Better suited for Certificate Transparency.

### Recommendation

**Use Option A (bridge entry) as primary, with Option B manifest as optional acceleration index.** The manifest can be regenerated from segment files if corrupted.

---

## 2. Sigstore/Rekor Patterns

### Sharded Logs

Rekor uses sharded logs where each shard is independent with its own tree ID. A shard list maps shards:

```json
{
  "shards": [
    {"treeID": "1234", "treeSize": 10000000, "encodedPublicKey": "..."},
    {"treeID": "5678", "treeSize": null, "encodedPublicKey": "..."}  // active
  ]
}
```

### Signed Tree Heads (STH)

Log operator periodically signs the current tree root — a checkpoint that verifiers can use to detect tampering or forking.

**Sentinel adaptation:** Periodically sign the chain head hash with Ed25519:

```rust
struct ChainCheckpoint {
    timestamp: String,
    entry_count: u64,
    segment_id: u64,
    chain_head_hash: String,
    signature: String,        // Ed25519 signature
}
```

### What Sentinel Should Adopt

1. **Signed checkpoints** — every K entries or T seconds, write signed checkpoint entry
2. **Segment manifests** — maintain index of rotated segments with boundary hashes
3. **Immutable segments** — rotated segments never modified; optionally store full-file hash

---

## 3. Certificate Transparency (RFC 6962) Patterns

### Merkle Hash Tree

- Leaf nodes: `SHA-256(0x00 || entry_data)`
- Internal nodes: `SHA-256(0x01 || left_child || right_child)`
- The prefix prevents second-preimage attacks

Sentinel's length-prefixed fields serve the same domain separation purpose.

### Consistency Proofs

CT's key insight: **log operator publishes STHs, monitors/auditors verify them.**

Sentinel should similarly:
1. Publish periodic checkpoints (STH equivalent)
2. Provide `verify_since(last_known_checkpoint)` API

### Maximum Merge Delay (MMD)

CT logs guarantee entries appear within bounded time. Sentinel's `sync_data()` for Deny verdicts handles the critical case.

---

## 4. Custom Rotation Implementation

### Architecture

```rust
pub struct RotatingAuditLogger {
    audit_dir: PathBuf,
    current_segment: Mutex<AuditSegment>,
    rotation_policy: RotationPolicy,
    signing_key: Option<ed25519_dalek::SigningKey>,
}

pub struct AuditSegment {
    segment_id: u64,
    file_path: PathBuf,
    entry_count: u64,
    file_size: u64,
    last_hash: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub enum RotationPolicy {
    MaxSize(u64),
    MaxAge(chrono::Duration),
    SizeOrAge { max_size: u64, max_age: chrono::Duration },
    Never,   // Current behavior
}
```

### File Naming Convention

```
audit/
  audit-segment-0001-20260201T000000Z.jsonl   # completed, immutable
  audit-segment-0002-20260201T120000Z.jsonl   # completed, immutable
  audit-segment-0003-20260202T000000Z.jsonl   # active (current)
  manifest.jsonl                                # segment index
```

### Why NOT tracing-appender

`tracing-appender` is designed for human-readable logs:
- No custom rotation triggers (size-based)
- No rotation callbacks (needed for bridge entries)
- No hash chain maintenance

**Use `tracing-appender` for diagnostic logs only.** Keep custom rotation for the audit JSONL log.

---

## 5. Verification at Scale

### Performance Reference

| Entries | Linear Verify | Checkpointed (1K interval) | Parallel (10 segments) |
|---------|--------------|---------------------------|----------------------|
| 10K | ~20ms | ~20ms (worst case) | ~2ms |
| 100K | ~200ms | ~20ms | ~20ms |
| 1M | ~2s | ~20ms | ~200ms |
| 10M | ~20s | ~20ms | ~2s |

### Strategy 1: Checkpointed Verification

Store periodic checkpoints every 1000 entries. Verification only goes back to last trusted checkpoint.

```rust
pub async fn verify_since_checkpoint(
    &self,
    checkpoint: &ChainCheckpoint,
) -> Result<ChainVerification, AuditError> {
    let entries = self.load_entries_from(checkpoint.entry_count).await?;
    // Only verify entries after the checkpoint
}
```

### Strategy 2: Parallel Segment Verification

With rotated segments, verify in parallel:

```rust
// Phase 1: Verify each segment internally (parallel)
let results = futures::future::join_all(
    segments.iter().map(|seg| self.verify_segment_internal(seg))
).await;

// Phase 2: Verify cross-segment links (sequential, fast)
for window in segments.windows(2) {
    assert_eq!(last_hash_of(&window[0]), first_prev_hash_of(&window[1]));
}
```

### Strategy 3: Incremental Verification with Watermark

Maintain "verified up to" watermark. Background verifier runs periodically:

```rust
pub struct VerificationState {
    verified_up_to: u64,
    verified_hash: String,
    last_verified: chrono::DateTime<chrono::Utc>,
}
```

---

## 6. Log Integrity Monitoring

### Pattern 1: Write-Ahead Verification

Before each write, verify previous entry's hash matches in-memory state. Detects tampering between writes.

### Pattern 2: Heartbeat Entries

Write periodic heartbeat entries even when no actions occur. Detects log truncation (missing heartbeats reveal deletion).

### Pattern 3: External Witnessing (Most Important for Production)

Periodically publish chain head hash to an independent system:

```rust
pub trait ChainWitness: Send + Sync {
    async fn publish_checkpoint(&self, checkpoint: &ChainCheckpoint) -> Result<(), WitnessError>;
    async fn verify_checkpoint(&self, checkpoint: &ChainCheckpoint) -> Result<bool, WitnessError>;
}

// Simple file-based witness (different volume)
pub struct FileWitness { witness_path: PathBuf }

// Remote witness (HTTP POST to monitoring service)
pub struct RemoteWitness { endpoint: String, auth_token: String }
```

A hash chain in a single file protects against undetected modification but NOT wholesale replacement. External witnessing makes the chain verifiable by a third party.

### Pattern 4: OS-Level Immutability

```bash
# Make rotated segments immutable
chattr +i audit-segment-0001.jsonl
# Use append-only on active segment
chattr +a audit-current.jsonl
```

### Pattern 5: Anomaly Detection

Monitor for:
- Timestamp gaps (non-monotonic)
- Entry count discontinuities
- File size decreases (truncation)
- Inode changes (file replacement)

---

## Recommended Implementation Plan

### Phase 1: Signed Checkpoints (Low Effort, High Value)
- Add `ChainCheckpoint` struct
- Write checkpoint entries every N entries
- Enables fast incremental verification and external witnessing

### Phase 2: Log Rotation with Bridge Entries
- Implement `RotatingAuditLogger`
- Size-based and time-based rotation policies
- Bridge entry at segment boundaries
- Segment manifest file
- Immutable segment protection

### Phase 3: Parallel Verification
- Segment-aware verification
- Parallel segment verification via `tokio::join!`
- Incremental verification from checkpoint watermark

### Phase 4: External Witnessing
- `ChainWitness` trait
- File-based witness (different volume)
- Optional remote witness endpoint
- Heartbeat entries for gap detection

---

## Recommended Crates

| Crate | Purpose | Notes |
|-------|---------|-------|
| `tracing-appender` | Diagnostic log rotation | Daily/hourly, non-blocking |
| `sha2` (already used) | SHA-256 | Pure Rust |
| `ed25519-dalek` | Checkpoint signing | For signed tree heads |
| `tempfile` (already used) | Atomic file operations | For safe rotation rename |

---

## Summary Table

| Area | Pattern | Complexity | Value |
|------|---------|------------|-------|
| Rotation | Bridge entry | Low | Critical |
| Rotation | Segment manifest | Low | High |
| Verification | Checkpointed incremental | Low | Critical |
| Verification | Parallel segment | Medium | High |
| Monitoring | Signed checkpoints | Medium | Critical |
| Monitoring | External witnessing | Medium | High |
| Monitoring | Heartbeat entries | Low | Medium |
| Monitoring | OS-level immutability | Low | High |

---

## References

- RFC 6962 (Certificate Transparency): https://www.rfc-editor.org/rfc/rfc6962
- RFC 9162 (CT v2): https://www.rfc-editor.org/rfc/rfc9162
- Sigstore Rekor: https://github.com/sigstore/rekor
- Rekor sharding: https://github.com/sigstore/rekor/blob/main/pkg/sharding/README.md
- Google Trillian: https://github.com/google/trillian
- Transparency.dev: https://transparency.dev
- tracing-appender: https://docs.rs/tracing-appender
- ed25519-dalek: https://docs.rs/ed25519-dalek
- NIST SP 800-92: https://csrc.nist.gov/publications/detail/sp/800-92/final

---

*Last updated: 2026-02-02*
