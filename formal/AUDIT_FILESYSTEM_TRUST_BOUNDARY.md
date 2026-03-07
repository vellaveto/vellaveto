# Audit Filesystem Trust Boundary

Last updated: 2026-03-07

This file names the remaining non-Verus filesystem assumptions for the audit
integrity layer. The concrete OS-dependent calls are centralized in:
Canonical registry: `formal/ASSUMPTION_REGISTRY.md`

- `vellaveto-audit/src/trusted_audit_fs.rs`

That boundary currently serves:

- `vellaveto-audit/src/logger.rs`
- `vellaveto-audit/src/rotation.rs`
- `vellaveto-audit/src/merkle.rs`

## Named Assumptions

### AUDIT-FS-1: Append targets the intended file

Open-with-append and parent-directory creation must append bytes to the
intended file path without redirecting or corrupting previously written data.

### AUDIT-FS-2: Flush and sync_data match the durability model

When the runtime asks for:

- flush-only durability
- `sync_data()` durability

the operating system and filesystem must honor those semantics closely enough
for the append-only audit and Merkle recovery logic to remain valid.

### AUDIT-FS-3: metadata() and read() report the current on-disk state

The audit proofs assume file length and file contents observed through
`metadata()` and `read()` correspond to the current persisted state of the
audit log, rotation manifest, and Merkle leaf file.

### AUDIT-FS-4: truncate/set_len removes partial-write tails

Merkle recovery assumes that truncating a leaf file to the last complete
32-byte boundary removes the partial tail and preserves the valid prefix.

### AUDIT-FS-5: rename preserves cross-rotation continuity

Rotation integrity assumes rename operations move the current audit log and
Merkle leaf file to their rotated destinations without silently duplicating,
dropping, or rewriting content.

## Current State

What is proved in Verus:

- append/recovery sequence arithmetic
- audit-chain verification guards
- rotation manifest linkage guards
- Merkle structure, path, and fold kernels

What remains outside Verus:

- concrete append/flush/sync/metadata/read/truncate/rename semantics
- filesystem durability and crash behavior
- permission enforcement by the host OS

## Relationship To Other Local Trust Artifacts

- `formal/MERKLE_TRUST_BOUNDARY.md` covers the concrete hash and hex-codec
  assumptions for the Merkle layer.
- This file covers the filesystem semantics used by audit append, rotation,
  and Merkle persistence.
