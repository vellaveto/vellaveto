# Merkle Trust Boundary

Last updated: 2026-03-07

This file names the remaining non-Verus assumptions for the audit Merkle layer.
The structural proof surface now covers:

- append/init/proof-shape guards
- proof-path sibling/orientation/parent selection
- next-level folding, peak folding, and abstract root reconstruction

The remaining trust boundary is intentionally narrow and anchored to code in:

- `vellaveto-audit/src/trusted_merkle_hash.rs`
- `vellaveto-audit/src/merkle.rs`
- `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` (for filesystem semantics)

## Named Assumptions

### MERKLE-HASH-1: RFC 6962 hashing is implemented as specified

`trusted_merkle_hash::hash_leaf_rfc6962()` and
`trusted_merkle_hash::hash_internal_rfc6962()` must compute:

- `SHA-256(0x00 || data)` for leaves
- `SHA-256(0x01 || left || right)` for internal nodes

Verus does not verify SHA-256 itself.

### MERKLE-HASH-2: Concrete hash soundness

The security story still relies on the usual cryptographic assumptions for
SHA-256:

- deterministic behavior
- practical collision resistance
- practical second-preimage resistance

The current Verus proofs treat the hash combiner structurally, not
cryptanalytically.

### MERKLE-CODEC-1: Hex codec correctness for persisted proof material

`trusted_merkle_hash::encode_hash_hex()` and
`trusted_merkle_hash::decode_hash_hex()` must preserve 32-byte Merkle hashes
without mutation. The verified proof-shape guard still checks decoded length
fail-closed in `merkle.rs`.

### MERKLE-FS-1: Audit filesystem semantics are trusted separately

The filesystem assumptions for leaf-file persistence, partial-write recovery,
and rotation continuity are now centralized in
`formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md`.

## Current State

What is proved in Verus:

- `formal/verus/verified_merkle.rs`
- `formal/verus/verified_merkle_fold.rs`
- `formal/verus/verified_merkle_path.rs`

What remains outside Verus:

- the concrete SHA-256 primitive
- the concrete hex codec
- filesystem durability and rename semantics described in
  `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md`

## Next Step

If we want to push Phase 4 further, the next decision is explicit:

1. keep `MERKLE-HASH-*` as a documented trust boundary and stop there, or
2. introduce a small axiomatized hash abstraction in Verus and list those axioms
   in `formal/trusted-assumptions.allowlist`

Either way, the boundary should remain centralized in
`vellaveto-audit/src/trusted_merkle_hash.rs`.
