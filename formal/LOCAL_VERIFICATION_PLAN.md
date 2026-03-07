# Local Formal Verification Plan

Last updated: 2026-03-07

This is the execution plan for finishing the formal-verification program in the
repository as it exists now. It is intentionally local-facing and may be more
specific than the public roadmap in [`docs/FORMAL_VERIFICATION_PLAN.md`](/home/paolo/.vella-workspace/sentinel/docs/FORMAL_VERIFICATION_PLAN.md).

## Purpose

The public formal docs currently mix completed work, older milestone language,
and future work. This file is the working plan for closing the remaining gaps
between:

- the current formal suite in [`formal/README.md`](/home/paolo/.vella-workspace/sentinel/formal/README.md)
- the stronger March 6, 2026 program shape agreed during planning
- the actual proof kernels and local/CI reproduction story

## Current Snapshot

Completed now:

- Trusted assumption inventory check exists and is enforced in CI.
- Canonical Verus shell entrypoint exists:
  [`formal/tools/verify-verus.sh`](/home/paolo/.vella-workspace/sentinel/formal/tools/verify-verus.sh)
- Verus parity check exists:
  [`formal/tools/check-verus-parity.sh`](/home/paolo/.vella-workspace/sentinel/formal/tools/check-verus-parity.sh)
- Proof-owner ledger exists:
  [`formal/PROOF_OWNER_LEDGER.md`](/home/paolo/.vella-workspace/sentinel/formal/PROOF_OWNER_LEDGER.md)
- Verified production kernels exist for:
  - core verdict computation
  - constraint evaluation fail-closed control flow
  - capability attenuation arithmetic in
    `vellaveto-mcp/src/verified_capability_attenuation.rs`
  - capability grant restriction/invocation attenuation in
    `vellaveto-mcp/src/verified_capability_grant.rs`
  - capability literal matching/subset fast paths in
    `vellaveto-mcp/src/verified_capability_literal.rs`
  - capability child-glob rejection guard in
    `vellaveto-mcp/src/verified_capability_pattern.rs`
  - audit-chain verification guard in
    `vellaveto-audit/src/verified_audit_chain.rs`
  - audit append/recovery counter kernel in
    `vellaveto-audit/src/verified_audit_append.rs`
  - Merkle append/init/proof-shape fail-closed guards in
    `vellaveto-audit/src/verified_merkle.rs`
  - Merkle next-level/proof-fold/peak-fold kernel in
    `vellaveto-audit/src/verified_merkle_fold.rs`
  - Merkle proof sibling/orientation/parent-step kernel in
    `vellaveto-audit/src/verified_merkle_path.rs`
  - cross-rotation manifest linkage/path-safety guards in
    `vellaveto-audit/src/verified_rotation_manifest.rs`
  - fixed-point entropy alert gate in `vellaveto-engine/src/verified_entropy_gate.rs`
  - cross-call tracker field-capacity/update gate in
    `vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs`
  - DLP buffer arithmetic
  - engine path normalization kernel in `vellaveto-engine/src/path.rs`
- Entropy-backed steganographic alert decisions now flow through a fixed-point
  decision helper in `vellaveto-engine/src/entropy_gate.rs` instead of direct
  raw `f64` threshold comparisons in `collusion.rs`.

Known gaps against the March 6 plan:

- No `formal/verus/Cargo.toml` or `cargo verus` entrypoint yet.
- No Verus kernels yet for broader entropy math, split-detection/pattern
  completeness, full capability delegation semantics, or broader Merkle
  correctness proofs.
- Refinement exists only as a documented map plus executable witnesses, not a
  machine-checked forward simulation.
- Public-facing formal counts and paper text are still stale in places outside
  this local plan.

## Phase Plan

### Phase 0: Canonical local proof architecture

Goal:
- one local entrypoint for the formal mesh
- one canonical Verus entrypoint
- trusted assumptions enforced from the start
- stable internal ledger of proof ownership

Must have:
- `make verify-all` runs the formal mesh
- `make formal` includes trusted-assumption checks and Verus
- local plan and ownership ledger exist under `formal/`

Remaining:
- add `formal/verus/Cargo.toml` if `cargo verus` can be made stable enough

### Phase 1: Finish the policy-engine kernel in Verus

Goal:
- prove the real engine kernel, not a nearby abstraction

Must have:
- keep `verified_core.rs`
- keep `verified_constraint_eval.rs`
- replace the path-proof boundary so it targets
  [`vellaveto-engine/src/path.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/path.rs)
- tighten deterministic ordering story around the production tertiary ID
  tiebreak

Exit criteria:
- A1 fail-closed total verdict
- A2 unbounded all-skipped detection
- A3 deterministic total-order selection on the real comparator
- A4 forbid-override on the real combiner
- A5 path idempotence on the real engine normalizer

### Phase 2: DLP proof stack on integer/spec math

Prerequisite:
- keep entropy-backed security decisions off raw `f64` threshold comparisons;
  the production boundary now runs through
  `vellaveto-engine/src/entropy_gate.rs`, with the integer alert kernel now
  mirrored in `formal/verus/verified_entropy_gate.rs`

Must have:
- `verified_entropy.rs`
- `verified_dlp_pattern.rs` or an explicit decision that pattern completeness
  remains non-Verus and stays in Kani/tests
- keep `verified_cross_call_dlp.rs` as the field-capacity/update gate
- tracker invariants covering:
  - bounded overlap
  - capacity fail-closed
  - split-detection completeness within the modeled window
  - stale/expired entry presence does not change detection outcomes

Current status:
- integer alert gate landed in Verus
- cross-call field-capacity/update gate landed in Verus
- bounded overlap and overlap completeness already exist in the extracted DLP
  core proof
- the stale/expired-entry invariant is blocked on current runtime shape because
  `CrossCallDlpTracker` is session-scoped and has no per-entry expiry state yet

### Phase 3: Capability delegation kernel

Must have:
- pure delegation attenuation kernel
- explicit revocation model
- proof coverage for attenuation, transitivity, and revocation completeness

Current status:
- arithmetic attenuation kernel landed for remaining-depth decrement and expiry
  clamping
- grant restriction-shape and `max_invocations` attenuation kernel landed
- literal-only matching and literal-child subset fast paths landed
- child-glob rejection guard landed for the conservative subset rule
- broader parent-glob containment semantics, holder/issuer chain semantics, and
  revocation are still outside the Verus boundary

### Phase 4: Audit integrity kernel

Must have:
 - `verified_audit_append.rs`
 - `verified_audit_chain.rs`
 - `verified_merkle.rs`
 - explicit filesystem assumptions kept outside the proof boundary

Current status:
- append/recovery counter kernel landed in Verus
- per-entry audit-chain verification guard landed in Verus
- Merkle append/init/proof-shape fail-closed guards landed in Verus
- Merkle next-level/proof-fold/peak-fold kernel landed in Verus
- Merkle proof sibling/orientation/parent-step kernel landed in Verus
- explicit concrete Merkle hash/codec boundary documented in
  `formal/MERKLE_TRUST_BOUNDARY.md` and anchored to
  `vellaveto-audit/src/trusted_merkle_hash.rs`
- explicit audit filesystem boundary documented in
  `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` and anchored to
  `vellaveto-audit/src/trusted_audit_fs.rs`
- cross-rotation manifest linkage/path-safety guards landed in Verus
- abstract Merkle root/proof induction landed in Verus
- concrete hash-function assumptions and explicit filesystem assumptions are
  still outside the Verus boundary

### Phase 5: Refinement in Verus

Must have:
- safety-preserving forward simulation in Verus spec form
- abstract state includes policy snapshot, DLP tracker projection, verdict
  history, and audit sequence

Current status:
- [`formal/refinement/MCPPolicyEngine.md`](/home/paolo/.vella-workspace/sentinel/formal/refinement/MCPPolicyEngine.md)
  is only a documented refinement map with executable witnesses

### Phase 6: Canonical trust-boundary module

Must have:
- named assumptions module
- inventory checks tied directly to it
- no undocumented proof escape hatches

Current status:
- inventory enforcement exists
- canonical assumptions module does not

### Phase 7: Artifact and CI hardening

Must have:
- one reproducible local command for the formal mesh
- one canonical Verus command in CI
- pinned environment story

Current status:
- CI is close
- local orchestration is in place
- public counts and paper text are still stale

## Immediate Work Queue

1. Add `formal/verus/Cargo.toml` if a stable `cargo verus` entrypoint is
   practical.
2. Decide whether Phase 2 needs a real per-entry expiry model in
   `CrossCallDlpTracker` or whether the stale-entry invariant should move to the
   session-lifecycle boundary instead.
3. Then expand into remaining capability containment, the concrete Merkle
   hash-function boundary, and refinement kernels.

## Working Rule

Do not broaden public claims until the local execution path, proof boundary,
and parity story for the new kernel are in place.
