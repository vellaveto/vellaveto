# Proof Owner Ledger

Last updated: 2026-03-07

This ledger is the local ownership map for formal artifacts. It is not a public
marketing surface. Its job is to answer:

- who owns each proof family
- where the proof lives
- what production code it covers
- what parity witness exists

## Ownership

Current primary owner for all entries below: `Paolo Vella`

## Verus Kernels

| ID Range | Formal Artifact | Production Artifact | Parity Story |
|----------|-----------------|---------------------|--------------|
| V1-V8, V11-V12 | [`formal/verus/verified_core.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_core.rs) | [`vellaveto-engine/src/verified_core.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/verified_core.rs) | structural parity check + production unit tests + Kani bridge harnesses |
| ENG-CON-1-ENG-CON-4 | [`formal/verus/verified_constraint_eval.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_constraint_eval.rs) | [`vellaveto-engine/src/verified_constraint_eval.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/verified_constraint_eval.rs) and [`vellaveto-engine/src/constraint_eval.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/constraint_eval.rs) | structural parity check + wrapper call-site checks + Rust tests |
| CAP-ATT-1-CAP-ATT-4 | [`formal/verus/verified_capability_attenuation.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_capability_attenuation.rs) | [`vellaveto-mcp/src/verified_capability_attenuation.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/verified_capability_attenuation.rs) and [`vellaveto-mcp/src/capability_token.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/capability_token.rs) | structural parity check + wrapper call-site checks + focused `capability_token` tests |
| ENT-GATE-1-ENT-GATE-5 | [`formal/verus/verified_entropy_gate.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_entropy_gate.rs) | [`vellaveto-engine/src/verified_entropy_gate.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/verified_entropy_gate.rs) and [`vellaveto-engine/src/entropy_gate.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/entropy_gate.rs) | structural parity check + wrapper import boundary + focused `entropy_gate`/`collusion` tests |
| CC-DLP-1-CC-DLP-5 | [`formal/verus/verified_cross_call_dlp.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_cross_call_dlp.rs) | [`vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs) and [`vellaveto-mcp/src/inspection/cross_call_dlp.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/inspection/cross_call_dlp.rs) | structural parity check + wrapper call-site checks + focused `cross_call_dlp` tests |
| D1-D6 | [`formal/verus/verified_dlp_core.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_dlp_core.rs) | [`vellaveto-mcp/src/inspection/verified_dlp_core.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/inspection/verified_dlp_core.rs) | structural parity check + `CrossCallDlpTracker::update_buffer()` wiring + Rust tests |
| V9-V10 | [`formal/verus/verified_path.rs`](/home/paolo/.vella-workspace/sentinel/formal/verus/verified_path.rs) | [`vellaveto-engine/src/path.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/path.rs) | byte-level reimplementation of `normalize_decoded_path` + parity check + focused engine tests |

## Trusted Assumptions

| Artifact | Owner | Enforcement |
|----------|-------|-------------|
| [`formal/trusted-assumptions.allowlist`](/home/paolo/.vella-workspace/sentinel/formal/trusted-assumptions.allowlist) | Paolo Vella | checked by [`formal/tools/check-formal-trusted-assumptions.sh`](/home/paolo/.vella-workspace/sentinel/formal/tools/check-formal-trusted-assumptions.sh) |

## Refinement

| Artifact | Owner | Current Status |
|----------|-------|----------------|
| [`formal/refinement/MCPPolicyEngine.md`](/home/paolo/.vella-workspace/sentinel/formal/refinement/MCPPolicyEngine.md) | Paolo Vella | documented refinement map with executable witnesses; not yet machine-checked |

## Pending Kernel Families

These are planned but not yet owned by a landed Verus artifact:

| Planned Family | Target Code | Planned Phase |
|----------------|-------------|---------------|
| Broader entropy / DLP decision kernel | [`vellaveto-engine/src/collusion.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/collusion.rs) and [`vellaveto-engine/src/entropy_gate.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/entropy_gate.rs) | P2 (integer alert gate landed; float-to-fixed wrapper and wider DLP math still pending) |
| Broader cross-call tracker invariants | [`vellaveto-mcp/src/inspection/cross_call_dlp.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/inspection/cross_call_dlp.rs) | P2 (field-capacity/update gate landed; split-detection completeness and any stale-entry semantics still pending) |
| Broader capability delegation kernel | [`vellaveto-mcp/src/capability_token.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-mcp/src/capability_token.rs) and [`vellaveto-engine/src/deputy.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/deputy.rs) | P3 (depth/expiry attenuation landed; grant subset semantics and revocation still pending) |
| Audit chain kernel | [`vellaveto-audit/src/verification.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-audit/src/verification.rs) | P4 |
| Merkle kernel | [`vellaveto-audit/src/merkle.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-audit/src/merkle.rs) | P4 |
