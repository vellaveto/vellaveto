# Formal Verification Scope

What is proven, what is tested, and what is assumed.

For the full property catalog with source traceability, see
[formal/README.md](../formal/README.md).

---

## What Is Formally Verified

### TLA+ Model Checking (6 specifications, 32 safety + 8 liveness)

| Property | Specification | ID | Status |
|----------|-------------|-----|--------|
| Fail-closed (no match → Deny) | MCPPolicyEngine | S1 | Verified |
| Priority ordering | MCPPolicyEngine | S2 | Verified |
| Blocked paths override allowed | MCPPolicyEngine | S3 | Verified |
| Blocked domains override allowed | MCPPolicyEngine | S4 | Verified |
| Allow requires matching Allow policy | MCPPolicyEngine | S5 | Verified |
| Missing context → Deny | MCPPolicyEngine | S6 | Verified |
| Conditional continue | MCPPolicyEngine | S7 | Verified |
| ABAC forbid dominance | AbacForbidOverrides | S7 | Verified |
| ABAC forbid ignores priority | AbacForbidOverrides | S8 | Verified |
| ABAC permit requires no forbid | AbacForbidOverrides | S9 | Verified |
| ABAC no match → NoMatch | AbacForbidOverrides | S10 | Verified |
| Terminal absorbing | MCPTaskLifecycle | T1 | Verified |
| Initial state | MCPTaskLifecycle | T2 | Verified |
| Policy evaluated | MCPTaskLifecycle | T3 | Verified |
| Terminal audited | MCPTaskLifecycle | T4 | Verified |
| Bounded concurrency | MCPTaskLifecycle | T5 | Verified |
| Chain depth bounded | CascadingFailure | C1 | Verified |
| Error threshold triggers open | CascadingFailure | C2 | Verified |
| Open circuit denies all | CascadingFailure | C3 | Verified |
| Half-open transient | CascadingFailure | C4 | Verified |
| Probe success closes | CascadingFailure | C5 | Verified |
| Workflow predecessor | WorkflowConstraint | S8 | Verified |
| Acyclic DAG | WorkflowConstraint | S9 | Verified |
| Delegation depth monotonic | CapabilityDelegation | D1 | Verified |
| Delegation depth bounded | CapabilityDelegation | D2 | Verified |
| Delegation temporal monotonicity | CapabilityDelegation | D3 | Verified |
| Issuer chain integrity | CapabilityDelegation | D4 | Verified |
| Terminal isolation | CapabilityDelegation | D5 | Verified |

### Alloy Bounded Model Checking (2 models, 10 assertions)

| Property | Model | ID | Status |
|----------|-------|-----|--------|
| Capability monotonic attenuation | CapabilityDelegation | S11 | Verified |
| Capability transitive attenuation | CapabilityDelegation | S12 | Verified |
| Capability depth budget | CapabilityDelegation | S13 | Verified |
| Capability temporal monotonicity | CapabilityDelegation | S14 | Verified |
| Terminal cannot delegate | CapabilityDelegation | S15 | Verified |
| Issuer chain integrity | CapabilityDelegation | S16 | Verified |
| ABAC forbid dominance | AbacForbidOverride | S7 | Verified |
| ABAC forbid ignores priority | AbacForbidOverride | S8 | Verified |
| ABAC permit requires no forbid | AbacForbidOverride | S9 | Verified |
| ABAC no match → NoMatch | AbacForbidOverride | S10 | Verified |

### Lean 4 Proofs (5 files, 21 theorems, 0 sorry)

| Property | File | Status |
|----------|------|--------|
| Fail-closed (S1, S5) | FailClosed.lean | Verified |
| Evaluation determinism | Determinism.lean | Verified |
| Path normalization idempotence | PathNormalization.lean | Verified |
| ABAC forbid dominance (S7-S10) | AbacForbidOverride.lean | Verified |
| Capability delegation (S11-S16) | CapabilityDelegation.lean | Verified |

### Coq Proofs (8 files, 27 theorems, 0 Admitted)

| Property | File | Status |
|----------|------|--------|
| Fail-closed (S1, S5) | FailClosed.v | Verified |
| Evaluation determinism | Determinism.v | Verified |
| Path normalization idempotence | PathNormalization.v | Verified |
| ABAC forbid-overrides (S7-S10) | AbacForbidOverride.v | Verified |
| Capability delegation (S11-S16) | CapabilityDelegation.v | Verified |
| Circuit breaker (C1-C5) | CircuitBreaker.v | Verified |
| Task lifecycle (T1-T3) | TaskLifecycle.v | Verified |

### Kani Proof Harnesses (9 harnesses on actual Rust code)

| Property | Harness | Status |
|----------|---------|--------|
| Fail-closed (K1) | proof_fail_closed_no_match_produces_deny | Verified |
| Path normalize idempotent (K2) | proof_path_normalize_idempotent | Verified |
| Path normalize no traversal (K3) | proof_path_normalize_no_traversal | Verified |
| Saturating counters (K4) | proof_saturating_counters_never_wrap | Verified |
| Verdict deny on error (K5) | proof_verdict_deny_on_error | Verified |
| ABAC forbid dominance (K6) | proof_abac_forbid_dominance | Verified |
| ABAC no-match → NoMatch (K7) | proof_abac_no_match_produces_nomatch | Verified |
| Evaluation determinism (K8) | proof_evaluation_deterministic | Verified |
| Domain normalize idempotent (K9) | proof_domain_normalize_idempotent | Verified |

**Total: 54+ verified properties across 5 tools.**

---

## What Is Tested But Not Formally Verified

These properties are covered by the test suite (8,972+ tests, 24 fuzz targets,
~50 proptest generators) but not by formal specifications:

| Property | Coverage |
|----------|----------|
| Glob/regex pattern compilation correctness | 24 fuzz targets, ~200 unit tests |
| Path traversal normalization (full impl) | Unit tests + proptest + fuzz |
| DNS rebinding / IP resolution | Unit tests |
| DLP multi-layer decode (base64, percent, combos) | Unit tests + fuzz |
| Injection detection (Aho-Corasick + NFKC + semantic) | Unit tests + fuzz |
| Tool squatting (Levenshtein + homoglyph) | Unit tests |
| Multimodal inspection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM) | Unit tests |
| Audit log rotation and continuity | Unit tests |
| OAuth 2.1 / JWT validation | Unit tests |
| Rate limiting correctness | Unit tests |
| MCP protocol conformance | Integration tests |
| Transport-specific behavior (HTTP/stdio/WS/gRPC) | Integration tests |

---

## What Is Assumed (Not Verified or Tested)

| Assumption | Rationale |
|------------|-----------|
| **Ed25519 signature correctness** | Uses `ed25519-dalek`, a widely-audited implementation. Cryptographic primitive verification is outside project scope. |
| **SHA-256 / HMAC-SHA256 correctness** | Uses `ring` (BoringSSL-derived). Same rationale. |
| **Rust memory safety** | No `unsafe` in library code. Relies on the Rust compiler and standard library. |
| **TLS correctness** | TLS termination is handled by upstream infrastructure (nginx, Caddy, cloud LB). |
| **OS filesystem semantics** | `write()` + `fsync()` provide the expected durability guarantees. |
| **Clock monotonicity** | Timestamps use `std::time::Instant` (monotonic) for durations and `SystemTime` for wall clock. NTP jumps could affect wall-clock ordering of audit entries. |
| **DNS resolver correctness** | System DNS resolver returns accurate results. DNS poisoning is mitigated by private-IP blocking but not eliminated. |

---

## Known Abstraction Gaps in Formal Models

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob patterns abstracted to wildcard + exact | Cannot detect glob-specific matching bugs | 24 fuzz targets cover pattern compilation |
| Path/domain subset uses set identity, not glob matching | Alloy model is more restrictive than Rust implementation | Sound over-approximation (security-safe direction) |
| ABAC CHOOSE vs priority-ordered selection | Reported `policy_id` may differ from Rust | Does not affect Deny/Allow decision |
| Conditional policies simplified to fire/no-fire | Constraint-level deny paths not modeled | Covered by 8,972+ unit tests |
| `RequireApproval` verdict not modeled in TLA+ | Approval flow not formally verified | Covered by integration tests |
| `max_invocations` not checked during attenuation | Child could inherit unlimited invocations | Known implementation gap, tracked |
| Grant subset axiomatized in Lean/Coq | Cannot verify concrete grant coverage | Verified by Alloy bounded model checking |
| Small model bounds (3 policies, 2 actions) | Exhaustive for structural properties | Properties are independent of bound values |

---

## Verification in CI

Formal checks run in CI via `.github/workflows/formal-verification.yml`,
triggered on `formal/**` path changes and weekly schedule:

| Tool | CI Job | Toolchain |
|------|--------|-----------|
| TLA+ (6 specs) | `tla-plus` | Java 21 + tla2tools.jar |
| Lean 4 (5 files) | `lean` | elan + lake |
| Coq (7 files) | `coq` | apt coq package |
| Kani (9 harnesses) | `kani` | cargo-kani + CBMC |
| Alloy (2 models) | Local only | Requires Alloy Analyzer JAR |

The CI also verifies zero `sorry` (Lean) and zero `Admitted` (Coq) markers.

For local verification: `make formal` (all tools) or `make formal-tla`,
`make formal-lean`, etc. for individual tools. The `make verify` target
includes formal checks when tools are available and skips gracefully
when they are not.

---

## Relation to Other Verification

| Layer | What It Catches | What It Misses |
|-------|----------------|----------------|
| **Formal specs** | Algorithmic correctness violations across *all* possible inputs | Implementation bugs, concurrency, I/O |
| **Fuzz testing** | Edge cases in parsing, encoding, pattern matching | Algorithmic design flaws |
| **Property tests** | Statistical coverage of invariants | Adversarial inputs (not guided) |
| **Unit tests** | Known-input regression | Novel inputs, emergent behavior |
| **Integration tests** | End-to-end transport/protocol correctness | Performance, scale |

Together, these layers provide defense in depth. No single layer is sufficient.
