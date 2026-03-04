# Trusted Computing Base (TCB) — Vellaveto Formal Verification

> **Version:** 2.0.0
> **Date:** 2026-03-04
> **Status:** Phases 0–3 complete (Verus V1-V8/D1-D6 + Kani K1-K25)
> **Plan:** See [FORMAL_VERIFICATION_PLAN.md](FORMAL_VERIFICATION_PLAN.md) for the full roadmap

This document defines what Vellaveto formally verifies, what it trusts, and
what it does not verify. It is the authoritative reference for all "formally
verified" claims. An auditor, security reviewer, or Hacker News reader should
be able to read this document and understand exactly what is proven and what
is not.

---

## 1. Verified Properties

### 1.1 TLA+ Model Checking (6 specifications, 34 safety + 8 liveness)

Model checked by TLC with exhaustive state space exploration within declared
bounds. Properties hold for all reachable states within the model.

#### Policy Engine (MCPPolicyEngine.tla)

```
PROPERTY: S1 — Fail-Closed Default
MEANING:  When no policy matches an action, the verdict is always Deny.
          An attacker cannot find an input that produces Allow without
          a matching Allow policy.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS1_FailClosed)
          Verus (verified_core.rs, V1 + V2 — ALL inputs, deductive)
          Lean 4 (FailClosed.lean, s1_empty_policies_deny, s1_no_match_implies_deny)
          Coq (FailClosed.v, s1_empty_policies_deny, s1_no_match_implies_deny)
          Kani (proof_fail_closed_no_match_produces_deny, proof_verdict_deny_on_error, proof_compute_verdict_fail_closed_empty)
SCOPE:    TLA+/Lean/Coq prove the property on abstract models with parameterized
          matching predicates. Verus proves it on the actual Rust verdict function
          for ALL possible inputs (deductive, no bounds). Kani proves it on
          actual Rust code with empty policy sets and error paths.
TRUST:    The correspondence between abstract matching predicates and the Rust
          implementation's glob/regex/exact matching is tested (10,200+ tests,
          24 fuzz targets) but not formally proven. The Verus proof closes the
          gap for the core verdict computation — it operates on actual Rust code.
MAPS TO:  vellaveto-engine/src/lib.rs, vellaveto-engine/src/verified_core.rs
```

```
PROPERTY: S2 — Priority Ordering
MEANING:  A higher-priority policy's verdict takes precedence over all
          lower-priority policies. The engine never skips a higher-priority
          match to apply a lower-priority one.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS2_PriorityOrder)
SCOPE:    Abstract model with integer priorities and 3 policies.
TRUST:    Rust sort_by implementation correctly orders policies by
          (priority desc, deny-first, id tiebreak). Covered by unit tests.
MAPS TO:  vellaveto-engine/src/lib.rs (sort_policies)
```

```
PROPERTY: S3 — Blocked Paths Override Allowed
MEANING:  A blocked path rule produces Deny even if the policy's base
          verdict is Allow.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS3_BlockedPathOverride)
SCOPE:    Abstract model with path matching predicate.
TRUST:    Glob/regex path matching correctness (fuzzed, not proven).
MAPS TO:  vellaveto-engine/src/lib.rs (check_path_rules)
```

```
PROPERTY: S4 — Blocked Domains Override Allowed
MEANING:  A blocked domain rule produces Deny even if the policy's base
          verdict is Allow.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS4_BlockedDomainOverride)
SCOPE:    Abstract model with domain matching predicate.
TRUST:    IDNA normalization, punycode handling (tested, not proven).
MAPS TO:  vellaveto-engine/src/lib.rs (check_network_rules)
```

```
PROPERTY: S5 — Allow Requires Matching Allow Policy
MEANING:  The verdict Allow is never produced without an explicit matching
          Allow policy. There is no implicit allow path.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS5_AllowRequiresMatch)
          Verus (verified_core.rs, V3 — ALL inputs, deductive)
          Lean 4 (FailClosed.lean, s5_allow_requires_matching_allow)
          Coq (FailClosed.v, s5_allow_requires_matching_allow)
          Kani (proof_compute_verdict_allow_requires_match)
SCOPE:    Proven unconditionally on abstract models (TLA+/Lean/Coq).
          Verus proves it on actual Rust code for ALL inputs. Kani
          proves it on actual Rust code within bounds.
TRUST:    Same as S1.
MAPS TO:  vellaveto-engine/src/lib.rs, vellaveto-engine/src/verified_core.rs
```

```
PROPERTY: S6 — Missing Context Produces Deny
MEANING:  When required evaluation context is missing, the verdict is Deny.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS6_MissingContextDeny)
SCOPE:    Abstract model.
TRUST:    Rust implementation correctly propagates missing context errors.
MAPS TO:  vellaveto-engine/src/lib.rs (context_check)
```

#### ABAC Combining (AbacForbidOverrides.tla)

```
PROPERTY: S7 — ABAC Forbid Dominance
MEANING:  If any ABAC constraint evaluates to Forbid, the combined result
          is Deny regardless of any Permit constraints.
TOOLS:    TLA+ (AbacForbidOverrides.tla, InvariantS7_ForbidDominance)
          Lean 4 (AbacForbidOverride.lean)
          Coq (AbacForbidOverride.v)
          Alloy (AbacForbidOverride.als)
          Kani (proof_abac_forbid_dominance)
SCOPE:    Proven unconditionally across all tools.
MAPS TO:  vellaveto-engine/src/abac.rs
```

```
PROPERTY: S8 — Forbid Ignores Priority
MEANING:  A low-priority Forbid overrides a high-priority Permit.
TOOLS:    TLA+ (AbacForbidOverrides.tla, InvariantS8)
          Alloy (AbacForbidOverride.als)
SCOPE:    Abstract model.
MAPS TO:  vellaveto-engine/src/abac.rs
```

```
PROPERTY: S9 — Permit Requires No Forbid
MEANING:  A Permit result is only produced when no Forbid constraint exists.
TOOLS:    TLA+ (AbacForbidOverrides.tla, InvariantS9)
          Lean 4, Coq, Alloy
SCOPE:    Proven unconditionally.
MAPS TO:  vellaveto-engine/src/abac.rs
```

```
PROPERTY: S10 — No Match Produces NoMatch
MEANING:  When no ABAC constraint matches, the result is NoMatch (not
          implicit Permit or Deny).
TOOLS:    TLA+ (AbacForbidOverrides.tla, InvariantS10)
          Lean 4, Coq, Alloy
          Kani (proof_abac_no_match_produces_nomatch)
SCOPE:    Proven unconditionally.
MAPS TO:  vellaveto-engine/src/abac.rs
```

#### Capability Delegation (CapabilityDelegation.tla)

```
PROPERTY: S11-S16 — Monotonic Attenuation
MEANING:  Delegated capabilities can only be restricted (attenuated), never
          expanded. Depth is bounded. Temporal constraints are monotonic.
          Issuer chain integrity is maintained. Terminal tokens cannot delegate.
TOOLS:    TLA+ (CapabilityDelegation.tla, D1-D5, DL1)
          Lean 4 (CapabilityDelegation.lean, 15 theorems)
          Coq (CapabilityDelegation.v, 6 theorems)
          Alloy (CapabilityDelegation.als, 6 assertions)
SCOPE:    Proven unconditionally on abstract models.
MAPS TO:  vellaveto-mcp/src/capability_token.rs
```

#### Cascading Failure (CascadingFailure.tla)

```
PROPERTY: C1-C5 — Circuit Breaker Safety
MEANING:  Chain depth is bounded. Error threshold triggers open state.
          Open circuit denies all requests. Half-open is transient.
          Probe success closes the circuit.
TOOLS:    TLA+ (CascadingFailure.tla, 5 invariants, 2 liveness)
          Coq (CircuitBreaker.v, 7 theorems)
SCOPE:    Model checked with bounded counters.
MAPS TO:  vellaveto-engine/src/cascading.rs
```

#### Task Lifecycle (MCPTaskLifecycle.tla)

```
PROPERTY: T1-T5 — State Machine Safety
MEANING:  Terminal states are absorbing. Initial state is valid. Policy
          is evaluated before transitions. Terminal tasks are audited.
          Bounded concurrency.
TOOLS:    TLA+ (MCPTaskLifecycle.tla, 5 invariants, 2 liveness)
          Coq (TaskLifecycle.v, 9 theorems)
SCOPE:    Model checked.
MAPS TO:  vellaveto-mcp/src/task_state.rs
```

#### Workflow Constraints (WorkflowConstraint.tla)

```
PROPERTY: WF1-WF4 — DAG Validity
MEANING:  Workflow predecessor constraints are satisfied. DAG is acyclic.
TOOLS:    TLA+ (WorkflowConstraint.tla, 2 invariants)
SCOPE:    Model checked.
MAPS TO:  vellaveto-engine/src/lib.rs (workflow constraint evaluation)
```

### 1.2 Alloy Bounded Model Checking (2 models, 10 assertions)

| Property | Model | ID | Status |
|----------|-------|-----|--------|
| Capability monotonic attenuation | CapabilityDelegation.als | S11 | Verified |
| Capability transitive attenuation | CapabilityDelegation.als | S12 | Verified |
| Capability depth budget | CapabilityDelegation.als | S13 | Verified |
| Capability temporal monotonicity | CapabilityDelegation.als | S14 | Verified |
| Terminal cannot delegate | CapabilityDelegation.als | S15 | Verified |
| Issuer chain integrity | CapabilityDelegation.als | S16 | Verified |
| ABAC forbid dominance | AbacForbidOverride.als | S7 | Verified |
| ABAC forbid ignores priority | AbacForbidOverride.als | S8 | Verified |
| ABAC permit requires no forbid | AbacForbidOverride.als | S9 | Verified |
| ABAC no match → NoMatch | AbacForbidOverride.als | S10 | Verified |

### 1.3 Lean 4 Proofs (5 files, 30 theorems, 0 sorry)

| File | Key Theorems |
|------|-------------|
| FailClosed.lean | s1_empty_policies_deny, s1_no_match_implies_deny, s5_allow_requires_matching_allow |
| Determinism.lean | evaluate_deterministic, determinism under substitution |
| PathNormalization.lean | normalize_idempotent, no_traversal_after_normalize |
| AbacForbidOverride.lean | forbid_dominance, permit_requires_no_forbid |
| CapabilityDelegation.lean | 15 theorems on attenuation, depth, expiry |

### 1.4 Coq Proofs (8 files, 43 theorems, 0 Admitted)

| File | Key Theorems |
|------|-------------|
| Types.v | 9 type definitions (foundation for all proofs) |
| FailClosed.v | s1_empty_policies_deny, s5_allow_requires_matching_allow |
| Determinism.v | evaluate_deterministic |
| PathNormalization.v | normalize_idempotent, no_traversal |
| AbacForbidOverride.v | S7-S10 (5 theorems/lemmas) |
| CapabilityDelegation.v | S11-S16 (8 theorems/lemmas) |
| CircuitBreaker.v | C1-C5 (6 theorems) |
| TaskLifecycle.v | T1-T3 (10 theorems) |

### 1.5 Verus Deductive Verification (23 proofs on actual Rust, ALL inputs)

Verus proves properties on the actual Rust code via Z3 SMT solving. Unlike
bounded model checking, Verus proofs hold for ALL possible inputs — no bounds,
no sampling. The verified code compiles with standard rustc after Verus erases
ghost annotations. The proof applies to the binary.

#### Core Verdict (V1-V8, 9 verified)

| ID | Property | Postcondition |
|----|----------|--------------|
| V1 | Fail-closed empty | `len() == 0 ==> Deny` |
| V2 | Fail-closed no match | All `!matched` → Deny |
| V3 | Allow requires match | `Allow` → ∃ matching Allow with no override |
| V4 | Rule override forces Deny | Path/network/IP override → Deny |
| V5 | Totality | Function always terminates |
| V6 | Priority ordering | Higher-priority wins (requires `is_sorted`) |
| V7 | Deny-dominance at equal priority | Deny beats Allow (requires `is_sorted`) |
| V8 | Conditional pass-through | Unfired condition → evaluation continues |

Source: `formal/verus/verified_core.rs` → `vellaveto-engine/src/verified_core.rs`

#### Cross-Call DLP (D1-D6, 14 verified)

| ID | Property | Meaning |
|----|----------|---------|
| D1 | UTF-8 boundary safety | `extract_tail` never returns start in mid-character |
| D2 | Buffer size bounded | Extracted tail ≤ `max_size` bytes |
| D3 | Byte accounting correct | `update_total_bytes` maintains consistency |
| D4 | Capacity fail-closed | At `max_fields`, `can_track_field` returns false |
| D5 | No arithmetic underflow | Saturating subtraction prevents wrapping |
| D6 | Overlap completeness | Secret ≤ 2 × overlap split at any byte fully covered |

Source: `formal/verus/verified_dlp_core.rs` → `vellaveto-mcp/src/inspection/verified_dlp_core.rs`

### 1.6 Kani Bounded Model Checking (25 harnesses on actual Rust)

#### K1-K9: Core Properties

| ID | Harness | Property | Bound |
|----|---------|----------|-------|
| K1 | proof_fail_closed_no_match_produces_deny | Empty policies → Deny | Unbounded |
| K2 | proof_path_normalize_idempotent | normalize(normalize(x)) = normalize(x) | 8-byte paths |
| K3 | proof_path_normalize_no_traversal | No ".." in normalized output | 8-byte paths |
| K4 | proof_saturating_counters_never_wrap | Counter monotonicity | u64 range |
| K5 | proof_verdict_deny_on_error | Errors → Deny | All error variants |
| K6 | proof_abac_forbid_dominance | Any Forbid → Deny | 4 constraints |
| K7 | proof_abac_no_match_produces_nomatch | No match → NoMatch | 4 constraints |
| K8 | proof_evaluation_deterministic | Same input → same output | 4 policies |
| K9 | proof_domain_normalize_idempotent | Domain normalization idempotent | 8-byte domains |

#### K10-K13: DLP Buffer Arithmetic (Verus D1-D6 Bridge)

| ID | Harness | Property | Verus Bridge |
|----|---------|----------|-------------|
| K10 | proof_extract_tail_no_panic | extract_tail safe for arbitrary bytes | D1, D2 |
| K11 | proof_utf8_char_boundary_exhaustive | All 256 byte values classified correctly | D1 |
| K12 | proof_can_track_field_fail_closed | At max_fields, always rejects | D4 |
| K13 | proof_update_total_bytes_saturating | Saturating accounting correct | D3, D5 |

#### K14-K18: Core Verdict Computation (Verus V1-V8 Bridge)

| ID | Harness | Property | Verus Bridge |
|----|---------|----------|-------------|
| K14 | proof_compute_verdict_fail_closed_empty | Empty → Deny | V1 |
| K15 | proof_compute_verdict_allow_requires_match | Allow requires matching Allow policy | V3 |
| K16 | proof_compute_verdict_rule_override_deny | rule_override_deny → Deny | V4 |
| K17 | proof_compute_verdict_conditional_passthrough | Unfired condition + continue → Continue | V8 |
| K18 | proof_sort_produces_sorted_output | Sort satisfies is_sorted precondition | V6, V7 |

#### K19-K25: ABAC, DLP Extensions, and Edge Cases

| ID | Harness | Property | Bridge |
|----|---------|----------|--------|
| K19 | proof_abac_forbid_ignores_priority_order | Forbid after Permit still Deny | S8 |
| K20 | proof_abac_permit_requires_no_forbid | Allow → no matching Forbid | S9 |
| K21 | proof_overlap_covers_small_secrets | Split secrets covered by overlap buffer | D6 |
| K22 | proof_overlap_region_size_saturating | Region size never overflows | D6 |
| K23 | proof_extract_tail_multibyte_boundary | 4-byte emoji never split mid-char | D1 |
| K24 | proof_context_deny_overrides_allow | context_deny forces Deny | V3 |
| K25 | proof_all_constraints_skipped_fail_closed | All skipped + no continue → Deny | V8 |

Kani operates on extracted Rust code verified to match production code via
9 production-parity unit tests (`cargo test --lib` in `formal/kani/`):
- `formal/kani/src/verified_core.rs` ↔ `vellaveto-engine/src/verified_core.rs` (identical algorithm, different doc comments)
- `formal/kani/src/dlp_core.rs` ↔ `vellaveto-mcp/src/inspection/verified_dlp_core.rs` (identical algorithm, different doc comments)
- `formal/kani/src/path.rs` ↔ `vellaveto-engine/src/path.rs` (identical algorithm, intentional error type difference)

**Total: 173 verification instances across 7 tools.**

---

## 2. Trusted Components

These are external dependencies whose correctness is assumed, not verified.

| Component | Version | Why Trusted | Audit Status |
|-----------|---------|-------------|--------------|
| **rustc / LLVM** | 1.88.0+ | Compiler correctness assumed | Ferrocene qualified to ISO 26262 ASIL D (upstream unqualified) |
| **rustls** | 0.23.x | TLS implementation | ISRG-funded, NCC Group (2023), Cure53 (2024) |
| **ed25519-dalek** | 4.x | Signature verification | Quarkslab (2023) |
| **aws-lc-sys** | 0.38.0 | Cryptographic primitives (FIPS 204 ML-DSA-65) | AWS-funded, FIPS 140-3 validated |
| **aho-corasick** | 1.x | Multi-pattern matching (injection scanner) | Extensively fuzzed by BurntSushi |
| **ring** | 0.17.x | HMAC-SHA256, key derivation | BoringSSL-derived, Google-maintained |
| **x509-parser** | 0.16.x | Certificate parsing | No formal audit known |
| **serde / serde_json** | 1.x | Serialization framework | De facto standard, no formal audit |
| **chrono** | 0.4.x | Date/time operations | Widely used, no formal audit |
| **tokio** | 1.x | Async runtime | Widely used, no formal audit |
| **percent-encoding** | 2.3.x | URL percent encoding/decoding | Part of servo-url, no formal audit |
| **OS / hardware** | Linux kernel | Execution environment | Outside scope |

### Cryptographic Assumptions

- Ed25519 signatures are unforgeable under the standard model.
- SHA-256 is collision-resistant.
- XChaCha20-Poly1305 provides authenticated encryption (consumer shield).
- Argon2id provides memory-hard key derivation (consumer shield).
- ML-DSA-65 (FIPS 204) provides post-quantum signature security (PQC feature).

---

## 3. Abstraction Boundaries

Every place where a formal model simplifies production code.

| Abstraction | Model | Production | Impact |
|-------------|-------|-----------|--------|
| **Pattern matching** | `matchesAction : Policy → Action → Bool` | Glob, regex, exact, prefix, suffix, infix wildcards with NFKC + homoglyph + leetspeak normalization | Model cannot detect matching bugs. Mitigated by 24 fuzz targets. |
| **Context conditions** | Single boolean predicate | 17 condition types (time window, call limit, agent match, circuit breaker, etc.) | Model proves condition-gated policies work. Individual condition correctness tested. |
| **ABAC attributes** | Abstract predicates | Entity store with group expansion, Cedar-style evaluation | Attribute resolution correctness tested, not proven. |
| **Policy sorting** | `SortedByPriority` operator | `sort_by` with three-level comparator (priority desc, deny-first, ID tiebreak) | Kani K18 proves sort produces `is_sorted` output (bounded). Verus V6/V7 prove verdict correct given sorted input (ALL inputs). |
| **String operations** | Not modeled | NFKC normalization, homoglyph mapping, case folding, percent-decode | All tested and fuzzed. Not formally verified. |
| **HashMap/collections** | Not modeled | `HashMap<String, T>` for tool index, policy lookup, DLP buffers | Correctness relies on Rust standard library. |
| **Concurrency** | Not modeled | `RwLock`, `Mutex`, atomics with `SeqCst` ordering | Engine core is synchronous. Concurrency in audit, DLP, cluster. |
| **Network I/O** | Not modeled | DNS resolution, TLS handshake, HTTP/WebSocket/gRPC transport | Outside formal verification scope. |

### Sound Over-Approximations

The Alloy model uses set identity for path/domain subset checking rather than
glob matching. This is more restrictive than the Rust implementation — the model
may reject inputs that the implementation would accept, but never the reverse.
This is the security-safe direction: the model over-denies.

---

## 4. Unverified Properties

These properties are intentionally NOT formally verified. Each has a rationale.

| Property | Why Not Verified | Mitigation |
|----------|-----------------|------------|
| **Side channels** (timing, cache) | Not modelable in current tools | Constant-time comparison in crypto paths (`subtle` crate) |
| **Availability / DoS** | Not modelable (resource exhaustion) | Rate limits, JSON depth/size bounds (MAX_SCAN_DEPTH=10), regex timeout, request body size limits |
| **Pattern completeness** (injection scanner) | Inherently open-ended (175+ patterns, evolving threat landscape) | 24 fuzz targets, encoding invariance tests, threat intelligence updates |
| **Distributed consensus** (cluster mode) | Redis-backed, single-writer per session | Not a consensus problem; Redis guarantees tested empirically |
| **Async Rust** | Unsupported by Verus, Kani, and all Rust verification tools | Engine core is synchronous by design. Async only in I/O layers. |
| **Compiled/legacy path equivalence** | Two evaluation paths should produce identical verdicts | Tested by unit tests. Both paths call the same `compute_verdict` core (Verus-verified). |
| **Glob/regex compilation correctness** | Complex interaction of glob library + Unicode normalization | 24 fuzz targets + 200+ unit tests. Glob library widely deployed. |
| **Injection scanner recall** | Cannot prove "all injections detected" | Defense-in-depth: multiple detection layers, encoding normalization |
| **SDK payload conformance** | 4 SDKs (Python/TypeScript/Go/Java) must match server format | SDK-specific test suites. Not formally linked to server types. |

---

## 5. Verification Tool Trust

Every tool in the verification stack is itself part of the TCB.

| Tool | Version | What We Trust | Basis for Trust |
|------|---------|--------------|-----------------|
| **TLC** (TLA+ model checker) | 1.8.0 | Exhaustive state exploration within declared bounds | 25+ years at AWS, Microsoft, Intel. Lamport's tool. |
| **Alloy Analyzer** | 6.x | Bounded relational model checking via SAT | 20+ years of academic use, SAT-solver backed |
| **Lean 4 kernel** | Current stable | Type checking and proof verification | Small trusted kernel (~10K LOC), community-audited, Mathlib |
| **Coq kernel** | System package | Type checking and proof verification | 40+ years, CompCert, seL4 |
| **CBMC** (via Kani) | Current stable | Bounded model checking of LLVM IR | 20+ years, AWS Firecracker verification |
| **Kani** | Current stable | Translation from Rust to CBMC | AWS-maintained, open-source, growing adoption |
| **Z3** (via Verus) | 4.13.x | SMT solving for Verus specs | Microsoft Research, most widely deployed SMT solver |
| **Verus** | 0.2026.03.01 | Translation from Rust+specs to Z3 queries | OOPSLA 2023, two best papers OSDI 2024, active development |

### Tool Independence

The verification stack uses multiple independent tools as defense-in-depth:
- TLA+ (TLC) and Alloy (SAT) use different solving backends
- Lean 4 and Coq use independent type theory kernels
- Kani (CBMC) operates on actual Rust via LLVM IR, not a model

A bug in one tool is unlikely to produce the same false positive in another.

---

## 6. CI Enforcement

Formal verification runs in CI via `.github/workflows/formal-verification.yml`.

| Job | Tool | Timeout | Trigger |
|-----|------|---------|---------|
| `tla-plus` | TLC 1.8.0 (Java 21) | 30 min | Push/PR to `formal/**`, `vellaveto-engine/src/**`, `vellaveto-mcp/src/inspection/**`, weekly Monday 6:00 UTC |
| `lean` | Lean 4 (elan) | 30 min | Same |
| `coq` | Coq (apt package) | 30 min | Same |
| `kani` | cargo-kani (CBMC) | 45 min | Same |
| `verus` | Verus 0.2026.03.01 (Z3) | 30 min | Same |

### Integrity Checks

- **No sorry (Lean):** CI greps for `sorry` markers — any found = hard failure
- **No Admitted (Coq):** CI greps for `Admitted` markers — any found = hard failure
- **All harnesses pass (Kani):** Every harness must report `SUCCESSFUL`
- **Code sync (Kani):** CI runs 9 production-parity unit tests verifying extracted code matches production behavior (identical test vectors, identical expected results)
- **All specs checked (TLA+):** All 6 specifications run through TLC
- **Verus verification (Verus):** Both `verified_core.rs` and `verified_dlp_core.rs` must report 0 errors

### Planned CI Additions (Phase 0+)

PR-level gating on security-critical paths will be added for:
- `vellaveto-engine/src/**` → Kani harnesses must pass
- `vellaveto-mcp/src/inspection/**` → Kani harnesses must pass
- `vellaveto-tls/src/**` → Kani harnesses must pass (Phase 3)
- `formal/**` → All verification jobs must pass

---

## 7. Verification Statistics

| Metric | Count |
|--------|-------|
| TLA+ safety invariants | 34 |
| TLA+ liveness properties | 8 |
| Alloy assertions | 10 |
| Lean 4 theorems | 30 |
| Coq theorems | 43 |
| Verus proofs (ALL inputs, deductive) | 23 |
| Kani proof harnesses (bounded) | 25 |
| **Total verification instances** | **173** |
| Rust unit/integration tests | 10,200+ |
| Fuzz targets | 24 |
| Property-based tests (proptest) | ~50 |
| Audit rounds | 235 |

---

## 8. Roadmap

Phases 0–3 are complete. The TCB now includes Verus deductive proofs on actual
Rust code and 25 Kani bounded model checking harnesses.

| Phase | Status | What Changed | Properties Added |
|-------|--------|-------------|-----------------|
| **Phase 0** (TCB + CI) | **Complete** | TCB document, CI workflow gating all 7 tools | Documentation baseline |
| **Phase 1** (Verus core) | **Complete** | Verus-verified verdict computation on actual Rust | V1-V8: fail-closed, priority, deny-dominance for ALL inputs |
| **Phase 2** (Verus DLP) | **Complete** | Verus-verified DLP buffer arithmetic on actual Rust | D1-D6: UTF-8 safety, overlap completeness for ALL inputs |
| **Phase 3** (Kani expansion) | **Complete** | 25 Kani harnesses (9 original + 16 new Verus bridge) | K10-K25: sort, ABAC, DLP, edge cases |
| **Phase 4** (arXiv paper) | Planned | Public documentation of methodology | No new properties |

Property S1 (fail-closed) is now proven on the actual Rust code for all possible
inputs via Verus V1/V2. The refinement gap between TLA+ model and Rust code is
formally closed for the core verdict logic (V1-V8) and DLP buffer arithmetic (D1-D6).

---

## 9. How to Verify Locally

```bash
# All formal verification
make formal

# Individual tools
make formal-tla    # TLA+ model checking (requires Java 21)
make formal-lean   # Lean 4 proofs (requires elan)
make formal-coq    # Coq proofs (requires coq)
make formal-kani   # Kani bounded checking (requires cargo-kani)
make formal-verus  # Verus deductive proofs (requires verus binary)

# Verus (manual)
verus --triggers-mode silent formal/verus/verified_core.rs      # 9 verified, 0 errors
verus --triggers-mode silent formal/verus/verified_dlp_core.rs  # 14 verified, 0 errors

# Verify integrity
grep -rn 'sorry' formal/lean/Vellaveto/*.lean   # Must find nothing
grep -rn 'Admitted' formal/coq/Vellaveto/*.v     # Must find nothing
diff formal/kani/src/path.rs vellaveto-engine/src/path.rs              # Must be identical
diff formal/kani/src/verified_core.rs vellaveto-engine/src/verified_core.rs  # Must be identical
diff formal/kani/src/dlp_core.rs vellaveto-mcp/src/inspection/verified_dlp_core.rs  # Must be identical
```

---

## 10. Changelog

| Date | Change |
|------|--------|
| 2026-03-04 | Phase 3 complete: 25 Kani harnesses (K1-K25), Verus bridge (K10-K25) |
| 2026-03-04 | Phase 2 complete: Verus DLP buffer verification (D1-D6, 14 verified) |
| 2026-03-04 | Phase 1 complete: Verus core verdict verification (V1-V8, 9 verified) |
| 2026-03-04 | Initial TCB document (Phase 0) |
