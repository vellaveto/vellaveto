# Trusted Computing Base (TCB) — Vellaveto Formal Verification

> **Version:** 1.0.0
> **Date:** 2026-03-04
> **Status:** Phase 0 — baseline TCB document
> **Plan:** See [FORMAL_VERIFICATION_PLAN.md](FORMAL_VERIFICATION_PLAN.md) for the full roadmap

This document defines what Vellaveto formally verifies, what it trusts, and
what it does not verify. It is the authoritative reference for all "formally
verified" claims. An auditor, security reviewer, or Hacker News reader should
be able to read this document and understand exactly what is proven and what
is not.

---

## 1. Verified Properties

### 1.1 TLA+ Model Checking (6 specifications, 32 safety + 8 liveness)

Model checked by TLC with exhaustive state space exploration within declared
bounds. Properties hold for all reachable states within the model.

#### Policy Engine (MCPPolicyEngine.tla)

```
PROPERTY: S1 — Fail-Closed Default
MEANING:  When no policy matches an action, the verdict is always Deny.
          An attacker cannot find an input that produces Allow without
          a matching Allow policy.
TOOLS:    TLA+ (MCPPolicyEngine.tla, InvariantS1_FailClosed)
          Lean 4 (FailClosed.lean, s1_empty_policies_deny, s1_no_match_implies_deny)
          Coq (FailClosed.v, s1_empty_policies_deny, s1_no_match_implies_deny)
          Kani (proof_fail_closed_no_match_produces_deny, proof_verdict_deny_on_error)
SCOPE:    TLA+/Lean/Coq prove the property on abstract models with parameterized
          matching predicates. Kani proves it on actual Rust code with empty
          policy sets and error paths.
TRUST:    The correspondence between abstract matching predicates and the Rust
          implementation's glob/regex/exact matching is tested (10,200+ tests,
          24 fuzz targets) but not formally proven.
MAPS TO:  vellaveto-engine/src/lib.rs (evaluate_action, evaluate_with_compiled)
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
          Lean 4 (FailClosed.lean, s5_allow_requires_matching_allow)
          Coq (FailClosed.v, s5_allow_requires_matching_allow)
SCOPE:    Proven unconditionally on abstract models.
TRUST:    Same as S1.
MAPS TO:  vellaveto-engine/src/lib.rs
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
| AbacForbidOverride.v | S7-S10 (4 theorems) |
| CapabilityDelegation.v | S11-S16 (6 theorems) |
| CircuitBreaker.v | C1-C5 (7 theorems) |
| TaskLifecycle.v | T1-T3 (9 theorems) |

### 1.5 Kani Bounded Model Checking (9 harnesses on actual Rust)

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

Kani operates on extracted Rust code (formal/kani/src/path.rs) verified to be
identical to production code (vellaveto-engine/src/path.rs) via a CI diff check.

**Total: 132 verification instances across 5 tools.**

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
| **Policy sorting** | `SortedByPriority` operator | `sort_by` with three-level comparator (priority desc, deny-first, ID tiebreak) | Sort correctness tested. Will be proven by Kani K19 in Phase 3. |
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
| **Compiled/legacy path equivalence** | Two evaluation paths should produce identical verdicts | Tested by unit tests. Will be proven by Kani K20 in Phase 3. |
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
| **Z3** (future, Verus) | — | SMT solving | Microsoft Research, most widely deployed SMT solver |
| **Verus** (future, Phase 1) | — | Translation from Rust+specs to Z3 queries | OOPSLA 2023, two best papers OSDI 2024 |

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
| `tla-plus` | TLC 1.8.0 (Java 21) | 30 min | Push/PR to `formal/**`, weekly Monday 6:00 UTC |
| `lean` | Lean 4 (elan) | 30 min | Same |
| `coq` | Coq (apt package) | 30 min | Same |
| `kani` | cargo-kani (CBMC) | 45 min | Same |

### Integrity Checks

- **No sorry (Lean):** CI greps for `sorry` markers — any found = hard failure
- **No Admitted (Coq):** CI greps for `Admitted` markers — any found = hard failure
- **All harnesses pass (Kani):** Every harness must report `SUCCESSFUL`
- **Code sync (Kani):** CI diff check verifies `formal/kani/src/path.rs` matches `vellaveto-engine/src/path.rs`
- **All specs checked (TLA+):** All 6 specifications run through TLC

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
| TLA+ safety invariants | 32 |
| TLA+ liveness properties | 8 |
| Alloy assertions | 10 |
| Lean 4 theorems | 30 |
| Coq theorems | 43 |
| Kani proof harnesses | 9 |
| **Total verification instances** | **132** |
| Rust unit/integration tests | 10,200+ |
| Fuzz targets | 24 |
| Property-based tests (proptest) | ~50 |
| Audit rounds | 232 |

---

## 8. Roadmap

The current TCB represents Phase 0 of the formal verification plan. Planned
expansions:

| Phase | What Changes | New Properties |
|-------|-------------|---------------|
| **Phase 1** (Verus core) | Verus-verified verdict computation on actual Rust | V1-V8: fail-closed, priority, deny-dominance for ALL inputs |
| **Phase 2** (Verus DLP) | Verus-verified DLP buffer arithmetic on actual Rust | D1-D6: UTF-8 safety, overlap completeness for ALL inputs |
| **Phase 3** (Kani expansion) | 34 total Kani harnesses (14 existing + 20 new) | K10-K34: sort, equivalence, path/domain/IP, TLS |
| **Phase 4** (arXiv paper) | Public documentation of methodology | No new properties |

After Phase 1, property S1 (fail-closed) will be proven on the actual Rust code
for all possible inputs — not just the abstract model. The refinement gap between
TLA+ model and Rust code will be formally closed for the core verdict logic.

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

# Verify integrity
grep -rn 'sorry' formal/lean/Vellaveto/*.lean   # Must find nothing
grep -rn 'Admitted' formal/coq/Vellaveto/*.v     # Must find nothing
diff formal/kani/src/path.rs vellaveto-engine/src/path.rs  # Must be identical
```

---

## 10. Changelog

| Date | Change |
|------|--------|
| 2026-03-04 | Initial TCB document (Phase 0) |
