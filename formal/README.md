# Formal Verification — Vellaveto MCP Policy Engine

Formal specifications of Vellaveto's core security properties using TLA+, Alloy, Lean 4, Coq, and Kani.

This is the first formal model of MCP policy enforcement in any framework,
addressing Gap #1 (severity: Critical) from `docs/MCP_SECURITY_GAPS.md`.

## What's Verified

| Model | Framework | Properties | What It Covers |
|-------|-----------|------------|----------------|
| `MCPPolicyEngine.tla` | TLA+ | S1–S7, L1–L2 | First-match-wins policy evaluation, fail-closed defaults |
| `AbacForbidOverrides.tla` | TLA+ | S7–S10, L3 | ABAC forbid-overrides combining algorithm |
| `MCPTaskLifecycle.tla` | TLA+ | T1–T5, TL1–TL2 | MCP Task primitive lifecycle state machine |
| `CascadingFailure.tla` | TLA+ | C1–C5, CL1–CL2 | Multi-agent cascading failure circuit breaker |
| `CapabilityDelegation.tla` | TLA+ | D1–D5, DL1 | Capability delegation depth/expiry/issuer invariants |
| `CapabilityDelegation.als` | Alloy | S11–S16 | Capability token delegation with monotonic attenuation |
| `AbacForbidOverride.als` | Alloy | S7–S10 | ABAC forbid-override combining algorithm |
| `Determinism.lean` | Lean 4 | — | Policy evaluation determinism (same input → same verdict) |
| `FailClosed.lean` | Lean 4 | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `PathNormalization.lean` | Lean 4 | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.lean` | Lean 4 | S7–S10 | ABAC forbid-overrides (first forbid wins) |
| `CapabilityDelegation.lean` | Lean 4 | S11–S16 | Capability delegation attenuation proofs |
| `kani/proofs.rs` | Kani | K1–K9 | Bounded model checking of actual Rust implementation |
| `FailClosed.v` | Coq | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `Determinism.v` | Coq | — | Policy evaluation determinism (same input → same verdict) |
| `PathNormalization.v` | Coq | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.v` | Coq | S7–S10 | ABAC forbid-overrides combining algorithm (first forbid wins) |
| `CapabilityDelegation.v` | Coq | S11–S16 | Capability token delegation with monotonic attenuation |
| `CircuitBreaker.v` | Coq | C1–C5 | Circuit breaker state machine properties |
| `TaskLifecycle.v` | Coq | T1–T3 | MCP Task lifecycle terminal absorbing, valid transitions |

**132 verification instances** across 5 tools:
- **TLA+:** 32 safety invariants + 8 liveness properties (6 specs)
- **Alloy:** 10 assertions (2 models)
- **Lean 4:** 30 theorems (5 files, no `sorry`)
- **Coq:** 43 theorems (8 files, no `Admitted`)
- **Kani:** 9 proof harnesses on actual Rust code

## Coverage Matrix

| Property | TLA+ | Alloy | Lean 4 | Coq | Kani |
|----------|------|-------|--------|-----|------|
| **S1: Fail-closed** | S1 | — | S1 | S1 | K1, K5 |
| **S2: Priority ordering** | S2 | — | — | — | — |
| **S3: Blocked paths override** | S3 | — | — | — | — |
| **S4: Blocked domains override** | S4 | — | — | — | — |
| **S5: Allow requires match** | S5 | — | S5 | S5 | — |
| **S6: Missing context → Deny** | S6 | — | — | — | — |
| **S7: Forbid dominance** | S7 | S7 | S7 | S7 | K6 |
| **S8: Forbid ignores priority** | S8 | S8 | S8 | S8 | — |
| **S9: Permit requires no forbid** | S9 | S9 | S9 | S9 | — |
| **S10: No match → NoMatch** | S10 | S10 | S10 | S10 | K7 |
| **S11: Monotonic attenuation** | D1 | S11 | S11 | S11 | — |
| **S12: Transitive attenuation** | — | S12 | S12 | S12 | — |
| **S13: Depth bounded** | D2 | S13 | S13 | S13 | — |
| **S14: Temporal monotonicity** | D3 | S14 | S14 | S14 | — |
| **S15: Terminal no delegate** | D5 | S15 | S15 | S15 | — |
| **S16: Issuer chain integrity** | D4 | S16 | S16 | S16 | — |
| **C1: Chain depth bounded** | C1 | — | — | C1 | — |
| **C2: Error threshold → open** | C2 | — | — | C2 | — |
| **C3: Open denies all** | C3 | — | — | C3 | — |
| **C4: Half-open resolves** | C4 | — | — | C4 | — |
| **C5: Probe success closes** | C5 | — | — | C5 | — |
| **T1: Terminal absorbing** | T1 | — | — | T1 | — |
| **T2: Initial state** | T2 | — | — | T2 | — |
| **T3: Valid transitions** | T3 | — | — | T3 | — |
| **Path idempotence** | — | — | idem | idem | K2 |
| **No traversal** | — | — | no_dot | no_dot | K3 |
| **Determinism** | — | — | det | det | K8 |
| **Counter monotonicity** | — | — | — | — | K4 |
| **Domain norm idempotent** | — | — | — | — | K9 |

## Directory Structure

```
formal/
  README.md                          ← This file
  tla/
    MCPCommon.tla                    ← Shared operators (pattern matching, sorting)
    MCPPolicyEngine.tla              ← Policy evaluation state machine
    MC_MCPPolicyEngine.tla           ← Model companion (concrete constants for TLC)
    MCPPolicyEngine.cfg              ← TLC model checker configuration
    AbacForbidOverrides.tla          ← ABAC forbid-overrides evaluation
    MC_AbacForbidOverrides.tla       ← Model companion (concrete constants for TLC)
    AbacForbidOverrides.cfg          ← TLC configuration for ABAC
    MCPTaskLifecycle.tla             ← MCP Task primitive lifecycle
    MC_MCPTaskLifecycle.tla          ← Model companion (task IDs)
    MCPTaskLifecycle.cfg             ← TLC configuration for tasks
    CascadingFailure.tla             ← Multi-agent cascading failure
    MC_CascadingFailure.tla          ← Model companion (agents, tools)
    CascadingFailure.cfg             ← TLC configuration for cascading failure
    CapabilityDelegation.tla         ← Capability delegation state machine
    MC_CapabilityDelegation.tla      ← Model companion (principals, depth)
    CapabilityDelegation.cfg         ← TLC configuration for delegation
  alloy/
    CapabilityDelegation.als         ← Capability token delegation model (S11-S16)
    AbacForbidOverride.als           ← ABAC forbid-override model (S7-S10)
  lean/
    lakefile.lean                    ← Lake build configuration
    lean-toolchain                   ← Lean 4 version pin
    Vellaveto/
      Determinism.lean              ← Evaluation determinism proof
      FailClosed.lean               ← Fail-closed and S1/S5 proofs
      PathNormalization.lean        ← Path normalization idempotence
      AbacForbidOverride.lean       ← ABAC forbid-override S7-S10 proofs
      CapabilityDelegation.lean     ← Capability delegation S11-S16 proofs
  coq/
    _CoqProject                      ← Build configuration (lists .v files)
    Makefile                         ← coq_makefile wrapper
    Vellaveto/
      Types.v                        ← Shared types (Verdict, Policy, Action, ABAC, CapToken)
      FailClosed.v                   ← Fail-closed and S1/S5 proofs (4 theorems)
      Determinism.v                  ← Evaluation determinism proof (4 theorems)
      PathNormalization.v            ← Path normalization idempotence (5 theorems)
      AbacForbidOverride.v           ← ABAC forbid-override S7-S10 (4 theorems)
      CapabilityDelegation.v         ← Capability delegation S11-S16 (6 theorems)
      CircuitBreaker.v               ← Circuit breaker C1-C5 (7 theorems)
      TaskLifecycle.v                ← Task lifecycle T1-T3 (9 theorems)
  kani/
    README.md                        ← Kani setup and usage guide
    proofs.rs                        ← Proof harnesses (9 properties)
```

## Tooling Setup

### TLA+ (TLC Model Checker)

Download `tla2tools.jar` from the [TLA+ releases](https://github.com/tlaplus/tlaplus/releases).

Requirements:
- Java 11+
- `tla2tools.jar` (or install the TLA+ Toolbox IDE)

### Alloy Analyzer 6

Download from [alloytools.org](https://alloytools.org/download.html).

Requirements:
- Java 11+
- `org.alloytools.alloy.dist.jar`

### Coq

Install via opam or nix:

```bash
# Via opam (recommended):
opam install coq

# Via nix:
nix-shell -p coq
```

Requirements:
- Coq 8.16+ (tested with 8.19)
- `coq_makefile` (included with Coq)

## Running Verification

### TLA+ Policy Engine (S1–S6, L1–L2)

```bash
cd formal/tla
# Note: TLC runs against the MC (model companion) module, which extends the spec.
java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla
```

Expected output: all 7 invariants and 2 temporal properties pass with zero violations.

### TLA+ ABAC Forbid-Overrides (S7–S10, L3)

```bash
cd formal/tla
java -jar tla2tools.jar -config AbacForbidOverrides.cfg MC_AbacForbidOverrides.tla
```

Expected output: all 4 invariants and 1 liveness property pass with zero violations.

### TLA+ Capability Delegation (D1–D5, DL1)

```bash
cd formal/tla
java -jar tla2tools.jar -config CapabilityDelegation.cfg MC_CapabilityDelegation.tla
```

Expected output: all 5 invariants and 1 liveness property pass with zero violations.

### Alloy Capability Delegation (S11–S16)

```bash
cd formal/alloy
# GUI mode (recommended for first run — shows counterexample visualizations):
java -jar org.alloytools.alloy.dist.jar

# Open CapabilityDelegation.als in the Alloy Analyzer and execute all check commands.
```

Expected output: all 6 assertions pass with 0 counterexamples found.

### Alloy ABAC Forbid-Override (S7–S10)

```bash
cd formal/alloy
java -jar org.alloytools.alloy.dist.jar

# Open AbacForbidOverride.als and execute all check commands.
```

Expected output: all 4 assertions pass with 0 counterexamples found.

### TLA+ Task Lifecycle (T1–T5, TL1–TL2)

```bash
cd formal/tla
java -jar tla2tools.jar -config MCPTaskLifecycle.cfg MC_MCPTaskLifecycle.tla
```

Expected output: all 5 invariants and 2 temporal properties pass with zero violations.

### TLA+ Cascading Failure (C1–C5, CL1–CL2)

```bash
cd formal/tla
java -jar tla2tools.jar -config CascadingFailure.cfg MC_CascadingFailure.tla
```

Expected output: all 5 invariants and 2 temporal properties pass with zero violations.

### Lean 4 Proofs

```bash
cd formal/lean
# Install Lean 4 if not already present:
#   curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
lake build
```

Expected output: all five files type-check with no `sorry` markers and no warnings.

### Coq Proofs

```bash
cd formal/coq
make
```

Expected output: all 8 `.v` files compile cleanly with no `Admitted` markers.
Verify: `grep -r "Admitted\|admit" Vellaveto/*.v` returns no matches.

### Kani Proof Harnesses (K1–K9)

```bash
cd formal/kani
# Install Kani: cargo install --locked kani-verifier && cargo kani setup
cargo kani --harness proof_fail_closed_no_match_produces_deny
cargo kani --harness proof_path_normalize_idempotent
cargo kani --harness proof_path_normalize_no_traversal
cargo kani --harness proof_saturating_counters_never_wrap
cargo kani --harness proof_verdict_deny_on_error
cargo kani --harness proof_abac_forbid_dominance
cargo kani --harness proof_abac_no_match_produces_nomatch
cargo kani --harness proof_evaluation_deterministic
cargo kani --harness proof_domain_normalize_idempotent
```

Expected output: all 9 harnesses report VERIFICATION:- SUCCESSFUL.

## Property Catalog

### Policy Engine Safety (S1–S6)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S1 | **Fail-closed:** no matching policy → Deny, never Allow | `vellaveto-engine/src/lib.rs:417-419` | `MCPPolicyEngine.tla`, `FailClosed.lean/v`, Kani K1/K5 |
| S2 | **Priority ordering:** policies evaluated in priority-descending order | `vellaveto-engine/src/lib.rs:209-224` | `MCPCommon.tla:SortedByPriority` |
| S3 | **Blocked paths override allowed:** first-match blocked path → Deny | `vellaveto-engine/src/rule_check.rs:50-59` | `MCPPolicyEngine.tla:InvariantS3` |
| S4 | **Blocked domains override allowed:** first-match blocked domain → Deny | `vellaveto-engine/src/rule_check.rs:124-133` | `MCPPolicyEngine.tla:InvariantS4` |
| S5 | **Allow requires matching Allow policy:** Allow verdict only from Allow policy | `vellaveto-engine/src/lib.rs:545-547` | `MCPPolicyEngine.tla`, `FailClosed.lean/v` |
| S6 | **Missing context → Deny:** context-conditions without context → Deny | `vellaveto-engine/src/lib.rs:519-535` | `MCPPolicyEngine.tla:InvariantS6` |

### ABAC Safety (S7–S10)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S7 | **Forbid dominance:** any matching forbid → Deny (regardless of permits) | `vellaveto-engine/src/abac.rs:226-230` | TLA+, Alloy, Lean, Coq, Kani K6 |
| S8 | **Forbid ignores priority:** low-priority forbid beats high-priority permit | `vellaveto-engine/src/abac.rs` | TLA+, Alloy, Lean, Coq |
| S9 | **Permit requires no forbid:** Allow only when zero forbids match | `vellaveto-engine/src/abac.rs:232-236` | TLA+, Alloy, Lean, Coq |
| S10 | **No match → NoMatch:** nothing matches → NoMatch (caller decides) | `vellaveto-engine/src/abac.rs:239` | TLA+, Alloy, Lean, Coq, Kani K7 |

### Capability Delegation Safety (S11–S16 / D1–D5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S11/D1 | **Monotonic attenuation / depth:** child grants ⊆ parent, depth decreases | `capability_token.rs:470-508` | TLA+ D1, Alloy S11, Lean S11, Coq S11 |
| S12 | **Transitive attenuation:** holds across entire delegation chains | Derived from S11 | Alloy S12, Lean S12, Coq S12 |
| S13/D2 | **Depth budget:** chain length ≤ MAX_DELEGATION_DEPTH | `capability.rs:21` | TLA+ D2, Alloy S13, Lean S13, Coq S13 |
| S14/D3 | **Temporal monotonicity:** child.expiry ≤ parent.expiry | `capability_token.rs:172-176` | TLA+ D3, Alloy S14, Lean S14, Coq S14 |
| S15/D5 | **Terminal cannot delegate:** depth=0 → no children | `capability_token.rs:128-131` | TLA+ D5, Alloy S15, Lean S15, Coq S15 |
| S16/D4 | **Issuer chain integrity:** child.issuer = parent.holder | `capability_token.rs:195` | TLA+ D4, Alloy S16, Lean S16, Coq S16 |

### Task Lifecycle Safety (T1–T5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| T1 | **Terminal absorbing:** completed/failed/cancelled are permanent | `task_state.rs` | TLA+ T1, Coq T1 |
| T2 | **Initial state:** tasks begin in Working or Failed | MCP 2025-11-25 Tasks spec | TLA+ T2, Coq T2 |
| T3 | **Policy evaluated / valid transitions:** every task has verdict, only valid transitions | `task_state.rs` | TLA+ T3, Coq T3 |
| T4 | **Terminal audited:** terminal tasks always have audit events | `events.rs` | TLA+ T4 |
| T5 | **Bounded concurrency:** non-terminal tasks ≤ MaxTasks | `task_state.rs` | TLA+ T5 |

### Cascading Failure Safety (C1–C5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| C1 | **Chain depth bounded:** call chain ≤ MaxChainDepth | `cascading.rs` | TLA+ C1, Coq C1 |
| C2 | **Error threshold:** consecutive errors trigger circuit open | OWASP ASI08 | TLA+ C2, Coq C2 |
| C3 | **Open denies all:** open circuit rejects requests (fail-closed) | `cascading.rs` | TLA+ C3, Coq C3 |
| C4 | **Half-open transient:** half-open is a transient probe state | Circuit breaker pattern | TLA+ C4, Coq C4 |
| C5 | **Probe success closes:** successful probe returns to closed | Circuit breaker pattern | TLA+ C5, Coq C5 |

### Kani Proof Harnesses (K1–K9)

| ID | Property | Source | Harness |
|----|----------|--------|---------|
| K1 | **Fail-closed (implementation):** empty policies → Deny | `vellaveto-engine/src/lib.rs` | `proof_fail_closed_no_match_produces_deny` |
| K2 | **Path idempotence:** `normalize(normalize(x)) == normalize(x)` | `vellaveto-engine/src/path.rs` | `proof_path_normalize_idempotent` |
| K3 | **No traversal:** normalized path has no `..` | `vellaveto-engine/src/path.rs` | `proof_path_normalize_no_traversal` |
| K4 | **Counter monotonicity:** `saturating_add` never decreases | All counter operations | `proof_saturating_counters_never_wrap` |
| K5 | **Error → Deny:** evaluation errors produce Deny | `vellaveto-engine/src/lib.rs` | `proof_verdict_deny_on_error` |
| K6 | **ABAC forbid dominance:** matching forbid → Deny | `vellaveto-engine/src/abac.rs` | `proof_abac_forbid_dominance` |
| K7 | **ABAC no-match → NoMatch:** no matches → NoMatch | `vellaveto-engine/src/abac.rs` | `proof_abac_no_match_produces_nomatch` |
| K8 | **Evaluation determinism:** same input → same output | `vellaveto-engine/src/lib.rs` | `proof_evaluation_deterministic` |
| K9 | **Domain normalization idempotent:** `normalize(normalize(x)) == normalize(x)` | Domain handling | `proof_domain_normalize_idempotent` |

### Liveness (L1–L3, TL1–TL2, CL1–CL2, DL1)

| ID | Property | Spec Location |
|----|----------|---------------|
| L1 | **Eventual verdict:** every pending action eventually receives a verdict | `MCPPolicyEngine.tla` |
| L2 | **No stuck states:** engine never permanently stuck | `MCPPolicyEngine.tla` |
| L3 | **ABAC eventual decision:** every pending ABAC eval eventually gets a decision | `AbacForbidOverrides.tla` |
| TL1 | **Task termination:** every task eventually reaches a terminal state | `MCPTaskLifecycle.tla` |
| TL2 | **Input resolved:** input-required tasks eventually resume or terminate | `MCPTaskLifecycle.tla` |
| CL1 | **Circuit recovery:** open circuits eventually transition to half-open | `CascadingFailure.tla` |
| CL2 | **Half-open resolves:** half-open circuits eventually close or reopen | `CascadingFailure.tla` |
| DL1 | **Delegation terminates:** delegation chains exhaust depth budget | `CapabilityDelegation.tla` |

## Design Decisions

### Abstract Pattern Matching

Pattern matching is reduced to two cases: wildcard (`*`) and exact match.
Full glob/regex correctness is already covered by 24 fuzz targets in the Rust
codebase. The security properties verified here are about evaluation ordering,
fail-closed semantics, and combining algorithms — not pattern compilation.

This abstraction is sound: if a safety property holds with abstract matching
(which is strictly more permissive), it holds with any concrete refinement.

### Small Model Bounds

The TLC configurations use small bounds (3 policies, 2 actions). This is
sufficient because the verified properties are structural:

- **Fail-closed** is independent of the number of policies
- **Priority ordering** is a pairwise relation on adjacent elements
- **Forbid-overrides** is independent of the number of matching policies
- **Monotonic attenuation** is a pairwise relation on parent-child pairs

A counterexample found with 3 policies also applies at 300. Alloy scopes use
7 tokens with MAX_DEPTH=3 to ensure the depth budget assertion (S13) is
non-vacuous (7 > MAX_DEPTH+1 = 4).

### TLC Model Companions (MC_*.tla)

TLC's `.cfg` file parser cannot handle set-of-record literals as CONSTANT
values. Record definitions (PolicySet, ActionSet, etc.) are placed in separate
`MC_*.tla` model companion modules that are loaded by TLC. The `.cfg` files
use `CONSTANT PolicySet <- const_PolicySet` operator overrides to reference them.

### Abstract Time

The Alloy and TLA+ capability delegation models use ordered values instead
of real timestamps. This captures temporal monotonicity (child.expiry ≤
parent.expiry) without requiring date arithmetic or timezone handling.

### Context Conditions as Booleans

Context conditions (time windows, call limits, agent identity, etc.) are
modeled as a single boolean predicate. The specification verifies the
fail-closed property: `requires_context ∧ ¬has_context → Deny`. It does not
model each of the 17 condition types individually — those are tested by the
8,972 Rust unit tests.

### Conditional on_no_match="continue"

The `Conditional` policy type with `on_no_match="continue"` is explicitly
modeled because this is a subtle corner where bypass bugs could hide: if a
conditional policy doesn't fire, evaluation must continue to the next policy
rather than producing a verdict.

### Fact/Assertion Separation (Alloy)

The Alloy models separate structural well-formedness (encoded as facts) from
protocol constraints (also facts) and verified properties (assertions).
This ensures that the key assertions — especially S12 (transitive attenuation)
and S13 (depth budget) — are genuine theorems, not tautological restatements
of axioms.

### Error Modeling (TLA+)

HandleError is modeled as a non-deterministic transition that can occur during
matching or applying, always producing Deny. It is intentionally NOT given weak
fairness — errors are possible but not required. This ensures liveness properties
hold for the normal evaluation path while still allowing error traces.

## Scope and Limitations

These specifications verify **structural security properties** of the policy
evaluation algorithms. They do **not** cover:

- Pattern compilation correctness (covered by 24 fuzz targets)
- Cryptographic correctness of Ed25519 signatures (assumes correct primitives)
- Timing side channels or performance properties
- Concurrency (the engine is synchronous by design)
- Network-level properties (DNS rebinding, IP resolution)
- IP rule evaluation (modeled code paths stop at path/domain rules)
- Full glob/regex semantics (abstracted to wildcard + exact)
- Conditional constraint evaluation internals (modeled as fire/no-fire)
- ABAC entity store / group membership (principal matching is abstracted)
- `max_invocations` grant field (not checked during attenuation in Rust code)
- Token size / grant count bounds (serialization-level constraints)

The model bounds are finite (bounded model checking), not unbounded proofs.
However, the properties are structural and do not depend on the specific
bound values.

### Known Abstraction Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob patterns → Wildcard + Exact | Cannot detect glob-specific matching bugs | 24 fuzz targets cover pattern compilation |
| Path/domain subset uses set identity, not glob matching | Alloy model is more restrictive than Rust | Sound over-approximation for security |
| ABAC CHOOSE vs priority-ordered selection | Reported policy_id may differ | Does not affect Deny/Allow decision |
| Conditional policies simplified to fire/no-fire | Constraint-level deny paths not modeled | Covered by 8,972 Rust unit tests |
| Grant subset axiomatized in Lean/Coq | Cannot verify concrete grant coverage | Verified by Alloy bounded model checking |

## Relation to Existing Test Suite

| Verification Layer | Method | Count |
|--------------------|--------|-------|
| Unit tests | Rust `#[test]` | 8,972 |
| Fuzz targets | `cargo fuzz` | 24 |
| Property-based tests | `proptest` | ~50 |
| **Formal specs (TLA+)** | **Model checking** | **6 specs, 32 safety + 8 liveness** |
| **Formal specs (Alloy)** | **Bounded model checking** | **2 models, 10 assertions** |
| **Formal specs (Lean 4)** | **Proof assistant** | **5 files, 30 theorems** |
| **Formal specs (Coq)** | **Proof assistant** | **8 files, 43 theorems** |
| **Formal specs (Kani)** | **CBMC on Rust code** | **9 proof harnesses** |

The formal specs complement (not replace) the test suite:
- Tests verify concrete executions against expected outputs
- Formal specs verify that **no possible execution** violates the invariants
- Together they provide defense in depth for security-critical properties
