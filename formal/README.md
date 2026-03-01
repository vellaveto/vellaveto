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
| `CapabilityDelegation.als` | Alloy | S11–S16 | Capability token delegation with monotonic attenuation |
| `Determinism.lean` | Lean 4 | — | Policy evaluation determinism (same input → same verdict) |
| `FailClosed.lean` | Lean 4 | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `PathNormalization.lean` | Lean 4 | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `kani/proofs.rs` | Kani | K1–K5 | Bounded model checking of actual Rust implementation |
| `FailClosed.v` | Coq | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `Determinism.v` | Coq | — | Policy evaluation determinism (same input → same verdict) |
| `PathNormalization.v` | Coq | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.v` | Coq | S7–S10 | ABAC forbid-overrides combining algorithm (first forbid wins) |
| `CapabilityDelegation.v` | Coq | S11–S16 | Capability token delegation with monotonic attenuation |

**33 verified properties total** (26 safety + 7 liveness) + **3 Lean 4 lemmas** + **15 Coq theorems** + **5 Kani proof harnesses**.

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
  alloy/
    CapabilityDelegation.als         ← Capability token delegation model
  lean/
    lakefile.lean                    ← Lake build configuration
    lean-toolchain                   ← Lean 4 version pin
    Vellaveto/
      Determinism.lean              ← Evaluation determinism proof
      FailClosed.lean               ← Fail-closed and S1/S5 proofs
      PathNormalization.lean        ← Path normalization idempotence
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
  kani/
    README.md                        ← Kani setup and usage guide
    proofs.rs                        ← Proof harnesses (5 properties)
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

### Alloy Capability Delegation (S11–S16)

```bash
cd formal/alloy
# GUI mode (recommended for first run — shows counterexample visualizations):
java -jar org.alloytools.alloy.dist.jar

# Open CapabilityDelegation.als in the Alloy Analyzer and execute all check commands.
```

Expected output: all 6 assertions pass with 0 counterexamples found.

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

### Lean 4 Lemmas (Determinism, Fail-Closed, Idempotence)

```bash
cd formal/lean
# Install Lean 4 if not already present:
#   curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
lake build
```

Expected output: all three files type-check with no `sorry` markers
and no warnings.

### Coq Proofs (S1, S5, S7–S16, Determinism, Idempotence)

```bash
cd formal/coq
make
```

Expected output: all 6 `.v` files compile cleanly with no `Admitted` markers.
Verify: `grep -r "Admitted\|admit" Vellaveto/*.v` returns no matches.

## Property Catalog

### Policy Engine Safety (S1–S6)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S1 | **Fail-closed:** no matching policy → Deny, never Allow | `vellaveto-engine/src/lib.rs:417-419` | `MCPPolicyEngine.tla:InvariantS1_FailClosed`, `FailClosed.v:s1_*` |
| S2 | **Priority ordering:** policies evaluated in priority-descending order | `vellaveto-engine/src/lib.rs:209-224` | `MCPCommon.tla:SortedByPriority` |
| S3 | **Blocked paths override allowed:** first-match blocked path → Deny | `vellaveto-engine/src/rule_check.rs:50-59` | `MCPPolicyEngine.tla:InvariantS3_BlockedPathsOverride` |
| S4 | **Blocked domains override allowed:** first-match blocked domain → Deny | `vellaveto-engine/src/rule_check.rs:124-133` | `MCPPolicyEngine.tla:InvariantS4_BlockedDomainsOverride` |
| S5 | **Allow requires matching Allow policy:** Allow verdict only from Allow policy | `vellaveto-engine/src/lib.rs:545-547` | `MCPPolicyEngine.tla:InvariantS5_ErrorsDeny`, `FailClosed.v:s5_allow_requires_match` |
| S6 | **Missing context → Deny:** context-conditions without context → Deny | `vellaveto-engine/src/lib.rs:519-535` | `MCPPolicyEngine.tla:InvariantS6_MissingContextDeny` |

### ABAC Safety (S7–S10)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S7 | **Forbid dominance:** any matching forbid → Deny (regardless of permits) | `vellaveto-engine/src/abac.rs:226-230` | `AbacForbidOverrides.tla:InvariantS7`, `AbacForbidOverride.v:s7_forbid_dominance` |
| S8 | **Forbid ignores priority:** low-priority forbid beats high-priority permit | `vellaveto-engine/src/abac.rs` (test line 1212) | `AbacForbidOverrides.tla:InvariantS8`, `AbacForbidOverride.v:s8_forbid_ignores_priority` |
| S9 | **Permit requires no forbid:** Allow only when zero forbids match | `vellaveto-engine/src/abac.rs:232-236` | `AbacForbidOverrides.tla:InvariantS9`, `AbacForbidOverride.v:s9_permit_requires_no_forbid` |
| S10 | **No match → NoMatch:** nothing matches → NoMatch (caller decides) | `vellaveto-engine/src/abac.rs:239` | `AbacForbidOverrides.tla:InvariantS10`, `AbacForbidOverride.v:s10_no_match_nomatch` |

### Capability Delegation Safety (S11–S16)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S11 | **Monotonic attenuation:** child grants ⊆ parent grants | `vellaveto-mcp/src/capability_token.rs:470-508` | `CapabilityDelegation.als:S11`, `CapabilityDelegation.v:s11_monotonic_attenuation` |
| S12 | **Transitive attenuation:** attenuation holds across entire delegation chains | Derived from S11 (non-trivial: verifies transitivity of composed relation) | `CapabilityDelegation.als:S12`, `CapabilityDelegation.v:s12_transitive_attenuation` |
| S13 | **Depth budget:** chain length ≤ MAX_DELEGATION_DEPTH | `vellaveto-types/src/capability.rs:21` | `CapabilityDelegation.als:S13`, `CapabilityDelegation.v:s13_depth_bounded` |
| S14 | **Temporal monotonicity:** child.expiry ≤ parent.expiry | `vellaveto-mcp/src/capability_token.rs:172-176` | `CapabilityDelegation.als:S14`, `CapabilityDelegation.v:s14_temporal_monotonicity` |
| S15 | **Terminal cannot delegate:** depth=0 → no children | `vellaveto-mcp/src/capability_token.rs:128-131` | `CapabilityDelegation.als:S15`, `CapabilityDelegation.v:s15_terminal_no_children` |
| S16 | **Issuer chain integrity:** child.issuer = parent.holder | `vellaveto-mcp/src/capability_token.rs:195` | `CapabilityDelegation.als:S16`, `CapabilityDelegation.v:s16_issuer_chain_integrity` |

### Task Lifecycle Safety (T1–T5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| T1 | **Terminal absorbing:** completed/failed/cancelled are permanent | `vellaveto-mcp/src/task_state.rs` | `MCPTaskLifecycle.tla:InvariantT1_TerminalAbsorbing` |
| T2 | **Initial state:** tasks begin in Working or Failed | MCP 2025-11-25 Tasks spec | `MCPTaskLifecycle.tla:InvariantT2_InitialState` |
| T3 | **Policy evaluated:** every task has a policy verdict | `vellaveto-mcp/src/task_state.rs:register_task_from_create` | `MCPTaskLifecycle.tla:InvariantT3_PolicyEvaluated` |
| T4 | **Terminal audited:** terminal tasks always have audit events | `vellaveto-audit/src/events.rs:log_task_lifecycle_event` | `MCPTaskLifecycle.tla:InvariantT4_TerminalAudited` |
| T5 | **Bounded concurrency:** non-terminal tasks ≤ MaxTasks | `vellaveto-mcp/src/task_state.rs:MAX_CONCURRENT_TASKS` | `MCPTaskLifecycle.tla:InvariantT5_BoundedConcurrency` |

### Cascading Failure Safety (C1–C5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| C1 | **Chain depth bounded:** call chain ≤ MaxChainDepth | `vellaveto-engine/src/circuit_breaker.rs` | `CascadingFailure.tla:InvariantC1_ChainDepthBounded` |
| C2 | **Error threshold:** consecutive errors trigger circuit open | OWASP ASI08 | `CascadingFailure.tla:InvariantC2_ErrorThresholdTriggersOpen` |
| C3 | **Open denies all:** open circuit rejects requests (fail-closed) | `vellaveto-engine/src/circuit_breaker.rs` | `CascadingFailure.tla:InvariantC3_OpenCircuitDenies` |
| C4 | **Half-open transient:** half-open is a transient probe state | Circuit breaker pattern | `CascadingFailure.tla:InvariantC4_HalfOpenTransient` |
| C5 | **Probe success closes:** successful probe returns to closed | Circuit breaker pattern | `CascadingFailure.tla:InvariantC5_ProbeSuccessCloses` |

### Kani Proof Harnesses (K1–K5)

| ID | Property | Source | Harness |
|----|----------|--------|---------|
| K1 | **Fail-closed (implementation):** empty policies → Deny | `vellaveto-engine/src/lib.rs` | `proof_fail_closed_no_match_produces_deny` |
| K2 | **Path idempotence (implementation):** `normalize(normalize(x)) == normalize(x)` | `vellaveto-engine/src/path.rs` | `proof_path_normalize_idempotent` |
| K3 | **No traversal (implementation):** normalized path has no `..` | `vellaveto-engine/src/path.rs` | `proof_path_normalize_no_traversal` |
| K4 | **Counter monotonicity:** `saturating_add` never decreases | All counter operations | `proof_saturating_counters_never_wrap` |
| K5 | **Error → Deny (implementation):** evaluation errors produce Deny | `vellaveto-engine/src/lib.rs` | `proof_verdict_deny_on_error` |

### Liveness (L1–L3, TL1–TL2, CL1–CL2)

| ID | Property | Spec Location |
|----|----------|---------------|
| L1 | **Eventual verdict:** every pending action eventually receives a verdict | `MCPPolicyEngine.tla:LivenessL1` |
| L2 | **No stuck states:** engine never permanently stuck in matching/applying | `MCPPolicyEngine.tla:LivenessL2` |
| L3 | **ABAC eventual decision:** every pending ABAC eval eventually gets a decision | `AbacForbidOverrides.tla:LivenessAbacEventualDecision` |
| TL1 | **Task termination:** every task eventually reaches a terminal state | `MCPTaskLifecycle.tla:LivenessTL1_EventualTermination` |
| TL2 | **Input resolved:** input-required tasks eventually resume or terminate | `MCPTaskLifecycle.tla:LivenessTL2_InputResolved` |
| CL1 | **Circuit recovery:** open circuits eventually transition to half-open | `CascadingFailure.tla:LivenessCL1_OpenEventuallyHalfOpen` |
| CL2 | **Half-open resolves:** half-open circuits eventually close or reopen | `CascadingFailure.tla:LivenessCL2_HalfOpenResolves` |

## Design Decisions

### Abstract Pattern Matching

Pattern matching is reduced to two cases: wildcard (`*`) and exact match.
Full glob/regex correctness is already covered by 22 fuzz targets in the Rust
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

The Alloy model uses a total order relation on abstract `Time` atoms instead
of real timestamps. This captures temporal monotonicity (child.expiry ≤
parent.expiry) without requiring date arithmetic or timezone handling.

### Context Conditions as Booleans

Context conditions (time windows, call limits, agent identity, etc.) are
modeled as a single boolean predicate. The specification verifies the
fail-closed property: `requires_context ∧ ¬has_context → Deny`. It does not
model each of the 17 condition types individually — those are tested by the
4,857 Rust unit tests.

### Conditional on_no_match="continue"

The `Conditional` policy type with `on_no_match="continue"` is explicitly
modeled because this is a subtle corner where bypass bugs could hide: if a
conditional policy doesn't fire, evaluation must continue to the next policy
rather than producing a verdict.

### Fact/Assertion Separation (Alloy)

The Alloy model separates structural well-formedness (encoded as facts) from
delegation protocol constraints (also facts) and verified properties (assertions).
This ensures that the key assertions — especially S12 (transitive attenuation)
and S13 (depth budget) — are genuine theorems, not tautological restatements
of axioms. S15 and S16 follow structurally from DelegationStructure but are
verified independently for completeness.

### Error Modeling (TLA+)

HandleError is modeled as a non-deterministic transition that can occur during
matching or applying, always producing Deny. It is intentionally NOT given weak
fairness — errors are possible but not required. This ensures liveness properties
hold for the normal evaluation path while still allowing error traces.

## Scope and Limitations

These specifications verify **structural security properties** of the policy
evaluation algorithms. They do **not** cover:

- Pattern compilation correctness (covered by 22 fuzz targets)
- Cryptographic correctness of Ed25519 signatures (assumes correct primitives)
- Timing side channels or performance properties
- Concurrency (the engine is synchronous by design)
- Network-level properties (DNS rebinding, IP resolution)
- IP rule evaluation (modeled code paths stop at path/domain rules)
- Full glob/regex semantics (abstracted to wildcard + exact)
- Conditional constraint evaluation internals (modeled as fire/no-fire)
- `RequireApproval` verdict type (not yet modeled in TLA+ spec)
- ABAC entity store / group membership (principal matching is abstracted)
- `max_invocations` grant field (not checked during attenuation in Rust code)
- Token size / grant count bounds (serialization-level constraints)
- Path normalization / traversal protection (tested by Rust unit tests)
- Determinism (same input → same output; would need separate model)

The model bounds are finite (bounded model checking), not unbounded proofs.
However, the properties are structural and do not depend on the specific
bound values.

### Known Abstraction Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob patterns → Wildcard + Exact | Cannot detect glob-specific matching bugs | 22 fuzz targets cover pattern compilation |
| Path/domain subset uses set identity, not glob matching | Alloy model is more restrictive than Rust | Sound over-approximation for security |
| ABAC CHOOSE vs priority-ordered selection | Reported policy_id may differ | Does not affect Deny/Allow decision |
| Conditional policies simplified to fire/no-fire | Constraint-level deny paths not modeled | Covered by 4,857 Rust unit tests |

## Relation to Existing Test Suite

| Verification Layer | Method | Count |
|--------------------|--------|-------|
| Unit tests | Rust `#[test]` | 8,044 |
| Fuzz targets | `cargo fuzz` | 22 |
| Property-based tests | `proptest` | ~50 |
| **Formal specs (models)** | **TLA+ / Alloy / Lean** | **33 properties + 3 lemmas** |
| **Formal specs (proofs)** | **Coq** | **15 theorems** |
| **Formal specs (code)** | **Kani** | **5 proof harnesses** |

The formal specs complement (not replace) the test suite:
- Tests verify concrete executions against expected outputs
- Formal specs verify that **no possible execution** violates the invariants
- Together they provide defense in depth for security-critical properties
