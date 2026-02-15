# Formal Verification — Vellaveto MCP Policy Engine

Formal specifications of Vellaveto's core security properties using TLA+ and Alloy.

This is the first formal model of MCP policy enforcement in any framework,
addressing Gap #1 (severity: Critical) from `docs/MCP_SECURITY_GAPS.md`.

## What's Verified

| Model | Framework | Properties | What It Covers |
|-------|-----------|------------|----------------|
| `MCPPolicyEngine.tla` | TLA+ | S1–S6, L1–L2 | First-match-wins policy evaluation, fail-closed defaults |
| `AbacForbidOverrides.tla` | TLA+ | S7–S10, L3 | ABAC forbid-overrides combining algorithm |
| `CapabilityDelegation.als` | Alloy | S11–S16 | Capability token delegation with monotonic attenuation |
| `Determinism.lean` | Lean 4 | — | Policy evaluation determinism (same input → same verdict) |
| `FailClosed.lean` | Lean 4 | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `PathNormalization.lean` | Lean 4 | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |

**19 verified properties total** (16 safety + 3 liveness) + **3 Lean 4 lemmas**.

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
  alloy/
    CapabilityDelegation.als         ← Capability token delegation model
  lean/
    lakefile.lean                    ← Lake build configuration
    lean-toolchain                   ← Lean 4 version pin
    Vellaveto/
      Determinism.lean              ← Evaluation determinism proof
      FailClosed.lean               ← Fail-closed and S1/S5 proofs
      PathNormalization.lean        ← Path normalization idempotence
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

### Lean 4 Lemmas (Determinism, Fail-Closed, Idempotence)

```bash
cd formal/lean
# Install Lean 4 if not already present:
#   curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
lake build
```

Expected output: all three files type-check with no `sorry` markers
and no warnings.

## Property Catalog

### Policy Engine Safety (S1–S6)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S1 | **Fail-closed:** no matching policy → Deny, never Allow | `vellaveto-engine/src/lib.rs:417-419` | `MCPPolicyEngine.tla:InvariantS1_FailClosed` |
| S2 | **Priority ordering:** policies evaluated in priority-descending order | `vellaveto-engine/src/lib.rs:209-224` | `MCPCommon.tla:SortedByPriority` |
| S3 | **Blocked paths override allowed:** first-match blocked path → Deny | `vellaveto-engine/src/rule_check.rs:50-59` | `MCPPolicyEngine.tla:InvariantS3_BlockedPathsOverride` |
| S4 | **Blocked domains override allowed:** first-match blocked domain → Deny | `vellaveto-engine/src/rule_check.rs:124-133` | `MCPPolicyEngine.tla:InvariantS4_BlockedDomainsOverride` |
| S5 | **Allow requires matching Allow policy:** Allow verdict only from Allow policy | `vellaveto-engine/src/lib.rs:545-547` | `MCPPolicyEngine.tla:InvariantS5_ErrorsDeny` |
| S6 | **Missing context → Deny:** context-conditions without context → Deny | `vellaveto-engine/src/lib.rs:519-535` | `MCPPolicyEngine.tla:InvariantS6_MissingContextDeny` |

### ABAC Safety (S7–S10)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S7 | **Forbid dominance:** any matching forbid → Deny (regardless of permits) | `vellaveto-engine/src/abac.rs:226-230` | `AbacForbidOverrides.tla:InvariantS7` |
| S8 | **Forbid ignores priority:** low-priority forbid beats high-priority permit | `vellaveto-engine/src/abac.rs` (test line 1212) | `AbacForbidOverrides.tla:InvariantS8` |
| S9 | **Permit requires no forbid:** Allow only when zero forbids match | `vellaveto-engine/src/abac.rs:232-236` | `AbacForbidOverrides.tla:InvariantS9` |
| S10 | **No match → NoMatch:** nothing matches → NoMatch (caller decides) | `vellaveto-engine/src/abac.rs:239` | `AbacForbidOverrides.tla:InvariantS10` |

### Capability Delegation Safety (S11–S16)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S11 | **Monotonic attenuation:** child grants ⊆ parent grants | `vellaveto-mcp/src/capability_token.rs:470-508` | `CapabilityDelegation.als:S11` |
| S12 | **Transitive attenuation:** attenuation holds across entire delegation chains | Derived from S11 (non-trivial: verifies transitivity of composed relation) | `CapabilityDelegation.als:S12` |
| S13 | **Depth budget:** chain length ≤ MAX_DELEGATION_DEPTH | `vellaveto-types/src/capability.rs:21` | `CapabilityDelegation.als:S13` |
| S14 | **Temporal monotonicity:** child.expiry ≤ parent.expiry | `vellaveto-mcp/src/capability_token.rs:172-176` | `CapabilityDelegation.als:S14` |
| S15 | **Terminal cannot delegate:** depth=0 → no children | `vellaveto-mcp/src/capability_token.rs:128-131` | `CapabilityDelegation.als:S15` |
| S16 | **Issuer chain integrity:** child.issuer = parent.holder | `vellaveto-mcp/src/capability_token.rs:195` | `CapabilityDelegation.als:S16` |

### Liveness (L1–L3)

| ID | Property | Spec Location |
|----|----------|---------------|
| L1 | **Eventual verdict:** every pending action eventually receives a verdict | `MCPPolicyEngine.tla:LivenessL1` |
| L2 | **No stuck states:** engine never permanently stuck in matching/applying | `MCPPolicyEngine.tla:LivenessL2` |
| L3 | **ABAC eventual decision:** every pending ABAC eval eventually gets a decision | `AbacForbidOverrides.tla:LivenessAbacEventualDecision` |

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
| Unit tests | Rust `#[test]` | 4,857 |
| Fuzz targets | `cargo fuzz` | 22 |
| Property-based tests | `proptest` | ~50 |
| **Formal specs** | **TLA+ / Alloy** | **19 properties** |

The formal specs complement (not replace) the test suite:
- Tests verify concrete executions against expected outputs
- Formal specs verify that **no possible execution** violates the invariants
- Together they provide defense in depth for security-critical properties
