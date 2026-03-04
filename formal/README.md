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
| `verus/verified_core.rs` | Verus | V1–V8 | Core verdict computation (ALL inputs, actual Rust) |
| `verus/verified_dlp_core.rs` | Verus | D1–D6 | Cross-call DLP buffer arithmetic (ALL inputs, actual Rust) |
| `kani/src/proofs.rs` | Kani | K1–K25 | Bounded model checking of actual Rust (Verus bridge) |
| `FailClosed.v` | Coq | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `Determinism.v` | Coq | — | Policy evaluation determinism (same input → same verdict) |
| `PathNormalization.v` | Coq | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.v` | Coq | S7–S10 | ABAC forbid-overrides combining algorithm (first forbid wins) |
| `CapabilityDelegation.v` | Coq | S11–S16 | Capability token delegation with monotonic attenuation |
| `CircuitBreaker.v` | Coq | C1–C5 | Circuit breaker state machine properties |
| `TaskLifecycle.v` | Coq | T1–T3 | MCP Task lifecycle terminal absorbing, valid transitions |

**173 verification instances** across 7 tools:
- **Verus:** 23 proofs on actual Rust code (ALL inputs, deductive)
- **TLA+:** 34 safety invariants + 8 liveness properties (6 specs)
- **Alloy:** 10 assertions (2 models)
- **Lean 4:** 30 theorems (5 files, no `sorry`)
- **Coq:** 43 theorems (8 files, no `Admitted`)
- **Kani:** 25 proof harnesses on actual Rust code (bounded)

## Coverage Matrix

| Property | TLA+ | Alloy | Lean 4 | Coq | Verus | Kani |
|----------|------|-------|--------|-----|-------|------|
| **S1: Fail-closed** | S1 | — | S1 | S1 | V1, V2 | K1, K5, K14 |
| **S2: Priority ordering** | S2 | — | — | — | V6 | K18 |
| **S3: Blocked paths override** | S3 | — | — | — | V4 | K16 |
| **S4: Blocked domains override** | S4 | — | — | — | V4 | K16 |
| **S5: Allow requires match** | S5 | — | S5 | S5 | V3 | K15 |
| **S6: Missing context → Deny** | S6 | — | — | — | — | K24 |
| **S7: Forbid dominance** | S7 | S7 | S7 | S7 | — | K6 |
| **S8: Forbid ignores priority** | S8 | S8 | S8 | S8 | — | K19 |
| **S9: Permit requires no forbid** | S9 | S9 | S9 | S9 | — | K20 |
| **S10: No match → NoMatch** | S10 | S10 | S10 | S10 | — | K7 |
| **S11: Monotonic attenuation** | D1 | S11 | S11 | S11 | — | — |
| **S12: Transitive attenuation** | — | S12 | S12 | S12 | — | — |
| **S13: Depth bounded** | D2 | S13 | S13 | S13 | — | — |
| **S14: Temporal monotonicity** | D3 | S14 | S14 | S14 | — | — |
| **S15: Terminal no delegate** | D5 | S15 | S15 | S15 | — | — |
| **S16: Issuer chain integrity** | D4 | S16 | S16 | S16 | — | — |
| **C1: Chain depth bounded** | C1 | — | — | C1 | — | — |
| **C2: Error threshold → open** | C2 | — | — | C2 | — | — |
| **C3: Open denies all** | C3 | — | — | C3 | — | — |
| **C4: Half-open resolves** | C4 | — | — | C4 | — | — |
| **C5: Probe success closes** | C5 | — | — | C5 | — | — |
| **T1: Terminal absorbing** | T1 | — | — | T1 | — | — |
| **T2: Initial state** | T2 | — | — | T2 | — | — |
| **T3: Valid transitions** | T3 | — | — | T3 | — | — |
| **V8: Conditional pass-through** | — | — | — | — | V8 | K17, K25 |
| **D1: UTF-8 boundary safety** | — | — | — | — | D1 | K10, K11, K23 |
| **D2: Buffer size bounded** | — | — | — | — | D2 | K10 |
| **D3: Byte accounting correct** | — | — | — | — | D3 | K13 |
| **D4: Capacity fail-closed** | — | — | — | — | D4 | K12 |
| **D5: No arithmetic underflow** | — | — | — | — | D5 | K13 |
| **D6: Overlap completeness** | — | — | — | — | D6 | K21, K22 |
| **Path idempotence** | — | — | idem | idem | — | K2 |
| **No traversal** | — | — | no_dot | no_dot | — | K3 |
| **Determinism** | — | — | det | det | — | K8 |
| **Counter monotonicity** | — | — | — | — | — | K4 |
| **Domain norm idempotent** | — | — | — | — | — | K9 |

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
      PathNormalization.v            ← Path normalization idempotence (6 theorems)
      AbacForbidOverride.v           ← ABAC forbid-override S7-S10 (5 theorems)
      CapabilityDelegation.v         ← Capability delegation S11-S16 (8 theorems)
      CircuitBreaker.v               ← Circuit breaker C1-C5 (6 theorems)
      TaskLifecycle.v                ← Task lifecycle T1-T3 (10 theorems)
  verus/
    README.md                        ← Verus setup and verification guide
    verified_core.rs                 ← Core verdict logic (V1-V8, 9 verified)
    verified_dlp_core.rs             ← DLP buffer arithmetic (D1-D6, 14 verified)
  kani/
    Cargo.toml                       ← Standalone crate (excluded from workspace)
    README.md                        ← Kani setup and usage guide
    src/
      lib.rs                         ← Crate root (K1-K25 property catalog)
      proofs.rs                      ← Proof harnesses (25 properties)
      path.rs                        ← Path normalization (from vellaveto-engine)
      verified_core.rs               ← Verdict computation (Verus bridge)
      dlp_core.rs                    ← DLP buffer arithmetic (Verus bridge)
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

### Verus Proofs (V1–V8, D1–D6)

```bash
# Option 1: Binary release (recommended)
VERUS_VERSION="0.2026.03.01.25809cb"
curl -sSL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip"
unzip verus.zip -d verus-bin
rustup install 1.93.1-x86_64-unknown-linux-gnu

# Core verdict (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# DLP buffer arithmetic (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs
```

Expected output:
- `verified_core.rs`: `verification results:: 9 verified, 0 errors`
- `verified_dlp_core.rs`: `verification results:: 14 verified, 0 errors`

### Kani Proof Harnesses (K1–K25)

```bash
cd formal/kani
# Install Kani: cargo install --locked kani-verifier && cargo kani setup

# Run all 25 harnesses (examples — see README.md for full list)
cargo kani --harness proof_fail_closed_no_match_produces_deny
cargo kani --harness proof_path_normalize_idempotent
cargo kani --harness proof_compute_verdict_fail_closed_empty
cargo kani --harness proof_extract_tail_no_panic
cargo kani --harness proof_sort_produces_sorted_output
# ... (25 total)
```

Expected output: all 25 harnesses report VERIFICATION:- SUCCESSFUL.

## Property Catalog

### Policy Engine Safety (S1–S6)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S1 | **Fail-closed:** no matching policy → Deny, never Allow | `vellaveto-engine/src/lib.rs:417-419` | TLA+, Lean, Coq, **Verus V1/V2**, Kani K1/K5/K14 |
| S2 | **Priority ordering:** policies evaluated in priority-descending order | `vellaveto-engine/src/lib.rs:209-224` | TLA+, **Verus V6**, Kani K18 |
| S3 | **Blocked paths override allowed:** first-match blocked path → Deny | `vellaveto-engine/src/rule_check.rs:50-59` | TLA+, **Verus V4**, Kani K16 |
| S4 | **Blocked domains override allowed:** first-match blocked domain → Deny | `vellaveto-engine/src/rule_check.rs:124-133` | TLA+, **Verus V4**, Kani K16 |
| S5 | **Allow requires matching Allow policy:** Allow verdict only from Allow policy | `vellaveto-engine/src/lib.rs:545-547` | TLA+, Lean, Coq, **Verus V3**, Kani K15 |
| S6 | **Missing context → Deny:** context-conditions without context → Deny | `vellaveto-engine/src/lib.rs:519-535` | TLA+, Kani K24 |

### ABAC Safety (S7–S10)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S7 | **Forbid dominance:** any matching forbid → Deny (regardless of permits) | `vellaveto-engine/src/abac.rs:226-230` | TLA+, Alloy, Lean, Coq, Kani K6 |
| S8 | **Forbid ignores priority:** low-priority forbid beats high-priority permit | `vellaveto-engine/src/abac.rs` | TLA+, Alloy, Lean, Coq, Kani K19 |
| S9 | **Permit requires no forbid:** Allow only when zero forbids match | `vellaveto-engine/src/abac.rs:232-236` | TLA+, Alloy, Lean, Coq, Kani K20 |
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

### Verus Core Verdict (V1–V8, proven for ALL inputs on actual Rust)

| ID | Property | Postcondition |
|----|----------|--------------|
| V1 | **Fail-closed empty** | `len() == 0 ==> Deny` |
| V2 | **Fail-closed no match** | All `!matched` → Deny |
| V3 | **Allow requires match** | `Allow` → ∃ matching Allow with no override |
| V4 | **Rule override forces Deny** | Path/network/IP override → Deny |
| V5 | **Totality** | Function always terminates |
| V6 | **Priority ordering** | Higher-priority wins (requires `is_sorted`) |
| V7 | **Deny-dominance at equal priority** | Deny beats Allow (requires `is_sorted`) |
| V8 | **Conditional pass-through** | Unfired condition → evaluation continues |

Source: `formal/verus/verified_core.rs` (9 verified, 0 errors)

### Verus Cross-Call DLP (D1–D6, proven for ALL inputs on actual Rust)

| ID | Property | Meaning |
|----|----------|---------|
| D1 | **UTF-8 boundary safety** | `extract_tail` never returns start in mid-character |
| D2 | **Buffer size bounded** | Extracted tail ≤ `max_size` bytes |
| D3 | **Byte accounting correct** | `update_total_bytes` maintains consistency |
| D4 | **Capacity fail-closed** | At `max_fields`, `can_track_field` returns false |
| D5 | **No arithmetic underflow** | Saturating subtraction prevents wrapping |
| D6 | **Overlap completeness** | Secret ≤ 2 × overlap split at any byte fully covered |

Source: `formal/verus/verified_dlp_core.rs` (14 verified, 0 errors)

### Kani Proof Harnesses (K1–K25, bounded model checking on actual Rust)

| ID | Property | Verus Bridge |
|----|----------|-------------|
| K1 | **Fail-closed:** empty policies → Deny | — |
| K2 | **Path idempotence:** `normalize(normalize(x)) == normalize(x)` | — |
| K3 | **No traversal:** normalized path has no `..` | — |
| K4 | **Counter monotonicity:** `saturating_add` never decreases | — |
| K5 | **Error → Deny:** evaluation errors produce Deny | — |
| K6 | **ABAC forbid dominance:** matching forbid → Deny | — |
| K7 | **ABAC no-match → NoMatch:** no matches → NoMatch | — |
| K8 | **Evaluation determinism:** same input → same output | — |
| K9 | **Domain normalization idempotent** | — |
| K10 | **extract_tail no panic** for arbitrary bytes | D1, D2 |
| K11 | **UTF-8 boundary exhaustive** (all 256 bytes) | D1 |
| K12 | **can_track_field fail-closed** at capacity | D4 |
| K13 | **update_total_bytes saturating** correctness | D3, D5 |
| K14 | **compute_verdict fail-closed** empty | V1 |
| K15 | **compute_verdict allow requires match** | V3 |
| K16 | **compute_verdict rule_override forces deny** | V4 |
| K17 | **compute_verdict conditional pass-through** | V8 |
| K18 | **Sort produces sorted output** (Verus precondition) | V6, V7 |
| K19 | **ABAC forbid ignores priority order** | S8 |
| K20 | **ABAC permit requires no forbid** | S9 |
| K21 | **Overlap covers small secrets** | D6 |
| K22 | **Overlap region size saturating** | D6 |
| K23 | **extract_tail multibyte boundary** (4-byte emoji) | D1 |
| K24 | **context_deny overrides allow** | V3 |
| K25 | **all_constraints_skipped fail-closed** | V8 |

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

For TLA+, Lean, Coq, Alloy, and Kani: the model bounds are finite (bounded
model checking), not unbounded proofs. However, the properties are structural
and do not depend on the specific bound values.

For Verus: properties V1-V8 and D1-D6 are proven for ALL possible inputs on
the actual Rust code. No bounds, no sampling. The Verus core is the strongest
verification layer.

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
| Unit tests | Rust `#[test]` | 9,018+ |
| Fuzz targets | `cargo fuzz` | 24 |
| Property-based tests | `proptest` | ~50 |
| **Verus (deductive)** | **SMT proof on actual Rust (ALL inputs)** | **23 proofs (V1-V8, D1-D6)** |
| **Kani (bounded)** | **CBMC on actual Rust** | **25 proof harnesses (K1-K25)** |
| **TLA+ (model checking)** | **Exhaustive state exploration** | **6 specs, 34 safety + 8 liveness** |
| **Alloy (bounded)** | **Bounded relational checking** | **2 models, 10 assertions** |
| **Lean 4 (deductive)** | **Proof assistant** | **5 files, 30 theorems** |
| **Coq (deductive)** | **Proof assistant** | **8 files, 43 theorems** |

The three-layer verification architecture:
- **Layer 3 (TLA+):** Proves protocol design is correct (no deadlocks, no safety violations)
- **Layer 2 (Verus):** Proves core Rust code correct for ALL inputs (zero refinement gap)
- **Layer 1 (Kani):** Proves wrapper Rust code correct within bounds (bridges Verus trust boundary)
- **Lean/Coq/Alloy:** Defense-in-depth mathematical proofs on abstract models
- **Tests:** Concrete execution verification (9,018+ tests + 24 fuzz targets)
