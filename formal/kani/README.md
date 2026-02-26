# Kani Proof Harnesses — Vellaveto

Bounded model checking proofs using [Kani](https://github.com/model-checking/kani)
for critical security invariants.

## What's Verified

| Harness | Property | Source |
|---------|----------|--------|
| `proof_fail_closed_no_match_produces_deny` | Fail-closed: no matching policy → Deny | `vellaveto-engine/src/lib.rs` |
| `proof_saturating_counters_never_wrap` | Saturating arithmetic: counters never overflow to zero | All counter operations |
| `proof_path_normalize_idempotent` | Path normalization: `normalize(normalize(x)) == normalize(x)` | `vellaveto-engine/src/normalize.rs` |
| `proof_path_normalize_no_traversal` | No `..` in normalized output | `vellaveto-engine/src/normalize.rs` |
| `proof_verdict_deny_on_error` | Errors in evaluation always produce Deny | `vellaveto-engine/src/lib.rs` |

## Running

```bash
# Install Kani (requires Rust nightly)
cargo install --locked kani-verifier
kani setup

# Run all proofs
cd vellaveto-engine
cargo kani --harness proof_fail_closed

# Run specific harness
cargo kani --harness proof_saturating_counters_never_wrap
```

## Design Decisions

- Harnesses use `kani::any()` to generate arbitrary inputs
- `kani::assume()` constrains inputs to valid ranges
- Properties verified via `kani::assert()` and `assert!()` macros
- Focus on security-critical invariants that are structural (not implementation-specific)
- Bounded verification: Kani unrolls loops up to a configured depth

## Relation to TLA+ and Lean Proofs

| Layer | Tool | What It Proves |
|-------|------|----------------|
| Algorithm correctness | TLA+ | State machine properties (ordering, fail-closed, liveness) |
| Mathematical properties | Lean 4 | Determinism, idempotence, fail-closed (pure logic) |
| **Implementation correctness** | **Kani** | **Actual Rust code satisfies invariants** |

Kani proofs are the strongest: they verify the actual compiled code,
not a model of it. However, they are bounded (finite loop unrolling)
and cannot verify liveness properties.
