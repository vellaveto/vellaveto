# Verus Formal Verification

Deductive verification of Vellaveto's core verdict computation, constraint
evaluation fail-closed control flow, DLP buffer arithmetic, and path
normalization using [Verus](https://github.com/verus-lang/verus).

## What Is Verified

### Core Verdict Logic (`verified_core.rs`) — 12 proofs, V1-V8, V11-V12

Properties proven for ALL possible inputs (not bounded):

| ID | Property | Meaning |
|----|----------|---------|
| V1 | Fail-closed empty | Empty policy set -> Deny |
| V2 | Fail-closed no match | All unmatched -> Deny |
| V3 | Allow requires match | Allow -> matching non-deny, non-override policy exists |
| V4 | Rule override -> Deny | Path/network/IP override forces Deny |
| V5 | Totality | Function always terminates |
| V8 | Conditional pass-through | Unfired condition + continue -> skip to next |

| V11 | Path block -> Deny | Path block sets rule_override_deny -> final verdict is Deny |
| V12 | Network block -> Deny | Network/IP block sets rule_override_deny -> final verdict is Deny |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

Priority-dependent properties (V6, V7) require a sortedness precondition that
will be proven by a Kani harness (K19) in Phase 3.

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_first_match_override_is_deny` | First matched policy with rule_override -> final verdict is Deny |
| `lemma_all_unmatched_is_deny` | All unmatched entries -> final verdict is Deny |
| `lemma_skip_continues` | Consecutive Continue outcomes can be skipped (induction helper) |
| `lemma_path_block_is_deny` | Path block -> rule_override_deny -> Deny (V11) |
| `lemma_network_block_is_deny` | Network/IP block -> rule_override_deny -> Deny (V12) |
| `lemma_any_rule_override_is_deny` | Any rule type setting rule_override_deny -> Deny |

### Constraint Evaluation Kernel (`verified_constraint_eval.rs`) — 12 verified items, ENG-CON-1–ENG-CON-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| ENG-CON-1 | All-skipped detection | `total_constraints > 0 && !any_evaluated` iff every configured constraint was skipped |
| ENG-CON-2 | Forbidden precedence | Any forbidden parameter presence forces `Deny` |
| ENG-CON-3 | Require-approval precedence | `require_approval` forces `RequireApproval` unless already denied |
| ENG-CON-4 | No-match handling | `on_no_match_continue` only yields `Continue` on the no-match path |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_all_skipped_is_fail_closed` | A non-empty all-skipped constraint set is fail-closed |
| `lemma_forbidden_precedes_approval` | Forbidden parameter presence overrides `require_approval` and yields `Deny` |
| `lemma_no_match_continue_is_only_continue` | `Continue` is reachable only on the explicit no-match path |

### Path Normalization (`verified_path.rs`) — 30 verified items; V9-V10 fully proved

Current status for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| V9 | Idempotence | Fully proved: `normalize(normalize(x)) = normalize(x)` |
| V10 | No traversal in output | Fully proved: normalized output never contains `..` component |

Verification result: **30 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Discharged Helper Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_component_has_no_dotdot` | A normal component cannot be `..` at component boundaries |
| `lemma_join_prefix_step_has_no_dotdot` | Reconstructing output from normal components preserves V10 |
| `lemma_normalize_idempotent` | The spec-normalized path is a fixed point of normalization (V9) |

Path idempotence is also independently proved elsewhere in the suite:
- Lean: `formal/lean/Vellaveto/PathNormalization.lean`
- Coq: `formal/coq/Vellaveto/PathNormalization.v`
- Kani: `proof_path_normalize_idempotent` in `formal/kani/src/proofs.rs`

### DLP Buffer Arithmetic (`verified_dlp_core.rs`) — 14 proofs, D1-D6

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| D1 | UTF-8 char boundary safety | `extract_tail` never returns start in mid-character |
| D2 | Single buffer size bounded | Extracted tail never exceeds `max_size` bytes |
| D3 | Total byte accounting correct | `update_total_bytes` maintains consistency |
| D4 | Capacity check fail-closed | At `max_fields`, `can_track_field` returns false |
| D5 | No arithmetic underflow | Saturating subtraction prevents wrapping |
| D6 | Overlap completeness | Secret <= 2 * overlap split at `split_point <= overlap_size` fully covered (first fragment must fit in tail buffer) |

Verification result: **14 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_continuation_not_boundary` | Continuation bytes (0x80-0xBF) are NOT char boundaries (bit_vector) |
| `lemma_non_continuation_is_boundary` | Non-continuation bytes are char boundaries (bit_vector) |
| `overlap_completeness_lemma` | Combined scan buffer covers entire split secret |
| `lemma_capacity_fail_closed` | At max_fields, can_track_field is always false |
| `lemma_ascii_all_boundaries` | For ASCII input, all bytes are char boundaries |

## Production Code Correspondence

| Verus File | Production File | Wiring |
|-----------|----------------|--------|
| `formal/verus/verified_core.rs` | `vellaveto-engine/src/verified_core.rs` | `debug_assert` at 7 decision points |
| `formal/verus/verified_constraint_eval.rs` | `vellaveto-engine/src/verified_constraint_eval.rs` | `constraint_eval.rs` calls the verified `all_constraints_skipped` and `no_match_verdict` helpers |
| `formal/verus/verified_dlp_core.rs` | `vellaveto-mcp/src/inspection/verified_dlp_core.rs` | Called by `CrossCallDlpTracker::update_buffer()` |
| `formal/verus/verified_path.rs` | `vellaveto-mcp/src/capability_token.rs` | Byte-level equivalent of `normalize_path_for_grant` |

The executable logic is semantically equivalent — Verus annotations (`ensures`,
`requires`, `invariant`, `decreases`, `proof fn`) are erased during normal
compilation. Minor syntactic differences exist (e.g., `len() == 0` vs
`.is_empty()`, `&Vec<T>` vs `&[T]`) but are operationally identical.

## How to Verify

```bash
# Option 1: Binary release (recommended)
VERUS_VERSION="0.2026.03.01.25809cb"
curl -sSL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip"
unzip verus.zip -d verus-bin
rustup install 1.93.1-x86_64-unknown-linux-gnu

# Constraint evaluation fail-closed control flow (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_constraint_eval.rs

# Core verdict + rule override (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# DLP buffer arithmetic (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs

# Path normalization no-traversal (30 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_path.rs

# Option 2: From source
git clone https://github.com/verus-lang/verus
cd verus && ./tools/get-z3.sh && source ./tools/activate
cargo build --release
verus formal/verus/verified_constraint_eval.rs
verus formal/verus/verified_core.rs
verus formal/verus/verified_dlp_core.rs
verus formal/verus/verified_path.rs
```

Expected output:
- `verified_constraint_eval.rs`: `verification results:: 12 verified, 0 errors`
- `verified_core.rs`: `verification results:: 12 verified, 0 errors`
- `verified_dlp_core.rs`: `verification results:: 14 verified, 0 errors`
- `verified_path.rs`: `verification results:: 30 verified, 0 errors`

## Trust Boundary

See `docs/TRUSTED_COMPUTING_BASE.md` Section 5 for the full trust model.

Verus trusts:
- Z3 SMT solver (Microsoft Research)
- Verus verifier (translation from Rust+specs to Z3 queries)
- rustc codegen (LLVM)

Verus does NOT verify:
- The `HashMap` wrapper in `cross_call_dlp.rs` (lookup table, not security logic)
- String operations, glob/regex matching, Unicode normalization
- HashMap, serde, I/O

The `ResolvedMatch` construction equivalence is now verified by Kani (K46-K48).
Other gaps are covered by Kani (bounded) and 10,000+ tests.
