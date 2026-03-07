# Verus Formal Verification

Deductive verification of Vellaveto's core verdict computation, constraint
evaluation fail-closed control flow, capability attenuation arithmetic,
capability grant attenuation, capability pattern attenuation, fixed-point
entropy alert gating, cross-call DLP tracker gating, DLP buffer arithmetic,
and path normalization using
[Verus](https://github.com/verus-lang/verus).

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

### Capability Attenuation Arithmetic (`verified_capability_attenuation.rs`) — 11 verified items, CAP-ATT-1–CAP-ATT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-ATT-1 | Depth decrement | A delegable parent always yields child depth `parent - 1` |
| CAP-ATT-2 | Depth fail-closed | Depth `0` cannot delegate further |
| CAP-ATT-3 | Expiry clamp | Child expiry is always at or before the parent expiry and at or before `now + ttl` |
| CAP-ATT-4 | Transitive non-increase | Repeated attenuation keeps both depth and expiry monotonically decreasing |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_depth_strictly_decreases` | Any delegable parent loses at least one depth unit |
| `lemma_depth_transitive` | Two attenuation steps keep depth strictly decreasing |
| `lemma_expiry_never_exceeds_parent` | The clamped child expiry never exceeds the parent expiry |
| `lemma_expiry_stays_within_requested_window` | The child expiry never exceeds the requested `now + ttl` window |
| `lemma_parent_expiry_is_fail_closed` | An already expired parent cannot produce a child expiry |
| `lemma_ttl_limit_is_fail_closed` | A TTL above policy cannot produce a child expiry |
| `lemma_expiry_transitive_nonincreasing` | A second attenuation step cannot increase expiry past the first or root parent |

### Capability Grant Attenuation (`verified_capability_grant.rs`) — 8 verified items, CAP-GRANT-1–CAP-GRANT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-GRANT-1 | Path restriction preservation | A child cannot drop required path restrictions when the parent has them |
| CAP-GRANT-2 | Domain restriction preservation | A child cannot drop required domain restrictions when the parent has them |
| CAP-GRANT-3 | Invocation bound attenuation | A limited parent rejects unlimited or larger child `max_invocations` |
| CAP-GRANT-4 | Unlimited-parent shape equivalence | When the parent is unlimited, only the restriction-shape checks remain |

Verification result: **8 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_path_restrictions_cannot_be_dropped` | A parent path restriction cannot be erased by the child |
| `lemma_domain_restrictions_cannot_be_dropped` | A parent domain restriction cannot be erased by the child |
| `lemma_limited_parent_rejects_unlimited_child` | A limited parent cannot delegate an unlimited child |
| `lemma_limited_parent_rejects_larger_child_limit` | A child invocation bound cannot exceed the parent's limit |
| `lemma_limited_parent_accepts_smaller_child_limit` | A smaller positive child bound is accepted when restriction shapes are preserved |
| `lemma_unlimited_parent_leaves_only_shape_checks` | With unlimited parent invocations, attenuation reduces to the shape-preservation checks |

### Capability Pattern Attenuation (`verified_capability_pattern.rs`) — 10 verified items, CAP-PAT-1–CAP-PAT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-PAT-1 | Metacharacter detection | `has_glob_metacharacters` precisely detects `*` and `?` bytes |
| CAP-PAT-2 | Non-identical child glob rejection | A child pattern with `*` or `?` is rejected unless the parent is wildcard or the patterns are equal ignoring ASCII case |
| CAP-PAT-3 | Wildcard/equality fast path | Wildcard parents and identical patterns always pass the guard |
| CAP-PAT-4 | Literal-child fallthrough | Literal children always fall through to the runtime matcher instead of being rejected by the guard |

Verification result: **10 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_non_identical_child_glob_rejected` | A differing child glob is fail-closed |
| `lemma_wildcard_parent_allows_child_glob` | A wildcard parent cannot be blocked by the guard |
| `lemma_identical_child_glob_allowed` | Exact equality bypasses the child-glob rejection |
| `lemma_literal_child_falls_through` | Literal child patterns are not rejected by the guard |
| `lemma_accepted_child_glob_requires_wildcard_or_equality` | An accepted child glob must be justified by wildcard parent or equality |

### Entropy Alert Gate (`verified_entropy_gate.rs`) — 11 verified items, ENT-GATE-1–ENT-GATE-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| ENT-GATE-1 | Fixed-point threshold comparison | `is_high_entropy_millibits(obs, thresh)` iff `obs >= thresh` |
| ENT-GATE-2 | Alert count threshold | Entropy alert activates iff `high_entropy_count >= min_entropy_observations` |
| ENT-GATE-3 | Saturating high-severity threshold | Doubling the minimum observation count saturates at `u32::MAX` |
| ENT-GATE-4 | Severity tier mapping | Counts at or above the doubled threshold map to `High`, otherwise `Medium` |
| ENT-GATE-5 | Optional alert severity | `entropy_alert_severity` returns `None` below threshold and `Some(level)` otherwise |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_no_alert_below_threshold` | Counts below the alert threshold can never yield an entropy alert |
| `lemma_threshold_alerts_medium` | In the non-saturating range, hitting the exact threshold yields `Medium` severity |
| `lemma_high_severity_threshold_alerts_high` | Hitting the saturated high-severity threshold always yields `High` |

### Path Normalization (`verified_path.rs`) — 31 verified items; V9-V10 fully proved

Current status for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| V9 | Idempotence | Fully proved: `normalize(normalize(x)) = normalize(x)` |
| V10 | No traversal in output | Fully proved: normalized output never contains `..` component |

Verification result: **31 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Discharged Helper Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_component_has_no_dotdot` | A normal component cannot be `..` at component boundaries |
| `lemma_join_prefix_step_has_no_dotdot` | Reconstructing output from normal components preserves V10 |
| `lemma_process_bytes_total` | The extracted component-processing kernel is total on null-free inputs |
| `lemma_normalize_idempotent` | The spec-normalized path is a fixed point of normalization (V9) |

This proof now targets the extracted engine kernel in
`vellaveto-engine/src/path.rs::normalize_decoded_path`, which is called by
`normalize_path_bounded()` after percent-decoding, UTF-8 validation, and
backslash normalization.

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

### Cross-Call DLP Tracker Gate (`verified_cross_call_dlp.rs`) — 9 verified items, CC-DLP-1–CC-DLP-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CC-DLP-1 | Existing field never emits capacity finding | Capacity-exhausted synthetic findings only apply to new fields |
| CC-DLP-2 | Existing field always updates | Existing tracked fields keep overlap coverage even when the tracker is at field capacity |
| CC-DLP-3 | New field at capacity blocks update | A new field at or above `max_fields` cannot enter the overlap tracker |
| CC-DLP-4 | New field below capacity with budget updates | A new field is admitted only when both field-count and byte-budget gates pass |
| CC-DLP-5 | Capacity finding implies update blocked | For new fields, the synthetic fail-closed finding and update denial stay aligned |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_existing_field_never_emits_capacity_finding` | Existing fields can never raise the synthetic capacity finding |
| `lemma_existing_field_always_updates` | Existing fields always pass the update gate |
| `lemma_new_field_at_capacity_emits_and_blocks_update` | New fields at capacity both emit the finding and fail the update gate |
| `lemma_new_field_below_capacity_with_budget_updates` | New fields below capacity and within byte budget are admitted |
| `lemma_capacity_finding_implies_update_blocked` | The fail-closed capacity finding cannot diverge from the update decision |

## Production Code Correspondence

| Verus File | Production File | Wiring |
|-----------|----------------|--------|
| `formal/verus/verified_core.rs` | `vellaveto-engine/src/verified_core.rs` | `debug_assert` at 7 decision points |
| `formal/verus/verified_constraint_eval.rs` | `vellaveto-engine/src/verified_constraint_eval.rs` | `constraint_eval.rs` calls the verified `all_constraints_skipped` and `no_match_verdict` helpers |
| `formal/verus/verified_capability_attenuation.rs` | `vellaveto-mcp/src/verified_capability_attenuation.rs` | `capability_token.rs` routes remaining-depth decrement and expiry clamping through the verified arithmetic gate |
| `formal/verus/verified_capability_grant.rs` | `vellaveto-mcp/src/verified_capability_grant.rs` | `capability_token.rs` routes required restriction-shape and `max_invocations` attenuation through the verified grant gate |
| `formal/verus/verified_capability_pattern.rs` | `vellaveto-mcp/src/verified_capability_pattern.rs` | `capability_token.rs` routes child-glob metacharacter rejection through the verified pattern guard |
| `formal/verus/verified_entropy_gate.rs` | `vellaveto-engine/src/verified_entropy_gate.rs` | `entropy_gate.rs` converts `f64` telemetry to millibits, then `collusion.rs` uses the verified integer gate |
| `formal/verus/verified_cross_call_dlp.rs` | `vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs` | `cross_call_dlp.rs` routes the synthetic capacity finding and overlap-buffer update decision through the verified gate |
| `formal/verus/verified_dlp_core.rs` | `vellaveto-mcp/src/inspection/verified_dlp_core.rs` | Called by `CrossCallDlpTracker::update_buffer()` |
| `formal/verus/verified_path.rs` | `vellaveto-engine/src/path.rs` | Byte-level equivalent of `normalize_decoded_path`, called by `normalize_path_bounded()` after decode/backslash normalization |

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

# Capability attenuation depth/expiry kernel (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_attenuation.rs

# Capability grant restriction/invocation kernel (8 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_grant.rs

# Capability child-glob rejection guard (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_pattern.rs

# Constraint evaluation fail-closed control flow (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_constraint_eval.rs

# Core verdict + rule override (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# Fixed-point entropy alert gate (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_entropy_gate.rs

# Cross-call DLP tracker gate (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_cross_call_dlp.rs

# DLP buffer arithmetic (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs

# Path normalization no-traversal (31 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_path.rs

# Option 2: From source
git clone https://github.com/verus-lang/verus
cd verus && ./tools/get-z3.sh && source ./tools/activate
cargo build --release
verus formal/verus/verified_capability_attenuation.rs
verus formal/verus/verified_capability_grant.rs
verus formal/verus/verified_capability_pattern.rs
verus formal/verus/verified_constraint_eval.rs
verus formal/verus/verified_core.rs
verus formal/verus/verified_entropy_gate.rs
verus formal/verus/verified_cross_call_dlp.rs
verus formal/verus/verified_dlp_core.rs
verus formal/verus/verified_path.rs
```

Expected output:
- `verified_capability_attenuation.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_grant.rs`: `verification results:: 8 verified, 0 errors`
- `verified_capability_pattern.rs`: `verification results:: 10 verified, 0 errors`
- `verified_constraint_eval.rs`: `verification results:: 12 verified, 0 errors`
- `verified_core.rs`: `verification results:: 12 verified, 0 errors`
- `verified_entropy_gate.rs`: `verification results:: 11 verified, 0 errors`
- `verified_cross_call_dlp.rs`: `verification results:: 9 verified, 0 errors`
- `verified_dlp_core.rs`: `verification results:: 14 verified, 0 errors`
- `verified_path.rs`: `verification results:: 31 verified, 0 errors`

## Trust Boundary

See `docs/TRUSTED_COMPUTING_BASE.md` Section 5 for the full trust model.

Verus trusts:
- Z3 SMT solver (Microsoft Research)
- Verus verifier (translation from Rust+specs to Z3 queries)
- rustc codegen (LLVM)

Verus does NOT verify:
- The `HashMap` wrapper in `cross_call_dlp.rs` beyond the extracted field-capacity/update gate
- Full pattern-language containment in `capability_token.rs` (literal/glob matching and path/domain coverage still rely on runtime checks and tests)
- String operations, glob/regex matching, Unicode normalization
- HashMap, serde, I/O

The `ResolvedMatch` construction equivalence is now verified by Kani (K46-K48).
Other gaps are covered by Kani (bounded) and 10,000+ tests.
