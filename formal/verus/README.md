# Verus Formal Verification

Deductive verification of Vellaveto's core verdict computation, constraint
evaluation fail-closed control flow, audit append/recovery counter transitions,
audit-chain verification guards, Merkle append/init/proof-shape guards,
Merkle fold structure, Merkle proof-path structure, cross-rotation
manifest linkage/path-safety guards, capability attenuation arithmetic,
capability parent-glob literal-child matching,
capability grant attenuation, capability literal matching fast paths,
capability pattern attenuation, capability holder/issuer identity-chain
guards, NHI delegation terminal-state/participant/link/depth guards,
fixed-point entropy alert gating,
cross-call DLP tracker gating, DLP buffer arithmetic, and path normalization using
[Verus](https://github.com/verus-lang/verus).

All standalone kernels now share `formal/verus/assumptions.rs`, a
Verus-facing mirror of the canonical local assumption registry.
Each standalone kernel now binds itself to a checker-enforced kernel-scoped
assumption contract rather than the whole shared boundary.
The Merkle and audit-filesystem trust boundaries are also mirrored as explicit
Verus axiom modules under `formal/verus/`.
The canonical multi-file entrypoint is now
`cargo-verus verify --manifest-path formal/verus/Cargo.toml`.
The local shell wrapper keeps a direct per-file `verus` fallback unless
`FORMAL_USE_CARGO_VERUS=1` is selected.

## What Is Verified

### Core Verdict Logic (`verified_core.rs`) — 14 proofs, V1-V8, V11-V12

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

Verification result: **14 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

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

### Constraint Evaluation Kernel (`verified_constraint_eval.rs`) — 14 verified items, ENG-CON-1–ENG-CON-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| ENG-CON-1 | All-skipped detection | `total_constraints > 0 && !any_evaluated` iff every configured constraint was skipped |
| ENG-CON-2 | Forbidden precedence | Any forbidden parameter presence forces `Deny` |
| ENG-CON-3 | Require-approval precedence | `require_approval` forces `RequireApproval` unless already denied |
| ENG-CON-4 | No-match handling | `on_no_match_continue` only yields `Continue` on the no-match path |

Verification result: **14 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_all_skipped_is_fail_closed` | A non-empty all-skipped constraint set is fail-closed |
| `lemma_forbidden_precedes_approval` | Forbidden parameter presence overrides `require_approval` and yields `Deny` |
| `lemma_no_match_continue_is_only_continue` | `Continue` is reachable only on the explicit no-match path |

### Audit Append/Recovery Counters (`verified_audit_append.rs`) — 19 verified items, AUD-APP-1–AUD-APP-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| AUD-APP-1 | Rotation resets per-file count | A rotation reset always sets `entry_count` to `0` before the next append |
| AUD-APP-2 | Per-file append count saturates monotonically | Each successful append increments the per-file `entry_count`, saturating at `u64::MAX` |
| AUD-APP-3 | Assigned sequence is the pre-append snapshot | The sequence written into a new entry is exactly the current `global_sequence` value before increment |
| AUD-APP-4 | Global sequence saturates monotonically | Each successful append increments `global_sequence`, saturating at `u64::MAX` |
| AUD-APP-5 | Recovery resumes at one past the highest observed sequence | Restart recovery sets the next `global_sequence` to `max_observed_sequence + 1`, saturating at `u64::MAX` |

Verification result: **19 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_rotation_resets_entry_count` | A rotation reset always yields per-file count `0` |
| `lemma_rotation_then_append_yields_one` | Resetting on rotation and then appending yields per-file count `1` |
| `lemma_assigned_sequence_is_identity` | The assigned sequence is exactly the pre-append `global_sequence` |
| `lemma_entry_count_increments_when_not_saturated` | A non-saturated per-file counter increases by exactly one |
| `lemma_entry_count_saturates_at_u64_max` | A saturated per-file counter stays pinned at `u64::MAX` |
| `lemma_global_sequence_increments_when_not_saturated` | A non-saturated global sequence increases by exactly one |
| `lemma_global_sequence_saturates_at_u64_max` | A saturated global sequence stays pinned at `u64::MAX` |
| `lemma_assigned_sequence_precedes_next_global_sequence` | The assigned sequence can never exceed the post-append global sequence |
| `lemma_recovery_sequence_advances_when_not_saturated` | Recovery advances one past the highest observed sequence when unsaturated |
| `lemma_recovery_sequence_saturates_at_u64_max` | Recovery stays pinned at `u64::MAX` when the observed maximum is saturated |

### Audit-Chain Verification Guard (`verified_audit_chain.rs`) — 19 verified items, AUD-CHAIN-1–AUD-CHAIN-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| AUD-CHAIN-1 | Timestamp guard fail-closed | Only UTC timestamps with non-decreasing normalized order can pass the timestamp guard |
| AUD-CHAIN-2 | Sequence monotonicity | Legacy `sequence = 0` entries are accepted, while tracked non-zero sequences must strictly increase |
| AUD-CHAIN-3 | Hash presence monotonicity | Once a hashed entry appears, all subsequent entries must also carry hashes |
| AUD-CHAIN-4 | Hashed-step linkage and self-hash | A hashed entry can pass only if both `prev_hash` linkage and recomputed `entry_hash` checks match |
| AUD-CHAIN-5 | Verifier state monotonicity | `seen_hashed_entry` latches true and legacy zero-sequence entries preserve the tracked non-zero sequence |

Verification result: **19 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_non_utc_timestamp_rejected` | A non-UTC timestamp can never pass the timestamp guard |
| `lemma_timestamp_regression_rejected` | A timestamp regression can never pass the timestamp guard |
| `lemma_legacy_zero_sequence_is_accepted` | Legacy zero-sequence entries always satisfy the monotonicity predicate |
| `lemma_sequence_regression_rejected` | A non-zero sequence that does not strictly increase is rejected |
| `lemma_unhashed_after_hashed_rejected` | An unhashed entry after a hashed prefix is fail-closed |
| `lemma_legacy_prefix_unhashed_allowed` | Unhashed legacy entries are allowed only before any hashed entry |
| `lemma_hashed_step_requires_link_and_hash` | A hashed step that passes must have both matching `prev_hash` and matching recomputed hash |
| `lemma_unhashed_step_ignores_hash_booleans` | Unhashed legacy steps depend only on the timestamp/sequence/hash-presence guards |
| `lemma_seen_hashed_latches_true` | Once the verifier has seen a hashed entry, the state remains latched |
| `lemma_next_prev_sequence_preserves_legacy_zero` | A zero-sequence legacy entry cannot overwrite the tracked non-zero sequence |

### Merkle Fail-Closed Guards (`verified_merkle.rs`) — 23 verified items, MERKLE-1–MERKLE-6

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| MERKLE-1 | Append capacity fail-closed | An append is accepted iff `leaf_count < max_leaf_count` |
| MERKLE-2 | Stored leaf-count replay bound | Initialization accepts persisted state iff `leaf_count <= max_leaf_count` |
| MERKLE-3 | Non-zero proof tree size | Merkle proof verification rejects `tree_size = 0` |
| MERKLE-4 | Leaf index range check | Merkle proof verification rejects `leaf_index >= tree_size` |
| MERKLE-5 | Proof depth bound | Merkle proof verification rejects sibling vectors longer than 64 steps |
| MERKLE-6 | Sibling hash width check | Merkle proof verification rejects decoded sibling hashes whose length is not 32 bytes |

Verification result: **23 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_append_rejects_at_limit` | An append at exactly the configured leaf limit is fail-closed |
| `lemma_append_accepts_below_limit` | An append strictly below the configured leaf limit is accepted |
| `lemma_stored_leaf_count_accepts_equal_limit` | Replaying persisted state exactly at the configured leaf limit is accepted |
| `lemma_stored_leaf_count_rejects_over_limit` | Replaying persisted state above the configured leaf limit is rejected |
| `lemma_zero_tree_size_rejected` | A Merkle proof claiming `tree_size = 0` can never pass the guard |
| `lemma_positive_tree_size_accepted` | A positive Merkle `tree_size` satisfies the tree-size guard |
| `lemma_leaf_index_out_of_range_rejected` | A proof leaf index at or above `tree_size` is rejected |
| `lemma_leaf_index_in_range_accepted` | A proof leaf index strictly below `tree_size` satisfies the range guard |
| `lemma_too_many_siblings_rejected` | A Merkle proof with more than 64 siblings is rejected |
| `lemma_bounded_sibling_count_accepted` | A Merkle proof with at most 64 siblings satisfies the depth guard |
| `lemma_hash_len_32_accepted` | A 32-byte decoded sibling hash satisfies the width guard |
| `lemma_hash_len_non_32_rejected` | Any decoded sibling hash whose length is not 32 bytes is rejected |

### Merkle Fold Kernel (`verified_merkle_fold.rs`) — 17 verified items, MERKLE-FOLD-1–MERKLE-FOLD-7

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| MERKLE-FOLD-1 | Next-level width rounds up | Building the next Merkle level always yields `len / 2 + len % 2` nodes |
| MERKLE-FOLD-2 | First pair parent construction | The first parent in any level of width at least two is `left || right` in that order |
| MERKLE-FOLD-3 | Odd-tail promotion | A trailing node in an odd-width level is promoted unchanged |
| MERKLE-FOLD-4 | Proof fold direction | Proof verification folds `current || sibling` or `sibling || current` exactly as encoded by the direction bit |
| MERKLE-FOLD-5 | Parent-step correspondence | One proof step reconstructs the same abstract parent that the next-level builder produces at the matching parent index |
| MERKLE-FOLD-6 | Peak fold direction | Root folding always places the higher peak on the left of the accumulator |
| MERKLE-FOLD-7 | Abstract proof/root reconstruction | The recursively generated proof steps reconstruct the same abstract root as repeated next-level folding |

Verification result: **17 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_next_level_len_drops_pair` | Removing a leading pair reduces the rounded-up next-level width by exactly one |
| `lemma_next_level_length_matches_round_up` | The recursive next-level builder has the expected rounded-up width |
| `lemma_fold_proof_step_respects_direction` | The proof-step fold preserves the exact left/right concatenation order |
| `lemma_fold_peak_places_peak_on_left` | Peak folding always puts the new peak on the left of the running root |
| `lemma_first_pair_builds_next_level_parent` | The first pair in a non-trivial level builds the first parent exactly |
| `lemma_trailing_odd_node_promoted` | The last node in an odd-width level is carried upward unchanged |
| `lemma_parent_step_matches_fold` | The proof-step fold at any index matches the parent selected by the next-level builder |
| `lemma_proof_reconstructs_root_with_fuel` | Any proof path reconstructs the same abstract root when given sufficient recursion fuel |
| `lemma_proof_reconstructs_root` | The canonical proof path for any valid index reconstructs the abstract tree root |

### Merkle Proof-Path Kernel (`verified_merkle_path.rs`) — 15 verified items, MERKLE-PATH-1–MERKLE-PATH-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| MERKLE-PATH-1 | Sibling pairing rule | Even node indices pair with the right neighbor; odd indices pair with the left neighbor |
| MERKLE-PATH-2 | Promotion boundary | A trailing unpaired node in an odd-width level emits no proof step and is promoted unchanged |
| MERKLE-PATH-3 | Direction-bit encoding | The generated `is_left` bit is true iff the sibling must be hashed on the left |
| MERKLE-PATH-4 | Parent ascent | Advancing one proof level always maps `node_index` to `node_index / 2` |
| MERKLE-PATH-5 | Verifier direction preservation | Proof verification interprets the encoded `is_left` bit without inversion |

Verification result: **15 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_even_index_uses_right_sibling` | An even node index pairs with the sibling at `index + 1` and does not encode a left sibling |
| `lemma_odd_index_uses_left_sibling` | An odd node index pairs with the sibling at `index - 1` and encodes a left sibling |
| `lemma_trailing_even_index_without_pair_is_promoted` | The last node in an odd-width level is promoted without emitting a sibling step |
| `lemma_paired_even_index_has_sibling` | An even node with a neighbor to its right always emits a proof step |
| `lemma_valid_odd_index_has_left_sibling` | Any odd node index within bounds always emits a left-sibling proof step |
| `lemma_parent_index_halves_child` | Each ascent step computes the parent index by integer division by two |
| `lemma_verifier_direction_is_identity` | The verifier preserves the encoded left/right direction bit exactly |

### Rotation Manifest Guards (`verified_rotation_manifest.rs`) — 16 verified items, ROT-MAN-1–ROT-MAN-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| ROT-MAN-1 | Start-hash linkage fail-closed | A non-empty manifest `start_hash` may pass only when there is no previous tail hash or it matches the previous tail exactly |
| ROT-MAN-2 | Rotated filename safety | A rotated-file reference may pass only when it is non-empty, non-absolute, traversal-free, and a bare filename |
| ROT-MAN-3 | Missing-file prune boundary | Missing rotated files are allowed only before any existing rotated segment has been checked |

Verification result: **16 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_empty_start_hash_always_valid` | An empty `start_hash` always satisfies the linkage guard |
| `lemma_first_segment_without_previous_tail_is_valid` | The first segment is allowed to carry a non-empty `start_hash` when there is no previous tail |
| `lemma_matching_previous_tail_is_valid` | A `start_hash` equal to the previous tail is accepted |
| `lemma_mismatching_nonempty_start_hash_is_rejected` | A non-empty mismatching `start_hash` is fail-closed |
| `lemma_safe_rotated_file_reference_is_valid` | A bare non-empty relative filename is accepted |
| `lemma_traversal_reference_is_rejected` | A path traversal reference is always rejected |
| `lemma_absolute_reference_is_rejected` | An absolute rotated-file reference is always rejected |
| `lemma_non_bare_reference_is_rejected` | A non-bare rotated-file reference is always rejected |
| `lemma_empty_reference_is_rejected` | An empty rotated-file reference is always rejected |
| `lemma_only_prefix_missing_files_are_allowed` | Missing rotated files are permitted only in the all-missing prefix before any existing segment |

### Capability Attenuation Arithmetic (`verified_capability_attenuation.rs`) — 13 verified items, CAP-ATT-1–CAP-ATT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-ATT-1 | Depth decrement | A delegable parent always yields child depth `parent - 1` |
| CAP-ATT-2 | Depth fail-closed | Depth `0` cannot delegate further |
| CAP-ATT-3 | Expiry clamp | Child expiry is always at or before the parent expiry and at or before `now + ttl` |
| CAP-ATT-4 | Transitive non-increase | Repeated attenuation keeps both depth and expiry monotonically decreasing |

Verification result: **13 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

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

### Capability Parent-Glob Matcher (`verified_capability_glob.rs`) — 19 verified items, CAP-GLOB-1–CAP-GLOB-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-GLOB-1 | ASCII fold correctness | Uppercase ASCII bytes fold to lowercase while non-uppercase bytes are unchanged |
| CAP-GLOB-2 | Case-insensitive byte equality | Byte comparison is exactly ASCII-case-insensitive equality after folding |
| CAP-GLOB-3 | Empty-pattern base case | An empty parent pattern matches iff the child literal is also empty |
| CAP-GLOB-4 | `?` fail-closed empty rejection | A `?` step cannot match an empty child suffix |
| CAP-GLOB-5 | Literal-child matcher equivalence | The extracted recursive parent-glob matcher is equivalent to its Verus spec for the delegation subset branch |

Verification result: **19 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_ascii_uppercase_folds_to_lowercase` | Any uppercase ASCII byte folds by the expected offset |
| `lemma_non_uppercase_byte_is_stable` | Bytes outside `A-Z` remain unchanged by the fold |
| `lemma_case_insensitive_byte_match_is_symmetric` | Case-insensitive byte comparison is symmetric |
| `lemma_empty_pattern_matches_only_empty_child` | The base case accepts only the empty child literal |
| `lemma_question_rejects_empty_child` | `?` cannot consume an empty child suffix |
| `lemma_literal_mismatch_is_rejected` | A mismatching literal byte cannot be accepted by the parent-glob matcher |

### Capability Grant Attenuation (`verified_capability_grant.rs`) — 10 verified items, CAP-GRANT-1–CAP-GRANT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-GRANT-1 | Path restriction preservation | A child cannot drop required path restrictions when the parent has them |
| CAP-GRANT-2 | Domain restriction preservation | A child cannot drop required domain restrictions when the parent has them |
| CAP-GRANT-3 | Invocation bound attenuation | A limited parent rejects unlimited or larger child `max_invocations` |
| CAP-GRANT-4 | Unlimited-parent shape equivalence | When the parent is unlimited, only the restriction-shape checks remain |

Verification result: **10 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_path_restrictions_cannot_be_dropped` | A parent path restriction cannot be erased by the child |
| `lemma_domain_restrictions_cannot_be_dropped` | A parent domain restriction cannot be erased by the child |
| `lemma_limited_parent_rejects_unlimited_child` | A limited parent cannot delegate an unlimited child |
| `lemma_limited_parent_rejects_larger_child_limit` | A child invocation bound cannot exceed the parent's limit |
| `lemma_limited_parent_accepts_smaller_child_limit` | A smaller positive child bound is accepted when restriction shapes are preserved |
| `lemma_unlimited_parent_leaves_only_shape_checks` | With unlimited parent invocations, attenuation reduces to the shape-preservation checks |

### Capability Literal Fast Paths (`verified_capability_literal.rs`) — 11 verified items, CAP-LIT-1–CAP-LIT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-LIT-1 | Literal match acceptance | A pattern with no metacharacters matches iff the case-insensitive equality bit is true |
| CAP-LIT-2 | Metacharacter exclusion | Patterns containing `*` or `?` can never use the literal fast path |
| CAP-LIT-3 | Literal-child subset acceptance | A literal child is accepted by the subset fast path iff the parent runtime matcher accepts the literal child |
| CAP-LIT-4 | Child-glob exclusion | Child patterns containing `*` or `?` can never use the literal-child subset branch |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_equal_literal_pattern_matches` | A literal pattern on an equal value is accepted by the literal fast path |
| `lemma_mismatching_literal_pattern_is_denied` | A literal pattern mismatch cannot be accepted by the literal fast path |
| `lemma_metacharacter_pattern_skips_literal_fast_path` | A metacharacter-bearing pattern always bypasses the literal fast path |
| `lemma_matching_literal_child_is_subset` | A literal child accepted by the parent matcher is accepted by the subset fast path |
| `lemma_mismatching_literal_child_is_denied` | A mismatching literal child is rejected by the subset fast path |
| `lemma_child_glob_cannot_use_literal_subset_branch` | A child glob can never be accepted by the literal-child subset branch |

### Capability Pattern Attenuation (`verified_capability_pattern.rs`) — 12 verified items, CAP-PAT-1–CAP-PAT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-PAT-1 | Metacharacter detection | `has_glob_metacharacters` precisely detects `*` and `?` bytes |
| CAP-PAT-2 | Non-identical child glob rejection | A child pattern with `*` or `?` is rejected unless the parent is wildcard or the patterns are equal ignoring ASCII case |
| CAP-PAT-3 | Wildcard/equality fast path | Wildcard parents and identical patterns always pass the guard |
| CAP-PAT-4 | Literal-child fallthrough | Literal children always fall through to the runtime matcher instead of being rejected by the guard |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_non_identical_child_glob_rejected` | A differing child glob is fail-closed |
| `lemma_wildcard_parent_allows_child_glob` | A wildcard parent cannot be blocked by the guard |
| `lemma_identical_child_glob_allowed` | Exact equality bypasses the child-glob rejection |
| `lemma_literal_child_falls_through` | Literal child patterns are not rejected by the guard |
| `lemma_accepted_child_glob_requires_wildcard_or_equality` | An accepted child glob must be justified by wildcard parent or equality |

### Capability Identity-Chain Guards (`verified_capability_identity.rs`) — 11 verified items, CAP-ID-1–CAP-ID-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-ID-1 | Self-delegation rejection | A delegated child holder normalized to the same identity as the parent holder is always rejected |
| CAP-ID-2 | Delegated issuer-link validity | Root tokens have no parent obligation; delegated children must carry the parent holder as issuer |
| CAP-ID-3 | Holder expectation satisfaction | Verification passes iff the normalized holder equals the expected holder |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_self_delegation_is_rejected` | Self-delegation (normalized new == parent holder) is always blocked |
| `lemma_distinct_holder_is_allowed` | A distinct holder passes the delegation guard |
| `lemma_root_token_issuer_is_unconstrained` | Root tokens (no parent) are unconstrained in their issuer field |
| `lemma_delegated_child_requires_parent_holder_issuer` | A delegated child with a mismatching issuer is rejected |
| `lemma_matching_holder_expectation_is_required` | Both directions of the holder-expectation identity are proved |

### NHI Delegation Guards (`verified_nhi_delegation.rs`) — 19 verified items, NHI-DEL-1–NHI-DEL-8

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| NHI-DEL-1 | Terminal-state detection | Revoked or expired identities are terminal (delegation-blocking) |
| NHI-DEL-2 | Participant guard fail-closed | Terminal identities cannot participate in delegation |
| NHI-DEL-3 | Link-effective guard | A delegation link is effective iff the target agent matches, the link is active, the expiry parsed, and now is before expiry |
| NHI-DEL-4 | Depth-exceeded guard | Chain depth exceeds the bound iff `chain_len > max_depth` (strict, not >=) |
| NHI-DEL-5 | Revoked link is not effective | A deactivated link is never effective regardless of agent matching, parse status, or expiry |
| NHI-DEL-6 | Chain stops at inactive link | An inactive link at position `k` prevents chain traversal beyond `k` |
| NHI-DEL-7 | Revocation completeness | Deactivating any link between root and leaf disconnects the leaf from the root in any chain traversal |
| NHI-DEL-8 | Liveness witness | A fully-active, fully-matched, fully-unexpired chain is traversable (revocation is not vacuously true) |

Verification result: **19 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_revoked_identity_is_terminal` | A revoked identity is always terminal regardless of expiry |
| `lemma_expired_identity_is_terminal` | An expired identity is always terminal regardless of revocation |
| `lemma_active_identity_is_not_terminal` | A non-revoked, non-expired identity is not terminal |
| `lemma_terminal_identity_cannot_delegate` | Terminal state implies delegation is blocked |
| `lemma_effective_link_requires_parse_success` | An unparseable expiry timestamp always fails the link-effective guard (fail-closed) |
| `lemma_effective_link_requires_active_and_unexpired` | Inactive or expired links are not effective |
| `lemma_depth_exceeded_is_strict` | Depth at exactly the bound does not exceed; depth at bound+1 does |
| `lemma_revoked_link_is_not_effective` | An inactive link is never effective (chain-level revocation primitive) |
| `lemma_chain_stops_at_inactive_link` | Chain traversal cannot advance past an inactive link |
| `lemma_revocation_disconnects_leaf` | Revoking any link disconnects all downstream agents (inductive proof over chain depth) |
| `lemma_all_active_chain_is_traversable` | An all-active chain is traversable to its full depth (liveness) |

### Safety-Critical Refinement (`verified_refinement_safety.rs`) — 16 verified items

Mechanizes the three safety-critical simulation obligations from the
policy engine refinement map (`formal/refinement/MCPPolicyEngine.md`).
These are the transitions where an incorrect implementation would be
fail-open.

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| R-MCP-START-EMPTY | Empty policy set → Deny | An empty policy set always produces a Deny verdict (fail-closed initialization) |
| R-MCP-APPLY-DENY | Deny contribution → Deny verdict | A Deny contribution at the first matching policy guarantees a Deny final verdict |
| R-MCP-EXHAUSTED-NOMATCH | No match → Deny | Exhausting all policies without a match always produces a Deny verdict |

Verification result: **16 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_empty_policies_fail_closed` | Empty policy set always produces Deny |
| `lemma_exhausted_no_match_fail_closed` | No matching policy always produces Deny |
| `lemma_deny_contribution_is_deny` | A Deny trace match has Deny verdict contribution |
| `lemma_no_policy_match_always_denies` | Composition: both empty and exhausted cases produce Deny |
| `lemma_deny_never_becomes_allow` | Deny contribution is never Allow (verdict stability) |
| `lemma_verdict_is_total` | Every verdict is Allow, Deny, or RequireApproval (exhaustiveness) |
| `lemma_allow_is_reachable` | Allow is reachable (safety proofs are not vacuous) |

### Entropy Alert Gate (`verified_entropy_gate.rs`) — 13 verified items, ENT-GATE-1–ENT-GATE-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| ENT-GATE-1 | Fixed-point threshold comparison | `is_high_entropy_millibits(obs, thresh)` iff `obs >= thresh` |
| ENT-GATE-2 | Alert count threshold | Entropy alert activates iff `high_entropy_count >= min_entropy_observations` |
| ENT-GATE-3 | Saturating high-severity threshold | Doubling the minimum observation count saturates at `u32::MAX` |
| ENT-GATE-4 | Severity tier mapping | Counts at or above the doubled threshold map to `High`, otherwise `Medium` |
| ENT-GATE-5 | Optional alert severity | `entropy_alert_severity` returns `None` below threshold and `Some(level)` otherwise |

Verification result: **13 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_no_alert_below_threshold` | Counts below the alert threshold can never yield an entropy alert |
| `lemma_threshold_alerts_medium` | In the non-saturating range, hitting the exact threshold yields `Medium` severity |
| `lemma_high_severity_threshold_alerts_high` | Hitting the saturated high-severity threshold always yields `High` |

### Path Normalization (`verified_path.rs`) — 33 verified items; V9-V10 fully proved

Current status for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| V9 | Idempotence | Fully proved: `normalize(normalize(x)) = normalize(x)` |
| V10 | No traversal in output | Fully proved: normalized output never contains `..` component |

Verification result: **33 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

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

### DLP Buffer Arithmetic (`verified_dlp_core.rs`) — 16 proofs, D1-D6

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| D1 | UTF-8 char boundary safety | `extract_tail` never returns start in mid-character |
| D2 | Single buffer size bounded | Extracted tail never exceeds `max_size` bytes |
| D3 | Total byte accounting correct | `update_total_bytes` maintains consistency |
| D4 | Capacity check fail-closed | At `max_fields`, `can_track_field` returns false |
| D5 | No arithmetic underflow | Saturating subtraction prevents wrapping |
| D6 | Overlap completeness | Secret <= 2 * overlap split at `split_point <= overlap_size` fully covered (first fragment must fit in tail buffer) |

Verification result: **16 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_continuation_not_boundary` | Continuation bytes (0x80-0xBF) are NOT char boundaries (bit_vector) |
| `lemma_non_continuation_is_boundary` | Non-continuation bytes are char boundaries (bit_vector) |
| `overlap_completeness_lemma` | Combined scan buffer covers entire split secret |
| `lemma_capacity_fail_closed` | At max_fields, can_track_field is always false |
| `lemma_ascii_all_boundaries` | For ASCII input, all bytes are char boundaries |

### Cross-Call DLP Tracker Gate (`verified_cross_call_dlp.rs`) — 11 verified items, CC-DLP-1–CC-DLP-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CC-DLP-1 | Existing field never emits capacity finding | Capacity-exhausted synthetic findings only apply to new fields |
| CC-DLP-2 | Existing field always updates | Existing tracked fields keep overlap coverage even when the tracker is at field capacity |
| CC-DLP-3 | New field at capacity blocks update | A new field at or above `max_fields` cannot enter the overlap tracker |
| CC-DLP-4 | New field below capacity with budget updates | A new field is admitted only when both field-count and byte-budget gates pass |
| CC-DLP-5 | Capacity finding implies update blocked | For new fields, the synthetic fail-closed finding and update denial stay aligned |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

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
| `formal/verus/verified_audit_append.rs` | `vellaveto-audit/src/verified_audit_append.rs` | `logger.rs` routes rotation reset and counter updates through the verified append kernel, while `rotation.rs` routes restart recovery through the verified next-sequence helper |
| `formal/verus/verified_audit_chain.rs` | `vellaveto-audit/src/verified_audit_chain.rs` | `verification.rs` routes timestamp, sequence, hash-presence, and hashed-step validation through the verified audit-chain kernel |
| `formal/verus/verified_merkle.rs` | `vellaveto-audit/src/verified_merkle.rs` | `merkle.rs` routes append capacity, initialization replay bounds, and proof shape validation through the verified Merkle kernel |
| `formal/verus/verified_merkle_fold.rs` | `vellaveto-audit/src/verified_merkle_fold.rs` | `merkle.rs` routes next-level construction, proof-step folding, and peak folding through the verified Merkle fold kernel |
| `formal/verus/verified_merkle_path.rs` | `vellaveto-audit/src/verified_merkle_path.rs` | `merkle.rs` routes sibling presence, sibling index selection, `is_left` encoding, parent ascent, and verifier concatenation direction through the verified proof-path kernel |
| `formal/verus/verified_rotation_manifest.rs` | `vellaveto-audit/src/verified_rotation_manifest.rs` | `rotation.rs` routes cross-rotation start-hash linkage, rotated filename safety, and the missing-file prune boundary through the verified manifest kernel |
| `formal/verus/verified_capability_attenuation.rs` | `vellaveto-mcp/src/verified_capability_attenuation.rs` | `capability_token.rs` routes remaining-depth decrement and expiry clamping through the verified arithmetic gate |
| `formal/verus/verified_capability_glob.rs` | `vellaveto-mcp/src/verified_capability_glob.rs` | `capability_token.rs` routes the literal-child parent-glob subset branch through the verified recursive matcher |
| `formal/verus/verified_capability_grant.rs` | `vellaveto-mcp/src/verified_capability_grant.rs` | `capability_token.rs` routes required restriction-shape and `max_invocations` attenuation through the verified grant gate |
| `formal/verus/verified_capability_literal.rs` | `vellaveto-mcp/src/verified_capability_literal.rs` | `capability_token.rs` routes literal pattern equality and literal-child subset fallthrough through the verified literal gate |
| `formal/verus/verified_capability_pattern.rs` | `vellaveto-mcp/src/verified_capability_pattern.rs` | `capability_token.rs` routes child-glob metacharacter rejection through the verified pattern guard |
| `formal/verus/verified_capability_identity.rs` | `vellaveto-mcp/src/verified_capability_identity.rs` | `capability_token.rs` routes self-delegation rejection, delegated-child issuer-link validation, and holder-expectation checks through the verified identity-chain gate |
| `formal/verus/verified_nhi_delegation.rs` | `vellaveto-mcp/src/verified_nhi_delegation.rs` | `nhi.rs` routes terminal-state detection, delegation participant guards, link-effective checks, and chain-depth bounds through the verified NHI delegation gate |
| `formal/verus/verified_entropy_gate.rs` | `vellaveto-engine/src/verified_entropy_gate.rs` | `entropy_gate.rs` converts `f64` telemetry to millibits, then `collusion.rs` uses the verified integer gate |
| `formal/verus/verified_cross_call_dlp.rs` | `vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs` | `cross_call_dlp.rs` routes the synthetic capacity finding and overlap-buffer update decision through the verified gate |
| `formal/verus/verified_dlp_core.rs` | `vellaveto-mcp/src/inspection/verified_dlp_core.rs` | Called by `CrossCallDlpTracker::update_buffer()` |
| `formal/verus/verified_path.rs` | `vellaveto-engine/src/path.rs` | Byte-level equivalent of `normalize_decoded_path`, called by `normalize_path_bounded()` after decode/backslash normalization |
| `formal/verus/Cargo.toml` and `formal/verus/src/lib.rs` | `formal/tools/verify-verus.sh` | Canonical `cargo-verus` manifest and shim for running the full standalone Verus suite through one entrypoint |
| `formal/verus/assumptions.rs` | `formal/ASSUMPTION_REGISTRY.md` | Shared Verus-facing kernel-assumption map for the canonical trust-boundary registry |
| `formal/verus/merkle_boundary_axioms.rs` | `formal/MERKLE_TRUST_BOUNDARY.md` and `vellaveto-audit/src/trusted_merkle_hash.rs` | Trusted proof-facing Merkle hash/codec axiom surface used by the shared assumptions layer |
| `formal/verus/audit_fs_boundary_axioms.rs` | `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` and `vellaveto-audit/src/trusted_audit_fs.rs` | Trusted proof-facing audit-filesystem axiom surface used by the shared assumptions layer |

The executable logic is semantically equivalent — Verus annotations (`ensures`,
`requires`, `invariant`, `decreases`, `proof fn`) are erased during normal
compilation. Minor syntactic differences exist (e.g., `len() == 0` vs
`.is_empty()`, `&Vec<T>` vs `&[T]`) but are operationally identical.

## How to Verify

```bash
# Option 0: Docker (reproducible, no local setup)
make formal-docker                    # Full mesh (all tools)
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-verus  # Verus only
```

```bash
# Option 1: Binary release (recommended)
VERUS_VERSION="0.2026.03.01.25809cb"
curl -sSL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip"
unzip verus.zip -d verus-bin
rustup install 1.93.1-x86_64-unknown-linux-gnu
chmod +x verus-bin/verus-x86-linux/verus verus-bin/verus-x86-linux/cargo-verus

# Canonical full-suite entrypoint
# Requires normal Cargo registry access for the pinned Verus crates.
verus-bin/verus-x86-linux/cargo-verus verify --manifest-path formal/verus/Cargo.toml -- --triggers-mode silent

# Audit append/recovery counter transitions (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_audit_append.rs

# Audit-chain verification guard (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_audit_chain.rs

# Merkle append/init/proof-shape fail-closed guards (23 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle.rs

# Merkle next-level/proof-fold/peak-fold structure (17 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle_fold.rs

# Merkle proof sibling/orientation/parent structure (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle_path.rs

# Cross-rotation manifest linkage/path-safety guards (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_rotation_manifest.rs

# Capability attenuation depth/expiry kernel (13 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_attenuation.rs

# Capability parent-glob literal-child matcher (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_glob.rs

# Capability grant restriction/invocation kernel (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_grant.rs

# Capability literal fast paths (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_literal.rs

# Capability child-glob rejection guard (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_pattern.rs

# Capability holder/issuer identity-chain guards (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_identity.rs

# NHI delegation terminal-state/participant/link/depth guards (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_nhi_delegation.rs

# Constraint evaluation fail-closed control flow (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_constraint_eval.rs

# Core verdict + rule override (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# Fixed-point entropy alert gate (13 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_entropy_gate.rs

# Cross-call DLP tracker gate (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_cross_call_dlp.rs

# DLP buffer arithmetic (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs

# Path normalization no-traversal (33 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_path.rs

# Option 2: From source
git clone https://github.com/verus-lang/verus
cd verus && ./tools/get-z3.sh && source ./tools/activate
cargo build --release
verus formal/verus/verified_audit_append.rs
verus formal/verus/verified_audit_chain.rs
verus formal/verus/verified_merkle.rs
verus formal/verus/verified_merkle_fold.rs
verus formal/verus/verified_merkle_path.rs
verus formal/verus/verified_rotation_manifest.rs
verus formal/verus/verified_capability_attenuation.rs
verus formal/verus/verified_capability_glob.rs
verus formal/verus/verified_capability_grant.rs
verus formal/verus/verified_capability_literal.rs
verus formal/verus/verified_capability_pattern.rs
verus formal/verus/verified_capability_identity.rs
verus formal/verus/verified_nhi_delegation.rs
verus formal/verus/verified_constraint_eval.rs
verus formal/verus/verified_core.rs
verus formal/verus/verified_entropy_gate.rs
verus formal/verus/verified_cross_call_dlp.rs
verus formal/verus/verified_dlp_core.rs
verus formal/verus/verified_path.rs
```

Expected output:
- `verified_audit_append.rs`: `verification results:: 19 verified, 0 errors`
- `verified_audit_chain.rs`: `verification results:: 19 verified, 0 errors`
- `verified_merkle.rs`: `verification results:: 23 verified, 0 errors`
- `verified_merkle_fold.rs`: `verification results:: 17 verified, 0 errors`
- `verified_merkle_path.rs`: `verification results:: 15 verified, 0 errors`
- `verified_rotation_manifest.rs`: `verification results:: 16 verified, 0 errors`
- `verified_capability_attenuation.rs`: `verification results:: 13 verified, 0 errors`
- `verified_capability_glob.rs`: `verification results:: 19 verified, 0 errors`
- `verified_capability_grant.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_literal.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_pattern.rs`: `verification results:: 12 verified, 0 errors`
- `verified_capability_identity.rs`: `verification results:: 11 verified, 0 errors`
- `verified_nhi_delegation.rs`: `verification results:: 14 verified, 0 errors`
- `verified_constraint_eval.rs`: `verification results:: 14 verified, 0 errors`
- `verified_core.rs`: `verification results:: 14 verified, 0 errors`
- `verified_entropy_gate.rs`: `verification results:: 13 verified, 0 errors`
- `verified_cross_call_dlp.rs`: `verification results:: 11 verified, 0 errors`
- `verified_dlp_core.rs`: `verification results:: 16 verified, 0 errors`
- `verified_path.rs`: `verification results:: 33 verified, 0 errors`

## Trust Boundary

See `docs/TRUSTED_COMPUTING_BASE.md` Section 5 for the full trust model.

Verus trusts:
- Z3 SMT solver (Microsoft Research)
- Verus verifier (translation from Rust+specs to Z3 queries)
- rustc codegen (LLVM)

Verus does NOT verify:
- Cryptographic collision resistance, full Merkle root/proof correctness, or filesystem append/durability semantics for the audit chain / Merkle layers
- The `HashMap` wrapper in `cross_call_dlp.rs` beyond the extracted field-capacity/update gate
- Full pattern-language containment in `capability_token.rs` (literal/glob matching and path/domain coverage still rely on runtime checks and tests)
- String operations, glob/regex matching, Unicode normalization
- HashMap, serde, I/O

The `ResolvedMatch` construction equivalence is now verified by Kani (K46-K48).
Other gaps are covered by Kani (bounded) and 10,000+ tests.
