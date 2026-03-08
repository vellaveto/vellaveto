# Verus Formal Verification

Deductive verification of Vellaveto's core verdict computation, constraint
evaluation fail-closed control flow, audit append/recovery counter transitions,
audit-chain verification guards, Merkle append/init/proof-shape guards,
Merkle fold structure, Merkle proof-path structure, cross-rotation
manifest linkage/path-safety guards, capability attenuation arithmetic,
combined deputy/capability context guards,
stdio bridge principal-binding guards,
post-deputy evaluation-principal handoff guards,
capability parent-glob literal-child matching,
capability exact parent-glob/child-glob subset checking,
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

### Capability Grant-Coverage Gate (`verified_capability_coverage.rs`) — 10 verified items, CAP-COV-1–CAP-COV-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-COV-1 | Missing path targets fail closed | If a grant restricts paths but the action has no `target_paths`, coverage fails |
| CAP-COV-2 | Uncovered path targets fail closed | If any required path target is uncovered after normalization/matching, coverage fails |
| CAP-COV-3 | Missing domain targets fail closed | If a grant restricts domains but the action has no `target_domains`, coverage fails |
| CAP-COV-4 | Uncovered domain targets fail closed | If any required domain target is uncovered, coverage fails |
| CAP-COV-5 | Absent restrictions impose no requirement | If the grant does not restrict a dimension, that dimension cannot block coverage |

Verification result: **10 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_missing_paths_fail_closed` | Missing `target_paths` always deny a path-restricted grant |
| `lemma_uncovered_paths_fail_closed` | Uncovered path targets always deny a path-restricted grant |
| `lemma_missing_domains_fail_closed` | Missing `target_domains` always deny a domain-restricted grant |
| `lemma_uncovered_domains_fail_closed` | Uncovered domain targets always deny a domain-restricted grant |
| `lemma_satisfied_restrictions_are_allowed` | Fully satisfied path/domain restrictions are accepted |
| `lemma_absent_restrictions_impose_no_requirement` | Unrestricted dimensions are ignored by the gate |

### Capability Domain Kernel (`verified_capability_domain.rs`) — 16 verified items, CAP-DOM-1–CAP-DOM-6

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-DOM-1 | Exact domain shape stays valid | An exact domain pattern with no metacharacters is accepted by the shape gate |
| CAP-DOM-2 | Wildcard domains require a suffix | A `*.` pattern with no domain after the wildcard label is rejected |
| CAP-DOM-3 | Unsupported metacharacters fail closed | Interior `*` or any `?` metacharacter makes the pattern invalid |
| CAP-DOM-4 | Normalized suffix match requires exact equality or `.` boundary | Wildcard suffix matching only succeeds on the exact suffix or a real subdomain boundary |
| CAP-DOM-5 | Wildcard matching routes through suffix containment | After normalization, wildcard domain matching is exactly suffix containment |
| CAP-DOM-6 | Exact parents cannot be widened by wildcard children | An exact parent domain pattern can only accept an equal exact child pattern |

Verification result: **16 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_exact_domain_pattern_shape_is_valid` | Plain exact-domain patterns are accepted by the shape gate |
| `lemma_wildcard_domain_pattern_requires_non_empty_suffix` | `*.` without a suffix is rejected while `*.suffix` is allowed |
| `lemma_other_metacharacters_fail_closed` | Interior wildcard/question-mark metacharacters invalidate the pattern |
| `lemma_suffix_match_accepts_exact_or_dot_boundary` | Suffix matching only accepts exact equality or a real subdomain boundary |
| `lemma_exact_patterns_require_exact_domain_match` | Exact patterns route matching to exact normalized equality |
| `lemma_wildcard_patterns_route_to_suffix_match` | Wildcard patterns route matching to normalized suffix containment |
| `lemma_exact_parent_rejects_child_wildcards` | Exact parents never accept wildcard child patterns in subset checking |
| `lemma_exact_parent_accepts_only_exact_equal_child` | Exact-parent subset acceptance requires an equal exact child |
| `lemma_wildcard_parent_accepts_matching_exact_or_wildcard_child` | Wildcard parents accept only children whose normalized suffix stays contained |

### Capability Grant Selection (`verified_capability_selection.rs`) — 8 verified items, CAP-SEL-1–CAP-SEL-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-SEL-1 | Non-match keeps no selection | With no prior selection, a non-covering grant leaves the selected index empty |
| CAP-SEL-2 | First match selects current grant | With no prior selection, the first covering grant selects its current index |
| CAP-SEL-3 | Existing selection survives later non-matches | Once selected, later non-covering grants cannot clear the index |
| CAP-SEL-4 | First match wins | Once selected, later covering grants cannot replace the earlier index |

Verification result: **8 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_non_matching_grant_keeps_none` | A non-covering grant cannot create a selection when none exists |
| `lemma_first_matching_grant_is_selected` | The first covering grant selects its current index |
| `lemma_existing_selection_is_preserved` | A previously selected index is preserved regardless of the current grant result |
| `lemma_selected_index_never_moves_forward` | The selected index cannot advance to a later matching grant |

### Capability Grant Path Kernel (`verified_capability_path.rs`) — 9 verified items, CAP-PATH-1–CAP-PATH-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-PATH-1 | Empty/dot component is a no-op | Empty and `.` path components preserve the current normalized depth |
| CAP-PATH-2 | Above-root traversal fails closed | A `..` component at depth zero rejects normalization |
| CAP-PATH-3 | Non-root parent traversal pops exactly one level | A `..` component below root decreases normalized depth by one |
| CAP-PATH-4 | Literal component increments depth | A non-special component increases normalized depth by one |
| CAP-PATH-5 | Depth overflow fails closed | Impossible component-depth overflow rejects normalization |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_empty_or_dot_component_keeps_depth` | Empty and `.`-style components preserve the current depth |
| `lemma_dotdot_at_root_fails_closed` | `..` at root denies normalization |
| `lemma_dotdot_below_root_pops` | `..` below root decrements the depth exactly once |
| `lemma_literal_component_pushes_when_bounded` | A normal component increments depth when not at the maximum |
| `lemma_literal_component_overflow_fails_closed` | Impossible depth overflow is rejected fail-closed |

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

### Capability Glob-Subset Kernel (`verified_capability_glob_subset.rs`) — 11 verified items, CAP-GSUB-1–CAP-GSUB-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-GSUB-1 | Accepting-counterexample predicate | The subset search rejects exactly when a child-accepting / parent-rejecting state pair is found |
| CAP-GSUB-2 | Fast-path routing | Wildcard/equality short-circuit to `true`, literal children route to the literal subset branch, and remaining child-glob cases route to the exact subset branch |
| CAP-GSUB-3 | Representative “other byte” condition | The representative alphabet model needs an extra “other” byte iff the literal classes do not already cover all 256 byte values |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_counterexample_requires_child_acceptance` | A rejecting counterexample must come from a child-accepting / parent-rejecting pair |
| `lemma_fast_path_accepts_wildcard_or_equality` | Wildcard parents and exact equality always short-circuit to acceptance |
| `lemma_fast_path_routes_literal_children` | Literal children route to the literal subset result |
| `lemma_fast_path_routes_child_globs` | Non-identical child globs route to the exact subset result |
| `lemma_other_byte_needed_below_full_alphabet` | The representative-alphabet model only needs an extra “other” byte below full literal-class coverage |

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

### Capability Pattern Fast-Path Guard (`verified_capability_pattern.rs`) — 12 verified items, CAP-PAT-1–CAP-PAT-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-PAT-1 | Metacharacter detection | `has_glob_metacharacters` precisely detects `*` and `?` bytes |
| CAP-PAT-2 | Non-identical child glob bypasses fast path | A differing child glob does not take the wildcard/equality/literal fast path |
| CAP-PAT-3 | Wildcard/equality fast path | Wildcard parents and identical patterns always pass the guard |
| CAP-PAT-4 | Literal-child fallthrough | Literal children always fall through to the runtime matcher instead of being rejected by the guard |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_non_identical_child_glob_rejected` | A differing child glob cannot be accepted by the fast-path guard |
| `lemma_wildcard_parent_allows_child_glob` | A wildcard parent cannot be blocked by the guard |
| `lemma_identical_child_glob_allowed` | Exact equality bypasses the exact-subset branch and stays in the fast path |
| `lemma_literal_child_falls_through` | Literal child patterns stay in the fast path instead of routing to the exact subset branch |
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

### Capability Verification Precheck Guards (`verified_capability_verification.rs`) — 15 verified items, CAP-VER-1–CAP-VER-5

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-VER-1 | Expiry fail-closed | Verification passes the temporal expiry gate iff `now < expires` |
| CAP-VER-2 | Future-issued-at skew bound | Verification accepts future `issued_at` values only when `skew <= max_skew` |
| CAP-VER-3 | Expected-key identity | The expected issuer-public-key gate passes iff the caller's equality check says the keys match |
| CAP-VER-4 | Public-key length exactness | The decoded issuer public key is accepted iff it is exactly 32 bytes |
| CAP-VER-5 | Signature length exactness | The decoded signature is accepted iff it is exactly 64 bytes |

Verification result: **15 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_expired_tokens_are_rejected` | An elapsed expiry window always fails the verification gate |
| `lemma_unexpired_tokens_are_allowed` | A still-valid expiry window passes the verification gate |
| `lemma_future_issued_at_beyond_skew_is_rejected` | Future-issued tokens beyond the configured skew are rejected |
| `lemma_issued_at_within_skew_is_allowed` | Issued-at values within the configured skew remain admissible |
| `lemma_public_key_expectation_is_identity` | The expected-key guard is exactly the caller-supplied equality bit |
| `lemma_public_key_length_must_match_exactly` | Only 32-byte decoded public keys satisfy the length gate |
| `lemma_signature_length_must_match_exactly` | Only 64-byte decoded signatures satisfy the length gate |

### Capability Context Guards (`verified_capability_context.rs`) — 12 verified items, CAP-CTX-1–CAP-CTX-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-CTX-1 | Holder binding fail-closed | Capability-token authorization passes only when an agent is present and the normalized token holder matches that agent |
| CAP-CTX-2 | Issuer allowlist guard | Issuer checks pass iff the allowlist is empty or the normalized issuer is in the configured allowlist |
| CAP-CTX-3 | Remaining-depth threshold | Capability-token depth checks pass iff `remaining_depth >= min_remaining_depth` |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_missing_agent_fails_closed` | Missing `agent_id` always blocks holder binding |
| `lemma_holder_binding_requires_match` | A present agent still fails unless the normalized holder matches |
| `lemma_empty_issuer_allowlist_allows_any_issuer` | An empty issuer allowlist is non-restrictive |
| `lemma_nonempty_issuer_allowlist_requires_membership` | A non-empty issuer allowlist rejects absent issuer membership |
| `lemma_depth_threshold_is_inclusive` | Depth exactly at the policy threshold is accepted |
| `lemma_depth_below_threshold_fails_closed` | Any depth strictly below the threshold is rejected |

### Context Delegation Guards (`verified_context_delegation.rs`) — 11 verified items, CTX-DEP-1–CTX-DEP-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CTX-DEP-1 | Principal presence aggregation | The engine treats an attested identity or a legacy `agent_id` as sufficient principal presence |
| CTX-DEP-2 | Required-principal fail-closed | `deputy_validation` denies when a principal is required but neither identity source is present |
| CTX-DEP-3 | Call-chain depth bound is inclusive | `max_chain_depth` allows `len == max_depth` and denies only when `len > max_depth` |
| CTX-DEP-4 | Delegation depth bound is inclusive | `deputy_validation` allows `delegation_depth == max_delegation_depth` and denies only when `delegation_depth > max_delegation_depth` |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_missing_identity_sources_mean_no_principal` | If both identity sources are absent, no principal is present |
| `lemma_principal_requirement_fails_closed_without_principal` | Requiring a principal fails closed when none is present |
| `lemma_chain_depth_limit_is_inclusive` | `max_chain_depth` accepts the exact bound and zero |
| `lemma_delegation_depth_limit_is_inclusive` | `deputy_validation` accepts the exact bound and zero |

### Combined Delegated Capability Context Guards (`verified_capability_delegation_context.rs`) — 11 verified items, CAP-DEP-CTX-1–CAP-DEP-CTX-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| CAP-DEP-CTX-1 | Principal/holder conjunction | The combined delegated-capability precheck passes only when any required principal is present, a capability token exists, an `agent_id` exists, and the normalized token holder matches that agent |
| CAP-DEP-CTX-2 | Delegation/depth conjunction | The combined depth precheck passes only when deputy delegation depth is within the configured bound, a capability token exists, and the token's remaining depth meets the configured minimum |
| CAP-DEP-CTX-3 | Combined fail-closed context gate | The extracted combined gate is exactly the conjunction of the principal/holder guard, issuer allowlist guard, and delegation/remaining-depth guard |

Verification result: **11 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_missing_capability_token_fails_closed` | The combined delegated-capability gate always fails when the capability token is absent |
| `lemma_principal_requirement_and_holder_binding_are_conjoined` | The combined principal/holder guard implies both token presence and `agent_id`-backed holder binding |
| `lemma_issuer_allowlist_is_conjoined` | The combined issuer guard is exactly the configured allowlist-or-membership disjunction |
| `lemma_delegation_and_remaining_depth_bounds_are_conjoined` | The combined depth guard implies both deputy delegation-depth compliance and capability remaining-depth compliance |

### Stdio Bridge Principal-Binding Guards (`verified_bridge_principal.rs`) — 12 verified items, BRIDGE-PRINC-1–BRIDGE-PRINC-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| BRIDGE-PRINC-1 | Configured/claimed consistency | If both the configured session principal and per-message claim are present, they pass only when the caller's normalization pipeline says they match |
| BRIDGE-PRINC-2 | Deputy source preference | Deputy validation uses the configured principal when present, else the claimed principal, else no principal |
| BRIDGE-PRINC-3 | Evaluation source trust | Engine evaluation in stdio mode only populates `EvaluationContext.agent_id` from the configured session principal |
| BRIDGE-PRINC-4 | Configured-source alignment | When a configured session principal exists, deputy validation and engine evaluation both bind to that same trusted source |

Verification result: **12 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_mismatch_rejected_when_both_sources_present` | Two present principal sources cannot both pass unless normalization agrees |
| `lemma_missing_side_has_no_consistency_obligation` | An absent configured or claimed principal imposes no equality requirement |
| `lemma_deputy_prefers_configured_identity` | Deputy validation always prefers the configured source when present |
| `lemma_engine_only_trusts_configured_identity` | Engine evaluation never trusts a claimed-only principal |
| `lemma_configured_source_aligns_deputy_and_engine` | A configured session principal aligns both subsystems on the same trusted source |

### Delegation Projection Guards (`verified_delegation_projection.rs`) — 7 verified items, DEP-PROJ-1–DEP-PROJ-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| DEP-PROJ-1 | Inactive delegation projects empty chain | Without an active deputy-validated delegation context, the relay exposes a zero-length engine call chain |
| DEP-PROJ-2 | Active delegation preserves validated depth | With an active delegation context, the projected engine call-chain length exactly matches the deputy-reported delegation depth |
| DEP-PROJ-3 | Projected depth stays bounded | The projected call-chain length never exceeds the deputy depth domain (`u8::MAX`) |

Verification result: **7 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_inactive_delegation_projects_empty_chain` | Inactive delegation always projects an empty chain regardless of deputy-reported depth |
| `lemma_active_delegation_preserves_depth` | Active delegation preserves the exact deputy-reported depth |
| `lemma_projected_depth_is_bounded_by_u8_max` | Projection cannot exceed the `u8` deputy-depth domain |

### Deputy Handoff Guards (`verified_deputy_handoff.rs`) — 9 verified items, DEP-HANDOFF-1–DEP-HANDOFF-3

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| DEP-HANDOFF-1 | Active-delegation requirement | A claimed principal is only promoted after deputy validation when that claim was checked against an active server-side delegation context |
| DEP-HANDOFF-2 | Configured source dominance | A configured session principal remains authoritative even if a deputy-validated claim also exists |
| DEP-HANDOFF-3 | Validated-claim promotion | Without a configured session principal, a deputy-validated claim becomes the engine evaluation principal; otherwise evaluation stays anonymous |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_deputy_validated_claim_requires_active_delegation` | Active delegation and a present claim are both necessary before promotion can occur |
| `lemma_configured_source_dominates_validated_claim` | A configured session principal always wins over a deputy-validated claim |
| `lemma_validated_claim_promotes_only_without_configured_source` | A validated claim is promoted only when no configured session principal exists |

### Evaluation Context Projection Guards (`verified_evaluation_context_projection.rs`) — 9 verified items, EVAL-CTX-1–EVAL-CTX-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| EVAL-CTX-1 | Configured source dominance | A configured session principal always remains authoritative for engine evaluation, even if a deputy-validated claim also exists |
| EVAL-CTX-2 | Validated-claim promotion | Without a configured session principal, an active deputy-validated claim becomes the engine evaluation principal |
| EVAL-CTX-3 | Unvalidated-claim rejection | Without active delegation, a claimed principal never populates `EvaluationContext.agent_id` |
| EVAL-CTX-4 | Delegation-depth projection | The engine-visible synthetic call-chain length is exactly the active deputy delegation depth, else zero |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_configured_identity_dominates_claim_and_depth` | A configured principal always wins, while projection never exceeds deputy-reported depth |
| `lemma_validated_claim_only_promotes_with_active_delegation` | Claimed principals are promoted only when delegation is active |
| `lemma_inactive_delegation_projects_empty_chain` | Inactive delegation always projects an empty call chain |
| `lemma_active_delegation_preserves_depth` | Active delegation preserves the exact deputy-reported depth |

### Transport Context Projection Guards (`verified_transport_context.rs`) — 10 verified items, TCTX-1–TCTX-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| TCTX-1 | Untrusted identity stripping | An untrusted transport can never preserve a presented `agent_identity` |
| TCTX-2 | Untrusted token stripping | An untrusted transport can never preserve a presented `capability_token` |
| TCTX-3 | Trusted identity preservation | A trusted transport preserves `agent_identity` exactly when it is present |
| TCTX-4 | Trusted token preservation | A trusted transport preserves `capability_token` exactly when it is present |

Verification result: **10 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_untrusted_transport_strips_sensitive_fields` | Untrusted transports always strip both sensitive context fields fail-closed |
| `lemma_trusted_transport_preserves_present_sensitive_fields` | Trusted transports preserve present identity and capability-token fields |
| `lemma_absent_sensitive_fields_remain_absent_when_projected` | Missing sensitive fields stay absent regardless of transport trust |

### Approval Scope Binding Guards (`verified_approval_scope.rs`) — 9 verified items, APPR-SCOPE-1–APPR-SCOPE-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| APPR-SCOPE-1 | Bound session requires present match | If an approval is bound to a session, missing or mismatched request sessions fail closed |
| APPR-SCOPE-2 | Unbound session is non-blocking | If no session binding exists, the session dimension cannot reject the approval |
| APPR-SCOPE-3 | Bound fingerprint requires present match | If an approval is bound to an action fingerprint, missing or mismatched request fingerprints fail closed |
| APPR-SCOPE-4 | Combined scope is conjunctive | Any bound scope dimension that is absent or mismatched is sufficient to reject approval reuse |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_bound_session_binding_requires_present_match` | Session-scoped approvals only succeed when the request presents the exact bound session |
| `lemma_bound_fingerprint_binding_requires_present_match` | Fingerprint-scoped approvals only succeed when the request presents the exact bound fingerprint |
| `lemma_scope_requires_all_bound_dimensions` | Combined scope checking is fail-closed across both bound dimensions |

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

### Deputy Delegation Guards (`verified_deputy.rs`) — 15 verified items, DEPUTY-1–DEPUTY-6

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| DEPUTY-1 | Saturating depth increment | The next delegation depth is `current + 1` unless already at `u8::MAX`, where it saturates |
| DEPUTY-2 | Strict depth-limit guard | A delegation is allowed iff `new_depth <= max_depth` |
| DEPUTY-3 | Root delegation has no parent continuity obligation | Sessions without a current delegate may start a delegation chain |
| DEPUTY-4 | Re-delegation requires parent delegate continuity | Chained delegations are allowed only when the normalized `from` principal equals the current session delegate |
| DEPUTY-5 | Restricted parent scope blocks missing tools | A child may receive only tools already granted by the parent, unless the parent is unrestricted |
| DEPUTY-6 | Delegate and tool checks fail closed | Validation passes only when the claimed delegate matches and the requested tool is in scope (or the scope is unrestricted) |

Verification result: **15 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_depth_saturates_at_max` | Delegation depth increments from 0 to 1 and saturates at `u8::MAX` |
| `lemma_depth_limit_is_strict` | Depth at the bound is allowed, depth at bound+1 is rejected |
| `lemma_root_delegation_has_no_parent_principal_obligation` | First delegation in a session is not blocked by missing parent context |
| `lemma_redelegation_requires_parent_delegate_match` | Re-delegation with a mismatching parent delegate is always rejected |
| `lemma_restricted_parent_scope_blocks_missing_tool` | Restricted parents can only re-delegate tools already in scope |
| `lemma_delegated_principal_and_tool_guards_are_fail_closed` | Mismatching delegates and out-of-scope tools are rejected |

### NHI Delegation Graph Guards (`verified_nhi_graph.rs`) — 9 verified items, NHI-GRAPH-1–NHI-GRAPH-4

Properties proven for ALL possible inputs:

| ID | Property | Meaning |
|----|----------|---------|
| NHI-GRAPH-1 | Successor-link guard | A forward graph edge is live iff the source agent matches, the link is active, the expiry parsed, and now is before expiry |
| NHI-GRAPH-2 | Cycle-preservation guard | A new delegation edge is allowed iff no live back-path from delegatee to delegator already exists |
| NHI-GRAPH-3 | Live back-path closes a cycle | If a live path already leads from delegatee back to delegator, inserting a live edge from delegator to delegatee forms a cycle |
| NHI-GRAPH-4 | No live back-path preserves acyclicity | In the absence of a live back-path, the extracted insertion guard accepts the new edge |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

#### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_inactive_or_unparseable_successor_link_is_not_effective` | Inactive or unparseable-expiry edges are never live successors |
| `lemma_live_back_path_with_live_inserted_edge_forms_cycle` | A pre-existing live back-path plus a new live edge creates a delegation cycle |
| `lemma_no_live_back_path_preserves_acyclicity` | No live back-path means the cycle guard admits the insertion |

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
| `formal/verus/verified_capability_context.rs` | `vellaveto-engine/src/verified_capability_context.rs` | `context_check.rs` routes capability-token holder binding, issuer allowlist, and remaining-depth threshold checks through the verified engine gate |
| `formal/verus/verified_context_delegation.rs` | `vellaveto-engine/src/verified_context_delegation.rs` | `context_check.rs` routes principal presence, required-principal satisfaction, max-chain-depth, and delegation-depth checks through the verified context-delegation gate |
| `formal/verus/verified_capability_delegation_context.rs` | `vellaveto-engine/src/verified_capability_delegation_context.rs` | `context_check.rs` routes the exact-one deputy-validation + capability-token conjunction through the verified combined engine gate before the residual issuer allowlist check |
| `formal/verus/verified_bridge_principal.rs` | `vellaveto-mcp/src/verified_bridge_principal.rs` | `relay.rs` routes configured-vs-claimed consistency, deputy principal-source selection, and engine evaluation principal-source selection through the verified bridge gate |
| `formal/verus/verified_delegation_projection.rs` | `vellaveto-mcp/src/verified_delegation_projection.rs` | `verified_evaluation_context_projection.rs` routes deputy-validated delegation depth through the verified projection kernel before the relay populates `EvaluationContext.call_chain` |
| `formal/verus/verified_deputy_handoff.rs` | `vellaveto-mcp/src/verified_deputy_handoff.rs` | `verified_evaluation_context_projection.rs` routes deputy-validated claim promotion and post-deputy evaluation principal selection through the verified handoff gate before the relay consumes it |
| `formal/verus/verified_evaluation_context_projection.rs` | `vellaveto-mcp/src/verified_evaluation_context_projection.rs` | `relay.rs` routes engine-visible principal selection and synthetic delegation-depth projection through the combined verified evaluation-context gate |
| `formal/verus/verified_approval_scope.rs` | `vellaveto-approval/src/verified_approval_scope.rs` | `PendingApproval::scope_matches()` routes `session_id` and `action_fingerprint` through the shared fail-closed approval-scope gate before approval reuse decisions |
| `formal/verus/verified_transport_context.rs` | `vellaveto-types/src/verified_transport_context.rs` | `vellaveto-server/src/routes/main.rs` and `relay.rs` route `agent_identity` and `capability_token` through the shared fail-closed transport projection gate |
| `formal/verus/verified_capability_coverage.rs` | `vellaveto-mcp/src/verified_capability_coverage.rs` | `capability_token.rs` routes path/domain target-presence and all-targets-covered fail-closed decisions through the verified coverage gate |
| `formal/verus/verified_capability_domain.rs` | `vellaveto-mcp/src/verified_capability_domain.rs` | `capability_token.rs` routes `allowed_domains` coverage and subset checks through the verified domain normalization/matching/containment kernel |
| `formal/verus/verified_capability_path.rs` | `vellaveto-mcp/src/verified_capability_path.rs` | `capability_token.rs` routes grant/action path normalization through the extracted fail-closed path kernel |
| `formal/verus/verified_capability_selection.rs` | `vellaveto-mcp/src/verified_capability_selection.rs` | `capability_token.rs` routes first-match grant selection in `check_grant_coverage()` through the verified selection kernel |
| `formal/verus/verified_capability_glob.rs` | `vellaveto-mcp/src/verified_capability_glob.rs` | `capability_token.rs` routes both the runtime metachar matcher branch and the literal-child parent-glob subset branch through the verified recursive matcher |
| `formal/verus/verified_capability_glob_subset.rs` | `vellaveto-mcp/src/verified_capability_glob_subset.rs` | `capability_token.rs` routes the remaining child-glob branch through the exact subset kernel after the wildcard/equality/literal fast paths |
| `formal/verus/verified_capability_grant.rs` | `vellaveto-mcp/src/verified_capability_grant.rs` | `capability_token.rs` routes required restriction-shape and `max_invocations` attenuation through the verified grant gate |
| `formal/verus/verified_capability_literal.rs` | `vellaveto-mcp/src/verified_capability_literal.rs` | `capability_token.rs` routes literal pattern equality and literal-child subset fallthrough through the verified literal gate |
| `formal/verus/verified_capability_pattern.rs` | `vellaveto-mcp/src/verified_capability_pattern.rs` | `capability_token.rs` routes wildcard/equality/literal-child fast-path selection through the verified pattern guard |
| `formal/verus/verified_capability_identity.rs` | `vellaveto-mcp/src/verified_capability_identity.rs` | `capability_token.rs` routes self-delegation rejection, delegated-child issuer-link validation, and holder-expectation checks through the verified identity-chain gate |
| `formal/verus/verified_capability_verification.rs` | `vellaveto-mcp/src/verified_capability_verification.rs` | `capability_token.rs` routes expiry, future-issued-at skew, expected-key, and decoded key/signature length checks through the verified verification-precheck gate |
| `formal/verus/verified_deputy.rs` | `vellaveto-engine/src/verified_deputy.rs` | `deputy.rs` routes re-delegation depth, parent continuity, child tool-scope, delegate match, and tool-allowance checks through the verified deputy gate |
| `formal/verus/verified_nhi_delegation.rs` | `vellaveto-mcp/src/verified_nhi_delegation.rs` | `nhi.rs` routes terminal-state detection, delegation participant guards, link-effective checks, and chain-depth bounds through the verified NHI delegation gate |
| `formal/verus/verified_nhi_graph.rs` | `vellaveto-mcp/src/verified_nhi_graph.rs` | `nhi.rs` routes live successor-edge traversal and cycle-free edge insertion through the verified NHI graph gate |
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

# Engine call-chain/principal delegation guards (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_context_delegation.rs

# Engine combined deputy/capability context guard (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_delegation_context.rs

# Stdio bridge principal-binding alignment (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_bridge_principal.rs

# Deputy delegation-depth projection into engine call-chain length (7 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_delegation_projection.rs

# Deputy-validated claim promotion into engine evaluation (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_deputy_handoff.rs

# Combined relay projection into engine evaluation context (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_evaluation_context_projection.rs

# Shared approval scope binding gate (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_approval_scope.rs

# Shared fail-closed transport projection for sensitive context fields (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_transport_context.rs

# Capability grant-coverage path/domain restriction gate (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_coverage.rs

# Capability domain normalization/matching/subset gate (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_domain.rs

# Capability grant path fail-closed transition gate (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_path.rs

# Capability first-match selection gate (8 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_selection.rs

# Engine capability-token holder/issuer/depth guards (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_context.rs

# Capability parent-glob literal-child matcher (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_glob.rs

# Capability exact parent-glob/child-glob subset boundary (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_glob_subset.rs

# Capability grant restriction/invocation kernel (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_grant.rs

# Capability literal fast paths (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_literal.rs

# Capability subset fast-path guard (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_pattern.rs

# Capability holder/issuer identity-chain guards (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_identity.rs

# Capability verification temporal/expected-key/length guards (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_verification.rs

# Deputy chain continuity/depth/tool guards (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_deputy.rs

# NHI delegation terminal-state/participant/link/depth guards (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_nhi_delegation.rs

# NHI delegation live-successor/cycle-free insertion guards (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_nhi_graph.rs

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
verus formal/verus/verified_context_delegation.rs
verus formal/verus/verified_capability_delegation_context.rs
verus formal/verus/verified_bridge_principal.rs
verus formal/verus/verified_delegation_projection.rs
verus formal/verus/verified_deputy_handoff.rs
verus formal/verus/verified_evaluation_context_projection.rs
verus formal/verus/verified_approval_scope.rs
verus formal/verus/verified_transport_context.rs
verus formal/verus/verified_capability_coverage.rs
verus formal/verus/verified_capability_domain.rs
verus formal/verus/verified_capability_path.rs
verus formal/verus/verified_capability_selection.rs
verus formal/verus/verified_capability_context.rs
verus formal/verus/verified_capability_glob.rs
verus formal/verus/verified_capability_glob_subset.rs
verus formal/verus/verified_capability_grant.rs
verus formal/verus/verified_capability_literal.rs
verus formal/verus/verified_capability_pattern.rs
verus formal/verus/verified_capability_identity.rs
verus formal/verus/verified_capability_verification.rs
verus formal/verus/verified_deputy.rs
verus formal/verus/verified_nhi_delegation.rs
verus formal/verus/verified_nhi_graph.rs
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
- `verified_context_delegation.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_delegation_context.rs`: `verification results:: 11 verified, 0 errors`
- `verified_bridge_principal.rs`: `verification results:: 12 verified, 0 errors`
- `verified_delegation_projection.rs`: `verification results:: 7 verified, 0 errors`
- `verified_deputy_handoff.rs`: `verification results:: 9 verified, 0 errors`
- `verified_evaluation_context_projection.rs`: `verification results:: 9 verified, 0 errors`
- `verified_approval_scope.rs`: `verification results:: 9 verified, 0 errors`
- `verified_transport_context.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_coverage.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_domain.rs`: `verification results:: 16 verified, 0 errors`
- `verified_capability_path.rs`: `verification results:: 9 verified, 0 errors`
- `verified_capability_selection.rs`: `verification results:: 8 verified, 0 errors`
- `verified_capability_context.rs`: `verification results:: 12 verified, 0 errors`
- `verified_capability_glob.rs`: `verification results:: 19 verified, 0 errors`
- `verified_capability_glob_subset.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_grant.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_literal.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_pattern.rs`: `verification results:: 12 verified, 0 errors`
- `verified_capability_identity.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_verification.rs`: `verification results:: 15 verified, 0 errors`
- `verified_deputy.rs`: `verification results:: 15 verified, 0 errors`
- `verified_nhi_delegation.rs`: `verification results:: 19 verified, 0 errors`
- `verified_nhi_graph.rs`: `verification results:: 9 verified, 0 errors`
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
- Full string-level matcher semantics in `capability_token.rs` beyond the extracted literal/glob/path/domain kernels still rely on runtime checks and tests
- String operations, glob/regex matching, Unicode normalization
- HashMap, serde, I/O

The `ResolvedMatch` construction equivalence is now verified by Kani (K46-K48).
Other gaps are covered by Kani (bounded) and 10,000+ tests.
