// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability grant-coverage gate.
//!
//! This file proves the fail-closed path/domain restriction gate extracted into
//! `vellaveto-mcp/src/verified_capability_coverage.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_coverage.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_grant_restrictions_cover_action(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
) -> bool {
    (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
        && (!grant_has_allowed_domains || (action_has_target_domains && all_target_domains_covered))
}

pub fn grant_restrictions_cover_action(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
) -> (result: bool)
    ensures
        result == spec_grant_restrictions_cover_action(
            grant_has_allowed_paths,
            action_has_target_paths,
            all_target_paths_covered,
            grant_has_allowed_domains,
            action_has_target_domains,
            all_target_domains_covered,
        ),
{
    (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
        && (!grant_has_allowed_domains || (action_has_target_domains && all_target_domains_covered))
}

pub proof fn lemma_missing_paths_fail_closed(
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
)
    ensures
        !spec_grant_restrictions_cover_action(
            true,
            false,
            all_target_paths_covered,
            grant_has_allowed_domains,
            action_has_target_domains,
            all_target_domains_covered,
        ),
{
}

pub proof fn lemma_uncovered_paths_fail_closed(
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
)
    ensures
        !spec_grant_restrictions_cover_action(
            true,
            true,
            false,
            grant_has_allowed_domains,
            action_has_target_domains,
            all_target_domains_covered,
        ),
{
}

pub proof fn lemma_missing_domains_fail_closed(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    all_target_domains_covered: bool,
)
    ensures
        !spec_grant_restrictions_cover_action(
            grant_has_allowed_paths,
            action_has_target_paths,
            all_target_paths_covered,
            true,
            false,
            all_target_domains_covered,
        ),
{
}

pub proof fn lemma_uncovered_domains_fail_closed(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
)
    ensures
        !spec_grant_restrictions_cover_action(
            grant_has_allowed_paths,
            action_has_target_paths,
            all_target_paths_covered,
            true,
            true,
            false,
        ),
{
}

pub proof fn lemma_satisfied_restrictions_are_allowed()
    ensures
        spec_grant_restrictions_cover_action(true, true, true, false, false, false),
        spec_grant_restrictions_cover_action(false, false, false, true, true, true),
        spec_grant_restrictions_cover_action(true, true, true, true, true, true),
{
}

pub proof fn lemma_absent_restrictions_impose_no_requirement(
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
)
    ensures
        spec_grant_restrictions_cover_action(
            false,
            action_has_target_paths,
            all_target_paths_covered,
            false,
            action_has_target_domains,
            all_target_domains_covered,
        ),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_coverage_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
