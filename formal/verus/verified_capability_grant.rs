// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability grant attenuation kernel.
//!
//! This file proves the pure restriction-shape and `max_invocations`
//! attenuation checks extracted into `vellaveto-mcp/src/verified_capability_grant.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_grant.rs`

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_required_restrictions_preserved(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
) -> bool {
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
}

pub open spec fn spec_max_invocations_attenuated(
    parent_max_invocations: nat,
    child_max_invocations: nat,
) -> bool {
    parent_max_invocations == 0
        || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations)
}

pub open spec fn spec_grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: nat,
    child_max_invocations: nat,
) -> bool {
    spec_required_restrictions_preserved(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
    ) && spec_max_invocations_attenuated(parent_max_invocations, child_max_invocations)
}

pub fn grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: u64,
    child_max_invocations: u64,
) -> (result: bool)
    ensures
        result == spec_grant_restrictions_attenuated(
            parent_has_allowed_paths,
            child_has_allowed_paths,
            parent_has_allowed_domains,
            child_has_allowed_domains,
            parent_max_invocations as nat,
            child_max_invocations as nat,
        ),
{
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
        && (parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations))
}

pub proof fn lemma_path_restrictions_cannot_be_dropped(
    child_has_allowed_domains: bool,
    parent_max_invocations: nat,
    child_max_invocations: nat,
)
    ensures !spec_grant_restrictions_attenuated(
        true,
        false,
        false,
        child_has_allowed_domains,
        parent_max_invocations,
        child_max_invocations,
    ),
{
}

pub proof fn lemma_domain_restrictions_cannot_be_dropped(
    child_has_allowed_paths: bool,
    parent_max_invocations: nat,
    child_max_invocations: nat,
)
    ensures !spec_grant_restrictions_attenuated(
        false,
        child_has_allowed_paths,
        true,
        false,
        parent_max_invocations,
        child_max_invocations,
    ),
{
}

pub proof fn lemma_limited_parent_rejects_unlimited_child(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: nat,
)
    requires parent_max_invocations > 0,
    ensures !spec_grant_restrictions_attenuated(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
        parent_max_invocations,
        0,
    ),
{
}

pub proof fn lemma_limited_parent_rejects_larger_child_limit(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: nat,
    child_max_invocations: nat,
)
    requires
        parent_max_invocations > 0,
        child_max_invocations > parent_max_invocations,
    ensures !spec_grant_restrictions_attenuated(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
        parent_max_invocations,
        child_max_invocations,
    ),
{
}

pub proof fn lemma_limited_parent_accepts_smaller_child_limit(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: nat,
    child_max_invocations: nat,
)
    requires
        spec_required_restrictions_preserved(
            parent_has_allowed_paths,
            child_has_allowed_paths,
            parent_has_allowed_domains,
            child_has_allowed_domains,
        ),
        parent_max_invocations > 0,
        child_max_invocations > 0,
        child_max_invocations <= parent_max_invocations,
    ensures spec_grant_restrictions_attenuated(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
        parent_max_invocations,
        child_max_invocations,
    ),
{
}

pub proof fn lemma_unlimited_parent_leaves_only_shape_checks(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    child_max_invocations: nat,
)
    ensures spec_grant_restrictions_attenuated(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
        0,
        child_max_invocations,
    ) == spec_required_restrictions_preserved(
        parent_has_allowed_paths,
        child_has_allowed_paths,
        parent_has_allowed_domains,
        child_has_allowed_domains,
    ),
{
}

fn main() {}

} // verus!
