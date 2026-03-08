// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified transport-trust projection for sensitive context fields.
//!
//! This file proves the extracted predicates in
//! `vellaveto-types/src/verified_transport_context.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_transport_context.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_trusted_transport_preserves_agent_identity(
    transport_trusted: bool,
    identity_present: bool,
) -> bool {
    transport_trusted && identity_present
}

pub fn trusted_transport_preserves_agent_identity(
    transport_trusted: bool,
    identity_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_trusted_transport_preserves_agent_identity(
                transport_trusted,
                identity_present,
            ),
        !transport_trusted ==> !result,
        transport_trusted && identity_present ==> result,
        !identity_present ==> !result,
{
    transport_trusted && identity_present
}

pub open spec fn spec_trusted_transport_preserves_capability_token(
    transport_trusted: bool,
    capability_token_present: bool,
) -> bool {
    transport_trusted && capability_token_present
}

pub fn trusted_transport_preserves_capability_token(
    transport_trusted: bool,
    capability_token_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_trusted_transport_preserves_capability_token(
                transport_trusted,
                capability_token_present,
            ),
        !transport_trusted ==> !result,
        transport_trusted && capability_token_present ==> result,
        !capability_token_present ==> !result,
{
    transport_trusted && capability_token_present
}

pub fn project_agent_identity_from_transport(
    transport_trusted: bool,
    identity_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_trusted_transport_preserves_agent_identity(
                transport_trusted,
                identity_present,
            ),
{
    trusted_transport_preserves_agent_identity(transport_trusted, identity_present)
}

pub fn project_capability_token_from_transport(
    transport_trusted: bool,
    capability_token_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_trusted_transport_preserves_capability_token(
                transport_trusted,
                capability_token_present,
            ),
{
    trusted_transport_preserves_capability_token(
        transport_trusted,
        capability_token_present,
    )
}

pub proof fn lemma_untrusted_transport_strips_sensitive_fields(
    identity_present: bool,
    capability_token_present: bool,
)
    ensures
        !spec_trusted_transport_preserves_agent_identity(false, identity_present),
        !spec_trusted_transport_preserves_capability_token(false, capability_token_present),
{
}

pub proof fn lemma_trusted_transport_preserves_present_sensitive_fields()
    ensures
        spec_trusted_transport_preserves_agent_identity(true, true),
        spec_trusted_transport_preserves_capability_token(true, true),
{
}

pub proof fn lemma_absent_sensitive_fields_remain_absent_when_projected(transport_trusted: bool)
    ensures
        !spec_trusted_transport_preserves_agent_identity(transport_trusted, false),
        !spec_trusted_transport_preserves_capability_token(transport_trusted, false),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::transport_context_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
