// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified NHI delegation terminal-state, chain guards, and
//! revocation chain propagation.
//!
//! This file proves the extracted predicates in
//! `vellaveto-mcp/src/verified_nhi_delegation.rs` and additionally proves
//! that revoking (deactivating) any link in a delegation chain prevents
//! traversal past that link.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_nhi_delegation.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_identity_is_terminal(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> bool {
    status_is_revoked || status_is_expired
}

pub fn identity_is_terminal(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> (result: bool)
    ensures result == spec_identity_is_terminal(status_is_revoked, status_is_expired),
{
    status_is_revoked || status_is_expired
}

pub open spec fn spec_delegation_participant_allowed(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> bool {
    !spec_identity_is_terminal(status_is_revoked, status_is_expired)
}

pub fn delegation_participant_allowed(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> (result: bool)
    ensures
        result == spec_delegation_participant_allowed(status_is_revoked, status_is_expired),
        result ==> !status_is_revoked && !status_is_expired,
{
    !identity_is_terminal(status_is_revoked, status_is_expired)
}

pub open spec fn spec_delegation_link_effective_for_chain(
    to_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    to_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

pub fn delegation_link_effective_for_chain(
    to_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> (result: bool)
    ensures
        result == spec_delegation_link_effective_for_chain(
            to_agent_matches_current,
            link_active,
            expiry_parsed,
            now_before_expiry,
        ),
        result ==> expiry_parsed,
{
    to_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

pub open spec fn spec_delegation_chain_depth_exceeded(chain_len: nat, max_depth: nat) -> bool {
    chain_len > max_depth
}

pub fn delegation_chain_depth_exceeded(chain_len: usize, max_depth: usize) -> (result: bool)
    ensures result == spec_delegation_chain_depth_exceeded(chain_len as nat, max_depth as nat),
{
    chain_len > max_depth
}

pub proof fn lemma_revoked_identity_is_terminal(status_is_expired: bool)
    ensures spec_identity_is_terminal(true, status_is_expired),
{
}

pub proof fn lemma_expired_identity_is_terminal(status_is_revoked: bool)
    ensures spec_identity_is_terminal(status_is_revoked, true),
{
}

pub proof fn lemma_active_identity_is_not_terminal()
    ensures !spec_identity_is_terminal(false, false),
{
}

pub proof fn lemma_terminal_identity_cannot_delegate(
    status_is_revoked: bool,
    status_is_expired: bool,
)
    ensures
        spec_identity_is_terminal(status_is_revoked, status_is_expired)
            ==> !spec_delegation_participant_allowed(status_is_revoked, status_is_expired),
{
}

pub proof fn lemma_effective_link_requires_parse_success(
    to_agent_matches_current: bool,
    link_active: bool,
    now_before_expiry: bool,
)
    ensures
        !spec_delegation_link_effective_for_chain(
            to_agent_matches_current,
            link_active,
            false,
            now_before_expiry,
        ),
{
}

pub proof fn lemma_effective_link_requires_active_and_unexpired()
    ensures
        !spec_delegation_link_effective_for_chain(true, false, true, true),
        !spec_delegation_link_effective_for_chain(true, true, true, false),
{
}

pub proof fn lemma_depth_exceeded_is_strict(max_depth: nat)
    ensures
        !spec_delegation_chain_depth_exceeded(max_depth, max_depth),
        spec_delegation_chain_depth_exceeded(max_depth + 1, max_depth),
{
}

// ── Chain-level revocation model ──────────────────────────────────────
//
// A delegation chain is modeled as a sequence of links, each with four
// boolean properties corresponding to the arguments of
// `spec_delegation_link_effective_for_chain`. The chain resolver walks
// the sequence and stops at the first link that is not effective.

/// A single link in the abstract delegation chain.
pub struct ChainLink {
    pub to_agent_matches: bool,
    pub active: bool,
    pub expiry_parsed: bool,
    pub now_before_expiry: bool,
}

/// Spec: a link is effective iff all four predicates hold.
pub open spec fn spec_link_effective(link: ChainLink) -> bool {
    spec_delegation_link_effective_for_chain(
        link.to_agent_matches,
        link.active,
        link.expiry_parsed,
        link.now_before_expiry,
    )
}

/// Spec: the chain is traversable up to position `n` iff every link
/// from index 0 to n-1 (inclusive) is effective.
pub open spec fn spec_chain_traversable_to(chain: Seq<ChainLink>, n: nat) -> bool
    decreases n,
{
    if n == 0 {
        true
    } else if n > chain.len() {
        false
    } else {
        spec_link_effective(chain[n - 1 as int]) && spec_chain_traversable_to(chain, (n - 1) as nat)
    }
}

/// NHI-DEL-5: A revoked (deactivated) link is never effective,
/// regardless of agent matching, parse status, or expiry.
pub proof fn lemma_revoked_link_is_not_effective(
    to_agent_matches: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
)
    ensures !spec_delegation_link_effective_for_chain(
        to_agent_matches, false, expiry_parsed, now_before_expiry,
    ),
{
}

/// NHI-DEL-6: If link at position `k` is inactive, the chain is not
/// traversable beyond `k`.
///
/// This models the production behavior: `resolve_delegation_chain` walks
/// links via `delegation_link_effective_for_chain`; an inactive link at
/// position `k` prevents the while-loop from advancing past `k`.
pub proof fn lemma_chain_stops_at_inactive_link(chain: Seq<ChainLink>, k: nat)
    requires
        k < chain.len(),
        !chain[k as int].active,
    ensures
        !spec_chain_traversable_to(chain, (k + 1) as nat),
    decreases k + 1,
{
    // The chain is traversable to k+1 only if link[k] is effective.
    // link[k].active == false, so spec_link_effective(chain[k]) == false.
    assert(!spec_link_effective(chain[k as int]));
}

/// NHI-DEL-7: Revocation completeness — revoking any link between the
/// root and a leaf disconnects the leaf from the root.
///
/// If the chain has at least `n` links and link at position `k`
/// (0-indexed, where `k < n`) is inactive, then the chain is not
/// traversable to depth `n`.
pub proof fn lemma_revocation_disconnects_leaf(chain: Seq<ChainLink>, n: nat, k: nat)
    requires
        n <= chain.len(),
        n > 0,
        k < n,
        !chain[k as int].active,
    ensures
        !spec_chain_traversable_to(chain, n),
    decreases n,
{
    if n == k + 1 {
        // Base: the inactive link is the last one we need.
        lemma_chain_stops_at_inactive_link(chain, k);
    } else {
        // n > k + 1: the chain to depth n requires traversability to n-1.
        if spec_link_effective(chain[(n - 1) as int]) {
            // Even if the last link is effective, the prefix must be traversable.
            lemma_revocation_disconnects_leaf(chain, (n - 1) as nat, k);
            // chain not traversable to n-1, so not traversable to n.
        } else {
            // Last link not effective — chain not traversable to n trivially.
            assert(!spec_chain_traversable_to(chain, n));
        }
    }
}

/// NHI-DEL-8: A fully-active, fully-matched, fully-unexpired chain IS
/// traversable (liveness witness — revocation is not vacuously true).
pub proof fn lemma_all_active_chain_is_traversable(chain: Seq<ChainLink>, n: nat)
    requires
        n <= chain.len(),
        forall|i: int| #![auto] 0 <= i < n as int ==> (
            chain[i].to_agent_matches
            && chain[i].active
            && chain[i].expiry_parsed
            && chain[i].now_before_expiry
        ),
    ensures
        spec_chain_traversable_to(chain, n),
    decreases n,
{
    if n > 0 {
        lemma_all_active_chain_is_traversable(chain, (n - 1) as nat);
        assert(spec_link_effective(chain[(n - 1) as int]));
    }
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::nhi_delegation_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
