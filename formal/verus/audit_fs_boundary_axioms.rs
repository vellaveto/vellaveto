// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Trusted audit-filesystem boundary modeled as explicit Verus axioms.
//!
//! These axioms mirror the documented boundary in
//! `formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md` and the concrete runtime hooks
//! in `vellaveto-audit/src/trusted_audit_fs.rs`.

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub uninterp spec fn fs_append_bytes(prior: Seq<u8>, appended: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn fs_metadata_len(contents: Seq<u8>) -> nat;

pub uninterp spec fn fs_read_bytes(contents: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn fs_truncate_bytes(contents: Seq<u8>, len: nat) -> Seq<u8>;

pub uninterp spec fn fs_rename_contents(contents: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn fs_durability_respected(sync_data: bool, contents: Seq<u8>) -> bool;

pub broadcast axiom fn axiom_fs_append_targets_intended_file(
    prior: Seq<u8>,
    appended: Seq<u8>,
)
    ensures
        #[trigger] fs_append_bytes(prior, appended) == prior + appended,
;

pub broadcast axiom fn axiom_fs_metadata_matches_state(contents: Seq<u8>)
    ensures
        #[trigger] fs_metadata_len(contents) == contents.len(),
;

pub broadcast axiom fn axiom_fs_read_matches_state(contents: Seq<u8>)
    ensures
        #[trigger] fs_read_bytes(contents) == contents,
;

pub broadcast axiom fn axiom_fs_truncate_preserves_prefix(contents: Seq<u8>, len: nat)
    requires
        len <= contents.len(),
    ensures
        #[trigger] fs_truncate_bytes(contents, len) == contents.subrange(0, len as int),
;

pub broadcast axiom fn axiom_fs_rename_preserves_contents(contents: Seq<u8>)
    ensures
        #[trigger] fs_rename_contents(contents) == contents,
;

pub broadcast axiom fn axiom_fs_durability_contract(sync_data: bool, contents: Seq<u8>)
    ensures
        #[trigger] fs_durability_respected(sync_data, contents),
;

pub broadcast group group_audit_fs_boundary_axioms {
    axiom_fs_append_targets_intended_file,
    axiom_fs_metadata_matches_state,
    axiom_fs_read_matches_state,
    axiom_fs_truncate_preserves_prefix,
    axiom_fs_rename_preserves_contents,
    axiom_fs_durability_contract,
}

pub open spec fn audit_filesystem_boundary_axioms_hold() -> bool {
    &&& forall|prior: Seq<u8>, appended: Seq<u8>|
        #[trigger] fs_append_bytes(prior, appended) == prior + appended
    &&& forall|contents: Seq<u8>| #[trigger] fs_metadata_len(contents) == contents.len()
    &&& forall|contents: Seq<u8>| #[trigger] fs_read_bytes(contents) == contents
    &&& forall|contents: Seq<u8>, len: nat|
        len <= contents.len() ==> #[trigger] fs_truncate_bytes(contents, len) == contents.subrange(0, len as int)
    &&& forall|contents: Seq<u8>| #[trigger] fs_rename_contents(contents) == contents
    &&& forall|sync_data: bool, contents: Seq<u8>| #[trigger] fs_durability_respected(sync_data, contents)
}

} // verus!
