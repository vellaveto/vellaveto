// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Trusted Merkle boundary modeled as explicit Verus axioms.
//!
//! These axioms mirror the documented boundary in
//! `formal/MERKLE_TRUST_BOUNDARY.md` and the concrete runtime hooks in
//! `vellaveto-audit/src/trusted_merkle_hash.rs`.

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub uninterp spec fn merkle_leaf_hash(data: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn merkle_internal_hash(left: Seq<u8>, right: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn merkle_encode_hash_hex(hash: Seq<u8>) -> Seq<u8>;

pub uninterp spec fn merkle_decode_hash_hex(encoded: Seq<u8>) -> Option<Seq<u8>>;

pub broadcast axiom fn axiom_merkle_leaf_hash_len(data: Seq<u8>)
    ensures
        #[trigger] merkle_leaf_hash(data).len() == 32,
;

pub broadcast axiom fn axiom_merkle_internal_hash_len(left: Seq<u8>, right: Seq<u8>)
    requires
        left.len() == 32,
        right.len() == 32,
    ensures
        #[trigger] merkle_internal_hash(left, right).len() == 32,
;

pub broadcast axiom fn axiom_merkle_rfc6962_domain_separation(
    data: Seq<u8>,
    left: Seq<u8>,
    right: Seq<u8>,
)
    requires
        left.len() == 32,
        right.len() == 32,
    ensures
        #![trigger merkle_leaf_hash(data), merkle_internal_hash(left, right)]
        merkle_leaf_hash(data) != merkle_internal_hash(left, right),
;

pub broadcast axiom fn axiom_merkle_leaf_second_preimage_resistance(
    data1: Seq<u8>,
    data2: Seq<u8>,
)
    ensures
        #![trigger merkle_leaf_hash(data1), merkle_leaf_hash(data2)]
        merkle_leaf_hash(data1) == merkle_leaf_hash(data2) ==> data1 == data2,
;

pub broadcast axiom fn axiom_merkle_internal_second_preimage_resistance(
    left1: Seq<u8>,
    right1: Seq<u8>,
    left2: Seq<u8>,
    right2: Seq<u8>,
)
    requires
        left1.len() == 32,
        right1.len() == 32,
        left2.len() == 32,
        right2.len() == 32,
    ensures
        #![trigger merkle_internal_hash(left1, right1), merkle_internal_hash(left2, right2)]
        merkle_internal_hash(left1, right1) == merkle_internal_hash(left2, right2)
            ==> left1 == left2 && right1 == right2,
;

pub broadcast axiom fn axiom_merkle_codec_roundtrip(hash: Seq<u8>)
    requires
        hash.len() == 32,
    ensures
        #[trigger] merkle_decode_hash_hex(merkle_encode_hash_hex(hash)) == Option::Some(hash),
;

pub broadcast axiom fn axiom_merkle_codec_decoded_hash_len(
    encoded: Seq<u8>,
    decoded: Seq<u8>,
)
    requires
        merkle_decode_hash_hex(encoded) == Option::Some(decoded),
    ensures
        #![trigger merkle_decode_hash_hex(encoded), decoded.len()]
        decoded.len() == 32,
;

pub broadcast group group_merkle_boundary_axioms {
    axiom_merkle_leaf_hash_len,
    axiom_merkle_internal_hash_len,
    axiom_merkle_rfc6962_domain_separation,
    axiom_merkle_leaf_second_preimage_resistance,
    axiom_merkle_internal_second_preimage_resistance,
    axiom_merkle_codec_roundtrip,
    axiom_merkle_codec_decoded_hash_len,
}

pub open spec fn merkle_boundary_axioms_hold() -> bool {
    &&& forall|data: Seq<u8>| #[trigger] merkle_leaf_hash(data).len() == 32
    &&& forall|left: Seq<u8>, right: Seq<u8>|
        left.len() == 32 && right.len() == 32 ==> #[trigger] merkle_internal_hash(left, right).len() == 32
    &&& forall|data: Seq<u8>, left: Seq<u8>, right: Seq<u8>|
        #![trigger merkle_leaf_hash(data), merkle_internal_hash(left, right)]
        left.len() == 32 && right.len() == 32 ==> merkle_leaf_hash(data) != merkle_internal_hash(left, right)
    &&& forall|data1: Seq<u8>, data2: Seq<u8>|
        #![trigger merkle_leaf_hash(data1), merkle_leaf_hash(data2)]
        merkle_leaf_hash(data1) == merkle_leaf_hash(data2) ==> data1 == data2
    &&& forall|left1: Seq<u8>, right1: Seq<u8>, left2: Seq<u8>, right2: Seq<u8>|
        #![trigger merkle_internal_hash(left1, right1), merkle_internal_hash(left2, right2)]
        left1.len() == 32 && right1.len() == 32 && left2.len() == 32 && right2.len() == 32
            ==> merkle_internal_hash(left1, right1) == merkle_internal_hash(left2, right2)
                ==> left1 == left2 && right1 == right2
    &&& forall|hash: Seq<u8>|
        hash.len() == 32
            ==> #[trigger] merkle_decode_hash_hex(merkle_encode_hash_hex(hash)) == Option::Some(hash)
    &&& forall|encoded: Seq<u8>, decoded: Seq<u8>|
        #![trigger merkle_decode_hash_hex(encoded), decoded.len()]
        merkle_decode_hash_hex(encoded) == Option::Some(decoded) ==> decoded.len() == 32
}

} // verus!
