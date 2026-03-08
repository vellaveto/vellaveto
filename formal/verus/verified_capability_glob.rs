// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability parent-glob matcher for literal child patterns.
//!
//! This file proves the literal-child containment matcher extracted into
//! `vellaveto-mcp/src/verified_capability_glob.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_glob.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const STAR: u8 = 0x2a;
pub const QUESTION: u8 = 0x3f;
pub const ASCII_A_UPPER: u8 = 0x41;
pub const ASCII_Z_UPPER: u8 = 0x5a;
pub const ASCII_CASE_OFFSET: u8 = 0x20;

pub open spec fn spec_ascii_fold_byte(byte: u8) -> u8 {
    if ASCII_A_UPPER <= byte && byte <= ASCII_Z_UPPER {
        ((byte as nat) + (ASCII_CASE_OFFSET as nat)) as u8
    } else {
        byte
    }
}

pub fn ascii_fold_byte(byte: u8) -> (result: u8)
    ensures result == spec_ascii_fold_byte(byte),
{
    if ASCII_A_UPPER <= byte && byte <= ASCII_Z_UPPER {
        byte + ASCII_CASE_OFFSET
    } else {
        byte
    }
}

pub open spec fn spec_byte_eq_ignore_ascii_case(left: u8, right: u8) -> bool {
    spec_ascii_fold_byte(left) == spec_ascii_fold_byte(right)
}

pub fn byte_eq_ignore_ascii_case(left: u8, right: u8) -> (result: bool)
    ensures result == spec_byte_eq_ignore_ascii_case(left, right),
{
    ascii_fold_byte(left) == ascii_fold_byte(right)
}

pub open spec fn spec_literal_child_matches_parent_glob_from(
    parent_pattern: Seq<u8>,
    pattern_start: nat,
    child_literal: Seq<u8>,
    child_start: nat,
) -> bool
    decreases parent_pattern.len() - pattern_start, child_literal.len() - child_start
{
    if pattern_start >= parent_pattern.len() {
        child_start >= child_literal.len()
    } else if parent_pattern[pattern_start as int] == STAR {
        spec_literal_child_matches_parent_glob_from(
            parent_pattern,
            pattern_start + 1,
            child_literal,
            child_start,
        ) || (child_start < child_literal.len() && spec_literal_child_matches_parent_glob_from(
            parent_pattern,
            pattern_start,
            child_literal,
            child_start + 1,
        ))
    } else {
        child_start < child_literal.len()
            && (parent_pattern[pattern_start as int] == QUESTION
                || spec_byte_eq_ignore_ascii_case(
                    parent_pattern[pattern_start as int],
                    child_literal[child_start as int],
                ))
            && spec_literal_child_matches_parent_glob_from(
                parent_pattern,
                pattern_start + 1,
                child_literal,
                child_start + 1,
            )
    }
}

pub open spec fn spec_literal_child_matches_parent_glob(
    parent_pattern: Seq<u8>,
    child_literal: Seq<u8>,
) -> bool {
    spec_literal_child_matches_parent_glob_from(parent_pattern, 0, child_literal, 0)
}

fn literal_child_matches_parent_glob_from(
    parent_pattern: &Vec<u8>,
    pattern_start: usize,
    child_literal: &Vec<u8>,
    child_start: usize,
) -> (result: bool)
    requires pattern_start <= parent_pattern.len(), child_start <= child_literal.len()
    ensures
        result == spec_literal_child_matches_parent_glob_from(
            parent_pattern@,
            pattern_start as nat,
            child_literal@,
            child_start as nat,
        )
    decreases parent_pattern.len() - pattern_start, child_literal.len() - child_start
{
    if pattern_start == parent_pattern.len() {
        child_start == child_literal.len()
    } else if parent_pattern[pattern_start] == STAR {
        let skip_star = literal_child_matches_parent_glob_from(
            parent_pattern,
            pattern_start + 1,
            child_literal,
            child_start,
        );
        if skip_star {
            true
        } else if child_start == child_literal.len() {
            false
        } else {
            literal_child_matches_parent_glob_from(
                parent_pattern,
                pattern_start,
                child_literal,
                child_start + 1,
            )
        }
    } else if child_start == child_literal.len() {
        false
    } else {
        let current_matches = parent_pattern[pattern_start] == QUESTION
            || byte_eq_ignore_ascii_case(parent_pattern[pattern_start], child_literal[child_start]);
        if current_matches {
            literal_child_matches_parent_glob_from(
                parent_pattern,
                pattern_start + 1,
                child_literal,
                child_start + 1,
            )
        } else {
            false
        }
    }
}

pub fn literal_child_matches_parent_glob(
    parent_pattern: Vec<u8>,
    child_literal: Vec<u8>,
) -> (result: bool)
    ensures result == spec_literal_child_matches_parent_glob(parent_pattern@, child_literal@),
{
    literal_child_matches_parent_glob_from(&parent_pattern, 0, &child_literal, 0)
}

pub proof fn lemma_ascii_uppercase_folds_to_lowercase(byte: u8)
    requires ASCII_A_UPPER <= byte && byte <= ASCII_Z_UPPER
    ensures spec_ascii_fold_byte(byte) == byte + ASCII_CASE_OFFSET,
{
}

pub proof fn lemma_non_uppercase_byte_is_stable(byte: u8)
    requires !(ASCII_A_UPPER <= byte && byte <= ASCII_Z_UPPER)
    ensures spec_ascii_fold_byte(byte) == byte,
{
}

pub proof fn lemma_case_insensitive_byte_match_is_symmetric(left: u8, right: u8)
    ensures
        spec_byte_eq_ignore_ascii_case(left, right)
            == spec_byte_eq_ignore_ascii_case(right, left),
{
}

pub proof fn lemma_empty_pattern_matches_only_empty_child()
    ensures
        spec_literal_child_matches_parent_glob(seq![], seq![]),
        !spec_literal_child_matches_parent_glob(seq![], seq![0x61u8]),
{
}

pub proof fn lemma_question_rejects_empty_child()
    ensures !spec_literal_child_matches_parent_glob(seq![QUESTION], seq![]),
{
}

pub proof fn lemma_literal_mismatch_is_rejected()
    ensures !spec_literal_child_matches_parent_glob(seq![0x66u8], seq![0x78u8]),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_glob_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
