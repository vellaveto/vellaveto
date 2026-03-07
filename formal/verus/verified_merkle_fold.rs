// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified Merkle fold kernel.
//!
//! This file proves the pure Merkle fold steps extracted into
//! `vellaveto-audit/src/verified_merkle_fold.rs`.
//!
//! The proof uses an abstract sequence model:
//! - a leaf is a singleton sequence
//! - an internal parent is left-to-right concatenation
//! - proof verification reconstructs a parent by replaying the same
//!   concatenation order
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_merkle_fold.rs`

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn next_level_len(level_len: nat) -> nat {
    level_len / 2 + level_len % 2
}

pub open spec fn proof_sibling_index(node_index: nat) -> nat {
    if node_index % 2 == 0 {
        node_index + 1
    } else {
        (node_index as int - 1) as nat
    }
}

pub open spec fn proof_step_is_left(node_index: nat) -> bool {
    node_index % 2 == 1
}

pub open spec fn proof_level_has_sibling(node_index: nat, level_len: nat) -> bool {
    proof_sibling_index(node_index) < level_len
}

pub open spec fn proof_parent_index(node_index: nat) -> nat {
    node_index / 2
}

pub open spec fn fold_proof_step(
    current: Seq<int>,
    sibling: Seq<int>,
    sibling_on_left: bool,
) -> Seq<int> {
    if sibling_on_left {
        sibling + current
    } else {
        current + sibling
    }
}

pub open spec fn fold_peak_into_root(peak: Seq<int>, acc: Seq<int>) -> Seq<int> {
    peak + acc
}

pub open spec fn next_level_hashes(level: Seq<Seq<int>>) -> Seq<Seq<int>>
    decreases level.len()
{
    if level.len() == 0 {
        seq![]
    } else if level.len() == 1 {
        seq![level[0]]
    } else {
        seq![fold_proof_step(level[0], level[1], false)]
            + next_level_hashes(level.subrange(2, level.len() as int))
    }
}

pub open spec fn parent_of_node(level: Seq<Seq<int>>, node_index: nat) -> Seq<int>
    recommends node_index < level.len()
{
    if proof_level_has_sibling(node_index, level.len() as nat) {
        fold_proof_step(
            level[node_index as int],
            level[proof_sibling_index(node_index) as int],
            proof_step_is_left(node_index),
        )
    } else {
        level[node_index as int]
    }
}

pub open spec fn proof_steps_with_fuel(
    level: Seq<Seq<int>>,
    node_index: nat,
    fuel: nat,
) -> Seq<(Seq<int>, bool)>
    decreases fuel
{
    if fuel == 0 || level.len() <= 1 || node_index >= level.len() {
        seq![]
    } else if proof_level_has_sibling(node_index, level.len() as nat) {
        seq![(level[proof_sibling_index(node_index) as int], proof_step_is_left(node_index))]
            + proof_steps_with_fuel(
                next_level_hashes(level),
                proof_parent_index(node_index),
                (fuel as int - 1) as nat,
            )
    } else {
        proof_steps_with_fuel(
            next_level_hashes(level),
            proof_parent_index(node_index),
            (fuel as int - 1) as nat,
        )
    }
}

pub open spec fn proof_steps(level: Seq<Seq<int>>, node_index: nat) -> Seq<(Seq<int>, bool)> {
    proof_steps_with_fuel(level, node_index, level.len() as nat)
}

pub open spec fn fold_proof(leaf: Seq<int>, proof: Seq<(Seq<int>, bool)>) -> Seq<int>
    decreases proof.len()
{
    if proof.len() == 0 {
        leaf
    } else {
        fold_proof(
            fold_proof_step(leaf, proof[0].0, proof[0].1),
            proof.subrange(1, proof.len() as int),
        )
    }
}

pub open spec fn root_from_level_with_fuel(level: Seq<Seq<int>>, fuel: nat) -> Seq<int>
    decreases fuel
{
    if fuel == 0 || level.len() == 0 {
        seq![]
    } else if level.len() == 1 {
        level[0]
    } else {
        root_from_level_with_fuel(next_level_hashes(level), (fuel as int - 1) as nat)
    }
}

pub open spec fn root_from_level(level: Seq<Seq<int>>) -> Seq<int> {
    root_from_level_with_fuel(level, level.len() as nat)
}

pub proof fn lemma_next_level_len_drops_pair(level_len: nat)
    requires level_len >= 2
    ensures next_level_len(level_len) == 1 + next_level_len((level_len as int - 2) as nat),
{
}

pub proof fn lemma_next_level_length_matches_round_up(level: Seq<Seq<int>>)
    ensures next_level_hashes(level).len() == next_level_len(level.len() as nat),
    decreases level.len()
{
    if level.len() == 0 {
    } else if level.len() == 1 {
    } else {
        let tail = level.subrange(2, level.len() as int);
        lemma_next_level_length_matches_round_up(tail);
        lemma_next_level_len_drops_pair(level.len() as nat);
        assert(next_level_hashes(level).len() == 1 + next_level_hashes(tail).len());
        assert(next_level_hashes(tail).len() == next_level_len(tail.len() as nat));
        assert(tail.len() as nat == (level.len() as int - 2) as nat);
    }
}

pub proof fn lemma_fold_proof_step_respects_direction(
    current: Seq<int>,
    sibling: Seq<int>,
)
    ensures
        fold_proof_step(current, sibling, false) == current + sibling,
        fold_proof_step(current, sibling, true) == sibling + current,
{
}

pub proof fn lemma_fold_proof_cons_step(
    current: Seq<int>,
    sibling: Seq<int>,
    sibling_on_left: bool,
    tail: Seq<(Seq<int>, bool)>,
)
    ensures
        fold_proof(current, seq![(sibling, sibling_on_left)] + tail)
            == fold_proof(fold_proof_step(current, sibling, sibling_on_left), tail),
{
    assert((seq![(sibling, sibling_on_left)] + tail)[0] == (sibling, sibling_on_left));
    assert((seq![(sibling, sibling_on_left)] + tail).subrange(
        1,
        (seq![(sibling, sibling_on_left)] + tail).len() as int,
    ) == tail);
}

pub proof fn lemma_fold_peak_places_peak_on_left(peak: Seq<int>, acc: Seq<int>)
    ensures fold_peak_into_root(peak, acc) == peak + acc,
{
}

pub proof fn lemma_first_pair_builds_next_level_parent(level: Seq<Seq<int>>)
    requires level.len() >= 2
    ensures next_level_hashes(level)[0] == fold_proof_step(level[0], level[1], false),
{
}

pub proof fn lemma_trailing_odd_node_promoted(level: Seq<Seq<int>>)
    requires level.len() % 2 == 1, level.len() > 0
    ensures
        next_level_hashes(level)[next_level_len(level.len() as nat) as int - 1]
            == level[level.len() - 1],
    decreases level.len()
{
    if level.len() == 1 {
    } else {
        let tail = level.subrange(2, level.len() as int);
        lemma_trailing_odd_node_promoted(tail);
        lemma_next_level_length_matches_round_up(tail);
        lemma_next_level_len_drops_pair(level.len() as nat);
        assert(tail.len() % 2 == 1);
        assert(tail.len() > 0);
        assert(next_level_len(level.len() as nat) as int - 1 == next_level_len(tail.len() as nat) as int);
        assert(next_level_hashes(level) == seq![fold_proof_step(level[0], level[1], false)] + next_level_hashes(tail));
        assert(next_level_hashes(level)[next_level_len(level.len() as nat) as int - 1]
            == next_level_hashes(tail)[next_level_len(tail.len() as nat) as int - 1]);
        assert(tail[tail.len() - 1] == level[level.len() - 1]);
    }
}

pub proof fn lemma_parent_step_matches_fold(level: Seq<Seq<int>>, node_index: nat)
    requires
        level.len() > 0,
        node_index < level.len(),
    ensures
        next_level_hashes(level)[proof_parent_index(node_index) as int]
            == parent_of_node(level, node_index),
    decreases level.len(), node_index
{
    if level.len() == 1 {
        assert(node_index == 0);
    } else if node_index < 2 {
        if node_index == 0 {
            assert(proof_parent_index(node_index) == 0);
            assert(proof_sibling_index(node_index) == 1);
            assert(proof_level_has_sibling(node_index, level.len() as nat));
            assert(parent_of_node(level, node_index) == fold_proof_step(level[0], level[1], false));
            assert(next_level_hashes(level)[0] == fold_proof_step(level[0], level[1], false));
        } else {
            assert(node_index == 1);
            assert(proof_parent_index(node_index) == 0);
            assert(proof_sibling_index(node_index) == 0);
            assert(proof_level_has_sibling(node_index, level.len() as nat));
            assert(parent_of_node(level, node_index) == fold_proof_step(level[1], level[0], true));
            assert(fold_proof_step(level[1], level[0], true) == fold_proof_step(level[0], level[1], false));
            assert(next_level_hashes(level)[0] == fold_proof_step(level[0], level[1], false));
        }
    } else {
        let tail = level.subrange(2, level.len() as int);
        let ghost tail_index = (node_index as int - 2) as nat;
        lemma_parent_step_matches_fold(tail, tail_index);
        assert(node_index == tail_index + 2);
        assert(proof_parent_index(node_index) == proof_parent_index(tail_index) + 1);
        assert(proof_step_is_left(node_index) == proof_step_is_left(tail_index));
        assert(proof_sibling_index(node_index) == proof_sibling_index(tail_index) + 2);
        assert(proof_level_has_sibling(node_index, level.len() as nat)
            == proof_level_has_sibling(tail_index, tail.len() as nat));
        assert(level[node_index as int] == tail[tail_index as int]);
        assert(next_level_hashes(level) == seq![fold_proof_step(level[0], level[1], false)] + next_level_hashes(tail));
        lemma_next_level_length_matches_round_up(tail);
        assert(proof_parent_index(tail_index) < next_level_hashes(tail).len());
        assert(next_level_hashes(level).len() == 1 + next_level_hashes(tail).len());
        assert(next_level_hashes(level)[proof_parent_index(node_index) as int]
            == next_level_hashes(tail)[proof_parent_index(tail_index) as int]) by {
            assert(proof_parent_index(node_index) as int == proof_parent_index(tail_index) as int + 1);
        }
        if proof_level_has_sibling(node_index, level.len() as nat) {
            assert(proof_level_has_sibling(tail_index, tail.len() as nat));
            assert(proof_sibling_index(tail_index) < tail.len());
            assert(level[proof_sibling_index(node_index) as int]
                == tail[proof_sibling_index(tail_index) as int]);
            assert(parent_of_node(level, node_index) == parent_of_node(tail, tail_index));
        } else {
            assert(!proof_level_has_sibling(tail_index, tail.len() as nat));
            assert(parent_of_node(level, node_index) == level[node_index as int]);
            assert(parent_of_node(tail, tail_index) == tail[tail_index as int]);
            assert(parent_of_node(level, node_index) == parent_of_node(tail, tail_index));
        }
    }
}

pub proof fn lemma_proof_reconstructs_root_with_fuel(
    level: Seq<Seq<int>>,
    node_index: nat,
    fuel: nat,
)
    requires
        level.len() > 0,
        node_index < level.len(),
        fuel >= level.len(),
    ensures
        fold_proof(
            level[node_index as int],
            proof_steps_with_fuel(level, node_index, fuel),
        ) == root_from_level_with_fuel(level, fuel),
    decreases fuel
{
    if level.len() == 1 {
    } else {
        let next = next_level_hashes(level);
        let ghost parent_index = proof_parent_index(node_index);
        lemma_parent_step_matches_fold(level, node_index);
        lemma_next_level_length_matches_round_up(level);
        assert(parent_index < next_level_len(level.len() as nat));
        assert(next.len() == next_level_len(level.len() as nat));
        assert(parent_index < next.len());
        assert((fuel as int - 1) as nat >= next.len());
        lemma_proof_reconstructs_root_with_fuel(next, parent_index, (fuel as int - 1) as nat);
        if proof_level_has_sibling(node_index, level.len() as nat) {
            assert(proof_steps_with_fuel(level, node_index, fuel)
                == seq![(level[proof_sibling_index(node_index) as int], proof_step_is_left(node_index))]
                    + proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat));
            lemma_fold_proof_cons_step(
                level[node_index as int],
                level[proof_sibling_index(node_index) as int],
                proof_step_is_left(node_index),
                proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat),
            );
            assert(parent_of_node(level, node_index)
                == fold_proof_step(
                    level[node_index as int],
                    level[proof_sibling_index(node_index) as int],
                    proof_step_is_left(node_index),
                ));
        } else {
            assert(proof_steps_with_fuel(level, node_index, fuel)
                == proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat));
            assert(parent_of_node(level, node_index) == level[node_index as int]);
            assert(fold_proof(
                level[node_index as int],
                proof_steps_with_fuel(level, node_index, fuel),
            ) == fold_proof(
                parent_of_node(level, node_index),
                proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat),
            ));
        }
        assert(parent_of_node(level, node_index) == next[parent_index as int]);
        assert(fold_proof(
            parent_of_node(level, node_index),
            proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat),
        ) == fold_proof(
            next[parent_index as int],
            proof_steps_with_fuel(next, parent_index, (fuel as int - 1) as nat),
        ));
        assert(root_from_level_with_fuel(level, fuel)
            == root_from_level_with_fuel(next, (fuel as int - 1) as nat));
    }
}

pub proof fn lemma_proof_reconstructs_root(level: Seq<Seq<int>>, node_index: nat)
    requires
        level.len() > 0,
        node_index < level.len(),
    ensures
        fold_proof(level[node_index as int], proof_steps(level, node_index))
            == root_from_level(level),
{
    lemma_proof_reconstructs_root_with_fuel(level, node_index, level.len() as nat);
}

fn main() {}

} // verus!
