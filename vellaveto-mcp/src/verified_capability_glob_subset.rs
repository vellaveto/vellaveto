// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability parent-glob/child-glob subset kernel.
//!
//! This module closes the remaining delegation gap in
//! `capability_token.rs::grant_is_subset()` by deciding whether the full child
//! glob language is contained within the parent glob language for the
//! case-insensitive `*`/`?` matcher used by capability delegation.
//!
//! The implementation determinizes each glob pattern into a compact NFA state
//! set and explores the reachable product graph over a finite set of
//! representative bytes. That alphabet is exact for this matcher because
//! transitions only distinguish:
//! - literal bytes present in either pattern, after ASCII folding
//! - all remaining bytes, which are behaviorally equivalent

use std::collections::{HashSet, VecDeque};

use crate::verified_capability_glob::{ascii_fold_byte, byte_eq_ignore_ascii_case};

const STAR: u8 = b'*';
const QUESTION: u8 = b'?';

#[derive(Clone, PartialEq, Eq, Hash)]
struct PatternStateSet {
    bits: Vec<u64>,
}

impl PatternStateSet {
    fn new(state_count: usize) -> Self {
        Self {
            bits: vec![0; state_count.div_ceil(64)],
        }
    }

    fn set(&mut self, index: usize) {
        self.bits[index / 64] |= 1u64 << (index % 64);
    }

    fn contains(&self, index: usize) -> bool {
        (self.bits[index / 64] & (1u64 << (index % 64))) != 0
    }

    fn apply_star_epsilon_closure(&mut self, pattern: &[u8]) {
        for index in 0..pattern.len() {
            if self.contains(index) && pattern[index] == STAR {
                self.set(index + 1);
            }
        }
    }

    fn start(pattern: &[u8]) -> Self {
        let mut state_set = Self::new(pattern.len() + 1);
        state_set.set(0);
        state_set.apply_star_epsilon_closure(pattern);
        state_set
    }

    fn transition(&self, pattern: &[u8], input: u8) -> Self {
        let mut next = Self::new(pattern.len() + 1);

        for index in 0..pattern.len() {
            if !self.contains(index) {
                continue;
            }

            let token = pattern[index];
            if token == STAR {
                next.set(index);
            } else if token == QUESTION || byte_eq_ignore_ascii_case(token, input) {
                next.set(index + 1);
            }
        }

        next.apply_star_epsilon_closure(pattern);
        next
    }

    fn accepts(&self, pattern: &[u8]) -> bool {
        self.contains(pattern.len())
    }
}

fn collect_representative_bytes(parent_pattern: &[u8], child_pattern: &[u8]) -> Vec<u8> {
    let mut seen = [false; 256];
    let mut representatives = Vec::new();

    for &byte in parent_pattern.iter().chain(child_pattern.iter()) {
        if byte == STAR || byte == QUESTION {
            continue;
        }

        let folded = ascii_fold_byte(byte);
        if !seen[folded as usize] {
            seen[folded as usize] = true;
            representatives.push(folded);
        }
    }

    if let Some(other) = (u8::MIN..=u8::MAX).find(|byte| !seen[*byte as usize]) {
        representatives.push(other);
    }

    representatives
}

/// Return true when every value matched by `child_pattern` is also matched by
/// `parent_pattern` under the case-insensitive `*`/`?` capability glob rules.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn glob_pattern_subset(parent_pattern: &str, child_pattern: &str) -> bool {
    let parent = parent_pattern.as_bytes();
    let child = child_pattern.as_bytes();
    let representatives = collect_representative_bytes(parent, child);

    let start = (
        PatternStateSet::start(parent),
        PatternStateSet::start(child),
    );
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = HashSet::from([start]);

    while let Some((parent_states, child_states)) = queue.pop_front() {
        if child_states.accepts(child) && !parent_states.accepts(parent) {
            return false;
        }

        for &input in &representatives {
            let next_parent = parent_states.transition(parent, input);
            let next_child = child_states.transition(child, input);
            let next = (next_parent.clone(), next_child.clone());

            if visited.insert(next) {
                queue.push_back((next_parent, next_child));
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enumerate_values(alphabet: &[u8], max_len: usize) -> Vec<String> {
        fn recurse(current: &mut Vec<u8>, out: &mut Vec<String>, alphabet: &[u8], max_len: usize) {
            out.push(String::from_utf8(current.clone()).expect("alphabet is ASCII"));
            if current.len() == max_len {
                return;
            }

            for &byte in alphabet {
                current.push(byte);
                recurse(current, out, alphabet, max_len);
                current.pop();
            }
        }

        let mut values = Vec::new();
        recurse(&mut Vec::new(), &mut values, alphabet, max_len);
        values
    }

    fn brute_force_subset(parent_pattern: &str, child_pattern: &str, max_len: usize) -> bool {
        enumerate_values(b"ab_", max_len).into_iter().all(|value| {
            !crate::verified_capability_glob::literal_child_matches_parent_glob(
                child_pattern,
                &value,
            ) || crate::verified_capability_glob::literal_child_matches_parent_glob(
                parent_pattern,
                &value,
            )
        })
    }

    #[test]
    fn test_glob_pattern_subset_accepts_narrower_child_star_prefix() {
        assert!(glob_pattern_subset("file_*", "file_read*"));
    }

    #[test]
    fn test_glob_pattern_subset_accepts_narrower_child_question_branch() {
        assert!(glob_pattern_subset("report_*", "report_??"));
    }

    #[test]
    fn test_glob_pattern_subset_rejects_broader_child_star() {
        assert!(!glob_pattern_subset("fi?", "fi*"));
    }

    #[test]
    fn test_glob_pattern_subset_is_case_insensitive() {
        assert!(glob_pattern_subset("FILE_*", "file_read*"));
    }

    #[test]
    fn test_glob_pattern_subset_matches_small_bruteforce_oracle() {
        let patterns = [
            "", "*", "?", "a", "A", "a*", "*a", "a?", "?a", "ab*", "a*b", "a?b",
        ];

        for parent in patterns {
            for child in patterns {
                assert_eq!(
                    glob_pattern_subset(parent, child),
                    brute_force_subset(parent, child, 4),
                    "subset mismatch for parent={parent:?} child={child:?}"
                );
            }
        }
    }
}
