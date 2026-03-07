// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified path normalization.
//!
//! This file proves path normalization properties V9-V10 for ALL inputs
//! using a pure byte-level algorithm that produces identical results to the
//! post-decode normalization kernel in `vellaveto-engine/src/path.rs`.
//!
//! We cannot use `std::path::PathBuf::components()` or `Cow` in Verus,
//! so we implement a byte-level equivalent that splits on `/`, resolves
//! `.` and `..`, and reconstructs the output.
//!
//! To verify:
//!   `~/verus/verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_path.rs`
//!
//! # Properties Proven
//!
//! | ID  | Property |
//! |-----|----------|
//! | V9  | Path normalization idempotent: normalize(normalize(x)) == normalize(x) |
//! | V10 | No ".." component in normalized output |
//!
//! # Trust Boundary
//!
//! Proves properties on a byte-level reimplementation. Parity with production
//! `normalize_decoded_path` is established by unit tests and parity checks.
//! The production function uses `str::split('/')` — we use an equivalent
//! byte-level split.

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const SLASH: u8 = 0x2f;
pub const DOT: u8 = 0x2e;

/// Spec: a byte sequence has no ".." component when split on '/'.
///
/// A ".." component is a sequence where bytes at positions [start, start+1]
/// are [b'.', b'.'] and start is either 0 or preceded by b'/', and start+2
/// is either the end or followed by b'/'.
pub open spec fn spec_no_dotdot_component_seq(path: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < path.len() - 1 ==>
        !(
            #[trigger] path[i] == DOT
            && path[i + 1] == DOT
            && (i == 0 || path[i - 1] == SLASH)
            && (i + 2 >= path.len() || path[i + 2] == SLASH)
        )
}

pub open spec fn spec_no_dotdot_component(path: &Vec<u8>) -> bool {
    spec_no_dotdot_component_seq(path@)
}

pub open spec fn spec_has_no_null_seq(path: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < path.len() ==> #[trigger] path[i] != 0
}

pub open spec fn spec_has_no_null(path: &Vec<u8>) -> bool {
    spec_has_no_null_seq(path@)
}

pub open spec fn spec_component_is_normal_seq(comp: Seq<u8>) -> bool {
    0 < comp.len()
    && (comp.len() == 1 ==> comp[0] != DOT)
    && (comp.len() == 2 ==> !(comp[0] == DOT && comp[1] == DOT))
    && forall|i: int| 0 <= i < comp.len() ==> #[trigger] comp[i] != SLASH && comp[i] != 0
}

pub open spec fn spec_component_is_normal(comp: &Vec<u8>) -> bool {
    spec_component_is_normal_seq(comp@)
}

pub open spec fn spec_stack_is_normal_seq(stack: Seq<Seq<u8>>) -> bool {
    forall|i: int| 0 <= i < stack.len() ==> #[trigger] spec_component_is_normal_seq(stack[i])
}

pub open spec fn spec_stack_is_normal(stack: &Vec<Vec<u8>>) -> bool {
    spec_stack_is_normal_seq(stack.deep_view())
}

pub open spec fn spec_render_relative(stack: Seq<Seq<u8>>) -> Seq<u8>
    decreases stack.len(),
{
    if stack.len() == 0 {
        Seq::<u8>::empty()
    } else if stack.len() == 1 {
        stack[0]
    } else {
        stack[0] + seq![SLASH] + spec_render_relative(stack.subrange(1, stack.len() as int))
    }
}

pub open spec fn spec_render_path(starts_with_slash: bool, stack: Seq<Seq<u8>>) -> Seq<u8>
    decreases stack.len(),
{
    if starts_with_slash {
        if stack.len() == 0 {
            seq![SLASH]
        } else {
            seq![SLASH] + spec_render_relative(stack)
        }
    } else {
        spec_render_relative(stack)
    }
}

pub open spec fn spec_process_component(
    comp: Seq<u8>,
    stack: Seq<Seq<u8>>,
) -> (bool, Seq<Seq<u8>>) {
    if comp.len() == 0 {
        (true, stack)
    } else if comp.len() == 1 && comp[0] == DOT {
        (true, stack)
    } else if comp.len() == 2 && comp[0] == DOT && comp[1] == DOT {
        if stack.len() == 0 {
            (true, stack)
        } else {
            (true, stack.drop_last())
        }
    } else {
        (true, stack.push(comp))
    }
}

pub open spec fn spec_process_bytes(
    rest: Seq<u8>,
    stack: Seq<Seq<u8>>,
    current: Seq<u8>,
) -> (bool, Seq<Seq<u8>>)
    decreases rest.len(),
{
    if rest.len() == 0 {
        spec_process_component(current, stack)
    } else if rest[0] == SLASH {
        let step = spec_process_component(current, stack);
        if !step.0 {
            step
        } else {
            spec_process_bytes(
                rest.subrange(1, rest.len() as int),
                step.1,
                Seq::<u8>::empty(),
            )
        }
    } else {
        spec_process_bytes(
            rest.subrange(1, rest.len() as int),
            stack,
            current.push(rest[0]),
        )
    }
}

/// Spec-level model of normalize_path_bytes result.
pub open spec fn spec_normalize_path_bytes(path: Seq<u8>) -> (bool, Seq<u8>) {
    if !spec_has_no_null_seq(path) {
        (false, Seq::<u8>::empty())
    } else {
        let starts_with_slash = path.len() > 0 && path[0] == SLASH;
        let processed = spec_process_bytes(path, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty());
        if starts_with_slash || processed.1.len() > 0 {
            (true, spec_render_path(true, processed.1))
        } else {
            (false, Seq::<u8>::empty())
        }
    }
}

pub proof fn lemma_process_component_normal(comp: Seq<u8>, stack: Seq<Seq<u8>>)
    requires spec_component_is_normal_seq(comp),
    ensures spec_process_component(comp, stack) == (true, stack.push(comp)),
{
}

pub proof fn lemma_render_relative_has_no_null(stack: Seq<Seq<u8>>)
    requires spec_stack_is_normal_seq(stack),
    ensures spec_has_no_null_seq(spec_render_relative(stack)),
    decreases stack.len(),
{
    if stack.len() == 0 {
    } else if stack.len() == 1 {
        assert(spec_has_no_null_seq(spec_render_relative(stack))) by {
            assert forall|i: int| 0 <= i < spec_render_relative(stack).len()
                implies #[trigger] spec_render_relative(stack)[i] != 0 by {
                assert(spec_render_relative(stack)[i] == stack[0][i]);
                assert(spec_component_is_normal_seq(stack[0]));
            };
        };
    } else {
        let tail = stack.subrange(1, stack.len() as int);
        lemma_render_relative_has_no_null(tail);
        assert(spec_has_no_null_seq(spec_render_relative(stack))) by {
            assert forall|i: int| 0 <= i < spec_render_relative(stack).len()
                implies #[trigger] spec_render_relative(stack)[i] != 0 by {
                if i < stack[0].len() {
                    assert(spec_render_relative(stack)[i] == stack[0][i]);
                    assert(spec_component_is_normal_seq(stack[0]));
                } else if i == stack[0].len() {
                    assert(spec_render_relative(stack)[i] == SLASH);
                } else {
                    let j = i - stack[0].len() - 1;
                    assert(0 <= j < spec_render_relative(tail).len());
                    assert(spec_render_relative(stack)[i] == spec_render_relative(tail)[j]);
                }
            };
        };
    }
}

pub proof fn lemma_render_path_has_no_null(starts_with_slash: bool, stack: Seq<Seq<u8>>)
    requires spec_stack_is_normal_seq(stack),
    ensures spec_has_no_null_seq(spec_render_path(starts_with_slash, stack)),
{
    if stack.len() > 0 {
        lemma_render_relative_has_no_null(stack);
    }
}

pub proof fn lemma_process_bytes_preserves_normality(
    rest: Seq<u8>,
    stack: Seq<Seq<u8>>,
    current: Seq<u8>,
)
    requires
        spec_has_no_null_seq(rest),
        spec_stack_is_normal_seq(stack),
        forall|i: int| 0 <= i < current.len() ==> #[trigger] current[i] != SLASH && current[i] != 0,
    ensures
        spec_process_bytes(rest, stack, current).0
            ==> spec_stack_is_normal_seq(spec_process_bytes(rest, stack, current).1),
    decreases rest.len(),
{
    if rest.len() == 0 {
        if current.len() > 0
            && !(current.len() == 1 && current[0] == DOT)
            && !(current.len() == 2 && current[0] == DOT && current[1] == DOT)
        {
            assert(spec_component_is_normal_seq(current));
        }
    } else if rest[0] == SLASH {
        if current.len() > 0
            && !(current.len() == 1 && current[0] == DOT)
            && !(current.len() == 2 && current[0] == DOT && current[1] == DOT)
        {
            assert(spec_component_is_normal_seq(current));
        }
        let step = spec_process_component(current, stack);
        if step.0 {
            lemma_process_bytes_preserves_normality(
                rest.subrange(1, rest.len() as int),
                step.1,
                Seq::<u8>::empty(),
            );
        }
    } else {
        lemma_process_bytes_preserves_normality(
            rest.subrange(1, rest.len() as int),
            stack,
            current.push(rest[0]),
        );
    }
}

pub proof fn lemma_process_bytes_total(
    rest: Seq<u8>,
    stack: Seq<Seq<u8>>,
    current: Seq<u8>,
)
    requires
        spec_has_no_null_seq(rest),
        spec_stack_is_normal_seq(stack),
        forall|i: int| 0 <= i < current.len() ==> #[trigger] current[i] != SLASH && current[i] != 0,
    ensures
        spec_process_bytes(rest, stack, current).0,
    decreases rest.len(),
{
    if rest.len() == 0 {
        assert(spec_process_component(current, stack).0);
    } else if rest[0] == SLASH {
        assert(spec_process_component(current, stack).0);
        lemma_process_bytes_total(
            rest.subrange(1, rest.len() as int),
            spec_process_component(current, stack).1,
            Seq::<u8>::empty(),
        );
    } else {
        assert(rest[0] != 0);
        assert forall|i: int| 0 <= i < current.push(rest[0]).len()
            implies #[trigger] current.push(rest[0])[i] != SLASH && current.push(rest[0])[i] != 0 by {
            if i < current.len() {
                assert(current.push(rest[0])[i] == current[i]);
            } else {
                assert(i == current.len());
                assert(current.push(rest[0])[i] == rest[0]);
            }
        };
        lemma_process_bytes_total(
            rest.subrange(1, rest.len() as int),
            stack,
            current.push(rest[0]),
        );
    }
}

pub proof fn lemma_process_bytes_append_prefix(
    prefix: Seq<u8>,
    rest: Seq<u8>,
    stack: Seq<Seq<u8>>,
    current: Seq<u8>,
)
    requires
        forall|i: int| 0 <= i < prefix.len() ==> #[trigger] prefix[i] != SLASH,
    ensures
        spec_process_bytes(prefix + rest, stack, current)
            == spec_process_bytes(rest, stack, current + prefix),
    decreases prefix.len(),
{
    if prefix.len() > 0 {
        assert((prefix + rest)[0] == prefix[0]);
        assert(
            (prefix + rest).subrange(1, (prefix + rest).len() as int)
                == prefix.subrange(1, prefix.len() as int) + rest
        );
        assert(current + prefix == current.push(prefix[0]) + prefix.subrange(1, prefix.len() as int)) by {
            assert(prefix == seq![prefix[0]] + prefix.subrange(1, prefix.len() as int));
        };
        assert forall|i: int| 0 <= i < prefix.subrange(1, prefix.len() as int).len()
            implies #[trigger] prefix.subrange(1, prefix.len() as int)[i] != SLASH by {
            assert(0 <= i < prefix.subrange(1, prefix.len() as int).len());
            assert(prefix.subrange(1, prefix.len() as int)[i] == prefix[i + 1]);
        };
        lemma_process_bytes_append_prefix(
            prefix.subrange(1, prefix.len() as int),
            rest,
            stack,
            current.push(prefix[0]),
        );
    }
}

pub proof fn lemma_process_render_relative_identity(stack: Seq<Seq<u8>>, acc: Seq<Seq<u8>>)
    requires spec_stack_is_normal_seq(stack), spec_stack_is_normal_seq(acc),
    ensures spec_process_bytes(spec_render_relative(stack), acc, Seq::<u8>::empty()) == (true, acc + stack),
    decreases stack.len(),
{
    if stack.len() == 0 {
        assert(spec_process_bytes(Seq::<u8>::empty(), acc, Seq::<u8>::empty()) == (true, acc));
    } else {
        let head = stack[0];
        let tail = stack.subrange(1, stack.len() as int);
        let rest = if tail.len() == 0 {
            Seq::<u8>::empty()
        } else {
            seq![SLASH] + spec_render_relative(tail)
        };
        assert(spec_render_relative(stack) == head + rest);
        assert forall|i: int| 0 <= i < head.len() implies #[trigger] head[i] != SLASH by {
            assert(spec_component_is_normal_seq(head));
        };
        lemma_process_bytes_append_prefix(head, rest, acc, Seq::<u8>::empty());
        lemma_process_component_normal(head, acc);
        assert(acc + stack == acc.push(head) + tail) by {
            assert(stack == seq![head] + tail);
        };
        if tail.len() == 0 {
            assert(spec_process_bytes(rest, acc, head) == (true, acc.push(head)));
        } else {
            assert(rest == seq![SLASH] + spec_render_relative(tail));
            assert(rest[0] == SLASH);
            assert(rest.subrange(1, rest.len() as int) == spec_render_relative(tail));
            assert(
                spec_process_bytes(rest, acc, head)
                    == spec_process_bytes(
                        spec_render_relative(tail),
                        acc.push(head),
                        Seq::<u8>::empty()
                    )
            ) by {
                assert(spec_process_component(head, acc) == (true, acc.push(head)));
            };
            lemma_process_render_relative_identity(tail, acc.push(head));
        }
    }
}

pub proof fn lemma_process_component_empty_noop(stack: Seq<Seq<u8>>)
    ensures spec_process_component(Seq::<u8>::empty(), stack) == (true, stack),
{
}

pub proof fn lemma_process_bytes_leading_slash(rest: Seq<u8>, stack: Seq<Seq<u8>>)
    ensures
        spec_process_bytes(seq![SLASH] + rest, stack, Seq::<u8>::empty())
            == spec_process_bytes(rest, stack, Seq::<u8>::empty()),
{
    lemma_process_component_empty_noop(stack);
    assert((seq![SLASH] + rest)[0] == SLASH);
    assert((seq![SLASH] + rest).subrange(1, (seq![SLASH] + rest).len() as int) == rest);
    assert(
        spec_process_bytes(seq![SLASH] + rest, stack, Seq::<u8>::empty())
            == spec_process_bytes(rest, stack, Seq::<u8>::empty())
    ) by {
        assert(spec_process_component(Seq::<u8>::empty(), stack) == (true, stack));
    };
}

pub proof fn lemma_process_render_path_identity(starts_with_slash: bool, stack: Seq<Seq<u8>>)
    requires spec_stack_is_normal_seq(stack),
    ensures
        spec_process_bytes(
            spec_render_path(starts_with_slash, stack),
            Seq::<Seq<u8>>::empty(),
            Seq::<u8>::empty(),
        ) == (true, stack),
{
    if starts_with_slash {
        if stack.len() == 0 {
            assert(spec_render_path(true, stack) == seq![SLASH]);
            lemma_process_bytes_leading_slash(Seq::<u8>::empty(), Seq::<Seq<u8>>::empty());
        } else {
            assert(spec_render_path(true, stack) == seq![SLASH] + spec_render_relative(stack));
            lemma_process_bytes_leading_slash(spec_render_relative(stack), Seq::<Seq<u8>>::empty());
            lemma_process_render_relative_identity(stack, Seq::<Seq<u8>>::empty());
        }
    } else {
        lemma_process_render_relative_identity(stack, Seq::<Seq<u8>>::empty());
    }
}

pub proof fn lemma_normalize_absolute_rendered_path_identity(stack: Seq<Seq<u8>>)
    requires spec_stack_is_normal_seq(stack),
    ensures
        spec_normalize_path_bytes(spec_render_path(true, stack))
            == (true, spec_render_path(true, stack)),
{
    let rendered = spec_render_path(true, stack);
    lemma_render_path_has_no_null(true, stack);
    lemma_process_render_path_identity(true, stack);
    assert(spec_has_no_null_seq(rendered));
    assert(spec_process_bytes(rendered, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()) == (true, stack));
    assert(spec_normalize_path_bytes(rendered) == (true, rendered)) by {
        assert(rendered.len() > 0);
        assert(rendered[0] == SLASH);
        assert(spec_process_bytes(rendered, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()) == (true, stack));
    };
}

/// V9: normalization is idempotent.
pub proof fn lemma_normalize_idempotent(path: Seq<u8>)
    ensures
        spec_normalize_path_bytes(path).0
            ==> spec_normalize_path_bytes(spec_normalize_path_bytes(path).1)
                == spec_normalize_path_bytes(path),
{
    if spec_has_no_null_seq(path) {
        let processed = spec_process_bytes(path, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty());
        if (path.len() > 0 && path[0] == SLASH) || processed.1.len() > 0 {
            lemma_process_bytes_total(path, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty());
            lemma_process_bytes_preserves_normality(path, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty());
            assert(processed.0);
            assert(spec_stack_is_normal_seq(processed.1));
            lemma_normalize_absolute_rendered_path_identity(processed.1);
            assert(spec_normalize_path_bytes(path) == (true, spec_render_path(true, processed.1)));
        }
    }
}

pub open spec fn spec_join_prefix(
    starts_with_slash: bool,
    stack: &Vec<Vec<u8>>,
    upto: int,
) -> Seq<u8>
    recommends 0 <= upto <= stack.len(),
    decreases upto,
{
    if upto <= 0 {
        if starts_with_slash {
            seq![SLASH]
        } else {
            Seq::<u8>::empty()
        }
    } else if upto == 1 {
        spec_join_prefix(starts_with_slash, stack, 0) + stack[0]@
    } else {
        spec_join_prefix(starts_with_slash, stack, upto - 1)
            + seq![SLASH]
            + stack[upto - 1]@
    }
}

/// Count the number of components in a '/'-separated path.
/// Used as a loop bound for Verus termination proofs.
pub fn count_components(path: &Vec<u8>) -> (result: usize)
    ensures result <= path.len() + 1,
{
    if path.len() == 0 {
        return 1;
    }
    let mut count: usize = 1;
    let mut i: usize = 0;
    while i < path.len()
        invariant
            0 <= i <= path.len(),
            1 <= count <= i + 1,
        decreases path.len() - i,
    {
        if path[i] == SLASH {
            if count < path.len() {
                count = count + 1;
            }
        }
        i = i + 1;
    }
    count
}

pub proof fn lemma_component_has_no_dotdot(comp: &Vec<u8>)
    requires spec_component_is_normal(comp),
    ensures spec_no_dotdot_component_seq(comp@),
{
    assert forall|i: int| 0 <= i < comp.len() - 1 implies
        !(
            #[trigger] comp[i] == DOT
            && comp[i + 1] == DOT
            && (i == 0 || comp[i - 1] == SLASH)
            && (i + 2 >= comp.len() || comp[i + 2] == SLASH)
        )
    by {
        if comp[i] == DOT
            && comp[i + 1] == DOT
            && (i == 0 || comp[i - 1] == SLASH)
            && (i + 2 >= comp.len() || comp[i + 2] == SLASH)
        {
            if i > 0 {
                assert(comp[i - 1] != SLASH);
                assert(false);
            }
            assert(i == 0);
            if i + 2 < comp.len() {
                assert(comp[i + 2] != SLASH);
                assert(false);
            }
            assert(i + 2 >= comp.len());
            assert(comp.len() == 2);
            assert(comp[0] == DOT && comp[1] == DOT);
            assert(false);
        }
    };
}

pub proof fn lemma_join_prefix_step_has_no_dotdot(
    starts_with_slash: bool,
    stack: &Vec<Vec<u8>>,
    upto: int,
)
    requires
        0 <= upto < stack.len(),
        spec_stack_is_normal(stack),
        spec_no_dotdot_component_seq(spec_join_prefix(starts_with_slash, stack, upto)),
    ensures
        spec_no_dotdot_component_seq(spec_join_prefix(starts_with_slash, stack, upto + 1)),
{
    let prev = spec_join_prefix(starts_with_slash, stack, upto);
    let comp = &stack[upto];
    assert(spec_stack_is_normal_seq(stack.deep_view()));
    assert(stack.deep_view()[upto] == comp@);
    assert(spec_component_is_normal_seq(comp@));
    assert(spec_component_is_normal(comp));
    lemma_component_has_no_dotdot(comp);

    if upto == 0 {
        assert forall|i: int| 0 <= i < spec_join_prefix(starts_with_slash, stack, 1).len() - 1
            implies !(
                #[trigger] spec_join_prefix(starts_with_slash, stack, 1)[i] == DOT
                && spec_join_prefix(starts_with_slash, stack, 1)[i + 1] == DOT
                && (i == 0 || spec_join_prefix(starts_with_slash, stack, 1)[i - 1] == SLASH)
                && (i + 2 >= spec_join_prefix(starts_with_slash, stack, 1).len()
                    || spec_join_prefix(starts_with_slash, stack, 1)[i + 2] == SLASH)
            )
        by {
            if starts_with_slash {
                assert(spec_join_prefix(starts_with_slash, stack, 1)[0] == SLASH);
            } else {
                assert(spec_join_prefix(starts_with_slash, stack, 1) == comp@);
            }
        };
        return;
    }

    assert forall|i: int|
        0 <= i < spec_join_prefix(starts_with_slash, stack, upto + 1).len() - 1 implies
        !(
            #[trigger] spec_join_prefix(starts_with_slash, stack, upto + 1)[i] == DOT
            && spec_join_prefix(starts_with_slash, stack, upto + 1)[i + 1] == DOT
            && (i == 0 || spec_join_prefix(starts_with_slash, stack, upto + 1)[i - 1] == SLASH)
            && (i + 2 >= spec_join_prefix(starts_with_slash, stack, upto + 1).len()
                || spec_join_prefix(starts_with_slash, stack, upto + 1)[i + 2] == SLASH)
        )
    by {
        let new = spec_join_prefix(starts_with_slash, stack, upto + 1);
        let sep = prev.len();
        let comp_start = prev.len() + 1;

        if new[i] == DOT
            && new[i + 1] == DOT
            && (i == 0 || new[i - 1] == SLASH)
            && (i + 2 >= new.len() || new[i + 2] == SLASH)
        {
            if i < prev.len() {
                if i + 1 < prev.len() {
                    assert(prev[i] == new[i]);
                    assert(prev[i + 1] == new[i + 1]);
                    if i > 0 {
                        assert(prev[i - 1] == new[i - 1]);
                    }
                    if i + 2 < prev.len() {
                        assert(prev[i + 2] == new[i + 2]);
                    }
                    assert(false);
                }
                assert(i == prev.len() - 1);
                assert(new[i + 1] == SLASH);
                assert(false);
            }

            if i == sep {
                assert(new[i] == SLASH);
                assert(false);
            }

            assert(i >= comp_start);
            let j = i - comp_start;
            assert(0 <= j < comp.len() - 1);
            assert(comp[j] == DOT);
            assert(comp[j + 1] == DOT);
            if j > 0 {
                assert(comp[j - 1] != SLASH);
                assert(false);
            }
            assert(j == 0);
            if j + 2 < comp.len() {
                assert(comp[j + 2] != SLASH);
                assert(false);
            }
            assert(j + 2 >= comp.len());
            assert(comp.len() == 2);
            assert(comp[0] == DOT && comp[1] == DOT);
            assert(false);
        }
    };
}

pub proof fn lemma_render_relative_push_last(prefix: Seq<Seq<u8>>, comp: Seq<u8>)
    ensures
        prefix.len() == 0 ==> spec_render_relative(prefix.push(comp)) == comp,
        prefix.len() > 0 ==> spec_render_relative(prefix.push(comp)) == spec_render_relative(prefix) + seq![SLASH] + comp,
    decreases prefix.len(),
{
    if prefix.len() == 0 {
    } else if prefix.len() == 1 {
        assert(prefix.push(comp).len() == 2);
        assert(prefix.push(comp)[0] == prefix[0]);
        assert(prefix.push(comp).subrange(1, prefix.push(comp).len() as int) == seq![comp]);
        assert(spec_render_relative(seq![comp]) == comp);
        assert(spec_render_relative(prefix.push(comp)) == prefix[0] + seq![SLASH] + comp);
        assert(spec_render_relative(prefix) == prefix[0]);
    } else {
        let tail = prefix.subrange(1, prefix.len() as int);
        lemma_render_relative_push_last(tail, comp);
        assert(prefix.push(comp)[0] == prefix[0]);
        assert(prefix.push(comp).subrange(1, prefix.push(comp).len() as int) == tail.push(comp));
        assert(spec_render_relative(prefix.push(comp)) == prefix[0] + seq![SLASH] + spec_render_relative(tail.push(comp)));
        assert(spec_render_relative(prefix) == prefix[0] + seq![SLASH] + spec_render_relative(tail));
    }
}

pub proof fn lemma_join_prefix_matches_render_path(
    starts_with_slash: bool,
    stack: &Vec<Vec<u8>>,
    upto: int,
)
    requires 0 <= upto <= stack.len(),
    ensures
        spec_join_prefix(starts_with_slash, stack, upto)
            == spec_render_path(starts_with_slash, stack.deep_view().subrange(0, upto)),
    decreases upto,
{
    if upto <= 0 {
    } else if upto == 1 {
        assert(stack.deep_view().subrange(0, upto).len() == 1);
        assert(stack.deep_view().subrange(0, upto)[0] == stack[0]@);
        assert(stack.deep_view().subrange(0, upto) == seq![stack[0]@]);
        if starts_with_slash {
            assert(spec_join_prefix(starts_with_slash, stack, 0) == seq![SLASH]);
            assert(spec_join_prefix(starts_with_slash, stack, upto) == spec_join_prefix(starts_with_slash, stack, 0) + stack[0]@);
            assert(spec_join_prefix(starts_with_slash, stack, upto) == seq![SLASH] + stack[0]@);
            assert(spec_render_path(starts_with_slash, stack.deep_view().subrange(0, upto)) == seq![SLASH] + stack[0]@);
        } else {
            assert(spec_join_prefix(starts_with_slash, stack, 0) == Seq::<u8>::empty());
            assert(spec_join_prefix(starts_with_slash, stack, upto) == spec_join_prefix(starts_with_slash, stack, 0) + stack[0]@);
            assert(spec_join_prefix(starts_with_slash, stack, upto) == stack[0]@);
            assert(spec_render_path(starts_with_slash, stack.deep_view().subrange(0, upto)) == stack[0]@);
        }
    } else {
        lemma_join_prefix_matches_render_path(starts_with_slash, stack, upto - 1);
        let prefix = stack.deep_view().subrange(0, upto - 1);
        let last = stack[upto - 1]@;
        assert(stack.deep_view().subrange(0, upto).len() == prefix.push(last).len());
        assert forall|i: int| 0 <= i < stack.deep_view().subrange(0, upto).len()
            implies #[trigger] stack.deep_view().subrange(0, upto)[i] == prefix.push(last)[i] by {
            if i < prefix.len() {
                assert(stack.deep_view().subrange(0, upto)[i] == prefix[i]);
            } else {
                assert(i == prefix.len());
                assert(stack.deep_view().subrange(0, upto)[i] == last);
            }
        };
        assert(stack.deep_view().subrange(0, upto) == prefix.push(last));
        lemma_render_relative_push_last(prefix, last);
        assert(prefix.len() > 0);
        if starts_with_slash {
            assert(
                spec_render_path(starts_with_slash, prefix.push(last))
                    == spec_render_path(starts_with_slash, prefix) + seq![SLASH] + last
            );
        } else {
            assert(
                spec_render_path(starts_with_slash, prefix.push(last))
                    == spec_render_path(starts_with_slash, prefix) + seq![SLASH] + last
            );
        }
    }
}

/// Apply the currently buffered component to the normalized stack.
pub fn apply_component(current: &Vec<u8>, stack: &mut Vec<Vec<u8>>) -> (ok: bool)
    requires
        spec_stack_is_normal_seq(old(stack).deep_view()),
        forall|i: int| 0 <= i < current.len() ==> #[trigger] current[i] != SLASH && current[i] != 0,
    ensures
        ok == spec_process_component(current@, old(stack).deep_view()).0,
        stack.deep_view() == spec_process_component(current@, old(stack).deep_view()).1,
        ok ==> spec_stack_is_normal_seq(stack.deep_view()),
{
    if current.len() == 0 {
        return true;
    }
    if current.len() == 1 && current[0] == DOT {
        return true;
    }
    if current.len() == 2 && current[0] == DOT && current[1] == DOT {
        if stack.len() > 0 {
            let _ = stack.pop();
            proof {
                assert forall|j: int| 0 <= j < stack.deep_view().len()
                    implies #[trigger] stack.deep_view()[j] == old(stack).deep_view()[j] by {
                    assert(stack@[j] == old(stack)@[j]);
                    assert(stack.deep_view()[j] == old(stack).deep_view()[j]);
                };
            }
        } else {
            proof {
                assert(stack.deep_view() == old(stack).deep_view());
            }
        }
        return true;
    }

    let mut comp: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < current.len()
        invariant
            0 <= i <= current.len(),
            comp@ == current@.subrange(0, i as int),
        decreases current.len() - i,
    {
        comp.push(current[i]);
        i = i + 1;
    }
    proof {
        assert(spec_component_is_normal_seq(current@));
        assert(comp@ == current@);
    }
    stack.push(comp);
    proof {
        assert(stack@ == old(stack)@.push(comp));
        assert(stack.deep_view().len() == old(stack).deep_view().len() + 1);
        assert forall|j: int| 0 <= j < stack.deep_view().len()
            implies #[trigger] stack.deep_view()[j] == old(stack).deep_view().push(current@)[j] by {
            if j < old(stack).deep_view().len() {
                assert(stack@[j] == old(stack)@[j]);
                assert(stack.deep_view()[j] == old(stack).deep_view()[j]);
            } else {
                assert(j == old(stack).deep_view().len());
                assert(stack@[j] == comp);
                assert(stack.deep_view()[j] == comp@);
                assert(comp@ == current@);
            }
        };
    }
    true
}

/// Normalize a path by resolving "." and ".." components.
///
/// Returns (success, normalized_bytes).
/// success=false only for null bytes or when a relative input collapses to an
/// empty normalized path.
///
/// This is a byte-level equivalent of production `normalize_decoded_path`.
pub fn normalize_path_bytes(path: &Vec<u8>) -> (result: (bool, Vec<u8>))
    ensures
        result.0 == spec_normalize_path_bytes(path@).0,
        result.1@ == spec_normalize_path_bytes(path@).1,
        result.0 ==> spec_no_dotdot_component(&result.1),
{
    // Check for null bytes up front so the remaining model is total.
    let mut k: usize = 0;
    while k < path.len()
        invariant
            0 <= k <= path.len(),
            forall|j: int| 0 <= j < k ==> #[trigger] path[j] != 0,
        decreases path.len() - k,
    {
        if path[k] == 0 {
            proof {
                assert(!spec_has_no_null_seq(path@));
                assert(spec_normalize_path_bytes(path@) == (false, Seq::<u8>::empty()));
            }
            return (false, Vec::new());
        }
        k = k + 1;
    }

    let starts_with_slash: bool = path.len() > 0 && path[0] == SLASH;

    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    proof {
        assert(stack.deep_view() == Seq::<Seq<u8>>::empty());
        assert(current@ == Seq::<u8>::empty());
        assert(path@.subrange(0, path.len() as int) == path@);
        assert(
            spec_process_bytes(
                path@.subrange(0, path.len() as int),
                stack.deep_view(),
                current@
            ) == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty())
        );
    }
    let mut i: usize = 0;
    while i < path.len()
        invariant
            0 <= i <= path.len(),
            spec_has_no_null(path),
            spec_stack_is_normal_seq(stack.deep_view()),
            forall|j: int| 0 <= j < current.len() ==> #[trigger] current[j] != SLASH && current[j] != 0,
            spec_process_bytes(
                path@.subrange(i as int, path.len() as int),
                stack.deep_view(),
                current@,
            ) == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()),
        decreases path.len() - i,
    {
        let ghost rest = path@.subrange(i as int, path.len() as int);
        let ghost stack_before = stack.deep_view();
        let ghost current_before = current@;
        let b = path[i];

        if b == SLASH {
            let _ok = apply_component(&current, &mut stack);
            proof {
                assert(rest.len() > 0);
                assert(rest[0] == SLASH);
                assert(spec_process_component(current_before, stack_before).0);
                assert(stack.deep_view() == spec_process_component(current_before, stack_before).1);
                assert(rest.subrange(1, rest.len() as int) == path@.subrange(i as int + 1, path.len() as int));
                assert(
                    spec_process_bytes(
                        path@.subrange(i as int + 1, path.len() as int),
                        stack.deep_view(),
                        Seq::<u8>::empty()
                    ) == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty())
                ) by {
                    assert(spec_process_bytes(rest, stack_before, current_before) == spec_process_bytes(
                        rest.subrange(1, rest.len() as int),
                        spec_process_component(current_before, stack_before).1,
                        Seq::<u8>::empty()
                    ));
                };
            }
            current = Vec::new();
        } else {
            current.push(b);
            proof {
                assert(b != 0);
                assert(rest.len() > 0);
                assert(rest[0] == b);
                assert(rest.subrange(1, rest.len() as int) == path@.subrange(i as int + 1, path.len() as int));
                assert(stack.deep_view() == stack_before);
                assert(
                    spec_process_bytes(
                        path@.subrange(i as int + 1, path.len() as int),
                        stack.deep_view(),
                        current@
                    ) == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty())
                ) by {
                    assert(spec_process_bytes(rest, stack_before, current_before) == spec_process_bytes(
                        rest.subrange(1, rest.len() as int),
                        stack_before,
                        current_before.push(b)
                    ));
                };
                assert forall|j: int| 0 <= j < current.len() implies #[trigger] current[j] != SLASH && current[j] != 0 by {
                    if j < current_before.len() {
                        assert(current[j] == current_before[j]);
                    } else {
                        assert(j == current_before.len());
                        assert(current[j] == b);
                    }
                };
            }
        }

        i = i + 1;
    }

    let ghost stack_before = stack.deep_view();
    let ghost current_before = current@;
    let _ok = apply_component(&current, &mut stack);
    proof {
        assert(spec_process_component(current_before, stack_before).0);
        assert(spec_process_bytes(Seq::<u8>::empty(), stack_before, current_before) == spec_process_component(current_before, stack_before));
        assert(spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).0);
        assert(stack.deep_view() == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).1);
    }

    if !starts_with_slash && stack.len() == 0 {
        proof {
            assert(stack.deep_view().len() == 0);
            assert(spec_normalize_path_bytes(path@) == (false, Seq::<u8>::empty())) by {
                assert(spec_has_no_null_seq(path@));
                assert(spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).1.len() == 0);
                assert(stack.deep_view() == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).1);
            };
        }
        return (false, Vec::new());
    }

    // Reconstruct the engine's canonical absolute output from the normalized stack.
    let mut out: Vec<u8> = Vec::new();
    out.push(SLASH);
    let mut si: usize = 0;
    while si < stack.len()
        invariant
            0 <= si <= stack.len(),
            spec_stack_is_normal(&stack),
            out@ =~= spec_join_prefix(true, &stack, si as int),
            spec_no_dotdot_component_seq(out@),
        decreases stack.len() - si,
    {
        if si > 0 {
            out.push(SLASH);
        }
        let ref comp = stack[si];
        proof {
            assert(spec_stack_is_normal_seq(stack.deep_view()));
            assert(stack.deep_view()[si as int] == comp@);
            assert(spec_component_is_normal_seq(comp@));
            assert(spec_component_is_normal(comp));
        }
        let mut ci: usize = 0;
        while ci < comp.len()
            invariant
                0 <= ci <= comp.len(),
                spec_component_is_normal(comp),
                out@ =~=
                    if si > 0 {
                        spec_join_prefix(true, &stack, si as int)
                            + seq![SLASH]
                            + comp@.subrange(0, ci as int)
                    } else {
                        spec_join_prefix(true, &stack, si as int)
                            + comp@.subrange(0, ci as int)
                    },
            decreases comp.len() - ci,
        {
            out.push(comp[ci]);
            ci = ci + 1;
        }
        proof {
            lemma_join_prefix_step_has_no_dotdot(true, &stack, si as int);
        }
        si = si + 1;
    }

    proof {
        lemma_join_prefix_matches_render_path(true, &stack, stack.len() as int);
        assert(out@ == spec_join_prefix(true, &stack, stack.len() as int));
        assert(stack.deep_view().subrange(0, stack.len() as int) == stack.deep_view());
        assert(out@ == spec_render_path(true, stack.deep_view()));
        assert(spec_normalize_path_bytes(path@) == (true, out@)) by {
            assert(spec_has_no_null_seq(path@));
            assert(spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).0);
            assert(stack.deep_view() == spec_process_bytes(path@, Seq::<Seq<u8>>::empty(), Seq::<u8>::empty()).1);
            assert(starts_with_slash || stack.deep_view().len() > 0);
        };
    }

    (true, out)
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::path_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
