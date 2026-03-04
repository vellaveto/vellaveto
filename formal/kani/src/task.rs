// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Task lifecycle verification extracted from
//! `vellaveto-mcp/src/task_state.rs`.
//!
//! Pure predicates for task state transitions, capacity enforcement,
//! and cancel authorization.
//!
//! # Verified Properties (K56-K58)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K56 | Terminal state → no further transitions |
//! | K57 | At max tasks → reject new registration |
//! | K58 | Self-cancel required + different requester → reject |
//!
//! # Production Correspondence
//!
//! - `is_terminal` ↔ `vellaveto-types` TrackedTask::is_terminal
//! - `check_capacity` ↔ `vellaveto-mcp/src/task_state.rs:137-153`
//! - `can_cancel` ↔ `vellaveto-mcp/src/task_state.rs:257-283`

/// Task states matching the production MCP task lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Submitted,
    Working,
    InputNeeded,
    Completed,
    Failed,
    Canceled,
    Expired,
}

/// Maximum tracked tasks (mirrors production constant).
pub const MAX_TRACKED_TASKS: usize = 100_000;

/// Check if a task state is terminal (no further transitions allowed).
///
/// Verbatim from production `TrackedTask::is_terminal`.
pub fn is_terminal(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Expired
    )
}

/// Check if a state transition is valid.
///
/// Terminal states cannot transition to any other state.
pub fn can_transition(from: TaskState, _to: TaskState) -> bool {
    !is_terminal(from)
}

/// Check capacity for new task registration.
///
/// Returns true if registration is allowed.
pub fn check_capacity(current_tasks: usize, terminal_count: usize) -> bool {
    if current_tasks < MAX_TRACKED_TASKS {
        return true;
    }
    // After evicting terminal tasks, check again
    let remaining = current_tasks.saturating_sub(terminal_count);
    remaining < MAX_TRACKED_TASKS
}

/// Cancel authorization check.
///
/// Parameters:
/// - `require_self_cancel`: config flag requiring creator-only cancel
/// - `creator`: the agent that created the task (None if unknown)
/// - `requester`: the agent requesting cancellation (None if unknown)
/// - `allow_list_contains_requester`: whether requester is in allow_cancellation list
///
/// Returns true if cancellation is authorized.
pub fn can_cancel(
    require_self_cancel: bool,
    creator: Option<&str>,
    requester: Option<&str>,
    allow_list_contains_requester: bool,
) -> bool {
    if require_self_cancel {
        match (creator, requester) {
            (Some(c), Some(r)) => c == r,
            (None, _) => true,      // No creator recorded, allow anyone
            (Some(_), None) => false, // Creator recorded but no requester
        }
    } else {
        match requester {
            Some(_) => allow_list_contains_requester,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_states() {
        assert!(is_terminal(TaskState::Completed));
        assert!(is_terminal(TaskState::Failed));
        assert!(is_terminal(TaskState::Canceled));
        assert!(is_terminal(TaskState::Expired));
    }

    #[test]
    fn test_non_terminal_states() {
        assert!(!is_terminal(TaskState::Submitted));
        assert!(!is_terminal(TaskState::Working));
        assert!(!is_terminal(TaskState::InputNeeded));
    }

    #[test]
    fn test_terminal_no_transition() {
        assert!(!can_transition(TaskState::Completed, TaskState::Working));
        assert!(!can_transition(TaskState::Failed, TaskState::Submitted));
    }

    #[test]
    fn test_non_terminal_can_transition() {
        assert!(can_transition(TaskState::Working, TaskState::Completed));
        assert!(can_transition(TaskState::Submitted, TaskState::Working));
    }

    #[test]
    fn test_capacity_at_max_no_terminals() {
        assert!(!check_capacity(MAX_TRACKED_TASKS, 0));
    }

    #[test]
    fn test_capacity_at_max_with_terminals() {
        assert!(check_capacity(MAX_TRACKED_TASKS, 1));
    }

    #[test]
    fn test_self_cancel_same_agent() {
        assert!(can_cancel(true, Some("agent-1"), Some("agent-1"), false));
    }

    #[test]
    fn test_self_cancel_different_agent() {
        assert!(!can_cancel(true, Some("agent-1"), Some("agent-2"), false));
    }

    #[test]
    fn test_self_cancel_no_requester() {
        assert!(!can_cancel(true, Some("agent-1"), None, false));
    }

    #[test]
    fn test_self_cancel_no_creator() {
        assert!(can_cancel(true, None, Some("agent-2"), false));
    }
}
