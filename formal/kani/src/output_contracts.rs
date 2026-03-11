// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Extracted semantic output-contract rules.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextChannel {
    Data,
    FreeText,
    Url,
    CommandLike,
    ToolOutput,
    ResourceContent,
    ApprovalPrompt,
    Memory,
}

pub const fn violates_output_contract(
    expected: ContextChannel,
    observed: ContextChannel,
) -> bool {
    match expected {
        ContextChannel::Data => matches!(
            observed,
            ContextChannel::FreeText
                | ContextChannel::Url
                | ContextChannel::CommandLike
                | ContextChannel::ApprovalPrompt
        ),
        ContextChannel::FreeText | ContextChannel::ToolOutput => matches!(
            observed,
            ContextChannel::Url | ContextChannel::CommandLike | ContextChannel::ApprovalPrompt
        ),
        ContextChannel::ResourceContent | ContextChannel::Url => {
            matches!(
                observed,
                ContextChannel::CommandLike | ContextChannel::ApprovalPrompt
            )
        }
        ContextChannel::CommandLike
        | ContextChannel::ApprovalPrompt
        | ContextChannel::Memory => false,
    }
}
