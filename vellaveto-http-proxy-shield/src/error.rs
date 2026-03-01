// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Shield HTTP proxy error types.

use thiserror::Error;

/// Errors from the shield HTTP proxy layer.
#[derive(Debug, Error)]
pub enum ShieldProxyError {
    /// Traffic padding configuration error.
    #[error("traffic padding error: {0}")]
    TrafficPadding(String),

    /// Request splitting error.
    #[error("request splitting error: {0}")]
    RequestSplitting(String),

    /// Proxy transport error.
    #[error("transport error: {0}")]
    Transport(String),
}
