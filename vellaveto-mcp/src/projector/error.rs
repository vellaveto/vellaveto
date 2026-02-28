// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

#[derive(Debug, thiserror::Error)]
pub enum ProjectorError {
    #[error("unsupported model family: {0:?}")]
    UnsupportedFamily(vellaveto_types::ModelFamily),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}
