// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Consumer shield HTTP proxy layer.
//!
//! Traffic analysis resistance, request padding, header stripping,
//! and advanced privacy features for the consumer shield.

pub mod error;
pub mod traffic_padding;

pub use error::ShieldProxyError;
pub use traffic_padding::{TrafficPaddingConfig, PRIVACY_STRIP_HEADERS};
