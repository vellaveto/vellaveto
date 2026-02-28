//! Consumer shield HTTP proxy layer.
//!
//! Traffic analysis resistance, request padding, header stripping,
//! and advanced privacy features for the consumer shield.

pub mod error;
pub mod traffic_padding;

pub use error::ShieldProxyError;
pub use traffic_padding::{TrafficPaddingConfig, PRIVACY_STRIP_HEADERS};
