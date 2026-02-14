//! Compliance framework types shared across crates.
//!
//! These types live in vellaveto-types (leaf crate) so both vellaveto-config
//! and vellaveto-audit can reference them without circular dependencies.

use serde::{Deserialize, Serialize};

// ── EU AI Act Risk Classification ────────────────────────────────────────────

/// Risk classification per EU AI Act Article 6.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiActRiskClass {
    /// Minimal risk — no obligations beyond transparency.
    Minimal,
    /// Limited risk — transparency obligations only (Art 50).
    #[default]
    Limited,
    /// High-risk — full Chapter III obligations (Art 6–15, 43).
    HighRisk,
    /// Unacceptable risk — prohibited (Art 5).
    Unacceptable,
}

impl std::fmt::Display for AiActRiskClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "Minimal"),
            Self::Limited => write!(f, "Limited"),
            Self::HighRisk => write!(f, "High-Risk"),
            Self::Unacceptable => write!(f, "Unacceptable"),
        }
    }
}

// ── SOC 2 Trust Services Category ────────────────────────────────────────────

/// SOC 2 Trust Services Category (TSC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustServicesCategory {
    /// CC1: Control Environment
    CC1,
    /// CC2: Communication and Information
    CC2,
    /// CC3: Risk Assessment
    CC3,
    /// CC4: Monitoring Activities
    CC4,
    /// CC5: Control Activities
    CC5,
    /// CC6: Logical and Physical Access Controls
    CC6,
    /// CC7: System Operations
    CC7,
    /// CC8: Change Management
    CC8,
    /// CC9: Risk Mitigation
    CC9,
}

impl std::fmt::Display for TrustServicesCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CC1 => write!(f, "CC1: Control Environment"),
            Self::CC2 => write!(f, "CC2: Communication and Information"),
            Self::CC3 => write!(f, "CC3: Risk Assessment"),
            Self::CC4 => write!(f, "CC4: Monitoring Activities"),
            Self::CC5 => write!(f, "CC5: Control Activities"),
            Self::CC6 => write!(f, "CC6: Logical and Physical Access Controls"),
            Self::CC7 => write!(f, "CC7: System Operations"),
            Self::CC8 => write!(f, "CC8: Change Management"),
            Self::CC9 => write!(f, "CC9: Risk Mitigation"),
        }
    }
}
