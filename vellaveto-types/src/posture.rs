// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

use serde::{Deserialize, Serialize};

/// Scope attached to posture responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureScope {
    /// Scope kind (`global` or `tenant`).
    pub kind: String,
    /// Tenant identifier when the response is tenant-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

impl PostureScope {
    /// Build a global posture scope.
    pub fn global() -> Self {
        Self {
            kind: "global".to_string(),
            tenant: None,
        }
    }

    /// Build a tenant-scoped posture scope.
    pub fn tenant(tenant: impl Into<String>) -> Self {
        Self {
            kind: "tenant".to_string(),
            tenant: Some(tenant.into()),
        }
    }

    /// Return true when this scope is global.
    pub fn is_global(&self) -> bool {
        self.tenant.is_none()
    }
}

/// Per-category score within the aggregate security posture response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureCategoryScore {
    /// Category identifier (for example: governance, runtime, supply_chain).
    pub name: String,
    /// Aggregate score for the category, in percent.
    pub score_percent: f32,
    /// Number of framework inputs used to compute the category.
    pub inputs: usize,
}

/// Coverage or readiness score for a single framework in the posture view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureFrameworkScore {
    /// Framework display name.
    pub name: String,
    /// Coverage or readiness score for the framework, in percent.
    pub score_percent: f32,
    /// Whether the framework-specific reporting is enabled in the current config.
    pub enabled: bool,
}

/// High-level security posture score for the active Vellaveto deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPostureScore {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the posture score.
    pub scope: PostureScope,
    /// Aggregate score across the category breakdown.
    pub overall_score_percent: f32,
    /// Qualitative tier derived from the overall score.
    pub tier: String,
    /// Category breakdown used to compute the overall score.
    pub categories: Vec<PostureCategoryScore>,
    /// Framework-level inputs that feed the posture score.
    pub frameworks: Vec<PostureFrameworkScore>,
}

/// A normalized coverage summary for a framework in the control matrix view.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageSummary {
    /// Framework display name.
    pub framework: String,
    /// Total controls/techniques/items for the framework.
    pub total_items: usize,
    /// Covered controls/techniques/items for the framework.
    pub covered_items: usize,
    /// Percent of covered items in the framework.
    pub coverage_percent: f32,
}

/// Consolidated control coverage matrix used by posture dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCoverageMatrix {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the control coverage matrix.
    pub scope: PostureScope,
    /// Weighted aggregate coverage across the listed frameworks.
    pub overall_coverage_percent: f32,
    /// Per-framework control coverage summaries.
    pub frameworks: Vec<ControlCoverageSummary>,
    /// Short operator-facing notes that explain how to interpret the matrix.
    pub highlights: Vec<String>,
}

/// A normalized remediation gap in the posture API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureGap {
    /// Framework where the gap appears.
    pub framework: String,
    /// Gap identifier within the framework.
    pub item_id: String,
    /// Severity label (for example: High, Medium).
    pub severity: String,
    /// Human-readable description of the gap.
    pub description: String,
}

/// Prioritized remediation gaps derived from the broader control matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureGapReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Scope used to generate the remediation queue.
    pub scope: PostureScope,
    /// Weighted aggregate coverage across the sources used in this report.
    pub overall_coverage_percent: f32,
    /// Highest-priority gaps to address.
    pub critical_gaps: Vec<PostureGap>,
    /// Actionable remediation guidance.
    pub recommendations: Vec<String>,
    /// A compact list of themes that need immediate attention.
    pub high_priority_focus_areas: Vec<String>,
}

/// Posture-focused export that combines a compliance evidence pack with the
/// current posture score and remediation focus areas.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureEvidencePackExport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Evidence pack framework identifier.
    pub framework: String,
    /// Scope used for the posture context.
    pub scope: PostureScope,
    /// Aggregate posture at export time.
    pub posture: SecurityPostureScore,
    /// Highest-priority remediation themes.
    pub high_priority_focus_areas: Vec<String>,
    /// Framework-specific evidence pack payload.
    pub evidence_pack: serde_json::Value,
}
