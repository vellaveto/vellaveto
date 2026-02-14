//! Compliance evidence generation API routes.
//!
//! Provides endpoints for EU AI Act, SOC 2, CoSAI, Adversa TOP 25, and
//! cross-framework gap analysis reporting. These read-only endpoints generate
//! reports at request time using registry-based classification (read-time,
//! not write-time).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::AppState;
use super::ErrorResponse;

// ── Query Parameters ─────────────────────────────────────────────────────────

/// Query parameters for the compliance status endpoint.
#[derive(Debug, Deserialize)]
pub struct ComplianceStatusQuery {
    /// Include NIST RMF coverage in status response.
    #[serde(default = "default_true")]
    pub include_nist: bool,
    /// Include ISO 27090 readiness in status response.
    #[serde(default = "default_true")]
    pub include_iso: bool,
}

fn default_true() -> bool {
    true
}

/// Query parameters for the SOC 2 evidence endpoint.
#[derive(Debug, Deserialize)]
pub struct Soc2EvidenceQuery {
    /// Filter to specific Trust Services Category.
    #[serde(default)]
    pub category: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/compliance/status` — Overall compliance posture.
///
/// Returns a summary of compliance readiness across all frameworks:
/// EU AI Act, SOC 2, NIST AI RMF, and ISO 27090.
#[tracing::instrument(name = "sentinel.compliance_status", skip(state))]
pub async fn compliance_status(
    State(state): State<AppState>,
    Query(params): Query<ComplianceStatusQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    // EU AI Act
    let eu_ai_act_status = if config.eu_ai_act.enabled {
        let registry = sentinel_audit::eu_ai_act::EuAiActRegistry::new();
        let report = registry.generate_assessment(
            config.eu_ai_act.risk_class,
            &config.eu_ai_act.deployer_name,
            &config.eu_ai_act.system_id,
        );
        Some(serde_json::json!({
            "enabled": true,
            "risk_class": config.eu_ai_act.risk_class,
            "compliance_percentage": report.compliance_percentage,
            "applicable_articles": report.applicable_articles,
            "compliant_articles": report.compliant_articles,
            "partial_articles": report.partial_articles,
        }))
    } else {
        Some(serde_json::json!({ "enabled": false }))
    };

    // SOC 2
    let soc2_status = if config.soc2.enabled {
        let registry = sentinel_audit::soc2::Soc2Registry::new();
        let report = registry.generate_evidence_report(
            &config.soc2.organization_name,
            &config.soc2.period_start,
            &config.soc2.period_end,
            &config.soc2.tracked_categories,
        );
        Some(serde_json::json!({
            "enabled": true,
            "overall_readiness": report.overall_readiness,
            "total_score": report.total_score,
            "max_score": report.max_score,
            "total_gaps": report.total_gaps,
        }))
    } else {
        Some(serde_json::json!({ "enabled": false }))
    };

    // NIST RMF (optional)
    let nist_status = if params.include_nist {
        let registry = sentinel_audit::nist_rmf::NistRmfRegistry::new();
        let report = registry.generate_report();
        Some(serde_json::json!({
            "overall_coverage": report.overall_coverage,
            "total_findings": report.findings.len(),
        }))
    } else {
        None
    };

    // ISO 27090 (optional)
    let iso_status = if params.include_iso {
        let registry = sentinel_audit::iso27090::Iso27090Registry::new();
        let assessment = registry.generate_assessment();
        Some(serde_json::json!({
            "overall_percentage": assessment.overall_percentage,
            "certification_ready": assessment.certification_ready,
        }))
    } else {
        None
    };

    let mut response = serde_json::json!({
        "eu_ai_act": eu_ai_act_status,
        "soc2": soc2_status,
    });

    if let Some(nist) = nist_status {
        response["nist_rmf"] = nist;
    }
    if let Some(iso) = iso_status {
        response["iso27090"] = iso;
    }

    Ok(Json(response))
}

/// `GET /api/compliance/eu-ai-act/report` — EU AI Act conformity assessment.
///
/// Generates a full conformity assessment report per Art 43 of the EU AI Act.
#[tracing::instrument(name = "sentinel.eu_ai_act_report", skip(state))]
pub async fn eu_ai_act_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    if !config.eu_ai_act.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "EU AI Act compliance is not enabled in configuration".to_string(),
            }),
        ));
    }

    let registry = sentinel_audit::eu_ai_act::EuAiActRegistry::new();
    let report = registry.generate_assessment(
        config.eu_ai_act.risk_class,
        &config.eu_ai_act.deployer_name,
        &config.eu_ai_act.system_id,
    );

    serde_json::to_value(&report)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to serialize EU AI Act report: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate report".to_string(),
                }),
            )
        })
}

/// `GET /api/compliance/soc2/evidence` — SOC 2 evidence collection.
///
/// Generates a SOC 2 evidence report with optional category filtering.
#[tracing::instrument(name = "sentinel.soc2_evidence", skip(state))]
pub async fn soc2_evidence(
    State(state): State<AppState>,
    Query(params): Query<Soc2EvidenceQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    if !config.soc2.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "SOC 2 compliance is not enabled in configuration".to_string(),
            }),
        ));
    }

    // Apply category filter from query param if present
    let tracked_categories = if let Some(ref cat_filter) = params.category {
        use sentinel_config::TrustServicesCategory;
        let parsed = match cat_filter.to_uppercase().as_str() {
            "CC1" => Some(TrustServicesCategory::CC1),
            "CC2" => Some(TrustServicesCategory::CC2),
            "CC3" => Some(TrustServicesCategory::CC3),
            "CC4" => Some(TrustServicesCategory::CC4),
            "CC5" => Some(TrustServicesCategory::CC5),
            "CC6" => Some(TrustServicesCategory::CC6),
            "CC7" => Some(TrustServicesCategory::CC7),
            "CC8" => Some(TrustServicesCategory::CC8),
            "CC9" => Some(TrustServicesCategory::CC9),
            _ => None,
        };
        if let Some(cat) = parsed {
            vec![cat]
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid category '{}'. Valid: CC1-CC9",
                        cat_filter
                    ),
                }),
            ));
        }
    } else {
        config.soc2.tracked_categories.clone()
    };

    let registry = sentinel_audit::soc2::Soc2Registry::new();
    let report = registry.generate_evidence_report(
        &config.soc2.organization_name,
        &config.soc2.period_start,
        &config.soc2.period_end,
        &tracked_categories,
    );

    serde_json::to_value(&report)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to serialize SOC 2 report: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate report".to_string(),
                }),
            )
        })
}

/// `GET /api/compliance/threat-coverage` — Threat framework coverage.
///
/// Returns coverage reports for MITRE ATLAS, CoSAI, and Adversa TOP 25
/// threat/vulnerability frameworks.
#[tracing::instrument(name = "sentinel.threat_coverage")]
pub async fn threat_coverage(
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let atlas = sentinel_audit::atlas::AtlasRegistry::new();
    let atlas_report = atlas.generate_coverage_report();

    let cosai = sentinel_audit::cosai::CosaiRegistry::new();
    let cosai_report = cosai.generate_coverage_report();

    let adversa = sentinel_audit::adversa_top25::AdversaTop25Registry::new();
    let adversa_report = adversa.generate_coverage_report();

    let response = serde_json::json!({
        "atlas": {
            "total_techniques": atlas_report.total_techniques,
            "covered": atlas_report.covered_techniques.len(),
            "coverage_percent": atlas_report.coverage_percent,
        },
        "cosai": {
            "total_categories": cosai_report.total_categories,
            "covered_categories": cosai_report.covered_categories,
            "total_threats": cosai_report.total_threats,
            "covered_threats": cosai_report.covered_threats.len(),
            "coverage_percent": cosai_report.coverage_percent,
        },
        "adversa_top25": {
            "total_vulnerabilities": adversa_report.total_vulnerabilities,
            "covered": adversa_report.covered_count,
            "coverage_percent": adversa_report.coverage_percent,
        },
    });

    Ok(Json(response))
}

/// `GET /api/compliance/gap-analysis` — Cross-framework gap analysis.
///
/// Generates a consolidated gap analysis across all 6 security frameworks
/// (ATLAS, NIST RMF, ISO 27090, EU AI Act, CoSAI, Adversa TOP 25).
#[tracing::instrument(name = "sentinel.gap_analysis")]
pub async fn gap_analysis(
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let report = sentinel_audit::gap_analysis::generate_gap_analysis();

    serde_json::to_value(&report)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to serialize gap analysis report: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate gap analysis report".to_string(),
                }),
            )
        })
}
