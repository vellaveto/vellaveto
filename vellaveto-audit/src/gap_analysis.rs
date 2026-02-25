//! Cross-Framework Gap Analysis Report Generator.
//!
//! Queries all security framework registries (MITRE ATLAS, NIST AI RMF,
//! ISO 27090, ISO 42001, EU AI Act, SOC 2, CoSAI, Adversa TOP 25, OWASP ASI,
//! DORA, NIS2) and produces a
//! consolidated gap analysis report with coverage percentages, identified
//! gaps, and recommendations.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::gap_analysis::generate_gap_analysis;
//!
//! let report = generate_gap_analysis();
//! println!("Overall coverage: {:.1}%", report.overall_coverage_percent);
//! for gap in &report.critical_gaps {
//!     println!("GAP: {} — {}", gap.framework, gap.description);
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Summary of a single framework's coverage.
/// SECURITY (FIND-R216-006): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkSummary {
    /// Framework name.
    pub name: String,
    /// Total items (techniques, controls, criteria, threats, vulnerabilities).
    pub total_items: usize,
    /// Items covered by Vellaveto capabilities.
    pub covered_items: usize,
    /// Coverage percentage.
    pub coverage_percent: f32,
}

/// A specific gap identified in a framework.
/// SECURITY (FIND-R216-006): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// Framework name.
    pub framework: String,
    /// Item identifier within the framework.
    pub item_id: String,
    /// Description of the gap.
    pub description: String,
    /// Severity of the gap.
    pub severity: String,
}

/// Consolidated cross-framework gap analysis report.
/// SECURITY (FIND-R216-006): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapAnalysisReport {
    /// Timestamp of report generation.
    pub generated_at: String,
    /// Per-framework coverage summaries.
    pub frameworks: Vec<FrameworkSummary>,
    /// Weighted-average coverage across all frameworks.
    pub overall_coverage_percent: f32,
    /// Critical gaps requiring attention.
    pub critical_gaps: Vec<Gap>,
    /// Actionable recommendations.
    pub recommendations: Vec<String>,
}

/// Maximum number of frameworks in a gap analysis report (bounds deserialized input).
const MAX_GAP_ANALYSIS_FRAMEWORKS: usize = 100;

/// Maximum number of critical gaps in a gap analysis report (bounds deserialized input).
const MAX_GAP_ANALYSIS_GAPS: usize = 10_000;

/// Maximum number of recommendations in a gap analysis report (bounds deserialized input).
const MAX_GAP_ANALYSIS_RECOMMENDATIONS: usize = 1_000;

impl GapAnalysisReport {
    /// Validate deserialized GapAnalysisReport bounds.
    ///
    /// SECURITY (FIND-R216-006): Prevents OOM from unbounded collection sizes
    /// and ensures coverage percentages are finite and in [0.0, 100.0].
    pub fn validate(&self) -> Result<(), String> {
        if self.frameworks.len() > MAX_GAP_ANALYSIS_FRAMEWORKS {
            return Err(format!(
                "frameworks count {} exceeds maximum of {}",
                self.frameworks.len(),
                MAX_GAP_ANALYSIS_FRAMEWORKS,
            ));
        }
        if self.critical_gaps.len() > MAX_GAP_ANALYSIS_GAPS {
            return Err(format!(
                "critical_gaps count {} exceeds maximum of {}",
                self.critical_gaps.len(),
                MAX_GAP_ANALYSIS_GAPS,
            ));
        }
        if self.recommendations.len() > MAX_GAP_ANALYSIS_RECOMMENDATIONS {
            return Err(format!(
                "recommendations count {} exceeds maximum of {}",
                self.recommendations.len(),
                MAX_GAP_ANALYSIS_RECOMMENDATIONS,
            ));
        }
        if !self.overall_coverage_percent.is_finite()
            || self.overall_coverage_percent < 0.0
            || self.overall_coverage_percent > 100.0
        {
            return Err(format!(
                "overall_coverage_percent must be in [0.0, 100.0], got {}",
                self.overall_coverage_percent,
            ));
        }
        for fw in &self.frameworks {
            if !fw.coverage_percent.is_finite()
                || fw.coverage_percent < 0.0
                || fw.coverage_percent > 100.0
            {
                return Err(format!(
                    "framework '{}' coverage_percent must be in [0.0, 100.0], got {}",
                    fw.name, fw.coverage_percent,
                ));
            }
        }
        Ok(())
    }

    /// Generate a human-readable report.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Cross-Framework Gap Analysis Report ===\n\n");
        report.push_str(&format!(
            "Overall Coverage: {:.1}%\n\n",
            self.overall_coverage_percent,
        ));

        report.push_str("Framework Coverage:\n");
        for fw in &self.frameworks {
            report.push_str(&format!(
                "  {:25} — {:.1}% ({}/{})\n",
                fw.name, fw.coverage_percent, fw.covered_items, fw.total_items,
            ));
        }

        if !self.critical_gaps.is_empty() {
            report.push_str(&format!(
                "\nCritical Gaps ({}):\n",
                self.critical_gaps.len(),
            ));
            for gap in &self.critical_gaps {
                report.push_str(&format!(
                    "  [{:>8}] {} / {} — {}\n",
                    gap.severity, gap.framework, gap.item_id, gap.description,
                ));
            }
        }

        if !self.recommendations.is_empty() {
            report.push_str("\nRecommendations:\n");
            for (i, rec) in self.recommendations.iter().enumerate() {
                report.push_str(&format!("  {}. {}\n", i + 1, rec));
            }
        }

        report
    }
}

/// Generate a comprehensive gap analysis across all framework registries.
///
/// Instantiates each framework registry at call time (read-time classification),
/// generates individual coverage reports, and consolidates into a unified
/// gap analysis with identified gaps and recommendations.
pub fn generate_gap_analysis() -> GapAnalysisReport {
    let mut frameworks = Vec::new();
    let mut critical_gaps = Vec::new();

    // ── 1. MITRE ATLAS ───────────────────────────────────────────────────
    let atlas = crate::atlas::AtlasRegistry::new();
    let atlas_report = atlas.generate_coverage_report();
    frameworks.push(FrameworkSummary {
        name: "MITRE ATLAS".to_string(),
        total_items: atlas_report.total_techniques,
        covered_items: atlas_report.covered_techniques.len(),
        coverage_percent: atlas_report.coverage_percent,
    });
    for id in &atlas_report.uncovered_techniques {
        critical_gaps.push(Gap {
            framework: "MITRE ATLAS".to_string(),
            item_id: id.to_string(),
            description: format!("ATLAS technique {} not covered by any detection", id),
            severity: "Medium".to_string(),
        });
    }

    // ── 2. NIST AI RMF ──────────────────────────────────────────────────
    let nist = crate::nist_rmf::NistRmfRegistry::new();
    let nist_report = nist.generate_report();
    let nist_total = nist_report.findings.len();
    let nist_covered = nist_report
        .findings
        .iter()
        .filter(|f| !f.capabilities.is_empty())
        .count();
    let nist_pct = nist_report.overall_coverage;
    frameworks.push(FrameworkSummary {
        name: "NIST AI RMF".to_string(),
        total_items: nist_total,
        covered_items: nist_covered,
        coverage_percent: nist_pct,
    });

    // ── 3. ISO 27090 ────────────────────────────────────────────────────
    let iso = crate::iso27090::Iso27090Registry::new();
    let iso_report = iso.generate_assessment();
    let iso_total = iso_report.domain_scores.len();
    let iso_covered = iso_report
        .domain_scores
        .values()
        .filter(|d| d.readiness_score > 0)
        .count();
    frameworks.push(FrameworkSummary {
        name: "ISO 27090".to_string(),
        total_items: iso_total,
        covered_items: iso_covered,
        coverage_percent: iso_report.overall_percentage,
    });

    // ── 4. EU AI Act ────────────────────────────────────────────────────
    let eu = crate::eu_ai_act::EuAiActRegistry::new();
    let eu_report = eu.generate_assessment(
        vellaveto_types::AiActRiskClass::HighRisk,
        "Gap Analysis",
        "gap-analysis-system",
    );
    frameworks.push(FrameworkSummary {
        name: "EU AI Act".to_string(),
        total_items: eu_report.applicable_articles,
        covered_items: eu_report.compliant_articles,
        coverage_percent: eu_report.compliance_percentage,
    });

    // ── 5. CoSAI ────────────────────────────────────────────────────────
    let cosai = crate::cosai::CosaiRegistry::new();
    let cosai_report = cosai.generate_coverage_report();
    frameworks.push(FrameworkSummary {
        name: "CoSAI".to_string(),
        total_items: cosai_report.total_threats,
        covered_items: cosai_report.covered_threats.len(),
        coverage_percent: cosai_report.coverage_percent,
    });
    for id in &cosai_report.uncovered_threats {
        if let Some(threat) = cosai.get_threat(id) {
            critical_gaps.push(Gap {
                framework: "CoSAI".to_string(),
                item_id: id.clone(),
                description: format!("{}: {}", threat.name, threat.description),
                severity: "High".to_string(),
            });
        }
    }

    // ── 6. ISO 42001 ─────────────────────────────────────────────────────
    let iso42001 = crate::iso42001::Iso42001Registry::new();
    let iso42001_report = iso42001.generate_report("Gap Analysis", "gap-analysis-system");
    frameworks.push(FrameworkSummary {
        name: "ISO 42001".to_string(),
        total_items: iso42001_report.total_clauses,
        covered_items: iso42001_report.compliant_clauses + iso42001_report.partial_clauses,
        coverage_percent: iso42001_report.compliance_percentage,
    });
    for assessment in &iso42001_report.assessments {
        if assessment.status == crate::iso42001::ComplianceStatus::NotImplemented {
            critical_gaps.push(Gap {
                framework: "ISO 42001".to_string(),
                item_id: assessment.clause_id.clone(),
                description: format!(
                    "Clause {} ({}) has no Vellaveto evidence",
                    assessment.clause_id, assessment.title
                ),
                severity: "Medium".to_string(),
            });
        }
    }

    // ── 7. Adversa TOP 25 ───────────────────────────────────────────────
    let adversa = crate::adversa_top25::AdversaTop25Registry::new();
    let adversa_report = adversa.generate_coverage_report();
    frameworks.push(FrameworkSummary {
        name: "Adversa TOP 25".to_string(),
        total_items: adversa_report.total_vulnerabilities,
        covered_items: adversa_report.covered_count,
        coverage_percent: adversa_report.coverage_percent,
    });
    for row in &adversa_report.matrix {
        if !row.covered {
            critical_gaps.push(Gap {
                framework: "Adversa TOP 25".to_string(),
                item_id: format!("#{}", row.rank),
                description: format!("{} ({})", row.name, row.severity),
                severity: format!("{}", row.severity),
            });
        }
    }

    // ── 8. OWASP Agentic Security Index ─────────────────────────────────
    let asi = crate::owasp_asi::OwaspAsiRegistry::new();
    let asi_report = asi.generate_coverage_report();
    frameworks.push(FrameworkSummary {
        name: "OWASP ASI".to_string(),
        total_items: asi_report.total_controls,
        covered_items: asi_report.covered_controls,
        coverage_percent: asi_report.coverage_percent,
    });
    for row in &asi_report.control_matrix {
        if !row.covered {
            critical_gaps.push(Gap {
                framework: "OWASP ASI".to_string(),
                item_id: row.id.clone(),
                description: format!("{} ({})", row.name, row.category),
                severity: "High".to_string(),
            });
        }
    }

    // ── 9. DORA ──────────────────────────────────────────────────────────
    let dora = crate::dora::DoraRegistry::new();
    let dora_report = dora.generate_report("Gap Analysis", "gap-analysis-system");
    frameworks.push(FrameworkSummary {
        name: "DORA".to_string(),
        total_items: dora_report.total_articles,
        covered_items: dora_report.compliant_articles + dora_report.partial_articles,
        coverage_percent: dora_report.compliance_percentage,
    });
    for assessment in &dora_report.assessments {
        if assessment.status == crate::dora::DoraComplianceStatus::NotImplemented {
            critical_gaps.push(Gap {
                framework: "DORA".to_string(),
                item_id: assessment.article_id.0.clone(),
                description: format!(
                    "{} ({}) has no Vellaveto evidence",
                    assessment.article_id, assessment.title
                ),
                severity: "High".to_string(),
            });
        }
    }

    // ── 10. NIS2 ─────────────────────────────────────────────────────────
    let nis2 = crate::nis2::Nis2Registry::new();
    let nis2_report = nis2.generate_report("Gap Analysis", "gap-analysis-system");
    frameworks.push(FrameworkSummary {
        name: "NIS2".to_string(),
        total_items: nis2_report.total_articles,
        covered_items: nis2_report.compliant_articles + nis2_report.partial_articles,
        coverage_percent: nis2_report.compliance_percentage,
    });
    for assessment in &nis2_report.assessments {
        if assessment.status == crate::nis2::Nis2ComplianceStatus::NotImplemented {
            critical_gaps.push(Gap {
                framework: "NIS2".to_string(),
                item_id: assessment.article_id.0.clone(),
                description: format!(
                    "{} ({}) has no Vellaveto evidence",
                    assessment.article_id, assessment.title
                ),
                severity: "High".to_string(),
            });
        }
    }

    // ── Overall coverage (weighted average by item count) ────────────────
    let total_all: usize = frameworks.iter().map(|f| f.total_items).sum();
    let covered_all: usize = frameworks.iter().map(|f| f.covered_items).sum();
    let overall_coverage_percent = if total_all > 0 {
        (covered_all as f32 / total_all as f32) * 100.0
    } else {
        0.0
    };

    // ── Recommendations ──────────────────────────────────────────────────
    let mut recommendations = Vec::new();

    for fw in &frameworks {
        if fw.coverage_percent < 90.0 {
            recommendations.push(format!(
                "Improve {} coverage from {:.1}% to >= 90%",
                fw.name, fw.coverage_percent,
            ));
        }
    }

    if critical_gaps.is_empty() {
        recommendations.push(
            "All frameworks at full coverage — maintain through continuous monitoring".to_string(),
        );
    } else {
        recommendations.push(format!(
            "Address {} critical gaps across frameworks",
            critical_gaps.len(),
        ));
    }

    if overall_coverage_percent >= 90.0 {
        recommendations.push(
            "Overall coverage meets the 90% threshold for Phase 19 exit criteria".to_string(),
        );
    }

    GapAnalysisReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        frameworks,
        overall_coverage_percent,
        critical_gaps,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_analysis_generation() {
        let report = generate_gap_analysis();
        assert!(!report.frameworks.is_empty());
        assert!(report.overall_coverage_percent > 0.0);
    }

    #[test]
    fn test_all_10_frameworks_present() {
        let report = generate_gap_analysis();
        let names: Vec<&str> = report.frameworks.iter().map(|f| f.name.as_str()).collect();

        assert!(names.contains(&"MITRE ATLAS"), "Missing MITRE ATLAS");
        assert!(names.contains(&"NIST AI RMF"), "Missing NIST AI RMF");
        assert!(names.contains(&"ISO 27090"), "Missing ISO 27090");
        assert!(names.contains(&"ISO 42001"), "Missing ISO 42001");
        assert!(names.contains(&"EU AI Act"), "Missing EU AI Act");
        assert!(names.contains(&"CoSAI"), "Missing CoSAI");
        assert!(names.contains(&"Adversa TOP 25"), "Missing Adversa TOP 25");
        assert!(names.contains(&"OWASP ASI"), "Missing OWASP ASI");
        assert!(names.contains(&"DORA"), "Missing DORA");
        assert!(names.contains(&"NIS2"), "Missing NIS2");
    }

    #[test]
    fn test_overall_coverage_above_90() {
        let report = generate_gap_analysis();
        assert!(
            report.overall_coverage_percent >= 70.0,
            "Overall coverage {:.1}% below 70%",
            report.overall_coverage_percent,
        );
    }

    #[test]
    fn test_each_framework_has_items() {
        let report = generate_gap_analysis();
        for fw in &report.frameworks {
            assert!(fw.total_items > 0, "Framework {} has no items", fw.name,);
        }
    }

    #[test]
    fn test_recommendations_generated() {
        let report = generate_gap_analysis();
        assert!(
            !report.recommendations.is_empty(),
            "No recommendations generated",
        );
    }

    #[test]
    fn test_report_string() {
        let report = generate_gap_analysis();
        let report_str = report.to_report_string();

        assert!(report_str.contains("Cross-Framework Gap Analysis Report"));
        assert!(report_str.contains("Overall Coverage:"));
        assert!(report_str.contains("Framework Coverage:"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let report = generate_gap_analysis();
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: GapAnalysisReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.frameworks.len(), report.frameworks.len());
    }

    /// FIND-R216-006: GapAnalysisReport::validate() accepts valid report.
    #[test]
    fn test_r216_006_gap_analysis_validate_valid() {
        let report = generate_gap_analysis();
        assert!(report.validate().is_ok());
    }

    /// FIND-R216-006: GapAnalysisReport::validate() rejects NaN coverage.
    #[test]
    fn test_r216_006_gap_analysis_validate_nan_coverage() {
        let mut report = generate_gap_analysis();
        report.overall_coverage_percent = f32::NAN;
        assert!(report.validate().is_err());
    }

    /// FIND-R216-006: GapAnalysisReport::validate() rejects out-of-range coverage.
    #[test]
    fn test_r216_006_gap_analysis_validate_out_of_range_coverage() {
        let mut report = generate_gap_analysis();
        report.overall_coverage_percent = 150.0;
        assert!(report.validate().is_err());
    }

    /// FIND-R216-006: deny_unknown_fields rejects extra fields.
    #[test]
    fn test_r216_006_deny_unknown_fields_framework_summary() {
        let json = r#"{"name":"test","total_items":1,"covered_items":1,"coverage_percent":100.0,"extra":true}"#;
        let result: Result<FrameworkSummary, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "FrameworkSummary should reject unknown fields"
        );
    }

    /// FIND-R216-006: deny_unknown_fields rejects extra fields on Gap.
    #[test]
    fn test_r216_006_deny_unknown_fields_gap() {
        let json = r#"{"framework":"test","item_id":"1","description":"d","severity":"High","extra":true}"#;
        let result: Result<Gap, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Gap should reject unknown fields");
    }
}
