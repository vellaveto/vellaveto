//! NIST AI Risk Management Framework (AI RMF 1.0) alignment module.
//!
//! Maps Vellaveto security capabilities to NIST AI RMF controls and subcategories.
//! The framework organizes AI risk management into four core functions:
//! - **Govern**: Policies, accountability, and organizational culture
//! - **Map**: Context understanding and risk identification
//! - **Measure**: Risk analysis and tracking
//! - **Manage**: Risk treatment and response
//!
//! Reference: <https://www.nist.gov/itl/ai-risk-management-framework>

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// NIST AI RMF core function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RmfFunction {
    /// Governance structures, policies, accountability
    Govern,
    /// Context and risk identification
    Map,
    /// Risk analysis and monitoring
    Measure,
    /// Risk treatment and response
    Manage,
}

impl std::fmt::Display for RmfFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RmfFunction::Govern => write!(f, "GOVERN"),
            RmfFunction::Map => write!(f, "MAP"),
            RmfFunction::Measure => write!(f, "MEASURE"),
            RmfFunction::Manage => write!(f, "MANAGE"),
        }
    }
}

/// NIST AI RMF category identifier (e.g., "GOVERN 1", "MAP 2").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RmfCategoryId(pub String);

impl RmfCategoryId {
    pub fn new(function: RmfFunction, number: u8) -> Self {
        Self(format!("{function} {number}"))
    }

    pub fn function(&self) -> Option<RmfFunction> {
        let prefix = self.0.split_whitespace().next()?;
        match prefix {
            "GOVERN" => Some(RmfFunction::Govern),
            "MAP" => Some(RmfFunction::Map),
            "MEASURE" => Some(RmfFunction::Measure),
            "MANAGE" => Some(RmfFunction::Manage),
            _ => None,
        }
    }
}

impl std::fmt::Display for RmfCategoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = &self.0;
        write!(f, "{inner}")
    }
}

/// NIST AI RMF subcategory identifier (e.g., "GOVERN 1.1", "MAP 2.3").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RmfSubcategoryId(pub String);

impl RmfSubcategoryId {
    pub fn new(function: RmfFunction, category: u8, subcategory: u8) -> Self {
        Self(format!("{function} {category}.{subcategory}"))
    }

    pub fn category_id(&self) -> Option<RmfCategoryId> {
        let parts: Vec<&str> = self.0.split_whitespace().collect();
        if parts.len() >= 2 {
            let num = parts[1].split('.').next()?;
            Some(RmfCategoryId(format!("{} {}", parts[0], num)))
        } else {
            None
        }
    }
}

impl std::fmt::Display for RmfSubcategoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// NIST AI RMF category with description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmfCategory {
    pub id: RmfCategoryId,
    pub function: RmfFunction,
    pub name: String,
    pub description: String,
}

/// NIST AI RMF subcategory with description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmfSubcategory {
    pub id: RmfSubcategoryId,
    pub category_id: RmfCategoryId,
    pub description: String,
}

/// Vellaveto capability that can be mapped to RMF controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VellavetoCapability {
    // Policy Engine
    PolicyEvaluation,
    PathRules,
    NetworkRules,
    ParameterConstraints,
    ContextConditions,

    // Security Detections
    InjectionDetection,
    RugPullDetection,
    ToolSquattingDetection,
    SchemaPoisoningDetection,
    ShadowAgentDetection,
    ConfusedDeputyPrevention,

    // Audit & Observability
    TamperEvidentAuditLog,
    HashChainVerification,
    AuditLogExport,
    MetricsCollection,

    // Access Control
    OAuthAuthentication,
    JwtValidation,
    AgentAttestation,
    RateLimiting,
    SessionManagement,

    // Response & Control
    CircuitBreaker,
    KillSwitch,
    HumanApproval,
    PolicyHotReload,

    // Advanced Security
    GoalTracking,
    WorkflowTracking,
    TokenSecurity,
    OutputValidation,
    DlpScanning,

    // Multi-Agent
    CrossAgentSecurity,
    PrivilegeEscalationDetection,
    TrustGraphTracking,
}

impl std::fmt::Display for VellavetoCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Implementation status for a capability mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImplementationStatus {
    /// Fully implemented and tested
    Implemented,
    /// Partially implemented
    Partial,
    /// Planned but not yet implemented
    Planned,
    /// Not applicable to Vellaveto
    NotApplicable,
}

impl std::fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplementationStatus::Implemented => write!(f, "Implemented"),
            ImplementationStatus::Partial => write!(f, "Partial"),
            ImplementationStatus::Planned => write!(f, "Planned"),
            ImplementationStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// Mapping between Vellaveto capability and RMF subcategory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityMapping {
    pub capability: VellavetoCapability,
    pub subcategory_id: RmfSubcategoryId,
    pub status: ImplementationStatus,
    pub notes: Option<String>,
}

/// NIST AI RMF registry containing the framework structure and Vellaveto mappings.
#[derive(Debug, Default)]
pub struct NistRmfRegistry {
    categories: HashMap<RmfCategoryId, RmfCategory>,
    subcategories: HashMap<RmfSubcategoryId, RmfSubcategory>,
    capability_mappings: Vec<CapabilityMapping>,
}

impl NistRmfRegistry {
    /// Create a new registry with the standard NIST AI RMF structure and Vellaveto mappings.
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.populate_framework();
        registry.populate_vellaveto_mappings();
        registry
    }

    fn populate_framework(&mut self) {
        // GOVERN function categories
        self.add_category(RmfFunction::Govern, 1,
            "Policies, processes, procedures, and practices",
            "Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place, transparent, and implemented effectively.");

        self.add_category(RmfFunction::Govern, 2,
            "Accountability structures",
            "Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks.");

        self.add_category(RmfFunction::Govern, 3,
            "Workforce diversity",
            "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle.");

        self.add_category(RmfFunction::Govern, 4,
            "Organizational culture",
            "Organizational teams are committed to a culture that considers and communicates AI risk.");

        self.add_category(
            RmfFunction::Govern,
            5,
            "Engagement with stakeholders",
            "Processes are in place for robust engagement with relevant AI actors.",
        );

        self.add_category(RmfFunction::Govern, 6,
            "Third-party management",
            "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues.");

        // MAP function categories
        self.add_category(
            RmfFunction::Map,
            1,
            "Context establishment",
            "Context is established and understood.",
        );

        self.add_category(
            RmfFunction::Map,
            2,
            "AI system categorization",
            "Categorization of the AI system is performed.",
        );

        self.add_category(RmfFunction::Map, 3,
            "AI capabilities and risks",
            "AI capabilities, targeted usage, goals, and expected benefits and costs compared with appropriate benchmarks are understood.");

        self.add_category(RmfFunction::Map, 4,
            "Risk and benefits mapping",
            "Risks and benefits are mapped for all components of the AI system including third-party software and data.");

        self.add_category(RmfFunction::Map, 5,
            "Impacts characterization",
            "Impacts to individuals, groups, communities, organizations, and society are characterized.");

        // MEASURE function categories
        self.add_category(
            RmfFunction::Measure,
            1,
            "Risk identification and analysis",
            "Appropriate methods and metrics are identified and applied.",
        );

        self.add_category(
            RmfFunction::Measure,
            2,
            "AI system evaluation",
            "AI systems are evaluated for trustworthy characteristics.",
        );

        self.add_category(
            RmfFunction::Measure,
            3,
            "Risk tracking",
            "Mechanisms for tracking identified AI risks over time are in place.",
        );

        self.add_category(
            RmfFunction::Measure,
            4,
            "Feedback integration",
            "Feedback about efficacy of measurement is gathered and integrated.",
        );

        // MANAGE function categories
        self.add_category(RmfFunction::Manage, 1,
            "Risk prioritization",
            "AI risks based on assessments and other analytical output from the MAP and MEASURE functions are prioritized, responded to, and managed.");

        self.add_category(RmfFunction::Manage, 2,
            "Risk treatment strategies",
            "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and informed by input from relevant AI actors.");

        self.add_category(
            RmfFunction::Manage,
            3,
            "Post-deployment risk management",
            "AI risks and benefits from third-party entities are managed.",
        );

        self.add_category(RmfFunction::Manage, 4,
            "Risk treatment implementation",
            "Risk treatments, including response and recovery, and communication plans for the identified and measured AI risks are documented and monitored regularly.");

        // Add key subcategories relevant to Vellaveto
        self.add_subcategory(RmfFunction::Govern, 1, 1,
            "Legal and regulatory requirements and internal policies pertaining to the organization are identified, documented, and prioritized.");
        self.add_subcategory(RmfFunction::Govern, 1, 2,
            "The characteristics of trustworthy AI are integrated into organizational policies, procedures, and processes.");
        self.add_subcategory(RmfFunction::Govern, 1, 5,
            "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined.");
        self.add_subcategory(RmfFunction::Govern, 1, 6,
            "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.");
        self.add_subcategory(RmfFunction::Govern, 1, 7,
            "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in ways that do not increase risks or harms.");

        self.add_subcategory(RmfFunction::Govern, 4, 1,
            "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems.");
        self.add_subcategory(RmfFunction::Govern, 4, 2,
            "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, or operate.");
        self.add_subcategory(RmfFunction::Govern, 4, 3,
            "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.");

        self.add_subcategory(RmfFunction::Govern, 6, 1,
            "Policies and procedures are in place that address AI risks associated with third-party entities.");
        self.add_subcategory(
            RmfFunction::Govern,
            6,
            2,
            "Contingency processes are in place for third-party AI systems and data.",
        );

        self.add_subcategory(RmfFunction::Map, 1, 6,
            "System requirements (e.g., functionality, performance, cost, efficiency) are elicited and documented.");
        self.add_subcategory(
            RmfFunction::Map,
            2,
            3,
            "Scientific integrity and TEVV considerations are identified and documented.",
        );
        self.add_subcategory(RmfFunction::Map, 3, 1,
            "Potential benefits of intended AI system functionality and performance are examined and documented.");
        self.add_subcategory(RmfFunction::Map, 4, 1,
            "Approaches for mapping AI technology and legal risks of its components – including third-party data, software, and models – are in place.");
        self.add_subcategory(
            RmfFunction::Map,
            4,
            2,
            "Internal risk controls for components of the AI system are identified and documented.",
        );

        self.add_subcategory(RmfFunction::Measure, 1, 1,
            "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation.");
        self.add_subcategory(RmfFunction::Measure, 1, 3,
            "Internal and external assessments of AI system functionality and behavior are performed and documented.");
        self.add_subcategory(RmfFunction::Measure, 2, 1,
            "Test sets, metrics, and details about the tools used during test, evaluation, validation, and verification are documented.");
        self.add_subcategory(
            RmfFunction::Measure,
            2,
            6,
            "The AI system is evaluated for safety.",
        );
        self.add_subcategory(
            RmfFunction::Measure,
            2,
            7,
            "The AI system is evaluated for security and resilience.",
        );
        self.add_subcategory(RmfFunction::Measure, 2, 9,
            "Mechanisms are in place to capture and evaluate input from internal and external sources.");
        self.add_subcategory(RmfFunction::Measure, 2, 11,
            "Fairness and bias – loss of liberty, deprivation of rights – the AI system is evaluated.");
        self.add_subcategory(RmfFunction::Measure, 2, 12,
            "Privacy and data protection – whether the AI system protects and does not violate privacy and data protection rules.");
        self.add_subcategory(RmfFunction::Measure, 3, 1,
            "Approaches, personnel, and documentation are in place to regularly identify and track existing and emergent AI risks.");
        self.add_subcategory(
            RmfFunction::Measure,
            3,
            2,
            "Processes for tracking known risks over time are in place.",
        );
        self.add_subcategory(RmfFunction::Measure, 3, 3,
            "Feedback processes for end users and affected communities to report problems are in place and operational.");

        self.add_subcategory(
            RmfFunction::Manage,
            1,
            1,
            "A determination is made as to whether AI risk is at an acceptable level.",
        );
        self.add_subcategory(RmfFunction::Manage, 1, 3,
            "Responses to the AI risks deemed high priority are developed, planned, and documented.");
        self.add_subcategory(
            RmfFunction::Manage,
            2,
            1,
            "Resources required to manage AI risks are taken into account.",
        );
        self.add_subcategory(
            RmfFunction::Manage,
            2,
            2,
            "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
        );
        self.add_subcategory(RmfFunction::Manage, 2, 4,
            "Mechanisms are in place and applied, and approaches are developed and documented, to enable human oversight of AI systems.");
        self.add_subcategory(
            RmfFunction::Manage,
            3,
            1,
            "AI risks and benefits from third-party resources are regularly monitored.",
        );
        self.add_subcategory(
            RmfFunction::Manage,
            3,
            2,
            "Pre-trained models that are used are monitored.",
        );
        self.add_subcategory(
            RmfFunction::Manage,
            4,
            1,
            "Post-deployment AI system monitoring plans are implemented.",
        );
        self.add_subcategory(RmfFunction::Manage, 4, 2,
            "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties.");
        self.add_subcategory(RmfFunction::Manage, 4, 3,
            "Processes for incident response, recovery, and appeals are established and operational.");
    }

    fn add_category(&mut self, function: RmfFunction, number: u8, name: &str, description: &str) {
        let id = RmfCategoryId::new(function, number);
        self.categories.insert(
            id.clone(),
            RmfCategory {
                id,
                function,
                name: name.to_string(),
                description: description.to_string(),
            },
        );
    }

    fn add_subcategory(
        &mut self,
        function: RmfFunction,
        category: u8,
        subcategory: u8,
        description: &str,
    ) {
        let id = RmfSubcategoryId::new(function, category, subcategory);
        let category_id = RmfCategoryId::new(function, category);
        self.subcategories.insert(
            id.clone(),
            RmfSubcategory {
                id,
                category_id,
                description: description.to_string(),
            },
        );
    }

    fn populate_vellaveto_mappings(&mut self) {
        // GOVERN mappings - Policy and governance
        self.add_mapping(
            VellavetoCapability::PolicyEvaluation,
            "GOVERN 1.1",
            ImplementationStatus::Implemented,
            Some("Policy engine enforces organizational security policies"),
        );
        self.add_mapping(
            VellavetoCapability::PolicyEvaluation,
            "GOVERN 1.2",
            ImplementationStatus::Implemented,
            Some("Trustworthy AI characteristics enforced through policy rules"),
        );
        self.add_mapping(
            VellavetoCapability::TamperEvidentAuditLog,
            "GOVERN 1.5",
            ImplementationStatus::Implemented,
            Some("Tamper-evident audit log enables monitoring and review"),
        );
        self.add_mapping(
            VellavetoCapability::PolicyHotReload,
            "GOVERN 1.6",
            ImplementationStatus::Implemented,
            Some("Hot reload enables policy inventory management"),
        );
        self.add_mapping(
            VellavetoCapability::KillSwitch,
            "GOVERN 1.7",
            ImplementationStatus::Implemented,
            Some("Kill switch enables safe decommissioning"),
        );

        self.add_mapping(
            VellavetoCapability::InjectionDetection,
            "GOVERN 4.1",
            ImplementationStatus::Implemented,
            Some("Safety-first detection of prompt injection attacks"),
        );
        self.add_mapping(
            VellavetoCapability::TamperEvidentAuditLog,
            "GOVERN 4.2",
            ImplementationStatus::Implemented,
            Some("All risks and impacts documented in audit trail"),
        );
        self.add_mapping(
            VellavetoCapability::AuditLogExport,
            "GOVERN 4.3",
            ImplementationStatus::Implemented,
            Some("CEF/JSONL export enables information sharing"),
        );

        self.add_mapping(
            VellavetoCapability::ToolSquattingDetection,
            "GOVERN 6.1",
            ImplementationStatus::Implemented,
            Some("Detects third-party tool impersonation"),
        );
        self.add_mapping(
            VellavetoCapability::CircuitBreaker,
            "GOVERN 6.2",
            ImplementationStatus::Implemented,
            Some("Circuit breaker provides contingency for third-party failures"),
        );

        // MAP mappings - Risk identification
        self.add_mapping(
            VellavetoCapability::ContextConditions,
            "MAP 1.6",
            ImplementationStatus::Implemented,
            Some("Context-aware policies document system requirements"),
        );
        self.add_mapping(
            VellavetoCapability::OutputValidation,
            "MAP 2.3",
            ImplementationStatus::Implemented,
            Some("Output validation ensures scientific integrity"),
        );
        self.add_mapping(
            VellavetoCapability::MetricsCollection,
            "MAP 3.1",
            ImplementationStatus::Implemented,
            Some("Prometheus metrics document system performance"),
        );
        self.add_mapping(
            VellavetoCapability::SchemaPoisoningDetection,
            "MAP 4.1",
            ImplementationStatus::Implemented,
            Some("Schema tracking maps risks of third-party components"),
        );
        self.add_mapping(
            VellavetoCapability::PathRules,
            "MAP 4.2",
            ImplementationStatus::Implemented,
            Some("Path rules document internal access controls"),
        );
        self.add_mapping(
            VellavetoCapability::NetworkRules,
            "MAP 4.2",
            ImplementationStatus::Implemented,
            Some("Network rules document internal access controls"),
        );

        // MEASURE mappings - Risk analysis
        self.add_mapping(
            VellavetoCapability::MetricsCollection,
            "MEASURE 1.1",
            ImplementationStatus::Implemented,
            Some("Prometheus metrics implement risk measurement"),
        );
        self.add_mapping(
            VellavetoCapability::TamperEvidentAuditLog,
            "MEASURE 1.3",
            ImplementationStatus::Implemented,
            Some("Audit log documents all system behavior assessments"),
        );
        self.add_mapping(
            VellavetoCapability::HashChainVerification,
            "MEASURE 2.1",
            ImplementationStatus::Implemented,
            Some("Hash chain verification validates audit integrity"),
        );
        self.add_mapping(
            VellavetoCapability::InjectionDetection,
            "MEASURE 2.6",
            ImplementationStatus::Implemented,
            Some("Injection detection evaluates system safety"),
        );
        self.add_mapping(
            VellavetoCapability::ShadowAgentDetection,
            "MEASURE 2.7",
            ImplementationStatus::Implemented,
            Some("Shadow agent detection evaluates security"),
        );
        self.add_mapping(
            VellavetoCapability::ConfusedDeputyPrevention,
            "MEASURE 2.7",
            ImplementationStatus::Implemented,
            Some("Confused deputy prevention evaluates resilience"),
        );
        self.add_mapping(
            VellavetoCapability::PrivilegeEscalationDetection,
            "MEASURE 2.11",
            ImplementationStatus::Implemented,
            Some("Privilege escalation detection evaluates access control fairness"),
        );
        self.add_mapping(
            VellavetoCapability::DlpScanning,
            "MEASURE 2.12",
            ImplementationStatus::Implemented,
            Some("DLP scanning protects privacy and data"),
        );
        self.add_mapping(
            VellavetoCapability::GoalTracking,
            "MEASURE 3.1",
            ImplementationStatus::Implemented,
            Some("Goal tracking identifies emergent drift risks"),
        );
        self.add_mapping(
            VellavetoCapability::WorkflowTracking,
            "MEASURE 3.2",
            ImplementationStatus::Implemented,
            Some("Workflow tracking monitors risks over time"),
        );
        self.add_mapping(
            VellavetoCapability::HumanApproval,
            "MEASURE 3.3",
            ImplementationStatus::Implemented,
            Some("Human approval enables problem reporting"),
        );

        // MANAGE mappings - Risk response
        self.add_mapping(
            VellavetoCapability::PolicyEvaluation,
            "MANAGE 1.1",
            ImplementationStatus::Implemented,
            Some("Policy verdicts determine acceptable risk levels"),
        );
        self.add_mapping(
            VellavetoCapability::CircuitBreaker,
            "MANAGE 1.3",
            ImplementationStatus::Implemented,
            Some("Circuit breaker responds to high priority risks"),
        );
        self.add_mapping(
            VellavetoCapability::RateLimiting,
            "MANAGE 2.1",
            ImplementationStatus::Implemented,
            Some("Rate limiting manages resource allocation"),
        );
        self.add_mapping(
            VellavetoCapability::PolicyHotReload,
            "MANAGE 2.2",
            ImplementationStatus::Implemented,
            Some("Hot reload sustains value through dynamic updates"),
        );
        self.add_mapping(
            VellavetoCapability::HumanApproval,
            "MANAGE 2.4",
            ImplementationStatus::Implemented,
            Some("Human approval enables human oversight"),
        );
        self.add_mapping(
            VellavetoCapability::RugPullDetection,
            "MANAGE 3.1",
            ImplementationStatus::Implemented,
            Some("Rug pull detection monitors third-party resources"),
        );
        self.add_mapping(
            VellavetoCapability::SchemaPoisoningDetection,
            "MANAGE 3.2",
            ImplementationStatus::Implemented,
            Some("Schema poisoning detection monitors model schemas"),
        );
        self.add_mapping(
            VellavetoCapability::TamperEvidentAuditLog,
            "MANAGE 4.1",
            ImplementationStatus::Implemented,
            Some("Audit logging implements post-deployment monitoring"),
        );
        self.add_mapping(
            VellavetoCapability::AuditLogExport,
            "MANAGE 4.2",
            ImplementationStatus::Implemented,
            Some("Export formats enable continuous improvement"),
        );
        self.add_mapping(
            VellavetoCapability::KillSwitch,
            "MANAGE 4.3",
            ImplementationStatus::Implemented,
            Some("Kill switch enables incident response and recovery"),
        );
    }

    fn add_mapping(
        &mut self,
        capability: VellavetoCapability,
        subcategory: &str,
        status: ImplementationStatus,
        notes: Option<&str>,
    ) {
        self.capability_mappings.push(CapabilityMapping {
            capability,
            subcategory_id: RmfSubcategoryId(subcategory.to_string()),
            status,
            notes: notes.map(String::from),
        });
    }

    /// Get all categories.
    pub fn categories(&self) -> impl Iterator<Item = &RmfCategory> {
        self.categories.values()
    }

    /// Get all subcategories.
    pub fn subcategories(&self) -> impl Iterator<Item = &RmfSubcategory> {
        self.subcategories.values()
    }

    /// Get category by ID.
    pub fn get_category(&self, id: &RmfCategoryId) -> Option<&RmfCategory> {
        self.categories.get(id)
    }

    /// Get subcategory by ID.
    pub fn get_subcategory(&self, id: &RmfSubcategoryId) -> Option<&RmfSubcategory> {
        self.subcategories.get(id)
    }

    /// Get all mappings for a capability.
    pub fn mappings_for_capability(
        &self,
        capability: VellavetoCapability,
    ) -> Vec<&CapabilityMapping> {
        self.capability_mappings
            .iter()
            .filter(|m| m.capability == capability)
            .collect()
    }

    /// Get all mappings for a subcategory.
    pub fn mappings_for_subcategory(
        &self,
        subcategory_id: &RmfSubcategoryId,
    ) -> Vec<&CapabilityMapping> {
        self.capability_mappings
            .iter()
            .filter(|m| &m.subcategory_id == subcategory_id)
            .collect()
    }

    /// Get coverage statistics by function.
    pub fn coverage_by_function(&self) -> HashMap<RmfFunction, CoverageStats> {
        let mut stats: HashMap<RmfFunction, CoverageStats> = HashMap::new();

        // Initialize stats for each function
        for function in [
            RmfFunction::Govern,
            RmfFunction::Map,
            RmfFunction::Measure,
            RmfFunction::Manage,
        ] {
            stats.insert(function, CoverageStats::default());
        }

        // Count subcategories per function
        for subcategory in self.subcategories.values() {
            if let Some(function) = subcategory.id.category_id().and_then(|c| c.function()) {
                if let Some(s) = stats.get_mut(&function) {
                    s.total_subcategories += 1;
                }
            }
        }

        // Count covered subcategories (those with implemented mappings)
        let mut covered: HashMap<RmfFunction, HashSet<String>> = HashMap::new();
        for mapping in &self.capability_mappings {
            if mapping.status == ImplementationStatus::Implemented {
                if let Some(function) = mapping
                    .subcategory_id
                    .category_id()
                    .and_then(|c| c.function())
                {
                    covered
                        .entry(function)
                        .or_default()
                        .insert(mapping.subcategory_id.0.clone());
                }
            }
        }

        for (function, subcategory_ids) in covered {
            if let Some(s) = stats.get_mut(&function) {
                s.covered_subcategories = subcategory_ids.len();
            }
        }

        // Calculate percentages
        for s in stats.values_mut() {
            if s.total_subcategories > 0 {
                s.coverage_percent =
                    (s.covered_subcategories as f32 / s.total_subcategories as f32) * 100.0;
            }
        }

        stats
    }

    /// Generate a compliance report.
    pub fn generate_report(&self) -> RmfComplianceReport {
        let mut findings = Vec::new();
        let coverage = self.coverage_by_function();

        // Group mappings by subcategory
        let mut by_subcategory: HashMap<String, Vec<&CapabilityMapping>> = HashMap::new();
        for mapping in &self.capability_mappings {
            by_subcategory
                .entry(mapping.subcategory_id.0.clone())
                .or_default()
                .push(mapping);
        }

        for (subcategory_id, mappings) in by_subcategory {
            let id = RmfSubcategoryId(subcategory_id.clone());
            let description = self
                .get_subcategory(&id)
                .map(|s| s.description.clone())
                .unwrap_or_default();

            let capabilities: Vec<_> = mappings.iter().map(|m| m.capability).collect();
            let status = if mappings
                .iter()
                .all(|m| m.status == ImplementationStatus::Implemented)
            {
                ImplementationStatus::Implemented
            } else if mappings
                .iter()
                .any(|m| m.status == ImplementationStatus::Implemented)
            {
                ImplementationStatus::Partial
            } else {
                ImplementationStatus::Planned
            };

            let notes: Vec<_> = mappings.iter().filter_map(|m| m.notes.clone()).collect();

            findings.push(RmfFinding {
                subcategory_id,
                description,
                capabilities,
                status,
                notes,
            });
        }

        // Sort findings by subcategory ID
        findings.sort_by(|a, b| a.subcategory_id.cmp(&b.subcategory_id));

        let overall_coverage = {
            let total: usize = coverage.values().map(|s| s.total_subcategories).sum();
            let covered: usize = coverage.values().map(|s| s.covered_subcategories).sum();
            if total > 0 {
                (covered as f32 / total as f32) * 100.0
            } else {
                0.0
            }
        };

        RmfComplianceReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            overall_coverage,
            coverage_by_function: coverage,
            findings,
        }
    }
}

/// Coverage statistics for an RMF function.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    pub total_subcategories: usize,
    pub covered_subcategories: usize,
    pub coverage_percent: f32,
}

/// A finding in the compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmfFinding {
    pub subcategory_id: String,
    pub description: String,
    pub capabilities: Vec<VellavetoCapability>,
    pub status: ImplementationStatus,
    pub notes: Vec<String>,
}

/// NIST AI RMF compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmfComplianceReport {
    pub generated_at: String,
    pub overall_coverage: f32,
    pub coverage_by_function: HashMap<RmfFunction, CoverageStats>,
    pub findings: Vec<RmfFinding>,
}

impl RmfComplianceReport {
    /// Convert report to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get summary statistics.
    pub fn summary(&self) -> String {
        let mut output = String::new();
        output.push_str("NIST AI RMF Compliance Summary\n");
        output.push_str("==============================\n\n");
        output.push_str(&format!("Generated: {}\n", self.generated_at));
        output.push_str(&format!(
            "Overall Coverage: {:.1}%\n\n",
            self.overall_coverage
        ));
        output.push_str("Coverage by Function:\n");

        for function in [
            RmfFunction::Govern,
            RmfFunction::Map,
            RmfFunction::Measure,
            RmfFunction::Manage,
        ] {
            if let Some(stats) = self.coverage_by_function.get(&function) {
                output.push_str(&format!(
                    "  {}: {}/{} ({:.1}%)\n",
                    function,
                    stats.covered_subcategories,
                    stats.total_subcategories,
                    stats.coverage_percent
                ));
            }
        }

        output.push_str(&format!("\nTotal Findings: {}\n", self.findings.len()));

        let implemented = self
            .findings
            .iter()
            .filter(|f| f.status == ImplementationStatus::Implemented)
            .count();
        let partial = self
            .findings
            .iter()
            .filter(|f| f.status == ImplementationStatus::Partial)
            .count();

        output.push_str(&format!("  Implemented: {implemented}\n"));
        output.push_str(&format!("  Partial: {partial}\n"));

        output
    }
}

/// Add NIST RMF metadata to an audit event.
pub fn add_rmf_metadata(
    metadata: &mut serde_json::Value,
    capability: VellavetoCapability,
    registry: &NistRmfRegistry,
) {
    let mappings = registry.mappings_for_capability(capability);
    if !mappings.is_empty() {
        let subcategories: Vec<String> = mappings
            .iter()
            .map(|m| m.subcategory_id.0.clone())
            .collect();

        if let serde_json::Value::Object(ref mut map) = metadata {
            map.insert(
                "nist_rmf_subcategories".to_string(),
                serde_json::json!(subcategories),
            );
            map.insert(
                "nist_rmf_capability".to_string(),
                serde_json::json!(capability.to_string()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = NistRmfRegistry::new();
        assert!(!registry.categories.is_empty());
        assert!(!registry.subcategories.is_empty());
        assert!(!registry.capability_mappings.is_empty());
    }

    #[test]
    fn test_category_id_parsing() {
        let id = RmfCategoryId::new(RmfFunction::Govern, 1);
        assert_eq!(id.0, "GOVERN 1");
        assert_eq!(id.function(), Some(RmfFunction::Govern));
    }

    #[test]
    fn test_subcategory_id_parsing() {
        let id = RmfSubcategoryId::new(RmfFunction::Measure, 2, 7);
        assert_eq!(id.0, "MEASURE 2.7");

        let category = id.category_id().unwrap();
        assert_eq!(category.0, "MEASURE 2");
    }

    #[test]
    fn test_function_display() {
        assert_eq!(format!("{}", RmfFunction::Govern), "GOVERN");
        assert_eq!(format!("{}", RmfFunction::Map), "MAP");
        assert_eq!(format!("{}", RmfFunction::Measure), "MEASURE");
        assert_eq!(format!("{}", RmfFunction::Manage), "MANAGE");
    }

    #[test]
    fn test_mappings_for_capability() {
        let registry = NistRmfRegistry::new();
        let mappings = registry.mappings_for_capability(VellavetoCapability::PolicyEvaluation);
        assert!(!mappings.is_empty());

        // Policy evaluation should map to multiple subcategories
        assert!(mappings.len() >= 2);
    }

    #[test]
    fn test_coverage_by_function() {
        let registry = NistRmfRegistry::new();
        let coverage = registry.coverage_by_function();

        // All four functions should have coverage stats
        assert!(coverage.contains_key(&RmfFunction::Govern));
        assert!(coverage.contains_key(&RmfFunction::Map));
        assert!(coverage.contains_key(&RmfFunction::Measure));
        assert!(coverage.contains_key(&RmfFunction::Manage));

        // Each function should have some coverage
        for stats in coverage.values() {
            assert!(stats.total_subcategories > 0);
        }
    }

    #[test]
    fn test_generate_report() {
        let registry = NistRmfRegistry::new();
        let report = registry.generate_report();

        assert!(!report.findings.is_empty());
        assert!(report.overall_coverage > 0.0);
        assert!(!report.generated_at.is_empty());
    }

    #[test]
    fn test_report_to_json() {
        let registry = NistRmfRegistry::new();
        let report = registry.generate_report();

        let json = report.to_json().unwrap();
        assert!(json.contains("overall_coverage"));
        assert!(json.contains("findings"));
    }

    #[test]
    fn test_report_summary() {
        let registry = NistRmfRegistry::new();
        let report = registry.generate_report();
        let summary = report.summary();

        assert!(summary.contains("NIST AI RMF Compliance Summary"));
        assert!(summary.contains("GOVERN"));
        assert!(summary.contains("MAP"));
        assert!(summary.contains("MEASURE"));
        assert!(summary.contains("MANAGE"));
    }

    #[test]
    fn test_add_rmf_metadata() {
        let registry = NistRmfRegistry::new();
        let mut metadata = serde_json::json!({});

        add_rmf_metadata(
            &mut metadata,
            VellavetoCapability::InjectionDetection,
            &registry,
        );

        assert!(metadata.get("nist_rmf_subcategories").is_some());
        assert!(metadata.get("nist_rmf_capability").is_some());
    }

    #[test]
    fn test_implementation_status_display() {
        assert_eq!(
            format!("{}", ImplementationStatus::Implemented),
            "Implemented"
        );
        assert_eq!(format!("{}", ImplementationStatus::Partial), "Partial");
        assert_eq!(format!("{}", ImplementationStatus::Planned), "Planned");
        assert_eq!(format!("{}", ImplementationStatus::NotApplicable), "N/A");
    }

    #[test]
    fn test_all_capabilities_have_mappings() {
        let registry = NistRmfRegistry::new();

        // Core security capabilities should all have mappings
        let core_capabilities = [
            VellavetoCapability::PolicyEvaluation,
            VellavetoCapability::InjectionDetection,
            VellavetoCapability::TamperEvidentAuditLog,
            VellavetoCapability::CircuitBreaker,
            VellavetoCapability::KillSwitch,
        ];

        for cap in core_capabilities {
            let mappings = registry.mappings_for_capability(cap);
            assert!(
                !mappings.is_empty(),
                "Capability {:?} should have mappings",
                cap
            );
        }
    }
}
