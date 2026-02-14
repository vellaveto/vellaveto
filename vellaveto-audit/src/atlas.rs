//! MITRE ATLAS Threat Mapping for AI Security.
//!
//! Maps Vellaveto security detections to MITRE ATLAS (Adversarial Threat
//! Landscape for AI Systems) techniques. ATLAS is a knowledge base of
//! adversary tactics and techniques based on real-world attack observations.
//!
//! References:
//! - MITRE ATLAS: <https://atlas.mitre.org/>
//! - ATLAS Techniques for Agentic AI (2025-2026 additions)
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::atlas::{AtlasRegistry, VellavetoDetection};
//!
//! let registry = AtlasRegistry::new();
//! let techniques = registry.get_techniques_for_detection(VellavetoDetection::PromptInjection);
//! for tech in techniques {
//!     println!("{}: {}", tech.id, tech.name);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATLAS technique identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AtlasId(pub String);

impl AtlasId {
    /// Create a new ATLAS ID.
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }

    /// Get the ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AtlasId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ATLAS tactic (high-level adversary goal).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AtlasTactic {
    /// Reconnaissance - Gathering information about the target AI system.
    Reconnaissance,
    /// Resource Development - Establishing resources to support operations.
    ResourceDevelopment,
    /// Initial Access - Gaining entry to the AI system.
    InitialAccess,
    /// ML Model Access - Accessing or interacting with the ML model.
    MlModelAccess,
    /// Execution - Running adversary-controlled code or prompts.
    Execution,
    /// Persistence - Maintaining access to the AI system.
    Persistence,
    /// Defense Evasion - Avoiding detection.
    DefenseEvasion,
    /// Discovery - Learning about the AI system's configuration.
    Discovery,
    /// Collection - Gathering data of interest.
    Collection,
    /// ML Attack Staging - Preparing ML-specific attacks.
    MlAttackStaging,
    /// Exfiltration - Stealing data from the AI system.
    Exfiltration,
    /// Impact - Manipulating, disrupting, or destroying the AI system.
    Impact,
}

impl std::fmt::Display for AtlasTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "Reconnaissance"),
            Self::ResourceDevelopment => write!(f, "Resource Development"),
            Self::InitialAccess => write!(f, "Initial Access"),
            Self::MlModelAccess => write!(f, "ML Model Access"),
            Self::Execution => write!(f, "Execution"),
            Self::Persistence => write!(f, "Persistence"),
            Self::DefenseEvasion => write!(f, "Defense Evasion"),
            Self::Discovery => write!(f, "Discovery"),
            Self::Collection => write!(f, "Collection"),
            Self::MlAttackStaging => write!(f, "ML Attack Staging"),
            Self::Exfiltration => write!(f, "Exfiltration"),
            Self::Impact => write!(f, "Impact"),
        }
    }
}

/// ATLAS technique definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasTechnique {
    /// Technique ID (e.g., "AML.T0060").
    pub id: AtlasId,
    /// Technique name.
    pub name: String,
    /// Description of the technique.
    pub description: String,
    /// Associated tactic.
    pub tactic: AtlasTactic,
    /// Sub-techniques (if any).
    pub sub_techniques: Vec<AtlasId>,
    /// Related techniques.
    pub related: Vec<AtlasId>,
    /// URL to ATLAS page.
    pub url: String,
}

/// Vellaveto detection types that map to ATLAS techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VellavetoDetection {
    // === ASI01: Prompt Injection ===
    /// Direct prompt injection in user input.
    PromptInjection,
    /// Indirect prompt injection via tool responses.
    IndirectInjection,
    /// Second-order prompt injection across agents.
    SecondOrderInjection,
    /// Unicode manipulation for injection.
    UnicodeManipulation,
    /// Delimiter injection attack.
    DelimiterInjection,

    // === ASI02: Confused Deputy ===
    /// Confused deputy attack (privilege escalation).
    ConfusedDeputy,
    /// Unauthorized delegation.
    UnauthorizedDelegation,
    /// Privilege escalation via agent chain.
    PrivilegeEscalation,

    // === ASI03: Tool Manipulation ===
    /// Tool annotation change (rug pull).
    ToolAnnotationChange,
    /// Tool squatting (name similarity).
    ToolSquatting,
    /// Tool shadowing (namespace collision).
    ToolShadowing,
    /// Schema poisoning.
    SchemaPoisoning,

    // === ASI05: Insecure Tool Output ===
    /// Secrets in tool output.
    SecretsInOutput,
    /// Covert channel in output.
    CovertChannel,
    /// Steganography in output.
    Steganography,

    // === ASI06: Memory Poisoning ===
    /// Cross-request data laundering.
    DataLaundering,
    /// Memory injection attack.
    MemoryInjection,
    /// Goal drift detection.
    GoalDrift,

    // === ASI07: Excessive Agency ===
    /// Excessive permissions granted.
    ExcessiveAgency,
    /// Workflow budget exceeded.
    WorkflowBudgetExceeded,
    /// Unauthorized tool access.
    UnauthorizedToolAccess,

    // === ASI08: Cascading Failures ===
    /// Circuit breaker triggered.
    CircuitBreakerTriggered,
    /// Cascading failure detected.
    CascadingFailure,

    // === Other Detections ===
    /// Shadow agent detected.
    ShadowAgent,
    /// Sampling attack.
    SamplingAttack,
    /// Token smuggling.
    TokenSmuggling,
    /// Context flooding.
    ContextFlooding,
    /// Glitch token detected.
    GlitchToken,
    /// Path traversal attempt.
    PathTraversal,
    /// DNS rebinding attempt.
    DnsRebinding,
    /// Rate limit exceeded.
    RateLimitExceeded,
}

impl std::fmt::Display for VellavetoDetection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::PromptInjection => "Prompt Injection",
            Self::IndirectInjection => "Indirect Injection",
            Self::SecondOrderInjection => "Second-Order Injection",
            Self::UnicodeManipulation => "Unicode Manipulation",
            Self::DelimiterInjection => "Delimiter Injection",
            Self::ConfusedDeputy => "Confused Deputy",
            Self::UnauthorizedDelegation => "Unauthorized Delegation",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::ToolAnnotationChange => "Tool Annotation Change",
            Self::ToolSquatting => "Tool Squatting",
            Self::ToolShadowing => "Tool Shadowing",
            Self::SchemaPoisoning => "Schema Poisoning",
            Self::SecretsInOutput => "Secrets in Output",
            Self::CovertChannel => "Covert Channel",
            Self::Steganography => "Steganography",
            Self::DataLaundering => "Data Laundering",
            Self::MemoryInjection => "Memory Injection",
            Self::GoalDrift => "Goal Drift",
            Self::ExcessiveAgency => "Excessive Agency",
            Self::WorkflowBudgetExceeded => "Workflow Budget Exceeded",
            Self::UnauthorizedToolAccess => "Unauthorized Tool Access",
            Self::CircuitBreakerTriggered => "Circuit Breaker Triggered",
            Self::CascadingFailure => "Cascading Failure",
            Self::ShadowAgent => "Shadow Agent",
            Self::SamplingAttack => "Sampling Attack",
            Self::TokenSmuggling => "Token Smuggling",
            Self::ContextFlooding => "Context Flooding",
            Self::GlitchToken => "Glitch Token",
            Self::PathTraversal => "Path Traversal",
            Self::DnsRebinding => "DNS Rebinding",
            Self::RateLimitExceeded => "Rate Limit Exceeded",
        };
        write!(f, "{name}")
    }
}

/// Registry of ATLAS techniques with mappings to Vellaveto detections.
pub struct AtlasRegistry {
    /// All registered techniques.
    techniques: HashMap<AtlasId, AtlasTechnique>,
    /// Mapping from Vellaveto detection to ATLAS techniques.
    detection_mappings: HashMap<VellavetoDetection, Vec<AtlasId>>,
}

impl AtlasRegistry {
    /// Create a new registry with all known ATLAS techniques.
    pub fn new() -> Self {
        let mut registry = Self {
            techniques: HashMap::new(),
            detection_mappings: HashMap::new(),
        };
        registry.register_techniques();
        registry.register_mappings();
        registry
    }

    /// Register all ATLAS techniques.
    fn register_techniques(&mut self) {
        // AML.T0051 - LLM Prompt Injection
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0051"),
            name: "LLM Prompt Injection".to_string(),
            description: "Adversaries may craft malicious prompts to manipulate LLM behavior, \
                causing it to ignore instructions, leak data, or execute unintended actions."
                .to_string(),
            tactic: AtlasTactic::InitialAccess,
            sub_techniques: vec![
                AtlasId::new("AML.T0051.001"), // Direct Injection
                AtlasId::new("AML.T0051.002"), // Indirect Injection
            ],
            related: vec![AtlasId::new("AML.T0054")],
            url: "https://atlas.mitre.org/techniques/AML.T0051".to_string(),
        });

        // AML.T0051.001 - Direct Prompt Injection
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0051.001"),
            name: "Direct Prompt Injection".to_string(),
            description: "Adversary directly inputs malicious prompts through user-facing \
                interfaces to manipulate LLM behavior."
                .to_string(),
            tactic: AtlasTactic::InitialAccess,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0051")],
            url: "https://atlas.mitre.org/techniques/AML.T0051.001".to_string(),
        });

        // AML.T0051.002 - Indirect Prompt Injection
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0051.002"),
            name: "Indirect Prompt Injection".to_string(),
            description: "Adversary plants malicious content in external data sources that \
                the LLM retrieves and processes."
                .to_string(),
            tactic: AtlasTactic::InitialAccess,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0051")],
            url: "https://atlas.mitre.org/techniques/AML.T0051.002".to_string(),
        });

        // AML.T0054 - LLM Jailbreak
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0054"),
            name: "LLM Jailbreak".to_string(),
            description: "Adversaries may use techniques to bypass safety guardrails and \
                content policies in LLMs."
                .to_string(),
            tactic: AtlasTactic::DefenseEvasion,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0051")],
            url: "https://atlas.mitre.org/techniques/AML.T0054".to_string(),
        });

        // AML.T0060 - Agent Manipulation (Agentic AI)
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0060"),
            name: "Agent Manipulation".to_string(),
            description: "Adversaries may manipulate AI agents through prompt injection, \
                goal hijacking, or exploiting agent reasoning to perform unauthorized actions."
                .to_string(),
            tactic: AtlasTactic::Execution,
            sub_techniques: vec![
                AtlasId::new("AML.T0060.001"), // Goal Hijacking
                AtlasId::new("AML.T0060.002"), // Reasoning Exploitation
            ],
            related: vec![AtlasId::new("AML.T0051"), AtlasId::new("AML.T0063")],
            url: "https://atlas.mitre.org/techniques/AML.T0060".to_string(),
        });

        // AML.T0060.001 - Goal Hijacking
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0060.001"),
            name: "Goal Hijacking".to_string(),
            description: "Adversaries redirect an agent's objectives to serve malicious goals \
                while maintaining apparent normal operation."
                .to_string(),
            tactic: AtlasTactic::Execution,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0060")],
            url: "https://atlas.mitre.org/techniques/AML.T0060.001".to_string(),
        });

        // AML.T0061 - Tool Poisoning (Agentic AI)
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0061"),
            name: "Tool Poisoning".to_string(),
            description: "Adversaries may compromise or manipulate tools available to AI agents, \
                including modifying tool definitions, responses, or creating malicious shadow tools."
                .to_string(),
            tactic: AtlasTactic::Persistence,
            sub_techniques: vec![
                AtlasId::new("AML.T0061.001"), // Tool Squatting
                AtlasId::new("AML.T0061.002"), // Schema Poisoning
                AtlasId::new("AML.T0061.003"), // Rug Pull
            ],
            related: vec![AtlasId::new("AML.T0060")],
            url: "https://atlas.mitre.org/techniques/AML.T0061".to_string(),
        });

        // AML.T0061.001 - Tool Squatting
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0061.001"),
            name: "Tool Squatting".to_string(),
            description: "Adversaries register tools with names similar to legitimate tools \
                to intercept agent requests."
                .to_string(),
            tactic: AtlasTactic::Persistence,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0061")],
            url: "https://atlas.mitre.org/techniques/AML.T0061.001".to_string(),
        });

        // AML.T0061.002 - Schema Poisoning
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0061.002"),
            name: "Schema Poisoning".to_string(),
            description: "Adversaries modify tool schemas to alter agent behavior or \
                exfiltrate data through modified parameters."
                .to_string(),
            tactic: AtlasTactic::Persistence,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0061")],
            url: "https://atlas.mitre.org/techniques/AML.T0061.002".to_string(),
        });

        // AML.T0061.003 - Rug Pull
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0061.003"),
            name: "Rug Pull".to_string(),
            description: "Adversaries change tool behavior after trust is established, \
                such as modifying annotations or capabilities."
                .to_string(),
            tactic: AtlasTactic::Persistence,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0061")],
            url: "https://atlas.mitre.org/techniques/AML.T0061.003".to_string(),
        });

        // AML.T0062 - Memory Injection (Agentic AI)
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0062"),
            name: "Memory Injection".to_string(),
            description: "Adversaries inject malicious content into agent memory or context \
                to influence future behavior, including cross-request data laundering."
                .to_string(),
            tactic: AtlasTactic::Persistence,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0051.002")],
            url: "https://atlas.mitre.org/techniques/AML.T0062".to_string(),
        });

        // AML.T0063 - Privilege Escalation (Agent)
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0063"),
            name: "Agent Privilege Escalation".to_string(),
            description: "Adversaries exploit agent architectures to gain elevated privileges, \
                including confused deputy attacks and delegation chain exploitation."
                .to_string(),
            tactic: AtlasTactic::Execution,
            sub_techniques: vec![
                AtlasId::new("AML.T0063.001"), // Confused Deputy
                AtlasId::new("AML.T0063.002"), // Delegation Chain Abuse
            ],
            related: vec![AtlasId::new("AML.T0060")],
            url: "https://atlas.mitre.org/techniques/AML.T0063".to_string(),
        });

        // AML.T0063.001 - Confused Deputy
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0063.001"),
            name: "Confused Deputy".to_string(),
            description: "Adversaries trick an agent with elevated privileges into performing \
                actions on their behalf."
                .to_string(),
            tactic: AtlasTactic::Execution,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0063")],
            url: "https://atlas.mitre.org/techniques/AML.T0063.001".to_string(),
        });

        // AML.T0064 - Data Exfiltration (Agent)
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0064"),
            name: "Agent Data Exfiltration".to_string(),
            description: "Adversaries use AI agents to exfiltrate sensitive data through \
                tool calls, covert channels, or steganographic techniques."
                .to_string(),
            tactic: AtlasTactic::Exfiltration,
            sub_techniques: vec![
                AtlasId::new("AML.T0064.001"), // Covert Channel
                AtlasId::new("AML.T0064.002"), // Steganography
            ],
            related: vec![],
            url: "https://atlas.mitre.org/techniques/AML.T0064".to_string(),
        });

        // AML.T0064.001 - Covert Channel
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0064.001"),
            name: "Covert Channel".to_string(),
            description: "Adversaries use hidden communication channels in agent outputs \
                to exfiltrate data."
                .to_string(),
            tactic: AtlasTactic::Exfiltration,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0064")],
            url: "https://atlas.mitre.org/techniques/AML.T0064.001".to_string(),
        });

        // AML.T0065 - Agent Impersonation
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0065"),
            name: "Agent Impersonation".to_string(),
            description: "Adversaries create shadow agents that impersonate legitimate agents \
                to intercept or manipulate communications."
                .to_string(),
            tactic: AtlasTactic::DefenseEvasion,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0060")],
            url: "https://atlas.mitre.org/techniques/AML.T0065".to_string(),
        });

        // AML.T0040 - Model Inference API Access
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0040"),
            name: "ML Model Inference API Access".to_string(),
            description: "Adversaries access ML model inference APIs to probe model behavior \
                or extract information."
                .to_string(),
            tactic: AtlasTactic::MlModelAccess,
            sub_techniques: vec![],
            related: vec![],
            url: "https://atlas.mitre.org/techniques/AML.T0040".to_string(),
        });

        // AML.T0025 - Exfiltration via ML Inference API
        self.add_technique(AtlasTechnique {
            id: AtlasId::new("AML.T0025"),
            name: "Exfiltration via ML Inference API".to_string(),
            description: "Adversaries exfiltrate data through responses from ML inference APIs."
                .to_string(),
            tactic: AtlasTactic::Exfiltration,
            sub_techniques: vec![],
            related: vec![AtlasId::new("AML.T0064")],
            url: "https://atlas.mitre.org/techniques/AML.T0025".to_string(),
        });
    }

    /// Register mappings from Vellaveto detections to ATLAS techniques.
    fn register_mappings(&mut self) {
        // Prompt Injection mappings
        self.map_detection(
            VellavetoDetection::PromptInjection,
            vec!["AML.T0051", "AML.T0051.001"],
        );
        self.map_detection(
            VellavetoDetection::IndirectInjection,
            vec!["AML.T0051", "AML.T0051.002"],
        );
        self.map_detection(
            VellavetoDetection::SecondOrderInjection,
            vec!["AML.T0051.002", "AML.T0060"],
        );
        self.map_detection(
            VellavetoDetection::UnicodeManipulation,
            vec!["AML.T0051", "AML.T0054"],
        );
        self.map_detection(
            VellavetoDetection::DelimiterInjection,
            vec!["AML.T0051", "AML.T0054"],
        );

        // Confused Deputy mappings
        self.map_detection(
            VellavetoDetection::ConfusedDeputy,
            vec!["AML.T0063", "AML.T0063.001"],
        );
        self.map_detection(VellavetoDetection::UnauthorizedDelegation, vec!["AML.T0063"]);
        self.map_detection(VellavetoDetection::PrivilegeEscalation, vec!["AML.T0063"]);

        // Tool Manipulation mappings
        self.map_detection(
            VellavetoDetection::ToolAnnotationChange,
            vec!["AML.T0061", "AML.T0061.003"],
        );
        self.map_detection(
            VellavetoDetection::ToolSquatting,
            vec!["AML.T0061", "AML.T0061.001"],
        );
        self.map_detection(
            VellavetoDetection::ToolShadowing,
            vec!["AML.T0061", "AML.T0061.001"],
        );
        self.map_detection(
            VellavetoDetection::SchemaPoisoning,
            vec!["AML.T0061", "AML.T0061.002"],
        );

        // Output Security mappings
        self.map_detection(
            VellavetoDetection::SecretsInOutput,
            vec!["AML.T0064", "AML.T0025"],
        );
        self.map_detection(
            VellavetoDetection::CovertChannel,
            vec!["AML.T0064", "AML.T0064.001"],
        );
        self.map_detection(VellavetoDetection::Steganography, vec!["AML.T0064"]);

        // Memory Poisoning mappings
        self.map_detection(VellavetoDetection::DataLaundering, vec!["AML.T0062"]);
        self.map_detection(VellavetoDetection::MemoryInjection, vec!["AML.T0062"]);
        self.map_detection(
            VellavetoDetection::GoalDrift,
            vec!["AML.T0060", "AML.T0060.001"],
        );

        // Excessive Agency mappings
        self.map_detection(VellavetoDetection::ExcessiveAgency, vec!["AML.T0060"]);
        self.map_detection(VellavetoDetection::WorkflowBudgetExceeded, vec!["AML.T0060"]);
        self.map_detection(VellavetoDetection::UnauthorizedToolAccess, vec!["AML.T0040"]);

        // Cascading Failure mappings (no direct ATLAS mapping yet)
        self.map_detection(VellavetoDetection::CircuitBreakerTriggered, vec![]);
        self.map_detection(VellavetoDetection::CascadingFailure, vec![]);

        // Shadow Agent mapping
        self.map_detection(VellavetoDetection::ShadowAgent, vec!["AML.T0065"]);

        // Sampling Attack mapping
        self.map_detection(
            VellavetoDetection::SamplingAttack,
            vec!["AML.T0040", "AML.T0025"],
        );

        // Token Security mappings
        self.map_detection(VellavetoDetection::TokenSmuggling, vec!["AML.T0054"]);
        self.map_detection(VellavetoDetection::ContextFlooding, vec!["AML.T0060"]);
        self.map_detection(VellavetoDetection::GlitchToken, vec!["AML.T0054"]);

        // Network Security mappings (no direct ATLAS mapping)
        self.map_detection(VellavetoDetection::PathTraversal, vec![]);
        self.map_detection(VellavetoDetection::DnsRebinding, vec![]);
        self.map_detection(VellavetoDetection::RateLimitExceeded, vec![]);
    }

    /// Add a technique to the registry.
    fn add_technique(&mut self, technique: AtlasTechnique) {
        self.techniques.insert(technique.id.clone(), technique);
    }

    /// Map a Vellaveto detection to ATLAS techniques.
    fn map_detection(&mut self, detection: VellavetoDetection, atlas_ids: Vec<&str>) {
        self.detection_mappings
            .insert(detection, atlas_ids.into_iter().map(AtlasId::new).collect());
    }

    /// Get technique by ID.
    pub fn get_technique(&self, id: &AtlasId) -> Option<&AtlasTechnique> {
        self.techniques.get(id)
    }

    /// Get all registered techniques.
    pub fn all_techniques(&self) -> impl Iterator<Item = &AtlasTechnique> {
        self.techniques.values()
    }

    /// Get ATLAS techniques for a Vellaveto detection.
    pub fn get_techniques_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&AtlasTechnique> {
        self.detection_mappings
            .get(&detection)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.techniques.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get ATLAS technique IDs for a Vellaveto detection.
    pub fn get_technique_ids_for_detection(&self, detection: VellavetoDetection) -> Vec<AtlasId> {
        self.detection_mappings
            .get(&detection)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all Vellaveto detections mapped to a specific ATLAS technique.
    pub fn get_detections_for_technique(&self, atlas_id: &AtlasId) -> Vec<VellavetoDetection> {
        self.detection_mappings
            .iter()
            .filter_map(|(detection, ids)| {
                if ids.contains(atlas_id) {
                    Some(*detection)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Generate coverage report.
    pub fn generate_coverage_report(&self) -> AtlasCoverageReport {
        let mut covered_techniques: Vec<AtlasId> = Vec::new();
        let mut uncovered_techniques: Vec<AtlasId> = Vec::new();
        let mut unmapped_detections: Vec<VellavetoDetection> = Vec::new();

        // Find covered techniques
        for (detection, ids) in &self.detection_mappings {
            if ids.is_empty() {
                unmapped_detections.push(*detection);
            } else {
                for id in ids {
                    if !covered_techniques.contains(id) {
                        covered_techniques.push(id.clone());
                    }
                }
            }
        }

        // Find uncovered techniques
        for id in self.techniques.keys() {
            if !covered_techniques.contains(id) {
                uncovered_techniques.push(id.clone());
            }
        }

        let total_techniques = self.techniques.len();
        let coverage_percent = if total_techniques > 0 {
            (covered_techniques.len() as f32 / total_techniques as f32) * 100.0
        } else {
            0.0
        };

        AtlasCoverageReport {
            total_techniques,
            covered_techniques,
            uncovered_techniques,
            unmapped_detections,
            coverage_percent,
        }
    }
}

impl Default for AtlasRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// ATLAS coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasCoverageReport {
    /// Total number of ATLAS techniques in registry.
    pub total_techniques: usize,
    /// Techniques covered by Vellaveto detections.
    pub covered_techniques: Vec<AtlasId>,
    /// Techniques not covered by Vellaveto.
    pub uncovered_techniques: Vec<AtlasId>,
    /// Vellaveto detections without ATLAS mapping.
    pub unmapped_detections: Vec<VellavetoDetection>,
    /// Coverage percentage.
    pub coverage_percent: f32,
}

impl AtlasCoverageReport {
    /// Generate a human-readable report.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== MITRE ATLAS Coverage Report ===\n\n");
        report.push_str(&format!(
            "Coverage: {:.1}% ({}/{} techniques)\n\n",
            self.coverage_percent,
            self.covered_techniques.len(),
            self.total_techniques
        ));

        report.push_str("Covered Techniques:\n");
        for id in &self.covered_techniques {
            report.push_str(&format!("  ✓ {id}\n"));
        }

        if !self.uncovered_techniques.is_empty() {
            report.push_str("\nUncovered Techniques:\n");
            for id in &self.uncovered_techniques {
                report.push_str(&format!("  ✗ {id}\n"));
            }
        }

        if !self.unmapped_detections.is_empty() {
            report.push_str("\nDetections without ATLAS Mapping:\n");
            for detection in &self.unmapped_detections {
                report.push_str(&format!("  ? {detection}\n"));
            }
        }

        report
    }
}

/// Helper to add ATLAS technique IDs to audit metadata.
pub fn add_atlas_metadata(
    metadata: &mut serde_json::Value,
    detection: VellavetoDetection,
    registry: &AtlasRegistry,
) {
    let technique_ids = registry.get_technique_ids_for_detection(detection);
    if !technique_ids.is_empty() {
        let ids: Vec<String> = technique_ids.iter().map(|id| id.0.clone()).collect();
        if let serde_json::Value::Object(ref mut map) = metadata {
            map.insert(
                "atlas_techniques".to_string(),
                serde_json::Value::Array(ids.into_iter().map(serde_json::Value::String).collect()),
            );
            map.insert(
                "detection_type".to_string(),
                serde_json::Value::String(detection.to_string()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = AtlasRegistry::new();
        assert!(!registry.techniques.is_empty());
        assert!(!registry.detection_mappings.is_empty());
    }

    #[test]
    fn test_get_technique() {
        let registry = AtlasRegistry::new();
        let technique = registry.get_technique(&AtlasId::new("AML.T0051"));
        assert!(technique.is_some());
        assert_eq!(technique.unwrap().name, "LLM Prompt Injection");
    }

    #[test]
    fn test_detection_to_techniques() {
        let registry = AtlasRegistry::new();
        let techniques = registry.get_techniques_for_detection(VellavetoDetection::PromptInjection);
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.id.0 == "AML.T0051"));
    }

    #[test]
    fn test_detection_to_technique_ids() {
        let registry = AtlasRegistry::new();
        let ids = registry.get_technique_ids_for_detection(VellavetoDetection::ToolSquatting);
        assert!(ids.iter().any(|id| id.0 == "AML.T0061.001"));
    }

    #[test]
    fn test_technique_to_detections() {
        let registry = AtlasRegistry::new();
        let detections = registry.get_detections_for_technique(&AtlasId::new("AML.T0051"));
        assert!(!detections.is_empty());
        assert!(detections.contains(&VellavetoDetection::PromptInjection));
    }

    #[test]
    fn test_coverage_report() {
        let registry = AtlasRegistry::new();
        let report = registry.generate_coverage_report();

        assert!(report.total_techniques > 0);
        assert!(!report.covered_techniques.is_empty());
        assert!(report.coverage_percent > 0.0);
    }

    #[test]
    fn test_coverage_report_string() {
        let registry = AtlasRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("MITRE ATLAS Coverage Report"));
        assert!(report_str.contains("Coverage:"));
    }

    #[test]
    fn test_add_atlas_metadata() {
        let registry = AtlasRegistry::new();
        let mut metadata = serde_json::json!({});

        add_atlas_metadata(&mut metadata, VellavetoDetection::PromptInjection, &registry);

        assert!(metadata.get("atlas_techniques").is_some());
        assert!(metadata.get("detection_type").is_some());
    }

    #[test]
    fn test_all_detections_have_mappings() {
        let registry = AtlasRegistry::new();

        // Verify all detection variants are in the mapping
        let detections = [
            VellavetoDetection::PromptInjection,
            VellavetoDetection::IndirectInjection,
            VellavetoDetection::ConfusedDeputy,
            VellavetoDetection::ToolSquatting,
            VellavetoDetection::ShadowAgent,
        ];

        for detection in detections {
            let _ = registry.get_technique_ids_for_detection(detection);
            // Just verify it doesn't panic
        }
    }

    #[test]
    fn test_tactic_display() {
        assert_eq!(format!("{}", AtlasTactic::Reconnaissance), "Reconnaissance");
        assert_eq!(format!("{}", AtlasTactic::Exfiltration), "Exfiltration");
    }

    #[test]
    fn test_detection_display() {
        assert_eq!(
            format!("{}", VellavetoDetection::PromptInjection),
            "Prompt Injection"
        );
        assert_eq!(
            format!("{}", VellavetoDetection::ShadowAgent),
            "Shadow Agent"
        );
    }
}
