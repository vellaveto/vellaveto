# Sentinel v2.1/v2.2 Comprehensive Implementation Plan

> **Generated:** 2026-02-09
> **Based on:** Swarm research of 6 web research agents
> **Current Status:** Phase 8 (ETDI) + Phase 9 (MINJA) complete
> **Remaining:** Phases 10-15

---

## Executive Summary

Based on comprehensive web research, this plan details the implementation of remaining Sentinel features for v2.1 and v2.2 releases. Key findings:

1. **NHI market is maturing** - CyberArk acquired Venafi for $1.54B, integrating human and machine identities
2. **MCP Tasks primitive** requires careful security consideration for state persistence and replay protection
3. **Semantic guardrails** are becoming standard - Guardrails AI Guardrails Index benchmarks 24 solutions
4. **RAG poisoning** is a critical threat - OWASP LLM08 addresses vector/embedding weaknesses
5. **A2A protocol** adoption accelerating - Agent Gateway provides drop-in security
6. **Observability platforms** (Langfuse, Arize, Helicone) all support OpenTelemetry

---

## Phase 10: Non-Human Identity (NHI) Lifecycle (v2.1 - P1)

### Research Findings

**Industry Trends:**
- Machine identities outnumber humans 45:1 (CyberArk)
- NIST SP 1800-35 mandates Zero Trust by 2026 for federal agencies
- NHI platforms (Oasis, Entro, Astrix) provide discovery, threat detection, lifecycle management

**Key Technologies:**
- **SPIFFE/SPIRE**: Cryptographic workload identities, federation across clouds
- **DPoP (RFC 9449)**: Proof-of-possession tokens, sender-constrained access
- **Workload Identity Federation**: AWS, Azure, GCP all support token exchange
- **Aembit**: Universal Security Token Service across clouds

### Implementation Tasks

#### 10.1 Agent Identity Registry
```rust
// sentinel-mcp/src/nhi.rs

pub struct AgentIdentity {
    pub id: String,
    pub attestation_type: AttestationType,
    pub spiffe_id: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub behavioral_baseline: Option<BehavioralBaseline>,
}

pub enum AttestationType {
    Jwt,
    Mtls,
    Spiffe,
    DPoP,
}

pub struct AgentRegistry {
    identities: DashMap<String, AgentIdentity>,
    revocation_list: HashSet<String>,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Define AgentIdentity and AttestationType types | P1 | 1 day |
| Implement AgentRegistry with registration/revocation | P1 | 2 days |
| Add SPIFFE ID extraction from X.509 certs (extend existing) | P1 | 1 day |
| Implement DPoP verification (RFC 9449) | P1 | 2 days |
| Add credential rotation tracking | P1 | 1 day |

#### 10.2 Behavioral Attestation
```rust
pub struct BehavioralBaseline {
    pub tool_call_patterns: HashMap<String, f64>,  // tool -> frequency
    pub avg_request_interval: Duration,
    pub typical_session_duration: Duration,
    pub last_updated: DateTime<Utc>,
}

pub struct BehavioralAttestator {
    baselines: DashMap<String, BehavioralBaseline>,
    anomaly_threshold: f64,  // 0.0-1.0
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Extend behavioral.rs for per-agent baselines | P1 | 2 days |
| Implement continuous authentication scoring | P1 | 2 days |
| Add behavioral drift detection with alerting | P1 | 1 day |
| Create baseline learning from historical data | P2 | 2 days |

#### 10.3 Delegation Accountability
```rust
pub struct DelegationChain {
    pub chain: Vec<DelegationLink>,
    pub max_depth: usize,
}

pub struct DelegationLink {
    pub from_agent: String,
    pub to_agent: String,
    pub permissions: HashSet<Permission>,
    pub scope_constraints: Vec<ScopeConstraint>,
    pub expires_at: DateTime<Utc>,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Enhance delegation chain with scope constraints | P1 | 2 days |
| Implement delegation approval workflow | P1 | 2 days |
| Add delegation audit reports | P1 | 1 day |

#### 10.4 Configuration
```toml
[nhi]
enabled = true
credential_ttl_secs = 3600
max_credential_ttl_secs = 86400
require_attestation = true
attestation_types = ["jwt", "mtls", "spiffe", "dpop"]
auto_revoke_on_anomaly = true
anomaly_threshold = 0.3
baseline_learning_period_hours = 168  # 7 days

[nhi.dpop]
require_nonce = true
max_clock_skew_secs = 300
allowed_algorithms = ["ES256", "RS256"]
```

### API Endpoints
- `POST /api/nhi/agents` - Register agent identity
- `GET /api/nhi/agents/{id}` - Get agent details
- `DELETE /api/nhi/agents/{id}` - Revoke agent
- `GET /api/nhi/agents/{id}/behavioral` - Get behavioral baseline
- `POST /api/nhi/delegations` - Create delegation
- `GET /api/nhi/delegations/{id}/chain` - Get full delegation chain

**Estimated Duration:** 3 weeks

---

## Phase 11: MCP Tasks Primitive Security (v2.1 - P1)

### Research Findings

**MCP 2025-11-25 Tasks Specification:**
- Tasks enable long-running operations with state persistence
- Status lifecycle: `working` → `input_required` | `completed` | `failed` | `cancelled`
- Task IDs must be cryptographically secure to prevent enumeration
- TTL-based resource management with configurable cleanup
- Result retrieval via `tasks/result` blocks until completion

**Security Concerns:**
- Task state tampering during execution
- Replay attacks on task resumption
- Unauthorized task cancellation (DoS)
- Session hijacking via stolen task tokens
- SSRF via push notification URLs

### Implementation Tasks

#### 11.1 Task State Security
```rust
// sentinel-mcp/src/task_security.rs

pub struct SecureTask {
    pub id: TaskId,
    pub state_hash: [u8; 32],  // SHA-256 of serialized state
    pub nonce: [u8; 16],
    pub created_at: DateTime<Utc>,
    pub session_binding: SessionBinding,
    pub authorization_context: AuthContext,
}

pub struct TaskSecurityManager {
    tasks: DashMap<TaskId, SecureTask>,
    state_signer: Ed25519Signer,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Define SecureTask with state hashing | P1 | 1 day |
| Implement task state signing (Ed25519) | P1 | 2 days |
| Add session binding validation | P1 | 1 day |
| Implement replay protection with nonces | P1 | 1 day |

#### 11.2 Task Authentication
```rust
pub struct TaskAuthenticator {
    /// Verify task ownership before resume/cancel
    pub fn verify_task_access(&self, task_id: &TaskId, context: &AuthContext) -> Result<(), TaskError>;

    /// Generate secure task token for polling
    pub fn generate_task_token(&self, task: &SecureTask) -> String;

    /// Validate task token on resume
    pub fn validate_task_token(&self, token: &str) -> Result<TaskId, TaskError>;
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement task ownership verification | P1 | 2 days |
| Add secure task token generation (JWT-based) | P1 | 1 day |
| Implement task timeout enforcement | P1 | 1 day |

#### 11.3 Task Integrity Verification
```rust
pub struct TaskCheckpoint {
    pub sequence: u64,
    pub state_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub signature: [u8; 64],
}

pub struct TaskIntegrityVerifier {
    /// Verify checkpoint chain integrity
    pub fn verify_checkpoint_chain(&self, checkpoints: &[TaskCheckpoint]) -> Result<(), IntegrityError>;

    /// Detect state tampering
    pub fn detect_tampering(&self, task: &SecureTask, new_state: &[u8]) -> bool;
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement checkpoint hash chain | P1 | 2 days |
| Add tampering detection on result retrieval | P1 | 1 day |
| Create checkpoint verification API | P1 | 1 day |

#### 11.4 Push Notification Security
```rust
pub struct PushNotificationValidator {
    /// Validate webhook URL (SSRF prevention)
    pub fn validate_webhook_url(&self, url: &str) -> Result<(), ValidationError>;

    /// Generate HMAC signature for notification
    pub fn sign_notification(&self, payload: &[u8], secret: &[u8]) -> [u8; 32];

    /// Verify notification replay protection
    pub fn check_replay(&self, notification_id: &str) -> bool;
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement webhook URL allowlisting | P1 | 1 day |
| Add HMAC signing for notifications | P1 | 1 day |
| Implement replay protection with nonce tracking | P1 | 1 day |

#### 11.5 Configuration
```toml
[mcp_tasks]
enabled = true
max_task_duration_secs = 3600
max_concurrent_tasks_per_session = 100
require_state_signing = true
checkpoint_interval_secs = 60
enable_push_notifications = true

[mcp_tasks.push_notifications]
allowed_domains = ["hooks.example.com", "webhooks.internal.corp"]
require_https = true
max_retry_attempts = 3
signature_algorithm = "hmac-sha256"
replay_window_secs = 300
```

### API Endpoints
- `GET /api/tasks` - List tasks with filtering
- `GET /api/tasks/{id}` - Get task details
- `GET /api/tasks/{id}/checkpoints` - Get checkpoint chain
- `POST /api/tasks/{id}/verify` - Verify task integrity
- `DELETE /api/tasks/{id}` - Cancel task (with auth)

**Estimated Duration:** 2 weeks

---

## Phase 12: Semantic Guardrails (v2.2 - P2)

### Research Findings

**Industry State (2025):**
- Guardrails AI launched Guardrails Index benchmarking 24 solutions
- Best performers: OpenAI embeddings + XGBoost (97.7% accuracy, 0.977 F1)
- Qwen3Guard-8B: 85.3% accuracy but poor generalization (91% → 34% on unseen)
- Critical trade-off: Speed vs Safety vs Accuracy (pick 2)
- Latency targets: <100ms for UX, <200ms tolerable

**Approaches:**
- **Embedding-based**: Cosine similarity to known attack patterns (fast, less accurate)
- **Classifier-based**: XGBoost/LightGBM on embeddings (good balance)
- **LLM-as-judge**: Full semantic understanding (slow, most accurate)
- **Hybrid**: Fast pre-filter + LLM verification for flagged content

### Implementation Tasks

#### 12.1 LLM Policy Evaluator Interface
```rust
// sentinel-mcp/src/semantic_guardrails.rs

pub trait SemanticEvaluator: Send + Sync {
    async fn evaluate(&self, input: &str, context: &EvalContext) -> Result<EvalResult, EvalError>;
}

pub struct EvalResult {
    pub verdict: Verdict,
    pub confidence: f64,
    pub intent_classification: Option<IntentClass>,
    pub risk_factors: Vec<RiskFactor>,
    pub latency_ms: u64,
}

pub enum IntentClass {
    Benign,
    DataExfiltration,
    PrivilegeEscalation,
    InjectionAttempt,
    Jailbreak,
    Other(String),
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Define SemanticEvaluator trait | P2 | 1 day |
| Implement local GGUF model support (llama.cpp bindings) | P2 | 3 days |
| Add cloud model support (OpenAI, Anthropic) | P2 | 2 days |
| Create evaluation caching layer (LRU) | P2 | 1 day |

#### 12.2 Embedding-Based Pre-Filter
```rust
pub struct EmbeddingGuardrail {
    attack_embeddings: Vec<([f32; 384], AttackType)>,  // MiniLM-L6-v2 dimension
    similarity_threshold: f32,
}

impl EmbeddingGuardrail {
    pub fn quick_check(&self, input_embedding: &[f32; 384]) -> Option<AttackType> {
        // Cosine similarity scan - O(n) but fast with SIMD
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Integrate sentence-transformers (MiniLM-L6-v2) | P2 | 2 days |
| Build attack pattern embedding database | P2 | 2 days |
| Implement SIMD-accelerated cosine similarity | P2 | 1 day |
| Add threshold tuning per attack category | P2 | 1 day |

#### 12.3 Intent Classification Pipeline
```rust
pub struct IntentClassifier {
    embedding_filter: EmbeddingGuardrail,
    llm_evaluator: Box<dyn SemanticEvaluator>,
    confidence_threshold: f64,
}

impl IntentClassifier {
    pub async fn classify(&self, input: &str) -> IntentResult {
        // Stage 1: Fast embedding check (5-10ms)
        if let Some(attack) = self.embedding_filter.quick_check(&embed(input)) {
            return IntentResult::blocked(attack);
        }

        // Stage 2: LLM evaluation for borderline cases (100-500ms)
        let eval = self.llm_evaluator.evaluate(input, &context).await?;
        // ...
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement two-stage classification pipeline | P2 | 2 days |
| Add confidence thresholds with fallback | P2 | 1 day |
| Create intent chain tracking (multi-turn) | P2 | 2 days |

#### 12.4 Configuration
```toml
[semantic_guardrails]
enabled = true
mode = "hybrid"  # embedding | llm | hybrid

[semantic_guardrails.embedding]
model = "sentence-transformers/all-MiniLM-L6-v2"
similarity_threshold = 0.85
attack_patterns_file = "/etc/sentinel/attack_patterns.json"

[semantic_guardrails.llm]
provider = "local"  # local | openai | anthropic
model = "llama-guard-3-8b"
model_path = "/models/llama-guard-3.gguf"
max_tokens = 100
timeout_ms = 500
fallback_on_timeout = "embedding"  # embedding | deny | allow

[semantic_guardrails.caching]
enabled = true
ttl_secs = 300
max_entries = 10000
```

### API Endpoints
- `POST /api/guardrails/evaluate` - Evaluate input
- `GET /api/guardrails/stats` - Classification statistics
- `POST /api/guardrails/patterns` - Add attack pattern
- `GET /api/guardrails/patterns` - List patterns

**Estimated Duration:** 4 weeks

---

## Phase 13: RAG Poisoning Defense (v2.2 - P2)

### Research Findings

**Attack Vectors (OWASP LLM08):**
- Embedding inversion: Reconstruct sensitive data from embeddings
- Data poisoning: Inject malicious content into knowledge base
- Query manipulation: Craft queries that surface poisoned documents
- Position bias exploitation: High-ranked poisoned docs get more weight

**Defense Mechanisms:**
- **RA-RAG**: Reliability-Aware RAG with source trust scoring
- **Perplexity filtering**: Flag docs with abnormal perplexity vs trusted corpus
- **Scoring-based filtering**: Suppress docs activated by narrow query sets
- **ReliabilityRAG**: Graph-theoretic "consistent majority" over retrieved docs

### Implementation Tasks

#### 13.1 Document Provenance
```rust
// sentinel-mcp/src/rag_security.rs

pub struct DocumentProvenance {
    pub id: String,
    pub source: DocumentSource,
    pub ingestion_time: DateTime<Utc>,
    pub content_hash: [u8; 32],
    pub trust_score: f64,
    pub approval_status: ApprovalStatus,
}

pub enum DocumentSource {
    Trusted { name: String, verified: bool },
    UserSubmitted { user_id: String },
    External { url: String, last_verified: DateTime<Utc> },
}

pub enum ApprovalStatus {
    Pending,
    Approved { by: String, at: DateTime<Utc> },
    Rejected { reason: String },
    AutoApproved,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Define DocumentProvenance with source tracking | P2 | 1 day |
| Implement document approval workflow | P2 | 2 days |
| Add content hashing and verification | P2 | 1 day |
| Create trust score calculation | P2 | 2 days |

#### 13.2 Retrieval Security
```rust
pub struct RetrievalSecurityFilter {
    trust_threshold: f64,
    diversity_minimum: usize,
    max_single_source_ratio: f64,
}

impl RetrievalSecurityFilter {
    pub fn filter_results(&self, results: Vec<RetrievalResult>) -> Vec<RetrievalResult> {
        // Filter by trust score
        // Enforce diversity (no single source dominance)
        // Apply position-aware weighting
    }

    pub fn detect_poisoning_pattern(&self, results: &[RetrievalResult]) -> Option<PoisoningAlert> {
        // Check for suspicious clustering
        // Detect narrow query activation
        // Flag anomalous embedding distances
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement retrieval result filtering | P2 | 2 days |
| Add diversity enforcement | P2 | 1 day |
| Create poisoning pattern detection | P2 | 3 days |

#### 13.3 Embedding Anomaly Detection
```rust
pub struct EmbeddingAnomalyDetector {
    baseline_distribution: EmbeddingDistribution,
    anomaly_threshold: f64,
}

impl EmbeddingAnomalyDetector {
    pub fn detect_anomaly(&self, embedding: &[f32]) -> Option<AnomalyReport> {
        // Statistical distance from baseline
        // Outlier detection (IQR or z-score)
    }

    pub fn update_baseline(&mut self, embeddings: &[[f32]]) {
        // Rolling update of baseline statistics
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement embedding distribution tracking | P2 | 2 days |
| Add statistical anomaly detection | P2 | 2 days |
| Create baseline update mechanism | P2 | 1 day |

#### 13.4 Configuration
```toml
[rag_security]
enabled = true
require_document_approval = false  # true for high-security
trust_threshold = 0.5
max_document_age_days = 365

[rag_security.retrieval]
diversity_minimum = 3
max_single_source_ratio = 0.6
enable_position_bias_correction = true

[rag_security.anomaly_detection]
enabled = true
anomaly_threshold = 3.0  # z-score
baseline_update_interval_hours = 24
```

### API Endpoints
- `POST /api/rag/documents` - Ingest document with provenance
- `GET /api/rag/documents/{id}/provenance` - Get document provenance
- `POST /api/rag/documents/{id}/approve` - Approve document
- `GET /api/rag/anomalies` - List detected anomalies
- `GET /api/rag/stats` - RAG security statistics

**Estimated Duration:** 3 weeks

---

## Phase 14: A2A Protocol Security (v2.2 - P2)

### Research Findings

**A2A Protocol (Google 2025):**
- JSON-RPC 2.0 based, complementary to MCP
- Agent discovery via AgentCard (similar to OpenAPI)
- OAuth 2.0/OIDC authentication standard
- Push notifications with HMAC/JWT verification
- Task management for long-running operations

**Security Considerations (Semgrep):**
- Session token theft: Multiple concurrent streams without termination
- Sensitive data in transit: Capabilities-based authorization needed
- JSON attack surface: Unicode normalization, nested depth, dynamic types
- SSRF via push notification URLs

**Solutions:**
- Agent Gateway (agentgateway.dev): Drop-in A2A/MCP security
- MCP Context Forge (IBM): Unified A2A/MCP gateway
- Gravitee Agent Mesh: Enterprise A2A governance

### Implementation Tasks

#### 14.1 A2A Message Parsing
```rust
// sentinel-mcp/src/a2a.rs

pub struct A2AMessage {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: Option<serde_json::Value>,
}

pub struct A2AParser {
    max_depth: usize,
    max_payload_size: usize,
}

impl A2AParser {
    pub fn parse(&self, input: &[u8]) -> Result<A2AMessage, A2AError> {
        // Depth limiting
        // Size validation
        // Unicode normalization
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement A2A message parser with limits | P2 | 2 days |
| Add Unicode normalization (NFKC) | P2 | 1 day |
| Create AgentCard parser and validator | P2 | 1 day |

#### 14.2 A2A Policy Evaluation
```rust
pub struct A2APolicy {
    pub agent_pattern: String,      // Glob pattern for agent IDs
    pub method_pattern: String,     // skills/invoke, tasks/*, etc.
    pub policy_type: PolicyType,
    pub capability_requirements: Vec<String>,
}

pub struct A2APolicyEngine {
    policies: Vec<A2APolicy>,
}

impl A2APolicyEngine {
    pub fn evaluate(&self, msg: &A2AMessage, agent: &AgentCard) -> Verdict {
        // Match agent ID
        // Match method
        // Verify capabilities
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Define A2APolicy type | P2 | 1 day |
| Implement A2A policy engine | P2 | 2 days |
| Add capability verification | P2 | 1 day |

#### 14.3 A2A Proxy Mode
```rust
pub struct A2AProxy {
    upstream: String,
    policy_engine: A2APolicyEngine,
    audit_logger: AuditLogger,
}

impl A2AProxy {
    pub async fn handle(&self, request: Request) -> Response {
        // Parse A2A message
        // Evaluate policy
        // Forward or deny
        // Audit log
    }
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement A2A proxy handler | P2 | 3 days |
| Add bidirectional streaming support | P2 | 2 days |
| Create A2A audit logging | P2 | 1 day |

#### 14.4 Configuration
```toml
[a2a]
enabled = true
mode = "proxy"  # proxy | passthrough | block

[[a2a.policies]]
agent_pattern = "spiffe://example.org/agents/*"
method_pattern = "skills/invoke"
policy_type = "Allow"
require_capabilities = ["skill:execute"]

[[a2a.policies]]
agent_pattern = "*"
method_pattern = "tasks/cancel"
policy_type = "RequireApproval"

[a2a.push_notifications]
allowed_domains = ["notify.example.org"]
require_jwt_verification = true
```

### API Endpoints
- `GET /api/a2a/agents` - List discovered agents
- `GET /api/a2a/agents/{id}` - Get agent card
- `GET /api/a2a/policies` - List A2A policies
- `POST /api/a2a/policies` - Create A2A policy
- `GET /api/a2a/stats` - A2A traffic statistics

**Estimated Duration:** 2 weeks

---

## Phase 15: Observability Platform Integration (v2.2 - P3)

### Research Findings

**Platform Landscape:**
- **Langfuse**: Open-source, self-hostable, OTEL support, tiered pricing calculations
- **Arize Phoenix**: OpenInference semantic conventions, OTEL-native
- **Helicone**: Proxy-based, simple URL swap integration
- **Datadog LLM Observability**: Enterprise APM integration

**OpenTelemetry for LLMs:**
- OpenInference semantic conventions: Span kinds (LLM, Chain, Tool, Agent, Retriever)
- Standard attributes: `llm.token_count.total`, `tool.name`, `tool.parameters`
- Gateway deployment: Single collector for all LLM traffic
- Security: Mask sensitive data, RBAC, audit trails

**Key Metrics:**
- Reliability: Latency, rate limits, provider failures
- Quality: Accuracy, grounding, eval performance
- Safety: Jailbreaks, toxicity, PII leaks
- Cost: Token usage, retries, budget adherence

### Implementation Tasks

#### 15.1 OpenTelemetry Enhancement
```rust
// sentinel-server/src/otel.rs

pub struct LLMSpanAttributes {
    pub span_kind: OpenInferenceSpanKind,
    pub model: String,
    pub token_count_prompt: u64,
    pub token_count_completion: u64,
    pub tool_name: Option<String>,
    pub verdict: Verdict,
}

pub enum OpenInferenceSpanKind {
    Llm,
    Chain,
    Tool,
    Agent,
    Retriever,
    Embedding,
    Guardrail,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Extend OTEL spans with OpenInference attributes | P3 | 2 days |
| Add security verdict to all spans | P3 | 1 day |
| Implement sensitive data masking | P3 | 1 day |

#### 15.2 Platform Exporters
```rust
pub trait ObservabilityExporter: Send + Sync {
    async fn export(&self, span: &SecuritySpan) -> Result<(), ExportError>;
}

pub struct LangfuseExporter {
    endpoint: String,
    api_key: String,
}

pub struct ArizeExporter {
    endpoint: String,
    space_key: String,
    api_key: String,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement Langfuse exporter (trace + generation) | P3 | 2 days |
| Implement Arize/Phoenix exporter | P3 | 2 days |
| Implement Helicone exporter (headers) | P3 | 1 day |
| Add generic webhook exporter | P3 | 1 day |

#### 15.3 Security Event Streaming
```rust
pub struct SecurityEventStream {
    exporters: Vec<Box<dyn ObservabilityExporter>>,
    buffer: mpsc::Sender<SecurityEvent>,
}

pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub verdict: Verdict,
    pub action: Action,
    pub detection_metadata: HashMap<String, serde_json::Value>,
}
```

| Task | Priority | Effort |
|------|----------|--------|
| Implement security event streaming | P3 | 2 days |
| Add buffering and batch export | P3 | 1 day |
| Create trace filtering by verdict | P3 | 1 day |

#### 15.4 Configuration
```toml
[observability]
enabled = true
mask_sensitive_data = true
sample_rate = 1.0

[observability.langfuse]
enabled = true
endpoint = "https://cloud.langfuse.com"
public_key = "pk-..."
secret_key = "sk-..."

[observability.arize]
enabled = false
endpoint = "https://api.arize.com"
space_key = "..."
api_key = "..."

[observability.helicone]
enabled = false
api_key = "..."

[observability.webhook]
enabled = true
url = "https://siem.example.com/webhook"
include_full_request = false  # PII consideration
```

### API Endpoints
- `GET /api/observability/exporters` - List configured exporters
- `POST /api/observability/test` - Test exporter connectivity
- `GET /api/observability/stats` - Export statistics

**Estimated Duration:** 2 weeks

---

## Timeline Summary

```
Phase 10: NHI Lifecycle                  3 weeks  ← v2.1 P1
Phase 11: MCP Tasks Primitive            2 weeks  ← v2.1 P1
─────────────────────────────────────────────────
v2.1 Total: 5 weeks (~1.25 months)

Phase 12: Semantic Guardrails            4 weeks  ← v2.2 P2
Phase 13: RAG Poisoning Defense          3 weeks  ← v2.2 P2
Phase 14: A2A Protocol Security          2 weeks  ← v2.2 P2
Phase 15: Observability Integration      2 weeks  ← v2.2 P3
─────────────────────────────────────────────────
v2.2 Total: 11 weeks (~2.75 months)

Grand Total: 16 weeks (~4 months)
```

---

## Implementation Order

### v2.1 (Priority: High)
1. **Phase 10.1**: Agent Identity Registry (foundation for NHI)
2. **Phase 11.1-11.2**: Task state security and authentication
3. **Phase 10.2**: Behavioral attestation
4. **Phase 11.3-11.4**: Task integrity and push notification security
5. **Phase 10.3**: Delegation accountability

### v2.2 (Priority: Medium-Low)
1. **Phase 12.1-12.2**: Embedding guardrails (fast path)
2. **Phase 14.1-14.2**: A2A parsing and policy (protocol support)
3. **Phase 12.3**: LLM evaluator (slow path)
4. **Phase 13.1-13.2**: RAG document provenance and filtering
5. **Phase 15.1-15.2**: Observability exporters
6. **Phase 13.3**: Embedding anomaly detection
7. **Phase 14.3**: A2A proxy mode
8. **Phase 15.3**: Security event streaming

---

## Dependencies

### External Libraries (New)
```toml
# Cargo.toml additions
sentence-transformers = "0.1"  # Embedding models (or candle bindings)
llama-cpp-rs = "0.5"          # Local LLM inference
dpop = "0.2"                  # RFC 9449 DPoP tokens
```

### Feature Flags
```toml
[features]
default = ["nhi", "mcp-tasks"]
nhi = ["dpop"]
mcp-tasks = []
semantic-guardrails = ["sentence-transformers", "llama-cpp-rs"]
rag-security = ["sentence-transformers"]
a2a = []
observability = []
```

---

## Success Metrics

### Phase 10 (NHI)
- Agent registration latency <10ms
- Behavioral anomaly detection accuracy >90%
- Delegation chain verification <5ms

### Phase 11 (MCP Tasks)
- Task state verification <1ms
- Zero replay attacks in adversarial testing
- Push notification delivery <100ms

### Phase 12 (Semantic Guardrails)
- Embedding pre-filter latency <20ms
- Combined pipeline latency <200ms (P95)
- Detection accuracy >95% on Guardrails Index benchmark

### Phase 13 (RAG Security)
- Document provenance lookup <5ms
- Poisoning detection precision >85%
- Zero false positives on trusted documents

### Phase 14 (A2A)
- A2A message parsing <2ms
- Policy evaluation <5ms
- Proxy overhead <10ms

### Phase 15 (Observability)
- Export latency <50ms
- Zero data loss at 10k events/sec
- All security verdicts captured in traces

---

## Research Sources

1. [CyberArk Venafi Acquisition](https://www.cyberark.com/venafi-and-cyberark-machine-identity-security/)
2. [MCP 2025-11-25 Tasks Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/tasks)
3. [Guardrails AI Guardrails Index](https://index.guardrailsai.com)
4. [OWASP LLM08 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
5. [A2A Protocol Security Guide (Semgrep)](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-the-a2a-protocol/)
6. [Agent Gateway](https://agentgateway.dev/)
7. [OpenInference Semantic Conventions](https://github.com/Arize-ai/openinference/blob/main/spec/semantic_conventions.md)
8. [Langfuse Cost Tracking](https://langfuse.com/docs/observability/features/token-and-cost-tracking)
9. [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
10. [RA-RAG: Reliability-Aware RAG](https://arxiv.org/abs/2410.22954)
