# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 12: Semantic Guardrails (LLM-Based Policy Evaluation)
- **Intent Classification** — Structured taxonomy of action intents (DataRead, DataWrite, SystemExecute, NetworkFetch, CredentialAccess, etc.) with confidence scoring and risk category detection
- **Natural Language Policies** — Define policies in plain English with glob-based tool/function matching, compiled to efficient matchers
- **LLM Evaluator Interface** — Pluggable backend abstraction supporting cloud (OpenAI, Anthropic) and local (GGUF, ONNX) model evaluation
- **Evaluation Caching** — LRU + TTL cache for LLM evaluations to minimize latency and cost on repeated patterns
- **Jailbreak Detection** — LLM-based detection of adversarial prompts resistant to pattern evasion, with configurable thresholds
- **Intent Chain Tracking** — Per-session tracking of action intents to detect suspicious patterns like reconnaissance→exfiltration sequences
- **SemanticGuardrailsService** — High-level service combining evaluator, cache, intent tracking, and NL policies
- **Mock Backend** — Configurable mock implementation for testing with pattern-based response rules and simulated latency
- **New Types**: `Intent`, `IntentClassification`, `IntentChain`, `RiskCategory`, `SuspiciousPattern`, `LlmEvalInput`, `LlmEvaluation`, `LlmEvaluator`, `NlPolicy`, `NlPolicyCompiler`, `JailbreakDetection`, `FallbackBehavior`
- **New Config**: `SemanticGuardrailsConfig` with OpenAI/Anthropic backend configs, intent classification settings, jailbreak detection thresholds, cache TTL, and fallback behavior
- **Feature Flag**: `semantic-guardrails` (core), `llm-cloud` (OpenAI/Anthropic), `llm-local-gguf`, `llm-local-onnx`

#### Phase 11: MCP Tasks Primitive Security
- **Task State Encryption** — ChaCha20-Poly1305 AEAD encryption for task state data, protecting sensitive information at rest
- **Resume Token Authentication** — HMAC-SHA256 tokens for authenticated task resumption, preventing unauthorized access to long-running tasks
- **Hash Chain Integrity** — SHA-256 hash chain tracking all state transitions with sequence numbers, timestamps, and agent IDs for tamper detection
- **Checkpoint Verification** — Ed25519 signed checkpoints of task state for non-repudiation and point-in-time verification
- **Replay Protection** — Nonce-based anti-replay with configurable FIFO eviction (default 1000 nonces per task)
- **SecureTaskManager** — New manager combining encryption, integrity, and authentication for MCP Tasks primitive
- **New Types**: `SecureTask`, `TaskStateTransition`, `TaskCheckpoint`, `TaskResumeRequest`, `TaskResumeResult`, `TaskIntegrityResult`, `SecureTaskStats`
- **New Config**: Extended `AsyncTaskConfig` with `encrypt_state`, `enable_hash_chain`, `require_resume_token`, `replay_protection`, `max_nonces`, `enable_checkpoints`, `checkpoint_interval`, `task_retention_secs`

#### Phase 10: NHI (Non-Human Identity) Lifecycle Management
- **Agent Identity Registration** — Multiple attestation types (JWT, mTLS, SPIFFE, DPoP, API key) with configurable TTL, public key binding, and metadata tags
- **Identity Lifecycle States** — Full lifecycle management: Probationary → Active → Suspended → Revoked → Expired with automatic status transitions
- **Behavioral Attestation** — Continuous authentication via behavioral baselines using Welford's online variance algorithm for request intervals, tool call patterns, and source IP tracking
- **Anomaly Detection** — Configurable anomaly thresholds with recommendations (Allow, AllowWithLogging, StepUpAuth, Suspend, Revoke) based on deviation severity
- **Delegation Chains** — Agent-to-agent permission delegation with scope constraints, depth limits, and chain resolution for accountability tracking
- **Credential Rotation** — Automatic credential lifecycle with expiration warnings, rotation history, and thumbprint tracking
- **DPoP Support** — RFC 9449 Demonstration of Proof-of-Possession with nonce generation, replay prevention, and access token hash binding
- **NHI API Endpoints**:
  - `GET/POST /api/nhi/agents` — List and register agent identities
  - `GET/DELETE /api/nhi/agents/{id}` — Get or revoke agent identity
  - `POST /api/nhi/agents/{id}/activate` — Activate probationary identity
  - `POST /api/nhi/agents/{id}/suspend` — Suspend active identity
  - `GET /api/nhi/agents/{id}/baseline` — Get behavioral baseline
  - `POST /api/nhi/agents/{id}/check` — Check behavior against baseline
  - `GET/POST /api/nhi/delegations` — List and create delegations
  - `GET/DELETE /api/nhi/delegations/{from}/{to}` — Get or revoke delegation
  - `GET /api/nhi/delegations/{id}/chain` — Resolve full delegation chain
  - `POST /api/nhi/agents/{id}/rotate` — Rotate credentials
  - `GET /api/nhi/expiring` — Get identities expiring soon
  - `POST /api/nhi/dpop/nonce` — Generate DPoP nonce
  - `GET /api/nhi/stats` — NHI statistics
- **New Types**: `NhiAgentIdentity`, `NhiIdentityStatus`, `NhiAttestationType`, `NhiBehavioralBaseline`, `NhiBehavioralCheckResult`, `NhiBehavioralDeviation`, `NhiBehavioralRecommendation`, `NhiDelegationLink`, `NhiDelegationChain`, `NhiDpopProof`, `NhiDpopVerificationResult`, `NhiCredentialRotation`, `NhiStats`
- **New Config**: `NhiConfig`, `DpopConfig` with comprehensive defaults for credential TTL, attestation types, anomaly thresholds, delegation limits, and rotation warnings

#### Phase 9: MINJA (Memory Injection Defense)
- **Taint Propagation** — Data from untrusted sources tagged with taint labels (`UserInput`, `ExternalApi`, `AgentOutput`, `DerivedData`, `Sanitized`) that propagate to derived data automatically
- **Provenance Graph** — DAG tracking data lineage with FIFO eviction, detects suspicious patterns (notification→replay chains, feedback loops, data laundering)
- **Trust Decay** — Exponential decay with configurable λ (default 0.029 for 24-hour half-life), time-based trust erosion for stale data
- **Quarantine Management** — Automatic quarantine on injection detection, manual quarantine/release via API, detection metadata tracking
- **Namespace Isolation** — Per-agent namespaces with configurable isolation levels:
  - `Session` — Data isolated per session
  - `Agent` — Data isolated per agent identity
  - `Shared` — Explicit sharing with approval
- **Sharing Approval** — Cross-namespace data sharing requires explicit approval with access type specification (Read/Write/Admin)
- **Memory Security API Endpoints**:
  - `GET /api/memory/entries` — List memory entries with taint filtering
  - `GET /api/memory/entries/{id}` — Get memory entry details
  - `GET /api/memory/entries/{id}/provenance` — Get provenance chain for entry
  - `POST /api/memory/quarantine/{id}` — Quarantine a memory entry
  - `DELETE /api/memory/quarantine/{id}` — Release entry from quarantine
  - `GET /api/memory/quarantine` — List quarantined entries
  - `GET /api/memory/namespaces` — List namespaces
  - `POST /api/memory/namespaces/{ns}/share` — Request namespace sharing
  - `POST /api/memory/namespaces/{ns}/share/approve` — Approve sharing request
  - `GET /api/memory/stats` — Get memory security statistics
- **New Types**: `TaintLabel`, `MemoryEntry`, `ProvenanceNode`, `ProvenanceEventType`, `QuarantineEntry`, `QuarantineDetection`, `MemoryNamespace`, `NamespaceIsolation`, `MemoryAccessDecision`, `NamespaceSharingRequest`, `NamespaceAccessType`, `MemorySecurityStats`
- **New Config**: `MemorySecurityConfig`, `NamespaceConfig` with decay λ, max provenance depth, quarantine policies

#### Phase 8: ETDI Cryptographic Tool Security
- **Tool Signature Verification** — Ed25519/ECDSA P-256 cryptographic signing of tool definitions with trusted signer allowlists (fingerprints + SPIFFE IDs) and expiration support
- **Attestation Chain** — Provenance tracking for tool definitions with initial registration, version updates, and chain integrity verification
- **Version Pinning** — Semantic versioning constraints (`^1.0.0`, `~2.1.0`, exact) with hash-based drift detection for rug-pull prevention
- **ETDI Store** — Persistent storage for signatures, attestations, and pins with optional HMAC integrity protection
- **ETDI API Endpoints**:
  - `GET /api/etdi/signatures` — List all tool signatures
  - `GET /api/etdi/signatures/{tool}` — Get signature for a tool
  - `POST /api/etdi/signatures/{tool}/verify` — Verify tool signature
  - `GET /api/etdi/attestations` — List all attestations
  - `GET /api/etdi/attestations/{tool}` — Get attestation chain for a tool
  - `GET /api/etdi/attestations/{tool}/verify` — Verify attestation chain integrity
  - `GET/POST/DELETE /api/etdi/pins/{tool}` — Manage version pins
- **Tool Registry Integration** — Signature verification on tool registration with configurable `require_signatures` mode for fail-closed enforcement
- **ETDI CLI Commands**:
  - `sentinel generate-key` — Generate Ed25519 keypair for tool signing
  - `sentinel sign-tool` — Sign a tool definition with expiration support
  - `sentinel verify-signature` — Verify a tool signature against its definition

### Security

- **R33-001**: Add monotonic sequence counter to audit hash chain to prevent collision attacks under high load
- **R33-002**: Add per-line size limits (64KB checkpoints, 1MB audit entries) to prevent memory exhaustion attacks
- **R33-003**: Use safe string slicing with char-based truncation to prevent UTF-8 boundary panics
- **R33-004**: Increase injection detection depth from 10 to 32 levels for deeply nested payloads
- **R33-005**: Add triple-encoding detection layers (6-8) to DLP for double-base64 and mixed encoding evasion
- **R33-006**: Store actual schema content for real field-level diff detection in schema poisoning

### Changed

- Security audit rounds: 33 → 34
- Test suite: 3,167 → 3,343 tests

### Documentation

- **ROADMAP.md**: Added v2.1 and v2.2 roadmap based on security research
  - Phase 8: ETDI Cryptographic Tool Security
  - Phase 9: Memory Injection Defense (MINJA)
  - Phase 10: Non-Human Identity (NHI) Lifecycle
  - Phase 11: MCP Tasks Primitive
  - Phase 12: Semantic Guardrails (LLM-based)
  - Phase 13: RAG Poisoning Defense
  - Phase 14: A2A Protocol Security
  - Phase 15: Observability Platform Integration
- Updated gap analysis vs competitor landscape (NeMo Guardrails, Guardrails AI, Zenity, Prisma AIRS)
- Added research bibliography with 10 academic/industry references

---

## [2.0.0] - 2026-02-08

### Added

#### Phase 6: Observability & Tooling
- **Execution Graph Data Model** — Comprehensive call chain visualization with `ExecutionNode` (tool, function, verdict, timing, depth), `ExecutionEdge` (call/data-flow/delegation edges), and `ExecutionGraph` (session-scoped graphs with metadata)
- **Execution Graph Store** — In-memory store with configurable max graphs and age limits, session-based lookup, node lifecycle tracking (add, complete), and automatic cleanup
- **Graph Export Formats** — DOT (Graphviz) and JSON export with color-coded verdicts (green=allow, red=deny), edge styling by type, and full graph statistics
- **Graph Export API** — RESTful endpoints for graph management:
  - `GET /api/graphs` — List sessions with pagination and tool filtering
  - `GET /api/graphs/{session}` — Get graph in JSON format
  - `GET /api/graphs/{session}/dot` — Get graph in DOT (Graphviz) format
  - `GET /api/graphs/{session}/stats` — Get graph statistics (node count, depths, tool distribution)
- **Policy Validation CLI** — Enhanced `sentinel check` command with:
  - `--strict` mode (warnings become errors)
  - `--format json|text` output format
  - `--no-best-practices` to skip best practice checks
  - `--no-security-checks` to skip security checks
  - Shadow policy, wide pattern, and dangerous configuration detection
- **Attack Simulation Framework** — Automated red-teaming based on OWASP ASI Top 10 and MCPTox benchmarks:
  - 10 attack categories (Prompt Injection, Data Disclosure, Sandboxing, etc.)
  - 40+ built-in attack payloads with severity ratings
  - Multi-step attack sequences, schema mutations, parameter manipulation
  - Result summarization by category and severity
  - JSON import/export for custom scenarios

#### Phase 5.5: Enterprise Hardening (Runtime)
- **TLS/mTLS Runtime** — TLS termination via tokio-rustls with client certificate extraction, SPIFFE identity parsing from X.509 SAN URIs, and configurable TLS/mTLS modes
- **OPA Client Runtime** — Async HTTP client for Open Policy Agent with LRU decision caching (configurable TTL), fail-open/fail-closed modes, and structured decision parsing
- **Threat Intelligence Runtime** — Full TAXII 2.1 (STIX format) and MISP client implementations with custom REST endpoint support, confidence filtering, and configurable actions on IOC match
- **JIT Access Runtime** — Session-based temporary elevated permissions with approval workflows, per-principal session limits, auto-revocation on security alerts, and permission/tool access checking

#### Phase 5: Enterprise Hardening (Configuration)
- **TLS/mTLS Configuration** — Server-side TLS and mutual TLS support with configurable cert paths, client CA verification, CRL/OCSP revocation checking, minimum TLS version, and cipher suite selection
- **SPIFFE/SPIRE Integration** — Zero-trust workload identity configuration with trust domain, workload API socket, allowed SPIFFE IDs allowlist, and ID-to-role mapping for RBAC
- **OPA Integration** — Open Policy Agent configuration for external policy evaluation with endpoint URL, decision path, caching (TTL), timeout, fail-open/closed mode, and local bundle support
- **Threat Intelligence Feeds** — Configuration for TAXII, MISP, and custom threat intelligence providers with IOC type filtering, confidence thresholds, refresh intervals, and configurable actions (deny/alert/require_approval)
- **Just-In-Time Access** — Temporary elevated permissions with configurable TTL, max sessions per principal, approval requirements, automatic revocation on security events, and notification webhooks

#### Phase 4.1: Standards Alignment
- **MITRE ATLAS Threat Mapping** — Registry of 14 ATLAS techniques (AML.T0051-T0065) with detection mappings for 30+ Sentinel detection types, coverage reports, and audit event enrichment
- **OWASP AIVSS Integration** — AI Vulnerability Scoring System with CVSS-style base scores plus AI-specific multipliers (autonomy, persistence, reversibility), severity levels (None/Low/Medium/High/Critical), vector string parsing, and predefined profiles for common detections
- **NIST AI RMF Alignment** — Complete mapping to all 4 RMF functions (Govern, Map, Measure, Manage) with 25+ subcategory mappings, coverage statistics, compliance reports, and audit metadata enrichment
- **ISO/IEC 27090 Preparation** — Readiness assessment for 5 control domains (Data Security, Model Security, Operational Security, Supply Chain Security, Privacy & Ethics), gap analysis, recommendations engine, and certification readiness scoring

#### Phase 3.3: Advanced Threat Detection
- **Goal State Tracking** (ASI01) — Detects objective drift mid-session with similarity-based alignment checks, manipulation keyword detection, and configurable drift thresholds
- **Workflow Intent Tracking** — Long-horizon attack detection with step budget enforcement, cumulative effect analysis, and suspicious exfiltration pattern detection
- **Tool Namespace Security** (ASI03) — Prevents tool shadowing attacks via Levenshtein distance typosquatting detection, protected name patterns, and collision detection (exact, similar, version, trust)
- **Output Security Analysis** (ASI07) — Covert channel detection including steganography (zero-width chars, homoglyphs, invisible Unicode), Shannon entropy analysis, and output normalization
- **Token Security Analysis** — Token-level attack detection including special token injection (`<|endoftext|>`, etc.), context flooding/budget tracking, glitch token patterns (SolidGoldMagikarp, etc.), and Unicode normalization attacks
- **AdvancedThreatConfig** — Configuration for all advanced threat detection features with goal drift threshold, workflow step budget, context budget, and protected tool patterns

#### Phase 3.2: Cross-Agent Security
- **Agent Trust Graph** — Multi-agent trust relationship tracking with privilege levels (None, Basic, Standard, Elevated, Admin), delegation chain validation, and escalation detection
- **Inter-Agent Message Signing** — Ed25519 signed message envelopes with nonce-based anti-replay protection for secure inter-agent communication
- **Privilege Escalation Detector** — Second-order prompt injection detection with configurable thresholds, Unicode manipulation checks, delimiter injection detection, and suspicious agent pair tracking
- **CrossAgentConfig** — Configuration for cross-agent security features including message signing requirements, chain depth limits, trusted agents, nonce expiry, and escalation thresholds

#### Phase 3.1: Runtime Integration for Security Managers
- **Admin API endpoints** for all Phase 1 & 2 security managers:
  - Circuit breaker: `GET/POST /api/circuit-breaker/*` (list, stats, get state, reset)
  - Shadow agent: `GET/POST/PUT/DELETE /api/shadow-agents/*` (list, register, update trust)
  - Schema lineage: `GET/PUT/DELETE /api/schema-lineage/*` (list, get, reset trust, remove)
  - Task state: `GET/POST /api/tasks/*` (list, stats, get, cancel)
  - Auth level: `GET/POST/DELETE /api/auth-levels/*` (get, upgrade, clear)
  - Sampling detection: `GET/POST /api/sampling/*` (stats, reset)
  - Deputy validation: `GET/POST/DELETE /api/deputy/delegations/*` (list, register, remove)
- **Audit event helpers** for security events:
  - `log_circuit_breaker_event` - tracks open/closed/half-open/rejected states
  - `log_deputy_event` - tracks delegation and validation failures
  - `log_shadow_agent_event` - tracks agent impersonation detection
  - `log_schema_event` - tracks schema poisoning alerts
  - `log_task_event` - tracks async task lifecycle
  - `log_auth_event` - tracks step-up authentication
  - `log_sampling_event` - tracks sampling request denials
- **HTTP proxy integration** with circuit breaker check before forwarding tool calls
- Security managers integrated into ProxyBridge and AppState for runtime enforcement

#### Phase 2: Advanced Threat Detection (OWASP ASI Top 10)
- **Circuit Breaker** (ASI08) — Cascading failure prevention with configurable thresholds
- **Confused Deputy Prevention** (ASI02) — Delegation chain validation with depth limits
- **Shadow Agent Detection** — Agent fingerprinting and impersonation alerts
- **Schema Poisoning Detection** (ASI05) — Schema lineage tracking with mutation thresholds
- **Sampling Attack Detection** — Rate limiting and content inspection for sampling requests

#### Phase 1: MCP 2025-11-25 Compliance
- **Async Tasks Security** — Task state manager with lifecycle tracking
- **OAuth Resource Indicators** — RFC 8707 parsing and validation
- **CIMD** — Capability-indexed message dispatch routing
- **Step-Up Authentication** — Auth level tracking with upgrade flow

### Security
- Fix timing side-channel in CORS origin validation (R33-001) - origin matching now checks all configured origins to prevent timing-based enumeration

### Changed
- Security audit rounds: 32 → 33

---

## [1.0.0] - 2026-02-08

Initial production release of Sentinel, a runtime security engine for AI agent tool calls.

### Core Features

#### Policy Engine
- Glob and regex-based policy matching for tools and functions
- Parameter constraint evaluation with multiple operators (glob, regex, domain_match, domain_in, domain_not_in)
- Priority-based policy ordering with deterministic evaluation
- Path traversal-safe normalization for filesystem rules
- RFC 1035-compliant domain validation for network rules
- Context-aware policies with time windows, call limits, and action sequences

#### Network Security
- DNS rebinding protection with private IP blocking
- CIDR-based allow/block lists for resolved IPs
- Domain allowlisting and blocklisting
- Carrier-grade NAT (100.64.0.0/10) blocking

#### Authentication & Authorization
- API key authentication for admin endpoints
- OAuth 2.1 / JWT support with JWKS validation
- Role-based access control (RBAC) with Admin, Operator, Auditor, and Viewer roles
- Agent identity attestation via signed JWTs
- Per-endpoint and per-principal rate limiting

#### Audit System
- Tamper-evident audit logging with SHA-256 hash chain
- Ed25519 signed checkpoints for integrity verification
- Configurable PII redaction (Off, Low, High)
- Audit log rotation support
- Multiple export formats: JSON Lines, CEF, syslog (RFC 5424)
- SIEM integrations: Splunk HEC, Datadog, Elasticsearch, webhook

#### Human-in-the-Loop Approvals
- Approval queue for dangerous operations
- Deduplication of pending approvals
- Full audit trail for approval decisions
- Configurable approval timeouts

#### Detection & Prevention
- Prompt injection scanning with Aho-Corasick pattern matching
- Unicode NFKC normalization for homoglyph attack prevention
- Semantic injection detection via n-gram TF-IDF similarity
- Data Loss Prevention (DLP) with 5-layer decode pipeline (raw, base64, percent, combinations)
- Rug-pull detection for tool schema changes
- Tool squatting detection via Levenshtein distance + homoglyph analysis
- Memory poisoning defense with cross-request data tracking
- Behavioral anomaly detection using EMA-based frequency tracking

#### Multi-Tenancy
- Tenant isolation for policy, audit, and approval data
- Tenant extraction from JWT claims, headers, or subdomains
- Per-tenant quotas and rate limiting
- Tenant management API endpoints

#### Observability
- Prometheus metrics endpoint with 24+ metrics
- OpenTelemetry instrumentation for distributed tracing
- Health and readiness endpoints
- Admin dashboard with server-rendered HTML

### Deployment

#### Docker
- Multi-stage Dockerfile for optimized builds
- Static musl-linked binaries (<50MB images)
- Non-root user execution
- Health checks included

#### Kubernetes
- Helm chart with comprehensive values.yaml
- Horizontal Pod Autoscaler support
- Ingress configuration
- Security contexts and pod disruption budgets

#### Clustering
- Redis backend for distributed state
- Shared approval state across instances
- Global rate limiting

### Security Hardening

- Fail-closed design: errors, missing policies, and unresolved context produce Deny
- Zero `unwrap()` in library code
- Constant-time API key comparison
- CSRF defense-in-depth via Origin/Referer validation
- Idempotency keys for at-most-once semantics
- 1MB request body limit
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
- CORS configuration
- 33 rounds of adversarial security audits

### Testing

- 3,167 tests across all crates
- Property-based testing with proptest
- Fuzz targets for:
  - JSON-RPC framing
  - Path normalization
  - Domain extraction
  - CIDR parsing
  - Message classification
  - Parameter scanning
  - Semantic similarity
- Criterion benchmarks for performance-critical paths
- Integration tests for OWASP MCP Top 10

### Documentation

- Comprehensive deployment guide (Docker, Kubernetes, bare metal)
- Operations runbook with troubleshooting procedures
- Security hardening guide
- Complete API reference
- Production configuration examples

### Breaking Changes from 0.x

This is the initial stable release. No breaking changes from previous versions.

---

## [0.1.0] - 2026-01-15

### Added
- Initial development release
- Core policy engine with basic glob matching
- Simple audit logging
- HTTP API server
- Stdio proxy mode
- Basic DLP scanning

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

[1.0.0]: https://github.com/paolovella/sentinel/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/paolovella/sentinel/releases/tag/v0.1.0
