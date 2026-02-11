# Sentinel Roadmap v2.2

> **Version:** 2.2.1 (Released)
> **Generated:** 2026-02-11
> **Status:** v2.2.1 released; v2.2 Phases 12-15 complete; Phase 16+ planned; architecture split and post-quantum readiness tracks active; OPA runtime decision enforcement is active (fail-open/fail-closed configurable); web-validated supply-chain and sender-constrained auth hardening tracks delivered
> **Based on:** Multi-agent research (MCP spec 2025-11-25, OWASP ASI Top 10, enterprise patterns, competitor analysis)

---

## Executive Summary

Sentinel v2.2.1 is production-ready with 35 audit rounds and 3,700+ tests. This roadmap captures completed v2.0-v2.2 work and upcoming priorities based on:

1. **MCP 2025-11-25 Protocol Compliance** — Async Tasks, Resource Indicators, CIMD
2. **Advanced Threat Detection** — Shadow agents, full schema poisoning, cascading failures
3. **Standards Alignment** — MITRE ATLAS, OWASP ASI Top 10, NIST AI Profile
4. **Enterprise Hardening** — mTLS/SPIFFE, OPA runtime wiring, threat intelligence
5. **Architecture Split Readiness** — Module extraction guardrails, dependency boundaries, and regression gates
6. **Post-Quantum Migration Readiness** — Crypto-agility planning for standards transition

**Research Sources:**
- MCP Specification 2025-11-25 updates
- OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)
- CoSAI MCP Security Whitepaper (12 threat categories, ~40 threats)
- MITRE ATLAS agentic AI techniques (14 new entries)
- Competitor analysis (Zenity, Lasso, Operant AI, NeMo Guardrails)

### 2026-02-10 Hardening Delta

- `X-Upstream-Agents` handling moved to strict fail-closed behavior for malformed/oversized and over-entry-limit chains (no truncation fallback).
- OPA runtime decision enforcement is active in evaluation request paths with fail-open/fail-closed controls and operational metrics.

### 2026-02-11 Research Delta

- Added P0 hardening track for CI supply chain:
  dependency review on pull requests, Dependabot automation, action SHA pinning, build provenance attestations, and SBOM publishing.
- Added P0 hardening track for sender-constrained OAuth in HTTP proxy request authorization path:
  integrate DPoP proof verification/binding in `sentinel-http-proxy` (RFC 9449 alignment).
- Added P1 hardening track for dependency policy enforcement (`cargo-deny`) and completion of OPA runtime decision-path wiring.

---

## Priority Matrix

| Priority | Theme | Business Value |
|----------|-------|----------------|
| **P0** | Protocol + Supply-Chain + Replay Defense | Protocol compatibility and highest-risk control closure |
| **P1** | Advanced Threat Detection + Runtime Policy Completion | Close security gaps and finish guarded enterprise paths |
| **P2** | Standards & Compliance | Enterprise adoption |
| **P3** | Enterprise Features | Feature parity |
| **P4** | Observability & Tooling | Operational excellence |

---

## Phase 1: MCP 2025-11-25 Compliance (Weeks 1-4) ✅ COMPLETE

*Focus: Protocol updates for Async Tasks, Resource Indicators, CIMD*

> **Status:** Implemented in commit `fad480c`. All deliverables complete.

### 1.1 Async Tasks Security

The MCP 2025-11-25 spec introduces async task execution. This creates new attack vectors:
- Task state manipulation during long-running operations
- Unauthorized task cancellation/resumption
- Task result tampering

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define `AsyncTaskPolicy` type | P0 | 1 day | — |
| Implement task state validation middleware | P0 | 3 days | Policy type |
| Add task lifecycle audit events | P0 | 1 day | Middleware |
| Implement task cancellation authorization | P0 | 2 days | Middleware |
| Add task timeout enforcement | P0 | 1 day | — |
| Create async task fuzz target | P0 | 1 day | All above |

**New policy configuration:**
```toml
[policies.async_tasks]
enabled = true
max_task_duration = "1h"
max_concurrent_tasks = 100
allow_cancellation = ["admin", "operator"]
require_completion_signature = true
```

### 1.2 OAuth Resource Indicators (RFC 8707)

MCP 2025-11-25 requires resource indicator support for OAuth flows.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse resource indicators from OAuth requests | P0 | 1 day | — |
| Validate resource scope against policy | P0 | 2 days | Parsing |
| Add resource indicator to audit context | P0 | 0.5 days | Validation |
| Support multiple resource servers | P1 | 2 days | — |
| Add resource indicator integration tests | P0 | 1 day | All above |

### 1.3 CIMD (Capability-Indexed Message Dispatch)

New MCP routing mechanism requiring policy enforcement.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse CIMD capability headers | P0 | 1 day | — |
| Define capability-based routing policies | P0 | 2 days | Parsing |
| Implement capability inheritance validation | P1 | 2 days | Policies |
| Add capability attestation verification | P1 | 2 days | — |

### 1.4 Step-Up Authentication

MCP 2025-11-25 defines step-up auth for sensitive operations.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define step-up auth policy triggers | P1 | 1 day | — |
| Implement auth level tracking per session | P1 | 2 days | Triggers |
| Add step-up challenge/response flow | P1 | 3 days | Tracking |
| Integrate with human-in-the-loop approvals | P1 | 2 days | Challenge flow |

### Phase 1 Deliverables
- [x] Async task policy enforcement
- [x] OAuth resource indicator validation
- [x] CIMD capability-based routing
- [x] Step-up authentication flow

**Estimated Duration:** 4 weeks
**Completed:** 2026-02-07

---

## Phase 2: Advanced Threat Detection (Weeks 5-8) ✅ COMPLETE

*Focus: Close gaps identified in CoSAI whitepaper and OWASP ASI Top 10*

> **Status:** Implemented in commit `e4deb2d`. All deliverables complete.

### 2.1 Shadow Agent Discovery (ASI02)

Detect unauthorized/rogue agents operating in the environment.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement agent fingerprinting | P1 | 2 days | — |
| Create agent registry with known-good baseline | P1 | 2 days | Fingerprinting |
| Add anomaly detection for unknown agents | P1 | 3 days | Registry |
| Implement agent behavior profiling | P1 | 3 days | — |
| Alert on shadow agent detection | P1 | 1 day | All above |

**Detection signals:**
- Unknown JWT issuers
- Unusual tool call patterns
- Unregistered client certificates
- Anomalous request origins

### 2.2 Full Schema Poisoning Detection

Extend rug-pull detection for complete schema replacement attacks.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Detect wholesale schema replacement | P1 | 2 days | — |
| Track schema lineage across versions | P1 | 2 days | Detection |
| Add schema signing/verification (optional) | P2 | 3 days | Lineage |
| Implement gradual schema change thresholds | P1 | 2 days | — |
| Add schema poisoning adversarial tests | P1 | 1 day | All above |

**Thresholds:**
```toml
[detection.schema_poisoning]
max_field_additions_per_update = 5
max_field_removals_per_update = 2
max_type_changes_per_update = 1
require_announcement_period = "24h"
```

### 2.3 Cascading Failure Protection (OWASP ASI08)

Prevent chain reactions when one agent fails.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement circuit breaker per upstream tool | P1 | 2 days | — |
| Add failure budget tracking | P1 | 2 days | Circuit breaker |
| Implement graceful degradation policies | P1 | 2 days | — |
| Add cascade detection alerts | P1 | 1 day | — |
| Create chaos testing framework | P2 | 3 days | All above |

**Circuit breaker configuration:**
```toml
[resilience.circuit_breaker]
failure_threshold = 5       # failures before opening
recovery_timeout = "30s"    # wait before half-open
success_threshold = 3       # successes to close
```

### 2.4 Sampling-Based Attack Detection

New attack vector from MCP sampling endpoint.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add sampling request rate limiting | P1 | 1 day | — |
| Detect sampling exfiltration patterns | P1 | 2 days | — |
| Validate sampling context constraints | P1 | 2 days | — |
| Add sampling to DLP inspection pipeline | P1 | 2 days | — |

### 2.5 Confused Deputy Prevention (ASI05)

Strengthen agent identity and authorization checks.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement strict principal binding | P1 | 2 days | — |
| Add request origin chain validation | P1 | 2 days | Binding |
| Enforce capability-based delegation | P1 | 3 days | — |
| Add confused deputy test suite | P1 | 2 days | All above |

### Phase 2 Deliverables
- [x] Shadow agent detection and alerting
- [x] Full schema poisoning detection
- [x] Circuit breaker with cascade protection
- [x] Sampling attack detection
- [x] Confused deputy prevention

**Estimated Duration:** 4 weeks
**Completed:** 2026-02-07

---

## Phase 3.1: Runtime Integration (Week 9) ✅ COMPLETE

*Focus: Wire Phase 1 & 2 security modules into runtime enforcement*

> **Status:** Implemented in commits `05364be` and `7a3c52d`. All deliverables complete.

### 3.1.1 Completed Tasks
- [x] ProxyBridge manager integration (circuit breaker, shadow agent, deputy, schema lineage, auth level, sampling detector)
- [x] Enforcement calls at request evaluation points
- [x] AppState manager fields for sentinel-server
- [x] Admin API endpoints (25+ routes for security manager management)
- [x] Audit event generation helpers (7 event types with comprehensive tests)
- [x] HTTP proxy integration with circuit breaker check

### 3.1.2 Files Modified
- `sentinel-mcp/src/proxy/bridge.rs` — Manager fields and enforcement
- `sentinel-server/src/lib.rs` — AppState integration
- `sentinel-server/src/routes.rs` — Admin API endpoints
- `sentinel-audit/src/lib.rs` — Security event helpers
- `sentinel-http-proxy/src/proxy.rs` — HTTP proxy integration

**Completed:** 2026-02-08

---

## Phase 3.2: Cross-Agent Security (Week 10) ✅ COMPLETE

*Focus: Multi-agent trust relationships, message signing, privilege escalation detection*

> **Status:** Implemented in commit `a043b17`. All deliverables complete.

### 3.2.1 Agent Trust Graph

Track trust relationships between agents in multi-agent systems.

| Task | Priority | Status |
|------|----------|--------|
| Implement privilege level enum | P0 | ✅ Complete |
| Create agent trust graph with delegation chains | P0 | ✅ Complete |
| Implement escalation detection for request chains | P0 | ✅ Complete |
| Add trust closure computation | P0 | ✅ Complete |
| Add circular delegation detection | P0 | ✅ Complete |

### 3.2.2 Inter-Agent Message Signing

Cryptographic message envelopes for inter-agent communication.

| Task | Priority | Status |
|------|----------|--------|
| Implement Ed25519 signed message envelope | P0 | ✅ Complete |
| Add nonce-based anti-replay protection | P0 | ✅ Complete |
| Create agent key registry | P0 | ✅ Complete |
| Add message verification with freshness check | P0 | ✅ Complete |

### 3.2.3 Privilege Escalation Detection

Detect second-order prompt injection and confused deputy attacks.

| Task | Priority | Status |
|------|----------|--------|
| Implement injection pattern analysis | P0 | ✅ Complete |
| Add Unicode manipulation detection | P0 | ✅ Complete |
| Add delimiter injection detection | P0 | ✅ Complete |
| Implement suspicious agent pair tracking | P0 | ✅ Complete |
| Add configurable thresholds | P0 | ✅ Complete |

### 3.2.4 Configuration

| Task | Priority | Status |
|------|----------|--------|
| Create CrossAgentConfig struct | P0 | ✅ Complete |
| Add validation for all config parameters | P0 | ✅ Complete |
| Integrate into PolicyConfig | P0 | ✅ Complete |

### Phase 3.2 Deliverables
- [x] Agent trust graph with privilege levels
- [x] Ed25519 message signing with anti-replay
- [x] Second-order prompt injection detection
- [x] Unicode and delimiter injection detection
- [x] CrossAgentConfig with full validation

**Completed:** 2026-02-08

---

## Phase 3.3: Advanced Threat Detection (Week 11) ✅ COMPLETE

*Focus: Goal tracking, workflow monitoring, namespace security, covert channel detection*

> **Status:** Implemented in commit `7cc3232`. All deliverables complete.

### 3.3.1 Goal State Tracking (ASI01)

Detect when agent objectives change unexpectedly mid-session.

| Task | Priority | Status |
|------|----------|--------|
| Implement GoalTracker with session goals | P0 | ✅ Complete |
| Add manipulation keyword detection | P0 | ✅ Complete |
| Implement similarity-based alignment checks | P0 | ✅ Complete |
| Add goal drift alerting | P0 | ✅ Complete |

### 3.3.2 Workflow Intent Tracking

Detect long-horizon attacks that span multiple steps.

| Task | Priority | Status |
|------|----------|--------|
| Implement WorkflowTracker with step budgets | P0 | ✅ Complete |
| Add cumulative effect analysis | P0 | ✅ Complete |
| Implement suspicious pattern detection | P0 | ✅ Complete |
| Add exfiltration chain detection | P0 | ✅ Complete |

### 3.3.3 Tool Namespace Security (ASI03)

Prevent tool shadowing and namespace collision attacks.

| Task | Priority | Status |
|------|----------|--------|
| Implement ToolNamespaceRegistry | P0 | ✅ Complete |
| Add Levenshtein typosquatting detection | P0 | ✅ Complete |
| Implement protected name patterns | P0 | ✅ Complete |
| Add collision detection (exact, similar, version, trust) | P0 | ✅ Complete |

### 3.3.4 Output Security Analysis (ASI07)

Detect covert channel exfiltration in tool outputs.

| Task | Priority | Status |
|------|----------|--------|
| Implement steganography detection | P0 | ✅ Complete |
| Add zero-width and homoglyph detection | P0 | ✅ Complete |
| Implement Shannon entropy analysis | P0 | ✅ Complete |
| Add output normalization | P0 | ✅ Complete |

### 3.3.5 Token Security Analysis

Detect token-level attacks against LLM agents.

| Task | Priority | Status |
|------|----------|--------|
| Implement special token injection detection | P0 | ✅ Complete |
| Add context flooding/budget tracking | P0 | ✅ Complete |
| Implement glitch token detection | P0 | ✅ Complete |
| Add Unicode normalization attack detection | P0 | ✅ Complete |

### 3.3.6 Configuration

| Task | Priority | Status |
|------|----------|--------|
| Create AdvancedThreatConfig struct | P0 | ✅ Complete |
| Add validation for all config parameters | P0 | ✅ Complete |
| Integrate into PolicyConfig | P0 | ✅ Complete |

### Phase 3.3 Deliverables
- [x] Goal state tracking with drift detection
- [x] Workflow intent tracking with step budgets
- [x] Tool namespace security with collision detection
- [x] Output security with steganography and entropy analysis
- [x] Token security with smuggling and flooding detection
- [x] AdvancedThreatConfig with full validation

**Completed:** 2026-02-08

---

## Phase 4.1: Standards Alignment (Weeks 12-14) ✅ COMPLETE

*Focus: MITRE ATLAS, OWASP AIVSS, NIST alignment*

> **Status:** Implemented in commit `8f6a78c`. All deliverables complete.

### 4.1.1 MITRE ATLAS Threat Mapping

Map Sentinel detections to MITRE ATLAS techniques.

| Task | Priority | Status |
|------|----------|--------|
| Create ATLAS technique registry | P2 | ✅ Complete |
| Map existing detections to ATLAS IDs | P2 | ✅ Complete |
| Add ATLAS technique ID to audit events | P2 | ✅ Complete |
| Generate ATLAS coverage report | P2 | ✅ Complete |
| Document unmapped techniques as gaps | P2 | ✅ Complete |

**ATLAS techniques mapped:**
- AML.T0051: Prompt Injection
- AML.T0052: Indirect Prompt Injection
- AML.T0053: Jailbreak
- AML.T0054: Data Extraction
- AML.T0055: Exfiltration via Tool Outputs
- AML.T0056: Tool Manipulation
- AML.T0057: Agent Hijacking
- AML.T0058: Confused Deputy
- AML.T0059: Shadow Agent
- AML.T0060: Agent Manipulation
- AML.T0061: Tool Poisoning
- AML.T0062: Memory Injection
- AML.T0063: Privilege Escalation (Agent)
- AML.T0064: Data Exfiltration (Agent)
- AML.T0065: Cascading Agent Failure

### 4.1.2 OWASP AIVSS Integration

| Task | Priority | Status |
|------|----------|--------|
| Design severity scoring framework | P2 | ✅ Complete |
| Implement AIVSS score calculation | P2 | ✅ Complete |
| Add severity to finding reports | P2 | ✅ Complete |
| Create AIVSS-formatted exports | P2 | ✅ Complete |

**Features:**
- CVSS-style base scoring (0.0-10.0)
- AI-specific multipliers: AgentAutonomy, AttackPersistence, Reversibility
- Severity levels: None, Low, Medium, High, Critical
- Vector string generation and parsing
- Predefined profiles for common detection types

### 4.1.3 NIST AI RMF Alignment

| Task | Priority | Status |
|------|----------|--------|
| Document NIST GOVERN function coverage | P2 | ✅ Complete |
| Document NIST MAP function coverage | P2 | ✅ Complete |
| Document NIST MEASURE function coverage | P2 | ✅ Complete |
| Document NIST MANAGE function coverage | P2 | ✅ Complete |
| Create NIST compliance report generator | P2 | ✅ Complete |

**Coverage:** 25+ subcategory mappings across all 4 RMF functions

### 4.1.4 ISO/IEC 27090 Preparation

| Task | Priority | Status |
|------|----------|--------|
| Review draft 27090 requirements | P3 | ✅ Complete |
| Gap analysis against current implementation | P3 | ✅ Complete |
| Document compliance mapping | P3 | ✅ Complete |
| Create readiness assessment generator | P3 | ✅ Complete |

**Control domains covered:**
- Data Security (DLP, input validation, output sanitization)
- Model Security (access control, schema integrity, anomaly detection)
- Operational Security (audit logging, monitoring, incident response)
- Supply Chain Security (tool attestation, rug pull detection)
- Privacy & Ethics (human oversight, transparency)

### Phase 4.1 Deliverables
- [x] MITRE ATLAS threat mapping (14 techniques, 30+ detection mappings)
- [x] AIVSS severity scoring with AI multipliers
- [x] NIST AI RMF compliance documentation and reports
- [x] ISO 27090 readiness assessment with gap analysis

**Completed:** 2026-02-08

---

## Phase 5: Enterprise Hardening - Configuration (Weeks 15-16) ✅ COMPLETE

*Focus: Configuration layer for mTLS, OPA, threat intelligence, JIT access*

> **Status:** Configuration types implemented in commit `fc8da13`. Runtime implementation pending.

### 5.1 mTLS / SPIFFE-SPIRE Configuration

| Task | Priority | Status |
|------|----------|--------|
| Add TlsConfig with mode (none/tls/mtls) | P2 | ✅ Complete |
| Add cert_path, key_path, client_ca_path | P2 | ✅ Complete |
| Add CRL and OCSP stapling options | P2 | ✅ Complete |
| Add min TLS version and cipher suites | P2 | ✅ Complete |
| Add SpiffeConfig with trust domain | P2 | ✅ Complete |
| Add allowed_spiffe_ids and id_to_role mapping | P2 | ✅ Complete |

**Configuration:**
```toml
[tls]
mode = "mtls"  # none | tls | mtls
cert_path = "/etc/sentinel/server.crt"
key_path = "/etc/sentinel/server.key"
client_ca_path = "/etc/sentinel/client-ca.pem"
require_client_cert = true
min_version = "1.2"
ocsp_stapling = true

[spiffe]
enabled = true
trust_domain = "example.org"
workload_socket = "unix:///var/run/spire/agent.sock"
allowed_spiffe_ids = ["spiffe://example.org/agent/frontend"]
```

### 5.2 OPA / Rego Policy Configuration

| Task | Priority | Status |
|------|----------|--------|
| Add OpaConfig with endpoint and decision_path | P2 | ✅ Complete |
| Add cache_ttl_secs and timeout_ms | P2 | ✅ Complete |
| Add fail_open option (default: false) | P2 | ✅ Complete |
| Add bundle_path for local evaluation | P2 | ✅ Complete |
| Add audit_decisions flag | P2 | ✅ Complete |

**Configuration:**
```toml
[opa]
enabled = true
endpoint = "http://opa:8181/v1/data/sentinel/allow"
decision_path = "result"
cache_ttl_secs = 60
timeout_ms = 100
fail_open = false
audit_decisions = true
```

### 5.3 Threat Intelligence Configuration

| Task | Priority | Status |
|------|----------|--------|
| Add ThreatIntelConfig with provider enum | P2 | ✅ Complete |
| Add TAXII, MISP, Custom provider types | P2 | ✅ Complete |
| Add refresh_interval and cache_ttl | P2 | ✅ Complete |
| Add ioc_types filter and min_confidence | P2 | ✅ Complete |
| Add on_match action (deny/alert/require_approval) | P2 | ✅ Complete |

**Configuration:**
```toml
[threat_intel]
enabled = true
provider = "taxii"
endpoint = "https://taxii.example.com/taxii2/"
collection_id = "indicators"
refresh_interval_secs = 3600
min_confidence = 70
on_match = "deny"
```

### 5.4 Just-In-Time Access Configuration

| Task | Priority | Status |
|------|----------|--------|
| Add JitAccessConfig with TTL settings | P2 | ✅ Complete |
| Add max_sessions_per_principal | P2 | ✅ Complete |
| Add require_approval and require_reason | P2 | ✅ Complete |
| Add auto_revoke_on_alert | P2 | ✅ Complete |
| Add notification_webhook | P2 | ✅ Complete |

**Configuration:**
```toml
[jit_access]
enabled = true
default_ttl_secs = 3600
max_ttl_secs = 86400
require_approval = true
require_reason = true
max_sessions_per_principal = 3
auto_revoke_on_alert = true
```

### Phase 5 Configuration Deliverables
- [x] TlsConfig with mTLS mode and revocation options
- [x] SpiffeConfig with trust domain and ID mapping
- [x] OpaConfig with caching and fail-open mode
- [x] ThreatIntelConfig with TAXII/MISP/Custom providers
- [x] JitAccessConfig with TTL and approval settings
- [x] Validation for all configuration parameters

**Completed:** 2026-02-08

---

## Phase 5.5: Enterprise Hardening - Runtime (Weeks 17-18) 🟡 PARTIALLY COMPLETE

*Focus: Runtime implementation of enterprise features*

> **Status:** Core runtime components implemented in commit `db7f99b`; OPA request-path decision enforcement is active with runtime metrics and fail-open/fail-closed behavior.

### 5.5.1 TLS Runtime Implementation

| Task | Priority | Status |
|------|----------|--------|
| Integrate tokio-rustls for TLS termination | P2 | ✅ Complete |
| Implement client certificate extraction | P2 | ✅ Complete |
| Add SPIFFE ID extraction from X.509 SAN | P2 | ✅ Complete |
| Implement CRL/OCSP checking | P3 | Deferred |

### 5.5.2 OPA Runtime Implementation

| Task | Priority | Status |
|------|----------|--------|
| Implement OPA HTTP client | P2 | ✅ Complete |
| Add decision caching with TTL | P2 | ✅ Complete |
| Implement fail-open/fail-closed modes | P2 | ✅ Complete |
| Add structured decision parsing | P2 | ✅ Complete |
| Wire OPA decisions into server request path (`serve`) | P1 | ✅ Complete |
| Wire OPA decisions into CLI policy path (`evaluate`) | P1 | ✅ Complete |

### 5.5.3 Threat Intelligence Runtime

| Task | Priority | Status |
|------|----------|--------|
| Implement TAXII 2.1 client | P3 | ✅ Complete |
| Implement MISP client | P3 | ✅ Complete |
| Implement custom REST endpoint support | P2 | ✅ Complete |
| Add confidence filtering | P2 | ✅ Complete |

### 5.5.4 JIT Access Runtime

| Task | Priority | Status |
|------|----------|--------|
| Implement JIT session management | P2 | ✅ Complete |
| Add approval workflow support | P2 | ✅ Complete |
| Implement auto-revocation on alerts | P2 | ✅ Complete |
| Add per-principal session limits | P2 | ✅ Complete |

### 5.5.5 FIPS 140-2 Compliance Mode

| Task | Priority | Status |
|------|----------|--------|
| Evaluate FIPS-compliant Rust crypto libraries | P3 | Deferred |
| Add FIPS mode configuration flag | P3 | Deferred |
| Replace crypto primitives in FIPS mode | P3 | Deferred |
| Document FIPS compliance scope | P3 | Deferred |

### Phase 5.5 Deliverables
- [x] TLS termination with client cert extraction
- [x] SPIFFE ID extraction from X.509 SAN URIs
- [x] OPA client with LRU caching and fail modes
- [x] OPA request-path decision enforcement wiring
- [x] Threat intelligence clients (TAXII, MISP, Custom)
- [x] JIT session management with approval workflow
- [ ] FIPS 140-2 compliance mode (deferred to v2.1)

**Updated:** 2026-02-10

---

## Phase 6: Observability & Tooling (Weeks 19-20) ✅ COMPLETE

*Focus: Execution graphs, CI/CD integration, red-teaming*

> **Status:** Implemented. Core observability features complete.

### 6.1 Execution Graph Visualization ✅

Visual representation of agent call chains.

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Define execution graph data model | P3 | 1 day | ✅ Done |
| Capture parent-child relationships in audit | P3 | 2 days | ✅ Done |
| Add graph export endpoint (DOT/JSON) | P3 | 2 days | ✅ Done |
| Create web-based graph viewer | P4 | 3 days | Deferred |

**Implemented:**
- `ExecutionNode`, `ExecutionEdge`, `ExecutionGraph` types in `sentinel-audit/src/exec_graph.rs`
- `ExecutionGraphStore` with session-based storage, cleanup, and lifecycle tracking
- DOT (Graphviz) export with color-coded verdicts and edge styling
- JSON export with full graph serialization
- API endpoints: `GET /api/graphs`, `GET /api/graphs/{session}`, `GET /api/graphs/{session}/dot`, `GET /api/graphs/{session}/stats`

### 6.2 CI/CD Pipeline Integration ✅

Security scanning for development workflows.

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Create policy validation CLI command | P3 | 1 day | ✅ Done |
| Add schema validation CLI command | P3 | 1 day | Deferred |
| Create GitHub Action for policy checks | P3 | 2 days | Deferred |
| Add GitLab CI template | P3 | 1 day | Deferred |
| Document CI/CD integration guide | P3 | 1 day | Deferred |

**Implemented:**
- `PolicyValidator` in `sentinel-config/src/validation.rs` with severity levels
- Enhanced `sentinel check` with `--strict`, `--format`, `--no-best-practices`, `--no-security-checks`
- Shadow policy detection, wide pattern warnings, dangerous config checks

### 6.3 Automated Red-Teaming ✅

Self-testing against known attack patterns.

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Create attack simulation framework | P3 | 3 days | ✅ Done |
| Implement MCPTox benchmark attacks | P3 | 3 days | ✅ Done |
| Add scheduled red-team runs | P4 | 2 days | Deferred |
| Generate red-team reports | P3 | 2 days | ✅ Done |

**Implemented:**
- `AttackSimulator` in `sentinel-mcp/src/attack_sim.rs` with 40+ attack payloads
- 10 attack categories aligned with OWASP ASI Top 10 (Prompt Injection, Data Disclosure, etc.)
- Multi-step attack sequences, schema mutations, parameter manipulation
- JSON import/export for custom scenarios, result summarization

### Phase 6 Deliverables
- [x] Execution graph visualization (DOT/JSON export, API endpoints)
- [ ] CI/CD integration (GitHub Actions, GitLab) — CLI ready, templates deferred
- [x] Red-team automation framework (40+ attacks, OWASP ASI alignment)
- [x] MCPTox benchmark coverage (via attack payloads)

**Estimated Duration:** 2 weeks

---

## Phase 7: Documentation & Release (Week 21-22) ✅ COMPLETE

> **Status:** v2.0.0 released. Documentation and release preparation complete.

### 7.1 Documentation Updates ✅

| Task | Priority | Status |
|------|----------|--------|
| Update deployment guide with new features | HIGH | Deferred to post-release |
| Create threat model documentation | HIGH | ✅ Done |
| Document MITRE ATLAS coverage | MEDIUM | ✅ In threat model |
| Create migration guide (v1 → v2) | HIGH | ✅ Done |
| Update API reference | HIGH | ✅ Done |

**Implemented:**
- `docs/THREAT_MODEL.md` — OWASP ASI Top 10, MITRE ATLAS, attack vectors, trust boundaries
- `docs/MIGRATION.md` — v1.x to v2.0 upgrade guide with step-by-step instructions
- `docs/API.md` — Updated with all Phase 1-6 endpoints (security managers, execution graphs)

### 7.2 Release Preparation ✅

| Task | Priority | Status |
|------|----------|--------|
| Version bump to 2.0.0 | HIGH | ✅ Done |
| Update CHANGELOG.md | HIGH | ✅ Done |
| Create GitHub release | HIGH | Ready |
| Publish updated Helm chart | HIGH | Ready |

**Implemented:**
- All 12 crates bumped to version 2.0.0
- CHANGELOG.md finalized with all Phase 1-6 features
- README.md updated with v2.0.0 badges and Docker tags

---

## Timeline Summary

```
Weeks 1-4:   Phase 1 — MCP 2025-11-25 Compliance ✅
Weeks 5-8:   Phase 2 — Advanced Threat Detection ✅
Weeks 9-10:  Phase 3.1-3.2 — Runtime Integration & Cross-Agent Security ✅
Week 11:     Phase 3.3 — Advanced Threat Detection ✅
Weeks 12-14: Phase 4.1 — Standards Alignment ✅
Weeks 15-16: Phase 5 — Enterprise Hardening (Config) ✅
Weeks 17-18: Phase 5.5 — Enterprise Hardening (Runtime) ✅
Weeks 19-20: Phase 6 — Observability & Tooling ✅
Weeks 21-22: Phase 7 — Documentation & Release ✅
```

**Total Duration:** 22 weeks (~5.5 months)
**Team Size:** 2-3 engineers

---

## Success Metrics

### Phase 1 Exit Criteria
- [ ] MCP 2025-11-25 protocol compliance verified
- [ ] Async task policy enforcement functional
- [ ] OAuth resource indicator validation passing

### Phase 2 Exit Criteria
- [ ] Shadow agent detection with <1% false positive rate
- [ ] Schema poisoning blocks 100% of MCPTox test cases
- [ ] Circuit breaker prevents cascade in chaos tests

### Phase 3 Exit Criteria
- [ ] 80%+ MITRE ATLAS technique coverage
- [ ] AIVSS scores generated for all findings
- [ ] NIST AI RMF documentation complete

### Phase 4 Exit Criteria
- [ ] mTLS/SPIFFE working in Kubernetes
- [ ] OPA integration tested with complex policies
- [ ] JIT access functional with audit trail

### Phase 5 Exit Criteria
- [ ] Execution graphs visible in dashboard
- [ ] GitHub Action published and documented
- [ ] MCPTox benchmark 95%+ detection rate

---

## Research Agent References

The following research agents provided input for this roadmap:

| Agent | Focus Area | Key Findings |
|-------|------------|--------------|
| MCP Security | Protocol updates | MCP 2025-11-25 (Async Tasks, CIMD, Resource Indicators) |
| AI Threats | Attack vectors | MCPTox benchmark, tool poisoning 72% success rate |
| Enterprise | Gateway features | mTLS, OPA, SPIFFE-SPIRE integration patterns |
| OWASP | Standards | AIVSS, NIST AI RMF, ISO 27090 timeline |
| Competitor | Market analysis | Shadow agent discovery, execution graphs as gaps |

---

## Appendix: OWASP ASI Top 10 Coverage

| ID | Threat | Sentinel Coverage |
|----|--------|-------------------|
| ASI01 | Prompt Injection | ✅ Injection detection (v1.0) |
| ASI02 | Sensitive Data Disclosure | ✅ DLP scanning (v1.0), Deputy validation (Phase 2) |
| ASI03 | Inadequate Sandboxing | ⚠️ Path/network rules (partial) |
| ASI04 | Privilege Escalation | ✅ RBAC, approval flow (v1.0) |
| ASI05 | Confused Deputy | ✅ Deputy validation with delegation chains (Phase 2) |
| ASI06 | Excessive Agency | ✅ Policy engine (v1.0) |
| ASI07 | Insecure Plugins | ✅ Rug-pull detection (v1.0), Schema poisoning (Phase 2) |
| ASI08 | Cascading Failures | ✅ Circuit breaker with failure budget (Phase 2) |
| ASI09 | Over-reliance on Agent | ⚠️ Human-in-the-loop (partial) |
| ASI10 | Inadequate Monitoring | ✅ Audit logging (v1.0), Security event helpers (Phase 3.1) |

---

## Appendix: Known CVEs Addressed

| CVE | Description | Sentinel Mitigation |
|-----|-------------|---------------------|
| CVE-2025-68143 | Git MCP Server path traversal | Path normalization (v1.0) |
| CVE-2025-68144 | Git MCP Server arbitrary read | Path rules, DLP (v1.0) |
| CVE-2025-68145 | Git MCP Server secret exposure | DLP scanning (v1.0) |
| CVE-2025-6514 | mcp-remote SSRF | DNS rebinding protection (v1.0) |

---

*This roadmap is a living document. Update as standards finalize and priorities shift.*

---

# Future Roadmap: v2.1 and Beyond

> **Research Sources (2026-02-08):**
> - MCP Specification 2025-11-25 Security Best Practices
> - OWASP Top 10 for Agentic Applications 2026 (finalized)
> - ETDI: Enhanced Tool Definition Interface (arxiv:2506.01333)
> - MINJA: Memory Injection Attacks (Agent Security Bench)
> - Agentic Trust Framework (ATF) for Zero Trust NHI
> - Enterprise AI Security Patterns (Microsoft, CrowdStrike Unit42)
> - Competitor Analysis: NeMo Guardrails, Guardrails AI, Zenity, Prisma AIRS

---

## Gap Analysis: Sentinel v2.0 vs Industry State-of-the-Art

### Implemented (Strong Coverage)
- [x] Policy engine with path/network rules
- [x] DLP scanning (8-layer decode pipeline)
- [x] Injection detection (Aho-Corasick + semantic)
- [x] Audit logging with tamper-evident hash chain
- [x] Circuit breaker for cascading failures
- [x] Schema poisoning detection
- [x] Cross-agent security (trust graph, message signing)
- [x] MITRE ATLAS mapping, OWASP AIVSS scoring

### Gaps Identified (v2.1 Priorities)

| Gap | Industry Standard | Sentinel Status | Priority |
|-----|-------------------|-----------------|----------|
| ~~ETDI Cryptographic Tool Verification~~ | ETDI proposal (2025) | ✅ Implemented (Phase 8) | ~~P0~~ |
| ~~Memory Injection Defense (MINJA)~~ | Agent Security Bench | ✅ Implemented (Phase 9) | ~~P1~~ |
| ~~Non-Human Identity (NHI) Lifecycle~~ | ATF, CyberArk | ✅ Implemented (Phase 10) | ~~P1~~ |
| Stateful Session Reasoning Guards | NeMo Guardrails | Not implemented | P2 |
| Semantic Guardrails (LLM-based) | Guardrails AI, NeMo | Not implemented | P2 |
| A2A Protocol Security | Google A2A (2025) | Not implemented | P2 |
| RAG Poisoning Detection | Microsoft research | Not implemented | P2 |
| MCP Tasks Primitive Support | MCP 2025-11-25 | Not implemented | P1 |
| Agent Observability Platform Integration | Arize, Langfuse | Partial (OTEL) | P3 |

---

## Phase 8: ETDI & Cryptographic Tool Security (v2.1) ✅ COMPLETE

*Focus: Implement Enhanced Tool Definition Interface for cryptographic tool attestation*

> **Status:** Implemented in commit `c9590d6`. All core deliverables complete.

### Background

ETDI (arxiv:2506.01333) proposes cryptographic verification of tool definitions to prevent:
- Tool rug-pulls (definition changes post-install)
- Tool squatting (malicious tools impersonating legitimate ones)
- Supply chain attacks on MCP tool servers

### 8.1 Tool Signature Verification

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Define ToolSignature schema (Ed25519/ECDSA) | P0 | 1 day | ✅ Complete |
| Implement signature verification in tool registry | P0 | 2 days | ✅ Complete |
| Add signature verification to schema poisoning checks | P0 | 1 day | ✅ Complete |
| Create tool signing CLI (`sentinel sign-tool`) | P0 | 2 days | ✅ Complete |
| Add signature verification failure audit events | P0 | 1 day | ✅ Complete |

**Configuration:**
```toml
[etdi]
enabled = true
require_signatures = true       # Reject unsigned tools
allowed_signers = [
  "spiffe://example.org/tool-server/official",
  "SHA256:abc123..."            # Or public key fingerprints
]
signature_algorithm = "ed25519" # ed25519 | ecdsa-p256
```

### 8.2 Tool Attestation Chain

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement attestation chain validation | P0 | 2 days | ✅ Complete |
| Add tool provenance tracking | P0 | 2 days | ✅ Complete |
| Create attestation transparency log | P1 | 3 days | ✅ Complete |
| Integrate with Sigstore/Rekor (optional) | P2 | 3 days | Deferred |

### 8.3 Tool Version Pinning

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement version pinning in tool registry | P0 | 1 day | ✅ Complete |
| Add semantic versioning constraint validation | P0 | 1 day | ✅ Complete |
| Detect unauthorized version updates | P0 | 1 day | ✅ Complete |
| Add version drift alerting | P0 | 1 day | ✅ Complete |

### 8.4 ETDI Store & API

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement persistent ETDI store | P0 | 2 days | ✅ Complete |
| Add HMAC integrity protection for store | P0 | 1 day | ✅ Complete |
| Create ETDI API endpoints | P0 | 2 days | ✅ Complete |
| Add SPIFFE workload identity trust | P0 | 1 day | ✅ Complete |

**Implemented API Endpoints:**
- `GET /api/etdi/signatures` — List all tool signatures
- `GET /api/etdi/signatures/{tool}` — Get signature for a tool
- `POST /api/etdi/signatures/{tool}/verify` — Verify tool signature
- `GET /api/etdi/attestations` — List all attestations
- `GET /api/etdi/attestations/{tool}` — Get attestation chain for a tool
- `GET /api/etdi/attestations/{tool}/verify` — Verify attestation chain integrity
- `GET/POST/DELETE /api/etdi/pins/{tool}` — Manage version pins

### Phase 8 Deliverables
- [x] Ed25519/ECDSA tool signature verification
- [x] Attestation chain with provenance tracking
- [x] Tool signing CLI for developers (`sentinel generate-key`, `sign-tool`, `verify-signature`)
- [x] Version pinning with semantic versioning
- [x] ETDI persistent store with HMAC protection
- [x] SPIFFE workload identity trust
- [ ] Sigstore integration (deferred to v2.2)

**Completed:** 2026-02-08

---

## Phase 9: Memory Injection Defense (v2.1) ✅ COMPLETE

*Focus: Comprehensive defense against MINJA (Memory Injection) attacks*

> **Status:** Implemented. All core deliverables complete.

### Background

MINJA attacks (Agent Security Bench, 2025) demonstrate that LLM agents with persistent memory are vulnerable to:
- Delayed injection: Malicious data stored in memory, activated later
- Cross-session poisoning: Poisoning one session affects future sessions
- Memory-based privilege escalation: Stored credentials/capabilities misused

### 9.1 Enhanced Memory Tracking

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Extend memory_tracking.rs with taint propagation | P1 | 3 days | ✅ Complete |
| Implement memory provenance graph | P1 | 2 days | ✅ Complete |
| Add memory age-based trust decay | P1 | 1 day | ✅ Complete |
| Create memory quarantine for suspicious data | P1 | 2 days | ✅ Complete |

**Configuration:**
```toml
[memory_security]
enabled = true
taint_propagation = true
trust_decay_hours = 24          # Trust decreases over time
max_memory_age_days = 7         # Force re-verification after 7 days
quarantine_on_injection_detect = true
```

### 9.2 Memory Integrity Verification

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement memory content hashing | P1 | 1 day | ✅ Complete |
| Add integrity verification on memory retrieval | P1 | 2 days | ✅ Complete |
| Detect memory tampering between sessions | P1 | 2 days | ✅ Complete |
| Create memory audit trail | P1 | 1 day | ✅ Complete |

### 9.3 Memory Isolation

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement per-agent memory namespaces | P1 | 2 days | ✅ Complete |
| Add memory access control policies | P1 | 2 days | ✅ Complete |
| Create memory sharing approval workflow | P2 | 2 days | ✅ Complete |
| Implement memory encryption at rest | P2 | 2 days | Deferred |

### Phase 9 Deliverables
- [x] Taint propagation for memory tracking
- [x] Memory provenance graph with trust decay
- [x] Integrity verification on retrieval
- [x] Per-agent memory isolation
- [x] Memory access control policies

**Completed:** 2026-02-09

---

## Phase 10: Non-Human Identity (NHI) Lifecycle (v2.1) ✅ COMPLETE

*Focus: Implement Agentic Trust Framework (ATF) for zero-trust agent identity*

> **Status:** Implemented in commit `0320659`. All core deliverables complete.

### Background

Traditional IAM assumes human users. AI agents require:
- Machine identities with short-lived credentials
- Just-in-time access with automatic revocation
- Behavioral attestation (is this agent acting normally?)
- Delegation chains with accountability

### 10.1 Agent Identity Lifecycle

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement agent registration with attestation | P1 | 2 days | ✅ Complete |
| Add agent credential rotation | P1 | 2 days | ✅ Complete |
| Implement agent revocation list | P1 | 1 day | ✅ Complete |
| Create agent identity federation | P2 | 3 days | Deferred |

**Configuration:**
```toml
[nhi]
enabled = true
credential_ttl_secs = 3600      # 1 hour max credential lifetime
require_attestation = true
attestation_types = ["jwt", "mtls", "spiffe", "dpop", "api_key"]
auto_revoke_on_anomaly = true
probationary_period_secs = 86400  # 24 hours
```

### 10.2 Behavioral Attestation

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Extend behavioral anomaly detection for NHI | P1 | 2 days | ✅ Complete |
| Implement continuous authentication | P1 | 2 days | ✅ Complete |
| Add behavioral drift alerting | P1 | 1 day | ✅ Complete |
| Create agent behavior baseline learning | P2 | 3 days | ✅ Complete |

**Features:**
- Welford's online algorithm for variance calculation
- Request interval, tool call frequency, and source IP tracking
- Anomaly thresholds with deviation severity (Minor, Moderate, Severe)
- Recommendations: Allow, AllowWithLogging, StepUpAuth, Suspend, Revoke

### 10.3 Delegation & Accountability

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Enhance delegation chain with NHI tracking | P1 | 2 days | ✅ Complete |
| Implement delegation approval workflow | P1 | 2 days | ✅ Complete |
| Add delegation scope constraints | P1 | 1 day | ✅ Complete |
| Create delegation audit reports | P1 | 1 day | ✅ Complete |

**Features:**
- Delegation links with scope (tools, resources, permissions)
- Depth limits (configurable, default 5)
- Chain resolution with cycle detection
- Approval workflow with approver tracking

### 10.4 DPoP Support (RFC 9449)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement DPoP proof verification | P1 | 2 days | ✅ Complete |
| Add nonce generation and tracking | P1 | 1 day | ✅ Complete |
| Implement access token hash binding | P1 | 1 day | ✅ Complete |

### 10.5 NHI API Endpoints

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/api/nhi/agents` | GET/POST | List/register identities | ✅ Complete |
| `/api/nhi/agents/{id}` | GET/DELETE | Get/revoke identity | ✅ Complete |
| `/api/nhi/agents/{id}/activate` | POST | Activate probationary | ✅ Complete |
| `/api/nhi/agents/{id}/suspend` | POST | Suspend identity | ✅ Complete |
| `/api/nhi/agents/{id}/baseline` | GET | Get behavioral baseline | ✅ Complete |
| `/api/nhi/agents/{id}/check` | POST | Check behavior | ✅ Complete |
| `/api/nhi/delegations` | GET/POST | List/create delegations | ✅ Complete |
| `/api/nhi/delegations/{from}/{to}` | GET/DELETE | Get/revoke delegation | ✅ Complete |
| `/api/nhi/delegations/{id}/chain` | GET | Resolve full chain | ✅ Complete |
| `/api/nhi/agents/{id}/rotate` | POST | Rotate credentials | ✅ Complete |
| `/api/nhi/expiring` | GET | Expiring identities | ✅ Complete |
| `/api/nhi/dpop/nonce` | POST | Generate DPoP nonce | ✅ Complete |
| `/api/nhi/stats` | GET | NHI statistics | ✅ Complete |

### Phase 10 Deliverables
- [x] Agent identity lifecycle (register, rotate, revoke)
- [x] Behavioral attestation with continuous auth
- [x] Enhanced delegation chains for NHI
- [x] Delegation scope constraints and approval
- [x] DPoP (RFC 9449) support
- [x] 16 REST API endpoints
- [x] 28 integration tests

**Completed:** 2026-02-09

---

## Phase 11: MCP Tasks Primitive (v2.1) ✅ COMPLETE

*Focus: Security for the new MCP Tasks primitive in 2025-11-25 spec*

> **Status:** Implemented in commit (pending). All core deliverables complete.

### Background

MCP 2025-11-25 introduces the Tasks primitive for long-running, multi-step operations:
- Task state persistence across reconnections
- Task cancellation and resumption
- Task result streaming

### 11.1 Task Security

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement task state encryption | P1 | 2 days | ✅ Complete |
| Add task authentication on resume | P1 | 2 days | ✅ Complete |
| Implement task result validation | P1 | 2 days | ✅ Complete |
| Create task timeout enforcement | P1 | 1 day | ✅ Complete |

**Features:**
- ChaCha20-Poly1305 AEAD encryption for task state
- HMAC-SHA256 resume tokens for authenticated task resumption
- Encrypted state stored as base64, decrypted only for authorized callers
- Timeout enforcement via existing TaskStateManager expires_at

### 11.2 Task Integrity

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement task state hash chain | P1 | 2 days | ✅ Complete |
| Add task state tampering detection | P1 | 1 day | ✅ Complete |
| Create task checkpoint verification | P1 | 2 days | ✅ Complete |
| Implement task replay protection | P1 | 1 day | ✅ Complete |

**Features:**
- SHA-256 hash chain: each transition includes prev_hash, sequence, status, timestamp
- Integrity verification detects any modified transitions
- Ed25519 signed checkpoints for non-repudiation
- Nonce-based replay protection with FIFO eviction

### 11.3 Configuration

```toml
[async_tasks]
enabled = true
max_concurrent_tasks = 100
max_task_duration_secs = 3600
encrypt_state = true           # ChaCha20-Poly1305 encryption
enable_hash_chain = true       # SHA-256 integrity tracking
require_resume_token = true    # HMAC-SHA256 resume authentication
replay_protection = true       # Nonce-based anti-replay
max_nonces = 1000              # Per-task nonce tracking limit
enable_checkpoints = false     # Ed25519 signed checkpoints
checkpoint_interval = 10       # Checkpoint every N transitions
task_retention_secs = 3600     # Completed task retention
```

### 11.4 New Types

- `SecureTask` — Task with encryption, hash chain, resume token, nonce tracking
- `TaskStateTransition` — Hash chain entry with sequence, prev_hash, status, hash
- `TaskCheckpoint` — Ed25519 signed snapshot of task state
- `TaskResumeRequest` / `TaskResumeResult` — Authenticated resume flow
- `TaskIntegrityResult` — Hash chain verification result
- `SecureTaskStats` — Task security statistics

### Phase 11 Deliverables
- [x] Task state encryption (ChaCha20-Poly1305)
- [x] Resume token authentication (HMAC-SHA256)
- [x] Task state hash chain (SHA-256)
- [x] Checkpoint verification (Ed25519 signatures)
- [x] Replay protection (nonce tracking)
- [x] 10 unit tests covering all security features

**Completed:** 2026-02-09

---

## Phase 12: Semantic Guardrails (v2.2) ✅ COMPLETE

*Focus: LLM-based guardrails for nuanced policy enforcement*

> **Status:** Implemented in commit `a56b3a8`. All core deliverables complete.

### Background

Competitors like NeMo Guardrails and Guardrails AI use LLM-based reasoning for:
- Intent classification beyond pattern matching
- Contextual policy enforcement
- Natural language policy definitions
- Jailbreak detection resistant to adversarial prompts

### 12.1 LLM Policy Evaluator

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Define LLM evaluator interface | P2 | 1 day | ✅ Complete |
| Implement local model support (GGUF/ONNX) | P2 | 3 days | ✅ Complete (feature-gated) |
| Add cloud model support (OpenAI, Anthropic) | P2 | 2 days | ✅ Complete (feature-gated) |
| Create evaluation caching layer | P2 | 2 days | ✅ Complete |

**Configuration:**
```toml
[semantic_guardrails]
enabled = true
model = "openai:gpt-4o-mini"   # or "anthropic:claude-3-haiku"
cache_ttl_secs = 300
cache_max_size = 10000
max_latency_ms = 500
fallback_on_timeout = "deny"    # deny | allow | pattern_match
min_confidence = 0.7

[semantic_guardrails.intent_classification]
enabled = true
confidence_threshold = 0.6
track_intent_chains = true

[semantic_guardrails.jailbreak_detection]
enabled = true
confidence_threshold = 0.7
block_on_detection = true

[[semantic_guardrails.nl_policies]]
id = "no-file-delete"
name = "Prevent file deletion"
statement = "Never allow file deletion outside of /tmp directory"
tool_patterns = ["filesystem:*", "shell:*"]
```

### 12.2 Intent Classification

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement intent taxonomy | P2 | 2 days | ✅ Complete |
| Add intent-based policy routing | P2 | 2 days | ✅ Complete |
| Create intent confidence thresholds | P2 | 1 day | ✅ Complete |
| Implement intent chain tracking | P2 | 2 days | ✅ Complete |

**Intent Taxonomy:**
- Data Operations: DataRead, DataWrite, DataDelete, DataExport, DataQuery
- System Operations: SystemExecute, SystemConfigure, SystemMonitor
- Network Operations: NetworkFetch, NetworkSend, NetworkConnect
- Security-Sensitive: CredentialAccess, PrivilegeEscalation, PolicyBypass
- Malicious: Injection, Exfiltration, DenialOfService

### 12.3 Natural Language Policies

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Design NL policy syntax | P2 | 2 days | ✅ Complete |
| Implement NL to rule compiler | P2 | 3 days | ✅ Complete |
| Add policy explanation generation | P2 | 2 days | ✅ Complete |
| Create policy testing framework | P2 | 2 days | ✅ Complete |

### 12.4 Jailbreak Detection

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement jailbreak pattern detection | P2 | 2 days | ✅ Complete |
| Add LLM-based jailbreak analysis | P2 | 2 days | ✅ Complete |
| Create configurable thresholds | P2 | 1 day | ✅ Complete |

### 12.5 Service Architecture

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Create SemanticGuardrailsService facade | P2 | 2 days | ✅ Complete |
| Implement backend dispatcher | P2 | 2 days | ✅ Complete |
| Add mock backend for testing | P2 | 2 days | ✅ Complete |
| Create comprehensive test suite | P2 | 1 day | ✅ Complete |

### Phase 12 Deliverables
- [x] LLM evaluator interface with pluggable backends
- [x] Intent classification with confidence thresholds
- [x] Intent chain tracking for suspicious pattern detection
- [x] Natural language policy definitions with glob matching
- [x] Jailbreak detection with configurable thresholds
- [x] LRU + TTL evaluation cache
- [x] Mock backend for testing
- [x] Comprehensive configuration in sentinel-config

**Completed:** 2026-02-09

---

## Phase 13: RAG Poisoning Defense (v2.2) ✅ COMPLETE

*Focus: Protect retrieval-augmented generation from data poisoning*

> **Status:** Implemented in commit `90541df`. All deliverables complete.

### Background

RAG systems are vulnerable to:
- Document injection: Malicious content in knowledge base
- Embedding manipulation: Adversarial perturbations
- Context window flooding: Irrelevant data diluting real information

### 13.1 Document Verification

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement document provenance tracking | P2 | 2 days | ✅ Complete |
| Add document content hashing | P2 | 1 day | ✅ Complete |
| Create document approval workflow | P2 | 2 days | ✅ Complete |
| Implement document trust scoring | P2 | 2 days | ✅ Complete |

### 13.2 Retrieval Security

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add retrieval result inspection | P2 | 2 days | ✅ Complete |
| Implement embedding similarity anomaly detection | P2 | 3 days | ✅ Complete |
| Create retrieval diversity enforcement | P2 | 2 days | ✅ Complete |
| Add context window budget tracking | P2 | 1 day | ✅ Complete |

### Phase 13 Deliverables
- [x] Document provenance and trust scoring
- [x] Retrieval result inspection
- [x] Embedding anomaly detection
- [x] Context window budget enforcement

**Implementation Details:**
- `sentinel-mcp/src/rag_defense/` module with 6 submodules (~1,300 lines)
- `RagDefenseConfig` in sentinel-config with 4 sub-configs
- 58 unit tests, all passing
- Feature flag: `rag-defense`

**Actual Duration:** 1 day

---

## Phase 14: A2A Protocol Security (v2.2) ✅ COMPLETE

*Focus: Security for Google's Agent-to-Agent (A2A) protocol*

> **Status:** Implemented. All deliverables complete.

### Background

Google's A2A protocol (2025) defines standardized agent-to-agent communication.
Sentinel secures A2A traffic using the same patterns established for MCP:
- Message interception and classification
- Policy evaluation for access control
- Security integration (DLP, injection detection, circuit breaker)
- Batch rejection for TOCTOU attack prevention

### 14.1 A2A Message Handling

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Define A2A message types (TaskState, PartContent, etc.) | P2 | 1 day | ✅ Complete |
| Implement message classification (message/send, tasks/*, etc.) | P2 | 1 day | ✅ Complete |
| Add method normalization (Unicode stripping, case folding) | P2 | 0.5 days | ✅ Complete |
| Extract text content for security scanning | P2 | 0.5 days | ✅ Complete |

### 14.2 Action Extraction & Policy Evaluation

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Map A2A messages to Sentinel Actions (a2a:message_send, etc.) | P2 | 0.5 days | ✅ Complete |
| Add JSON-RPC error/denial response helpers | P2 | 0.5 days | ✅ Complete |
| Integrate with PolicyEngine for access control | P2 | 0.5 days | ✅ Complete |
| Add task operation restrictions | P2 | 0.5 days | ✅ Complete |

### 14.3 Agent Card Handling

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Define AgentCard types (capabilities, skills, auth schemes) | P2 | 0.5 days | ✅ Complete |
| Implement AgentCardCache with TTL-based expiration | P2 | 0.5 days | ✅ Complete |
| Add agent card validation helpers | P2 | 0.5 days | ✅ Complete |
| Support authentication scheme detection | P2 | 0.5 days | ✅ Complete |

### 14.4 A2A Proxy Service

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement A2aProxyService with request processing | P2 | 1 day | ✅ Complete |
| Integrate security scanning (DLP, injection) | P2 | 0.5 days | ✅ Complete |
| Add batch rejection (security hardening) | P2 | 0.5 days | ✅ Complete |
| Create A2aConfig for policy configuration | P2 | 0.5 days | ✅ Complete |

### Phase 14 Deliverables
- [x] A2A protocol support with message classification
- [x] A2A policy evaluation via PolicyEngine
- [x] Agent card handling with caching
- [x] A2A proxy service with security integration
- [x] A2aConfig for configuration
- [x] Feature flag: `a2a`
- [x] 58 unit tests

**Implementation Details:**
- `sentinel-mcp/src/a2a/` module with 5 submodules (~950 lines)
- `A2aConfig` in sentinel-config with security toggles
- 58 unit tests, all passing
- Feature flag: `a2a`

**Actual Duration:** 1 day

---

## Phase 15: Observability Platform Integration (v2.2) ✅ COMPLETE

*Focus: Deep integration with AI observability platforms*

> **Status:** Implemented in v2.2.1. Core integrations and hardening complete.

### Background

AI observability platforms (Arize, Langfuse, Helicone) provide:
- LLM call tracing and debugging
- Token usage analytics
- Quality evaluation
- A/B testing

### 15.1 Platform Integrations

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add Arize export integration | P3 | 2 days | ✅ Complete |
| Add Langfuse export integration | P3 | 2 days | ✅ Complete |
| Add Helicone export integration | P3 | 2 days | ✅ Complete |
| Create custom webhook export | P3 | 1 day | ✅ Complete |

### 15.2 Enhanced Tracing

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add full request/response capture | P3 | 2 days | ✅ Complete |
| Implement trace sampling | P3 | 1 day | ✅ Complete |
| Add trace filtering by policy outcome | P3 | 1 day | ✅ Complete |
| Create trace correlation with external spans | P3 | 2 days | ✅ Complete |

### Phase 15 Deliverables
- [x] Arize, Langfuse, Helicone integrations
- [x] Full request/response capture
- [x] Trace sampling and filtering
- [x] External span correlation
- [x] Fail-closed SSE output schema validation parity in HTTP proxy streaming path
- [x] Observability regression hardening with async integration coverage and property tests

**Actual Duration:** 2 weeks
**Completed:** 2026-02-10

---

## v2.1 Timeline Summary

```
Phase 8:  ETDI & Cryptographic Tool Security     (3 weeks)  ✅ COMPLETE
Phase 9:  Memory Injection Defense               (3 weeks)  ✅ COMPLETE
Phase 10: Non-Human Identity Lifecycle           (3 weeks)  ✅ COMPLETE
Phase 11: MCP Tasks Primitive                    (2 weeks)  ✅ COMPLETE
───────────────────────────────────────────────────────────
v2.1 Complete! Ready for release.
```

## v2.2 Timeline Summary

```
Phase 12: Semantic Guardrails                    (4 weeks)  ✅ COMPLETE
Phase 13: RAG Poisoning Defense                  (3 weeks)  ✅ COMPLETE
Phase 14: A2A Protocol Security                  (2 weeks)  ✅ COMPLETE
Phase 15: Observability Platform Integration     (2 weeks)  ✅ COMPLETE
───────────────────────────────────────────────────────────
v2.2 Complete! Ready for v2.3 planning.
```

---

## Competitor Feature Comparison (Updated)

| Feature | Sentinel v2.2.1 | NeMo Guardrails | Guardrails AI | Zenity | Prisma AIRS |
|---------|---------------|-----------------|---------------|--------|-------------|
| Policy Engine | ✅ Strong | ✅ Strong | ✅ Strong | ✅ Strong | ✅ Strong |
| Injection Detection | ✅ Multi-layer | ✅ LLM-based | ✅ LLM-based | ⚠️ Basic | ✅ Strong |
| DLP/Data Loss Prevention | ✅ 8-layer | ⚠️ Basic | ✅ Validators | ✅ Strong | ✅ Strong |
| Audit Logging | ✅ Hash chain | ⚠️ Basic | ⚠️ Basic | ✅ Strong | ✅ Strong |
| MCP Protocol Support | ✅ Native | ❌ | ❌ | ⚠️ Basic | ❌ |
| A2A Protocol Support | ✅ Native | ❌ | ❌ | ❌ | ❌ |
| Schema Poisoning | ✅ Jaccard | ❌ | ❌ | ❌ | ❌ |
| Cross-Agent Security | ✅ Trust graph | ❌ | ❌ | ⚠️ Basic | ❌ |
| ETDI Tool Signing | ✅ Ed25519/ECDSA | ❌ | ❌ | ❌ | ❌ |
| Memory Injection Defense | ✅ Full MINJA | ❌ | ❌ | ❌ | ❌ |
| Semantic Guardrails | ✅ LLM-based | ✅ Native | ✅ Native | ⚠️ Basic | ⚠️ Basic |
| NHI Lifecycle | ✅ Full | ❌ | ❌ | ⚠️ Basic | ❌ |
| RAG Poisoning Defense | ✅ Full | ❌ | ❌ | ❌ | ❌ |

---

## Phase 16+ Future Roadmap

*Items identified through adversarial analysis for future consideration*

### 16.1 SDK & Framework Integration

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| LangChain/LangGraph SDK integration | P3 | 2 weeks | Research |
| AutoGen framework adapter | P3 | 2 weeks | Research |
| Semantic Kernel integration | P3 | 1 week | Research |
| CrewAI integration | P3 | 1 week | Research |

### 16.2 Deployment & Distribution

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| AWS Marketplace listing | P4 | 2 weeks | Pending |
| GCP Marketplace listing | P4 | 2 weeks | Pending |
| Azure Marketplace listing | P4 | 2 weeks | Pending |
| Docker Hub official images | P3 | 3 days | Pending |

### 16.3 Developer Experience

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Visual execution graph UI | P3 | 4 weeks | Research |
| Browser extension for MCP debugging | P4 | 3 weeks | Research |
| VS Code extension | P3 | 2 weeks | Pending |
| CLI interactive mode enhancements | P3 | 1 week | Pending |

### 16.4 Advanced Security Research

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Decision Dependency Graph analysis | P4 | Research | Research |
| GPU-accelerated semantic guardrails | P4 | 4 weeks | Research |
| Continuous autonomous red teaming | P4 | Research | Research |
| ToolHijacker defense (tool source verification) | P3 | 3 weeks | Research |
| Multimodal injection detection | P4 | 4 weeks | Research |

### 16.5 Dependency Upgrades (Blocked)

| Task | Blocker | Resolution |
|------|---------|------------|
| rand 0.8 → 0.9 | ed25519-dalek uses rand_core 0.6 | Wait for upstream update |
| Consider ring → aws-lc-rs | Performance evaluation needed | Benchmark first |

### 16.6 Architecture Split & Modularization (Active)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Extract route handlers to dedicated modules (`sentinel-server`) | P2 | 3 days | ✅ Complete |
| Maintain crate-boundary architecture map (owners, interfaces, tests) | P2 | 2 days | Active |
| Enforce split safety gates (`check`, `clippy`, workspace tests) per extraction step | P1 | Ongoing | Active |
| Track formatting drift and non-functional deltas during split windows | P2 | Ongoing | Active |
| Define post-split contract checks for `sentinel-types` changes | P1 | 3 days | ✅ Complete |
| Add module extraction playbook for contributors | P2 | 2 days | ✅ Complete |

**2026-02-11 Update:** Server route modularization complete. Created 17 dedicated route modules (approval, audit, auth_level, circuit_breaker, deputy, etdi, exec_graph, memory, nhi, observability, policy, registry, sampling, schema_lineage, shadow_agent, task_state, tenant). Reduced `routes/main.rs` from ~3300 to ~2500 lines.
**2026-02-11 Update:** Added post-split `sentinel-types` contract CI gate (`sentinel-types-contract`) and published contributor guidance in `MODULE_EXTRACTION_PLAYBOOK.md`.

### 16.7 Post-Quantum Cryptography Transition (Active)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add `tls.kex_policy` config surface (`classical_only`, `hybrid_preferred`, `hybrid_required_when_supported`) | P1 | 3 days | ✅ Initial implementation |
| Enforce KEX policy against rustls provider groups with downgrade warnings | P1 | 2 days | ✅ Initial implementation |
| Emit negotiated TLS metadata (KEX group, protocol, cipher) in telemetry and audit | P1 | 3 days | ✅ Initial implementation |
| Standardize outbound TLS backend strategy for workspace `reqwest` clients | P1 | 2 days | ✅ Initial implementation |
| Add hybrid/classical negotiation integration tests and failure-mode checks | P2 | 4 days | ✅ Initial implementation |
| Publish `docs/quantum-migration.md` rollout + rollback runbook | P2 | 2 days | Planned |
| Track IETF TLS PQ drafts to RFC and tighten defaults when ecosystem support stabilizes | P1 | Ongoing | Active Research |

**2026-02-11 Update:** `sentinel-server` now emits negotiated TLS metadata (`protocol`, `cipher`, `kex_group`) from sanitized forwarded TLS headers into evaluate-path audit metadata and observability span attributes.
**2026-02-11 Update:** Added `sentinel-server` TLS KEX integration tests covering classical-only, hybrid-preferred fallback, and hybrid-required failure-mode enforcement against classical-only clients.
**2026-02-11 Update:** Standardized workspace outbound `reqwest` TLS backend to rustls (`default-features = false`, `features = ["json", "rustls-tls"]`) and validated compile paths for `sentinel-server`, `sentinel-http-proxy`, `sentinel-audit` observability exporters, and `sentinel-mcp` `llm-cloud`.

**External milestones we align to (planning targets):**
- Define migration goals and inventory by **2028**
- Complete highest-priority migration activities by **2031**
- Complete full migration by **2035**

### 16.8 CI Supply-Chain Hardening Pack (Delivered)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add pull-request dependency review gate (`dependency-review-action`) | P0 | 1 day | ✅ Complete |
| Add `.github/dependabot.yml` for Cargo and GitHub Actions | P0 | 1 day | ✅ Complete |
| Add `cargo-deny` policy workflow + baseline config (`deny.toml`) | P1 | 1 day | ✅ Complete (initial baseline) |
| Pin third-party GitHub Actions to immutable commit SHAs | P0 | 2 days | ✅ Complete |
| Add build provenance attestation in release workflow | P0 | 2 days | ✅ Complete |
| Generate and publish SBOM (CycloneDX/SPDX) with releases | P0 | 2 days | ✅ Complete |

### 16.9 Sender-Constrained OAuth for HTTP Proxy (Delivered)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add DPoP enforcement mode to `sentinel-http-proxy` OAuth config | P0 | 2 days | ✅ Complete |
| Validate DPoP proof claims (`htu`, `htm`, `jti`, nonce, `ath`) per RFC 9449 | P0 | 3 days | ✅ Complete |
| Bind proof validation to access token and request path/method checks | P0 | 2 days | ✅ Complete |
| Add proxy integration tests for replay and mismatch cases | P1 | 2 days | ✅ Complete |
| Add audit events and Prometheus metrics for DPoP failures/replay | P1 | 2 days | ✅ Complete |

---

## Research Bibliography

1. **ETDI: Enhanced Tool Definition Interface** — arxiv:2506.01333 (2025)
2. **MINJA: Memory Injection Attacks on LLM Agents** — Agent Security Bench (2025)
3. **Agentic Trust Framework (ATF)** — CyberArk, Astrix Security (2026)
4. **MCP Specification 2025-11-25** — modelcontextprotocol.io
5. **OWASP Top 10 for Agentic Applications 2026** — genai.owasp.org
6. **A2A Protocol Specification** — Google (2025)
7. **Enterprise-Grade Security for MCP** — arxiv:2504.08623 (2025)
8. **Runtime Risk to Real-Time Defense** — Microsoft Security Blog (2026)
9. **Agent Security Bench: Evaluating LLM Agent Safety** — Stanford (2025)
10. **Privilege Management in MCP** — arxiv:2507.06250 (2025)
11. **NIST Post-Quantum Cryptography Project** — csrc.nist.gov/projects/post-quantum-cryptography
12. **FIPS 203 (ML-KEM)** — csrc.nist.gov/pubs/fips/203/final
13. **NIST SP 800-227 (KEM Guidance)** — csrc.nist.gov/pubs/sp/800/227/final
14. **NCSC: Preparing for PQC Migration** — ncsc.gov.uk (2025)
15. **NSA CNSA 2.0 PQ Transition FAQ** — media.defense.gov (2022)
