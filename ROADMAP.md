# Sentinel Roadmap v3.0

> **Version:** 3.0.0 (Planning)
> **Generated:** 2026-02-13
> **Baseline:** v2.2.1 — 4,353+ Rust tests, 130 Python SDK tests, 35 audit rounds, 22 fuzz targets, 11 CI workflows
> **Scope:** 12 months (Q1–Q4 2026), quarterly milestones
> **Status:** All v2.0–v2.2 phases (1–15) complete; Phases 17.1–17.2 complete; Phase 19 complete (all 9 exit criteria); Phase 21.0 complete; v3.0 in progress

---

## Executive Summary

Sentinel v2.2.1 is production-ready. The v3.0 roadmap addresses the next wave of protocol evolution, regulatory deadlines, and enterprise competition:

1. **MCP Next Spec (June 2026)** — WebSocket transport (SEP-1288), gRPC transport (Google), async operations (SEP-1391), protocol extensions, SDK tiering
2. **EU AI Act Enforcement (August 2, 2026)** — High-risk AI system compliance, transparency obligations, penalties up to 7% global revenue
3. **Threat Landscape Maturity** — CoSAI MCP Security Whitepaper (12 threat categories, ~40 threats), Adversa AI MCP Security TOP 25 vulnerability catalog
4. **Observability Standards** — OpenTelemetry GenAI Semantic Conventions for standardized agent telemetry
5. **Gateway Competition** — Microsoft MCP Gateway (K8s), AWS AgentCore, MintMCP (SOC 2)
6. **Enterprise Competitors** — Cisco AI Defense, Palo Alto Prisma AIRS, Radware, CalypsoAI, Akamai
7. **Transport Evolution** — gRPC (Google Cloud), WebSocket (SEP-1288), transport negotiation

### Research Sources

| Source | Relevance |
|--------|-----------|
| [MCP Specification 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18) | Current baseline spec |
| [MCP SEP-1288: WebSocket Transport](https://github.com/modelcontextprotocol/specification/discussions/1288) | Bidirectional, session-persistent transport |
| [MCP SEP-1391: Async Operations](https://github.com/modelcontextprotocol/specification/discussions/1391) | Long-running task improvements |
| [Google gRPC Transport for MCP](https://cloud.google.com/blog/products/ai-machine-learning/grpc-transport-for-mcp) | Protocol Buffers transport proposal |
| [EU AI Act — EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | Regulation (EU) 2024/1689, enforcement August 2, 2026 |
| [CoSAI MCP Security Whitepaper](https://www.cosai.owasp.org/) | 12 threat categories, ~40 threats |
| [Adversa AI MCP Security TOP 25](https://adversa.ai/mcp-security-top-25/) | Industry-first MCP vulnerability catalog |
| [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Standardized agent observability |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | Kubernetes-native MCP gateway |
| [AWS AgentCore](https://aws.amazon.com/agentcore/) | Managed agent runtime |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ASI01–ASI10 threat taxonomy |
| [OWASP Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/) | MCP security best practices |
| [ETDI: Mitigating Tool Squatting and Rug Pull Attacks](https://arxiv.org/abs/2506.01333) | Cryptographic tool attestation |
| [Enterprise-Grade Security for MCP](https://arxiv.org/pdf/2504.08623) | Enterprise security patterns |
| [Microsoft: Runtime Risk to Real-Time Defense](https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/) | Agent runtime security |
| [Kaspersky: Agentic AI Security per OWASP ASI Top 10](https://www.kaspersky.com/blog/top-agentic-ai-risks-2026/55184/) | Threat analysis |

---

## Priority Matrix

| Priority | Theme | Business Driver | Deadline Pressure |
|----------|-------|-----------------|-------------------|
| **P0** | Protocol compliance + Regulatory | MCP June 2026 spec, EU AI Act Aug 2 2026 | Hard deadlines |
| **P1** | Gateway mode + Authorization | Enterprise customer requirements, competitive parity | H2 2026 |
| **P2** | Developer experience + SDK | Adoption, community growth | Q4 2026 |
| **P3** | Research + Future-proofing | Technical differentiation, long-term moat | Ongoing |

---

## Timeline Overview

```
Q1 2026 (Feb–Mar):  Phase 17 — MCP Next Spec Preparation          [P0]
Q2 2026 (Apr–Jun):  Phase 18 — MCP June 2026 Spec Compliance      [P0]
                     Phase 19 — Regulatory Compliance               [P0] ✅ COMPLETE
Q3 2026 (Jul–Sep):  Phase 20 — MCP Gateway Mode                   [P1]
                     Phase 21 — Advanced Authorization              [P1]
Q4 2026 (Oct–Dec):  Phase 22 — Developer Experience               [P2]
                     Phase 23 — Research & Future                   [P3]
```

---

## Q1 2026 (Feb–Mar): Foundation & Protocol Prep

### Phase 17: MCP Next Spec Preparation (P0)

*Focus: Prepare for the upcoming MCP June 2026 specification by implementing transport layer extensions and async operation enhancements*

The MCP specification is evolving rapidly. Three major proposals are expected to land in the June 2026 spec:
- **SEP-1288** introduces WebSocket transport for bidirectional, session-persistent connections
- **Google's gRPC proposal** adds Protocol Buffers-based transport for high-throughput environments
- **SEP-1391** enhances async operations for long-running agent tasks

#### 17.1 WebSocket Transport Support (SEP-1288) ✅ COMPLETE

Bidirectional, session-persistent transport replacing HTTP SSE for real-time agent communication.

> **Status:** Implemented in commit `2423f0e`. All deliverables complete.

| Task | Status | Notes |
|------|--------|-------|
| Bidirectional MCP-over-WebSocket reverse proxy at `/mcp/ws` | ✅ | `sentinel-http-proxy/src/proxy/websocket/mod.rs` |
| Full policy enforcement on client→upstream tool calls | ✅ | Fail-closed semantics, engine errors produce Deny |
| DLP scanning + injection detection on upstream→client responses | ✅ | Reuses existing inspection infrastructure |
| TOCTOU-safe JSON canonicalization before forwarding | ✅ | Matching HTTP proxy behavior |
| Per-connection rate limiting (sliding window) | ✅ | Configurable messages/sec, default 100/s |
| Idle timeout enforcement | ✅ | Configurable, default 300s |
| Max message size enforcement | ✅ | Configurable, default 1MB, close code 1009 |
| Session binding (one session per WebSocket connection) | ✅ | Via query parameter or auto-created |
| Binary frame rejection | ✅ | Close code 1003 (Unsupported Data) |
| Unparseable message rejection | ✅ | Close code 1008 (Policy Violation) |
| Upstream WebSocket client via `tokio-tungstenite` | ✅ | http→ws / https→wss URL conversion, 10s timeout |
| WebSocket metrics | ✅ | `sentinel_ws_connections_total`, `sentinel_ws_messages_total` |
| CLI args | ✅ | `--ws-max-message-size`, `--ws-idle-timeout`, `--ws-message-rate-limit` |
| WebSocket transport fuzz target | ✅ | `fuzz_ws_frame` (21 fuzz targets total) |
| WebSocket unit tests | ✅ | 29 tests covering all components |

**Security properties delivered:**
- Origin validation on WebSocket upgrade requests
- Per-message policy evaluation (not just per-connection)
- Frame size limits to prevent memory exhaustion
- Connection idle timeout enforcement
- Fail-closed: unparseable → close 1008, binary → close 1003, engine error → Deny
- No `unwrap()` in library code

**Configuration (CLI args):**
```
--ws-max-message-size 1048576    # 1 MB (default)
--ws-message-rate-limit 100      # per second per connection (default)
--ws-idle-timeout 300            # seconds (default)
```

**Completed:** 2026-02-13

#### 17.2 gRPC Transport Support (Google Proposal) ✅ COMPLETE

Protocol Buffers-based transport for high-throughput, strongly-typed agent communication.

> **Status:** Implemented. All deliverables complete. Feature-gated behind `grpc`.

| Task | Status | Notes |
|------|--------|-------|
| Protobuf schema for MCP messages (`proto/mcp/v1/mcp.proto`) | ✅ | Unary Call, bidirectional StreamCall, server-streaming Subscribe |
| gRPC transport adapter with tonic 0.13 | ✅ | `sentinel-http-proxy/src/proxy/grpc/mod.rs`, separate listener on port 50051 |
| gRPC service with full policy evaluation pipeline | ✅ | `service.rs` — classify → evaluate → audit → forward → DLP/injection scan |
| Proto↔JSON conversion with depth-bounded recursion | ✅ | `convert.rs` — MAX_DEPTH=64, NaN/Infinity rejection, fail-closed |
| Auth interceptor with constant-time API key validation | ✅ | `interceptors.rs` — SHA-256 + `subtle::ConstantTimeEq` |
| gRPC Health Checking v1 | ✅ | `tonic-health` integration, configurable |
| DLP scanning + injection detection on gRPC responses | ✅ | Reuses existing inspection infrastructure |
| gRPC-to-HTTP fallback upstream forwarding | ✅ | `upstream.rs` — gRPC clients work with HTTP MCP servers |
| Bidirectional streaming with per-message policy evaluation | ✅ | `stream_call()` — same pattern as WebSocket relay |
| gRPC transport fuzz target | ✅ | `fuzz_grpc_proto` (22 fuzz targets total) |
| gRPC unit tests | ✅ | 46 tests covering conversion, config, classification, auth, interceptors |
| GrpcTransportConfig in sentinel-config | ✅ | `sentinel-config/src/grpc_transport.rs` |
| CLI args for gRPC | ✅ | `--grpc`, `--grpc-port`, `--grpc-max-message-size`, `--upstream-grpc-url` |
| Metrics | ✅ | `sentinel_grpc_requests_total`, `sentinel_grpc_messages_total` |

**Security properties delivered:**
- Constant-time API key validation (SHA-256 hash comparison)
- Fail-closed: proto conversion errors → gRPC INTERNAL, policy denials → JSON-RPC error (not gRPC status)
- Depth-bounded proto↔JSON conversion (MAX_DEPTH=64) prevents stack overflow
- NaN/Infinity rejection in float conversion
- Message size limits at gRPC transport level (default 4 MB)
- Session ID extraction from gRPC metadata with length limits
- Binary frame semantics: invalid proto → gRPC INTERNAL status
- No `unwrap()` in library code
- Feature-gated: zero impact on non-grpc builds

**Configuration (CLI args):**
```
--grpc                              # Enable gRPC transport
--grpc-port 50051                   # Listen port (default)
--grpc-max-message-size 4194304     # 4 MB (default)
--upstream-grpc-url <url>           # Optional native gRPC upstream
```

**Completed:** 2026-02-13

#### 17.3 Async Operations Enhancements (SEP-1391)

Improvements to long-running task management for agent workflows.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement task progress streaming with policy checkpoints | P0 | 2 days | — |
| Add task delegation across transport boundaries | P0 | 3 days | Progress streaming |
| Implement task cancellation propagation in multi-agent chains | P0 | 2 days | — |
| Add task result caching with integrity verification | P1 | 2 days | — |
| Extend existing SecureTask with transport-agnostic state | P0 | 2 days | — |
| Add async operation integration tests across transports | P0 | 2 days | All above |

#### 17.4 Protocol Extensions Framework

Pluggable domain-specific extensions for MCP protocol.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define extension registry trait and lifecycle hooks | P1 | 2 days | — |
| Implement extension capability negotiation | P1 | 2 days | Registry trait |
| Add extension-scoped policy evaluation | P1 | 2 days | Capability negotiation |
| Create extension isolation (per-extension resource limits) | P1 | 2 days | — |
| Add extension validation and signing | P1 | 2 days | — |
| Document extension authoring guide | P1 | 1 day | All above |

### Phase 17 Exit Criteria
- [x] WebSocket transport passes all security tests with origin validation
- [x] gRPC transport passes all security tests with auth interceptor and fail-closed semantics
- [ ] Async operations work across all three transports (HTTP, WebSocket, gRPC)
- [ ] Protocol extensions framework supports at least one example extension
- [x] All fuzz targets passing, zero new `unwrap()` in library code
- [x] P99 evaluation latency remains <5ms on existing transports

**Estimated Duration:** 8 weeks

---

## Q2 2026 (Apr–Jun): Protocol & Compliance

### Phase 18: MCP June 2026 Spec Compliance (P0)

*Focus: Adopt final MCP June 2026 specification changes, achieve SDK tiering compliance, implement transport negotiation*

This phase activates once the June 2026 spec is published. Work items will be refined based on the final spec.

#### 18.1 Spec Delta Adoption

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Analyze June 2026 spec diff against current implementation | P0 | 2 days | Spec publication |
| Implement new required protocol features | P0 | TBD | Analysis |
| Update protocol version negotiation (2025-06-18 → 2026-06) | P0 | 1 day | — |
| Add backward compatibility for 2025-06-18 clients | P0 | 2 days | Version negotiation |
| Update all protocol compliance tests | P0 | 3 days | Implementation |

#### 18.2 SDK Tiering Compliance

MCP SDK tiering defines capability levels that implementations must declare and maintain.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Declare Sentinel SDK tier level based on spec requirements | P0 | 1 day | Spec publication |
| Implement tier-specific capability advertisements | P0 | 2 days | Tier declaration |
| Add tier compliance validation in CI | P0 | 1 day | Capability ads |
| Create tier compatibility matrix documentation | P1 | 1 day | — |

#### 18.3 Transport Negotiation and Fallback

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement transport capability advertisement | P0 | 2 days | Phase 17 transports |
| Add automatic transport negotiation (prefer gRPC → WebSocket → HTTP SSE → stdio) | P0 | 3 days | Capability ad |
| Implement graceful transport fallback on connection failure | P0 | 2 days | Negotiation |
| Add transport selection policy (admin can restrict transports) | P1 | 2 days | — |
| Create transport migration tests (upgrade/downgrade scenarios) | P0 | 2 days | All above |

### Phase 18 Exit Criteria
- [ ] Full compliance with MCP June 2026 specification
- [ ] SDK tier level declared and CI-validated
- [ ] Transport negotiation working across all supported transports
- [ ] Backward compatibility with 2025-06-18 clients verified

**Estimated Duration:** 4 weeks (parallel with Phase 19)

---

### Phase 19: Regulatory Compliance (P0) ✅ COMPLETE

*Focus: EU AI Act Article 50 compliance, OpenTelemetry standardization, threat framework gap closure, SOC 2 audit readiness*

> **Status:** All 9 exit criteria delivered. Completed 2026-02-14.

The EU AI Act enforcement date of **August 2, 2026** creates a hard deadline for transparency and logging requirements applicable to AI systems.

#### 19.1 EU AI Act Compliance Evidence Generation ✅ COMPLETE

Conformity assessment, transparency evidence generation, and runtime transparency features for EU AI Act obligations.

> **Status:** Implemented. Registry-based evidence generation, Art 50(1) runtime transparency marking, Art 14 human oversight triggers, and compliance dashboard all complete.

| Task | Status | Notes |
|------|--------|-------|
| EU AI Act registry with obligation mappings (Art 5, 6, 9, 12, 13, 14, 15, 43, 50) | ✅ | `sentinel-audit/src/eu_ai_act.rs` |
| Conformity assessment report generator (Art. 43) | ✅ | `EuAiActRegistry::generate_assessment()` |
| Risk classification with capability mappings (Art. 6/Annex III) | ✅ | `AiActRiskClass` enum, 18 capability mappings |
| Transparency entry classification (read-time) | ✅ | `classify_entry_transparency()` |
| Compliance status API endpoint | ✅ | `GET /api/compliance/status` |
| EU AI Act report API endpoint | ✅ | `GET /api/compliance/eu-ai-act/report` |
| `ComplianceConfig` with validation | ✅ | `sentinel-config/src/compliance.rs` |
| Shared compliance types in leaf crate | ✅ | `sentinel-types/src/compliance.rs` |
| EU AI Act unit tests | ✅ | 11 tests |
| Implement AI system identification in all agent outputs (Art. 50(1)) | ✅ | `mark_ai_mediated()` injects `_meta.sentinel_ai_mediated` into responses (`sentinel-mcp/src/transparency.rs`) |
| Add automated decision explanation logging (Art. 50(2)) | 🔲 | Future: per-verdict explanations |
| Implement human oversight notification triggers (Art. 14) | ✅ | `requires_human_oversight()` with glob-based tool matching + audit events in relay loop |
| Implement data governance record keeping (Art. 10) | 🔲 | Future |
| Create EU AI Act compliance dashboard section | ✅ | 4 metric cards + 6-framework table in `sentinel-server/src/dashboard.rs` |

**Configuration:**
```toml
[compliance.eu_ai_act]
enabled = true
risk_class = "high_risk"             # minimal | limited | high_risk | unacceptable
deployer_name = "Acme Corp"
system_id = "sentinel-mcp-firewall-v3"
transparency_marking = true          # Art 50(1)
human_oversight_tools = ["CredentialAccess", "SystemExecute", "DataDelete"]  # Art 14
record_retention_days = 365          # Art 12
conformity_assessment = true         # Art 43
```

#### 19.2 OpenTelemetry GenAI Semantic Conventions ✅ COMPLETE

Native OTLP export using the standardized GenAI semantic conventions for agent observability.

> **Status:** Implemented. OTLP exporter with GenAI semantic conventions, OtlpConfig with validation, feature-gated behind `otlp-exporter`.

| Task | Status | Notes |
|------|--------|-------|
| Implement OTLP exporter with GenAI semantic conventions | ✅ | `sentinel-audit/src/observability/otlp.rs` |
| Add `gen_ai.system`, `gen_ai.operation.name` attributes | ✅ | `span_to_otel_attributes()` with GenAI + sentinel.* attributes |
| Map SecuritySpan to OTel spans (span kind, verdict→status, ID/time parsing) | ✅ | `map_span_kind()`, `verdict_to_status()`, `parse_trace_id()`, `parse_span_id()` |
| OtlpConfig with endpoint/protocol/headers validation | ✅ | `sentinel-config/src/observability.rs` |
| Feature-gated behind `otlp-exporter` | ✅ | Zero impact on default builds |
| OTLP unit tests | ✅ | 11 tests |
| Implement `gen_ai.agent.*` attributes for multi-agent tracing | 🔲 | Future: multi-agent trace context |
| Add trace context propagation across MCP/A2A boundaries | 🔲 | Future: distributed tracing |
| Create Grafana dashboard templates for GenAI metrics | 🔲 | Future |
| Add Jaeger/Tempo integration tests | 🔲 | Future |

**Configuration:**
```toml
[observability.otlp]
enabled = true
endpoint = "http://otel-collector:4317"
protocol = "grpc"                    # grpc | http_proto
service_name = "sentinel"
batch_size = 100
flush_interval_secs = 10
max_retries = 3
timeout_secs = 30
```

**Completed:** 2026-02-14

#### 19.3 CoSAI Threat Coverage Gap Closure ✅ COMPLETE

Map all 12 CoSAI threat categories (~40 threats) to Sentinel controls and close identified gaps.

> **Status:** Implemented in commit `a8314c1`. All deliverables complete.

| Task | Status | Notes |
|------|--------|-------|
| CoSAI 12-category threat registry (38 threats) | ✅ | `sentinel-audit/src/cosai.rs` |
| CoSAI detection mappings (SentinelDetection → threats) | ✅ | Runtime + structural mitigations, 100% coverage |
| CoSAI coverage report generation | ✅ | `CosaiRegistry::generate_coverage_report()` |
| Adversa AI TOP 25 coverage matrix (25/25) | ✅ | `sentinel-audit/src/adversa_top25.rs` |
| Cross-framework gap analysis (6 frameworks) | ✅ | `sentinel-audit/src/gap_analysis.rs` |
| Threat coverage API endpoint | ✅ | `GET /api/compliance/threat-coverage` |
| Gap analysis API endpoint | ✅ | `GET /api/compliance/gap-analysis` |
| Unit tests | ✅ | 35 tests (14 CoSAI + 14 Adversa + 7 gap analysis) |

**Frameworks covered in gap analysis:**
- MITRE ATLAS (14 techniques)
- NIST AI RMF (Govern/Map/Measure/Manage)
- ISO 27090 (5 control domains)
- EU AI Act (Art 5–50)
- CoSAI (12 categories, 38 threats)
- Adversa AI TOP 25 (25 vulnerabilities)

**Completed:** 2026-02-14

#### 19.4 SOC 2 Type II Audit Trail Enhancements ✅ COMPLETE

SOC 2 evidence generation with Trust Services Categories (CC1-CC9), Merkle tree inclusion proofs, and immutable audit log archive.

> **Status:** Implemented. Registry-based evidence generation, Merkle tree proofs, and immutable audit log archive all complete.

| Task | Status | Notes |
|------|--------|-------|
| SOC 2 registry with 22 criteria across CC1-CC9 | ✅ | `sentinel-audit/src/soc2.rs` |
| SOC 2 evidence report generator | ✅ | `Soc2Registry::generate_evidence_report()` |
| Coverage by category with readiness levels | ✅ | `coverage_by_category()`, 5-level ReadinessLevel |
| Read-time audit entry classification | ✅ | `classify_entry()` → `Soc2EvidenceRecord` |
| SOC 2 evidence API endpoint with category filter | ✅ | `GET /api/compliance/soc2/evidence?category=CC1` |
| SOC 2 unit tests | ✅ | 14 tests |
| Merkle tree inclusion proofs (RFC 6962 domain separation) | ✅ | `sentinel-audit/src/merkle.rs` |
| Merkle proof generation and verification | ✅ | `generate_proof()`, `verify_proof()` (static) |
| Merkle integration with audit logger | ✅ | `with_merkle_tree()` builder, leaf append on log_entry |
| Merkle root in checkpoints | ✅ | `merkle_root: Option<String>` in Checkpoint |
| Merkle tree rotation support | ✅ | Leaf file renamed alongside rotated log, tree reset |
| Merkle tree crash recovery | ✅ | `initialize()` rebuilds peaks from existing leaf file |
| Merkle tree unit tests | ✅ | 24 tests |
| Implement immutable audit log archive with retention policies | ✅ | `sentinel-audit/src/archive.rs` — gzip compression + retention enforcement, feature-gated `archive`. 9 tests |
| Create access review report generator | 🔲 | Future |

### Phase 19 Exit Criteria
- [x] EU AI Act conformity assessment registry and evidence generation API
- [x] SOC 2 evidence registry with CC1-CC9 coverage and evidence collection API
- [x] Merkle tree inclusion proofs integrated with audit logger and checkpoints
- [x] Compliance configuration with validation in sentinel-config
- [x] EU AI Act Article 50 runtime transparency features (output marking, human oversight triggers)
- [x] OTLP export with GenAI semantic conventions verified against OTel Collector
- [x] CoSAI/Adversa threat coverage >90% with documented exceptions (100% CoSAI, 100% Adversa TOP 25)
- [x] Immutable audit log archive with retention policies
- [x] Compliance dashboard shows real-time status

**Estimated Duration:** 6 weeks (parallel with Phase 18)

---

## Q3 2026 (Jul–Sep): Gateway & Enterprise

### Phase 20: MCP Gateway Mode (P1)

*Focus: Transform Sentinel from a single-server proxy into a multi-backend MCP gateway with session routing, tool aggregation, and Kubernetes-native deployment*

Enterprise deployments need a gateway that aggregates multiple MCP servers behind a single entry point — similar to Microsoft MCP Gateway but with Sentinel's security stack built in.

#### 20.1 Session-Aware Routing

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement session affinity routing (sticky sessions) | P1 | 3 days | — |
| Add content-based routing (route by tool name, agent ID, intent) | P1 | 3 days | — |
| Implement weighted round-robin with health checks | P1 | 2 days | — |
| Add circuit breaker per upstream backend | P1 | 2 days | — |
| Create routing policy DSL | P1 | 3 days | — |
| Add routing decision audit logging | P1 | 1 day | All above |

**Configuration:**
```toml
[gateway]
enabled = true
mode = "aggregating"               # passthrough | aggregating | filtering

[[gateway.upstreams]]
name = "code-tools"
url = "http://code-mcp:3000"
tools = ["filesystem:*", "git:*"]
weight = 100
health_check_interval_secs = 10

[[gateway.upstreams]]
name = "data-tools"
url = "http://data-mcp:3000"
tools = ["database:*", "api:*"]
weight = 100
health_check_interval_secs = 10

[gateway.routing]
strategy = "content_based"          # round_robin | content_based | sticky
session_affinity = true
session_ttl_secs = 3600
```

#### 20.2 Multi-Server Tool Discovery

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement upstream tool discovery via `tools/list` | P1 | 2 days | — |
| Add unified tool namespace with conflict resolution | P1 | 3 days | Tool discovery |
| Implement tool capability merging across backends | P1 | 2 days | Unified namespace |
| Add tool availability tracking (mark tools offline when backend unhealthy) | P1 | 2 days | Health checks |
| Create tool catalog API endpoint | P1 | 1 day | All above |

#### 20.3 Health-Aware Upstream Routing

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement active health checking (configurable probe endpoints) | P1 | 2 days | — |
| Add passive health checking (track error rates from real traffic) | P1 | 2 days | — |
| Implement gradual backend drain for maintenance | P1 | 2 days | Health checking |
| Add upstream connection pooling with limits | P1 | 2 days | — |
| Create health status dashboard section | P1 | 1 day | All above |

#### 20.4 Kubernetes-Native Deployment

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create Helm chart for gateway mode (StatefulSet with PVC) | P1 | 3 days | — |
| Implement leader election for cluster coordination | P1 | 3 days | — |
| Add Kubernetes Service discovery for upstream auto-registration | P1 | 2 days | — |
| Create PodDisruptionBudget and HPA templates | P1 | 1 day | Helm chart |
| Implement readiness/liveness probes with policy engine health | P1 | 1 day | — |
| Add Kubernetes NetworkPolicy templates | P1 | 1 day | — |
| Create Helm chart integration tests | P1 | 2 days | All above |

### Phase 20 Exit Criteria
- [ ] Gateway routes requests to multiple upstream MCP servers
- [ ] Session affinity maintained across reconnections
- [ ] Tool namespace unified with conflict detection
- [ ] Health-based routing removes unhealthy backends within 30s
- [ ] Helm chart passes `helm lint` and deploys to kind cluster
- [ ] P99 routing latency <2ms overhead above single-server mode

**Estimated Duration:** 6 weeks

---

### Phase 21: Advanced Authorization (P1)

*Focus: Fine-grained attribute-based access control, least-agency enforcement, identity federation, and continuous authorization*

#### 21.0 Capability-Based Delegation Tokens ✅ COMPLETE

Ed25519-signed capability tokens with monotonic attenuation for protocol-level delegation.

> **Status:** Implemented. Foundation for Phase 21 authorization features.

| Task | Status | Notes |
|------|--------|-------|
| CapabilityToken type with grants, delegation chain, depth budget | ✅ | `sentinel-types/src/capability.rs` |
| Ed25519 signing with length-prefixed canonical content | ✅ | `sentinel-mcp/src/capability_token.rs` |
| Token issuance, attenuation, and verification | ✅ | `issue_capability_token()`, `attenuate_capability_token()`, `verify_capability_token()` |
| Monotonic attenuation enforcement (depth decrements, grants subset, expiry clamped) | ✅ | Escalation rejected at attenuation time |
| Grant coverage matching (glob patterns, path/domain constraints) | ✅ | `check_grant_coverage()` |
| RequireCapabilityToken policy condition (fail-closed) | ✅ | `sentinel-engine/src/context_check.rs` |
| Policy compilation for `require_capability_token` | ✅ | `sentinel-engine/src/policy_compile.rs` |
| EvaluationContext extended with `capability_token` field | ✅ | `sentinel-types/src/identity.rs` |
| Structural validation (MAX_GRANTS=64, MAX_DEPTH=16, MAX_TOKEN_SIZE=65536) | ✅ | `validate_structure()` |
| Capability token unit tests | ✅ | 31 tests (4 types + 5 engine + 22 mcp) |

**Security properties delivered:**
- Fail-closed: missing or invalid token = Deny
- Monotonic attenuation: child tokens can only narrow parent grants
- Depth budget prevents unbounded delegation chains
- Ed25519 signature over canonical content prevents tampering
- Grant coverage checked against Action tool/function/paths/domains
- No new dependencies (reuses ed25519-dalek, hex, serde)

**Completed:** 2026-02-14

#### 21.1 Fine-Grained ABAC Engine (Cedar-Style)

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design Cedar-inspired policy language for agent authorization | P1 | 3 days | — |
| Implement policy parser and compiler | P1 | 5 days | Language design |
| Add policy decision engine with permit/forbid/conditional | P1 | 3 days | Parser |
| Implement entity store for principals, resources, actions | P1 | 3 days | Decision engine |
| Add policy analysis tools (coverage, conflict detection) | P1 | 2 days | Engine |
| Create ABAC policy migration from current format | P1 | 2 days | All above |
| Add ABAC integration tests with complex scenarios | P1 | 2 days | All above |

**Example policy:**
```cedar
// Allow code-agent to read files only in /workspace
permit(
    principal == Agent::"code-agent",
    action in [Action::"filesystem:read_file"],
    resource
) when {
    resource.path.startsWith("/workspace/") &&
    context.session.verified == true
};

// Deny all agents from accessing credentials
forbid(
    principal,
    action in [Action::"vault:read_secret", Action::"env:get_variable"],
    resource
) when {
    resource.tags.contains("credential")
};
```

#### 21.2 Least-Agency Principle Enforcement

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement capability scope tracking per agent session | P1 | 2 days | — |
| Add automatic permission narrowing over session lifetime | P1 | 2 days | Scope tracking |
| Implement unused-permission alerting | P1 | 2 days | — |
| Add permission request justification requirements | P1 | 2 days | — |
| Create least-agency compliance report | P1 | 1 day | All above |

#### 21.3 Identity Federation Across Organizations

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement cross-organization trust anchors | P1 | 3 days | — |
| Add federated identity mapping (external ID → internal principal) | P1 | 2 days | Trust anchors |
| Implement delegation across federation boundaries | P1 | 3 days | Identity mapping |
| Add federation audit trail (cross-org access logging) | P1 | 2 days | — |

#### 21.4 Continuous Authorization with Real-Time Context

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement real-time context evaluation (risk score changes mid-session) | P1 | 3 days | — |
| Add session re-evaluation triggers (threat intel update, anomaly detected) | P1 | 2 days | Context evaluation |
| Implement progressive authorization degradation | P1 | 2 days | Re-evaluation |
| Add continuous auth metrics and dashboard | P1 | 1 day | All above |

### Phase 21 Exit Criteria
- [ ] ABAC engine evaluates Cedar-style policies with <1ms P99 latency
- [ ] Least-agency enforcement measurably reduces over-permissioned sessions
- [ ] Identity federation working across at least 2 organizations in test
- [ ] Continuous authorization re-evaluates within 500ms of context change
- [ ] Full backward compatibility with existing policy format

**Estimated Duration:** 6 weeks (parallel with Phase 20)

---

## Q4 2026 (Oct–Dec): DX & Research

### Phase 22: Developer Experience (P2)

*Focus: Make Sentinel accessible to developers with visual tools, IDE integration, policy simulation, and CI gates*

#### 22.1 Visual Execution Graph UI

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design execution graph web UI (React/WASM) | P2 | 3 days | — |
| Implement real-time graph rendering with D3.js or similar | P2 | 5 days | Design |
| Add interactive node inspection (click to view verdict, policy, audit) | P2 | 3 days | Graph rendering |
| Implement timeline view for session replay | P2 | 3 days | — |
| Add graph export (PNG, SVG, PDF) | P2 | 1 day | Graph rendering |
| Create graph embedding for external dashboards | P2 | 2 days | — |

#### 22.2 VS Code Extension

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create VS Code extension scaffold (TypeScript) | P2 | 1 day | — |
| Implement policy file syntax highlighting and validation | P2 | 3 days | Scaffold |
| Add inline policy evaluation preview | P2 | 3 days | Syntax highlighting |
| Implement MCP traffic inspector panel | P2 | 3 days | — |
| Add quick-fix suggestions for policy issues | P2 | 2 days | Validation |
| Publish to VS Code Marketplace | P2 | 1 day | All above |

#### 22.3 Policy Playground / Simulator

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create web-based policy simulator | P2 | 4 days | — |
| Implement action builder UI (construct test actions interactively) | P2 | 3 days | Simulator |
| Add policy diff visualization (before/after changes) | P2 | 2 days | — |
| Implement batch evaluation (test policy against historical traffic) | P2 | 3 days | Simulator |
| Create shareable playground links | P2 | 1 day | All above |

#### 22.4 GitHub Action for Policy CI Gate

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create `sentinel-policy-check` GitHub Action | P2 | 2 days | — |
| Implement policy validation with configurable severity thresholds | P2 | 1 day | Action |
| Add policy diff annotation on PRs (changed policies highlighted) | P2 | 2 days | Action |
| Create action marketplace listing | P2 | 1 day | All above |
| Add GitLab CI template equivalent | P2 | 1 day | — |

#### 22.5 SDK Ecosystem Expansion

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Go SDK — client, middleware, policy evaluation | P2 | 2 weeks | — |
| Java SDK — client, Spring Boot starter | P2 | 2 weeks | — |
| TypeScript SDK — client, Express middleware | P2 | 2 weeks | — |
| Update Python SDK with v3.0 features | P2 | 1 week | — |
| Create SDK integration test matrix (cross-language) | P2 | 3 days | All SDKs |

### Phase 22 Exit Criteria
- [ ] Execution graph UI renders real-time agent sessions
- [ ] VS Code extension published with syntax highlighting and validation
- [ ] Policy playground evaluates policies against test actions
- [ ] GitHub Action blocks PRs with invalid policy changes
- [ ] At least Go and TypeScript SDKs published with core functionality

**Estimated Duration:** 8 weeks

---

### Phase 23: Research & Future (P3)

*Focus: Forward-looking capabilities for technical differentiation and long-term competitive moat*

#### 23.1 Multimodal Injection Detection

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Research image-based injection vectors (steganography, OCR-bait) | P3 | 1 week | — |
| Research audio-based injection vectors (speech-to-text manipulation) | P3 | 1 week | — |
| Implement image content analysis pipeline | P3 | 2 weeks | Research |
| Implement audio content analysis pipeline | P3 | 2 weeks | Research |
| Create multimodal injection test suite | P3 | 1 week | Pipelines |

#### 23.2 Continuous Autonomous Red Teaming

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design autonomous red team agent architecture | P3 | 1 week | — |
| Implement attack generation using LLM-based fuzzing | P3 | 2 weeks | Architecture |
| Add policy evasion detection (find policy gaps automatically) | P3 | 2 weeks | Attack generation |
| Create red team report generation | P3 | 1 week | — |
| Implement continuous red team scheduling | P3 | 1 week | All above |

#### 23.3 FIPS 140-3 Compliance Mode

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Evaluate FIPS 140-3 validated Rust crypto libraries (aws-lc-rs) | P3 | 1 week | — |
| Implement FIPS mode flag with algorithm restrictions | P3 | 2 weeks | Evaluation |
| Replace Ed25519 with FIPS-approved alternatives in FIPS mode | P3 | 2 weeks | FIPS mode |
| Create FIPS compliance documentation | P3 | 1 week | Implementation |
| Add FIPS mode CI validation | P3 | 1 week | Documentation |

#### 23.4 Sigstore/Rekor Transparency Log Integration

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement Rekor client for transparency log entries | P3 | 2 weeks | — |
| Add tool signature publication to Rekor | P3 | 1 week | Rekor client |
| Implement Fulcio integration for keyless signing | P3 | 2 weeks | — |
| Add transparency log verification in tool registry | P3 | 1 week | Rekor client |

#### 23.5 Stateful Session Reasoning Guards

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design session reasoning state model | P3 | 1 week | — |
| Implement multi-turn intent tracking with state machine | P3 | 2 weeks | State model |
| Add session-level policy evaluation (policies that span turns) | P3 | 2 weeks | Intent tracking |
| Create session anomaly detection (deviation from expected flow) | P3 | 1 week | — |

### Phase 23 Exit Criteria
- [ ] At least one multimodal injection detection modality working
- [ ] Autonomous red team generates novel attack patterns
- [ ] FIPS 140-3 mode passes basic compliance checks
- [ ] Sigstore integration publishes and verifies tool signatures
- [ ] Session reasoning guards detect multi-turn attack patterns

**Estimated Duration:** 8 weeks (research-driven, scope may adjust)

---

## Competitor Comparison (Updated)

| Feature | Sentinel v3.0 | Cisco AI Defense | Prisma AIRS | Radware | CalypsoAI | Akamai | NeMo Guardrails | Microsoft MCP GW |
|---------|--------------|-----------------|-------------|---------|-----------|--------|-----------------|------------------|
| MCP Native Support | ✅ Full | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Gateway |
| A2A Protocol Support | ✅ Full | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| WebSocket Transport | ✅ Phase 17.1 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| gRPC Transport | ✅ Phase 17.2 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Policy Engine | ✅ Strong | ✅ ML-based | ✅ Strong | ✅ WAF | ✅ Strong | ✅ WAF | ✅ Colang | ⚠️ Basic |
| Injection Detection | ✅ Multi-layer | ✅ ML-based | ✅ ML-based | ✅ Strong | ✅ ML-based | ✅ Strong | ✅ LLM-based | ❌ |
| DLP / Data Loss Prevention | ✅ 8-layer decode | ⚠️ Basic | ✅ Strong | ⚠️ Basic | ✅ Strong | ⚠️ Basic | ⚠️ Basic | ❌ |
| Tamper-Evident Audit | ✅ Hash chain + Merkle | ⚠️ Basic | ✅ Strong | ⚠️ Basic | ✅ Strong | ✅ Strong | ⚠️ Basic | ❌ |
| ETDI Tool Signing | ✅ Ed25519/ECDSA | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Schema Poisoning Detection | ✅ Jaccard | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cross-Agent Security | ✅ Trust graph | ⚠️ Basic | ⚠️ Basic | ❌ | ⚠️ Basic | ❌ | ❌ | ❌ |
| Memory Injection Defense | ✅ Full MINJA | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Semantic Guardrails | ✅ LLM-based | ✅ ML-based | ✅ ML-based | ❌ | ✅ ML-based | ❌ | ✅ Native | ❌ |
| NHI Lifecycle | ✅ Full | ⚠️ Basic | ⚠️ Basic | ❌ | ❌ | ❌ | ❌ | ❌ |
| RAG Poisoning Defense | ✅ Full | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gateway / Multi-Backend | 🔲 Phase 20 | ✅ Native | ✅ Native | ✅ Native | ❌ | ✅ Native | ❌ | ✅ Native |
| ABAC (Cedar-style) | 🔲 Phase 21 | ⚠️ Basic | ✅ Strong | ❌ | ⚠️ Basic | ❌ | ❌ | ❌ |
| EU AI Act Compliance | ✅ Phase 19.1 | ⚠️ Basic | ⚠️ Basic | ❌ | ✅ Strong | ❌ | ❌ | ❌ |
| OpenTelemetry GenAI | ✅ Phase 19 | ❌ | ⚠️ Basic | ❌ | ❌ | ❌ | ❌ | ❌ |
| K8s Native Deployment | 🔲 Phase 20 | ✅ Native | ✅ Native | ✅ Native | ⚠️ Basic | ✅ Native | ❌ | ✅ Native |
| Open Source | ✅ AGPL-3.0 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Apache-2.0 | ✅ MIT |
| Self-Hosted | ✅ Full | ❌ Cloud | ❌ Cloud | ❌ Cloud | ❌ Cloud | ❌ Cloud | ✅ Full | ✅ Full |

**Legend:** ✅ = Implemented | ⚠️ = Partial | ❌ = Not available | 🔲 = Planned

---

## CoSAI / Adversa AI Threat Coverage

### CoSAI MCP Security Whitepaper — 12 Threat Categories

| # | Threat Category | Sentinel Coverage | Gaps |
|---|----------------|-------------------|------|
| 1 | Tool Definition Manipulation | ✅ ETDI signing, schema poisoning, rug-pull detection | — |
| 2 | Prompt Injection via Tool I/O | ✅ Multi-layer injection detection, semantic analysis | — |
| 3 | Unauthorized Data Access | ✅ DLP scanning, path/network rules, DPoP | — |
| 4 | Privilege Escalation | ✅ RBAC, call chain validation, confused deputy prevention | ABAC (Phase 21) |
| 5 | Cross-Agent Attacks | ✅ Trust graph, message signing, shadow agent detection | Federation (Phase 21) |
| 6 | Memory/Context Poisoning | ✅ MINJA defense, taint tracking, quarantine | — |
| 7 | Supply Chain Attacks | ✅ ETDI attestation chain, version pinning, SBOM | Sigstore (Phase 23) |
| 8 | Transport Security | ✅ mTLS, SPIFFE, DPoP, WebSocket, gRPC | — |
| 9 | Denial of Service | ✅ Rate limiting, circuit breaker, resource limits | — |
| 10 | Audit Evasion | ✅ Hash chain, Ed25519 checkpoints, rotation manifests | — |
| 11 | Configuration Attacks | ✅ Config validation, hot reload integrity | — |
| 12 | Compliance Gaps | ✅ MITRE ATLAS, NIST RMF, AIVSS, EU AI Act evidence + Art 50 transparency, SOC 2 evidence, OTLP GenAI export, compliance dashboard | — |

### Adversa AI MCP Security TOP 25

| # | Vulnerability | Sentinel Status |
|---|--------------|----------------|
| 1 | Tool Poisoning | ✅ ETDI + schema poisoning |
| 2 | Rug Pull Attacks | ✅ Rug-pull detection with persistent flagging |
| 3 | Tool Squatting | ✅ Levenshtein + homoglyph detection |
| 4 | Cross-Server Injection | ✅ Injection detection on all MCP messages |
| 5 | Prompt Injection via Parameters | ✅ Parameter-level injection scanning |
| 6 | Data Exfiltration via Tool Output | ✅ DLP on responses, covert channel detection |
| 7 | Schema Manipulation | ✅ Jaccard similarity tracking |
| 8 | Unauthorized Tool Invocation | ✅ Policy engine, RBAC, approval workflow |
| 9 | Privilege Escalation via Delegation | ✅ Call chain validation, deputy checks |
| 10 | Memory Injection (MINJA) | ✅ Taint tracking, provenance, quarantine |
| 11 | Shadow Agent Injection | ✅ Agent fingerprinting, behavior profiling |
| 12 | Context Window Poisoning | ✅ Token security, context budget tracking |
| 13 | Transport Layer Attacks | ✅ mTLS, origin validation, CSRF protection |
| 14 | Replay Attacks | ✅ Nonce-based anti-replay, DPoP |
| 15 | Denial of Service | ✅ Rate limiting, circuit breaker |
| 16 | Configuration Tampering | ✅ Config validation, hot reload integrity |
| 17 | Audit Log Tampering | ✅ SHA-256 hash chain, Ed25519 checkpoints |
| 18 | Side-Channel Exfiltration | ✅ Steganography detection, entropy analysis |
| 19 | Sampling-Based Attacks | ✅ Sampling rate limiting, exfiltration detection |
| 20 | Resource Exhaustion | ✅ Per-tool resource limits, connection pooling |
| 21 | Identity Spoofing | ✅ NHI lifecycle, behavioral attestation |
| 22 | Cascading Failures | ✅ Circuit breaker, failure budget |
| 23 | Goal Manipulation | ✅ Goal tracking, drift detection |
| 24 | Namespace Collision | ✅ Tool namespace registry, collision detection |
| 25 | Workflow Manipulation | ✅ Workflow tracking, step budgets |

**Coverage: 25/25** (all addressed, some strengthened in v3.0 phases)

---

## OWASP ASI Top 10 Coverage (Updated)

| ID | Threat | Sentinel Coverage | v3.0 Enhancement |
|----|--------|-------------------|------------------|
| ASI01 | Prompt Injection | ✅ Multi-layer detection (Aho-Corasick, semantic, Unicode NFKC) | Multimodal detection (Phase 23) |
| ASI02 | Sensitive Data Disclosure | ✅ DLP scanning (8-layer decode), DPoP, Art 50 transparency marking | — |
| ASI03 | Inadequate Sandboxing | ✅ Path/network rules, tool namespace registry | Gateway isolation (Phase 20) |
| ASI04 | Privilege Escalation | ✅ RBAC, call chain, approval flow | ABAC engine (Phase 21) |
| ASI05 | Confused Deputy | ✅ Deputy validation, delegation chains | Federation (Phase 21) |
| ASI06 | Excessive Agency | ✅ Policy engine, least-agency tracking | Least-agency enforcement (Phase 21) |
| ASI07 | Insecure Plugins | ✅ ETDI signing, rug-pull, schema poisoning | Sigstore (Phase 23) |
| ASI08 | Cascading Failures | ✅ Circuit breaker, failure budget | Gateway health routing (Phase 20) |
| ASI09 | Over-reliance on Agent | ✅ Human-in-the-loop approvals, Art 14 human oversight triggers | — |
| ASI10 | Inadequate Monitoring | ✅ Audit logging, security events, exec graphs, OTLP GenAI export | — |

---

## Known CVEs Addressed

| CVE | Description | Sentinel Mitigation |
|-----|-------------|---------------------|
| CVE-2025-68143 | Git MCP Server path traversal | Path normalization (v1.0) |
| CVE-2025-68144 | Git MCP Server arbitrary read | Path rules, DLP (v1.0) |
| CVE-2025-68145 | Git MCP Server secret exposure | DLP scanning (v1.0) |
| CVE-2025-6514 | mcp-remote SSRF | DNS rebinding protection (v1.0) |

---

## MCP Ecosystem Security Gaps Analysis

> **Full analysis:** [`docs/MCP_SECURITY_GAPS.md`](docs/MCP_SECURITY_GAPS.md)
>
> Eight critical, well-defined gaps exist across the MCP security landscape. Only 14% of organizations running agents in production have runtime guardrails (Lakera, Q4 2025). The table below maps each gap to Sentinel's current coverage and planned roadmap work.

| # | Gap | Severity | Sentinel Current Coverage | Roadmap Phase | Status |
|---|-----|----------|--------------------------|---------------|--------|
| 1 | **Formal verification of MCP policy enforcement** | Critical | No formal model exists in any framework (TLA+, Alloy, Lean, Coq). No one has verified safety/liveness/complete mediation for any MCP policy engine. | Phase 23 (Research) | 🔲 Open research question |
| 2 | **Cryptographic audit trails** | Critical | ✅ **Sentinel is the only shipping product combining runtime firewall + cryptographic audit.** SHA-256 hash chains, Ed25519 signed checkpoints, rotation manifests, SIEM export (CEF/JSONL/webhook). **Merkle tree inclusion proofs** with RFC 6962 domain separation, proof generation/verification, crash recovery. | Phase 19.4 ✅ | ✅ Production-ready — Merkle proofs shipped; zk-audit is future work |
| 3 | **Multi-agent delegation / confused deputy** | Critical | ✅ Deputy validation, delegation chains with depth limits, call chain tracking, NHI lifecycle, agent trust graph, Ed25519 message signing. **Capability-based delegation tokens** with monotonic attenuation, grant coverage matching, RequireCapabilityToken policy condition (fail-closed). | Phase 21.0 ✅, Phase 21.1 (ABAC), Phase 21.3 (Federation) | ✅ Runtime enforcement + protocol-level capability tokens shipped; ABAC and federation planned |
| 4 | **MCP supply chain security** | Critical | ✅ ETDI tool signing (Ed25519/ECDSA), attestation chains, version pinning with hash drift detection, rug-pull detection, schema poisoning (Jaccard), tool squatting (Levenshtein + homoglyph), SHA-256 binary verification. | Phase 23.4 (Sigstore/Rekor) | ✅ Runtime enforcement shipped — transparency log integration planned |
| 5 | **Performance benchmarking** | Important | ✅ Criterion benchmarks: 7–31 ns single policy, ~1.2 μs for 100 policies. Sub-5ms P99 claimed. No peer-reviewed publication yet. | — | ⚠️ Internal benchmarks exist; rigorous paper needed (OSDI/NSDI target) |
| 6 | **MCP protocol-level security deficits** | Critical | ✅ Sentinel enforces what the spec leaves advisory: tool pinning (ETDI), namespace isolation (collision detection), annotation tracking (rug-pull alerts), session binding (not in URLs), auth enforcement. | Phases 18–21 | ✅ Application-layer mitigations shipped for all 6 protocol deficits |
| 7 | **Compliance frameworks for agentic AI** | Critical | ✅ MITRE ATLAS (14 techniques), OWASP AIVSS scoring, NIST AI RMF, ISO 27090 readiness. Audit trail with decision context, user attribution, approval chains. **EU AI Act conformity assessment** (Art 5–50, 10 obligations, 18 capability mappings), **Art 50(1) runtime transparency marking**, **Art 14 human oversight triggers**, **SOC 2 evidence generation** (CC1-CC9, 22 criteria, 30 capability mappings), **OTLP export with GenAI semantic conventions**, **compliance dashboard**, **immutable audit archive** with API endpoints. | Phase 19 ✅ | ✅ All Phase 19 exit criteria shipped |
| 8 | **MCP incident tracking infrastructure** | Important | ✅ 4 known CVEs mitigated (CVE-2025-68143/44/45, CVE-2025-6514). Adversa TOP 25: 25/25 addressed. CoSAI 12 categories: all covered. | — | ⚠️ No centralized MCP vulnerability DB exists ecosystem-wide |

### Sentinel's Position Relative to Ecosystem Gaps

**Gaps where Sentinel leads the ecosystem:**
- **Cryptographic audit trail** (#2) — Only shipping product combining runtime firewall + hash-chained audit with Ed25519 signatures
- **Supply chain integrity** (#4) — Most comprehensive runtime enforcement: ETDI signing, attestation chains, version pinning, rug-pull/schema poisoning/squatting detection
- **Protocol deficit mitigations** (#6) — Application-layer enforcement for all 6 spec-level gaps (tool pinning, namespace isolation, annotation enforcement, session binding, auth)
- **Compliance evidence** (#7) — EU AI Act (evidence + Art 50 transparency + Art 14 oversight), SOC 2 (CC1-CC9), OTLP GenAI export, immutable archive, compliance dashboard — all shipped
- **Threat coverage** (#8) — 25/25 Adversa TOP 25, all 12 CoSAI categories, all 10 OWASP ASI threats

**Gaps where Sentinel has partial coverage (roadmap planned):**
- **Multi-agent delegation** (#3) — Runtime enforcement + protocol-level capability tokens shipped; Cedar-style ABAC (Phase 21.1) and federation (Phase 21.3) planned
- **Performance characterization** (#5) — Internal criterion benchmarks exist; rigorous peer-reviewed paper needed

**Gaps that are open research (no one has solved):**
- **Formal verification** (#1) — No formal model of MCP exists in any framework. A TLA+/Alloy specification + Lean/Coq proofs of Sentinel's policy engine would be a first-of-its-kind contribution targeting USENIX Security/CCS/S&P

### Strategic Research Opportunities

The single most impactful research combination: **formal verification of complete mediation + cryptographic audit trail + deterministic performance characterization.** This trifecta — provably correct enforcement, tamper-evident logging, and rigorous latency guarantees — does not exist anywhere. Publishing it would establish the definitive reference implementation for MCP runtime security.

| Opportunity | Target Venue | Difficulty | Timeline |
|-------------|-------------|------------|----------|
| TLA+/Alloy formal model of MCP + verified policy engine properties | USENIX Security, CCS, S&P | High | 12–18 months |
| Capability-based delegation replacing ambient authority | S&P, CCS | High | 12 months |
| Merkle-tree transparency log for agent actions | OSDI, NSDI | Medium | 6–9 months |
| Deterministic vs. probabilistic enforcement benchmarking paper | MLSys, NSDI | Low–Medium | 3–6 months |
| EU AI Act Article 50 compliance evidence generation | Regulatory/policy venue | Medium | 6 months |

### Key External References

| Source | Relevance |
|--------|-----------|
| [Securing the Model Context Protocol](https://arxiv.org/abs/2511.20920) (arXiv, Nov 2025) | Formal verification called out as open research question |
| [VeriGuard](https://arxiv.org/abs/2510.05156) (Google DeepMind, Oct 2025) | Nagini/Viper formal verification of safety policies (not MCP) |
| [31 Formal Properties for Agentic AI](https://arxiv.org/abs/2510.14133) (Allegrini et al., Oct 2025) | CTL/LTL specifications, no model-checking against real systems |
| [AAP: Agent Authorization Profile](https://aap-protocol.org) | Most complete capability delegation spec for agents |
| [Capabilities Are the Only Way](https://niyikiza.dev) (Niyikiza, Dec 2025) | Object-capability theory applied to agent delegation |
| [zk-MCP](https://arxiv.org/abs/2512.14737) (Jing & Qi, Dec 2025) | ZK-SNARK privacy-preserving MCP audit (<4.14% overhead) |
| [Missing Primitives for Trustworthy AI Agents](https://sakurasky.dev) (Stevens, Nov 2025) | Cryptographic audit architecture for agents (design only) |
| [Singapore IMDA Agentic AI Framework](https://www.imda.gov.sg) (v1.0, Jan 2026) | First government governance framework for agentic AI |
| [NIST RFI on AI Agent Security](https://www.nist.gov) (Jan 2026, deadline Mar 9) | Federal interest in agent runtime security standards |
| [MCP-Guard](https://arxiv.org/abs/2508.10991) | Multi-stage MCP guardrails with LLM arbitration (~456ms full pipeline) |
| [Invariant Labs](https://invariantlabs.ai) | Information-flow analyzer for agent traces (ETH Zurich) |
| [ToolHive by Stacklok](https://github.com/stacklok/toolhive) | Sigstore + GitHub Attestations for container provenance |

---

## Research Bibliography

1. **MCP Specification 2025-06-18** — modelcontextprotocol.io
2. **MCP SEP-1288: WebSocket Transport** — github.com/modelcontextprotocol/specification
3. **MCP SEP-1391: Async Operations** — github.com/modelcontextprotocol/specification
4. **Google gRPC Transport for MCP** — cloud.google.com (2026)
5. **EU AI Act (Regulation 2024/1689)** — Official Journal of the European Union
6. **CoSAI MCP Security Whitepaper** — Coalition for Secure AI (2026)
7. **Adversa AI MCP Security TOP 25** — adversa.ai (2026)
8. **OpenTelemetry GenAI Semantic Conventions** — opentelemetry.io (2026)
9. **Microsoft MCP Gateway** — github.com/microsoft/mcp-gateway (2026)
10. **AWS AgentCore** — aws.amazon.com/agentcore (2026)
11. **OWASP Top 10 for Agentic Applications 2026** — genai.owasp.org
12. **OWASP Guide for Securely Using Third-Party MCP Servers** — genai.owasp.org
13. **ETDI: Enhanced Tool Definition Interface** — arxiv:2506.01333 (2025)
14. **MINJA: Memory Injection Attacks on LLM Agents** — Agent Security Bench (2025)
15. **Agentic Trust Framework (ATF)** — CyberArk, Astrix Security (2026)
16. **Enterprise-Grade Security for MCP** — arxiv:2504.08623 (2025)
17. **Runtime Risk to Real-Time Defense** — Microsoft Security Blog (2026)
18. **Kaspersky: Agentic AI Security per OWASP ASI Top 10** — kaspersky.com (2026)
19. **A2A Protocol Specification** — Google (2025)
20. **Privilege Management in MCP** — arxiv:2507.06250 (2025)
21. **NIST Post-Quantum Cryptography Project** — csrc.nist.gov
22. **FIPS 203 (ML-KEM)** — csrc.nist.gov/pubs/fips/203/final
23. **Cedar Policy Language** — cedarpolicy.com (Amazon, 2023)
24. **Sigstore: Software Signing for Everyone** — sigstore.dev
25. **MITRE ATLAS** — atlas.mitre.org
26. **Securing the Model Context Protocol** — arxiv:2511.20920 (2025)
27. **VeriGuard: Formal Verification of Safety Policies** — arxiv:2510.05156, Google DeepMind (2025)
28. **31 Formal Properties for Agentic AI** — arxiv:2510.14133, Allegrini et al. (2025)
29. **AAP: Agent Authorization Profile** — aap-protocol.org (2025)
30. **zk-MCP: Privacy-Preserving Audit** — arxiv:2512.14737, Jing & Qi (2025)
31. **Missing Primitives for Trustworthy AI Agents** — Sakura Sky / Andrew Stevens (2025)
32. **Singapore IMDA Model AI Governance Framework for Agentic AI** — v1.0 (2026)
33. **MCP-Guard: Multi-Stage Guardrails** — arxiv:2508.10991 (2025)
34. **Invariant Labs: Information-Flow Analysis for Agents** — invariantlabs.ai (2024)
35. **ToolHive: Sigstore for MCP Supply Chain** — Stacklok (2025)
36. **Capabilities Are the Only Way to Secure Agent Delegation** — Niyikiza (2025)
37. **Constant-Size Cryptographic Evidence Structures** — arxiv:2511.17118, Codebat Technologies (2025)
38. **OIDC-A 1.0: OpenID Connect for Agents** — Subramanya N (2025)
39. **Lakera Agent Security Report Q4 2025** — lakera.ai (2025)

---

*This roadmap is a living document. Update as standards finalize and priorities shift.*

---

<details>
<summary><h2>Archive: v2.0–v2.2 Completed Phases (1–15)</h2></summary>

> All phases below are **implemented, tested, and hardened** through 35 audit rounds.
> Preserved here for historical reference and traceability.

---

### Phase 1: MCP 2025-11-25 Compliance (Weeks 1-4) ✅ COMPLETE

*Focus: Protocol updates for Async Tasks, Resource Indicators, CIMD*

> **Status:** Implemented in commit `fad480c`. All deliverables complete.

#### 1.1 Async Tasks Security

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

#### 1.2 OAuth Resource Indicators (RFC 8707)

MCP 2025-11-25 requires resource indicator support for OAuth flows.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse resource indicators from OAuth requests | P0 | 1 day | — |
| Validate resource scope against policy | P0 | 2 days | Parsing |
| Add resource indicator to audit context | P0 | 0.5 days | Validation |
| Support multiple resource servers | P1 | 2 days | — |
| Add resource indicator integration tests | P0 | 1 day | All above |

#### 1.3 CIMD (Capability-Indexed Message Dispatch)

New MCP routing mechanism requiring policy enforcement.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse CIMD capability headers | P0 | 1 day | — |
| Define capability-based routing policies | P0 | 2 days | Parsing |
| Implement capability inheritance validation | P1 | 2 days | Policies |
| Add capability attestation verification | P1 | 2 days | — |

#### 1.4 Step-Up Authentication

MCP 2025-11-25 defines step-up auth for sensitive operations.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define step-up auth policy triggers | P1 | 1 day | — |
| Implement auth level tracking per session | P1 | 2 days | Triggers |
| Add step-up challenge/response flow | P1 | 3 days | Tracking |
| Integrate with human-in-the-loop approvals | P1 | 2 days | Challenge flow |

#### Phase 1 Deliverables
- [x] Async task policy enforcement
- [x] OAuth resource indicator validation
- [x] CIMD capability-based routing
- [x] Step-up authentication flow

**Completed:** 2026-02-07

---

### Phase 2: Advanced Threat Detection (Weeks 5-8) ✅ COMPLETE

*Focus: Close gaps identified in CoSAI whitepaper and OWASP ASI Top 10*

> **Status:** Implemented in commit `e4deb2d`. All deliverables complete.

#### 2.1 Shadow Agent Discovery (ASI02)

Detect unauthorized/rogue agents operating in the environment.

**Detection signals:**
- Unknown JWT issuers
- Unusual tool call patterns
- Unregistered client certificates
- Anomalous request origins

#### 2.2 Full Schema Poisoning Detection

Extended rug-pull detection for complete schema replacement attacks.

#### 2.3 Cascading Failure Protection (OWASP ASI08)

Circuit breaker per upstream tool with failure budget tracking.

#### 2.4 Sampling-Based Attack Detection

Rate limiting and exfiltration pattern detection for MCP sampling endpoint.

#### 2.5 Confused Deputy Prevention (ASI05)

Strict principal binding, request origin chain validation, capability-based delegation.

#### Phase 2 Deliverables
- [x] Shadow agent detection and alerting
- [x] Full schema poisoning detection
- [x] Circuit breaker with cascade protection
- [x] Sampling attack detection
- [x] Confused deputy prevention

**Completed:** 2026-02-07

---

### Phase 3.1: Runtime Integration (Week 9) ✅ COMPLETE

*Focus: Wire Phase 1 & 2 security modules into runtime enforcement*

> **Status:** Implemented in commits `05364be` and `7a3c52d`. All deliverables complete.

- [x] ProxyBridge manager integration
- [x] Enforcement calls at request evaluation points
- [x] AppState manager fields for sentinel-server
- [x] Admin API endpoints (25+ routes)
- [x] Audit event generation helpers
- [x] HTTP proxy integration with circuit breaker

**Completed:** 2026-02-08

---

### Phase 3.2: Cross-Agent Security (Week 10) ✅ COMPLETE

*Focus: Multi-agent trust relationships, message signing, privilege escalation detection*

> **Status:** Implemented in commit `a043b17`. All deliverables complete.

- [x] Agent trust graph with privilege levels
- [x] Ed25519 message signing with anti-replay
- [x] Second-order prompt injection detection
- [x] Unicode and delimiter injection detection
- [x] CrossAgentConfig with full validation

**Completed:** 2026-02-08

---

### Phase 3.3: Advanced Threat Detection (Week 11) ✅ COMPLETE

*Focus: Goal tracking, workflow monitoring, namespace security, covert channel detection*

> **Status:** Implemented in commit `7cc3232`. All deliverables complete.

- [x] Goal state tracking with drift detection
- [x] Workflow intent tracking with step budgets
- [x] Tool namespace security with collision detection
- [x] Output security with steganography and entropy analysis
- [x] Token security with smuggling and flooding detection
- [x] AdvancedThreatConfig with full validation

**Completed:** 2026-02-08

---

### Phase 4.1: Standards Alignment (Weeks 12-14) ✅ COMPLETE

*Focus: MITRE ATLAS, OWASP AIVSS, NIST alignment*

> **Status:** Implemented in commit `8f6a78c`. All deliverables complete.

- [x] MITRE ATLAS threat mapping (14 techniques, 30+ detection mappings)
- [x] AIVSS severity scoring with AI multipliers
- [x] NIST AI RMF compliance documentation and reports
- [x] ISO 27090 readiness assessment with gap analysis

**Completed:** 2026-02-08

---

### Phase 5: Enterprise Hardening - Configuration (Weeks 15-16) ✅ COMPLETE

*Focus: Configuration layer for mTLS, OPA, threat intelligence, JIT access*

> **Status:** Configuration types implemented in commit `fc8da13`.

- [x] TlsConfig with mTLS mode and revocation options
- [x] SpiffeConfig with trust domain and ID mapping
- [x] OpaConfig with caching and fail-open mode
- [x] ThreatIntelConfig with TAXII/MISP/Custom providers
- [x] JitAccessConfig with TTL and approval settings
- [x] Validation for all configuration parameters

**Completed:** 2026-02-08

---

### Phase 5.5: Enterprise Hardening - Runtime (Weeks 17-18) ✅ COMPLETE

*Focus: Runtime implementation of enterprise features*

> **Status:** Core runtime components implemented. OPA request-path decision enforcement active.

- [x] TLS termination with client cert extraction
- [x] SPIFFE ID extraction from X.509 SAN URIs
- [x] OPA client with LRU caching and fail modes
- [x] OPA request-path decision enforcement wiring
- [x] Threat intelligence clients (TAXII, MISP, Custom)
- [x] JIT session management with approval workflow

**Updated:** 2026-02-10

---

### Phase 6: Observability & Tooling (Weeks 19-20) ✅ COMPLETE

*Focus: Execution graphs, CI/CD integration, red-teaming*

- [x] Execution graph visualization (DOT/JSON export, API endpoints)
- [x] Red-team automation framework (40+ attacks, OWASP ASI alignment)
- [x] Policy validation CLI with `--strict`, `--format` options

---

### Phase 7: Documentation & Release (Week 21-22) ✅ COMPLETE

> **Status:** v2.0.0 released.

- [x] `docs/THREAT_MODEL.md` — OWASP ASI Top 10, MITRE ATLAS
- [x] `docs/MIGRATION.md` — v1.x to v2.0 upgrade guide
- [x] `docs/API.md` — All endpoints documented
- [x] All 12 crates bumped to version 2.0.0

---

### Phase 8: ETDI & Cryptographic Tool Security (v2.1) ✅ COMPLETE

*Focus: Enhanced Tool Definition Interface for cryptographic tool attestation*

> **Status:** Implemented in commit `c9590d6`.

- [x] Ed25519/ECDSA tool signature verification
- [x] Attestation chain with provenance tracking
- [x] Tool signing CLI (`sentinel generate-key`, `sign-tool`, `verify-signature`)
- [x] Version pinning with semantic versioning
- [x] ETDI persistent store with HMAC protection
- [x] SPIFFE workload identity trust

**Completed:** 2026-02-08

---

### Phase 9: Memory Injection Defense (v2.1) ✅ COMPLETE

*Focus: Comprehensive defense against MINJA attacks*

- [x] Taint propagation for memory tracking
- [x] Memory provenance graph with trust decay
- [x] Integrity verification on retrieval
- [x] Per-agent memory isolation
- [x] Memory access control policies

**Completed:** 2026-02-09

---

### Phase 10: Non-Human Identity (NHI) Lifecycle (v2.1) ✅ COMPLETE

*Focus: Agentic Trust Framework for zero-trust agent identity*

- [x] Agent identity lifecycle (register, rotate, revoke)
- [x] Behavioral attestation with continuous auth
- [x] Enhanced delegation chains for NHI
- [x] DPoP (RFC 9449) support
- [x] 16 REST API endpoints, 28 integration tests

**Completed:** 2026-02-09

---

### Phase 11: MCP Tasks Primitive (v2.1) ✅ COMPLETE

*Focus: Security for the MCP Tasks primitive*

- [x] Task state encryption (ChaCha20-Poly1305)
- [x] Resume token authentication (HMAC-SHA256)
- [x] Task state hash chain (SHA-256)
- [x] Checkpoint verification (Ed25519 signatures)
- [x] Replay protection (nonce tracking)

**Completed:** 2026-02-09

---

### Phase 12: Semantic Guardrails (v2.2) ✅ COMPLETE

*Focus: LLM-based guardrails for nuanced policy enforcement*

> **Status:** Implemented in commit `a56b3a8`.

- [x] LLM evaluator interface with pluggable backends
- [x] Intent classification with confidence thresholds
- [x] Intent chain tracking for suspicious pattern detection
- [x] Natural language policy definitions with glob matching
- [x] Jailbreak detection with configurable thresholds
- [x] LRU + TTL evaluation cache

**Completed:** 2026-02-09

---

### Phase 13: RAG Poisoning Defense (v2.2) ✅ COMPLETE

*Focus: Protect retrieval-augmented generation from data poisoning*

> **Status:** Implemented in commit `90541df`.

- [x] Document provenance and trust scoring
- [x] Retrieval result inspection
- [x] Embedding anomaly detection
- [x] Context window budget enforcement
- [x] 58 unit tests

**Completed:** 2026-02-09

---

### Phase 14: A2A Protocol Security (v2.2) ✅ COMPLETE

*Focus: Security for Google's Agent-to-Agent protocol*

- [x] A2A protocol support with message classification
- [x] A2A policy evaluation via PolicyEngine
- [x] Agent card handling with caching
- [x] A2A proxy service with security integration
- [x] 58 unit tests

**Completed:** 2026-02-09

---

### Phase 15: Observability Platform Integration (v2.2) ✅ COMPLETE

*Focus: Deep integration with AI observability platforms*

- [x] Arize, Langfuse, Helicone integrations
- [x] Full request/response capture
- [x] Trace sampling and filtering
- [x] External span correlation

**Completed:** 2026-02-10

---

### Previously Active Tracks (v2.2)

**Architecture Split (16.6):** Server route modularization complete. HTTP proxy split into 8 submodules.

**Post-Quantum Cryptography (16.7):** `tls.kex_policy` config, KEX enforcement, TLS metadata telemetry, outbound TLS standardization, quantum migration runbook published.

**CI Supply-Chain Hardening (16.8):** Dependency review, Dependabot, cargo-deny, SHA-pinned actions, build provenance, SBOM publishing — all delivered.

**Sender-Constrained OAuth (16.9):** DPoP enforcement in HTTP proxy, RFC 9449 validation, replay/mismatch tests, audit events — all delivered.

</details>
