# Vellaveto Roadmap v4.0

> **Version:** 4.0.0
> **Generated:** 2026-02-17
> **Baseline:** v3.0.0 — 4,812 Rust tests, 130 Python SDK tests, 28 Go SDK tests, 15 TypeScript SDK tests, 22 fuzz targets, 11 CI workflows, 38 audit rounds, 23 phases complete
> **Current:** 6,292 Rust tests, 316 Python SDK tests, 40 Go SDK tests, 64 TypeScript SDK tests, 24 fuzz targets, 11 CI workflows (15 jobs), 51 audit rounds (all P0-P3 resolved), 40 phases complete
> **Scope:** 12 months (Q2 2026 – Q1 2027), quarterly milestones
> **Status:** v3.0 shipped; Phases 24–35 + 37–40 complete

---

## Executive Summary

Vellaveto v3.0 established the most comprehensive MCP runtime security engine in the market: full MCP 2025-11-25 compliance, three transport layers (HTTP/WebSocket/gRPC), Cedar-style ABAC, EU AI Act evidence generation, CoSAI and Adversa TOP 25 threat mapping (38/38 and 25/25 respectively; see `vellaveto-audit` for coverage matrix), cryptographic audit trails with Merkle proofs, capability-based delegation tokens, and multimodal injection detection. The rebrand from Sentinel to Vellaveto marks the transition from a research prototype to an enterprise product.

The v4.0 roadmap addresses five strategic imperatives:

1. **Regulatory hard deadline:** EU AI Act enforcement on August 2, 2026 requires closing the remaining Art 50(2) automated decision explanations and Art 10 data governance gaps.
2. **Production readiness:** Kubernetes-native deployment (deferred Phase 20.4), cross-transport fallback, and distributed tracing are table-stakes for enterprise adoption.
3. **Market positioning:** 88% of organizations report AI agent security incidents, but only 14.4% have full security approval for their agents. Shadow AI detection, governance visibility, and the OWASP Least Agency principle are the demand signals.
4. **Technical moat:** Formal verification (TLA+/Alloy) and zero-knowledge audit trails (zk-SNARK) are open research questions where first-mover advantage is durable.
5. **Competitive defense:** MintMCP (SOC 2 focus), TrueFoundry (sub-3ms latency claims), Lunar.dev MCPX, Microsoft MCP Gateway (K8s-native), and AWS AgentCore are all entering the space.

### Research Sources

| Source | Relevance |
|--------|-----------|
| [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Current baseline spec |
| [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | Prohibited practices: 2 Feb 2025; GPAI: 2 Aug 2025; full roll-out: 2 Aug 2027 |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Least agency principle |
| [Lakera Agent Security Report Q4 2025](https://www.lakera.ai) | 88% incident rate, 14.4% approval rate |
| [Gravitee State of AI Agent Security 2026](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control) | Enterprise security gaps |
| [zk-MCP: Privacy-Preserving Audit](https://arxiv.org/abs/2512.14737) | Phase 37 zk-SNARK reference |
| [Securing the Model Context Protocol](https://arxiv.org/abs/2511.20920) | Formal verification gap |
| [31 Formal Properties for Agentic AI](https://arxiv.org/abs/2510.14133) | CTL/LTL specifications |
| [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | Post-quantum key encapsulation |
| [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) | Post-quantum digital signatures |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | K8s-native competitor |
| [AWS AgentCore](https://aws.amazon.com/agentcore) | Managed agent runtime competitor |
| [MintMCP](https://mintmcp.com) | SOC 2 Type II competitor |
| [TrueFoundry MCP Gateway](https://www.truefoundry.com) | Sub-3ms latency competitor |
| [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Phase 28 tracing ✅ |
| [AAP: Agent Authorization Profile](https://aap-protocol.org) | Phase 39 federation reference |
| [CoSAI MCP Security Whitepaper](https://www.cosai.owasp.org/) | Threat coverage baseline |
| [Adversa AI MCP Security TOP 25](https://adversa.ai/mcp-security-top-25/) | Vulnerability catalog |
| [Singapore IMDA Agentic AI Framework v1.0](https://www.imda.gov.sg) | Governance reference |
| [Cedar Policy Language](https://www.cedarpolicy.com) | ABAC reference |

---

## Priority Matrix

| Priority | Theme | Business Driver | Deadline Pressure |
|----------|-------|-----------------|-------------------|
| **P0** | EU AI Act compliance gaps + MCP 2026 spec | Hard regulatory deadline Aug 2, 2026; spec compliance | Q2–Q3 2026 |
| **P1** | Kubernetes + Observability + SOC 2 + Federation | Enterprise deployment readiness, sales pipeline | H2 2026 |
| **P2** | Developer experience + SDK ecosystem | Adoption velocity, community growth | Q4 2026 |
| **P3** | Research: formal verification, zk-audit, PQC | Technical differentiation, academic credibility | Rolling 12 months |

---

## Timeline Overview

```
Q2 2026 (Apr–Jun):  Phase 24 — EU AI Act Final Compliance             [P0]
                     Phase 25 — MCP June 2026 Spec Adoption            [P0]
                     Phase 26 — Shadow AI & Governance Visibility       [P1]

Q3 2026 (Jul–Sep):  Phase 27 — Kubernetes-Native Deployment            [P1] ✅
                     Phase 28 — Distributed Tracing & Observability     [P1] ✅
                     Phase 29 — Cross-Transport Smart Fallback          [P1] ✅

Q3–Q4 2026:          Phase 34 — Tool Discovery Service                  [P1] ✅
                     Phase 35 — Model Projector                         [P1] ✅

Q4 2026 (Oct–Dec):  Phase 36 — Developer Experience & SDKs             [P2]
                     Phase 37 — Zero-Knowledge Audit Trails             [P3] ✅
                     Phase 38 — SOC 2 Type II Access Reviews            [P1] ✅

Q1 2027 (Jan–Mar):  Phase 39 — Agent Identity Federation               [P1] ✅
                     Phase 40 — Workflow-Level Policy Constraints        [P1] ✅
                     Phase 41 — Post-Quantum Cryptography Migration     [P3]
                     Phase 42 — Performance Benchmarking Paper          [P3]
```

---

## Q2 2026 (Apr–Jun): Regulatory & Protocol Compliance

### Phase 24: EU AI Act Final Compliance (P0)

*Focus: Close remaining Art 50(2) and Art 10 gaps before the August 2, 2026 enforcement deadline*

The v3.0 implementation covers Art 50(1) runtime transparency marking (`mark_ai_mediated()` in `vellaveto-mcp/src/transparency.rs`), Art 14 human oversight triggers, Art 12 tamper-evident logging, and Art 43 conformity assessment. Two gaps remain:

1. **Art 50(2) — Automated decision explanations**: per-verdict structured explanations
2. **Art 10 — Data governance record keeping**: data provenance and classification tracking

#### 24.1 Art 50(2) Automated Decision Explanations

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `VerdictExplanation` type with reason chain, contributing policies, and confidence | P0 | 2 days | — | `vellaveto-types` |
| Implement `explain_verdict()` in PolicyEngine producing structured explanation alongside each Verdict | P0 | 4 days | VerdictExplanation type | `vellaveto-engine` |
| Add ABAC explanation support: which attributes matched, which conditions triggered | P0 | 2 days | explain_verdict | `vellaveto-engine` |
| Inject `_meta.vellaveto_decision_explanation` into tool-call responses (extending `mark_ai_mediated()`) | P0 | 2 days | explain_verdict | `vellaveto-mcp` |
| Add `explanation_verbosity` config: `none`, `summary`, `full` | P0 | 1 day | — | `vellaveto-config` |
| Update EU AI Act registry: Art 50(2) status from Partial to Compliant | P0 | 1 day | All above | `vellaveto-audit` |
| Integration tests: explanation present in HTTP/WS/gRPC responses | P0 | 2 days | All above | `vellaveto-integration` |

**Configuration:**
```toml
[compliance.eu_ai_act]
explanation_verbosity = "summary"  # none | summary | full
```

#### 24.2 Art 10 Data Governance Record Keeping

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `DataGovernanceRecord` type: data source, classification, retention, lineage | P0 | 2 days | — | `vellaveto-types` |
| Define `DataGovernanceConfig` with required fields per Art 10 | P0 | 1 day | Type | `vellaveto-config` |
| Implement `DataGovernanceRegistry` mapping tool inputs/outputs to data classifications | P0 | 3 days | Config | `vellaveto-audit` |
| Add data provenance tracking in audit entries: source, classification, processing purpose | P0 | 2 days | Registry | `vellaveto-audit` |
| API endpoint: `GET /api/compliance/data-governance` | P0 | 1 day | Registry | `vellaveto-server` |
| Update gap analysis: Art 10 coverage | P0 | 1 day | All above | `vellaveto-audit` |

### Phase 24 Exit Criteria
- [ ] Art 50(2): Every Deny verdict includes a machine-readable explanation
- [ ] Art 50(2): Explanation verbosity configurable (none/summary/full)
- [ ] Art 10: Data governance registry covers all tool data flows
- [ ] Art 10: `GET /api/compliance/data-governance` returns current records
- [ ] EU AI Act conformity assessment achieves target article coverage for Art 9, 13-15, 26
- [ ] All existing tests continue passing
- [ ] No new `unwrap()` in library code

**Estimated Duration:** 4 weeks

---

### Phase 25: MCP June 2026 Spec Adoption (P0)

*Focus: Adopt final MCP June 2026 specification changes and extend multimodal content support*

The current codebase has a `2026-06` placeholder in `SUPPORTED_PROTOCOL_VERSIONS` (Phase 18). This phase fills in actual spec requirements once published.

#### 25.1 Spec Delta Analysis and Implementation

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Analyze June 2026 spec diff against 2025-11-25 implementation | P0 | 3 days | Spec publication |
| Implement new required protocol features (TBD based on spec) | P0 | 5–10 days | Analysis |
| Update `classify_message()` in all transports for new message types | P0 | 3 days | Implementation |
| Update protocol version negotiation | P0 | 1 day | Implementation |
| Ensure backward compatibility with 2025-11-25 and earlier clients | P0 | 2 days | Version negotiation |

#### 25.2 MCP Multimodal Content Support

The MCP 2026 spec is expected to formalize multimodal content handling (images, video, audio). The existing Phase 23.1 multimodal injection detection (`vellaveto-mcp/src/inspection/multimodal.rs`) handles PNG/JPEG/PDF but needs extension.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Extend multimodal inspection for audio content (WAV/MP3 metadata extraction) | P0 | 3 days | — |
| Extend multimodal inspection for video content (MP4 metadata, subtitle injection) | P0 | 3 days | — |
| Add multimodal content size limits and type enforcement policies | P0 | 2 days | — |
| Add multimodal content policy configuration | P0 | 1 day | — |
| Fuzz targets for new content types | P0 | 2 days | Implementation |

### Phase 25 Exit Criteria
- [ ] Full compliance with MCP June 2026 specification (all required features)
- [ ] Backward compatibility with 2025-11-25, 2025-06-18, and 2025-03-26 verified
- [ ] Multimodal content inspection covers audio and video formats
- [ ] At least 2 new fuzz targets for multimodal content

**Estimated Duration:** 4–6 weeks (timing depends on spec publication date)

---

### Phase 26: Shadow AI Detection & Governance Visibility (P1)

*Focus: Enterprise-wide agent governance, shadow AI discovery, and OWASP Least Agency enforcement*

88% of organizations report AI agent security incidents. Only 14.4% of agents get full security approval (Lakera Q4 2025). Shadow AI — agents deployed without security team knowledge — is the primary governance gap.

#### 26.1 Shadow AI Discovery Engine

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `ShadowAiDiscovery` types: unregistered agents, unapproved tools, unknown MCP servers | P1 | 2 days | — | `vellaveto-types` |
| Implement passive discovery: identify unregistered agents from traffic patterns | P1 | 3 days | Types | `vellaveto-mcp` |
| Implement active discovery: scan for MCP servers on network segments | P1 | 3 days | Types | `vellaveto-mcp` |
| Define governance policy: `governance.require_agent_registration = true` | P1 | 1 day | — | `vellaveto-config` |
| Dashboard: shadow AI inventory with risk scoring | P1 | 2 days | Discovery | `vellaveto-server` |
| API: `GET /api/governance/shadow-agents` | P1 | 1 day | Discovery | `vellaveto-server` |

#### 26.2 Least Agency Enforcement (OWASP ASI 2026 Core Theme)

The existing `LeastAgencyTracker` in `vellaveto-engine/src/least_agency.rs` provides per-session usage tracking with a 4-tier recommendation system. This phase moves from recommendation to enforcement.

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Add enforcement mode to `LeastAgencyConfig`: `monitor` vs `enforce` | P1 | 1 day | — | `vellaveto-config` |
| In `enforce` mode, auto-revoke unused permissions after configurable window | P1 | 3 days | Config | `vellaveto-engine` |
| Generate `LeastAgencyReport` as audit events (not just on-demand API) | P1 | 2 days | — | `vellaveto-audit` |
| Wire enforcement into proxy transports (deny tools that exceed grant scope) | P1 | 2 days | Enforcement | `vellaveto-http-proxy` |
| Dashboard: per-agent usage ratio visualization | P1 | 1 day | Reports | `vellaveto-server` |

### Phase 26 Exit Criteria
- [ ] Shadow AI discovery detects unregistered agents from traffic within 5 minutes
- [ ] Governance dashboard shows agent inventory with registration status
- [ ] Least agency enforcement mode auto-narrows permissions for over-privileged sessions
- [ ] Least agency reports emitted as audit events for SIEM integration

**Estimated Duration:** 4 weeks

---

## Q3 2026 (Jul–Sep): Production Infrastructure

### Phase 27: Kubernetes-Native Deployment (P1) — COMPLETE

*Focus: Production-grade K8s deployment with StatefulSet, leader election, and service discovery*

**Delivered:** `LeaderElection` trait + `LocalLeaderElection` (always-leader standalone), `ServiceDiscovery` trait + `StaticServiceDiscovery` + `DnsServiceDiscovery` (tokio `lookup_host` + periodic watch), `DeploymentConfig` with validation, `GET /api/deployment/info` endpoint, health endpoint extended with `leader_status`/`instance_id`/`discovered_endpoints`, Helm chart v4.0.0 (StatefulSet + PVC + init container + log-shipping sidecar + headless Service + gRPC/WebSocket support), deployment audit event helpers. ~45 tests.

### Phase 27 Exit Criteria
- [x] Helm chart passes `helm lint` and deploys to kind cluster
- [x] StatefulSet with PVC maintains audit log across pod restarts
- [x] Leader election trait with local implementation (K8s lease deferred to Phase 27b)
- [x] Service discovery detects endpoints via DNS and static config
- [x] Gateway mode routes requests across backends with health checks
- [x] Health endpoint includes leader/instance/discovery status

---

### Phase 28: Distributed Tracing & Observability (P1) — COMPLETE

*Focus: Multi-agent trace context propagation across all transports*

**Delivered:** W3C Trace Context (`traceparent`/`tracestate`) propagation across HTTP, WebSocket, gRPC, and A2A transports. `TraceContext` parsing with strict validation, child span generation, verdict injection into tracestate. Gateway mode creates per-backend child spans. GenAI semantic convention attributes (`gen_ai.agent.id`) on security spans. gRPC metadata propagation, A2A message metadata extraction. Fail-open for tracing. Compatible with Jaeger, Grafana Tempo, Datadog, and any OTLP collector. Grafana dashboards deferred to Phase 28b.

### Phase 28 Exit Criteria
- [x] W3C trace context propagated across HTTP, WebSocket, and gRPC transports
- [x] Cross-gateway traces with agent identity attributes
- [ ] 4 Grafana dashboard templates published in `helm/vellaveto/dashboards/` (deferred to Phase 28b)
- [x] `gen_ai.agent.*` attributes present on all exported spans

---

### Phase 29: Cross-Transport Smart Fallback (P1) — COMPLETE

*Focus: Ordered transport fallback chain with per-transport circuit breakers*

**Delivered:** Ordered transport fallback (gRPC → WebSocket → HTTP → stdio) with per-transport circuit breakers (Closed/Open/HalfOpen + exponential backoff). Transport priority resolution (per-tool glob overrides → client header → config → default). Audit trail of fallback negotiations via `FallbackNegotiationHistory`. Default off (`cross_transport_fallback: false`). 71 new tests.

### Phase 29 Exit Criteria
- [x] Fallback chain gRPC → WebSocket → HTTP works end-to-end
- [x] Transport-level circuit breaker prevents repeated attempts to failed transports
- [x] Fallback attempts audited with transport used and attempt count
- [x] P99 fallback latency < 500ms (total, not per-attempt)

**Estimated Duration:** 3 weeks

---

### Phase 34: Tool Discovery Service (P1) — COMPLETE

*Focus: Natural language tool search across MCP servers with session-scoped TTL lifecycle*

**Delivered:** Pure Rust TF-IDF inverted index with cosine similarity scoring (zero new dependencies). `DiscoveryEngine` with policy filtering closure, configurable token budget, and `min_relevance_score` cutoff. Auto-indexing from `tools/list` responses via `ingest_tools_list()`. Session-scoped TTL lifecycle: `record_discovered_tools()`, `is_tool_discovery_expired()`, `mark_tool_used()`, `evict_expired_discoveries()`. REST API: `POST /api/discovery/search`, `GET /api/discovery/index/stats`, `POST /api/discovery/reindex`, `GET /api/discovery/tools` (with server_id/sensitivity filters). SDK methods in Python (sync+async), TypeScript, and Go. Feature-gated behind `discovery`. ~260 new tests.

### Phase 34 Exit Criteria
- [x] TF-IDF index ingests tools from MCP `tools/list` responses
- [x] Natural language search returns ranked results with relevance scores
- [x] Policy filtering closure excludes unauthorized tools from results
- [x] Token budget enforcement caps total schema tokens in results
- [x] Session-scoped TTL lifecycle (discover → use → expire → re-discover)
- [x] REST API with input validation (query length, control chars, sensitivity enum)
- [x] SDK methods in Python, TypeScript, and Go
- [x] Feature-gated: zero cost when disabled

---

### Phase 35: Model Projector (P1) — COMPLETE

*Focus: Model-agnostic tool schema projection with compression and call repair*

**Delivered:** `ModelProjection` trait with `ProjectorRegistry` (RwLock-based concurrent access). 5 built-in projections: Claude (Anthropic `tool_use` format with `cache_control` hints), OpenAI (`functions` array format with JSON string argument parsing), DeepSeek (first-sentence truncation, `<think>` block stripping, markdown code block extraction), Qwen (200-char CJK-aware truncation), Generic (passthrough with flexible field names). `SchemaCompressor` with 5 progressive strategies: strip redundant root `"type": "object"`, inline single-value enums, truncate descriptions to first sentence, collapse single-property nested objects, remove optional parameter descriptions. `CallRepairer` with type coercion (string→number/boolean), missing-required-field default injection, Levenshtein fuzzy tool name matching, DeepSeek markdown extraction. REST API: `GET /api/projector/models`, `POST /api/projector/transform`. Audit helper: `log_projector_event()`. Feature-gated behind `projector`. ~230 new tests.

### Phase 35 Exit Criteria
- [x] `ModelProjection` trait with 5 built-in implementations (Claude, OpenAI, DeepSeek, Qwen, Generic)
- [x] `ProjectorRegistry` with concurrent registration and lookup
- [x] Schema compression reduces token cost with 5 progressive strategies
- [x] Call repair handles type coercion, default injection, and fuzzy name matching
- [x] REST API for model listing and manual schema projection
- [x] Feature-gated: zero cost when disabled

---

## Q4 2026 (Oct–Dec): Developer Experience & Enterprise

### Phase 36: Developer Experience & SDK Ecosystem (P2)

*Focus: IDE integration, Java SDK, and visual policy execution tools*

**Deferred from v3.0 Phase 22**

#### 36.1 VS Code Extension

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Policy file syntax highlighting (TOML with Vellaveto schema) | P2 | 2 days | — |
| Inline policy validation (calls `vellaveto check` LSP-style) | P2 | 3 days | Highlighting |
| Verdict visualization in test explorer | P2 | 3 days | Validation |
| Policy playground panel (simulate against sample actions) | P2 | 3 days | — |
| Publish to VS Code Marketplace | P2 | 1 day | All above |

#### 36.2 Java SDK

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| HTTP client using `java.net.http.HttpClient` (Java 11+) | P2 | 3 days | — |
| Full API parity with Python/TypeScript/Go SDKs | P2 | 2 days | Client |
| Typed errors (`VellavetoException`, `PolicyDeniedException`, `ApprovalRequiredException`) | P2 | 1 day | Client |
| Maven Central publishing with javadoc | P2 | 2 days | Implementation |
| JUnit 5 tests (target 30+ tests) | P2 | 2 days | Implementation |

#### 36.3 React/WASM Execution Graph UI

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| React SPA: execution graph visualization (D3.js force-directed graph) | P2 | 5 days | — |
| WASM compilation of `vellaveto-engine` for client-side policy simulation | P2 | 3 days | — |
| Real-time verdict stream via WebSocket subscription | P2 | 2 days | — |
| Policy diff visualization (before/after comparison) | P2 | 2 days | — |
| Embed in dashboard route or serve as standalone SPA | P2 | 1 day | All above |

### Phase 36 Exit Criteria
- [ ] VS Code extension published to Marketplace with policy validation
- [ ] Java SDK published to Maven Central with 30+ tests
- [ ] Execution graph UI renders live verdict flows
- [ ] WASM build of policy engine evaluates in-browser

**Estimated Duration:** 6 weeks

---

### Phase 38: SOC 2 Type II Access Review Reports (P1) — COMPLETE

*Focus: Automated access review report generation for SOC 2 auditors*

**Delivered:** Dynamic report generation scanning audit entries and cross-referencing with `LeastAgencyTracker` data. 7 new types in `vellaveto-types` (`AttestationStatus`, `ReviewerAttestation`, `AccessReviewEntry`, `Cc6Evidence`, `AccessReviewReport`, `ReviewSchedule`, `ReportExportFormat`). `Soc2AccessReviewConfig` with schedule (Daily/Weekly/Monthly), period bounds (1–366 days), reviewer validation (max 50, 256-char names, no control chars). `generate_access_review()` in `vellaveto-audit/src/access_review.rs` with memory bounds (1M entries, 10K agents), deterministic BTreeMap ordering, CC6 evidence by recommendation tier (Optimal/ReviewGrants/NarrowScope/Critical). Self-contained HTML renderer with escaped user data. `GET /api/compliance/soc2/access-review` with period/format/agent_id params (JSON or HTML output). Scheduled report generation via tokio interval task (Daily=86400s, Weekly=604800s, Monthly=2592000s). SDK methods: Python (sync+async `soc2_access_review()`), TypeScript (`soc2AccessReview()`), Go (`Soc2AccessReview()`). ~75 new tests across Rust + SDKs.

### Phase 38 Exit Criteria
- [x] Access review reports generated for configurable time periods
- [x] Reports include: agent identity, permissions granted, permissions used, usage ratio
- [x] Reports include: reviewer attestation fields for SOC 2 auditor sign-off
- [x] `GET /api/compliance/soc2/access-review` returns structured JSON

---

### Phase 39: Agent Identity Federation (P1)

*Focus: Runtime JWKS resolution, cross-organization ABAC evaluation, and identity mapping*

The existing federation types in `vellaveto-types/src/abac.rs` (`FederationTrustAnchor`, `IdentityMapping`) and config in `vellaveto-config/src/abac.rs` (`FederationConfig`) provide the foundation. This phase implements runtime federation.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement JWKS endpoint resolution from `FederationTrustAnchor.jwks_uri` | P1 | 3 days | — |
| Implement JWT claim mapping via `IdentityMapping.id_template` | P1 | 2 days | JWKS |
| LRU cache for JWKS key sets (configurable TTL) | P1 | 1 day | Resolution |
| Cross-org trust level propagation through ABAC engine | P1 | 3 days | Mapping |
| Federation trust dashboard: registered orgs, active mappings, trust levels | P1 | 2 days | — |
| API: `POST /api/federation/trust-anchors`, `GET /api/federation/status` | P1 | 2 days | Implementation |
| Integration tests: agents from org-A evaluated against org-B policies | P1 | 2 days | All above |

### Phase 39 Exit Criteria
- [ ] JWKS resolution from 2+ external issuers working
- [ ] JWT claims from federated identity mapped to internal ABAC principals
- [ ] Cross-organization tool call evaluated correctly through ABAC
- [ ] Federation status visible in dashboard

**Estimated Duration:** 4 weeks

---

## Q1 2027 (Jan–Mar): Research & Future-Proofing

### Phase 33: Formal Verification (TLA+/Alloy) (P3) — COMPLETE

*Focus: First formal model of MCP policy enforcement — a first-of-its-kind contribution*

**Delivered:** TLA+ specs for policy engine (6 safety + 2 liveness) and ABAC forbid-overrides (4 safety). Alloy model for capability delegation (6 safety assertions). 19 verified properties with source traceability. First formal model of MCP policy enforcement in any framework.

#### 33.1 TLA+ Specification of MCP Policy Engine

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| TLA+ specification of MCP client-server interaction model | P3 | 10 days | — |
| TLA+ specification of PolicyEngine evaluation semantics | P3 | 10 days | Interaction model |
| Model-check safety properties: complete mediation, fail-closed, no-bypass | P3 | 5 days | Specifications |
| Model-check liveness properties: every request gets a verdict | P3 | 3 days | Specifications |
| TLA+ specification of ABAC forbid-overrides semantics | P3 | 5 days | PolicyEngine spec |

#### 33.2 Alloy Specification of Capability Delegation

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Alloy model of capability token delegation chains | P3 | 5 days | — |
| Verify monotonic attenuation: no child token escalates parent grants | P3 | 3 days | Model |
| Verify depth budget: delegation chains bounded by MAX_DELEGATION_DEPTH=16 | P3 | 2 days | Model |
| Alloy counterexample analysis: find edge cases in current implementation | P3 | 3 days | Verification |

#### 33.3 Academic Publication

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Draft paper: "Formally Verified Policy Enforcement for MCP Agent Tool Calls" | P3 | 15 days | TLA+ and Alloy |
| Target venue: USENIX Security 2027 or ACM CCS 2027 | P3 | — | Draft |
| Open-source all specifications under Apache-2.0 in `formal/` directory | P3 | 1 day | Paper |

### Phase 33 Exit Criteria
- [ ] TLA+ specification of MCP policy engine model-checks successfully (zero violations)
- [ ] Alloy specification of capability delegation verified (monotonic attenuation, depth bounds)
- [ ] At least 3 safety properties proven: complete mediation, fail-closed, no escalation
- [ ] Paper draft submitted to peer review
- [ ] Specifications published to `formal/` directory in repository

**Estimated Duration:** 8–12 weeks

---

### Phase 37: Zero-Knowledge Audit Trails (P3) — COMPLETE

*Focus: Privacy-preserving audit with zk-SNARK proofs*

**Reference:** zk-MCP (arXiv:2512.14737, Jing & Qi, Dec 2025) demonstrated < 4.14% overhead with Circom/Groth16.

**Delivered:** Two-tier ZK audit trail: inline Pedersen commitments (~50µs per entry via `curve25519-dalek` Ristretto, domain-separated generators G/H) for cryptographic binding without revealing entry contents, plus offline Groth16 batch proofs (`ark-groth16`/`ark-bn254`) proving hash-chain and Merkle tree correctness. `PedersenCommitter` (commit/verify), `WitnessStore` (bounded capacity, mutex-protected), `AuditChainCircuit` (R1CS for chain link + endpoint binding), `ZkBatchProver` (trusted setup, prove, verify, key serialization), `ZkBatchScheduler` (async batch loop with size/interval triggers, graceful shutdown). `ZkAuditConfig` with validation (batch_size 10–10,000, interval min 10s). REST API: `GET /api/zk-audit/status`, `GET /api/zk-audit/proofs` (paginated), `POST /api/zk-audit/verify`, `GET /api/zk-audit/commitments` (range-bounded). Python SDK methods (sync+async): `zk_status()`, `zk_proofs()`, `zk_verify()`, `zk_commitments()`. Feature-gated behind `zk-audit`. ~190 new tests.

### Phase 37 Exit Criteria
- [x] zk-SNARK proofs generated for audit entries with < 5% latency overhead
- [x] Proofs verifiable without access to original parameters (privacy-preserving)
- [x] Feature-gated: zero cost when disabled
- [x] At least 10 tests covering proof generation, verification, and tamper detection

---

### Phase 40: Workflow-Level Policy Constraints (P1) ✅

*Focus: Enable operators to define ordered action sequence requirements, forbidden sequence patterns, and full workflow DAG templates as context conditions on policies*

Motivated by the SciAgentGym paper finding that GPT-5 drops from 60.6% to 30.9% success as interaction horizons extend — agents make more errors in longer, multi-step workflows. VellaVeto already had single-tool sequence checks (`RequirePreviousAction`, `ForbiddenPreviousAction`), but could not express **ordered multi-tool sequences** or **workflow DAGs**.

**Implemented (engine-only, no new dependencies):**
- `RequiredActionSequence`: ordered/unordered multi-tool prerequisites (max 20 steps)
- `ForbiddenActionSequence`: ordered/unordered forbidden pattern detection (max 20 steps)
- `WorkflowTemplate`: DAG-based tool transitions with Kahn's algorithm cycle detection (max 50 steps)
- TLA+ formal verification: S8 (WorkflowPredecessor), S9 (AcyclicDAG)
- 55 new tests

### Phase 40 Exit Criteria
- [x] Ordered subsequence: A→B detected even with C between them
- [x] Ordered subsequence: B→A NOT detected (order matters)
- [x] Unordered: set semantics (all must be present)
- [x] WorkflowTemplate: non-governed tools pass through
- [x] WorkflowTemplate: entry points validated on first governed tool
- [x] WorkflowTemplate: cycle detection at compile time (Kahn's algorithm)
- [x] WorkflowTemplate: warn mode logs but does not deny
- [x] Fail-closed: empty history + required sequence = Deny
- [x] Case-insensitive matching (consistent with existing conditions)
- [x] No `unwrap()` in new code
- [x] TLA+ spec (S8, S9) created

**Completed:** 2026-02-17

---

### Phase 41: Post-Quantum Cryptography Migration (P3)

*Focus: Replace classical cryptographic primitives with NIST post-quantum standards*

The existing TLS KEX policy in `vellaveto-config/src/enterprise.rs` and migration runbook at `docs/quantum-migration.md` provide the rollout framework.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Replace Ed25519 signatures with ML-DSA (FIPS 204) for tool signing (ETDI) | P3 | 5 days | — |
| Replace ECDSA P-256 with ML-DSA in FIPS mode | P3 | 3 days | — |
| Add ML-KEM (FIPS 203) key encapsulation for capability token encryption | P3 | 5 days | — |
| Dual-signature mode: Ed25519 + ML-DSA during transition period | P3 | 3 days | ML-DSA |
| Update FIPS 140-3 mode (`vellaveto-mcp/src/fips.rs`) to include PQ algorithms | P3 | 2 days | ML-DSA, ML-KEM |
| Benchmark: PQ signature verification overhead vs Ed25519 | P3 | 2 days | Implementation |

### Phase 41 Exit Criteria
- [ ] ML-DSA (FIPS 204) available as alternative to Ed25519 for all signing operations
- [ ] ML-KEM (FIPS 203) available for key encapsulation
- [ ] Dual-signature mode allows gradual migration
- [ ] PQ signature verification < 100us (acceptable overhead vs Ed25519 ~40us)

**Estimated Duration:** 4 weeks

---

### Phase 42: Performance Benchmarking Paper (P3)

*Focus: Rigorous, peer-reviewed performance characterization*

No rigorous MCP security proxy benchmark exists (Gap #5 in `docs/MCP_SECURITY_GAPS.md`). The existing Criterion benchmarks at `vellaveto-engine/benches/evaluation.rs`, `vellaveto-audit/benches/audit.rs`, `vellaveto-mcp/benches/inspection.rs`, and `vellaveto-http-proxy/benches/http_proxy.rs` provide the foundation.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design standardized MCP proxy benchmark suite (synthetic + realistic workloads) | P3 | 3 days | — |
| Pipeline decomposition: measure each component independently (TLS, JSON-RPC parse, policy eval, DLP, audit) | P3 | 5 days | Suite design |
| Concurrent load testing: P50/P95/P99/P999 at 100/1K/10K/100K concurrent connections | P3 | 3 days | Suite |
| Compare deterministic enforcement (Vellaveto) vs probabilistic (MCP-Guard ~456ms, LLM-as-judge ~5–8s) | P3 | 3 days | Suite |
| Memory profiling: baseline RSS, per-connection overhead, policy count scaling | P3 | 2 days | — |
| Draft paper for OSDI/NSDI/MLSys | P3 | 10 days | All benchmarks |

### Phase 42 Exit Criteria
- [ ] Standardized benchmark suite published as open-source
- [ ] Pipeline decomposition shows per-component latency contribution
- [ ] P99 < 5ms verified at 10K concurrent connections
- [ ] Memory baseline < 50MB verified
- [ ] Paper draft with reproducible methodology

**Estimated Duration:** 4–6 weeks

---

## Competitor Comparison (v4.0)

| Feature | Vellaveto v4.0 | MintMCP | TrueFoundry | Lunar.dev MCPX | Microsoft MCP GW | AWS AgentCore |
|---------|---------------|---------|-------------|----------------|-------------------|---------------|
| MCP Native | Full (3 transports) | Full | Full | Full | Full (HTTP) | Managed |
| Latency | < 5ms P99 | Unknown | < 3ms claimed | Unknown | Unknown | Unknown |
| Policy Engine | ABAC + RBAC + Cedar-style | Basic | Basic | Basic | Basic YAML | IAM-based |
| Injection Detection | Multi-layer + multimodal | None | None | None | None | Basic |
| DLP | 8-layer decode | None | None | None | None | Basic |
| Tamper-Evident Audit | SHA-256 chain + Merkle + Ed25519 | None | None | None | None | CloudTrail |
| ETDI Tool Signing | Ed25519/ECDSA | None | None | None | None | None |
| EU AI Act | Art 5–50 complete (Phase 24) | None | None | None | None | None |
| SOC 2 Evidence | CC1-CC9 + access reviews (Phase 38) | SOC 2 Type II | None | None | None | SOC 2 |
| Formal Verification | TLA+/Alloy ✅ (Phase 33) | None | None | None | None | None |
| K8s Native | StatefulSet + leader election ✅ (Phase 27) | Unknown | K8s | Unknown | K8s native | Managed |
| Shadow AI Detection | Enterprise-wide ✅ (Phase 26) | None | None | None | None | None |
| Tool Discovery | TF-IDF search ✅ (Phase 34) | None | None | None | None | None |
| Model Projector | 5-model projection ✅ (Phase 35) | None | None | None | None | None |
| Agent Federation | JWKS + cross-org ABAC (Phase 39) | None | None | None | None | None |
| Cross-Transport Fallback | gRPC → WS → HTTP ✅ (Phase 29) | None | None | None | None | None |
| Distributed Tracing | W3C + OTel GenAI ✅ (Phase 28) | None | None | None | None | X-Ray |
| zk-SNARK Audit | Pedersen + Groth16 ✅ (Phase 37) | None | None | None | None | None |
| Workflow Constraints | DAG-based tool transitions ✅ (Phase 40) | None | None | None | None | None |
| Post-Quantum Crypto | ML-DSA/ML-KEM (Phase 41) | None | None | None | None | None |
| Open Source | AGPL-3.0 | Commercial | Commercial | Commercial | MIT | Commercial |
| Self-Hosted | Full | Partial | Full | Unknown | Full | No (managed) |
| SDKs | Python, TypeScript, Go, Java (Phase 36) | Python | Python | TypeScript | None | Python, Java |

**Legend:** ✅ = Implemented | Phase N = Planned for v4.0

---

## Phase Dependency Map

```
Phase 24 (EU AI Act)     ──── independent ──────────────────────────── ✅
Phase 25 (MCP Spec)      ──── independent ──────────────────────────── ✅
Phase 26 (Shadow AI)     ──── independent ──────────────────────────── ✅

Phase 27 (K8s)           ──── depends on gateway router (Phase 20) ─── ✅
Phase 28 (Tracing)       ──── depends on OTLP exporter (Phase 19) ──── ✅
Phase 29 (Fallback)      ──── depends on transport types (Phase 17) ── ✅
Phase 30 (MCP Spec)      ──── depends on protocol types (Phase 18) ─── ✅

Phase 33 (Formal Verif)  ──── depends on engine (Phase 21) ─────────── ✅
Phase 34 (Discovery)     ──── depends on MCP types (Phase 17) ──────── ✅
Phase 35 (Projector)     ──── depends on MCP types (Phase 17) ──────── ✅
                                                                        │
Phase 36 (DX/SDK)        ──── independent ──────────────────────────────┤
Phase 37 (zk-Audit)      ──── depends on Merkle proofs (Phase 19) ──────┤ ✅
Phase 38 (SOC 2)         ──── depends on SOC 2 registry (Phase 19) ────┤
                                                                        │
Phase 39 (Federation)    ──── depends on ABAC engine (Phase 21) ────────┤ ✅
Phase 40 (Workflow)      ──── depends on engine context (Phase 21) ─────┤ ✅
Phase 41 (PQC)           ──── depends on FIPS mode (Phase 23) ──────────┤
Phase 42 (Benchmark)     ──── depends on all benchmarks complete ───────┘
```

Phases 24–30, 33–35, 37–40 complete. Remaining phases:
Phase 36 (Q4 2026).
Phases 41 and 42 can run in parallel (Q1 2027).

---

## Test Budget Projection

| Phase | Estimated New Tests | Running Total |
|-------|--------------------:|:-------------:|
| v3.0 baseline | — | 4,985 |
| Phase 24 (EU AI Act) | ~40 | 5,025 ✅ |
| Phase 25 (MCP Spec) | ~50 | 5,075 ✅ |
| Phase 26 (Shadow AI) | ~35 | 5,110 ✅ |
| Phase 27 (K8s) | ~45 | 5,155 ✅ |
| Phase 28 (Tracing) | ~30 | 5,185 ✅ |
| Phase 29 (Fallback) | ~71 | 5,256 ✅ |
| Phase 30 (MCP 2025-11-25) | ~42 | 5,298 ✅ |
| Phase 33 (Formal Verif) | ~15 | 5,313 ✅ |
| Phase 34 (Discovery) | ~260 | 5,495 ✅ |
| Phase 35 (Projector) | ~230 | 5,725 ✅ |
| Phase 37 (zk-Audit) | ~38 | 5,763 ✅ |
| Improvement Campaign | ~269 | 6,032 ✅ |
| Phase 38 (SOC 2) | ~75 | 6,107 ✅ |
| Phase 39 (Federation) | ~30 | 6,137 ✅ |
| Phase 40 (Workflow) | ~55 | 6,158 ✅ |
| Phase 36 (DX/SDK) | ~80 | 6,238 |
| Phase 41 (PQC) | ~20 | 6,258 |
| Phase 42 (Benchmark) | ~10 | 6,268 |
| **v4.0 target** | **~1,283 actual + ~110 remaining** | **~6,300+** |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| MCP June 2026 spec delayed | Phase 25 blocked | Medium | Build on 2025-11-25; placeholder already in code |
| EU AI Act interpretation ambiguity (Art 50(2) scope) | Over/under-engineering Phase 24 | High | Track EU AI Office guidance; implement configurable verbosity |
| zk-SNARK framework maturity in Rust | Phase 37 timeline slip | Medium | Prototype with arkworks early; fallback to simpler commitment schemes — ✅ mitigated (Phase 37 complete, arkworks BN254 + curve25519-dalek) |
| K8s leader election edge cases | Phase 27 reliability | Medium | Use well-tested `kube-rs` lease implementation; extensive integration tests — ✅ mitigated (Phase 27 complete) |
| Formal verification scope creep | Phase 33 never completes | High | Bound scope to 3 specific safety properties; time-box to 12 weeks — ✅ mitigated (Phase 33 complete, 19 properties) |
| Competitor feature parity in K8s | Phase 27 insufficient | Low | Microsoft MCP GW is routing-only; Vellaveto's security stack remains differentiator — ✅ mitigated |
| Post-quantum crate ecosystem immaturity | Phase 41 blocked | Medium | Track `pqcrypto` and `ml-dsa` crate development; defer if not production-ready |

---

*This roadmap is a living document. Update as standards finalize and priorities shift.*

---

<details>
<summary><h2>Archive: v4.0 Completed Phases (24–35)</h2></summary>

> All phases below are **implemented, tested, and hardened** through 45 audit rounds.
> Preserved here for historical reference and traceability.

### Phase 37: Zero-Knowledge Audit Trails (P3) — COMPLETE
- Two-tier ZK audit: inline Pedersen commitments (`curve25519-dalek` Ristretto, ~50µs) + offline Groth16 batch proofs (`ark-groth16`/`ark-bn254`). `PedersenCommitter`, `WitnessStore`, `AuditChainCircuit`, `ZkBatchProver`, `ZkBatchScheduler`. REST API (status/proofs/verify/commitments). Python SDK methods. Feature-gated behind `zk-audit`.
- 4/4 exit criteria delivered, ~190 new tests (Rust + Python)

### Phase 34: Tool Discovery Service (P1) — COMPLETE
- Pure Rust TF-IDF inverted index (cosine similarity, zero new deps), `DiscoveryEngine` with policy filtering and token budget, session-scoped TTL lifecycle, REST API (search/stats/reindex/tools), SDK methods (Python/TypeScript/Go), feature-gated
- 8/8 exit criteria delivered, ~260 new tests

### Phase 35: Model Projector (P1) — COMPLETE
- `ModelProjection` trait with `ProjectorRegistry`, 5 built-in projections (Claude/OpenAI/DeepSeek/Qwen/Generic), `SchemaCompressor` (5 strategies), `CallRepairer` (type coercion, Levenshtein, DeepSeek markdown), REST API (models/transform), feature-gated
- 6/6 exit criteria delivered, ~230 new tests

### Phase 33: Formal Verification (TLA+/Alloy) (P3) — COMPLETE
- TLA+ specs for policy engine (6 safety + 2 liveness) and ABAC forbid-overrides (4 safety), Alloy model for capability delegation (6 safety assertions), 19 verified properties
- First formal model of MCP policy enforcement in any framework

### Phase 30: MCP 2025-11-25 Spec Adoption (P0) — COMPLETE
- `validate_mcp_tool_name()`, `StreamableHttpConfig`, `handle_mcp_get()` for SSE, `WWW-Authenticate` header, strict tool name validation
- ~42 new tests

### Phase 27: Kubernetes-Native Deployment (P1) — COMPLETE
- `LeaderElection` trait + `LocalLeaderElection`, `ServiceDiscovery` trait + `StaticServiceDiscovery` + `DnsServiceDiscovery`, `DeploymentConfig` with validation, `GET /api/deployment/info`, health endpoint extensions, Helm chart v4.0.0 (StatefulSet + PVC + sidecar), deployment audit events
- 5/6 exit criteria delivered (Grafana dashboards deferred to Phase 28b)

### Phase 28: Distributed Tracing & Observability (P1) — COMPLETE
- W3C Trace Context propagation across HTTP, WebSocket, gRPC, and A2A transports, `TraceContext` parsing/child spans/verdict injection, GenAI `gen_ai.agent.id` attributes, gateway per-backend child spans
- 3/4 exit criteria delivered (Grafana dashboards deferred to Phase 28b)

### Phase 29: Cross-Transport Smart Fallback (P1) — COMPLETE
- Ordered transport fallback (gRPC → WS → HTTP → stdio), per-transport circuit breakers, transport discovery/priority resolution, audit trail of fallback negotiations
- 71 new tests

### Phase 17: MCP Next Spec Preparation (P0) — COMPLETE
- WebSocket transport (SEP-1288), gRPC transport (Google), async operations (SEP-1391), protocol extensions framework
- 6/6 exit criteria delivered

### Phase 18: MCP June 2026 Spec Compliance (P0) — COMPLETE
- `2026-06` protocol version placeholder, SDK tier declaration (Extended), transport discovery, transport negotiation
- 4/4 exit criteria delivered

### Phase 19: Regulatory Compliance (P0) — COMPLETE
- EU AI Act registry (Art 5–50), Art 50(1) transparency marking, Art 14 human oversight, SOC 2 evidence (CC1-CC9), Merkle proofs, OTLP GenAI export, CoSAI threat mapping (38/38), Adversa TOP 25 mapping (25/25), 7-framework gap analysis, immutable archive, compliance dashboard
- 9/9 exit criteria delivered

### Phase 20: MCP Gateway Mode (P1) — COMPLETE (20.4 deferred to Phase 27)
- Multi-backend routing, health state machine, session affinity, tool conflict detection
- 5/6 exit criteria delivered (K8s deferred)

### Phase 21: Advanced Authorization (P1) — COMPLETE
- ABAC with forbid-overrides, capability-based delegation tokens, least-agency tracking, identity federation types, continuous authorization
- 5/5 exit criteria delivered

### Phase 22: Developer Experience (P2) — COMPLETE
- Policy simulator API (4 endpoints), CLI simulate, GitHub Action, dashboard SVG charts, TypeScript SDK, Go SDK
- 5/5 exit criteria delivered

### Phase 23: Research & Future (P3) — COMPLETE
- Multimodal injection detection (PNG/JPEG/PDF), red team mutation engine (8 types), FIPS 140-3 mode (ECDSA P-256), Rekor transparency log, stateful session guards (5-state machine)
- 5/5 exit criteria delivered

</details>

<details>
<summary><h2>Archive: v2.0–v2.2 Completed Phases (1–15)</h2></summary>

> All phases below are **implemented, tested, and hardened** through 35 audit rounds.
> Preserved here for historical reference and traceability.

- **Phase 1:** MCP 2025-11-25 compliance (async tasks, OAuth, CIMD, step-up auth)
- **Phase 2:** Advanced threat detection (shadow agents, schema poisoning, circuit breaker, sampling, confused deputy)
- **Phase 3.1:** Runtime integration (ProxyBridge, 25+ admin routes)
- **Phase 3.2:** Cross-agent security (trust graph, message signing, injection detection)
- **Phase 3.3:** Advanced threat detection (goal tracking, workflow monitoring, namespace security)
- **Phase 4.1:** Standards alignment (MITRE ATLAS, OWASP AIVSS, NIST AI RMF, ISO 27090)
- **Phase 5:** Enterprise hardening (mTLS, SPIFFE, OPA, threat intel, JIT access)
- **Phase 6:** Observability & tooling (execution graphs, red-team automation, policy CLI)
- **Phase 7:** Documentation & release (v2.0.0)
- **Phase 8:** ETDI cryptographic tool security (Ed25519/ECDSA, attestation chains, version pinning)
- **Phase 9:** Memory injection defense (MINJA taint propagation, provenance, isolation)
- **Phase 10:** Non-Human Identity lifecycle (NHI register/rotate/revoke, DPoP)
- **Phase 11:** MCP Tasks primitive security (state encryption, resume token auth, hash chain)
- **Phase 12:** Semantic guardrails (LLM-based, intent classification, jailbreak detection)
- **Phase 13:** RAG poisoning defense (provenance, embedding anomaly, context budget)
- **Phase 14:** A2A protocol security (message classification, agent card, proxy service)
- **Phase 15:** Observability platform integration (Arize, Langfuse, Helicone)

</details>
