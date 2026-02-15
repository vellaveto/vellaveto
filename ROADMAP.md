# Vellaveto Roadmap v4.0

> **Version:** 4.0.0
> **Generated:** 2026-02-15
> **Baseline:** v3.0.0 — 4,812 Rust tests, 130 Python SDK tests, 28 Go SDK tests, 15 TypeScript SDK tests, 22 fuzz targets, 11 CI workflows, 38 audit rounds, 23 phases complete
> **Scope:** 12 months (Q2 2026 – Q1 2027), quarterly milestones
> **Status:** v3.0 shipped; all 23 phases complete

---

## Executive Summary

Vellaveto v3.0 established the most comprehensive MCP runtime security engine in the market: full MCP 2025-11-25 compliance, three transport layers (HTTP/WebSocket/gRPC), Cedar-style ABAC, EU AI Act evidence generation, 100% CoSAI and Adversa TOP 25 coverage, cryptographic audit trails with Merkle proofs, capability-based delegation tokens, and multimodal injection detection. The rebrand from Sentinel to Vellaveto marks the transition from a research prototype to an enterprise product.

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
| [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | Hard deadline Aug 2, 2026 |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Least agency principle |
| [Lakera Agent Security Report Q4 2025](https://www.lakera.ai) | 88% incident rate, 14.4% approval rate |
| [Gravitee State of AI Agent Security 2026](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control) | Enterprise security gaps |
| [zk-MCP: Privacy-Preserving Audit](https://arxiv.org/abs/2512.14737) | Phase 34 zk-SNARK reference |
| [Securing the Model Context Protocol](https://arxiv.org/abs/2511.20920) | Formal verification gap |
| [31 Formal Properties for Agentic AI](https://arxiv.org/abs/2510.14133) | CTL/LTL specifications |
| [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | Post-quantum key encapsulation |
| [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) | Post-quantum digital signatures |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | K8s-native competitor |
| [AWS AgentCore](https://aws.amazon.com/agentcore) | Managed agent runtime competitor |
| [MintMCP](https://mintmcp.com) | SOC 2 Type II competitor |
| [TrueFoundry MCP Gateway](https://www.truefoundry.com) | Sub-3ms latency competitor |
| [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Phase 28 tracing |
| [AAP: Agent Authorization Profile](https://aap-protocol.org) | Phase 32 federation reference |
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

Q3 2026 (Jul–Sep):  Phase 27 — Kubernetes-Native Deployment            [P1]
                     Phase 28 — Distributed Tracing & Observability     [P1]
                     Phase 29 — Cross-Transport Smart Fallback          [P1]

Q4 2026 (Oct–Dec):  Phase 30 — Developer Experience & SDKs             [P2]
                     Phase 31 — SOC 2 Type II Access Reviews            [P1]
                     Phase 32 — Agent Identity Federation               [P1]

Q1 2027 (Jan–Mar):  Phase 33 — Formal Verification (TLA+/Alloy)        [P3]
                     Phase 34 — Zero-Knowledge Audit Trails             [P3]
                     Phase 35 — Post-Quantum Cryptography Migration     [P3]
                     Phase 36 — Performance Benchmarking Paper          [P3]
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
- [ ] EU AI Act conformity assessment shows 100% article coverage
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

### Phase 27: Kubernetes-Native Deployment (P1)

*Focus: Production-grade K8s deployment with StatefulSet, leader election, and service discovery*

**Deferred from Phase 20.4 in v3.0**

The existing Helm chart at `helm/vellaveto/` provides a basic Deployment with HPA, PDB, NetworkPolicy, and ServiceMonitor templates. This phase extends it to a production-grade gateway deployment.

#### 27.1 Helm Chart Gateway Mode

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Convert Deployment to StatefulSet with PVC for audit log persistence | P1 | 2 days | — |
| Add `gateway.enabled` values with upstream backend configuration | P1 | 2 days | — |
| Add init container for config validation (`vellaveto check`) | P1 | 1 day | — |
| Add sidecar container for audit log shipping (fluentbit/vector) | P1 | 2 days | — |
| gRPC port exposure (50051) when `grpc.enabled = true` | P1 | 1 day | — |
| WebSocket upgrade support in Ingress annotations | P1 | 1 day | — |
| Helm chart CI: `helm lint` + `helm template` + kind cluster smoke test | P1 | 3 days | All above |

#### 27.2 Leader Election and Cluster Coordination

The existing `ClusterBackend` trait in `vellaveto-cluster/src/lib.rs` provides `LocalBackend` and `RedisBackend` implementations. Leader election builds on this.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement Kubernetes lease-based leader election | P1 | 4 days | — |
| Leader responsibilities: policy reload coordination, audit checkpoint signing | P1 | 3 days | Leader election |
| Follower responsibilities: forward approval decisions to leader | P1 | 2 days | Leader election |
| Health endpoint extended: `/health` includes leader/follower status | P1 | 1 day | — |

#### 27.3 Service Discovery

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Kubernetes Service discovery for upstream MCP servers (label selector) | P1 | 3 days | — |
| Auto-registration of discovered backends into `GatewayRouter` | P1 | 2 days | Discovery |
| Endpoint watch for dynamic backend add/remove | P1 | 2 days | Auto-registration |
| DNS-based service discovery fallback (for non-K8s environments) | P1 | 2 days | — |

### Phase 27 Exit Criteria
- [ ] Helm chart passes `helm lint` and deploys to kind cluster
- [ ] StatefulSet with PVC maintains audit log across pod restarts
- [ ] Leader election converges within 15 seconds of leader failure
- [ ] Service discovery detects new/removed upstream MCP servers within 30 seconds
- [ ] Gateway mode routes requests across 3+ backends in kind cluster
- [ ] PDB ensures zero downtime during rolling updates

**Estimated Duration:** 6 weeks

---

### Phase 28: Distributed Tracing & Observability (P1)

*Focus: Multi-agent trace context propagation and pre-built observability dashboards*

**Deferred from v3.0 Phase 19.2**

The existing OTLP exporter at `vellaveto-audit/src/observability/otlp.rs` exports spans with GenAI semantic conventions. This phase adds multi-agent trace context propagation and pre-built dashboards.

#### 28.1 Multi-Agent Trace Context

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Implement W3C Trace Context (traceparent/tracestate) extraction from MCP headers | P1 | 2 days | — | `vellaveto-http-proxy` |
| Propagate trace context across gateway routing (upstream calls carry parent span) | P1 | 2 days | Extraction | `vellaveto-http-proxy` |
| Add `gen_ai.agent.id`, `gen_ai.agent.name` attributes to OTLP spans | P1 | 1 day | — | `vellaveto-audit` |
| Cross-MCP/A2A boundary trace linking (child spans reference parent across protocols) | P1 | 3 days | Propagation | `vellaveto-mcp` |
| Trace context propagation in WebSocket and gRPC transports | P1 | 2 days | HTTP implementation | `vellaveto-http-proxy` |

#### 28.2 Grafana Dashboard Templates

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Grafana dashboard JSON: verdict distribution over time (allow/deny/approval) | P1 | 1 day | — |
| Grafana dashboard JSON: P50/P95/P99 evaluation latency | P1 | 1 day | — |
| Grafana dashboard JSON: agent activity heatmap (tool calls per agent per hour) | P1 | 1 day | — |
| Grafana dashboard JSON: compliance posture (EU AI Act, SOC 2, CoSAI) | P1 | 1 day | — |
| Jaeger/Tempo integration test: end-to-end trace verification | P1 | 2 days | Trace context |

### Phase 28 Exit Criteria
- [ ] W3C trace context propagated across HTTP, WebSocket, and gRPC transports
- [ ] Cross-gateway traces visible in Jaeger/Tempo with agent identity attributes
- [ ] 4 Grafana dashboard templates published in `helm/vellaveto/dashboards/`
- [ ] `gen_ai.agent.*` attributes present on all exported spans

**Estimated Duration:** 4 weeks

---

### Phase 29: Cross-Transport Smart Fallback (P1)

*Focus: Ordered transport fallback chain with per-transport circuit breakers*

**Deferred from v3.0 Phase 18.3**

The existing `forward_with_fallback()` in `vellaveto-http-proxy/src/proxy/fallback.rs` supports HTTP-only retry. This phase extends it to cross-transport negotiation.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Extend `FallbackResult` to track transport negotiation history | P1 | 1 day | — |
| Implement ordered fallback chain: gRPC → WebSocket → HTTP SSE → stdio | P1 | 4 days | — |
| Add transport health tracking per upstream (healthy transport list) | P1 | 2 days | — |
| Add transport preference override per policy (some tools require specific transport) | P1 | 2 days | — |
| Circuit breaker per transport per upstream | P1 | 2 days | — |
| Metrics: `vellaveto_transport_fallback_total` with transport labels | P1 | 1 day | — |
| Integration tests: simulate transport failures and verify fallback behavior | P1 | 2 days | All above |

### Phase 29 Exit Criteria
- [ ] Fallback chain gRPC → WebSocket → HTTP works end-to-end
- [ ] Transport-level circuit breaker prevents repeated attempts to failed transports
- [ ] Fallback attempts audited with transport used and attempt count
- [ ] P99 fallback latency < 500ms (total, not per-attempt)

**Estimated Duration:** 3 weeks

---

## Q4 2026 (Oct–Dec): Developer Experience & Enterprise

### Phase 30: Developer Experience & SDK Ecosystem (P2)

*Focus: IDE integration, Java SDK, and visual policy execution tools*

**Deferred from v3.0 Phase 22**

#### 30.1 VS Code Extension

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Policy file syntax highlighting (TOML with Vellaveto schema) | P2 | 2 days | — |
| Inline policy validation (calls `vellaveto check` LSP-style) | P2 | 3 days | Highlighting |
| Verdict visualization in test explorer | P2 | 3 days | Validation |
| Policy playground panel (simulate against sample actions) | P2 | 3 days | — |
| Publish to VS Code Marketplace | P2 | 1 day | All above |

#### 30.2 Java SDK

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| HTTP client using `java.net.http.HttpClient` (Java 11+) | P2 | 3 days | — |
| Full API parity with Python/TypeScript/Go SDKs | P2 | 2 days | Client |
| Typed errors (`VellavetoException`, `PolicyDeniedException`, `ApprovalRequiredException`) | P2 | 1 day | Client |
| Maven Central publishing with javadoc | P2 | 2 days | Implementation |
| JUnit 5 tests (target 30+ tests) | P2 | 2 days | Implementation |

#### 30.3 React/WASM Execution Graph UI

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| React SPA: execution graph visualization (D3.js force-directed graph) | P2 | 5 days | — |
| WASM compilation of `vellaveto-engine` for client-side policy simulation | P2 | 3 days | — |
| Real-time verdict stream via WebSocket subscription | P2 | 2 days | — |
| Policy diff visualization (before/after comparison) | P2 | 2 days | — |
| Embed in dashboard route or serve as standalone SPA | P2 | 1 day | All above |

### Phase 30 Exit Criteria
- [ ] VS Code extension published to Marketplace with policy validation
- [ ] Java SDK published to Maven Central with 30+ tests
- [ ] Execution graph UI renders live verdict flows
- [ ] WASM build of policy engine evaluates in-browser

**Estimated Duration:** 6 weeks

---

### Phase 31: SOC 2 Type II Access Review Reports (P1)

*Focus: Automated access review report generation for SOC 2 auditors*

**Deferred from v3.0 Phase 19.4**

The existing SOC 2 evidence generation at `vellaveto-audit/src/soc2.rs` covers CC1-CC9 criteria with readiness levels. The access review report generator produces the periodic reports that SOC 2 Type II auditors require.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define `AccessReviewReport` type: user/agent list, permissions, last access, reviewer | P1 | 2 days | — |
| Implement access review data collection from audit log entries | P1 | 3 days | Type |
| Generate SOC 2 CC6 (logical/physical access) evidence reports | P1 | 2 days | Collection |
| Scheduled report generation (daily/weekly/monthly) | P1 | 2 days | Generation |
| API: `GET /api/compliance/soc2/access-review?period=30d` | P1 | 1 day | Generation |
| PDF/HTML export of access review reports | P1 | 2 days | API |

### Phase 31 Exit Criteria
- [ ] Access review reports generated for configurable time periods
- [ ] Reports include: agent identity, permissions granted, permissions used, usage ratio
- [ ] Reports include: reviewer attestation fields for SOC 2 auditor sign-off
- [ ] `GET /api/compliance/soc2/access-review` returns structured JSON

**Estimated Duration:** 3 weeks

---

### Phase 32: Agent Identity Federation (P1)

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

### Phase 32 Exit Criteria
- [ ] JWKS resolution from 2+ external issuers working
- [ ] JWT claims from federated identity mapped to internal ABAC principals
- [ ] Cross-organization tool call evaluated correctly through ABAC
- [ ] Federation status visible in dashboard

**Estimated Duration:** 4 weeks

---

## Q1 2027 (Jan–Mar): Research & Future-Proofing

### Phase 33: Formal Verification (TLA+/Alloy) (P3)

*Focus: First formal model of MCP policy enforcement — a first-of-its-kind contribution*

No formal model of MCP policy enforcement exists in any framework (TLA+, Alloy, Lean, Coq). Documented as Gap #1 in `docs/MCP_SECURITY_GAPS.md`.

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

### Phase 34: Zero-Knowledge Audit Trails (P3)

*Focus: Privacy-preserving audit with zk-SNARK proofs*

**Reference:** zk-MCP (arXiv:2512.14737, Jing & Qi, Dec 2025) demonstrated < 4.14% overhead with Circom/Groth16.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Research and select zk-SNARK framework for Rust (arkworks vs bellman vs halo2) | P3 | 3 days | — |
| Define audit circuit: prove "action was evaluated and produced Deny" without revealing parameters | P3 | 5 days | Framework |
| Implement proof generation alongside each audit entry | P3 | 10 days | Circuit |
| Implement proof verification without access to original audit data | P3 | 5 days | Generation |
| Benchmark: prove overhead < 5% of evaluation latency | P3 | 3 days | Implementation |
| Feature-gate behind `zk-audit` to avoid dependency cost for non-users | P3 | 1 day | — |
| Integration with existing Merkle tree proofs (combine zk + Merkle for full audit) | P3 | 3 days | Both systems |

### Phase 34 Exit Criteria
- [ ] zk-SNARK proofs generated for audit entries with < 5% latency overhead
- [ ] Proofs verifiable without access to original parameters (privacy-preserving)
- [ ] Feature-gated: zero cost when disabled
- [ ] At least 10 tests covering proof generation, verification, and tamper detection

**Estimated Duration:** 6–8 weeks

---

### Phase 35: Post-Quantum Cryptography Migration (P3)

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

### Phase 35 Exit Criteria
- [ ] ML-DSA (FIPS 204) available as alternative to Ed25519 for all signing operations
- [ ] ML-KEM (FIPS 203) available for key encapsulation
- [ ] Dual-signature mode allows gradual migration
- [ ] PQ signature verification < 100us (acceptable overhead vs Ed25519 ~40us)

**Estimated Duration:** 4 weeks

---

### Phase 36: Performance Benchmarking Paper (P3)

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

### Phase 36 Exit Criteria
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
| SOC 2 Evidence | CC1-CC9 + access reviews (Phase 31) | SOC 2 Type II | None | None | None | SOC 2 |
| Formal Verification | TLA+/Alloy (Phase 33) | None | None | None | None | None |
| K8s Native | StatefulSet + leader election (Phase 27) | Unknown | K8s | Unknown | K8s native | Managed |
| Shadow AI Detection | Enterprise-wide (Phase 26) | None | None | None | None | None |
| Agent Federation | JWKS + cross-org ABAC (Phase 32) | None | None | None | None | None |
| Cross-Transport Fallback | gRPC → WS → HTTP (Phase 29) | None | None | None | None | None |
| Distributed Tracing | W3C + OTel GenAI (Phase 28) | None | None | None | None | X-Ray |
| zk-SNARK Audit | Phase 34 | None | None | None | None | None |
| Post-Quantum Crypto | ML-DSA/ML-KEM (Phase 35) | None | None | None | None | None |
| Open Source | AGPL-3.0 | Commercial | Commercial | Commercial | MIT | Commercial |
| Self-Hosted | Full | Partial | Full | Unknown | Full | No (managed) |
| SDKs | Python, TypeScript, Go, Java (Phase 30) | Python | Python | TypeScript | None | Python, Java |

**Legend:** ✅ = Implemented | Phase N = Planned for v4.0

---

## Phase Dependency Map

```
Phase 24 (EU AI Act)     ──── independent ──────────────────────────────┐
Phase 25 (MCP Spec)      ──── independent ──────────────────────────────┤
Phase 26 (Shadow AI)     ──── independent ──────────────────────────────┤
                                                                        │
Phase 27 (K8s)           ──── depends on gateway router (Phase 20) ─────┤
Phase 28 (Tracing)       ──── depends on OTLP exporter (Phase 19) ──────┤
Phase 29 (Fallback)      ──── depends on transport types (Phase 17) ────┤
                                                                        │
Phase 30 (DX/SDK)        ──── independent ──────────────────────────────┤
Phase 31 (SOC 2)         ──── depends on SOC 2 registry (Phase 19) ────┤
Phase 32 (Federation)    ──── depends on ABAC engine (Phase 21) ────────┤
                                                                        │
Phase 33 (Formal Verif)  ──── depends on engine (Phase 21) ─────────────┤
Phase 34 (zk-Audit)      ──── depends on Merkle proofs (Phase 19) ──────┤
Phase 35 (PQC)           ──── depends on FIPS mode (Phase 23) ──────────┤
Phase 36 (Benchmark)     ──── depends on all benchmarks complete ───────┘
```

Phases 24, 25, and 26 can run in parallel (Q2 2026).
Phases 27, 28, and 29 can run in parallel (Q3 2026).
Phases 30, 31, and 32 can run in parallel (Q4 2026).
Phases 33, 34, 35, and 36 can run in parallel (Q1 2027).

---

## Test Budget Projection

| Phase | Estimated New Tests | Running Total |
|-------|--------------------:|:-------------:|
| v3.0 baseline | — | 4,985 |
| Phase 24 (EU AI Act) | ~40 | 5,025 |
| Phase 25 (MCP Spec) | ~50 | 5,075 |
| Phase 26 (Shadow AI) | ~35 | 5,110 |
| Phase 27 (K8s) | ~45 | 5,155 |
| Phase 28 (Tracing) | ~30 | 5,185 |
| Phase 29 (Fallback) | ~25 | 5,210 |
| Phase 30 (DX/SDK) | ~80 | 5,290 |
| Phase 31 (SOC 2) | ~20 | 5,310 |
| Phase 32 (Federation) | ~30 | 5,340 |
| Phase 33 (Formal Verif) | ~15 | 5,355 |
| Phase 34 (zk-Audit) | ~25 | 5,380 |
| Phase 35 (PQC) | ~20 | 5,400 |
| Phase 36 (Benchmark) | ~10 | 5,410 |
| **v4.0 target** | **~425 new** | **~5,400+** |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| MCP June 2026 spec delayed | Phase 25 blocked | Medium | Build on 2025-11-25; placeholder already in code |
| EU AI Act interpretation ambiguity (Art 50(2) scope) | Over/under-engineering Phase 24 | High | Track EU AI Office guidance; implement configurable verbosity |
| zk-SNARK framework maturity in Rust | Phase 34 timeline slip | Medium | Prototype with arkworks early; fallback to simpler commitment schemes |
| K8s leader election edge cases | Phase 27 reliability | Medium | Use well-tested `kube-rs` lease implementation; extensive integration tests |
| Formal verification scope creep | Phase 33 never completes | High | Bound scope to 3 specific safety properties; time-box to 12 weeks |
| Competitor feature parity in K8s | Phase 27 insufficient | Low | Microsoft MCP GW is routing-only; Vellaveto's security stack remains differentiator |
| Post-quantum crate ecosystem immaturity | Phase 35 blocked | Medium | Track `pqcrypto` and `ml-dsa` crate development; defer if not production-ready |

---

*This roadmap is a living document. Update as standards finalize and priorities shift.*

---

<details>
<summary><h2>Archive: v3.0 Completed Phases (17–23)</h2></summary>

> All phases below are **implemented, tested, and hardened** through 38 audit rounds.
> Preserved here for historical reference and traceability.

### Phase 17: MCP Next Spec Preparation (P0) — COMPLETE
- WebSocket transport (SEP-1288), gRPC transport (Google), async operations (SEP-1391), protocol extensions framework
- 6/6 exit criteria delivered

### Phase 18: MCP June 2026 Spec Compliance (P0) — COMPLETE
- `2026-06` protocol version placeholder, SDK tier declaration (Extended), transport discovery, transport negotiation
- 4/4 exit criteria delivered

### Phase 19: Regulatory Compliance (P0) — COMPLETE
- EU AI Act registry (Art 5–50), Art 50(1) transparency marking, Art 14 human oversight, SOC 2 evidence (CC1-CC9), Merkle proofs, OTLP GenAI export, CoSAI 38/38, Adversa TOP 25 25/25, 7-framework gap analysis, immutable archive, compliance dashboard
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
