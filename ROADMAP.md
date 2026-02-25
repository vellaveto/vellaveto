# Vellaveto Roadmap

> **Version:** 5.0.0-dev
> **Updated:** 2026-02-25
> **Current:** 7,697 Rust tests, 385 Python, 127 Go, 119 TypeScript | 224 audit rounds | 49 phases complete
> **Strategic position:** Agentic Security Control Plane & Policy Gateway
> **License:** AGPL-3.0 (core) + Commercial Enterprise

---

## Executive Summary

Vellaveto is an **Agentic Security Control Plane** — the platform through which enterprises govern, observe, and secure every AI agent tool call. Built on the most comprehensive open-source MCP runtime security engine (full MCP 2025-06-18 compliance, 4 transport layers, Cedar-style ABAC, formal verification, zero-knowledge audit trails), the roadmap extends into centralized multi-tenant governance, enterprise IAM, and commercial packaging.

**Market signals driving the roadmap:**
1. **Enterprises need centralized agent governance** — the explosion of AI agents (LangChain, CrewAI, AutoGen, Google ADK, OpenAI Agents SDK) demands a unified control plane
2. **Regulatory acceleration** — EU AI Act (Aug 2026), DORA, NIS2, ISO 42001
3. **Nascent competitive landscape** — MintMCP, TrueFoundry, Lunar.dev, Microsoft MCP Gateway, AWS AgentCore entering; none offer enterprise-grade policy management + admin UI + compliance packs
4. **Italy-first GTM** — UniCredit, Intesa Sanpaolo, Generali, Enel are early adopters under heavy regulatory pressure (Banca d'Italia + DORA + NIS2)
5. **Open-core monetization** — AGPL-3.0 core engine + Commercial Enterprise license

---

## Priority Matrix

| Priority | Theme | Business Driver |
|----------|-------|-----------------|
| **P1** | Admin Console + Enterprise IAM | Enterprise sales, partner demos |
| **P2** | Developer Experience & SDK Ecosystem | Developer adoption, enterprise integration |
| **P3** | Billing/Metering + Marketplace + Scale | Revenue, GTM scale |

---

## Timeline

```
Q2 2026 (Now):   Phase 36 — Developer Experience & SDK Ecosystem         [P2]

Q3 2026:         Phase 45 — Admin Console (React SPA)                    [P1]
                  Phase 46 — Enterprise IAM (SSO/OIDC/SAML)              [P1]

Q4 2026:         Phase 50 — Usage Metering & Billing Foundation          [P3]

Q1 2027:         Phase 51 — Partner Integration Kit                      [P3]
                  Phase 53 — Marketplace & Self-Service Onboarding       [P3]

Q2 2027:         Phase 54 — Post-Quantum Cryptography Migration          [P3]
                  Phase 55 — Performance & Scale Validation              [P3]
```

---

## Phase 36: Developer Experience & SDK Ecosystem (P2) — In Progress

*Focus: Lower the barrier for enterprise developers to adopt Vellaveto.*

### 36.1 Java SDK

| Task | Effort | Status |
|------|--------|--------|
| VellavetoClient with all 33 API methods (evaluate, approve, discover, ZK, compliance, federation, usage) | 3 days | |
| Action, EvaluationResult, Verdict, EvaluationContext types | 1 day | |
| Input validation (control chars, Unicode format chars, length bounds) | 1 day | |
| Retry with exponential backoff (429/502/503/504) | 0.5 day | |
| ParameterRedactor (client-side secret redaction) | 0.5 day | |
| JUnit 5 tests (50+) | 2 days | |

### 36.2 VS Code Extension

| Task | Effort | Status |
|------|--------|--------|
| Extension scaffold with policy file detection (*.vellaveto.toml) | 0.5 day | |
| On-save validation via POST /api/simulator/validate with VS Code diagnostics | 1 day | |
| TOML completion provider for policy fields and enum values | 1 day | |
| Snippet library from 5 presets (dev-laptop, ci-agent, database-agent, browser-agent, rag-agent) | 0.5 day | |
| Simulator webview panel (test actions against current policy file) | 1.5 days | |
| Tests (15+) | 1 day | |

### 36.3 Execution Graph SVG Export

| Task | Effort | Status |
|------|--------|--------|
| GET /api/graphs/{session}/svg endpoint with hierarchical layout | 1 day | |
| Verdict-colored nodes (green/red/yellow), call chain edges | 0.5 day | |
| Dashboard integration (SVG link for recent sessions) | 0.5 day | |

### Exit Criteria
- [ ] Java SDK: 33 API methods with full parity to Go/Python/TypeScript SDKs
- [ ] Java SDK: 50+ passing JUnit 5 tests
- [ ] VS Code extension: policy validation, completions, snippets, simulator
- [ ] VS Code extension: 15+ passing tests
- [ ] SVG export: embeddable execution graph visualization
- [ ] All existing workspace tests still pass

---

## Phase 45: Admin Console (P1)

*Focus: Web-based admin console replacing CLI/API for security teams and compliance officers.*

| Sub-phase | Key Deliverables |
|-----------|-----------------|
| 45.1 Core UI Framework | React + TypeScript + Vite, OIDC auth, RBAC (Admin/Operator/Viewer/Auditor), tenant selector |
| 45.2 Dashboard & Monitoring | Real-time verdict stream (WebSocket), agent/tool inventories, shadow AI alerts, health |
| 45.3 Audit Viewer | Searchable audit log (time range, agent, tool, verdict), export (CSV/JSONL/PDF), real-time tail |
| 45.4 Policy Editor | TOML syntax highlighting with live validation, policy simulator, version diff |

**Exit criteria:** OIDC login, RBAC navigation, real-time verdicts, audit viewer with search, policy editor, WCAG 2.1 AA

---

## Phase 46: Enterprise IAM (P1)

*Focus: Enterprise identity provider integration for admin console and agent identity resolution.*

| Task | Priority |
|------|----------|
| OIDC provider integration (Okta, Azure AD/Entra ID, Keycloak) | P1 |
| SAML 2.0 SP implementation for legacy IdPs | P1 |
| Session management (secure cookies, CSRF, idle timeout) | P1 |
| RBAC with tenant scoping | P1 |
| SCIM 2.0 provisioning (auto-create/deactivate from IdP) | P2 |
| Agent identity resolution from enterprise JWT claims | P1 |

**Exit criteria:** OIDC + SAML login, RBAC enforced, configurable session timeout, agent identity from JWT claims

---

## Phase 50: Usage Metering & Billing Foundation (P3)

*Focus: Per-tenant usage tracking for commercial licensing.*

| Task | Priority |
|------|----------|
| PostgresUsageMeter with hourly rollup tables | P3 |
| Per-tenant usage API with period aggregation | P3 |
| Stripe metered billing webhook | P3 |
| License enforcement: Community (10K evals/day), Pro (100K), Enterprise (unlimited) | P3 |

**Exit criteria:** Accurate per-tenant counts, Community tier enforcement, Stripe billing functional

---

## Phase 51: Partner Integration Kit (P3)

*Focus: Pre-packaged integrations for SI partners and enterprise AI platforms.*

| Integration | Framework |
|------------|-----------|
| LangChain/LangGraph middleware | Python SDK |
| CrewAI crew-level policy enforcement | Python SDK |
| Google ADK tool validation callback | Python SDK |
| OpenAI Agents SDK function calling interceptor | Python SDK |
| Terraform provider (policies, tenants, users) | Go |
| SI pilot kit (deployment guide, demo script, reference architecture) | Docs |

**Exit criteria:** LangChain + CrewAI on PyPI, Terraform provider, SI pilot kit, 10+ tests per integration

---

## Phase 53: Marketplace & Self-Service Onboarding (P3)

*Focus: Self-service tenant onboarding and community ecosystem.*

- Self-service signup with email verification
- Policy marketplace (community-contributed templates)
- Cloud marketplace images (AWS AMI, Azure VM, GCP)
- Interactive API docs (OpenAPI/Swagger)

**Exit criteria:** Signup-to-first-evaluation in < 5 min, 10+ policy templates, 2+ cloud marketplaces

---

## Phase 54: Post-Quantum Cryptography Migration (P3)

*Focus: FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) for audit signatures and key exchange.*

- ML-KEM-768 for key encapsulation (replacing X25519 where applicable)
- ML-DSA-65 for audit checkpoint signatures (hybrid with Ed25519)
- Backward-compatible signature verification (Ed25519 + ML-DSA dual)
- NIST SP 800-227 compliance documentation

**Exit criteria:** Hybrid Ed25519+ML-DSA signatures, backward-compatible verification, NIST compliance

---

## Phase 55: Performance & Scale Validation (P3)

*Focus: Validate control plane architecture at enterprise scale.*

- 100K evaluations/second sustained on 3-node cluster
- Multi-tenant isolation verification under load
- PostgreSQL audit write throughput >= 50K entries/sec
- P99 < 5ms at 10K concurrent connections
- Chaos testing (pod kill, network partition, database failover)
- Benchmark paper publication

**Exit criteria:** All targets met for 1 hour sustained, zero cross-tenant leakage, chaos recovery < 30s

---

## Phase Dependency Map

```
Phase 36 (DX/SDK)          ──── independent, in progress ──────────────────┐
                                                                            │
Phase 45 (Admin Console)   ──── depends on Phase 46 ───────────────────────┤
Phase 46 (Enterprise IAM)  ──── independent ───────────────────────────────┤
                                                                            │
Phase 50 (Billing)         ──── depends on Phase 46 ───────────────────────┤
Phase 51 (Partner Kit)     ──── depends on Phase 36 ───────────────────────┤
Phase 53 (Marketplace)     ──── depends on Phase 46 + 50 ─────────────────┤
Phase 54 (PQC)             ──── independent ───────────────────────────────┤
Phase 55 (Scale)           ──── depends on Phase 50 ───────────────────────┘
```

**Critical path:** Phase 46 (IAM) -> Phase 45 (Console) -> Phase 50 (Billing) -> Phase 53 (Marketplace)

---

## Competitive Comparison

| Feature | Vellaveto | MintMCP | TrueFoundry | MS MCP GW | AWS AgentCore |
|---------|-----------|---------|-------------|-----------|---------------|
| MCP Native | Full (4 transports) | Full | Full | HTTP only | Managed |
| Multi-Tenancy | Per-tenant isolation | Unknown | Unknown | Unknown | Per-account |
| Admin Console | Dashboard (SPA planned) | Dashboard | Dashboard | None | Console |
| Enterprise IAM | JWT/OAuth (SSO planned) | OAuth | OAuth | Azure AD | IAM |
| Compliance Packs | DORA/NIS2/ISO42001/EUAIA | SOC 2 only | None | None | SOC 2 |
| K8s Operator | CRDs (3 resources) | None | K8s | K8s native | Managed |
| Formal Verification | TLA+/Alloy (20+ props) | None | None | None | None |
| zk-SNARK Audit | Pedersen + Groth16 | None | None | None | None |
| Open Source | AGPL-3.0 (core) | Commercial | Commercial | MIT | Commercial |
| SDKs | Python/TS/Go/Java | Python | Python | None | Python |

---

## Packaging & Pricing (Target)

| Tier | Price | Tenants | Evals/Day | Features |
|------|-------|---------|-----------|----------|
| **Community** | Free (AGPL-3.0) | 1 | 10,000 | Full engine, CLI, file audit, SDKs |
| **Pro** | EUR 499/mo | 5 | 100,000 | + PostgreSQL audit, admin console, email support |
| **Enterprise** | Custom | Unlimited | Unlimited | + SSO/SAML, RBAC, compliance packs, K8s operator, SLA, Terraform |

---

## Go-To-Market: Italy-First Strategy

**Target pilots (Q3-Q4 2026):** UniCredit, Intesa Sanpaolo, Generali, Enel, Leonardo
**SI partners:** Accenture Italy, Reply, NTT Data Italia, Deloitte Italy
**12-month targets:** 3-5 design partners, 1-2 paid contracts, 500+ GitHub stars, 50+ monthly active tenants

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Admin console scope creep | Phase 45 3x overrun | MVP-first: audit viewer + agent inventory; policy editor in v2 |
| Enterprise IAM SAML edge cases | Phase 46 blocked | Start OIDC-only; SAML as follow-up |
| Italian pilot accounts slow to engage | GTM delayed | Parallel outreach to 5 targets; 3+ conferences |
| Competitor launches enterprise product first | Market weakened | Differentiate on compliance depth (DORA/NIS2 unique to EU) |
| Open-core tension | Community trust | Clear licensing: engine always AGPL; commercial = console + SSO + support |
| Team scaling (currently solo) | Execution bottleneck | Prioritize IAM + console (infrastructure), then recruit for GTM |

---

<details>
<summary>Completed Phases Archive (1-49)</summary>

| Phase | Name | Key Deliverable |
|-------|------|-----------------|
| 1-10 | Core Engine | Policy evaluation, path/domain/IP rules, DNS rebinding protection, audit logging |
| 11 | Capability Delegation | Scoped capability tokens with Ed25519 signatures |
| 12 | Injection Detection | Aho-Corasick + NFKC normalization, 5-layer decode |
| 13 | DLP | PII scanning, secret detection, parameter redaction |
| 14 | Tool Squatting | Homoglyph detection, version pin enforcement |
| 15 | Memory Poisoning | Behavioral fingerprinting, quarantine mechanism |
| 16 | Multimodal Injection | Image/audio/video content scanning |
| 17 | OAuth 2.1 / JWT / JWKS | Token validation, JWKS rotation, audience verification |
| 18 | ABAC | Cedar-style attribute-based access control with forbid-overrides |
| 19 | EU AI Act (initial) | Risk classification, Art 12 record-keeping, Merkle proofs |
| 20 | HTTP/WebSocket/gRPC Proxy | Multi-transport proxying with security checks |
| 21 | Context-Aware Policies | Evaluation context, time/geo/behavioral constraints |
| 22 | Policy Simulator | Simulate/batch/validate/diff/red-team endpoints |
| 23 | SOC 2 Controls | Access reviews, control evidence generation |
| 24 | EU AI Act Final | Art 50(2) explanations, Art 10 data governance |
| 25 | MCP 2025-06-18 Spec | Full spec compliance (elicitation, structured output, sampling) |
| 26 | Shadow AI & Governance | Unregistered agent detection, governance visibility |
| 27 | Kubernetes Deployment | Helm chart, leader election, service discovery |
| 28 | Distributed Tracing | OpenTelemetry integration, trace propagation |
| 29 | Smart Transport Fallback | Health-based routing, circuit breakers |
| 30 | CoSAI Framework | 38/38 coverage mapping |
| 31 | Adversa TOP 25 | 25/25 threat coverage |
| 32 | DORA Compliance | ICT risk management evidence |
| 33 | NIS2 Compliance | Cybersecurity evidence |
| 34 | Tool Discovery | Discovery service, semantic search, tool registry |
| 35 | Model Projector | Schema transformation across model families |
| 37 | Zero-Knowledge Audit | Pedersen commitments + Groth16 proofs |
| 38 | SOC 2 Type II | Access review reports, evidence packs |
| 39 | Agent Identity Federation | DID:PLC, cross-org trust anchors |
| 40 | Workflow Constraints | Sequence enforcement, least-agency tracking |
| 41 | OWASP ASI Coverage | ASI01-ASI10 comprehensive mapping |
| 42 | Performance Benchmarking | Sub-5ms P99, benchmark paper |
| 43 | Centralized Audit Store | PostgreSQL backend, S3 archival, streaming |
| 44 | Multi-Tenancy | Tenant isolation, per-tenant policies/audit/quotas |
| 47 | Policy Lifecycle | Versioned policies, approval workflows, staging, rollback |
| 48 | Compliance Evidence Packs | DORA/NIS2/ISO 42001/EU AI Act bundles |
| 49 | Kubernetes Operator | CRDs (VellavetoCluster, VellavetoPolicy, VellavetoTenant), HPA |

</details>

---

*This roadmap is a living document. Updated as market feedback, pilot learnings, and regulatory guidance emerge.*
