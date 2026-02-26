# Vellaveto Roadmap

> **Version:** 5.0.0-dev
> **Updated:** 2026-02-25
> **Current:** 7,877 Rust + 59 React + 12 Terraform, 433 Python, 127 Go, 119 TypeScript | 224 audit rounds | 56 phases complete
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
Q2 2026 (Done):  Phase 36 — Developer Experience & SDK Ecosystem         [P2] ✅
                  Phase 45 — Admin Console (React SPA)                    [P1] ✅
                  Phase 46 — Enterprise IAM (SSO/OIDC/SAML)              [P1] ✅
                  Phase 50 — Usage Metering & Billing Foundation          [P3] ✅ (core complete)

Q2 2026 (Done):  Phase 51 — Partner Integration Kit                      [P3] ✅
                  Phase 53 — Marketplace & Self-Service Onboarding       [P3] ✅

Q2 2026 (Done):  Phase 54 — Post-Quantum Cryptography Migration          [P3] ✅
Q4 2026:         Phase 55 — Performance & Scale Validation              [P3]
```

---

---

## Phase 54: Post-Quantum Cryptography Migration (P3) ✅

*Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures for audit integrity.*

- ML-DSA-65 hybrid signatures for checkpoints and rotation manifests
- Backward-compatible verification (v1 Ed25519-only checkpoints still verify)
- PQC key continuity enforcement and trusted key pinning
- Feature-gated via `pqc-hybrid` Cargo feature (fail-closed without feature)
- Domain separation: checkpoint vs manifest context bytes
- 10 dedicated PQC tests + all existing tests pass

**Delivered:** `vellaveto-audit/src/pqc.rs`, hybrid signing in checkpoints.rs/rotation.rs

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
Phase 36 (DX/SDK)          ──── ✅ complete ─────────────────────────────────┐
Phase 45 (Admin Console)   ──── ✅ complete ─────────────────────────────────┤
Phase 46 (Enterprise IAM)  ──── ✅ complete ─────────────────────────────────┤
Phase 50 (Billing)         ──── ✅ core complete (Postgres persistence TBD) ─┤
                                                                            │
Phase 51 (Partner Kit)     ──── ✅ complete ─────────────────────────────────┤
Phase 53 (Marketplace)     ──── ✅ complete ─────────────────────────────────┤
Phase 54 (PQC)             ──── ✅ complete ─────────────────────────────────┤
Phase 55 (Scale)           ──── depends on Phase 50 ✅ ──── UNBLOCKED ─────┘
```

**Critical path:** All predecessor phases complete. Only Phase 55 (Scale) remains.

---

## Competitive Comparison

| Feature | Vellaveto | MintMCP | TrueFoundry | MS MCP GW | AWS AgentCore |
|---------|-----------|---------|-------------|-----------|---------------|
| MCP Native | Full (4 transports) | Full | Full | HTTP only | Managed |
| Multi-Tenancy | Per-tenant isolation | Unknown | Unknown | Unknown | Per-account |
| Admin Console | React SPA (10 pages, RBAC) | Dashboard | Dashboard | None | Console |
| Enterprise IAM | OIDC/SAML/RBAC/SCIM | OAuth | OAuth | Azure AD | IAM |
| Compliance Packs | DORA/NIS2/ISO42001/EUAIA | SOC 2 only | None | None | SOC 2 |
| K8s Operator | CRDs (3 resources) | None | K8s | K8s native | Managed |
| Formal Verification | TLA+/Alloy (20+ props) | None | None | None | None |
| zk-SNARK Audit | Pedersen + Groth16 | None | None | None | None |
| Open Source | AGPL-3.0 (core) | Commercial | Commercial | MIT | Commercial |
| SDKs | Python/TS/Go/Java | Python | Python | None | Python |
| Self-Service Signup | API + marketplace | SaaS only | SaaS only | Portal | Console |
| Policy Templates | 11 presets | None | None | None | None |
| OpenAPI Spec | 135+ endpoints | Unknown | Unknown | Unknown | Managed |

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
<summary>Completed Phases Archive (1-54)</summary>

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
| 36 | Developer Experience | Java SDK (33 methods, 53 tests), VS Code extension, SVG graph export |
| 45 | Admin Console | React SPA: 10 pages, OIDC+API-key auth, RBAC nav, dark theme, 59 vitest tests |
| 46 | Enterprise IAM | OIDC, SAML 2.0, RBAC (4 roles, 14 perms), sessions, SCIM provisioning |
| 50 | Usage Metering & Billing | In-memory atomic counters, per-tenant quotas, Stripe/Paddle webhooks |
| 51 | Partner Integration Kit | CrewAI, Google ADK, OpenAI Agents integrations + Terraform provider + SI pilot kit |
| 53 | Marketplace & Onboarding | 11 policy presets, OpenAPI 3.0 spec (135+ endpoints), self-service signup, cloud marketplace docs |
| 54 | Post-Quantum Cryptography | Hybrid Ed25519+ML-DSA-65 (FIPS 204) checkpoint/manifest signatures, backward-compatible |

</details>

---

*This roadmap is a living document. Updated as market feedback, pilot learnings, and regulatory guidance emerge.*
