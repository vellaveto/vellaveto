# Vellaveto Roadmap

> **Version:** 6.0.0-dev
> **Updated:** 2026-02-26
> **Current:** 8,228 Rust + 59 React + 12 Terraform, 433 Python, 127 Go, 119 TypeScript | 225 audit rounds | 67 phases complete
> **Strategic position:** Agentic Security Control Plane & Policy Gateway
> **License:** AGPL-3.0 (core) + Commercial Enterprise

---

## Executive Summary

Vellaveto is an **Agentic Security Control Plane** — the platform through which enterprises govern, observe, and secure every AI agent tool call. Built on the most comprehensive open-source MCP runtime security engine (full MCP 2025-11-25 compliance, 4 transport layers, Cedar-style ABAC, formal verification, zero-knowledge audit trails), the roadmap extends into centralized multi-tenant governance, enterprise IAM, and commercial packaging.

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

Q2 2026 (Done):  Phase 56 — MCP 2025-11-25 Specification Update          [P1] ✅
                  Phase 57 — New SDK Integrations (Claude/Strands/MS)     [P1] ✅
                  Phase 58 — Compliance Registry Updates                  [P1] ✅

Q2 2026 (Done):  Phase 59 — Observability & SIEM Modernization           [P2] ✅
                  Phase 60 — Wasm Policy Plugin System                    [P2] ✅
                  Phase 61 — Rust Ecosystem Modernization                 [P2] ✅
                  Phase 62 — Advanced Security Features                   [P2] ✅

Q2 2026 (Done):  Phase 63 — Performance & Data Structure Optimization    [P3] ✅
                  Phase 64 — Cedar Policy Compatibility                   [P3] ✅
                  Phase 65 — A2A Protocol Hardening & MCP Registry        [P3] ✅
                  Phase 66 — Formal Verification Expansion                [P3] ✅

Q2 2026 (Done):  Phase 55 — Performance & Scale Validation              [P3] ✅
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

## Phases 56–66: v6.0 Platform Expansion ✅

*MCP spec update, new SDKs, compliance expansion, observability, Wasm plugins, advanced security, Cedar compatibility, A2A hardening, formal verification.*

### Phase 56: MCP 2025-11-25 Specification Update (P1) ✅
- Tasks primitive support (create/get/cancel, state tracking, policy evaluation)
- CIMD (Client ID Metadata Documents) for OAuth
- URL-mode elicitation for credential acquisition
- Cross App Access (XAA) with enterprise IdP tokens
- Machine-to-machine auth (OAuth client credentials)
- Step-up authorization (403 with required_scopes)

### Phase 57: New SDK Integrations (P1) ✅
- Anthropic Claude Agent SDK integration (Python + TypeScript)
- AWS Strands Agents SDK integration (Python)
- Microsoft Agent Framework SDK integration (Python)

### Phase 58: Compliance Registry Updates (P1) ✅
- Singapore MGF for Agentic AI — world's first agentic governance framework
- NIST AI RMF + AI 600-1 GenAI Profile (200+ mitigation actions)
- CSA Agentic Trust Framework — progressive autonomy levels

### Phase 59: Observability & SIEM Modernization (P2) ✅
- OCSF (Open Cybersecurity Schema Framework) export for AWS Security Lake, Datadog, Splunk
- OTLP exporter for OpenTelemetry Collector deployments

### Phase 60: Wasm Policy Plugin System (P2) ✅
- Wasmtime-based plugin host with fuel metering and memory limits
- WIT interface for custom policy evaluation
- Hot-reload on policy file change

### Phase 61: Rust Ecosystem Modernization (P2) ✅
- Enhanced cargo-deny configuration (advisories, licenses, sources)
- Tokio LTS pinning (1.42)
- SBOM generation script
- Edition 2024 migration plan

### Phase 62: Advanced Security Features (P2) ✅
- Multi-agent collusion detection (Shannon entropy, Pearson correlation, coordinated access)
- Cascading failure circuit breakers (chain depth limits, sliding window error rates)
- NHI identity lifecycle (ephemeral JIT credentials, rotation enforcement, inventory)

### Phase 63: Performance & Data Structure Optimization (P3) ✅
- Decision cache (LRU with TTL and generation-based invalidation)
- Batch policy evaluation API

### Phase 64: Cedar Policy Compatibility (P3) ✅
- Cedar policy import/export for AWS AgentCore/CNCF Cedar interoperability
- Permit/forbid with conditions, entity type mapping

### Phase 65: A2A Protocol Hardening & MCP Registry (P3) ✅
- Agent Card Ed25519 signature enforcement with constant-time comparison
- MCP Registry client with TTL-based cache and identity verification
- DPoP (RFC 9449) token binding with JTI replay detection

### Phase 66: Formal Verification Expansion (P3) ✅
- TLA+: MCPTaskLifecycle (5 safety + 2 liveness properties)
- TLA+: CascadingFailure (5 safety + 2 liveness properties)
- Kani: 5 proof harnesses (fail-closed, path normalization, saturating arithmetic)

**Delivered:** 8,208 Rust tests passing, 11 compliance frameworks, 8 SDK integrations, 33 TLA+ properties + 5 Kani harnesses

---

## Phase 55: Performance & Scale Validation (P3) ✅

*Validated control plane architecture at enterprise scale.*

- 100K evaluations/second sustained throughput (engine-level, verified via Criterion + stress tests)
- Multi-tenant isolation verified under concurrent load (zero cross-tenant leakage)
- Audit pipeline throughput: 50K entries/sec (file-based, verified via stress tests)
- P99 < 5ms at 100 policies (measured < 200µs)
- Chaos testing: policy reload, corrupt audit recovery, concurrent compilation, edge-case inputs
- Benchmark report published (`docs/BENCHMARK_REPORT.md`)

**Delivered:** 15 Criterion throughput benchmarks, 16 integration stress/chaos tests, k6 load test scripts, benchmark report. 8,229 Rust tests passing.

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
                                                                            │
Phase 56 (MCP 2025-11-25)  ──── ✅ complete ─────────────────────────────────┤
Phase 57 (New SDKs)        ──── ✅ complete ─────────────────────────────────┤
Phase 58 (Compliance)      ──── ✅ complete ─────────────────────────────────┤
Phase 59 (Observability)   ──── ✅ complete ─────────────────────────────────┤
Phase 60 (Wasm Plugins)    ──── ✅ complete ─────────────────────────────────┤
Phase 61 (Rust Modernize)  ──── ✅ complete ─────────────────────────────────┤
Phase 62 (Adv. Security)   ──── ✅ complete ─────────────────────────────────┤
Phase 63 (Performance)     ──── ✅ complete ─────────────────────────────────┤
Phase 64 (Cedar Compat)    ──── ✅ complete ─────────────────────────────────┤
Phase 65 (A2A Hardening)   ──── ✅ complete ─────────────────────────────────┤
Phase 66 (Formal Verif.)   ──── ✅ complete ─────────────────────────────────┤
                                                                            │
Phase 55 (Scale)           ──── ✅ complete ─────────────────────────────────┘
```

**All phases complete.** 67 phases delivered across core engine, security, compliance, SDKs, infrastructure, and performance validation.

---

## Competitive Comparison

| Feature | Vellaveto | MintMCP | TrueFoundry | MS MCP GW | AWS AgentCore |
|---------|-----------|---------|-------------|-----------|---------------|
| MCP Native | Full (4 transports, 2025-11-25) | Full | Full | HTTP only | Managed |
| Policy Language | TOML + Cedar import/export | Custom | Custom | Custom | Cedar |
| Multi-Tenancy | Per-tenant isolation | Unknown | Unknown | Unknown | Per-account |
| Admin Console | React SPA (10 pages, RBAC) | Dashboard | Dashboard | None | Console |
| Enterprise IAM | OIDC/SAML/RBAC/SCIM/DPoP | OAuth | OAuth | Azure AD | IAM |
| Compliance Packs | 11 frameworks (DORA/NIS2/ISO42001/EUAIA/Singapore MGF/NIST/CSA ATF) | SOC 2 only | None | None | SOC 2 |
| Wasm Plugins | User-extensible (Wasmtime) | None | None | None | None |
| K8s Operator | CRDs (3 resources) | None | K8s | K8s native | Managed |
| Formal Verification | TLA+ + Alloy + Kani (33 props + 5 harnesses) | None | None | None | None |
| zk-SNARK Audit | Pedersen + Groth16 | None | None | None | None |
| Observability | OTel GenAI + OCSF + OTLP | Basic | Basic | CloudWatch | CloudWatch |
| Open Source | AGPL-3.0 (core) | Commercial | Commercial | MIT | Commercial |
| SDKs | 8 frameworks (Python/TS/Go/Java + Claude/Strands/MS) | Python | Python | None | Python |
| A2A Security | Enforced Ed25519 signing | None | None | None | None |
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
<summary>Completed Phases Archive (1-66)</summary>

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
| 56 | MCP 2025-11-25 Spec | Tasks primitive, CIMD, XAA, M2M auth, step-up authorization |
| 57 | New SDK Integrations | Claude Agent SDK, AWS Strands, Microsoft Agent Framework |
| 58 | Compliance Registries | Singapore MGF, NIST AI 600-1, CSA Agentic Trust Framework |
| 59 | Observability/SIEM | OCSF export, OTLP exporter, OTel GenAI semantic conventions |
| 60 | Wasm Policy Plugins | Wasmtime host, fuel metering, WIT interface, hot-reload |
| 61 | Rust Modernization | cargo-deny, Tokio LTS, SBOM generation, Edition 2024 plan |
| 62 | Advanced Security | Collusion detection, cascading circuit breakers, NHI lifecycle |
| 63 | Performance Optimization | Decision cache (LRU+TTL), batch evaluation API |
| 64 | Cedar Compatibility | Cedar policy import/export for AgentCore/CNCF interop |
| 65 | A2A Hardening | Agent Card signatures, MCP Registry, DPoP token binding |
| 66 | Formal Verification | TLA+ task lifecycle + cascading failure, 5 Kani proof harnesses |
| 55 | Performance & Scale | 100K eval/s, P99 < 5ms, chaos testing, 16 stress tests, k6 load scripts |

</details>

---

*This roadmap is a living document. Updated as market feedback, pilot learnings, and regulatory guidance emerge.*
