# Vellaveto — Agent Control Plane Roadmap v5.0

> **Version:** 5.0.0-dev
> **Generated:** 2026-02-23
> **Baseline:** v4.0.0-dev — 6,293 Rust tests, 316 Python SDK tests, 40 Go SDK tests, 64 TypeScript SDK tests, 24 fuzz targets, 196 audit rounds, 40 phases complete
> **Scope:** 18 months (Q2 2026 – Q3 2027), quarterly milestones
> **Strategic pivot:** From MCP runtime security engine → **Agentic Security Control Plane**

---

## Executive Summary

Vellaveto v4.0 is the most comprehensive open-source MCP runtime security engine available: full MCP 2025-11-25 compliance, 3 transport layers, Cedar-style ABAC, EU AI Act evidence, SOC 2 access reviews, formal verification, zero-knowledge audit trails, multimodal injection detection, and 196 adversarial audit rounds.

The v5.0 roadmap repositions Vellaveto as an **Agentic Security Control Plane & Policy Gateway** — the platform through which enterprises govern, observe, and secure every AI agent tool call. This shift is driven by five market signals:

1. **Enterprises need centralized agent governance**, not per-agent security. The explosion of AI agents (LangChain, CrewAI, AutoGen, Google ADK, OpenAI Agents SDK) demands a unified control plane.
2. **Regulatory pressure is accelerating**: EU AI Act enforcement (Aug 2026), DORA (Jan 2025 for ICT risk, ongoing for AI), NIS2 (Oct 2024 transposition), ISO 42001. Enterprises need compliance evidence packs, not raw audit logs.
3. **The market is nascent**: MintMCP, TrueFoundry, Lunar.dev, Microsoft MCP Gateway, and AWS AgentCore are entering, but none offer enterprise-grade policy management with an admin UI.
4. **Italy-first GTM**: UniCredit, Intesa Sanpaolo, Generali, and Enel are early AI adopters under heavy regulatory pressure (Banca d'Italia + DORA + NIS2). Italian system integrators (Accenture Italy, Reply, NTT Data Italia) are the distribution channel.
5. **Open-core monetization**: AGPL-3.0 core engine + commercial Enterprise license (admin console, SSO, multi-tenancy, SLA).

### What's Missing for Control Plane (Gap Analysis)

| Gap | Current State | Required for Control Plane |
|-----|---------------|---------------------------|
| **Multi-Tenancy** | Single-tenant only | Tenant isolation, per-tenant policies, per-tenant audit |
| **Enterprise IAM** | JWT/OAuth stub | SAML 2.0/OIDC SSO, Okta/Azure AD/Keycloak integration |
| **Admin Console** | Dashboard SVG charts (server-rendered) | React SPA with RBAC, policy editor, agent inventory, audit viewer |
| **Centralized Audit Store** | File-based JSONL + Merkle | PostgreSQL/ClickHouse + S3/GCS archival + real-time streaming |
| **Policy Lifecycle** | Static TOML config | Versioned policies with approval workflows, diff/rollback, staging environments |
| **Compliance Evidence Packs** | Raw registry data | Pre-packaged DORA/NIS2/ISO 42001/EU AI Act evidence bundles |
| **Billing/Metering** | None | Per-tenant usage metering, evaluation counts, storage |
| **Helm/Operator** | Basic Helm chart | K8s Operator with CRDs (VellavetoPolicy, VellavetoTenant) |

### Research Sources

| Source | Relevance |
|--------|-----------|
| [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Current protocol baseline |
| [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | Full roll-out: 2 Aug 2027 |
| [DORA (Regulation 2022/2554)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) | ICT risk management for financial entities |
| [NIS2 (Directive 2022/2555)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) | Cybersecurity for essential/important entities |
| [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html) | AI management system standard |
| [Gravitee State of AI Agent Security 2026](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control) | Enterprise security gaps |
| [Lakera Agent Security Report Q4 2025](https://www.lakera.ai) | 88% incident rate |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Threat catalog |
| [MintMCP](https://mintmcp.com) | SOC 2 competitor |
| [TrueFoundry MCP Gateway](https://www.truefoundry.com) | Sub-3ms latency competitor |
| [Microsoft MCP Gateway](https://github.com/microsoft/mcp-gateway) | K8s-native competitor |
| [AWS AgentCore](https://aws.amazon.com/agentcore) | Managed agent runtime competitor |
| [Cedar Policy Language](https://www.cedarpolicy.com) | Policy-as-code reference |

---

## Priority Matrix

| Priority | Theme | Business Driver | Deadline Pressure |
|----------|-------|-----------------|-------------------|
| **P0** | Centralized Audit Store + Multi-Tenancy | Enterprise readiness, pilot deployments | Q2–Q3 2026 |
| **P1** | Admin Console + Enterprise IAM + Policy Lifecycle | Enterprise sales, partner demos | Q3–Q4 2026 |
| **P2** | Compliance Evidence Packs + K8s Operator | Regulatory deadlines (DORA, NIS2, EU AI Act) | Q4 2026 |
| **P3** | Billing/Metering + Marketplace + Partner Integrations | Revenue, GTM scale | H1 2027 |

---

## Timeline Overview

```
Q2 2026 (Apr–Jun):  Phase 43 — Centralized Audit Store               [P0]
                     Phase 44 — Multi-Tenancy Foundation               [P0]

Q3 2026 (Jul–Sep):  Phase 45 — Admin Console (React SPA)              [P1]
                     Phase 46 — Enterprise IAM (SSO/OIDC/SAML)         [P1]

Q4 2026 (Oct–Dec):  Phase 47 — Policy Lifecycle Management            [P1]
                     Phase 48 — Compliance Evidence Packs              [P2]
                     Phase 49 — Kubernetes Operator (CRDs)             [P2]

Q1 2027 (Jan–Mar):  Phase 50 — Usage Metering & Billing Foundation    [P3]
                     Phase 51 — Partner Integration Kit                [P3]
                     Phase 52 — Performance & Scale Validation         [P3]

Q2–Q3 2027:         Phase 53 — Marketplace & Self-Service Onboarding  [P3]
```

---

## Q2 2026 (Apr–Jun): Data Platform Foundation

### Phase 43: Centralized Audit Store (P0)

*Focus: Replace file-based JSONL audit with a production-grade data platform — the prerequisite for multi-tenancy, admin console, and compliance evidence generation.*

The current `AuditLogger` in `vellaveto-audit/src/lib.rs` writes to local JSONL files with SHA-256 hash chains, Merkle proofs, and Ed25519 checkpoints. This is correct for single-node deployments but insufficient for:
- Multi-node clusters (each node writes its own file)
- Real-time search/aggregation (JSONL requires full scan)
- Long-term retention (no native archival tier)
- Admin console (cannot query by time range, agent, verdict without loading entire file)

#### 43.1 Database Backend

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `AuditStore` trait abstracting read/write/query operations | P0 | 3 days | — | `vellaveto-audit` |
| Implement `FileAuditStore` (existing JSONL, backward compatible) | P0 | 2 days | Trait | `vellaveto-audit` |
| Implement `PostgresAuditStore` (sqlx, async, connection pool) | P0 | 5 days | Trait | `vellaveto-audit` |
| Database schema: `audit_entries` table with BRIN index on timestamp, GIN on metadata | P0 | 2 days | PostgreSQL | `vellaveto-audit` |
| Hash-chain verification across distributed writers (sequence allocation via `pg_advisory_lock`) | P0 | 3 days | Schema | `vellaveto-audit` |
| Merkle proof storage in PostgreSQL (materialized view or separate table) | P0 | 2 days | Schema | `vellaveto-audit` |
| `AuditStoreConfig` with backend selection (`file` / `postgres` / `clickhouse`) | P0 | 1 day | — | `vellaveto-config` |

#### 43.2 Object Storage Archival

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `ArchivalBackend` trait (put/get/list with prefix) | P0 | 1 day | — | `vellaveto-audit` |
| Implement `S3ArchivalBackend` (aws-sdk-s3, async) | P0 | 3 days | Trait | `vellaveto-audit` |
| Implement `GcsArchivalBackend` (google-cloud-storage) | P2 | 2 days | Trait | `vellaveto-audit` |
| Retention policy: automatic archival after configurable days (default 90) | P0 | 2 days | Backend | `vellaveto-audit` |
| Compressed archival format (zstd + Parquet for analytics) | P1 | 2 days | Backend | `vellaveto-audit` |

#### 43.3 Real-Time Streaming

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `AuditStream` trait (publish/subscribe) | P1 | 1 day | — | `vellaveto-audit` |
| Implement `NatsAuditStream` (NATS JetStream) | P1 | 3 days | Trait | `vellaveto-audit` |
| WebSocket audit stream endpoint for admin console | P1 | 2 days | Stream | `vellaveto-server` |
| SIEM connector: Splunk HEC + Elasticsearch bulk API | P2 | 3 days | Stream | `vellaveto-audit` |

### Phase 43 Exit Criteria
- [ ] PostgreSQL backend passes all existing audit tests
- [ ] Hash-chain integrity maintained across 3+ concurrent writers
- [ ] S3 archival with configurable retention policy
- [ ] WebSocket real-time audit stream functional
- [ ] FileAuditStore remains default (zero-config backward compatibility)
- [ ] No new `unwrap()` in library code

**Estimated Duration:** 6 weeks

---

### Phase 44: Multi-Tenancy Foundation (P0)

*Focus: Tenant isolation for audit data, policies, and agent inventories — enabling a single Vellaveto deployment to serve multiple teams or organizations.*

#### 44.1 Tenant Model

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `Tenant` type: id, name, created_at, settings, quotas | P0 | 2 days | — | `vellaveto-types` |
| Define `TenantConfig` with per-tenant policy sets, agent inventories, audit retention | P0 | 2 days | Type | `vellaveto-config` |
| Tenant resolution from request: `X-Vellaveto-Tenant` header or JWT claim `tenant_id` | P0 | 2 days | Type | `vellaveto-http-proxy` |
| Tenant-scoped policy evaluation: each tenant has its own PolicyEngine instance | P0 | 3 days | Config | `vellaveto-engine` |
| Tenant-scoped audit writes: `audit_entries.tenant_id` column (PostgreSQL) | P0 | 2 days | Phase 43 | `vellaveto-audit` |

#### 44.2 Tenant Isolation

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Row-level security in PostgreSQL (tenant_id filter on all queries) | P0 | 2 days | Schema | `vellaveto-audit` |
| Per-tenant rate limiting (separate token buckets) | P0 | 2 days | Tenant resolution | `vellaveto-http-proxy` |
| Per-tenant quota enforcement: max evaluations/day, max policies, max agents | P0 | 2 days | Config | `vellaveto-engine` |
| Tenant CRUD API: `POST/GET/PUT/DELETE /api/tenants` (admin-only) | P0 | 2 days | Model | `vellaveto-server` |
| Tenant-scoped SDK methods: `client = VellavetoClient(tenant="acme")` | P1 | 2 days | API | SDKs |

### Phase 44 Exit Criteria
- [ ] Tenant A cannot read/modify Tenant B's audit entries, policies, or agent data
- [ ] Per-tenant rate limits enforced independently
- [ ] Tenant quota violation produces HTTP 429 with `Retry-After` header
- [ ] Default tenant for backward compatibility (single-tenant mode unchanged)
- [ ] SDK clients accept optional `tenant` parameter

**Estimated Duration:** 4 weeks

---

## Q3 2026 (Jul–Sep): Enterprise User Experience

### Phase 45: Admin Console (React SPA) (P1)

*Focus: A web-based admin console that replaces CLI/API interactions for security teams and compliance officers.*

#### 45.1 Core UI Framework

| Task | Priority | Effort | Depends On | Crate/Dir |
|------|----------|--------|------------|-----------|
| React + TypeScript + Vite scaffold with Tailwind CSS | P1 | 2 days | — | `console/` |
| Authentication: OIDC login flow, token refresh, session management | P1 | 3 days | Phase 46 | `console/` |
| RBAC: Admin, Operator, Viewer, Auditor roles | P1 | 2 days | Auth | `console/` |
| Layout: sidebar navigation, tenant selector, user menu | P1 | 2 days | Scaffold | `console/` |
| Server-side: `GET /console/*` serves SPA, `GET /api/console/me` user info | P1 | 1 day | Auth | `vellaveto-server` |

#### 45.2 Dashboard & Monitoring

| Task | Priority | Effort | Depends On | Crate/Dir |
|------|----------|--------|------------|-----------|
| Real-time verdict stream (WebSocket) with sparkline charts | P1 | 3 days | Phase 43.3 | `console/` |
| Agent inventory: list, search, registration status, last activity | P1 | 2 days | Phase 26 | `console/` |
| Tool inventory: registered tools, sensitivity levels, usage stats | P1 | 2 days | Phase 34 | `console/` |
| Shadow AI alerts: unregistered agents, unapproved tools | P1 | 2 days | Phase 26 | `console/` |
| Health dashboard: cluster status, transport health, circuit breakers | P1 | 2 days | Phase 29 | `console/` |

#### 45.3 Audit Viewer

| Task | Priority | Effort | Depends On | Crate/Dir |
|------|----------|--------|------------|-----------|
| Searchable audit log: time range, agent, tool, verdict, full-text | P1 | 3 days | Phase 43 | `console/` |
| Audit entry detail: verdict explanation, policy chain, parameters (redacted) | P1 | 2 days | Phase 24 | `console/` |
| Export: CSV, JSONL, PDF report | P1 | 2 days | Viewer | `console/` |
| Real-time tail with filtering | P1 | 1 day | Phase 43.3 | `console/` |

#### 45.4 Policy Editor

| Task | Priority | Effort | Depends On | Crate/Dir |
|------|----------|--------|------------|-----------|
| Visual policy editor: TOML syntax highlighting with live validation | P1 | 3 days | — | `console/` |
| Policy simulator: test actions against policies with visual verdict flow | P1 | 3 days | Phase 22 | `console/` |
| Policy diff: side-by-side comparison of versions | P1 | 2 days | Phase 47 | `console/` |

### Phase 45 Exit Criteria
- [ ] Login with OIDC, role-based navigation
- [ ] Real-time verdict stream with filtering
- [ ] Agent and tool inventories with search
- [ ] Audit log viewer with time range and text search
- [ ] Policy editor with syntax validation
- [ ] Responsive design (desktop + tablet)
- [ ] Accessibility: WCAG 2.1 AA

**Estimated Duration:** 8 weeks

---

### Phase 46: Enterprise IAM (SSO/OIDC/SAML) (P1)

*Focus: Integrate with enterprise identity providers for admin console authentication and agent identity resolution.*

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| OIDC provider integration: Okta, Azure AD (Entra ID), Keycloak | P1 | 4 days | — | `vellaveto-server` |
| SAML 2.0 SP implementation for legacy enterprise IdPs | P1 | 4 days | — | `vellaveto-server` |
| Admin console session management: secure cookies, CSRF, idle timeout | P1 | 2 days | OIDC/SAML | `vellaveto-server` |
| RBAC model: Admin → Operator → Viewer → Auditor with tenant scoping | P1 | 2 days | Session | `vellaveto-server` |
| SCIM 2.0 provisioning: auto-create/deactivate users from IdP | P2 | 3 days | RBAC | `vellaveto-server` |
| Agent identity resolution from enterprise IdP claims (map JWT claims to AgentIdentity) | P1 | 2 days | OIDC | `vellaveto-mcp` |
| `IamConfig` with provider selection, client_id/secret (env var), callback URLs | P1 | 1 day | — | `vellaveto-config` |

### Phase 46 Exit Criteria
- [ ] OIDC login working with Okta and Azure AD
- [ ] SAML 2.0 login working with at least one IdP
- [ ] RBAC enforced: Viewers cannot modify policies
- [ ] Session idle timeout configurable (default 30 min)
- [ ] Agent identity resolved from enterprise JWT claims

**Estimated Duration:** 4 weeks

---

## Q4 2026 (Oct–Dec): Governance & Compliance

### Phase 47: Policy Lifecycle Management (P1)

*Focus: Versioned policies with approval workflows, staging environments, and rollback — replacing static TOML config with a policy-as-code pipeline.*

#### 47.1 Policy Versioning

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `PolicyVersion` type: id, version, policy, created_by, created_at, status (draft/staging/active/archived) | P1 | 2 days | — | `vellaveto-types` |
| Policy store: PostgreSQL table with version history, immutable once active | P1 | 3 days | Phase 43 | `vellaveto-config` |
| Policy diff: structural comparison between versions (JSON patch format) | P1 | 2 days | Store | `vellaveto-config` |
| Policy rollback: revert to previous active version (creates new version) | P1 | 2 days | Store | `vellaveto-config` |

#### 47.2 Approval Workflows

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `PolicyApprovalWorkflow`: required_approvers, auto_approve_for_roles | P1 | 2 days | — | `vellaveto-types` |
| Approval API: `POST /api/policies/{id}/versions/{v}/approve` | P1 | 2 days | Workflow | `vellaveto-server` |
| Notification hooks: webhook on policy change requiring approval | P1 | 2 days | API | `vellaveto-server` |
| Audit trail: who approved, when, what changed | P1 | 1 day | API | `vellaveto-audit` |

#### 47.3 Staging Environments

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Policy staging: evaluate new policy version alongside active version (shadow mode) | P1 | 3 days | Versioning | `vellaveto-engine` |
| Staging metrics: comparison report (would-allow vs would-deny differences) | P1 | 2 days | Staging | `vellaveto-engine` |
| Promote: move staging policy to active after validation period | P1 | 1 day | Staging | `vellaveto-server` |

### Phase 47 Exit Criteria
- [ ] Policy versions stored with full history
- [ ] Policy diff shows structural changes between versions
- [ ] Approval workflow with configurable required approvers
- [ ] Staging mode runs new policy alongside active without affecting verdicts
- [ ] Rollback creates new version from previous active version
- [ ] All policy changes audited (who, when, what)

**Estimated Duration:** 5 weeks

---

### Phase 48: Compliance Evidence Packs (P2)

*Focus: Pre-packaged compliance evidence bundles for DORA, NIS2, ISO 42001, and EU AI Act — reducing auditor preparation from weeks to hours.*

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `ComplianceEvidencePack` type: framework, period, sections, evidence items, attestation | P2 | 2 days | — | `vellaveto-types` |
| **DORA evidence pack**: ICT risk management (Art 5-16), incident reporting (Art 17-23), digital resilience testing (Art 24-27), third-party risk (Art 28-44) | P2 | 5 days | Pack type | `vellaveto-audit` |
| **NIS2 evidence pack**: risk management (Art 21), incident notification (Art 23), supply chain security (Art 22) | P2 | 3 days | Pack type | `vellaveto-audit` |
| **ISO 42001 evidence pack**: AI policy (5.2), risk assessment (6.1), AI system lifecycle (8.4), performance evaluation (9.1) | P2 | 3 days | Pack type | `vellaveto-audit` |
| **EU AI Act evidence pack**: Art 9 (risk management), Art 10 (data governance), Art 12 (record-keeping), Art 13 (transparency), Art 14 (human oversight), Art 15 (accuracy/robustness) | P2 | 3 days | Pack type, Phase 24 | `vellaveto-audit` |
| Evidence pack generation API: `GET /api/compliance/evidence-pack/{framework}` (JSON/PDF) | P2 | 2 days | All packs | `vellaveto-server` |
| PDF renderer: professional evidence pack with cover page, TOC, section evidence, gap analysis | P2 | 3 days | API | `vellaveto-audit` |
| Admin console: compliance dashboard with framework coverage meters, evidence download | P2 | 2 days | API | `console/` |

### Phase 48 Exit Criteria
- [x] DORA evidence pack covers Articles 5-44 with mapped Vellaveto evidence (27 articles, 13 capabilities)
- [x] NIS2 evidence pack covers Articles 21-23 (16 articles, 12 capabilities)
- [x] ISO 42001 evidence pack covers key clauses (reuses existing registry)
- [x] EU AI Act evidence pack covers Articles 9-15 (reuses existing registry)
- [x] HTML renderer produces audit-ready documents (browser print-to-PDF, no new dep)
- [x] Evidence packs generated at request time with 60s cache TTL

**Estimated Duration:** 5 weeks

---

### Phase 49: Kubernetes Operator (CRDs) (P2)

*Focus: Replace Helm chart with a Kubernetes Operator that manages Vellaveto deployments declaratively via Custom Resource Definitions.*

| Task | Priority | Effort | Depends On | Crate/Dir |
|------|----------|--------|------------|-----------|
| Define CRDs: `VellavetoCluster`, `VellavetoPolicy`, `VellavetoTenant` | P2 | 3 days | — | `operator/` |
| Operator controller (kube-rs): reconciliation loop for cluster lifecycle | P2 | 5 days | CRDs | `operator/` |
| `VellavetoPolicy` reconciler: sync K8s resources to policy store | P2 | 3 days | Phase 47 | `operator/` |
| `VellavetoTenant` reconciler: create/update tenant with quotas | P2 | 2 days | Phase 44 | `operator/` |
| Auto-scaling: HPA based on evaluation rate metrics | P2 | 2 days | Controller | `operator/` |
| OLM (Operator Lifecycle Manager) packaging for Red Hat Marketplace | P3 | 2 days | Operator | `operator/` |

### Phase 49 Exit Criteria
- [ ] `kubectl apply -f vellaveto-cluster.yaml` creates a functional deployment
- [ ] Policy changes via `VellavetoPolicy` CRD propagate within 30 seconds
- [ ] Tenant CRUD via `VellavetoTenant` CRD
- [ ] Operator handles upgrades (rolling update, canary)
- [ ] OLM bundle published

**Estimated Duration:** 4 weeks

---

## Q1 2027 (Jan–Mar): Commercial Foundation

### Phase 50: Usage Metering & Billing Foundation (P3)

*Focus: Per-tenant usage tracking for commercial licensing — the prerequisite for paid tiers.*

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Define `UsageMeter` trait: record evaluation, query usage by tenant/period | P3 | 2 days | — | `vellaveto-types` |
| Implement `PostgresUsageMeter` with hourly rollup tables | P3 | 3 days | Phase 43 | `vellaveto-audit` |
| Per-tenant usage API: `GET /api/tenants/{id}/usage` with period aggregation | P3 | 2 days | Meter | `vellaveto-server` |
| Usage dashboard in admin console: per-tenant charts, quota alerts | P3 | 2 days | API | `console/` |
| Stripe integration: metered billing webhook | P3 | 3 days | Meter | `vellaveto-server` |
| License enforcement: Community (1 tenant, 10K evals/day), Pro (5 tenants, 100K), Enterprise (unlimited) | P3 | 2 days | Meter | `vellaveto-engine` |

### Phase 50 Exit Criteria
- [ ] Per-tenant evaluation count tracked with hourly rollup
- [ ] Usage API returns accurate counts for arbitrary time ranges
- [ ] Community tier enforces 10K evaluations/day limit
- [ ] Stripe metered billing functional for Pro/Enterprise

**Estimated Duration:** 4 weeks

---

### Phase 51: Partner Integration Kit (P3)

*Focus: Pre-packaged integrations for system integrator partners and enterprise AI platforms.*

| Task | Priority | Effort | Depends On | Dir |
|------|----------|--------|------------|-----|
| **LangChain/LangGraph integration**: middleware that wraps tool execution with Vellaveto evaluation | P3 | 3 days | — | `sdk/python` |
| **CrewAI integration**: crew-level policy enforcement via before/after hooks | P3 | 3 days | — | `sdk/python` |
| **Google ADK integration**: tool validation callback | P3 | 2 days | — | `sdk/python` |
| **OpenAI Agents SDK integration**: function calling interceptor | P3 | 2 days | — | `sdk/python` |
| **Terraform provider**: manage policies, tenants, and users via IaC | P3 | 5 days | Phase 44, 47 | `terraform/` |
| **SI pilot kit**: deployment guide, reference architecture, demo script, slide deck | P3 | 3 days | All above | `docs/pilot-kit/` |
| **Integration test suite**: end-to-end tests for each framework integration | P3 | 3 days | All above | `vellaveto-integration` |

### Phase 51 Exit Criteria
- [ ] LangChain and CrewAI integrations published to PyPI
- [ ] Terraform provider manages tenants and policies
- [ ] SI pilot kit contains deployment guide, demo, and slides
- [ ] Each integration has ≥10 tests

**Estimated Duration:** 4 weeks

---

### Phase 52: Performance & Scale Validation (P3)

*Focus: Validate that the control plane architecture meets enterprise scale requirements.*

| Task | Priority | Effort | Depends On | Crate |
|------|----------|--------|------------|-------|
| Load test: 100K evaluations/second sustained on 3-node cluster | P3 | 3 days | Phase 43, 44 | `vellaveto-integration` |
| Multi-tenant isolation test: verify zero cross-tenant data leakage under load | P3 | 2 days | Phase 44 | `vellaveto-integration` |
| Audit write throughput: PostgreSQL backend at 50K entries/second | P3 | 2 days | Phase 43 | `vellaveto-integration` |
| P99 latency regression test: < 5ms evaluation at 10K concurrent connections | P3 | 2 days | — | `vellaveto-integration` |
| Memory profiling: < 200MB per tenant at 1K policies | P3 | 2 days | Phase 44 | `vellaveto-integration` |
| Chaos testing: pod kill, network partition, database failover | P3 | 3 days | Phase 49 | `vellaveto-integration` |
| Publish benchmark paper (extend Phase 42) | P3 | 5 days | All above | `docs/` |

### Phase 52 Exit Criteria
- [ ] 100K eval/sec sustained for 1 hour on 3-node cluster
- [ ] Zero cross-tenant leakage verified
- [ ] PostgreSQL audit write throughput ≥ 50K entries/sec
- [ ] P99 < 5ms at 10K concurrent connections
- [ ] Chaos tests pass: system recovers within 30 seconds

**Estimated Duration:** 4 weeks

---

## Q2–Q3 2027: Growth & Scale

### Phase 53: Marketplace & Self-Service Onboarding (P3)

*Focus: Self-service tenant onboarding, policy marketplace, and community ecosystem.*

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Self-service signup: tenant creation with email verification | P3 | 3 days | Phase 44, 46 |
| Policy marketplace: community-contributed policy templates (OWASP, SOC 2, EU AI Act) | P3 | 5 days | Phase 47 |
| One-click deploy: AWS Marketplace AMI, Azure Marketplace VM, GCP Marketplace | P3 | 5 days | Phase 49 |
| Documentation portal: interactive API docs (OpenAPI/Swagger), quickstart wizard | P3 | 3 days | — |
| Community forum: GitHub Discussions + Discord integration | P3 | 1 day | — |

### Phase 53 Exit Criteria
- [ ] Self-service onboarding functional (signup → tenant → first evaluation in < 5 minutes)
- [ ] ≥ 10 policy templates in marketplace
- [ ] Available on at least 2 cloud marketplaces

**Estimated Duration:** 4 weeks

---

## Competitive Comparison (v5.0 Target)

| Feature | Vellaveto v5.0 | MintMCP | TrueFoundry | Microsoft MCP GW | AWS AgentCore |
|---------|---------------|---------|-------------|-------------------|---------------|
| **MCP Native** | Full (3 transports) | Full | Full | Full (HTTP) | Managed |
| **Multi-Tenancy** | Per-tenant isolation | Unknown | Unknown | Unknown | Per-account |
| **Admin Console** | React SPA + RBAC | Dashboard | Dashboard | None | Console |
| **Enterprise IAM** | OIDC + SAML + SCIM | OAuth | OAuth | Azure AD | IAM |
| **Policy Lifecycle** | Versioned + staging + approval | None | Basic | YAML | IAM policies |
| **Compliance Packs** | DORA/NIS2/ISO42001/EUAIA | SOC 2 only | None | None | SOC 2 |
| **K8s Operator** | CRDs (Policy/Tenant/Cluster) | None | K8s | K8s native | Managed |
| **Centralized Audit** | PostgreSQL + S3 + streaming | None | None | None | CloudTrail |
| **Billing/Metering** | Per-tenant usage | SaaS | SaaS | Free | Pay-per-use |
| **Latency** | < 5ms P99 | Unknown | < 3ms claimed | Unknown | Unknown |
| **Policy Engine** | ABAC + RBAC + Cedar + workflows | Basic | Basic | YAML | IAM-based |
| **Formal Verification** | TLA+/Alloy (20 properties) | None | None | None | None |
| **zk-SNARK Audit** | Pedersen + Groth16 | None | None | None | None |
| **Open Source** | AGPL-3.0 (core) | Commercial | Commercial | MIT | Commercial |

---

## Packaging & Pricing (Target)

| Tier | Price | Tenants | Evals/Day | Features |
|------|-------|---------|-----------|----------|
| **Community** | Free (AGPL-3.0) | 1 | 10,000 | Full engine, CLI, file audit, SDKs |
| **Pro** | €499/mo | 5 | 100,000 | + PostgreSQL audit, admin console (Viewer+Operator), email support |
| **Enterprise** | Custom | Unlimited | Unlimited | + SSO/SAML, RBAC, compliance packs, K8s operator, SLA, Terraform provider |

---

## Phase Dependency Map

```
Phase 43 (Audit Store)   ──── prerequisite for almost everything ────────┐
Phase 44 (Multi-Tenancy) ──── depends on Phase 43 ──────────────────────┤
                                                                         │
Phase 45 (Admin Console) ──── depends on Phase 43 + 46 ────────────────┤
Phase 46 (Enterprise IAM)──── independent ──────────────────────────────┤
                                                                         │
Phase 47 (Policy Lifecycle)── depends on Phase 43 ──────────────────────┤
Phase 48 (Compliance)    ──── depends on Phase 43 + 44 (per-tenant) ───┤
Phase 49 (K8s Operator)  ──── depends on Phase 44 + 47 ────────────────┤
                                                                         │
Phase 50 (Billing)       ──── depends on Phase 43 + 44 ────────────────┤
Phase 51 (Partner Kit)   ──── depends on Phase 44 + 47 ────────────────┤
Phase 52 (Scale)         ──── depends on Phase 43 + 44 + 49 ───────────┤
Phase 53 (Marketplace)   ──── depends on Phase 44 + 47 + 49 ───────────┘
```

**Critical path:** Phase 43 → Phase 44 → Phase 45/47 (parallel) → Phase 48/49 (parallel)

---

## Go-To-Market: Italy-First Strategy

### Target Pilot Accounts (Q3–Q4 2026)

| Organization | Sector | AI Maturity | Regulatory Pressure | Entry Point |
|-------------|--------|-------------|---------------------|-------------|
| **UniCredit** | Banking | High (AI lab, LLM experiments) | DORA + NIS2 + EBA | Risk/Compliance team via CISO org |
| **Intesa Sanpaolo** | Banking | High (AI Center of Excellence) | DORA + NIS2 | Innovation team |
| **Generali** | Insurance | Medium-High (claims AI) | DORA + EIOPA | IT Security / Claims Automation |
| **Enel** | Energy/Utilities | Medium (grid optimization AI) | NIS2 | Digital/Innovation team |
| **Leonardo** | Defense/Aerospace | Medium (NLP, CV) | NIS2 + classified | Cybersecurity division |

### System Integrator Partnerships

| SI Partner | Strengths | Engagement Model |
|-----------|-----------|-----------------|
| **Accenture Italy** | Deep banking relationships, compliance practice | Technology partner, co-sell |
| **Reply** | Strong in Italian enterprise, AI/ML practice | Reseller + implementation partner |
| **NTT Data Italia** | Banca d'Italia relationships, DORA expertise | Co-development, pilot delivery |
| **Deloitte Italy** | Audit/compliance authority, DORA readiness | Compliance validation partner |

### 90-Day Launch Plan (Q2 2026)

| Week | Milestone | Deliverable |
|------|-----------|-------------|
| 1–2 | **Foundation** | Open-core licensing finalized, AGPL-3.0 + Commercial CLA |
| 3–4 | **Pilot Kit** | Deployment guide, demo script, reference architecture, 2-page datasheet |
| 5–6 | **First Contact** | Outreach to 3 target CISOs via warm introductions (Italian AI/security network) |
| 7–8 | **POC Setup** | Deploy POC for first design partner (target: UniCredit or Generali) |
| 9–10 | **Conference** | Present at Italian AI/cybersecurity conference (Cybertech Europe, AI Festival) |
| 11–12 | **Iterate** | Incorporate POC feedback, publish case study outline, refine pricing |

### Key Metrics (12-Month Targets)

| Metric | Target |
|--------|--------|
| Design partners (free pilots) | 3–5 |
| Paid Enterprise contracts | 1–2 |
| Community GitHub stars | 500+ |
| Monthly active tenants (Community tier) | 50+ |
| Conference presentations | 3+ |
| Published case studies | 1–2 |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| PostgreSQL audit backend performance at scale | Phase 43 timeline slip | Medium | Prototype with BRIN indexes early; ClickHouse as fallback |
| Multi-tenancy isolation bugs | Security incident, trust loss | Medium | Extensive fuzz testing, row-level security audit, penetration test |
| Admin console scope creep | Phase 45 takes 3x estimated | High | MVP-first: audit viewer + agent inventory only; policy editor in v2 |
| Enterprise IAM complexity (SAML edge cases) | Phase 46 blocked | Medium | Start with OIDC only; SAML as follow-up |
| Italian pilot accounts slow to engage | GTM delayed | Medium | Parallel outreach to 5 targets; attend 3+ conferences |
| Competitor launches enterprise product first | Market positioning weakened | Medium | Differentiate on compliance depth (DORA/NIS2) — unique to Italian/EU market |
| Open-core tension (community vs commercial) | Community trust erosion | Low | Clear licensing: engine always AGPL; commercial = admin console + SSO + support |
| Team scaling (currently solo) | Execution bottleneck | High | Prioritize Phase 43+44 (infrastructure), then recruit for console/GTM |

---

## Dependency on Existing v4.0 Roadmap

The v5.0 ACP roadmap builds on top of the completed v4.0 phases. Key dependencies:

| v5.0 Phase | Depends on v4.0 |
|-----------|-----------------|
| Phase 43 (Audit Store) | Phase 19 (Merkle proofs), Phase 37 (ZK audit) |
| Phase 44 (Multi-Tenancy) | Phase 21 (ABAC), Phase 26 (Governance) |
| Phase 45 (Admin Console) | Phase 22 (Simulator API), Phase 34 (Discovery), Phase 38 (SOC 2) |
| Phase 46 (Enterprise IAM) | Phase 39 (Federation) |
| Phase 47 (Policy Lifecycle) | Phase 40 (Workflow Constraints) |
| Phase 48 (Compliance) | Phase 19 (EU AI Act), Phase 24 (Art 50/Art 10), Phase 38 (SOC 2) |
| Phase 49 (K8s Operator) | Phase 27 (Helm chart, leader election) |

Remaining v4.0 phases (36 DX/SDK, 41 PQC, 42 Benchmark) can proceed in parallel with v5.0 work.

---

*This roadmap is a living document. Update as market feedback, pilot learnings, and regulatory guidance emerge.*
