# Vellaveto Roadmap

> **Version:** 7.0.0-planning
> **Updated:** 2026-02-28
> **Status:** v6 foundation complete; next horizon planning
> **Current baseline:** 8,932 Rust tests passing | 232 audit rounds | 70 completed phases
> **Strategic position:** Security-first control plane for agentic systems
> **Primary mechanism:** MCP-native policy gateway
> **Licensing:** Multi-tier open-core (see LICENSING.md)

---

## Executive Summary

The v6 program is complete. Vellaveto already ships the core ingredients of an agentic security control plane: runtime enforcement, identity-aware access controls, discovery, audit, analytics, policy portability, compliance mapping, consumer privacy modes, and enterprise deployment surfaces.

The next roadmap is no longer about filling foundational feature gaps. It is about turning that shipped platform into the default enterprise control plane for MCP and tool-calling agents before the category gets flattened into commodity "MCP gateway" offerings.

This roadmap prioritizes:

1. **Owning the registry and access plane** before gateway vendors normalize discovery and hosted onboarding
2. **Productizing delegated identity and token brokerage** in direct response to MCP authorization requirements and the rise of auth-first competitors
3. **Meeting managed-runtime expectations** as AWS, Microsoft, and platform vendors move toward hosted server-side execution
4. **Converting compliance mapping into customer-grade evidence automation**
5. **Improving adoption and distribution** so the product wins on deployment speed, not just depth

---

## Market Reset (Verified 2026-02-28)

The current market signal is clear:

1. **MCP security is now explicit protocol surface, not optional hygiene.**
   The MCP security guidance and authorization specification explicitly require token audience binding, consent controls, PKCE, and forbid token passthrough.

2. **OWASP now treats secure MCP implementation as its own practical discipline.**
   On **February 16, 2026**, OWASP published *A Practical Guide for Secure MCP Server Development*, focused on strong authn/authz, validation, session isolation, and hardened deployment.

3. **"Gateway" is no longer differentiated language.**
   MintMCP, TrueFoundry, Microsoft, AWS, and Permit all now market some combination of gateway, registry, auth, routing, or managed control-plane capabilities.

4. **Discovery and hosted onboarding are becoming table stakes.**
   MintMCP and TrueFoundry both emphasize registry, discovery, hosted/managed MCP server onboarding, and centralized governance.

5. **Identity is becoming the primary buying wedge.**
   Permit positions MCPermit around five-stage authz, ReBAC, and HITL approvals. The standards direction reinforces that.

6. **Managed execution is accelerating.**
   AWS moved from AgentCore GA (**October 13, 2025**) to API Gateway MCP proxy (**December 2, 2025**) to Bedrock server-side tool execution through AgentCore Gateway (**February 24, 2026**).

7. **SDK-side guardrails are improving, but they do not replace external enforcement.**
   OpenAI Agents SDK tool guardrails only cover function tools and do not cover hosted tools or local built-in runtime tools, preserving the need for an external enforcement layer.

**Implication:** Vellaveto should not spend the next cycle adding more undifferentiated gateway mechanics. It should use the existing runtime core to win the control-plane layer above the gateway.

---

## Product Thesis

Vellaveto should be positioned and built as:

**the security-first control plane for MCP and tool-calling agents, with a fail-closed runtime gateway at its core.**

That means the next roadmap focuses on four defensible moats:

1. **Identity plane**
   User, agent, tenant, tool, and downstream-service identity bound together with explicit delegation.

2. **Registry and inventory plane**
   Verified tools, known topology, drift detection, and trust metadata that determine what can be called at all.

3. **Evidence plane**
   Audit trails become decision-ready evidence packs, not just logs.

4. **Distribution plane**
   Fast rollout for local, self-hosted, and managed deployment models.

---

## 2026 Priorities

| Priority | Theme | Why It Matters Now |
|----------|-------|--------------------|
| **P1** | Registry + Access Plane | Strongest differentiation against MintMCP, TrueFoundry, and Permit |
| **P2** | Managed Deployment + Ecosystem Reach | Required to stay relevant against AWS and Microsoft managed pathways |
| **P3** | Evidence Automation + Posture Intelligence | Turns existing depth into enterprise buying leverage |

---

## Timeline

```text
Q2 2026 (Planned):  Phase 73 — Verified Registry & Connector Trust         [P1]
                    Phase 74 — Delegated Identity Broker & Access Graph    [P1]
                    Phase 75 — Inventory, Posture & Exposure Views         [P3]

Q3 2026 (Planned):  Phase 76 — Hosted Gateway & Remote MCP Onboarding      [P2]
                    Phase 77 — Server-Side Tool Execution Integrations     [P2]
                    Phase 78 — Policy Lifecycle Automation & GitOps        [P1]

Q4 2026 (Planned):  Phase 79 — Evidence Automation & Audit Packs           [P3]
                    Phase 80 — Adaptive Runtime Defense & Policy Tuning    [P3]
                    Phase 81 — Verified Partner Marketplace & Channels     [P2]
```

---

## Phase 73: Verified Registry & Connector Trust (P1)

**Goal:** Make the registry a trust boundary, not a catalog.

### Why now

Competitors are normalizing server registries and discovery. Vellaveto needs the registry to become a security differentiator: verified publishers, connector trust state, risk metadata, and policy-aware admission.

### Deliverables

- Signed connector and server manifests with publisher identity
- Trust tiers for tools and servers (`verified`, `internal`, `quarantined`, `blocked`)
- Registry-side risk metadata: auth mode, data class, side effects, network reach, execution model
- Admission policies that can deny or gate untrusted connectors before runtime
- Unknown-tool and tool-drift workflows connected directly to the registry
- Registry API/UX for approving, promoting, and revoking connectors

### Exit criteria

- A tenant can allow only verified connectors by policy
- Registry trust metadata is enforceable at runtime without manual duplication
- New connector onboarding produces both inventory and trust posture in one flow

---

## Phase 74: Delegated Identity Broker & Access Graph (P1)

**Goal:** Make delegated access the strongest product wedge.

### Why now

The MCP authorization model and current vendor direction both push toward identity-bound access. Vellaveto already has the pieces (OIDC, SAML, DPoP, M2M, step-up auth, NHI lifecycle), but they need to become a unified product surface.

### Deliverables

- First-class delegation model: user -> agent -> gateway -> MCP server -> downstream service
- Resource-indicator-aware token brokerage with explicit audience validation
- Step-up auth and approval orchestration tied to risk policy
- Access graph visualization for originator, agent, server, and downstream service relationships
- Just-in-time scoped credentials for high-risk calls
- Replay-safe short-lived service tokens and revocation hooks

### Exit criteria

- Every high-risk call can be explained as a concrete delegated path
- Token issuance and validation are visible, auditable, and policy-addressable
- Identity failures are diagnosable without exposing secrets or unsafe detail

---

## Phase 75: Inventory, Posture & Exposure Views (P3)

**Goal:** Turn topology and discovery into an operator-facing posture product.

### Why now

Discovery is already implemented, but the buyer value is not "a crawler exists." The buyer value is "I can see what agents can reach, what changed, and what is risky."

### Deliverables

- Unified inventory view for servers, tools, identities, transports, and trust state
- Drift and exposure dashboards: new tool, changed schema, missing auth, broad scopes, high-risk tool chains
- Policy coverage views tied to live inventory
- Posture scoring per tenant and per environment
- "Shadow MCP" detection for servers observed at runtime but not approved in registry
- Exportable posture snapshots for internal review and audit workflows

### Exit criteria

- Admins can answer "what tools exist, who can use them, and what changed this week?" from one surface
- Inventory feeds both enforcement and sales-proof posture reporting

---

## Phase 76: Hosted Gateway & Remote MCP Onboarding (P2)

**Goal:** Remove deployment friction as a blocker to adoption.

### Why now

MintMCP, TrueFoundry, and Microsoft are all pushing centralized management and simpler onboarding. Vellaveto needs a clear path from local hardening to managed enterprise rollout.

### Deliverables

- Hosted control-plane deployment mode for remote MCP onboarding
- One-click bring-your-own MCP server registration for HTTP and remote transports
- Managed bootstrap flows for stdio-to-remote conversion where appropriate
- Tenant-safe secret and OAuth bootstrap flows
- Production-ready starter templates for common MCP server patterns
- Simplified environment promotion (dev -> staging -> prod)

### Exit criteria

- Teams can onboard a remote MCP server in minutes without hand-editing multiple configs
- The hosted path preserves the same enforcement semantics as self-hosted deployments

---

## Phase 77: Server-Side Tool Execution Integrations (P2)

**Goal:** Stay relevant as model providers absorb more orchestration.

### Why now

AWS has already moved to server-side tool execution with AgentCore Gateway. If the market shifts toward provider-side orchestration, Vellaveto must remain the control layer those providers connect through.

### Deliverables

- First-class gateway integration patterns for server-side tool execution platforms
- Gateway-as-tool-connector interfaces for managed runtimes
- Policy-preserving execution receipts for server-side invocation paths
- Compatibility adapters for model-provider execution loops where feasible
- Clear separation of provider execution from Vellaveto authorization and audit guarantees

### Exit criteria

- Vellaveto remains the policy and audit boundary even when the model provider executes tools server-side
- The roadmap is no longer dependent on client-side orchestration staying dominant

---

## Phase 78: Policy Lifecycle Automation & GitOps (P1)

**Goal:** Turn policy from authored config into managed product lifecycle.

### Why now

As the platform grows, policy management becomes operational overhead unless it is versioned, promotable, explainable, and safe to roll out.

### Deliverables

- Native policy environments, drafts, approvals, rollout windows, and rollback
- Git-backed policy sync and promotion pipelines
- Change impact previews using coverage and analytics data
- Staged rollout / canary enforcement for risky policy changes
- Policy drift detection between Git, control plane, and runtime
- Signed policy bundles and release provenance

### Exit criteria

- Policy teams can ship changes through controlled promotion, not manual edits
- Operators can predict blast radius before rollout

---

## Phase 79: Evidence Automation & Audit Packs (P3)

**Goal:** Convert logs and mappings into enterprise-grade proof artifacts.

### Why now

Many vendors can claim "audit logs." Fewer can produce reusable evidence that makes security, compliance, and procurement easier.

### Deliverables

- Automated evidence packs for key frameworks and internal control sets
- Scheduled access review, exception review, and approval review reporting
- Incident-ready evidence exports with chain-of-custody metadata
- Tenant-scoped control attestation bundles
- Crosswalks from runtime events to control objectives
- API and UI flows for exporting evidence by period, framework, or incident

### Exit criteria

- A buyer can pull auditor-ready evidence without reconstructing it manually from raw logs
- Evidence exports become a repeatable enterprise workflow, not a services task

---

## Phase 80: Adaptive Runtime Defense & Policy Tuning (P3)

**Goal:** Close the loop between telemetry and enforcement.

### Why now

You already have analytics, adaptive throttling, and coverage signals. The next step is using those to recommend safer defaults and reduce manual tuning without weakening fail-closed behavior.

### Deliverables

- Policy recommendations derived from denied traffic, repeated approvals, drift, and unused rules
- Adaptive protective modes for emerging abuse patterns (burst abuse, chained exfiltration, abnormal cross-tool behavior)
- Tunable automatic safeguards that can recommend, simulate, or enforce based on operator policy
- Feedback loops linking analytics, coverage, and rate controls
- Safety rails for recommendation quality to avoid unsafe automation

### Exit criteria

- The platform helps operators tighten policy faster without turning into opaque auto-allow behavior
- Auto-tuning remains recommendation-first and explicitly fail-closed by design

---

## Phase 81: Verified Partner Marketplace & Channels (P2)

**Goal:** Turn the ecosystem into a distribution advantage.

### Why now

If partners and customers can buy or install "managed tools" elsewhere with less friction, the best technical platform still loses attention.

### Deliverables

- Verified partner connector program with trust requirements
- Marketplace flows tied to registry trust state and deployment templates
- Partner bundles for regulated verticals (finance, healthcare, public sector)
- Commercial packaging for verified connectors, templates, and evidence packs
- Distribution integrations aligned with cloud and SI partner channels

### Exit criteria

- The marketplace is not just a list; it is a trusted distribution and onboarding channel
- Channel partners can deploy opinionated Vellaveto packages without custom project assembly

---

## Success Metrics

The next roadmap should be judged by product adoption and control-plane leverage, not by raw feature count.

### Product metrics

- Time to first protected MCP server
- Time to first approved remote onboarding
- Percentage of calls governed by identity-bound policy
- Registry coverage: approved vs observed tools
- Evidence export usage per tenant

### Commercial metrics

- Design partners converted to production
- Paid tenants with multi-environment deployments
- Verified connectors installed per tenant
- Expansion from gateway-only deployment to control-plane adoption

### Security metrics

- Percentage of high-risk calls requiring explicit identity and approval context
- Unknown-tool denial rate
- Drift detection time
- Mean time to produce incident evidence pack

---

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Registry becomes a catalog, not a trust boundary | Weak differentiation | Tie registry state directly to runtime admission and policy |
| Managed deployment dilutes security posture | Brand erosion | Preserve identical fail-closed semantics across hosted and self-hosted paths |
| Over-automated policy tuning becomes opaque | Trust loss | Keep recommendations explicit and operator-approved by default |
| Too much breadth slows delivery | Missed market window | Sequence around three wedges only: access plane, managed onboarding, evidence |
| Competitors win on simpler onboarding | Adoption drag | Prioritize onboarding UX and verified templates ahead of more deep primitives |

---

## Foundation Already Shipped

The following baseline is complete and should be treated as platform foundation, not backlog:

- Phases **36-72** delivered across DX, IAM, billing, MCP 2025-11-25 support, compliance expansion, observability, Wasm plugins, advanced security, Cedar compatibility, A2A hardening, formal verification, consumer shield, analytics, bulk policy operations, adaptive rate limiting, and policy coverage
- **8,932** Rust tests passing (9,800+ total across all languages)
- **232** adversarial audit rounds completed
- Core control-plane surfaces already exist: admin console, server APIs, stdio/HTTP gateways, discovery, audit, Terraform, Helm, operator, VS Code extension, SDKs

The next roadmap assumes this foundation is stable enough to productize and distribute, not re-invent.

---

## External Signals Used For This Reset

Verified on **February 28, 2026**:

- MCP Security Best Practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- MCP Authorization (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- OWASP Secure MCP Guide (published February 16, 2026): https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- Microsoft MCP Gateway: https://github.com/microsoft/mcp-gateway
- MintMCP Gateway: https://www.mintmcp.com/mcp-gateway
- TrueFoundry MCP Gateway: https://www.truefoundry.com/mcp-gateway
- TrueFoundry MCP docs: https://www.truefoundry.com/docs/ai-gateway/mcp-overview
- Permit MCP Permissions Overview: https://docs.permit.io/mcp-permissions/overview
- Permit MCP Permissions Architecture: https://docs.permit.io/ai-security/mcp-permissions/architecture/
- AWS AgentCore GA (October 13, 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available/
- AWS API Gateway MCP proxy (December 2, 2025): https://aws.amazon.com/about-aws/whats-new/2025/12/api-gateway-mcp-proxy-support/
- AWS Bedrock server-side tool execution (February 24, 2026): https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-bedrock-server-side-tool-execution-agentcore-gateway/
- OpenAI Agents SDK Guardrails: https://openai.github.io/openai-agents-python/guardrails/

