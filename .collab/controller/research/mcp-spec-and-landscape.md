# Controller Research Report: MCP Specification & Security Landscape

**Date:** 2026-02-02
**Author:** Controller Instance (Web Research)
**Sources:** MCP Specification 2025-11-25, OWASP MCP Top 10, Elastic Security Labs, Practical DevSecOps, AuthZed timeline, integrate.io MCP gateways analysis

---

## 1. MCP Specification Has Evolved Significantly

The MCP spec is now at **version 2025-11-25** (latest). Key versions:

| Version | Date | Key Changes |
|---------|------|-------------|
| 2024-11-05 | Original | stdio transport, basic tools/resources/prompts |
| 2025-03-26 | Major | Streamable HTTP transport, tool annotations, OAuth 2.1 |
| 2025-06-18 | Major | Structured tool outputs, elicitation, OAuth Resource Servers |
| 2025-11-25 | Latest | Full spec refinement, governance transferred to Linux Foundation (AAIF) |

**Governance:** In December 2025, Anthropic donated MCP to the Agentic AI Foundation (AAIF) under the Linux Foundation, co-founded by Anthropic, Block, and OpenAI.

### 1.1 Streamable HTTP Transport (NEW — Not Supported by Sentinel)

Streamable HTTP replaced SSE as the recommended HTTP transport:
- Single HTTP endpoint (e.g., `/mcp`)
- Client sends JSON-RPC requests via HTTP POST
- Server responds with either direct JSON or SSE stream
- Session management via `Mcp-Session-Id` header
- Supports stateless deployments (AWS Lambda, serverless)

**Impact on Sentinel:** Sentinel only supports stdio transport. To be relevant for remote/cloud MCP servers, it MUST support Streamable HTTP as a reverse proxy. This is the single biggest feature gap.

### 1.2 Tool Annotations (NEW — Not Supported by Sentinel)

The spec now includes tool behavior metadata:

| Annotation | Type | Default | Meaning |
|-----------|------|---------|---------|
| `readOnlyHint` | bool | false | Tool does not modify state |
| `destructiveHint` | bool | true | Tool may perform destructive actions |
| `idempotentHint` | bool | false | Same args = same effect |
| `openWorldHint` | bool | true | Interacts with external systems |

**CRITICAL SECURITY NOTE from spec:** "Tool annotations MUST be considered untrusted unless they come from trusted servers."

**Impact on Sentinel:** Annotations provide a natural integration point:
- Auto-generate default policies from annotations (destructiveHint=true -> require approval)
- Monitor for annotation changes (rug-pull detection)
- Use as policy evaluation context

### 1.3 Structured Tool Outputs (NEW)

Tools can now return typed JSON via `outputSchema` and `structuredContent` fields. For backward compatibility, structured content should also be in a text content block.

**Impact on Sentinel:** Response inspection should understand structured outputs and validate them.

### 1.4 OAuth 2.1 Authorization (NEW)

For HTTP transports, MCP now defines:
- OAuth 2.1 with PKCE for client authentication
- `.well-known/oauth-authorization-server` metadata
- Dynamic client registration (RFC 7591)
- MCP servers are OAuth Resource Servers

**Impact on Sentinel:** When acting as HTTP proxy, Sentinel must handle OAuth tokens correctly (verify, pass-through, or enforce additional constraints).

### 1.5 Elicitation (NEW)

Servers can now request additional information from users via the client. This is a new server-to-client flow.

**Impact on Sentinel:** This is a potential data exfiltration vector — a malicious server could use elicitation to request sensitive information.

---

## 2. OWASP MCP Top 10 (Published 2025)

The OWASP Foundation published a Top 10 specifically for MCP:

| # | Risk | Sentinel Coverage |
|---|------|------------------|
| MCP01 | Token Mismanagement & Secret Exposure | PARTIAL — redacts sensitive values in audit, but no token lifecycle management |
| MCP02 | Privilege Escalation via Scope Creep | PARTIAL — static policies, no dynamic scope enforcement |
| MCP03 | Tool Poisoning | NOT COVERED — no tool description monitoring |
| MCP04 | Supply Chain Attacks & Dependency Tampering | NOT APPLICABLE — Sentinel is the security layer |
| MCP05 | Command Injection & Execution | GOOD — parameter constraints with regex/glob |
| MCP06 | Prompt Injection via Contextual Payloads | NOT COVERED — no response inspection |
| MCP07 | Insufficient Authentication & Authorization | GOOD — Bearer token auth on server endpoints |
| MCP08 | Lack of Audit and Telemetry | EXCELLENT — tamper-evident hash-chained audit log |
| MCP09 | Shadow MCP Servers | NOT APPLICABLE — Sentinel is infrastructure |
| MCP10 | Context Injection & Over-Sharing | PARTIAL — parameter scanning, but no context isolation |

**Key gaps: MCP03 (tool poisoning), MCP06 (prompt injection in responses)**

---

## 3. Real-World MCP Security Incidents

### CVE-2025-6514: mcp-remote Command Injection (CRITICAL)
- OS command injection in mcp-remote OAuth proxy
- Malicious authorization_endpoint passed to system shell
- 437,000+ downloads affected (Cloudflare, Hugging Face, Auth0)
- **Lesson for Sentinel:** Validate all URIs before any processing

### Tool Poisoning Attacks (Invariant Labs)
- Malicious MCP server exfiltrated entire WhatsApp history
- Combined "tool poisoning" with legitimate whatsapp-mcp server
- **Lesson for Sentinel:** Must monitor tool descriptions for hidden instructions

### Industry Statistics
- **43% of tested MCP server implementations contain command injection flaws**
- **30% permit unrestricted URL fetching**
- These numbers validate Sentinel's mission

---

## 4. Competitive Landscape: MCP Gateways & Security Tools

The MCP gateway category is emerging rapidly:

### Direct Competitors
- **Lasso Security MCP Gateway** — Specialized MCP secure gateway, LLM interaction protection
- **Palo Alto Prisma AIRS** — Runtime security with prompt injection monitoring
- **Various open-source MCP proxies** — Basic filtering, no tamper-evident audit

### Sentinel's Differentiators
1. **Tamper-evident audit log** — SHA-256 hash chain is rare in this space
2. **Parameter-level constraint evaluation** — 9 operators, recursive scanning, fail-closed
3. **Approval workflow** — Human-in-the-loop with persistence
4. **Rust implementation** — Performance and safety advantages over Python/JS alternatives

### Sentinel's Gaps vs. Market
1. **No Streamable HTTP transport** — Can't protect remote MCP servers
2. **No tool annotation awareness** — Missing easy policy defaults
3. **No response inspection** — Prompt injection via tool results undetected
4. **No tools/list monitoring** — Rug-pull attacks undetected
5. **No sampling/createMessage interception** — Server-side exfiltration unmonitored
6. **No multi-server topology** — Can only proxy one server at a time

---

## 5. Attack Vectors & Defense Recommendations (Elastic Security Labs)

### Key Attack Patterns
1. **Tool poisoning** — Malicious instructions in tool descriptions
2. **Rug-pull redefinitions** — Tools silently altered after user approval
3. **Orchestration injection** — Cross-tool coordination attacks
4. **Data poisoning** — Untrusted external data triggers exfiltration
5. **Context exfiltration** — Tool parameters request system prompts

### Defense Strategies Relevant to Sentinel
- Enforce human approval for sensitive operations
- Apply least-privilege tool access
- Log and review all tool invocations (Sentinel already does this)
- Detect suspicious patterns in tool descriptions using LLM analysis
- Sandbox MCP servers in containers

---

## 6. Regulatory Context

- **EU AI Act** requirements are driving need for audit logging of AI agent actions
- Organizations need compliance documentation for AI tool use
- Tamper-evident audit trail is increasingly a regulatory requirement
- Sentinel's audit system positions it well for compliance use cases

---

## 7. Strategic Recommendations for Sentinel

### P0 — Must Have for Market Relevance
1. **Streamable HTTP transport proxy** — Without this, Sentinel only works with local stdio servers. The market is moving to remote/cloud MCP servers.
2. **Tool annotation awareness** — Intercept `tools/list`, extract annotations, use for default policies. Low effort, high value.
3. **Response inspection** — Scan tool results for prompt injection patterns. Critical for MCP06 defense.

### P1 — Strong Differentiators
4. **Tool definition pinning** — Detect when tool schemas/descriptions change (rug-pull detection). Maps to OWASP MCP03.
5. **`sampling/createMessage` interception** — Monitor server-to-client LLM requests. Prevents exfiltration via sampling.
6. **Protocol version awareness** — Verify negotiated MCP version during `initialize`.

### P2 — Competitive Advantages
7. **Multi-server topology** — Handle multiple backend MCP servers with tool namespace isolation.
8. **OAuth 2.1 integration** — Full HTTP auth for Streamable HTTP transport.
9. **Elicitation monitoring** — Detect servers abusing elicitation for data collection.
10. **`.well-known` server discovery** — Support MCP server metadata for auto-configuration.

### P3 — Future Vision
11. **LLM-based tool description analysis** — Use an LLM to detect suspicious tool descriptions.
12. **Behavioral anomaly detection** — Track tool usage patterns, alert on deviations.
13. **Cross-agent correlation** — Detect multi-step attack patterns across sessions.

---

## Sources

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP GitHub](https://github.com/modelcontextprotocol/modelcontextprotocol)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Elastic Security Labs — MCP Attack Vectors](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Practical DevSecOps — MCP Security Vulnerabilities](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [AuthZed — Timeline of MCP Security Breaches](https://authzed.com/blog/timeline-mcp-breaches)
- [integrate.io — Best MCP Gateways](https://www.integrate.io/blog/best-mcp-gateways-and-ai-agent-security-tools/)
- [Red Hat — MCP Security Risks](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [Bitdefender — MCP Security Introduction](https://businessinsights.bitdefender.com/security-risks-agentic-ai-model-context-protocol-mcp-introduction)
- [Auth0 — MCP Spec Updates June 2025](https://auth0.com/blog/mcp-specs-update-all-about-auth/)
- [MCP Release Notes (Speakeasy)](https://www.speakeasy.com/mcp/release-notes)

---

*Last updated: 2026-02-02*
