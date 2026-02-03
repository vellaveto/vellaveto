# Directive C-17: Post-Release Improvements — Work Split

**Author:** Instance B
**Date:** 2026-02-03
**Status:** PROPOSED
**Context:** All C-1 through C-16 directives COMPLETE. All adversary findings (Phases 1-6) FIXED. 2,036 tests pass. This directive proposes the next wave of improvements based on web research of the current MCP security ecosystem (OWASP MCP Top 10, MCP spec updates, industry best practices as of Feb 2026).

---

## Priority 1 — High Impact

### C-17.1: OAuth 2.1 + PKCE Authentication (Instance A)
**Scope:** sentinel-server, new sentinel-auth crate
**Why:** The MCP spec now REQUIRES OAuth 2.1 with PKCE for remote server auth. Sentinel currently uses static API keys only. This is the single biggest spec compliance gap.
**Work:**
- [ ] Create `sentinel-auth` crate with OAuth 2.1 client/server support
- [ ] Implement PKCE (S256 code challenge method, per MCP spec)
- [ ] Add Protected Resource Metadata endpoint (RFC 9728)
- [ ] Support Dynamic Client Registration for MCP clients
- [ ] Short-lived scoped tokens with rotation
- [ ] Backward-compatible: static API key still works when OAuth not configured
- [ ] Integration tests for full OAuth flow

**Rationale for Instance A:** Instance A owns sentinel-server auth (Directive C-3, finding #7), CI, and has experience with the auth middleware in routes.rs.

---

### C-17.2: Tool Manifest Signing & Schema Pinning (Instance B)
**Scope:** sentinel-mcp, sentinel-engine
**Why:** OWASP MCP Top 10 lists tool poisoning as critical. Sentinel has rug-pull detection but no cryptographic verification of tool descriptors. 43% of analyzed MCP servers are vulnerable to tool manipulation.
**Work:**
- [ ] Define `ToolManifest` type with Ed25519 signature field
- [ ] `verify_tool_manifest()` — check signature against trusted keys
- [ ] Schema pinning: hash tool input/output schemas at first observation, alert on change
- [ ] Tool allowlist/denylist by manifest hash
- [ ] Integrate into both stdio proxy and HTTP proxy tool-list handling
- [ ] Tests for: valid manifest, tampered manifest, schema drift detection

**Rationale for Instance B:** Instance B owns sentinel-mcp (proxy, extractor, inspection, rug-pull detection) and sentinel-engine (policy evaluation).

---

### C-17.3: Context-Aware Dynamic Policies (Instance B)
**Scope:** sentinel-engine, sentinel-types
**Why:** Industry consensus: static tool/function/parameter policies are necessary but not sufficient. Policies should consider runtime context (session history, time, agent identity).
**Work:**
- [ ] Add `context_conditions` field to Policy (optional, backward-compatible)
- [ ] Condition types: `time_window`, `session_call_count`, `agent_id`, `previous_action`
- [ ] Engine evaluates context conditions after parameter constraints
- [ ] `EvaluationContext` struct passed into evaluate (session state, timestamp, agent ID)
- [ ] Tests for: time-based deny, call-count throttle, agent-scoped permissions

**Rationale for Instance B:** Instance B owns the policy engine evaluation pipeline and parameter constraint system.

---

### C-17.4: Sandbox Orchestration for Tool Calls (Instance A)
**Scope:** new sentinel-sandbox crate, sentinel-mcp integration
**Why:** Policy enforcement prevents unauthorized calls, but authorized calls still execute with full process privileges. The industry is moving toward defense-in-depth with Wasm/namespace isolation.
**Work:**
- [ ] Create `sentinel-sandbox` crate with pluggable backend trait
- [ ] Backend: `bubblewrap` (Linux namespace + seccomp) for local tool execution
- [ ] Backend: `wasmtime` (Wasm) for capability-restricted execution
- [ ] Backend: `passthrough` (no isolation, for backward compat)
- [ ] Configuration: per-tool sandbox policy in config TOML
- [ ] Wire into stdio proxy: wrap tool call execution in sandbox
- [ ] Tests for: namespace isolation, Wasm memory bounds, passthrough mode

**Rationale for Instance A:** Instance A owns sentinel-http-proxy and has experience with process lifecycle (child reaping, graceful shutdown).

---

## Priority 2 — Medium Impact

### C-17.5: SIEM / Immutable Storage Export (Instance A)
**Scope:** sentinel-audit
**Why:** Sentinel has hash chains + Ed25519 checkpoints (ahead of most). Next step: ship logs to immutable external storage for compliance (SOC 2, ISO 27001).
**Work:**
- [ ] Structured log export in CEF or JSON-lines format for SIEM ingestion
- [ ] Optional S3-compatible append-only upload (Object Lock / WORM)
- [ ] Compliance report generator: summary of verdicts, policy violations, checkpoint integrity
- [ ] Configuration: `[audit.export]` section in TOML

---

### C-17.6: Sliding Window Rate Limiting (Instance A)
**Scope:** sentinel-server
**Why:** Current fixed-window rate limiting is vulnerable to burst-at-boundary attacks. The `governor` crate supports sliding window out of the box.
**Work:**
- [ ] Switch PerIpRateLimiter from fixed-window to sliding window
- [ ] Add adaptive rate limiting: auto-adjust thresholds based on traffic patterns
- [ ] Configuration: `rate_limit_algorithm = "sliding_window"` in TOML

---

### C-17.7: Supply Chain Verification for MCP Servers (Instance B)
**Scope:** sentinel-mcp, sentinel-proxy
**Why:** Supply chain attacks are in OWASP's top 5 for both MCP and Agentic AI. Sentinel should verify the MCP servers it proxies to.
**Work:**
- [ ] MCP server binary hash verification before spawning
- [ ] Server allowlist by hash/path in config
- [ ] Optional: check against known-malicious server database (remote registry)
- [ ] Refuse to proxy to unverified servers (fail-closed, configurable)

---

### C-17.8: PII Detection in Audit Logs (Instance B)
**Scope:** sentinel-audit
**Why:** MCP spec requires data minimization. Current redaction is key-name-based. Pattern-based PII detection catches more.
**Work:**
- [ ] Regex-based PII patterns: email, phone, SSN, credit card, IP addresses
- [ ] Configurable: `redaction_level = "keys_only" | "keys_and_patterns" | "full"`
- [ ] PII detection report in audit verify output

---

## Priority 3 — Future

### C-17.9: Multi-Agent Identity & Delegation Chains
**Scope:** sentinel-types, sentinel-engine
**Why:** OWASP ASI03 — agents inheriting credentials. As multi-agent systems grow, Sentinel needs to track which agent delegated to which.
- Agent identity attestation (each agent gets unique ID)
- Delegation chain tracking with configurable depth limits
- Per-agent permission scoping

### C-17.10: Confused Deputy Prevention
**Scope:** sentinel-mcp, sentinel-http-proxy
**Why:** MCP proxy servers connecting to third-party APIs are vulnerable to authorization code interception in multi-hop chains.
- Validate tool call origin against authorized agent list
- Bind tokens to specific agent sessions

---

## Proposed Assignment Summary

| Task | Instance | Priority | New Crate? |
|------|----------|----------|------------|
| C-17.1 OAuth 2.1 + PKCE | A | P1 | sentinel-auth |
| C-17.2 Tool manifest signing | B | P1 | No |
| C-17.3 Context-aware policies | B | P1 | No |
| C-17.4 Sandbox orchestration | A | P1 | sentinel-sandbox |
| C-17.5 SIEM export | A | P2 | No |
| C-17.6 Sliding window rate limit | A | P2 | No |
| C-17.7 Supply chain verification | B | P2 | No |
| C-17.8 PII detection | B | P2 | No |
| C-17.9 Multi-agent identity | Unassigned | P3 | No |
| C-17.10 Confused deputy | Unassigned | P3 | No |

**Instance A: 4 tasks** (C-17.1, C-17.4, C-17.5, C-17.6)
**Instance B: 4 tasks** (C-17.2, C-17.3, C-17.7, C-17.8)
**Unassigned: 2 tasks** (C-17.9, C-17.10 — defer to next cycle)

---

## References

- [MCP Security Best Practices (Official Spec)](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [MCP Authorization Spec (OAuth 2.1)](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Practical Guide for MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [Aembit: MCP OAuth 2.1 + PKCE](https://aembit.io/blog/mcp-oauth-2-1-pkce-and-the-future-of-ai-authorization/)
- [NVIDIA: Sandboxing Agentic AI with Wasm](https://developer.nvidia.com/blog/sandboxing-agentic-ai-workflows-with-webassembly/)
- [Practical DevSecOps: MCP Security Vulnerabilities](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [SlowMist MCP Security Checklist](https://github.com/slowmist/MCP-Security-Checklist)
- [Clawprint: Tamper-Evident Audit Trail](https://github.com/cyntrisec/clawprint)
- [Cloudflare Rate Limiting Best Practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/)
