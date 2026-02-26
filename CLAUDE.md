# CLAUDE.md — Vellaveto Project Instructions

> **Project:** Vellaveto — MCP Tool Firewall
> **State:** v5.0.0-dev (Phases 1–53 complete, 224 audit rounds)
> **Version:** 5.0.0-dev
> **License:** AGPL-3.0 dual license (see LICENSING.md)
> **Tests:** 7,867 Rust + 59 React + 12 Terraform + 433 Python + 127 Go + 119 TypeScript + 120 Java + 26 VS Code, zero warnings, zero `unwrap()` in library code
> **Updated:** 2026-02-25

---

## Mission

Vellaveto is a runtime security engine for AI agent tool calls. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies on paths/domains/actions, and maintains a tamper-evident audit trail.

**Non-negotiable properties:**
- **Fast:** <5ms P99 evaluation latency, <50MB memory baseline
- **Fail-closed:** Errors, missing policies, and unresolved context all produce `Deny`
- **Observable:** Every decision logged, every failure diagnosed
- **No panics:** Zero `unwrap()` in library code, `?` and `ok_or_else()` everywhere

---

## Before Every Session

```bash
git status
cargo check --workspace 2>&1 | head -50
cargo test --workspace --no-fail-fast 2>&1 | tail -5
cargo clippy --workspace
```

**If tests fail at session start:** STOP. Diagnose and fix before proceeding.

---

## Architecture

### Crate Dependency Graph (NEVER VIOLATE)

```
vellaveto-types          (leaf — no internal deps)
       |
vellaveto-canonical      (types only)
vellaveto-config         (types only)
       |
vellaveto-engine         (types, ipnet)
       |
vellaveto-audit          (types, engine)
vellaveto-approval       (types)
       |
vellaveto-mcp            (types, engine, audit, approval, config)
       |
vellaveto-cluster        (types, config, approval)
       |
vellaveto-server         (all above)
vellaveto-http-proxy     (all above)
vellaveto-proxy          (all above, stdio mode)
vellaveto-integration    (all above, test only)
vellaveto-operator       (standalone — kube-rs, no internal deps)
```

Lower crates MUST NOT depend on higher crates.
`vellaveto-operator` is a standalone binary crate with no internal deps — it talks to `vellaveto-server` via REST API.

### Key Types

```rust
Action { tool, function, parameters, target_paths, target_domains, resolved_ips }
Policy { id, name, policy_type, priority, path_rules, network_rules }
NetworkRules { allowed_domains, blocked_domains, ip_rules: Option<IpRules> }
IpRules { block_private, blocked_cidrs, allowed_cidrs }
Verdict::Allow | Verdict::Deny { reason } | Verdict::RequireApproval { .. }
```

### File Locations

| What | Where |
|------|-------|
| **vellaveto-types** | |
| Core types: Action, Verdict, Policy, PathRules, NetworkRules | `vellaveto-types/src/core.rs` |
| Identity: AgentIdentity, EvaluationContext, RequestContext, StatelessContextBlob | `vellaveto-types/src/identity.rs` |
| ETDI, Threat, ABAC, capability, compliance, NHI, governance, discovery, projector, ZK audit, audit store, policy lifecycle, evidence pack | `vellaveto-types/src/*.rs` |
| Time utilities: parse_iso8601_secs | `vellaveto-types/src/time_util.rs` |
| Tests (~180) | `vellaveto-types/src/tests.rs` |
| **vellaveto-engine** | |
| Policy evaluation | `vellaveto-engine/src/lib.rs` |
| ABAC engine + Cedar-style evaluation | `vellaveto-engine/src/abac.rs` |
| Least-agency tracker | `vellaveto-engine/src/least_agency.rs` |
| **vellaveto-audit** | |
| AuditLogger + rotation + verification | `vellaveto-audit/src/lib.rs` |
| Compliance registries (EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, OWASP ASI, DORA, NIS2) | `vellaveto-audit/src/{eu_ai_act,soc2,cosai,adversa_top25,iso42001,owasp_asi,dora,nis2,gap_analysis}.rs` |
| Evidence pack + ZK audit | `vellaveto-audit/src/evidence_pack.rs`, `vellaveto-audit/src/zk/*.rs` |
| Audit sink + PostgreSQL | `vellaveto-audit/src/sink.rs`, `vellaveto-audit/src/sink/postgres.rs` |
| Audit query (file/PostgreSQL) | `vellaveto-audit/src/query/{file,postgres}.rs` |
| Tests (~421) | `vellaveto-audit/src/tests.rs` |
| **vellaveto-config** | |
| PolicyConfig + validation | `vellaveto-config/src/lib.rs`, `vellaveto-config/src/config_validate.rs` |
| All config modules | `vellaveto-config/src/*.rs` |
| Tests (~301) | `vellaveto-config/src/tests.rs` |
| **vellaveto-mcp** | |
| MCP handling + proxy bridge | `vellaveto-mcp/src/lib.rs`, `vellaveto-mcp/src/proxy/bridge/*.rs` |
| DLP / inspection + multimodal | `vellaveto-mcp/src/inspection.rs`, `vellaveto-mcp/src/inspection/multimodal.rs` |
| Capability tokens, accountability, DID:PLC, session guard | `vellaveto-mcp/src/{capability_token,accountability,did_plc,session_guard}.rs` |
| Semantic guardrails, A2A, transparency, discovery, projector | `vellaveto-mcp/src/{semantic_guardrails,a2a,transparency,discovery,projector}/` |
| **vellaveto-http-proxy** | |
| HTTP/WebSocket/gRPC proxy | `vellaveto-http-proxy/src/proxy/*.rs` |
| Transport health + smart fallback | `vellaveto-http-proxy/src/proxy/{transport_health,smart_fallback}.rs` |
| **vellaveto-server** | |
| HTTP API + routes | `vellaveto-server/src/main.rs`, `vellaveto-server/src/routes/*.rs` |
| Dashboard + setup wizard | `vellaveto-server/src/{dashboard,setup_wizard}.rs` |
| **vellaveto-operator** | |
| CRDs + reconcilers + client | `vellaveto-operator/src/{crd,client}.rs`, `vellaveto-operator/src/reconciler/*.rs` |
| Helm chart | `helm/vellaveto/` |
| **Other** | |
| Stdio proxy | `vellaveto-proxy/src/main.rs` |
| Cluster (leader election, service discovery) | `vellaveto-cluster/src/*.rs` |
| Integration tests (~110 files) | `vellaveto-integration/tests/` |
| SDKs: Python, TypeScript, Go, Java | `sdk/{python,typescript,go,java}/` |
| VS Code Extension | `vscode-vellaveto/` |
| Admin Console (React SPA) | `admin-console/` |
| Enterprise IAM (OIDC/SAML/RBAC) | `vellaveto-server/src/iam.rs`, `vellaveto-server/src/rbac.rs` |
| Self-service signup | `vellaveto-server/src/routes/signup.rs` |
| Terraform provider | `terraform-provider-vellaveto/` |
| OpenAPI 3.0 spec | `docs/openapi.yaml` |
| Policy preset templates (11) | `examples/presets/*.toml` |
| Cloud marketplace docs | `docs/MARKETPLACE.md` |
| SI pilot kit | `docs/si-pilot-kit/` |
| Formal verification (TLA+, Alloy) | `formal/` |

---

## What's Done (DO NOT rebuild)

All phases implemented, tested, and hardened through 224 audit rounds. Details in CHANGELOG.md.

**Core:** Policy evaluation (glob/regex/domain), path traversal protection, DNS rebinding, context-aware policies | **Audit:** Tamper-evident logging (SHA-256, Merkle, Ed25519), export (CEF/JSONL/webhook/syslog), PostgreSQL dual-write, ZK proofs (Pedersen + Groth16) | **Security:** Injection (Aho-Corasick + NFKC), DLP (5-layer decode), tool squatting, memory poisoning, behavioral anomaly, multimodal injection | **Auth:** OAuth 2.1/JWT/JWKS, ABAC forbid-overrides, capability delegation, least-agency | **Enterprise IAM:** OIDC (Okta/AzureAD/Keycloak), SAML 2.0, RBAC (4 roles, 14 perms), session management, SCIM 2.0 | **Transport:** HTTP, stdio, WebSocket, gRPC, MCP gateway, smart fallback | **Compliance:** EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, OWASP ASI, DORA, NIS2, evidence packs | **Infra:** K8s operator (3 CRDs), multi-tenancy, policy lifecycle (Draft→Active), setup wizard | **Admin Console:** React SPA (10 pages), OIDC+API-key auth, RBAC navigation, dark theme, 59 vitest tests | **SDKs:** Python (sync+async, LangChain/LangGraph/CrewAI/Google ADK/OpenAI Agents/Composio), TypeScript, Go, Java (120 tests) | **DevEx:** VS Code extension (validation, completions, snippets, simulator), execution graph SVG export | **Terraform:** Provider with policy resource + data sources (health, policies) | **Billing:** Per-tenant metering (atomic counters), quota enforcement, Stripe/Paddle webhooks, tiered licensing | **Marketplace:** Self-service signup (POST /api/signup), 11 policy preset templates, OpenAPI 3.0 spec (135+ endpoints), cloud deployment docs (AWS/Azure/GCP) | **Formal:** TLA+ (policy engine, ABAC, workflow), Alloy (capability delegation)

**Adversarial hardening:** 224 audit rounds, 1000+ findings fixed. Key patterns enforced: `deny_unknown_fields` on all deserialized structs, `validate()` with bounded collections, `has_dangerous_chars()` on all external strings, custom `Debug` redacting secrets, `saturating_add` on all counters, transport parity across HTTP/WS/gRPC/stdio/SSE.

---

## Code Change Protocol

### Small Change (<20 lines)
```bash
cargo test -p <crate>
git add <files> && git commit -m "<type>(<scope>): <description>"
```

### Large Change (>100 lines)
```bash
# 1. Types first (compile, test)
# 2. Core logic (compile, test)
# 3. Integration points (compile, test)
# 4. Full validation
cargo test --workspace
cargo clippy --workspace
```

### Commit Format
```
<type>(<scope>): <subject>

<body>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`
Scopes: `types`, `engine`, `audit`, `config`, `mcp`, `server`, `proxy`, `integration`

---

## Error Handling Rules

```rust
// CORRECT: Custom error type, no panics
pub fn evaluate(&self, action: &Action) -> Result<Verdict, EngineError> {
    let policy = self.find_policy(&action.tool)
        .ok_or_else(|| EngineError::NoPolicyFound(action.tool.clone()))?;
}

// WRONG: Panics in library code
pub fn evaluate(&self, action: &Action) -> Verdict {
    let policy = self.find_policy(&action.tool).unwrap(); // NEVER
}
```

---

## Testing Protocol

```bash
cargo test --lib --workspace          # Quick check
cargo test --workspace                # Full suite
cargo test -p vellaveto-engine        # Specific crate
cargo test -p vellaveto-engine -- --nocapture  # With output
```

Test naming: `test_<function>_<scenario>_<expected>`

---

## Security Checklist (before any PR)

- [ ] Fail-closed: errors produce Deny, not Allow
- [ ] No path traversal possible in PathRules
- [ ] Domain normalization handles edge cases
- [ ] Secrets never logged (parameters may contain API keys)
- [ ] Input validation on all external data
- [ ] No `unwrap()` or `expect()` in library code
- [ ] Rate limiting considered for new endpoints

---

## Common Mistakes to Avoid

> **Full orientation protocol:** See `docs/ONBOARDING.md` for the
> complete 17-trap checklist, transport parity matrix, and verification gates.
> Every instance MUST read it before modifying code.

### General
1. **Adding dependencies without justification** — every dep is attack surface
2. **Using `unwrap()` in library code** — use `?` or `ok_or_else()`
3. **Cloning when borrowing works** — check if `&T` suffices
4. **Skipping tests** — tests catch regressions you will introduce
5. **Ignoring warnings** — warnings become bugs
6. **Async where sync suffices** — the engine is synchronous by design
7. **Silent failures** — every error must be observable
8. **Premature optimization** — measure first, optimize proven hot spots

### Discovered from 224 audit rounds (top causes of breakage)
9. **Changing error messages without grepping tests** — tests assert on exact substrings; grep `tests.rs` for the old string before changing
10. **Using a name-similar constant** — `MAX_ID_LENGTH` vs `MAX_SERVER_ID_LENGTH` are different; verify the doc comment matches your domain
11. **Adding unbounded collections** — every `Vec`/`HashMap`/`HashSet` needs a `MAX_*` constant enforced in `validate()`
12. **Fail-open defaults** — defaults and error branches must produce `Deny`, not `Allow`; `unwrap_or(true)` on a lock is a security bypass
13. **Missing transport parity** — if HTTP handler has a check, WebSocket/gRPC/stdio/SSE must too; see `docs/ONBOARDING.md` Section 4
14. **Leaking secrets in `Debug`** — custom `Debug` impl required for types with keys, tokens, or signatures
15. **SDK payload format drift** — all 3 SDKs must match server's serde layout; test after any server format change
16. **Numeric fields without range validation** — `f64` scores need `[0.0, 1.0]` checks; `NaN`/`Infinity` bypass thresholds
17. **Counters without saturating arithmetic** — `+= 1` wraps to zero; use `saturating_add` for rate limits and circuit breakers

---

## References

- [MCP Specification 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP (arxiv)](https://arxiv.org/pdf/2504.08623)

---

## Bottega Multi-Agent Protocol

This project uses [Bottega](https://github.com/paolovella/bottega) for multi-agent orchestration. See `.claude/rules/` for agent roles, communication protocols, coordination state management, and dangerous commands policy.
