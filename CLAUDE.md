# CLAUDE.md — Sentinel Project Instructions

> **Project:** Sentinel — MCP Tool Firewall
> **State:** v2.2.1 stable (Phases 1–23 complete, 38 audit rounds — all phases done)
> **Version:** 3.0.0-dev (crates at 2.2.1, targeting v3.0 release)
> **License:** AGPL-3.0 dual license (see LICENSING.md)
> **Tests:** 4,812 Rust tests + 130 Python SDK tests + 28 Go SDK tests + 15 TypeScript SDK tests, zero warnings, zero `unwrap()` in library code
> **Fuzz targets:** 22
> **CI workflows:** 11
> **Updated:** 2026-02-14

---

## Mission

Sentinel is a runtime security engine for AI agent tool calls. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies on paths/domains/actions, and maintains a tamper-evident audit trail.

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
sentinel-types          (leaf — no internal deps)
       |
sentinel-canonical      (types only)
sentinel-config         (types only)
       |
sentinel-engine         (types, ipnet)
       |
sentinel-audit          (types, engine)
sentinel-approval       (types)
       |
sentinel-mcp            (types, engine, audit, approval, config)
       |
sentinel-cluster        (types, config, approval)
       |
sentinel-server         (all above)
sentinel-http-proxy     (all above)
sentinel-proxy          (all above, stdio mode)
sentinel-integration    (all above, test only)
```

Lower crates MUST NOT depend on higher crates.

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
| **sentinel-types** (leaf crate) | |
| Core types: Action, Verdict, Policy, PathRules, NetworkRules | `sentinel-types/src/core.rs` |
| Identity: AgentIdentity, CallChainEntry, EvaluationContext | `sentinel-types/src/identity.rs` |
| ETDI: signatures, attestation, version pinning | `sentinel-types/src/etdi.rs` |
| Threat: auth levels, circuit breakers, fingerprints, trust | `sentinel-types/src/threat.rs` |
| Advanced: ABAC, capability, compliance, extension, gateway, transport, verification, NHI, MINJA, DID:PLC, task | `sentinel-types/src/*.rs` |
| Tests (~137) | `sentinel-types/src/tests.rs` |
| **sentinel-engine** | |
| Policy evaluation | `sentinel-engine/src/lib.rs` |
| ABAC engine + Cedar-style evaluation | `sentinel-engine/src/abac.rs` |
| Least-agency tracker | `sentinel-engine/src/least_agency.rs` |
| **sentinel-audit** | |
| Module root + AuditLogger + rotation + verification | `sentinel-audit/src/lib.rs` |
| Redaction, checkpoints, Merkle proofs, events | `sentinel-audit/src/*.rs` |
| Compliance registries: EU AI Act, SOC 2, CoSAI, Adversa, gap analysis | `sentinel-audit/src/{eu_ai_act,soc2,cosai,adversa_top25,gap_analysis}.rs` |
| OTLP exporter, archive | `sentinel-audit/src/observability/otlp.rs`, `sentinel-audit/src/archive.rs` |
| Tests (~214) | `sentinel-audit/src/tests.rs` |
| **sentinel-config** | |
| Module root + PolicyConfig + validation | `sentinel-config/src/lib.rs`, `sentinel-config/src/config_validate.rs` |
| Detection, enterprise, ETDI, MCP protocol, threat detection | `sentinel-config/src/*.rs` |
| Advanced: ABAC, compliance, extension, FIPS, gateway, gRPC, transport | `sentinel-config/src/*.rs` |
| Tests (~164) | `sentinel-config/src/tests.rs` |
| **sentinel-mcp** | |
| MCP handling | `sentinel-mcp/src/lib.rs` |
| Proxy bridge (struct, builder, evaluation, relay, tests) | `sentinel-mcp/src/proxy/bridge/*.rs` |
| DLP / inspection + multimodal injection | `sentinel-mcp/src/inspection.rs`, `sentinel-mcp/src/inspection/multimodal.rs` |
| Capability tokens, accountability, DID:PLC | `sentinel-mcp/src/{capability_token,accountability,did_plc}.rs` |
| Red team, FIPS, Rekor, session guard | `sentinel-mcp/src/{red_team,fips,rekor,session_guard}.rs` |
| Semantic guardrails | `sentinel-mcp/src/semantic_guardrails/` |
| A2A protocol security | `sentinel-mcp/src/a2a/` |
| Extension registry | `sentinel-mcp/src/extension_registry.rs` |
| **sentinel-http-proxy** | |
| HTTP proxy: handlers, auth, origin, upstream, inspection | `sentinel-http-proxy/src/proxy/*.rs` |
| WebSocket reverse proxy | `sentinel-http-proxy/src/proxy/websocket/mod.rs` |
| gRPC reverse proxy (feature-gated) | `sentinel-http-proxy/src/proxy/grpc/*.rs` |
| Gateway router + health checker | `sentinel-http-proxy/src/proxy/gateway.rs` |
| Transport discovery + fallback | `sentinel-http-proxy/src/proxy/{discovery,fallback}.rs` |
| **sentinel-server** | |
| HTTP API server + routes | `sentinel-server/src/main.rs`, `sentinel-server/src/routes.rs` |
| Compliance + simulator API endpoints | `sentinel-server/src/routes/{compliance,simulator}.rs` |
| Dashboard | `sentinel-server/src/dashboard.rs` |
| **Other** | |
| Stdio proxy | `sentinel-proxy/src/main.rs` |
| Cluster backend | `sentinel-cluster/src/lib.rs` |
| Integration tests (~110 files) | `sentinel-integration/tests/` |
| Proto: MCP gRPC schema | `proto/mcp/v1/mcp.proto` |
| GitHub Action: policy-check | `.github/actions/policy-check/action.yml` |
| **SDKs** | |
| Python SDK: client, langchain, langgraph, redaction (130 tests) | `sdk/python/` |
| TypeScript SDK: client + types (15 tests) | `sdk/typescript/` |
| Go SDK: client + types + errors (28 tests) | `sdk/go/` |

---

## What's Done (DO NOT rebuild)

All 23 phases implemented, tested, and hardened through 38 audit rounds. Details in CHANGELOG.md.

- **Core Engine:** Policy evaluation with glob/regex/domain matching, path traversal protection, DNS rebinding defense, context-aware policies (time windows, call limits, agent ID, action sequences)
- **Audit:** Tamper-evident logging (SHA-256 chain, Merkle proofs, Ed25519 checkpoints, rotation), export (CEF/JSONL/webhook/syslog), immutable archive with retention
- **Security Detections:** Injection (Aho-Corasick + NFKC), rug-pull, DLP (5-layer decode), tool squatting (Levenshtein + homoglyph), memory poisoning, semantic injection (TF-IDF), behavioral anomaly (EMA), cross-request exfiltration tracking, multimodal injection (PNG/JPEG/PDF + stego)
- **Auth & Transport:** OAuth 2.1/JWT/JWKS, CSRF, rate limiting, MCP 2025-06-18 compliance, 6 deployment modes (HTTP, stdio, HTTP proxy, WebSocket proxy, gRPC proxy, MCP gateway)
- **Advanced Authorization (Phase 21):** ABAC with forbid-overrides, capability-based delegation tokens, least-agency tracking, identity federation, continuous authorization
- **MCP Gateway (Phase 20):** Multi-backend routing, health state machine, session affinity, tool conflict detection
- **Compliance (Phase 19):** EU AI Act registry + Art 50 transparency marking, SOC 2 evidence, CoSAI 38/38, Adversa TOP 25 25/25, 6-framework gap analysis, OTLP export, Merkle inclusion proofs
- **MCP Ecosystem:** Tool registry with trust scoring, elicitation interception, sampling enforcement, semantic guardrails (LLM-based), A2A protocol security
- **Transport (Phases 17–18):** WebSocket bidirectional proxy, gRPC reverse proxy (tonic), extension registry, transport discovery/negotiation/fallback
- **Research (Phase 23):** Red team mutation engine, FIPS 140-3 mode, Rekor transparency log, stateful session guards
- **Developer Experience (Phase 22):** Policy simulator API, CLI simulate, GitHub Action, dashboard SVG charts
- **Adversarial Hardening:** 5 pentest rounds (FIND-043–084 + Phase 23 Critical/High + Medium), RwLock poisoning hardened, PDF byte-level parsing, session guard fail-closed, Rekor canonical JSON, JPEG stego loop bound, PDF 4096-byte dict look-back, whitespace-normalized injection scan, EXIF 4-char min extraction, PDF hex string parsing, stego limitations documented
- **CI/CD:** 11 workflows, Docker/GHCR, release automation, SBOM, provenance attestation
- **SDKs:** Python (sync+async, LangChain/LangGraph, 130 tests), TypeScript (fetch-based, 15 tests), Go (stdlib-only, 28 tests)
- **Docs:** Quickstart guides, security model, benchmarks, 5 policy presets

---

## Code Change Protocol

### Small Change (<20 lines)
```bash
# Make change, test, commit
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
# Quick check
cargo test --lib --workspace

# Full suite
cargo test --workspace

# Specific crate
cargo test -p sentinel-engine

# With output
cargo test -p sentinel-engine -- --nocapture

# Coverage (requires cargo-llvm-cov)
cargo llvm-cov --workspace --html
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

1. **Adding dependencies without justification** — every dep is attack surface
2. **Using `unwrap()` in library code** — use `?` or `ok_or_else()`
3. **Cloning when borrowing works** — check if `&T` suffices
4. **Skipping tests** — tests catch regressions you will introduce
5. **Ignoring warnings** — warnings become bugs
6. **Async where sync suffices** — the engine is synchronous by design
7. **Silent failures** — every error must be observable
8. **Premature optimization** — measure first, optimize proven hot spots

---

## References

- [MCP Specification 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP (arxiv)](https://arxiv.org/pdf/2504.08623)

---

## Bottega Multi-Agent Protocol

This project uses [Bottega](https://github.com/paolovella/bottega) for multi-agent orchestration. See `.claude/rules/` for agent roles, communication protocols, coordination state management, and dangerous commands policy.
