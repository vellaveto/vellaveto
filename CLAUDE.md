# CLAUDE.md — Sentinel Project Instructions

> **Project:** Sentinel — MCP Tool Firewall
> **State:** All priority items (P0–P4) implemented, Phase 14 A2A protocol security complete, all adversarial audit findings (FIND-043–054) addressed
> **Tests:** 4,300+ passing, zero warnings, zero `unwrap()` in library code
> **Updated:** 2026-02-12

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
| Core types | `sentinel-types/src/lib.rs` |
| Policy evaluation | `sentinel-engine/src/lib.rs` |
| Audit: module root + re-exports | `sentinel-audit/src/lib.rs` |
| Audit: types (AuditEntry, AuditError, etc.) | `sentinel-audit/src/types.rs` |
| Audit: sensitive key/PII redaction | `sentinel-audit/src/redaction.rs` |
| Audit: AuditLogger struct + log_entry | `sentinel-audit/src/logger.rs` |
| Audit: log rotation + manifest | `sentinel-audit/src/rotation.rs` |
| Audit: hash chain verification | `sentinel-audit/src/verification.rs` |
| Audit: Ed25519 signed checkpoints | `sentinel-audit/src/checkpoints.rs` |
| Audit: security event logging helpers | `sentinel-audit/src/events.rs` |
| Audit: ETDI tool security logging | `sentinel-audit/src/etdi_audit.rs` |
| Audit: tests (~130 unit tests) | `sentinel-audit/src/tests.rs` |
| Config root + PolicyConfig | `sentinel-config/src/lib.rs` |
| Config: injection/DLP/rate-limit/audit | `sentinel-config/src/detection.rs` |
| Config: supply chain verification | `sentinel-config/src/supply_chain.rs` |
| Config: tool manifest signing | `sentinel-config/src/manifest.rs` |
| Config: ETDI / version pinning | `sentinel-config/src/etdi.rs` |
| Config: MCP protocol (elicitation, sampling) | `sentinel-config/src/mcp_protocol.rs` |
| Config: threat detection (10 detectors) | `sentinel-config/src/threat_detection.rs` |
| Config: TLS/OPA/SPIFFE/JIT/threat-intel | `sentinel-config/src/enterprise.rs` |
| Config: memory security / NHI / DPoP | `sentinel-config/src/memory_nhi.rs` |
| Config: semantic guardrails backends | `sentinel-config/src/semantic_guardrails_config.rs` |
| Config: RAG defense / grounding | `sentinel-config/src/rag_defense_config.rs` |
| Config: observability | `sentinel-config/src/observability.rs` |
| Config: validation helpers | `sentinel-config/src/validation.rs` |
| MCP handling | `sentinel-mcp/src/lib.rs` |
| Proxy bridge: struct + constructor | `sentinel-mcp/src/proxy/bridge/mod.rs` |
| Proxy bridge: builder methods | `sentinel-mcp/src/proxy/bridge/builder.rs` |
| Proxy bridge: policy evaluation | `sentinel-mcp/src/proxy/bridge/evaluation.rs` |
| Proxy bridge: identity + flagged tools | `sentinel-mcp/src/proxy/bridge/helpers.rs` |
| Proxy bridge: run() relay loop | `sentinel-mcp/src/proxy/bridge/relay.rs` |
| Proxy bridge: tests | `sentinel-mcp/src/proxy/bridge/tests.rs` |
| DLP / inspection | `sentinel-mcp/src/inspection.rs` |
| Output validation | `sentinel-mcp/src/output_validation.rs` |
| Semantic guardrails | `sentinel-mcp/src/semantic_guardrails/` |
| A2A protocol security | `sentinel-mcp/src/a2a/` |
| HTTP proxy: structs + constants | `sentinel-http-proxy/src/proxy/mod.rs` |
| HTTP proxy: handler functions | `sentinel-http-proxy/src/proxy/handlers.rs` |
| HTTP proxy: OAuth/API key/agent auth | `sentinel-http-proxy/src/proxy/auth.rs` |
| HTTP proxy: origin/CSRF validation | `sentinel-http-proxy/src/proxy/origin.rs` |
| HTTP proxy: call chain/escalation | `sentinel-http-proxy/src/proxy/call_chain.rs` |
| HTTP proxy: upstream forwarding | `sentinel-http-proxy/src/proxy/upstream.rs` |
| HTTP proxy: response inspection | `sentinel-http-proxy/src/proxy/inspection.rs` |
| HTTP proxy: utility helpers | `sentinel-http-proxy/src/proxy/helpers.rs` |
| HTTP proxy: tests | `sentinel-http-proxy/src/proxy/tests.rs` |
| Stdio proxy | `sentinel-proxy/src/main.rs` |
| HTTP API server | `sentinel-server/src/main.rs` |
| Server routes | `sentinel-server/src/routes.rs` |
| Cluster backend | `sentinel-cluster/src/lib.rs` |
| Integration tests | `sentinel-integration/tests/` (~95 test files) |
| Example configs | `examples/` |

---

## What's Done (DO NOT rebuild)

The following are **implemented, tested, and hardened** through 18 rounds of adversarial audit:

**Core Engine & Policies:**
- Policy engine with glob, regex, domain matching, parameter constraints
- Path rules (allowed/blocked globs, traversal-safe normalization)
- Network rules (allowed/blocked domains, RFC 1035 validation)
- DNS rebinding protection (IpRules: block_private, CIDR allow/blocklists)
- Context-aware policies (time windows, per-session call limits, agent ID, action sequences)

**Audit & Approvals:**
- Tamper-evident audit logging (SHA-256 hash chain, Ed25519 checkpoints, rotation)
- Human-in-the-loop approvals with deduplication and audit trail
- Audit log export: CEF, JSON Lines, webhook, syslog (`sentinel-audit/src/export.rs`)

**Security Detections:**
- Injection detection (Aho-Corasick, Unicode NFKC normalization, configurable blocking)
- Rug-pull detection (annotation changes, schema mutations, persistent flagging)
- DLP scanning (requests + responses, 5-layer decode: raw/base64/percent/combos)
- Structured output validation (OutputSchemaRegistry)
- Tool squatting detection — Levenshtein + homoglyph (`sentinel-mcp/src/rug_pull.rs`)
- Memory poisoning defense — cross-request data laundering detection (`sentinel-mcp/src/memory_tracking.rs`)
- Semantic injection detection — n-gram TF-IDF similarity (`sentinel-mcp/src/semantic_detection.rs`)
- Behavioral anomaly detection — EMA-based tool call frequency tracking (`sentinel-engine/src/behavioral.rs`)
- Cross-request data flow tracking — session-level exfiltration chain detection (`sentinel-mcp/src/inspection.rs`)

**Auth & Transport:**
- OAuth 2.1 / JWT with JWKS and scope enforcement
- Agent identity attestation via signed JWTs (`sentinel-server/src/routes.rs`)
- CSRF, rate limiting, security headers, session management
- MCP 2025-06-18 compliance (protocol version header, resource indicators, `_meta`)

**Deployment & Operations:**
- Three deployment modes: HTTP API, stdio proxy, HTTP reverse proxy
- Canonical presets for common security scenarios
- CI: `cargo audit`, `unwrap()` hygiene, clippy clean
- Distributed clustering via `sentinel-cluster` crate (LocalBackend + RedisBackend with feature gate)
- Prometheus metrics endpoint (`/metrics`) with evaluation histograms (`sentinel-server/src/metrics.rs`)
- Hot policy reload via filesystem watcher and `/api/policies/reload` endpoint
- Admin dashboard — server-rendered HTML (`sentinel-server/src/dashboard.rs`)
- Multi-agent communication monitoring — privilege escalation detection (`sentinel-http-proxy/src/proxy/call_chain.rs`)

**MCP Ecosystem:**
- Tool registry with trust scoring (`sentinel-mcp/src/tool_registry.rs`)
- Elicitation interception — capability/schema/rate-limit validation (`sentinel-mcp/src/elicitation.rs`)
- Sampling request policy enforcement — configurable model/content/tool-output rules (`sentinel-mcp/src/proxy/bridge/relay.rs`)

**Semantic Guardrails (Phase 12):**
- LLM-based policy evaluation with pluggable backends (`sentinel-mcp/src/semantic_guardrails/`)
- Intent classification taxonomy — DataRead, DataWrite, SystemExecute, NetworkFetch, CredentialAccess, etc.
- Natural language policies with glob-based tool/function matching (`sentinel-mcp/src/semantic_guardrails/nl_policy.rs`)
- Intent chain tracking for suspicious pattern detection (`sentinel-mcp/src/semantic_guardrails/intent.rs`)
- Jailbreak detection with configurable thresholds (`sentinel-mcp/src/semantic_guardrails/evaluator.rs`)
- LRU + TTL evaluation caching (`sentinel-mcp/src/semantic_guardrails/cache.rs`)
- Mock backend for testing (`sentinel-mcp/src/semantic_guardrails/backends/mock.rs`)
- Feature flags: `semantic-guardrails`, `llm-cloud`, `llm-local-gguf`, `llm-local-onnx`

**A2A Protocol Security (Phase 14):**
- A2A message classification — message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe (`sentinel-mcp/src/a2a/message.rs`)
- Action extraction — Convert A2A messages to Sentinel Actions for policy evaluation (`sentinel-mcp/src/a2a/extractor.rs`)
- Agent Card handling — Fetch, cache, and validate A2A Agent Cards with TTL expiration (`sentinel-mcp/src/a2a/agent_card.rs`)
- A2A proxy service — HTTP proxy with policy evaluation and security integration (`sentinel-mcp/src/a2a/proxy.rs`)
- Batch rejection — JSON-RPC batch requests rejected for TOCTOU attack prevention
- Security integration — DLP scanning, injection detection, circuit breaker support
- Feature flag: `a2a`

**Testing & Quality:**
- Criterion benchmarks for policy evaluation, path normalization, domain matching, DLP scanning (`sentinel-engine/benches/`, `sentinel-mcp/benches/`)
- Fuzz targets for JSON-RPC framing, path normalization, domain extraction, CIDR parsing, message classification, scan_params_for_targets (`fuzz/fuzz_targets/`)

**Adversarial Audit Coverage (FIND-043–054):**
- 25 context condition tests covering all 10 condition types (MaxChainDepth, AgentIdentityMatch, AsyncTaskPolicy, ResourceIndicator, CapabilityRequired, StepUpAuth, CircuitBreaker, DeputyValidation, SchemaPoisoningCheck, ShadowAgentCheck)
- Circuit breaker HalfOpen→Closed recovery + Open→HalfOpen auto-transition tests
- 16 end-to-end OAuth JWT validation tests (sign → mock JWKS server → validate_token)
- Domain homoglyph tests (Cyrillic, zero-width, fullwidth, mixed-script)
- Windows path normalization tests (UNC, drive letters, mixed separators)
- Audit rotation manifest tamper detection tests (deletion, reordering)
- Memory tracker fingerprint evasion tests (case sensitivity, encoding, query params)
- 13 semantic scanner Unicode evasion tests (fullwidth, Cyrillic, ZWSP, combining diacritics, RTL)
- Agent card URL edge case tests (file://, internal IPs, path traversal, XSS)
- Behavioral EMA edge case tests (epsilon guard, u64::MAX, overflow)
- Output validation depth bomb tests (nested schemas at/beyond MAX_VALIDATION_DEPTH)
- Elicitation rate limit boundary tests (u32::MAX, exact boundary)

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
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP (arxiv)](https://arxiv.org/pdf/2504.08623)
- [Microsoft: From Runtime Risk to Real-Time Defense](https://www.microsoft.com/en-us/security/blog/2026/01/23/runtime-risk-realtime-defense-securing-ai-agents/)
- [Kaspersky: Agentic AI Security per OWASP ASI Top 10](https://www.kaspersky.com/blog/top-agentic-ai-risks-2026/55184/)

---

## Bottega Multi-Agent Protocol

This project uses the [Bottega](https://github.com/paolovella/bottega) multi-agent orchestration system.

### Agent Roles

| Agent | Role | Worktree Branch |
|-------|------|-----------------|
| **Orchestrator** | Decomposes tasks, assigns work, approves merges | `work/orchestrator` |
| **Adversarial** | Security scanning, architecture review, bug finding | `work/adversarial` |
| **Gap-Hunter** | Finds test/reliability/observability/docs gaps | `work/gap-hunter` |
| **Improvement-Scout** | Proposes prioritized, high-ROI improvements | `work/improvement-scout` |
| **Worker-1 (Builder)** | Implements tasks, writes tests | `work/worker-1` |
| **Worker-2 (Researcher)** | Researches then implements complex tasks | `work/worker-2` |
| **Reviewer** | Reviews completed work, approves or requests changes | `work/reviewer` |

### Coordination State

All coordination state lives in `coordination/` (a symlink to shared storage):

- **`kanban.json`** — Task board with optimistic concurrency control
- **`events.jsonl`** — Append-only event log

### Writing State

**CRITICAL: Never open coordination files directly for writing.**

```bash
# Append to event log
python3 scripts/lib/lock.py append coordination/events.jsonl '<json>'

# Update kanban (optimistic locking)
python3 scripts/lib/lock.py read-revision coordination/kanban.json
python3 scripts/lib/lock.py revision-write coordination/kanban.json <rev> '<json>'
```

### Quality Gates (Rust)

Before any merge:
```bash
cargo test --workspace           # All tests pass
cargo clippy --workspace         # No warnings
cargo fmt --check                # Properly formatted
```

### Task Lifecycle

```
todo → in_progress (worker claims) → review (worker submits)
  → reviewed (reviewer approves) → quality gates → merge to main
  → rebase all branches → done
```

See `.claude/rules/` for detailed communication, security, and architecture rules.
