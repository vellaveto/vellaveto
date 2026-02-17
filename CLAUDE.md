# CLAUDE.md — Vellaveto Project Instructions

> **Project:** Vellaveto — MCP Tool Firewall
> **State:** v4.0.0-dev (Phases 1–25.1/25.2/25.6 + 26 + 27 + 29 + 30 + 33 + 34 + 35 + 37 + 38 complete, 49 audit rounds)
> **Version:** 4.0.0-dev
> **License:** AGPL-3.0 dual license (see LICENSING.md)
> **Tests:** 6,103 Rust tests + 298 Python SDK tests + 40 Go SDK tests + 64 TypeScript SDK tests, zero warnings, zero `unwrap()` in library code
> **Fuzz targets:** 24
> **CI workflows:** 11 (15 jobs)
> **Updated:** 2026-02-17

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
| **vellaveto-types** (leaf crate) | |
| Core types: Action, Verdict, Policy, PathRules, NetworkRules | `vellaveto-types/src/core.rs` |
| Identity: AgentIdentity, CallChainEntry, EvaluationContext, RequestContext trait, StatelessContextBlob | `vellaveto-types/src/identity.rs` |
| ETDI: signatures, attestation, version pinning | `vellaveto-types/src/etdi.rs` |
| Threat: auth levels, circuit breakers, fingerprints, trust | `vellaveto-types/src/threat.rs` |
| Advanced: ABAC, capability, compliance, extension, gateway, transport, verification, NHI, MINJA, DID:PLC, task | `vellaveto-types/src/*.rs` |
| Governance: EnforcementMode, UnregisteredAgent, ShadowAiReport | `vellaveto-types/src/governance.rs` |
| Discovery: ToolMetadata, ToolSensitivity, DiscoveryResult | `vellaveto-types/src/discovery.rs` |
| Projector: CanonicalToolSchema, CanonicalToolCall, ModelFamily | `vellaveto-types/src/projector.rs` |
| ZK Audit: PedersenCommitment, ZkBatchProof, ZkVerifyResult, ZkSchedulerStatus | `vellaveto-types/src/zk_audit.rs` |
| Tests (~180) | `vellaveto-types/src/tests.rs` |
| **vellaveto-engine** | |
| Policy evaluation | `vellaveto-engine/src/lib.rs` |
| ABAC engine + Cedar-style evaluation | `vellaveto-engine/src/abac.rs` |
| Least-agency tracker | `vellaveto-engine/src/least_agency.rs` |
| **vellaveto-audit** | |
| Module root + AuditLogger + rotation + verification | `vellaveto-audit/src/lib.rs` |
| Redaction, checkpoints, Merkle proofs, events | `vellaveto-audit/src/*.rs` |
| Compliance registries: EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, gap analysis | `vellaveto-audit/src/{eu_ai_act,soc2,cosai,adversa_top25,iso42001,gap_analysis}.rs` |
| Data governance registry (Art 10) | `vellaveto-audit/src/data_governance.rs` |
| ZK audit: Pedersen commitments, witness store, Groth16 circuit, batch prover, scheduler | `vellaveto-audit/src/zk/{mod,pedersen,witness,circuit,prover,scheduler}.rs` |
| Access review report generator + HTML renderer | `vellaveto-audit/src/access_review.rs` |
| OTLP exporter, archive | `vellaveto-audit/src/observability/otlp.rs`, `vellaveto-audit/src/archive.rs` |
| Tests (~421) | `vellaveto-audit/src/tests.rs` |
| **vellaveto-config** | |
| Module root + PolicyConfig + validation | `vellaveto-config/src/lib.rs`, `vellaveto-config/src/config_validate.rs` |
| Detection, enterprise, ETDI, MCP protocol, threat detection | `vellaveto-config/src/*.rs` |
| Advanced: ABAC, compliance, extension, FIPS, gateway, gRPC, transport | `vellaveto-config/src/*.rs` |
| Governance config | `vellaveto-config/src/governance.rs` |
| Discovery config | `vellaveto-config/src/discovery.rs` |
| Projector config | `vellaveto-config/src/projector.rs` |
| ZK Audit config | `vellaveto-config/src/zk_audit.rs` |
| Tests (~301) | `vellaveto-config/src/tests.rs` |
| **vellaveto-mcp** | |
| MCP handling | `vellaveto-mcp/src/lib.rs` |
| Proxy bridge (struct, builder, evaluation, relay, tests) | `vellaveto-mcp/src/proxy/bridge/*.rs` |
| DLP / inspection + multimodal injection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM) | `vellaveto-mcp/src/inspection.rs`, `vellaveto-mcp/src/inspection/multimodal.rs` |
| Capability tokens, accountability, DID:PLC | `vellaveto-mcp/src/{capability_token,accountability,did_plc}.rs` |
| Red team, FIPS, Rekor, session guard | `vellaveto-mcp/src/{red_team,fips,rekor,session_guard}.rs` |
| Semantic guardrails | `vellaveto-mcp/src/semantic_guardrails/` |
| A2A protocol security | `vellaveto-mcp/src/a2a/` |
| Transparency marking + decision explanation | `vellaveto-mcp/src/transparency.rs` |
| Extension registry | `vellaveto-mcp/src/extension_registry.rs` |
| Shadow AI discovery engine | `vellaveto-mcp/src/shadow_ai_discovery.rs` |
| Tool discovery (TF-IDF index, engine, feature-gated) | `vellaveto-mcp/src/discovery/` |
| Model projector (trait, registry, 5 projections, compress, repair) | `vellaveto-mcp/src/projector/` |
| **vellaveto-http-proxy** | |
| HTTP proxy: handlers, auth, origin, upstream, inspection | `vellaveto-http-proxy/src/proxy/*.rs` |
| WebSocket reverse proxy | `vellaveto-http-proxy/src/proxy/websocket/mod.rs` |
| gRPC reverse proxy (feature-gated) | `vellaveto-http-proxy/src/proxy/grpc/*.rs` |
| Gateway router + health checker | `vellaveto-http-proxy/src/proxy/gateway.rs` |
| Transport discovery + fallback | `vellaveto-http-proxy/src/proxy/{discovery,fallback}.rs` |
| Transport health tracker (per-transport circuit breaker) | `vellaveto-http-proxy/src/proxy/transport_health.rs` |
| Smart fallback chain orchestrator | `vellaveto-http-proxy/src/proxy/smart_fallback.rs` |
| **vellaveto-server** | |
| HTTP API server + routes | `vellaveto-server/src/main.rs`, `vellaveto-server/src/routes.rs` |
| Compliance + simulator API endpoints | `vellaveto-server/src/routes/{compliance,simulator}.rs` |
| Governance API routes | `vellaveto-server/src/routes/governance.rs` |
| Discovery API routes | `vellaveto-server/src/routes/discovery.rs` |
| Projector API routes | `vellaveto-server/src/routes/projector.rs` |
| ZK Audit API routes (status, proofs, verify, commitments) | `vellaveto-server/src/routes/zk_audit.rs` |
| SOC 2 Access Review route (JSON/HTML) | `vellaveto-server/src/routes/compliance.rs` |
| Dashboard | `vellaveto-server/src/dashboard.rs` |
| **Other** | |
| Stdio proxy | `vellaveto-proxy/src/main.rs` |
| Cluster backend | `vellaveto-cluster/src/lib.rs` |
| Leader election trait + local impl | `vellaveto-cluster/src/{leader,leader_local}.rs` |
| Service discovery trait + static/DNS impls | `vellaveto-cluster/src/{discovery,discovery_static,discovery_dns}.rs` |
| Deployment types (LeaderStatus, ServiceEndpoint, etc.) | `vellaveto-types/src/deployment.rs` |
| Deployment config (mode, leader election, service discovery) | `vellaveto-config/src/deployment.rs` |
| Deployment API route | `vellaveto-server/src/routes/deployment.rs` |
| Integration tests (~110 files) | `vellaveto-integration/tests/` |
| Proto: MCP gRPC schema | `proto/mcp/v1/mcp.proto` |
| GitHub Action: policy-check | `.github/actions/policy-check/action.yml` |
| **SDKs** | |
| Python SDK: client, langchain, langgraph, composio, redaction (298 tests) | `sdk/python/` |
| Composio integration: guard, modifiers, extractor, scanner (84 tests) | `sdk/python/vellaveto/composio/` |
| TypeScript SDK: client + types (64 tests) | `sdk/typescript/` |
| Go SDK: client + types + errors (40 tests) | `sdk/go/` |
| **Formal Verification** | |
| Shared TLA+ operators (pattern matching, sorting) | `formal/tla/MCPCommon.tla` |
| Policy engine state machine (S1–S6, L1–L2) | `formal/tla/MCPPolicyEngine.tla` + `.cfg` |
| ABAC forbid-overrides (S7–S10) | `formal/tla/AbacForbidOverrides.tla` + `.cfg` |
| Capability delegation model (S11–S16) | `formal/alloy/CapabilityDelegation.als` |

---

## What's Done (DO NOT rebuild)

All 24 phases + Phase 25 (sub-phases 25.1/25.2/25.6) + Phase 26 + Phase 27 + Phase 29 + Phase 30 + Phase 33 + Phase 34 + Phase 35 + Phase 37 + Phase 38 implemented, tested, and hardened through 47 audit rounds. Details in CHANGELOG.md.

- **Core Engine:** Policy evaluation with glob/regex/domain matching, path traversal protection, DNS rebinding defense, context-aware policies (time windows, call limits, agent ID, action sequences)
- **Audit:** Tamper-evident logging (SHA-256 chain, Merkle proofs, Ed25519 checkpoints, rotation), export (CEF/JSONL/webhook/syslog), immutable archive with retention
- **Security Detections:** Injection (Aho-Corasick + NFKC), rug-pull, DLP (5-layer decode), tool squatting (Levenshtein + homoglyph), memory poisoning, semantic injection (TF-IDF), behavioral anomaly (EMA), cross-request exfiltration tracking, multimodal injection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM + stego)
- **Auth & Transport:** OAuth 2.1/JWT/JWKS, CSRF, rate limiting, MCP 2025-06-18 compliance, 6 deployment modes (HTTP, stdio, HTTP proxy, WebSocket proxy, gRPC proxy, MCP gateway)
- **Advanced Authorization (Phase 21):** ABAC with forbid-overrides, capability-based delegation tokens, least-agency tracking, identity federation, continuous authorization
- **MCP Gateway (Phase 20):** Multi-backend routing, health state machine, session affinity, tool conflict detection
- **Compliance (Phase 19):** EU AI Act registry + Art 50 transparency marking, SOC 2 evidence, CoSAI 38/38, Adversa TOP 25 25/25, 7-framework gap analysis, OTLP export, Merkle inclusion proofs
- **EU AI Act Final Compliance (Phase 24):** Art 50(2) automated decision explanations (VerdictExplanation at configurable verbosity), Art 10 data governance registry (DataGovernanceRecord with classification/purpose/provenance/retention), decision explanation injection into `_meta`
- **MCP Ecosystem:** Tool registry with trust scoring, elicitation interception, sampling enforcement, semantic guardrails (LLM-based), A2A protocol security
- **Transport (Phases 17–18):** WebSocket bidirectional proxy, gRPC reverse proxy (tonic), extension registry, transport discovery/negotiation/fallback
- **Research (Phase 23):** Red team mutation engine, FIPS 140-3 mode, Rekor transparency log, stateful session guards
- **Audio/Video Inspection (Phase 25.1/25.2):** WAV LIST/INFO metadata extraction, MP3 ID3v2 tag parsing (text/comment/lyrics frames, syncsafe integers, 4 encodings), MP4 moov/udta/meta/ilst metadata, WebM EBML tag extraction, FLAC/OGG/AVI magic bytes detection
- **Stateless Protocol Abstraction (Phase 25.6):** `RequestContext` trait for session-agnostic policy evaluation, `StatefulContext` adapter for SessionState, `StatelessContextBlob` struct for future stateless HTTP mode (signed per-request context with HMAC-SHA256, expiry)
- **Developer Experience (Phase 22):** Policy simulator API, CLI simulate, GitHub Action, dashboard SVG charts
- **Adversarial Hardening:** 5 pentest rounds (FIND-043–084 + Phase 23 Critical/High + Medium), RwLock poisoning hardened, PDF byte-level parsing, session guard fail-closed, Rekor canonical JSON, JPEG stego loop bound, PDF 4096-byte dict look-back, whitespace-normalized injection scan, EXIF 4-char min extraction, PDF hex string parsing, stego limitations documented, Phase 27 adversarial audit (FIND-P27-001–007: DNS amplification DoS on /health cached, mutex poisoning propagated, SSRF dns_name validation, instance_id dot validation, effective_instance_id cached at startup), Phase 29 adversarial audit round 41 (FIND-R41-001–015: header allowlist on forwarded requests, shell injection prevention for stdio command, circuit breaker OOM bound, response body size limit, stdio zombie process kill-on-timeout, exec graph node limit, gateway URL scheme validation, transport overrides count bound, stderr capture, control character log injection, glob key validation), Round 42 (FIND-R42-002–020: transport preference header dedup+cap, URL host parser SSRF via userinfo/@/IPv6, circuit breaker capacity fail-closed, exec graph metadata-before-bounds-check, agent trust graph session limit, backend URL scheme validation, wildcard glob coexistence rejection, half-open thundering herd prevention, DOT language injection escaping, failure_count saturating arithmetic, duplicate protocol validation, clock error logging, path parameter length validation, self-delegation rejection, fallback response body bounded, rotation manifest start_hash), Round 43 (FIND-R43-001–035: stdio pipe deadlock fixed via concurrent stdout read, subprocess environment cleared, kill_on_drop(true), 5xx circuit breaker corrected, stale Open→HalfOpen success discarded, Merkle leaf pruning exclusion, manifest skip-missing-files verification, NHI terminal-state enforcement, unbounded trust_edges/privilege_levels/trusted_agents capped, cleanup() auto-invoked, Unicode format char validation, case-insensitive self-delegation, match-all glob pattern rejection, URL-encoded %40 userinfo, IPv6 gRPC URL brackets, gateway counter saturating_add, WebSocket URL prefix-only replacement, dangerous status code blocking, exec_graph edge validation/dedup/self-loop rejection, escape_dot pipe+null, roots dedup, NHI body field validation, TOCTOU delegation fix, DeputyError redaction, backend ID validation, tool prefix uniqueness, UTF-8 safe gateway truncation), Round 44 (FIND-R44-001–008), Round 45 (FIND-R45-001–015: GET /mcp full security parity with POST — session ownership binding, agent identity validation, call chain validation, audit logging, rug-pull detection in GET SSE path, output schema validation, gateway mode rejection, session touch/request_count, error message normalization, Last-Event-ID generic errors), Round 46 (~177 findings across P1/P2/P3: fail-closed defaults for ToolSensitivity/NhiIdentityStatus/ABAC NotIn, MemoryEntry trust consistency, deny_unknown_fields on security structs, relay channel bounds, Merkle rotation hardening, SDK input validation/redaction/thread safety, config pattern length limits, JSON depth validation, token budget caps), Round 47 (3 P0 + 12 P1: unbounded intent_chains capped at 10K, SDK payload format mismatch fixed — Python/Go/TS now send flattened fields matching server's `#[serde(flatten)]`, async response body size limit, ZK witness restore-on-failure, ES retry with exponential backoff, OTLP stub error on non-empty batch, ES partial failure detection, ABAC CompiledPathMatcher with globset parity, MINJA trust decay fail-closed on corrupt timestamps, ZK commitments endpoint bounded at 500K entries, SDK approval API paths corrected, TS evaluate extracts verdict fields, Go/TS ZK Audit methods added, 30 P2 + 22 P3: ABAC IDNA normalization, RwLock poison recovery, max_calls_in_window overflow error, no-op context warn!, infix wildcard warning, validate_finite for 5 types, Policy::validate(), UpstreamBackend::validate(), LeastAgencyTracker poisoned lock logging, MAX_PARAMETERS_SIZE 1MB, webhook/streaming URL scheme validation, redaction fail-closed at max depth, ZK scheduler exponential backoff, MAX_COMPILED_POLICIES 10K, FallbackBehavior::Allow warning, serialization errors return HTTP 500, MAX_DASHBOARD_AUDIT_ENTRIES 1K, MAX_DISCOVERED_TOOLS_PER_SESSION 10K, proxy env clearing), Round 48 (2 P1 + 10 P2 + 4 P3: WS canonicalization fail-closed across 6 message types closing TOCTOU gap, Action::validate() fail-closed on serialization failure, ABAC NaN risk.score treated as max risk preventing Forbid bypass, ProvenanceNode/AbacEntity/NhiAgentIdentity/NhiDelegationLink/MemoryNamespace/NhiBehavioralBaseline validate() bounds on deserialized collections, exec graph session path validation, discovery sensitivity param validation, SamplingStats flagged_patterns truncated at 1K, Policy deny_unknown_fields, truncate_for_log max_len<4 guard, WS extract_strings_recursive parts bounded at 1K), Round 49 (6 P1 + 17 P2 + 10 P3: EvaluationContext/StatelessContextBlob collection bounds enforced preventing pre-sanitization OOM, AccessReviewEntry.usage_ratio validate_finite preventing NaN threshold bypass, ZK audit mutex poison details redacted from client responses, list_graphs tool filter iteration capped at 10K, session guard violation/anomaly counters saturating_add preventing overflow lock bypass, ETDI is_expired() UTC-only validation preventing timezone bypass, AgentIdentity.claims bounded at 64, ShadowAiReport/governance vectors bounded matching runtime caps, FederationTrustAnchor.identity_mappings bounded at 64, ABAC path normalization uses bounded iterations, MaxChainDepth off-by-one fixed to >= for consistency, circuit breaker saturating arithmetic, dashboard error leak + control char validation, audit export parameter validation, shadow AI discovery lock poisoning fail-closed, access review timestamp UTC normalization, SOC 2 access review entry count guard, ZkVerifyRequest deny_unknown_fields, legacy infix wildcard fail-closed, ABAC absent claim returns false not empty string)
- **CI/CD:** 11 workflows, Docker/GHCR, release automation, SBOM, provenance attestation
- **SDKs:** Python (sync+async, LangChain/LangGraph/Composio, 298 tests), TypeScript (fetch-based, 64 tests), Go (stdlib-only, 40 tests)
- **Composio Integration:** `ComposioGuard` with `before_execute`/`after_execute` modifier factories for universal Composio provider support (OpenAI, LangChain, CrewAI, AutoGen, Google ADK), client-side response scanning (DLP + injection with NFKC normalization + invisible char stripping), `CallChainTracker` (thread-safe, bounded FIFO), slug normalization (ASCII-only with homoglyph rejection), target extraction (recursive with depth bound, file:// URI support), standalone `execute()` wrapper with TOCTOU prevention, 84 tests (49 adversarial)
- **Formal Verification (Phase 33):** TLA+ specs for policy engine (7 safety + 2 liveness, including S7 RequireApproval invariant) and ABAC forbid-overrides (4 safety), Alloy model for capability delegation (6 safety assertions), 20 verified properties with source traceability and VERIFIED markers in engine/mcp source
- **Codebase Improvement Campaign:** ~165 new unit tests (engine 687, MCP 1,083, audit 441), 14 Criterion benchmarks (ABAC, Merkle, injection/DLP, E2E pipeline), 4 new CI jobs (cargo-vet, semver-checks, MSRV 1.75.0, feature matrix), relay security hardening (VELLAVETO_AGENT_ID env var, channel buffer bounds, oversized message dropping)
- **Shadow AI Detection & Governance (Phase 26):** Passive shadow AI discovery engine (unregistered agents, unapproved tools, unknown MCP servers with bounded tracking — max 1000/500/100), governance API endpoints (shadow-report, unregistered-agents, unapproved-tools, least-agency), `GovernanceConfig` with `require_agent_registration` fail-closed mode, `LeastAgencyTracker` enforcement mode with auto-revocation, governance dashboard section, audit event helpers (`shadow_ai.{unregistered_agent,unapproved_tool,unknown_server}`, `least_agency.{report,auto_revoke}`)
- **Kubernetes-Native Deployment (Phase 27):** `LeaderElection` trait + `LocalLeaderElection` (always-leader standalone), `ServiceDiscovery` trait + `StaticServiceDiscovery` + `DnsServiceDiscovery` (tokio lookup_host + periodic watch), `DeploymentConfig` with validation (mode/leader-election/service-discovery/instance-id), `GET /api/deployment/info` endpoint, health endpoint extended with `leader_status`/`instance_id`/`discovered_endpoints`, Helm chart StatefulSet with PVC + init container + log-shipping sidecar + headless Service + gRPC/WebSocket support, Chart version 4.0.0, audit event helpers (`leader_election.{acquired,renewed,released,lost,failed}`, `service_discovery.{endpoint_added,endpoint_removed,endpoint_updated,refresh_failed}`)
- **Cross-Transport Smart Fallback (Phase 29):** `TransportHealthTracker` per-transport circuit breaker (Closed/Open/HalfOpen, exponential backoff, RwLock fail-closed, bounded 10K circuits), `SmartFallbackChain` ordered fallback orchestrator (gRPC → WS → HTTP → stdio with per-attempt/total timeouts, 16MB response body limit), `resolve_transport_priority()` with per-tool glob overrides (iterative DP matching) + client preference + config priorities, `TransportAttempt`/`FallbackNegotiationHistory` audit types, `cross_transport_fallback` config gate (default off), handler integration with `build_transport_targets()`, header allowlist for upstream proxying, stdio command injection prevention (absolute path + no metacharacters), 71 new tests
- **MCP 2025-11-25 Spec Adoption (Phase 30):** `validate_mcp_tool_name()` in vellaveto-types (1–64 chars, `[a-zA-Z0-9_\-./]`, no `..`), `StreamableHttpConfig` with `resumability_enabled`/`strict_tool_name_validation`/`max_event_id_length`/`sse_retry_ms`, `handle_mcp_get()` for SSE stream initiation/resumption with `Last-Event-ID` forwarding, RFC 6750 §3.1 `WWW-Authenticate` header on `InsufficientScope`, strict tool name validation in proxy (config-gated), ~42 new tests
- **Tool Discovery (Phase 34):** Pure Rust TF-IDF inverted index (cosine similarity, zero new deps), `DiscoveryEngine` with policy filtering and token budget, session-scoped TTL lifecycle (record/expire/evict), REST API (search/stats/reindex/tools), SDK methods (Python/TypeScript/Go), feature-gated behind `discovery`, ~260 new tests
- **Model Projector (Phase 35):** `ModelProjection` trait with `ProjectorRegistry`, 5 built-in projections (Claude/OpenAI/DeepSeek/Qwen/Generic), `SchemaCompressor` (5 progressive strategies), `CallRepairer` (type coercion, Levenshtein fuzzy matching, DeepSeek markdown extraction), REST API (models/transform), feature-gated behind `projector`, ~230 new tests
- **Zero-Knowledge Audit Trails (Phase 37):** Two-tier ZK audit: inline Pedersen commitments (~50µs per entry, `curve25519-dalek` Ristretto) + offline Groth16 batch proofs (`ark-groth16`/`ark-bn254`). `PedersenCommitter` with domain-separated generators, `WitnessStore` with bounded capacity, `AuditChainCircuit` (R1CS for hash-chain + commitment verification), `ZkBatchProver` (setup/prove/verify with key serialization), `ZkBatchScheduler` (async batch loop with size/interval triggers). REST API: `GET /api/zk-audit/status`, `GET /api/zk-audit/proofs`, `POST /api/zk-audit/verify`, `GET /api/zk-audit/commitments`. `ZkAuditConfig` with validation (batch_size 10–10,000). Python SDK methods (sync+async): `zk_status()`, `zk_proofs()`, `zk_verify()`, `zk_commitments()`. Feature-gated behind `zk-audit`, ~190 new tests (Rust + Python)
- **SOC 2 Type II Access Review Reports (Phase 38):** Dynamic report generation scanning audit entries and cross-referencing with least-agency data. Types: `AttestationStatus`, `ReviewerAttestation`, `AccessReviewEntry`, `Cc6Evidence`, `AccessReviewReport`, `ReviewSchedule`, `ReportExportFormat`. `Soc2AccessReviewConfig` with schedule (Daily/Weekly/Monthly), period bounds (1–366 days), reviewer validation. `generate_access_review()` with memory bounds (1M entries, 10K agents), deterministic BTreeMap ordering, CC6 evidence by recommendation tier. HTML renderer with escaped user data. REST API: `GET /api/compliance/soc2/access-review` (JSON/HTML, period/agent_id filters). Scheduled report generation (tokio interval task). SDK methods: Python (sync+async), TypeScript, Go with input validation. ~75 new tests across Rust + SDKs.
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
cargo test -p vellaveto-engine

# With output
cargo test -p vellaveto-engine -- --nocapture

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
