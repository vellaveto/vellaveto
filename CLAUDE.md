# CLAUDE.md — Sentinel Project Instructions

> **Project:** Sentinel — MCP Tool Firewall
> **State:** v2.2.1 stable (Phases 1–15 complete, 35 audit rounds); v3.0 roadmap active (Phase 17 complete, Phase 18 complete, 19.1–19.4 complete, 21.0 complete, Phases 20–23 remaining)
> **Version:** 3.0.0-dev (crates at 2.2.1, targeting v3.0 release)
> **License:** AGPL-3.0 dual license (see LICENSING.md)
> **Tests:** 4,500+ Rust tests + 130 Python SDK tests, zero warnings, zero `unwrap()` in library code
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
| Types: module root + re-exports | `sentinel-types/src/lib.rs` |
| Types: MCP task types + secure task primitives | `sentinel-types/src/task.rs` |
| Types: auth levels, circuit breakers, fingerprints, trust, validation | `sentinel-types/src/threat.rs` |
| Types: Action, Verdict, Policy, PathRules, NetworkRules, trace | `sentinel-types/src/core.rs` |
| Types: ETDI signatures, attestation, version pinning | `sentinel-types/src/etdi.rs` |
| Types: AgentIdentity, CallChainEntry, EvaluationContext | `sentinel-types/src/identity.rs` |
| Types: MINJA taint tracking, provenance, quarantine, namespaces | `sentinel-types/src/minja.rs` |
| Types: NHI lifecycle, behavioral baselines, delegation, DPoP | `sentinel-types/src/nhi.rs` |
| Types: DID:PLC identifiers, genesis operations, validation | `sentinel-types/src/did_plc.rs` |
| Types: VerificationTier, AccountabilityAttestation | `sentinel-types/src/verification.rs` |
| Types: CapabilityToken, CapabilityGrant, CapabilityVerification | `sentinel-types/src/capability.rs` |
| Types: AiActRiskClass, TrustServicesCategory (shared compliance enums) | `sentinel-types/src/compliance.rs` |
| Types: ExtensionDescriptor, ExtensionResourceLimits, ExtensionError | `sentinel-types/src/extension.rs` |
| Types: TransportProtocol, SdkTier, TransportEndpoint, SdkCapabilities | `sentinel-types/src/transport.rs` |
| Types: tests (~129 unit tests) | `sentinel-types/src/tests.rs` |
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
| Audit: Merkle tree inclusion proofs (RFC 6962) | `sentinel-audit/src/merkle.rs` |
| Audit: EU AI Act conformity assessment registry | `sentinel-audit/src/eu_ai_act.rs` |
| Audit: SOC 2 evidence generation registry | `sentinel-audit/src/soc2.rs` |
| Audit: CoSAI 12-category threat coverage registry | `sentinel-audit/src/cosai.rs` |
| Audit: Adversa AI TOP 25 coverage matrix | `sentinel-audit/src/adversa_top25.rs` |
| Audit: Cross-framework gap analysis (6 frameworks) | `sentinel-audit/src/gap_analysis.rs` |
| Audit: Immutable archive with gzip compression + retention | `sentinel-audit/src/archive.rs` |
| Audit: OTLP exporter with GenAI semantic conventions | `sentinel-audit/src/observability/otlp.rs` |
| Audit: tests (~214 unit tests) | `sentinel-audit/src/tests.rs` |
| Config: module root + PolicyConfig + re-exports | `sentinel-config/src/lib.rs` |
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
| Config: observability (incl. OtlpConfig) | `sentinel-config/src/observability.rs` |
| Config: validation helpers | `sentinel-config/src/validation.rs` |
| Config: PolicyRule struct + helpers | `sentinel-config/src/policy_rule.rs` |
| Config: ToolRegistryConfig | `sentinel-config/src/tool_registry.rs` |
| Config: ClusterConfig (Redis/local) | `sentinel-config/src/cluster.rs` |
| Config: A2aConfig (Agent-to-Agent) | `sentinel-config/src/a2a.rs` |
| Config: LimitsConfig + validate() | `sentinel-config/src/limits.rs` |
| Config: ComplianceConfig (EU AI Act + SOC 2) | `sentinel-config/src/compliance.rs` |
| Config: ExtensionConfig (allow/block/signatures/limits) | `sentinel-config/src/extension.rs` |
| Config: TransportConfig (discovery/negotiation/fallback) | `sentinel-config/src/transport.rs` |
| Config: PolicyConfig::validate() + load_file() | `sentinel-config/src/config_validate.rs` |
| Config: tests (~164 unit tests) | `sentinel-config/src/tests.rs` |
| MCP handling | `sentinel-mcp/src/lib.rs` |
| Proxy bridge: struct + constructor | `sentinel-mcp/src/proxy/bridge/mod.rs` |
| Proxy bridge: builder methods | `sentinel-mcp/src/proxy/bridge/builder.rs` |
| Proxy bridge: policy evaluation | `sentinel-mcp/src/proxy/bridge/evaluation.rs` |
| Proxy bridge: identity + flagged tools | `sentinel-mcp/src/proxy/bridge/helpers.rs` |
| Proxy bridge: run() relay loop | `sentinel-mcp/src/proxy/bridge/relay.rs` |
| Proxy bridge: tests | `sentinel-mcp/src/proxy/bridge/tests.rs` |
| DID:PLC generation + Base32 encoding | `sentinel-mcp/src/did_plc.rs` |
| Accountability attestation sign/verify | `sentinel-mcp/src/accountability.rs` |
| Capability token issue/attenuate/verify | `sentinel-mcp/src/capability_token.rs` |
| DLP / inspection | `sentinel-mcp/src/inspection.rs` |
| Output validation | `sentinel-mcp/src/output_validation.rs` |
| Semantic guardrails | `sentinel-mcp/src/semantic_guardrails/` |
| A2A protocol security | `sentinel-mcp/src/a2a/` |
| EU AI Act Art 50 transparency marking + human oversight | `sentinel-mcp/src/transparency.rs` |
| Extension registry + ExtensionHandler trait | `sentinel-mcp/src/extension_registry.rs` |
| Extensions: audit query example | `sentinel-mcp/src/extensions/audit_query.rs` |
| HTTP proxy: structs + constants | `sentinel-http-proxy/src/proxy/mod.rs` |
| HTTP proxy: handler functions | `sentinel-http-proxy/src/proxy/handlers.rs` |
| HTTP proxy: OAuth/API key/agent auth | `sentinel-http-proxy/src/proxy/auth.rs` |
| HTTP proxy: origin/CSRF validation | `sentinel-http-proxy/src/proxy/origin.rs` |
| HTTP proxy: call chain/escalation | `sentinel-http-proxy/src/proxy/call_chain.rs` |
| HTTP proxy: upstream forwarding | `sentinel-http-proxy/src/proxy/upstream.rs` |
| HTTP proxy: response inspection | `sentinel-http-proxy/src/proxy/inspection.rs` |
| HTTP proxy: utility helpers | `sentinel-http-proxy/src/proxy/helpers.rs` |
| HTTP proxy: tests | `sentinel-http-proxy/src/proxy/tests.rs` |
| HTTP proxy: transport discovery + negotiation | `sentinel-http-proxy/src/proxy/discovery.rs` |
| HTTP proxy: upstream transport fallback | `sentinel-http-proxy/src/proxy/fallback.rs` |
| HTTP proxy: WebSocket handler + relay | `sentinel-http-proxy/src/proxy/websocket/mod.rs` |
| HTTP proxy: WebSocket tests (~29 tests) | `sentinel-http-proxy/src/proxy/websocket/tests.rs` |
| HTTP proxy: gRPC module root + GrpcConfig + server start | `sentinel-http-proxy/src/proxy/grpc/mod.rs` |
| HTTP proxy: gRPC proto↔JSON conversion | `sentinel-http-proxy/src/proxy/grpc/convert.rs` |
| HTTP proxy: gRPC auth interceptor + metadata extraction | `sentinel-http-proxy/src/proxy/grpc/interceptors.rs` |
| HTTP proxy: gRPC McpService impl (unary + streaming) | `sentinel-http-proxy/src/proxy/grpc/service.rs` |
| HTTP proxy: gRPC upstream forwarding (HTTP fallback) | `sentinel-http-proxy/src/proxy/grpc/upstream.rs` |
| HTTP proxy: gRPC tests (~46 tests) | `sentinel-http-proxy/src/proxy/grpc/tests.rs` |
| Config: gRPC transport configuration | `sentinel-config/src/grpc_transport.rs` |
| Proto: MCP JSON-RPC gRPC schema | `proto/mcp/v1/mcp.proto` |
| Stdio proxy | `sentinel-proxy/src/main.rs` |
| HTTP API server | `sentinel-server/src/main.rs` |
| Server routes | `sentinel-server/src/routes.rs` |
| Server: compliance API endpoints (EU AI Act, SOC 2, threat coverage, gap analysis) | `sentinel-server/src/routes/compliance.rs` |
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
- Tamper-evident audit logging (SHA-256 hash chain, Merkle tree inclusion proofs, Ed25519 checkpoints, rotation)
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
- Five deployment modes: HTTP API, stdio proxy, HTTP reverse proxy, WebSocket reverse proxy, gRPC reverse proxy
- Canonical presets for common security scenarios
- CI: `cargo audit`, `unwrap()` hygiene, clippy clean
- Distributed clustering via `sentinel-cluster` crate (LocalBackend + RedisBackend with feature gate)
- Prometheus metrics endpoint (`/metrics`) with evaluation histograms (`sentinel-server/src/metrics.rs`)
- Hot policy reload via filesystem watcher and `/api/policies/reload` endpoint
- Admin dashboard — server-rendered HTML (`sentinel-server/src/dashboard.rs`)
- Multi-agent communication monitoring — privilege escalation detection (`sentinel-http-proxy/src/proxy/call_chain.rs`)

**WebSocket Transport (Phase 17.1 — SEP-1288):**
- Bidirectional MCP-over-WebSocket reverse proxy at `/mcp/ws` (`sentinel-http-proxy/src/proxy/websocket/mod.rs`)
- Full policy enforcement on client→upstream tool calls with fail-closed semantics
- DLP scanning + injection detection on upstream→client responses
- TOCTOU-safe JSON canonicalization before forwarding
- Per-connection rate limiting (sliding window), idle timeout, max message size enforcement
- Session binding — each WebSocket connection bound to exactly one `SessionState`
- Binary frame rejection (close 1003), unparseable message rejection (close 1008)
- Upstream connection via `tokio-tungstenite` with http→ws / https→wss URL conversion
- Metrics: `sentinel_ws_connections_total`, `sentinel_ws_messages_total`
- CLI args: `--ws-max-message-size`, `--ws-idle-timeout`, `--ws-message-rate-limit`
- 29 unit tests + `fuzz_ws_frame` fuzz target

**gRPC Transport (Phase 17.2):**
- gRPC reverse proxy on separate port (default 50051) via `tonic` (`sentinel-http-proxy/src/proxy/grpc/mod.rs`)
- Full policy enforcement on unary and bidirectional streaming calls with fail-closed semantics
- Proto↔JSON conversion layer with depth-bounded recursion (MAX_DEPTH=64) (`sentinel-http-proxy/src/proxy/grpc/convert.rs`)
- NaN/Infinity float rejection, policy denials as JSON-RPC errors (not gRPC status codes)
- Auth interceptor with constant-time SHA-256 API key validation (`sentinel-http-proxy/src/proxy/grpc/interceptors.rs`)
- DLP scanning + injection detection on upstream responses
- gRPC-to-HTTP upstream fallback — gRPC clients work with existing HTTP MCP servers
- gRPC Health Checking v1 via `tonic-health`
- Protobuf schema using `google.protobuf.Struct` for dynamic JSON fields (`proto/mcp/v1/mcp.proto`)
- Feature-gated behind `grpc` — zero impact on non-grpc builds
- Metrics: `sentinel_grpc_requests_total`, `sentinel_grpc_messages_total`
- CLI args: `--grpc`, `--grpc-port`, `--grpc-max-message-size`, `--upstream-grpc-url`
- Config type: `GrpcTransportConfig` (`sentinel-config/src/grpc_transport.rs`)
- 46 unit tests + `fuzz_grpc_proto` fuzz target
- Coordinated graceful shutdown with HTTP server via `CancellationToken`

**Async Operations & Protocol Extensions (Phase 17.3/17.4):**
- TaskRequest policy enforcement across all 4 transports (HTTP, WebSocket, gRPC, stdio) — extract action → evaluate → audit → forward/deny with fail-closed semantics
- `ProgressNotification` message classification — `notifications/progress` identified for future per-transport handling
- `ExtensionMethod` message classification — `x-` prefixed methods routed through policy evaluation
- Extension types in leaf crate — `ExtensionDescriptor`, `ExtensionResourceLimits`, `ExtensionNegotiationResult`, `ExtensionError` (`sentinel-types/src/extension.rs`)
- Extension configuration — `ExtensionConfig` with allow/block patterns, signature requirements, resource limits (`sentinel-config/src/extension.rs`)
- Extension registry — `ExtensionHandler` trait with lifecycle hooks, `ExtensionRegistry` with thread-safe registration, glob-based negotiation, O(1) method dispatch (`sentinel-mcp/src/extension_registry.rs`)
- Audit query example extension — `AuditQueryExtension` handling `x-sentinel-audit/stats` (`sentinel-mcp/src/extensions/audit_query.rs`)
- `extract_extension_action()` — Converts extension method calls to `Action` for policy evaluation
- `ProxyState.extension_registry` — Optional `Arc<ExtensionRegistry>` for extension method routing
- 50+ new tests across all transport layers

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

**Merkle Tree Inclusion Proofs (Phase 19.4):**
- Append-only Merkle tree with RFC 6962 domain separation — `hash_leaf(0x00||data)`, `hash_internal(0x01||l||r)` (`sentinel-audit/src/merkle.rs`)
- Inclusion proof generation and static verification (no disk access for verification)
- Audit logger integration via `with_merkle_tree()` builder — leaf hash appended on each `log_entry()`
- Checkpoint integration — `merkle_root: Option<String>` in `Checkpoint` with backward-compatible `signing_content()`
- Log rotation support — `.merkle-leaves` file renamed alongside rotated log, tree reset
- Crash recovery — `initialize()` rebuilds peaks from existing leaf file
- 24 unit tests

**MCP June 2026 Spec Compliance (Phase 18):**
- Transport types in leaf crate — `TransportProtocol` (Grpc/WebSocket/Http/Stdio with Ord), `TransportEndpoint`, `SdkTier` (Core/Standard/Extended/Full), `SdkCapabilities` (`sentinel-types/src/transport.rs`)
- Transport configuration — `TransportConfig` with `discovery_enabled`, `upstream_priorities`, `restricted_transports`, `max_fallback_retries`, `fallback_timeout_secs` (`sentinel-config/src/transport.rs`)
- Transport discovery endpoint — `GET /.well-known/mcp-transport` with JSON response (transports, SDK tier, versions). 404 when disabled. (`sentinel-http-proxy/src/proxy/discovery.rs`)
- Protocol version `2026-06` placeholder — first entry in `SUPPORTED_PROTOCOL_VERSIONS`, backward compat with 2025-03-26/2025-06-18/2025-11-25
- Transport preference negotiation — `parse_transport_preference()` (aliases: ws=websocket, sse=http), `negotiate_transport()` pure logic
- SDK tier declaration — `SdkTier::Extended` with 12 capabilities, CI validation in `sdk_tier_ci.rs`
- Upstream fallback foundation — `forward_with_fallback()` HTTP retry (`sentinel-http-proxy/src/proxy/fallback.rs`)
- 25 new tests across types, config, proxy, and integration

**Capability-Based Delegation Tokens (Phase 21.0):**
- `CapabilityToken` with Ed25519 signature, delegation chain, depth budget, grants, expiry (`sentinel-types/src/capability.rs`)
- `CapabilityGrant` — tool/function glob patterns, path/domain constraints, invocation limits
- `issue_capability_token()`, `attenuate_capability_token()`, `verify_capability_token()` (`sentinel-mcp/src/capability_token.rs`)
- Monotonic attenuation — depth decrements, grants subset of parent, expiry clamped to parent
- `check_grant_coverage()` — matches grants against Action tool/function/paths/domains
- `RequireCapabilityToken` policy condition with fail-closed semantics (`sentinel-engine/src/context_check.rs`)
- Policy compilation for `require_capability_token` condition (`sentinel-engine/src/policy_compile.rs`)
- `EvaluationContext` extended with `capability_token: Option<CapabilityToken>` (`sentinel-types/src/identity.rs`)
- Structural validation: MAX_GRANTS=64, MAX_DELEGATION_DEPTH=16, MAX_TOKEN_SIZE=65536
- 31 unit tests (4 types + 5 engine + 22 mcp)

**Compliance Evidence Generation (Phase 19.1 / 19.4):**
- Shared compliance enums in leaf crate — `AiActRiskClass`, `TrustServicesCategory` (`sentinel-types/src/compliance.rs`)
- `ComplianceConfig` — `EuAiActConfig` + `Soc2Config` with validation (`sentinel-config/src/compliance.rs`)
- EU AI Act registry — 10 obligations (Art 5–50), 18 capability mappings, conformity assessment reports (`sentinel-audit/src/eu_ai_act.rs`)
- SOC 2 registry — 22 criteria across CC1-CC9, ~30 capability mappings, evidence reports with readiness levels (`sentinel-audit/src/soc2.rs`)
- Read-time entry classification for both frameworks (not write-time)
- Compliance API endpoints — `GET /api/compliance/status`, `GET /api/compliance/eu-ai-act/report`, `GET /api/compliance/soc2/evidence` (`sentinel-server/src/routes/compliance.rs`)
- `PolicySnapshot` extended with `compliance_config` for atomic policy reload
- 34 unit tests (9 config + 11 EU AI Act + 14 SOC 2)

**CoSAI/Adversa Threat Coverage (Phase 19.3):**
- CoSAI 12-category threat registry — 38 threats across all categories with `SentinelDetection` mappings and structural mitigations (`sentinel-audit/src/cosai.rs`)
- Adversa AI TOP 25 coverage matrix — 25 ranked vulnerabilities with severity levels, detection mappings, and coverage matrix output (`sentinel-audit/src/adversa_top25.rs`)
- Cross-framework gap analysis — unified report across 6 frameworks (ATLAS, NIST RMF, ISO 27090, EU AI Act, CoSAI, Adversa TOP 25) with weighted coverage and recommendations (`sentinel-audit/src/gap_analysis.rs`)
- Threat coverage API endpoint — `GET /api/compliance/threat-coverage` (ATLAS + CoSAI + Adversa summaries)
- Gap analysis API endpoint — `GET /api/compliance/gap-analysis` (consolidated 6-framework report)
- 100% CoSAI coverage (38/38 threats), 100% Adversa TOP 25 coverage (25/25)
- 35 unit tests (14 CoSAI + 14 Adversa + 7 gap analysis)

**Compliance Dashboard (Phase 19):**
- Real-time compliance status section in admin dashboard (`sentinel-server/src/dashboard.rs`)
- 4 metric cards: EU AI Act %, SOC 2 Readiness %, Framework Coverage %, Critical Gaps
- 6-framework coverage table with color-coded thresholds (green >=90%, yellow >=70%, red <70%)
- Data sourced from existing stateless registries (EU AI Act, SOC 2, gap analysis)

**EU AI Act Article 50 Runtime Transparency (Phase 19):**
- `mark_ai_mediated()` — injects `result._meta.sentinel_ai_mediated = true` into tool-call responses (`sentinel-mcp/src/transparency.rs`)
- `requires_human_oversight()` — glob-based tool name matching against configurable patterns
- ProxyBridge integration — transparency marking + human oversight audit events in relay loop
- Builder methods: `with_transparency_marking(bool)`, `with_human_oversight_tools(Vec<String>)`
- EU AI Act Art 50(1) status upgraded to Compliant in registry (`sentinel-audit/src/eu_ai_act.rs`)
- 11 unit tests

**Immutable Audit Log Archive (Phase 19):**
- gzip compression of rotated log files via `flate2` (`sentinel-audit/src/archive.rs`)
- Retention enforcement — deletes archives older than configured `retention_days`
- `run_archive_maintenance()` — combines compression + retention in a single pass
- Feature-gated behind `archive` — zero impact on default builds
- `ArchiveConfig` (compress, retention_days) + `ArchiveReport` (compressed, deleted, errors)
- 9 unit tests

**OTLP Export with GenAI Semantic Conventions (Phase 19):**
- `OtlpExporter` implementing `ObservabilityExporter` trait (`sentinel-audit/src/observability/otlp.rs`)
- SecuritySpan → OTel span mapping with `gen_ai.system`, `gen_ai.operation.name`, `sentinel.*` attributes
- `map_span_kind()` — Chain→Server, Tool/Guardrail/Policy/Approval→Internal, Llm→Client
- `verdict_to_status()` — allow→Ok, deny→Error, other→Unset
- ID/time parsing helpers: `parse_trace_id()`, `parse_span_id()`, `parse_time()`
- `OtlpConfig` + `OtlpProtocol` in sentinel-config with validation (`sentinel-config/src/observability.rs`)
- Feature-gated behind `otlp-exporter` — zero impact on default builds
- 11 unit tests

**Identity Verification Primitives:**
- DID:PLC generation — SHA-256 + Base32 from canonicalized genesis operations (`sentinel-mcp/src/did_plc.rs`)
- Verification tiers — ordered enum (Unverified→FullyVerified) with fail-closed policy enforcement (`sentinel-types/src/verification.rs`)
- Accountability attestation — Ed25519 signed, length-prefixed content (`sentinel-mcp/src/accountability.rs`)
- Policy condition: `min_verification_tier` — fail-closed when tier missing (`sentinel-engine/src/context_check.rs`)
- NHI integration — DID generation, tier management, attestation lifecycle (`sentinel-mcp/src/nhi.rs`)
- Zero new dependencies — reuses sha2, ed25519-dalek, hex, serde_json_canonicalizer

**Testing & Quality:**
- Criterion benchmarks for policy evaluation, path normalization, domain matching, DLP scanning (`sentinel-engine/benches/`, `sentinel-mcp/benches/`)
- Fuzz targets for JSON-RPC framing, path normalization, domain extraction, CIDR parsing, message classification, scan_params_for_targets, WebSocket frame parsing (`fuzz/fuzz_targets/`)

**Adversarial Audit Coverage (FIND-043–074):**
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
- FIND-055: Agent card SSRF prevention — URL scheme/host/private-IP validation with 9 tests
- FIND-057: Bounded stack size in `collect_string_leaves()` to prevent DoS via wide JSON
- FIND-063: Regex pattern length validation (MAX_PATTERN_LEN = 2048) before compilation
- FIND-065: Audit log permission failures now logged as warnings instead of silently ignored
- FIND-068: Accountability attestation rejects empty agent_id/statement/policy_hash
- FIND-071: `ObservabilityExporterConfig` validation with MAX_BATCH_SIZE bound
- FIND-074: All control characters (U+0000–U+009F) rejected in tool/function names
- RwLock poisoning hardened across 10 modules (schema_poisoning, agent_trust, workflow_tracker, tool_namespace, sampling_detector, shadow_agent, token_security, output_security, agent_message, goal_tracking)

**CI/CD & Publishing:**
- 11 GitHub Actions workflows: CI, security-audit, cargo-deny, dependency-review, scorecard, provenance-sbom, docker-publish, release, docs, publish-pypi, publish-crates
- Docker publish workflow with GHCR push and Trivy vulnerability scanning
- Release automation: static musl binaries, SHA-256 checksums, CycloneDX SBOM, provenance attestation, GitHub Release
- Rustdoc GitHub Pages deployment
- PyPI publishing with trusted OIDC and Python 3.9–3.12 test matrix
- crates.io publishing with dependency-ordered workspace crate publishing
- Docker Compose for local deployment with hardened services
- GitHub issue templates (bug report, feature request) and PR template

**Python SDK:**
- Sync and async HTTP clients with httpx/requests fallback (`sdk/python/sentinel/client.py`)
- LangChain callback handler and tool guard decorator (`sdk/python/sentinel/langchain.py`)
- LangGraph sentinel node and guarded tool node (`sdk/python/sentinel/langgraph.py`)
- Client-side parameter redaction with 3 modes — keys_only, values, all (`sdk/python/sentinel/redaction.py`)
- 130 pytest tests covering types, client, langchain, langgraph, and redaction (`sdk/python/tests/`)

**Documentation:**
- Framework quickstart guides: Anthropic, OpenAI, LangChain, LangGraph, MCP proxy (`docs/QUICKSTART.md`)
- Security model: trust boundaries, data flows, storage, residual risks (`docs/SECURITY_MODEL.md`)
- Reproducible benchmarks with methodology (`docs/BENCHMARKS.md`)
- 5 curated policy presets: dev-laptop, CI/CD, RAG, database, browser agent (`examples/presets/`)

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
