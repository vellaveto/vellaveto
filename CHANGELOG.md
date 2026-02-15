# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 29 — Cross-Transport Smart Fallback
- **Transport health tracker** (`vellaveto-http-proxy/src/proxy/transport_health.rs`) — per-transport circuit breaker keyed by `(upstream_id, TransportProtocol)` with Closed/Open/HalfOpen state machine, exponential backoff (2^trip_count, max 32x), RwLock fail-closed semantics. API: `can_use()`, `record_success()`, `record_failure()`, `available_transports()`, `summary()`, `reset()`.
- **Smart fallback chain** (`vellaveto-http-proxy/src/proxy/smart_fallback.rs`) — ordered transport fallback orchestrator (gRPC → WebSocket → HTTP → stdio). Per-attempt and total timeout budgets, transport-specific dispatch (HTTP POST, WebSocket one-shot via tokio-tungstenite, gRPC HTTP bridge, stdio subprocess). Circuit breaker integration skips Open transports.
- **Transport priority resolution** (`vellaveto-http-proxy/src/proxy/discovery.rs`) — `resolve_transport_priority()` with 4-level resolution: per-tool glob overrides → client `mcp-transport-preference` header → config `upstream_priorities` → default `[Grpc, WebSocket, Http]`. Restricted transports filtered in all paths.
- **Fallback audit types** (`vellaveto-types/src/transport.rs`) — `TransportAttempt` (protocol, endpoint, success, duration, error) and `FallbackNegotiationHistory` (attempts, successful_transport, total_duration) for full audit trail of fallback negotiations.
- **Smart fallback config** (`vellaveto-config/src/transport.rs`) — `cross_transport_fallback: bool` (default false), `transport_overrides: HashMap<String, Vec<TransportProtocol>>`, circuit breaker threshold/duration, `stdio_fallback_enabled`/`stdio_command`. Per-backend `transport_urls` in `BackendConfig`.
- **Handler integration** (`vellaveto-http-proxy/src/proxy/handlers.rs`) — smart fallback branch in `handle_mcp_post` gated behind `cross_transport_fallback` flag. `build_transport_targets()` derives targets from gateway `BackendConfig.transport_urls` or single-server URL derivation.
- **Default off:** `cross_transport_fallback: false` — zero behavioral change without opt-in. Fail-closed: all transports failed → deny.
- 71 new tests across 6 crates. Integration tests in `vellaveto-integration/tests/cross_transport_fallback.rs`.

### Fixed (Adversarial Hardening — Round 41: Phase 29)
- **FIND-R41-001** (Critical): Header allowlist for upstream proxy — `dispatch_http` now filters forwarded headers through `FORWARDED_HEADERS` allowlist (content-type, accept, user-agent, traceparent, tracestate, x-request-id) preventing cookie/auth header leakage to upstream servers.
- **FIND-R41-002** (High): Shell injection in stdio fallback — replaced `sh -c <command>` with direct `Command::new(command)`, added config validation requiring absolute paths with no shell metacharacters.
- **FIND-R41-003** (High): Unbounded circuit breaker state — `TransportHealthTracker` capped at `MAX_TRACKED_CIRCUITS = 10,000` entries with fail-closed (Open) for new circuits at capacity.
- **FIND-R41-004** (High): Unbounded HTTP response body — added `MAX_RESPONSE_BODY_BYTES = 16MB` limit in `dispatch_http` and `MAX_STDERR_BYTES = 4096` in `dispatch_stdio`.
- **FIND-R41-006** (High): Zombie stdio processes on timeout — restructured `dispatch_stdio` with `tokio::select!` to call `child.kill().await` on timeout branch instead of leaking the process.
- **FIND-R41-007** (Medium): Unbounded execution graph — `ExecGraph::add_node` capped at `MAX_NODES_PER_GRAPH = 50,000` with skip-and-warn on overflow.
- **FIND-R41-008** (Medium): URL scheme mismatch in gateway — `BackendConfig::validate` now checks URL schemes match transport protocol (http/https for HTTP/gRPC, ws/wss for WebSocket).
- **FIND-R41-009** (Medium): Unbounded transport overrides map — `TransportConfig::validate` rejects >100 entries in `transport_overrides`.
- **FIND-R41-010** (Medium): Discarded stdio stderr — `dispatch_stdio` now captures stderr via `Stdio::piped()` and includes it in error diagnostics.
- **FIND-R41-011** (Medium): Log injection via control chars — `validate_field` in deputy/NHI routes now rejects ALL control characters (including `\n`, `\t`) to prevent log injection.
- **FIND-R41-014** (Medium): Glob key validation — transport override glob keys validated for max length (256), empty key, and null byte content.
- 7 new tests for config validation (stdio path, metacharacters, override bounds, glob keys, URL schemes).

### Fixed (Adversarial Hardening — Round 42)
- **FIND-R42-002** (High): Transport preference header DoS — `parse_transport_preference` now deduplicates and caps at 4 entries (one per protocol variant), preventing unbounded Vec from malicious `mcp-transport-preference` headers.
- **FIND-R42-003** (High): URL host parser SSRF — `extract_host_from_url` now strips userinfo (`user:pass@host`) via `rfind('@')` to prevent @-smuggling, and handles IPv6 addresses in brackets (`[::1]:8080`).
- **FIND-R42-020** (High): Unbounded response body in fallback — `forward_with_fallback` now reads response body in chunks with `MAX_RESPONSE_BODY_BYTES = 16MB` bound (matching `smart_fallback.rs`).
- **FIND-R42-005** (Medium): Circuit breaker bypass at capacity — `can_use()` now returns `Err` for unknown circuits when tracker is at capacity, preventing untracked requests from bypassing fail-closed semantics.
- **FIND-R42-006** (Medium): Exec graph metadata leak — `ExecutionGraph::add_node` now checks `MAX_NODES_PER_GRAPH` bound BEFORE updating metadata (`total_calls`, `unique_tools`, `unique_agents`, parent `children`).
- **FIND-R42-007** (Medium): Agent trust graph session exhaustion — `AgentTrustGraph::record_request` now enforces `MAX_TRACKED_SESSIONS = 10,000` to prevent unbounded memory growth from unique session IDs.
- **FIND-R42-008** (Medium): Backend URL scheme validation — `GatewayConfig::validate` now requires `backend.url` to use `http://` or `https://` scheme (previously only validated non-empty).
- **FIND-R42-009** (Medium): Wildcard glob override shadowing — `TransportConfig::validate` rejects `"*"` wildcard in `transport_overrides` when other patterns exist, since lexicographic sort makes `"*"` match first and shadow all specific overrides.
- **FIND-R42-010** (Medium): Half-open thundering herd — `TransportHealthTracker` now tracks `half_open_in_flight` per circuit, allowing only one concurrent probe request in HalfOpen state.
- **FIND-R42-011** (Medium): DOT language injection — `ExecutionGraph::to_dot()` now escapes all user-controlled strings (node IDs, tool names, function names) via `escape_dot()` to prevent injection of DOT constructs.
- **FIND-R42-012** (Low): Failure count overflow — `failure_count += 1` replaced with `saturating_add(1)` in both Closed and Open branches of `record_failure`.
- **FIND-R42-013** (Low): Duplicate protocols in overrides — `TransportConfig::validate` rejects duplicate protocols within `transport_overrides` values.
- **FIND-R42-014** (Low): Clock error logging — `now_secs()` now logs `tracing::error!` when system clock is before Unix epoch instead of silently returning 0.
- **FIND-R42-015** (Low): Duplicate upstream priorities — `TransportConfig::validate` rejects duplicate protocols in `upstream_priorities`.
- **FIND-R42-016** (Low): Path parameter validation — `remove_delegation`, `get_nhi_agent`, and all NHI path-based endpoints now validate path parameter length and content.
- **FIND-R42-017** (Low): Rotation manifest chain linking — manifest entries now include `start_hash` (prev_hash of first entry) for cross-rotation segment verification.
- **FIND-R42-018** (Low): Self-delegation rejection — `register_delegation` now rejects `from_principal == to_principal`.
- 17 new tests across 4 crates (discovery, transport_health, exec_graph, config).

#### Phase 25.1 — Audio Metadata Inspection (WAV + MP3)
- **WAV LIST/INFO chunk parser** (`extract_text_from_wav`) — walks RIFF container for INFO sub-chunks (INAM, IART, ICMT, IGNR, ISFT), extracts null-terminated text, bounded at 200 sub-chunks and 1MB aggregate text.
- **MP3 ID3v2 tag parser** (`extract_text_from_mp3`) — parses ID3v2.3/2.4 headers with syncsafe integer decoding, extracts text from TIT2, TPE1, TALB, COMM, USLT, TXXX frames. Supports 4 encodings: ISO-8859-1, UTF-16 with BOM, UTF-16BE, UTF-8. Bounded at 200 frames and 1MB aggregate.
- **Audio extraction wired into `scan_content()`** — extracted text feeds into existing `scan_text_for_injection()` pipeline for injection detection.
- **FLAC/OGG magic bytes** — `fLaC` and `OggS` detected as `ContentType::Audio`.
- 15 new tests.

#### Phase 25.2 — Video Metadata Inspection (MP4 + WebM)
- **MP4 ISO BMFF box walker** (`extract_text_from_mp4`) — traverses ftyp → moov → udta → meta → ilst for iTunes-style metadata (©nam, ©ART, ©cmt, ©des) and legacy QuickTime format. Bounded at 500 boxes, 10 nesting levels, 1MB aggregate text.
- **WebM EBML tag parser** (`extract_text_from_webm`) — parses variable-length element IDs/sizes (VINT encoding), walks Segment → Tags → Tag → SimpleTag to extract TagString values. Bounded at 200 elements per level and 1MB aggregate text.
- **Video extraction wired into `scan_content()`** — extracted text feeds into injection detection pipeline.
- **MP4/WebM/AVI magic bytes** — ftyp at offset 4 → Video, EBML header `\x1A\x45\xDF\xA3` → Video, RIFF....AVI → Video.
- 12 new tests.

#### Phase 25 — Multimodal Enforcement & Fuzz Targets
- **Per-content-type size limits** — `max_audio_size` (50MB default), `max_video_size` (100MB default) in `MultimodalConfig`. Image/PDF keep `max_image_size`. Fail-closed on oversize.
- **Blocked content types** — `blocked_content_types` field rejects specified types before scanning (priority over `content_types`). Returns `MultimodalError::BlockedContentType`.
- **Fuzz targets for audio/video** — `fuzz_audio_metadata` and `fuzz_video_metadata` exercise WAV/MP3/MP4/WebM parsers with arbitrary bytes. Total fuzz targets: 24.
- 9 new tests for enforcement policies (blocked types, per-type size limits, config defaults).

#### Phase 25.6 — Stateless Protocol Abstraction
- **`RequestContext` trait** (`vellaveto-types/src/identity.rs`) — abstracts session state access for policy evaluation. Methods: `call_counts()`, `previous_actions()`, `call_chain()`, `agent_identity()`, `session_guard_state()`, `risk_score()`. Default `to_evaluation_context()` builder populates `EvaluationContext` from any implementor.
- **`StatelessContextBlob` struct** — signed per-request context for future stateless HTTP mode (MCP June 2026). Carries agent_id, call_counts, recent_actions, call_chain, risk_score, issued_at timestamp, and HMAC-SHA256 signature. 5-minute expiry. Implements `RequestContext`.
- **`StatefulContext` adapter** (`vellaveto-http-proxy/src/session.rs`) — wraps `&SessionState` to implement `RequestContext`, zero-cost migration for existing stateful code.
- 8 new tests.

#### Phase 33 — Formal Verification (TLA+/Alloy)
- **TLA+ policy engine specification** (`formal/tla/MCPPolicyEngine.tla`) — state machine modeling `PolicyEngine::evaluate_action` with 6 safety invariants (fail-closed default, priority ordering, blocked-paths-override, blocked-domains-override, errors-produce-deny, missing-context-deny) and 2 liveness properties (eventual verdict, no stuck states).
- **TLA+ ABAC forbid-overrides specification** (`formal/tla/AbacForbidOverrides.tla`) — models `AbacEngine::evaluate` with 4 safety invariants: forbid dominance, forbid ignores priority, permit-only-without-forbid, no-match result.
- **TLA+ shared operators** (`formal/tla/MCPCommon.tla`) — abstract pattern matching, policy sorting predicate, path/domain rule checking operators.
- **Alloy capability delegation model** (`formal/alloy/CapabilityDelegation.als`) — models capability token delegation with 6 assertions: monotonic attenuation, transitive attenuation across chains, depth budget, temporal monotonicity, terminal-cannot-delegate, issuer chain integrity.
- **TLC model checker configs** for both TLA+ specs with small-bound verification (3 policies, 2 actions).
- **19 verified properties total** (16 safety + 3 liveness), each mapped to exact source locations in the Rust codebase.
- First formal model of MCP policy enforcement in any framework (TLA+, Alloy, Lean, Coq) — addresses Gap #1 from `docs/MCP_SECURITY_GAPS.md`.

### Fixed (Adversarial Hardening — Round 1)
- **P0-1/P0-2**: Moved TLC record definitions to `MC_*.tla` model companion modules (TLC `.cfg` parser cannot handle set-of-record literals).
- **P0-3**: Removed `SafetyFailClosed` operator that used primed variables in state predicate (invalid for TLC invariant checking).
- **P0-4**: Replaced tautological `InvariantS1_FailClosed` (was `TRUE`) with real fail-closed invariant: no-match implies Deny.
- **P0-5**: Fixed Alloy `minus` → `sub` (correct Alloy integer subtraction function).
- **P0-6**: Fixed Alloy module-level `let MAX_DEPTH = 4` → `fun MAX_DEPTH : one Int { 3 }`.
- **P1-1**: Fixed S3/S4 invariants to restrict blocked-path/domain check to first matching policy only (first-match-wins semantics).
- **P1-2**: Reformulated S5 invariant — Allow verdicts require a matching Allow policy (previously failed when prior evaluations produced Allow).
- **P1-6**: Removed weak fairness on `HandleError` — errors are possible but don't preempt normal evaluation.
- **P1-7**: Fixed Alloy `add` → `plus` for integer addition.
- **P1-8**: Reduced Alloy `MAX_DEPTH` from 4→3, increased scope from 5→7 tokens so S13 (depth budget) is non-vacuous.
- **P2-3**: Fixed `CheckPathRules`/`CheckDomainRules` to deny on empty targets with configured allowlist (fail-closed R28-ENG-1).
- **P2-7**: Restructured Alloy facts/assertions — structural well-formedness as facts, delegation constraints separated, making S12 (transitive attenuation) a genuine theorem.
- **P3-2**: Added ABAC policy with `conditions=FALSE` to test condition-exclusion logic.
- **P3-4**: Added ABAC liveness property L3 (eventual decision for all pending evaluations).
- Added grant ownership fact (each Grant belongs to exactly one Token).
- Added `FirstMatchIndex` helper operator for correct first-match-wins invariant formulation.
- Documented all known abstraction gaps in `formal/README.md`.

## [4.0.0-dev] — Phase 26: Shadow AI Detection & Governance Visibility (2026-02-15)

### Added
- **Shadow AI Discovery Engine** (`vellaveto-mcp/src/shadow_ai_discovery.rs`): Passive traffic analysis detects unregistered agents, unapproved tools, and unknown MCP servers with bounded tracking (max 1000/500/100 entities)
- **Governance Types** (`vellaveto-types/src/governance.rs`): `EnforcementMode`, `UnregisteredAgent`, `UnapprovedTool`, `UnknownMcpServer`, `ShadowAiReport`
- **Governance Config** (`vellaveto-config/src/governance.rs`): `GovernanceConfig` with shadow AI discovery, agent registration enforcement, approved tools/servers lists, least agency enforcement mode, auto-revocation window
- **Governance API** (`vellaveto-server/src/routes/governance.rs`): `GET /api/governance/shadow-report`, `/unregistered-agents`, `/unapproved-tools`, `/least-agency/{agent_id}/{session_id}`
- **Least Agency Enforcement** (`vellaveto-engine/src/least_agency.rs`): `new_with_config()` constructor with `EnforcementMode`, `check_auto_revoke()` method with per-permission `last_used` tracking
- **Audit Events** (`vellaveto-audit/src/events.rs`): `log_shadow_ai_discovery_event()` and `log_least_agency_event()` helpers for governance audit trail
- **Dashboard Governance Section** (`vellaveto-server/src/dashboard.rs`): Unregistered agents table with risk scores, unapproved tools/unknown servers counters
- 43 new tests across 4 crates (17 shadow_ai_discovery, 8 governance config, 5 least agency enforcement, 13 engine)

### Design Decisions
- Passive discovery only — observe traffic, don't scan network
- Bounded tracking prevents memory growth (LRU eviction at capacity)
- `require_agent_registration` enables fail-closed mode for unregistered agents
- `EnforcementMode::Monitor` (default) → safe rollout; `Enforce` → auto-revocation

## [3.0.0] — 2026-02-14

### Added

#### Go SDK
- **Zero-dependency Go client** — stdlib-only (`net/http`, `encoding/json`) HTTP client with full API parity: `Evaluate`, `EvaluateOrError`, `Health`, `ListPolicies`, `ReloadPolicies`, `Simulate`, `BatchEvaluate`, `ValidateConfig`, `DiffConfigs`, `ListPendingApprovals`, `ApproveApproval`, `DenyApproval` (`sdk/go/`).
- Functional options pattern: `WithAPIKey()`, `WithTimeout()`, `WithHTTPClient()`, `WithHeaders()`.
- `context.Context` on all public methods.
- Fail-closed verdict parsing — unknown verdict strings map to `VerdictDeny`.
- Both string and object verdict form parsing (matching Python/TypeScript behavior).
- Typed errors: `VellavetoError`, `PolicyDeniedError`, `ApprovalRequiredError`.
- 28 table-driven tests using `net/http/httptest`.

#### HTTP Proxy Benchmarks
- **35 Criterion benchmarks** for the production hot path (`vellaveto-http-proxy/benches/http_proxy.rs`):
  - Origin validation (5 benchmarks): `is_loopback` variants, `build_loopback_origins`, `extract_authority` (5 URL formats), `validate_origin` (4 scenarios).
  - HMAC operations (7 benchmarks): signing content, compute (small/4KB), verify (valid/invalid), build entry (with/without HMAC).
  - Call chain parsing (4 benchmarks): header extraction with 0/1/5 entries, with/without HMAC.
  - Privilege escalation (4 benchmarks): 0/1/5/10-hop chains.
  - Audit context (3 benchmarks): minimal, with OAuth, with 3-hop chain.
- Made `origin` and `call_chain` modules `pub` (from `pub(super)`) to enable benchmark access.
- All operations sub-microsecond to low-microsecond: origin validation <440ns, HMAC <1.6µs, privilege escalation <76ns.

### Changed

- **CLAUDE.md trimmed** — 47,834 bytes → 11,675 bytes (76% reduction). Collapsed "What's Done" section to 16 one-line summaries, trimmed file locations table from ~120 to ~52 rows, simplified Bottega section to reference `.claude/rules/`.

### Documentation

- **Roadmap v3.0**: Replaced v2.2 roadmap with 12-month v3.0 plan (Q1–Q4 2026) covering 7 phases:
  - Phase 17 (P0): MCP next spec preparation — WebSocket transport (SEP-1288), gRPC transport (Google), async operations (SEP-1391), protocol extensions framework
  - Phase 18 (P0): MCP June 2026 spec compliance — spec delta adoption, SDK tiering, transport negotiation and fallback
  - Phase 19 (P0): Regulatory compliance — EU AI Act Article 50 transparency (Aug 2 2026 deadline), OpenTelemetry GenAI semantic conventions, CoSAI/Adversa AI threat gap closure, SOC 2 Type II audit enhancements
  - Phase 20 (P1): MCP gateway mode — session-aware routing, multi-server tool discovery, health-aware upstream routing, Kubernetes-native StatefulSet deployment
  - Phase 21 (P1): Advanced authorization — Cedar-style ABAC engine, least-agency enforcement, identity federation, continuous authorization
  - Phase 22 (P2): Developer experience — visual execution graph UI, VS Code extension, policy playground, GitHub Action CI gate, SDK ecosystem (Go, Java, TypeScript)
  - Phase 23 (P3): Research — multimodal injection detection, continuous autonomous red teaming, FIPS 140-3 compliance, Sigstore/Rekor transparency logs, stateful session reasoning guards
- Added expanded competitor comparison (Cisco AI Defense, Prisma AIRS, Radware, CalypsoAI, Akamai, Microsoft MCP Gateway)
- Added CoSAI 12-category and Adversa AI TOP 25 threat coverage matrices
- Added updated OWASP ASI Top 10 coverage with v3.0 enhancement mapping
- Added 25-entry research bibliography with links
- Archived all v2.0–v2.2 completed phases (1–15) in collapsible appendix

### Security

#### Phase 23 Adversarial Hardening (Round 2 — Medium Findings)
- **FIND-P23-005**: JPEG stego `get_image_data_region` loop now bounded to `MAX_MARKER_ITERATIONS=500` — prevents infinite loop on malformed JPEG with no SOS marker.
- **FIND-P23-006**: PDF dictionary look-back window increased from 256 to 4096 bytes — correctly detects `/FlateDecode` in large PDF object dictionaries.
- **FIND-P23-007**: `scan_text_for_injection` now normalizes whitespace before scanning — detects injection payloads split across multiple PNG tEXt chunks joined by newlines.
- **FIND-P23-008**: EXIF ASCII string minimum lowered from 8 to 4 characters — catches short injection keywords like "exec", "eval", "sudo".
- **FIND-P23-009**: PDF `extract_pdf_text_operators` now parses hex strings `<...>` in addition to literal strings `(...)` — `<<` dictionary delimiters correctly excluded.
- **FIND-P23-010**: `detect_steganography` documented with comprehensive limitations section (adaptive stego, low-payload evasion, JPEG DCT, false positives, non-LSB methods).
- **8 new integration tests** in `pentest_phase23_hardening.rs` (total 23).

### Added

#### Phase 23: Research & Future (23.1–23.5)
- **Multimodal injection detection (23.1)** — Pure-Rust PNG tEXt/zTXt/iTXt chunk extraction, JPEG COM/EXIF comment extraction, PDF stream/FlateDecode text extraction with Tj/TJ operator parsing, chi-squared LSB steganography detection. No `image`/`pdf`/OCR crates — uses `flate2` for decompression with 10MB zip bomb protection. (`vellaveto-mcp/src/inspection/multimodal.rs`). 12 tests.
- **Continuous autonomous red teaming (23.2)** — `MutationEngine` with 8 mutation types (URL encode, double encode, null byte inject, homoglyph replace, case variation, whitespace inject, parameter alias, context wrapping). `RedTeamRunner` evaluates mutated payloads against `PolicyEngine`, reports `BypassFinding` gaps. `CoverageReport` tracks by category and mutation type. (`vellaveto-mcp/src/red_team.rs`). 15 tests.
- **Red team API** — `POST /api/simulator/red-team` runs mutation engine against server's current policies, returns `RedTeamReport` with bypass findings and coverage gaps.
- **FIPS 140-3 compliance mode (23.3)** — `FipsMode` with approved algorithm list (ECDSA P-256, SHA-256/384/512, AES-256-GCM, HMAC-SHA-256, RSA-PSS) and non-FIPS rejection list (Ed25519, ChaCha20-Poly1305, Blake2, Curve25519). Fail-closed for unknown algorithms. ECDSA P-256 sign/verify via `p256` crate, feature-gated behind `fips`. (`vellaveto-mcp/src/fips.rs`). 12 tests.
- **Sigstore/Rekor transparency log integration (23.4)** — `RekorEntry` types with full serde support. `RekorVerifier` with RFC 6962 domain-separated Merkle tree inclusion proof verification (leaf: `SHA-256(0x00||body)`, interior: `SHA-256(0x01||left||right)`). Offline tool hash matching and full `verify_entry()` combining proof + hash. (`vellaveto-mcp/src/rekor.rs`). 12 tests.
- **Stateful session reasoning guards (23.5)** — Formal state machine (Init→Active→Suspicious→Locked→Ended) with configurable `suspicious_threshold`, `lock_threshold`, `cooldown_secs`. `SessionGuard` integrates `WorkflowAlert` severity mapping and `GoalDriftAlert` similarity-to-severity conversion. Admin unlock, cooldown recovery, session eviction (max_sessions). (`vellaveto-mcp/src/session_guard.rs`). 20 tests.
- **Cross-crate integration** — `FipsConfig` in vellaveto-config with module + `PolicyConfig` field. `rekor_entry: Option<serde_json::Value>` on `ToolSignature` for Rekor provenance. `session_state: Option<String>` on `EvaluationContext` with builder support. `SessionStateRequired` compiled context condition with fail-closed evaluation and policy compilation.
- **74 new tests** across Phase 23 (12 multimodal + 15 red team + 12 FIPS + 12 Rekor + 20 session guard + 3 fips config)

#### Phase 22: Developer Experience (Backend Focus)
- **Policy simulator API** — 4 new endpoints: `POST /api/simulator/evaluate` (single action with trace), `/batch` (up to 100 actions), `/validate` (config validation), `/diff` (policy diff). Supports inline TOML policy configs for sandbox evaluation. (`vellaveto-server/src/routes/simulator.rs`). 9 tests.
- **CLI `simulate` subcommand** — Batch-evaluate actions from a JSON file against a policy config. Supports text table and JSON output formats.
- **GitHub Action `policy-check`** — Composite action that downloads Vellaveto binary and runs `vellaveto check` for CI policy gates. Supports version pinning, strict mode, and text/JSON output. (`.github/actions/policy-check/action.yml`). Example workflow at `examples/github-action-policy-check.yml`.
- **Dashboard SVG charts** — Verdict distribution bar chart (allow/deny/approval) and policy type pie chart (Allow/Deny/Conditional) rendered as inline SVG in the admin dashboard. 4 tests.
- **TypeScript SDK** — Zero runtime dependency HTTP client using native `fetch()` (Node 18+). Full API parity with Python SDK: `evaluate`, `health`, `listPolicies`, `reloadPolicies`, `simulate`, `batchEvaluate`, `validateConfig`, `diffConfigs`, `listPendingApprovals`, `approveApproval`, `denyApproval`. Error classes: `VellavetoError`, `PolicyDenied`, `ApprovalRequired`. (`sdk/typescript/`). 15 Jest tests.

#### Phase 20: MCP Gateway Mode (20.1–20.3)
- **Gateway types** — `BackendHealth` (Healthy/Degraded/Unhealthy), `UpstreamBackend`, `RoutingDecision`, `ToolConflict` in leaf crate (`vellaveto-types/src/gateway.rs`). 3 tests.
- **Gateway configuration** — `GatewayConfig` with backend list, health check interval/thresholds, `BackendConfig` with tool prefixes and weights (`vellaveto-config/src/gateway.rs`). Added to `PolicyConfig` with `#[serde(default)]`. Validation for duplicate IDs, zero weights, interval bounds, multiple defaults. 5 tests.
- **Gateway router** — `GatewayRouter` with longest-prefix-first tool name matching, configurable unhealthy/healthy thresholds, `route_with_affinity()` for session-sticky routing, fail-closed when all backends unhealthy (`vellaveto-http-proxy/src/proxy/gateway.rs`). 30 tests.
- **Health state machine** — Healthy→Unhealthy after `unhealthy_threshold` consecutive failures; Unhealthy→Degraded (1 success) →Healthy (`healthy_threshold` successes). Degraded backends remain routable.
- **Health checker background task** — Periodic JSON-RPC `ping` to each backend with 5s timeout. Updates `vellaveto_gateway_backends_total` and `vellaveto_gateway_backends_healthy` gauge metrics.
- **Handler wiring** — ToolCall match arm in `handle_mcp_post()` routes via gateway when `ProxyState.gateway` is `Some`. Records success/failure from HTTP response status.
- **`forward_to_upstream_url()`** — Extracted URL parameter from `forward_to_upstream()` enabling gateway routing without rewriting the 808-line forwarding function.
- **WebSocket gateway** — Default backend resolution for new WS connections; closes with 1008 if no healthy backend.
- **gRPC gateway** — Default backend resolution for HTTP fallback forwarding.
- **Tool conflict detection** — `detect_conflicts()` builds tool→backends map, returns entries served by multiple backends.
- **Session state** — `backend_sessions: HashMap<String, String>` and `gateway_tools: HashMap<String, Vec<String>>` for session affinity and tool discovery tracking.
- **38 new tests** across 4 files (3 types + 5 config + 30 router)

#### Phase 18: MCP June 2026 Spec Compliance
- **Transport & SDK tier types** — `TransportProtocol` (Grpc/WebSocket/Http/Stdio), `TransportEndpoint`, `SdkTier` (Core/Standard/Extended/Full), `SdkCapabilities` in leaf crate (`vellaveto-types/src/transport.rs`). 4 tests.
- **Transport configuration** — `TransportConfig` with `discovery_enabled`, `upstream_priorities`, `restricted_transports`, `advertise_capabilities`, `max_fallback_retries`, `fallback_timeout_secs` (`vellaveto-config/src/transport.rs`). Added to `PolicyConfig` with `#[serde(default)]`. Validation for bounds and conflict detection. 4 tests.
- **Transport discovery endpoint** — `GET /.well-known/mcp-transport` returns JSON with available transports, SDK tier (Extended with 12 capabilities), and supported protocol versions. 404 when `discovery_enabled=false`. (`vellaveto-http-proxy/src/proxy/discovery.rs`)
- **Protocol version `2026-06` placeholder** — Added to `SUPPORTED_PROTOCOL_VERSIONS` (first position) for forward compatibility with upcoming MCP June 2026 spec. All existing versions (2025-11-25, 2025-06-18, 2025-03-26) preserved for backward compatibility.
- **Transport preference negotiation** — `parse_transport_preference()` parses `mcp-transport-preference` header (aliases: ws=websocket, sse=http). `negotiate_transport()` pure logic finds best match respecting restrictions.
- **Upstream fallback foundation** — `forward_with_fallback()` with timeout-based retry for HTTP transport. Cross-transport fallback deferred to Phase 20 (`vellaveto-http-proxy/src/proxy/fallback.rs`).
- **SDK tier CI validation** — `test_sdk_tier_minimum_standard` and `test_extended_tier_required_capabilities` ensure Vellaveto maintains Extended tier (`vellaveto-integration/tests/sdk_tier_ci.rs`).
- **Backward compatibility tests** — Verify 2025-03-26, 2025-06-18, 2025-11-25 protocol versions remain supported and HTTP default works without negotiation headers (`vellaveto-integration/tests/transport_negotiation.rs`).
- **25 new tests** across 6 files (4 types + 4 config + 10 proxy + 5 transport integration + 2 SDK CI)

#### Phase 17.3: Async Operations Enhancements (SEP-1391)
- **TaskRequest policy enforcement across all transports** — `TaskRequest` messages (`tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/send`) now receive full policy evaluation (extract action → evaluate → audit → forward/deny) in HTTP, WebSocket, gRPC, and stdio relay. Previously forwarded without policy checks.
- **`ProgressNotification` message classification** — `notifications/progress` messages classified as `ProgressNotification` variant with `progress_token`, `progress`, and optional `total` fields for future per-transport handling. Currently forwarded as PassThrough.
- **`ExtensionMethod` message classification** — Methods with `x-` prefix classified as `ExtensionMethod` variant with `extension_id` and `method` fields. Policy evaluation enforced on all transports.
- **`extract_extension_action()`** — Converts extension method calls to `Action` for policy evaluation (`vellaveto-mcp/src/extractor.rs`)
- **32+ new tests** across WebSocket, gRPC, HTTP, and extractor test suites

#### Phase 17.4: Protocol Extensions Framework
- **Extension types** — `ExtensionDescriptor`, `ExtensionResourceLimits`, `ExtensionNegotiationResult`, `ExtensionError` in leaf crate (`vellaveto-types/src/extension.rs`). 6 tests.
- **Extension configuration** — `ExtensionConfig` with `enabled`, `allowed_extensions`, `blocked_extensions`, `require_signatures`, `trusted_public_keys`, `default_resource_limits` (`vellaveto-config/src/extension.rs`). Added to `PolicyConfig` with `#[serde(default)]`. 2 tests.
- **Extension registry** — `ExtensionHandler` trait with `on_load`, `on_unload`, `handle_method`, `descriptor` lifecycle hooks. `ExtensionRegistry` with RwLock-based thread-safe registration, glob-based allow/block negotiation, and O(1) method dispatch via `route_method()` (`vellaveto-mcp/src/extension_registry.rs`). 12 tests.
- **Audit query example extension** — `AuditQueryExtension` implementing `ExtensionHandler`, handles `x-vellaveto-audit/stats` method (`vellaveto-mcp/src/extensions/audit_query.rs`). 4 tests.
- **`ProxyState.extension_registry`** — Optional `Arc<ExtensionRegistry>` field for extension method routing across HTTP, WebSocket, and gRPC transports (`vellaveto-http-proxy/src/proxy/mod.rs`)
- All Phase 17 exit criteria now complete (6/6)

#### Phase 19: Regulatory Compliance — Remaining Exit Criteria
- **Compliance dashboard section** — Real-time compliance status in admin dashboard (`vellaveto-server/src/dashboard.rs`) with 4 metric cards (EU AI Act %, SOC 2 Readiness %, Framework Coverage %, Critical Gaps) and a 7-framework coverage table with color-coded thresholds (green >=90%, yellow >=70%, red <70%)
- **EU AI Act Article 50 runtime transparency** — `mark_ai_mediated()` injects `result._meta.vellaveto_ai_mediated = true` into tool-call responses before forwarding to agent (`vellaveto-mcp/src/transparency.rs`). `requires_human_oversight()` checks tool names against configurable glob patterns and logs audit events. ProxyBridge extended with `with_transparency_marking(bool)` and `with_human_oversight_tools(Vec<String>)` builder methods. Art 50(1) status upgraded to Compliant in EU AI Act registry. 11 tests.
- **Immutable audit log archive** — gzip compression of rotated audit log files and retention enforcement (`vellaveto-audit/src/archive.rs`). `compress_rotated_file()` compresses `.log` → `.log.gz` via `flate2`. `enforce_retention()` deletes archives older than configured `retention_days`. `run_archive_maintenance()` combines both in a single pass. Feature-gated behind `archive`. 9 tests.
- **OTLP export with GenAI semantic conventions** — `OtlpExporter` implementing `ObservabilityExporter` trait maps `SecuritySpan` to OpenTelemetry spans (`vellaveto-audit/src/observability/otlp.rs`). GenAI attributes: `gen_ai.system` → `"vellaveto"`, `gen_ai.operation.name` → tool name. Vellaveto attributes: `vellaveto.verdict`, `vellaveto.policy.id`, `vellaveto.detection.type`, `vellaveto.tool.name`. `map_span_kind()` maps Chain→Server, Tool→Internal, Llm→Client. `verdict_to_status()` maps allow→Ok, deny→Error. Feature-gated behind `otlp-exporter`. 11 tests.
- **OtlpConfig** — New configuration type in `vellaveto-config/src/observability.rs` with endpoint, protocol (Grpc/HttpProto), headers, batch_size, flush_interval_secs, max_retries, timeout_secs, service_name. Validation rejects empty endpoints and zero timeouts when enabled. 6 tests.
- **`compress_archives` field** — Added to `EuAiActConfig` in `vellaveto-config/src/compliance.rs` (default: true)
- All Phase 19 exit criteria now complete (9/9)

#### Phase 17.1: WebSocket Transport Support (SEP-1288)
- **WebSocket reverse proxy** — Bidirectional MCP-over-WebSocket at `/mcp/ws` endpoint (`vellaveto-http-proxy/src/proxy/websocket/mod.rs`)
- **Full policy enforcement** — Client→upstream tool calls classified via `classify_message()`, evaluated against policies with fail-closed semantics; engine errors and unknown verdict variants produce Deny
- **Response scanning** — Upstream→client responses scanned for DLP secrets and injection patterns before forwarding
- **TOCTOU-safe canonicalization** — JSON re-serialized before forwarding to prevent time-of-check/time-of-use attacks
- **Per-connection rate limiting** — Sliding window rate limiter (configurable messages/sec, default 100/s) with atomic counter and 1-second window reset
- **Idle timeout** — Configurable inactivity timeout (default 300s) closes stale WebSocket connections
- **Max message size** — Configurable limit (default 1MB) rejects oversized frames with close code 1009
- **Session binding** — Each WebSocket connection bound to exactly one `SessionState` via query parameter or auto-created
- **Binary frame rejection** — Non-text frames rejected with close code 1003 (Unsupported Data)
- **Unparseable message rejection** — Invalid JSON or unclassifiable messages rejected with close code 1008 (Policy Violation)
- **Upstream connection** — `tokio-tungstenite` client with http→ws / https→wss URL scheme conversion and 10s connection timeout
- **Metrics** — `vellaveto_ws_connections_total` and `vellaveto_ws_messages_total` counters with direction labels
- **CLI args** — `--ws-max-message-size`, `--ws-idle-timeout`, `--ws-message-rate-limit`
- **WebSocketConfig** — New config struct in `ProxyState` for WebSocket transport parameters
- **29 unit tests** covering URL conversion, rate limiting, frame classification, error responses, scannable text extraction, config defaults, close codes, metrics, evaluation context, and query params
- **Fuzz target** — `fuzz_ws_frame` for arbitrary bytes → text frame → JSON parse → classify → extract action (21 fuzz targets total)
- **New dependencies**: `tokio-tungstenite = "0.26"` (workspace), `axum` `ws` feature

#### Phase 17.2: gRPC Transport Support
- **gRPC reverse proxy** — Protocol Buffers–based MCP transport on separate port (default 50051) using `tonic` (`vellaveto-http-proxy/src/proxy/grpc/mod.rs`), feature-gated behind `grpc`
- **Protobuf schema** — `proto/mcp/v1/mcp.proto` with `McpService` (Call, StreamCall, Subscribe RPCs) using `google.protobuf.Struct` for dynamic JSON-RPC params/result fields
- **Proto↔JSON conversion** — Bidirectional conversion between prost `Struct` and `serde_json::Value` with depth-bounded recursion (MAX_DEPTH=64) and NaN/Infinity float rejection (`vellaveto-http-proxy/src/proxy/grpc/convert.rs`)
- **Full policy enforcement** — Unary and bidirectional streaming calls classified via `classify_message()`, evaluated against policies with fail-closed semantics; policy denials returned as JSON-RPC errors inside successful gRPC responses (matching HTTP/WS behavior)
- **Auth interceptor** — Constant-time SHA-256 API key validation on gRPC metadata (FIND-008 pattern), returns `UNAUTHENTICATED` status on failure (`vellaveto-http-proxy/src/proxy/grpc/interceptors.rs`)
- **Response scanning** — DLP scanning and injection detection on upstream→client responses before proto conversion
- **gRPC-to-HTTP fallback** — When no upstream gRPC URL configured, converts proto→JSON, POSTs to upstream HTTP URL, converts response back to proto (`vellaveto-http-proxy/src/proxy/grpc/upstream.rs`)
- **gRPC Health Checking v1** — `tonic-health` service registered alongside McpService
- **Coordinated shutdown** — `CancellationToken` shared between HTTP and gRPC servers for graceful shutdown
- **Metrics** — `vellaveto_grpc_requests_total` and `vellaveto_grpc_messages_total` counters with direction labels
- **CLI args** — `--grpc` (enable), `--grpc-port` (default 50051), `--grpc-max-message-size` (default 4MB), `--upstream-grpc-url` (optional)
- **Config type** — `GrpcTransportConfig` in `vellaveto-config/src/grpc_transport.rs` with serde support
- **46 unit tests** covering proto↔JSON conversion (all 6 prost value types, NaN/Infinity, depth limits, roundtrips), config defaults/serde, message classification via proto, session/request-id extraction, error response construction, metadata constants
- **Fuzz target** — `fuzz_grpc_proto` for arbitrary bytes → prost decode → convert → classify (22 fuzz targets total)
- **New workspace dependencies**: `tonic = "0.13"`, `prost = "0.13"`, `prost-types = "0.13"`, `tonic-health = "0.13"`, `tonic-build = "0.13"`, `tokio-util = "0.7"`, `tokio-stream = "0.1"`
- **Zero impact on non-grpc builds** — All code behind `#[cfg(feature = "grpc")]`

#### Merkle Tree Inclusion Proofs (Phase 19.4)
- **Append-only Merkle tree** — Incremental construction with O(log n) peak-based append and RFC 6962 domain separation (`vellaveto-audit/src/merkle.rs`)
- **Domain separation** — `hash_leaf(data) = SHA-256(0x00 || data)`, `hash_internal(l, r) = SHA-256(0x01 || l || r)` prevents second-preimage attacks
- **Inclusion proof generation** — `generate_proof(index)` produces bottom-up sibling path for any leaf in the tree
- **Static proof verification** — `verify_proof(leaf_hash, proof)` verifies without disk access, suitable for external auditors
- **Audit logger integration** — `with_merkle_tree()` builder method; leaf hash appended automatically on each `log_entry()` call
- **Checkpoint integration** — `merkle_root: Option<String>` in `Checkpoint` struct with backward-compatible `signing_content()` (old checkpoints still verify)
- **Log rotation support** — `.merkle-leaves` file renamed alongside rotated log; tree reset for new segment
- **Crash recovery** — `initialize()` rebuilds peaks from existing leaf file after restart
- **24 unit tests** covering empty/single/multi-element trees, proof roundtrips, tampered leaf/sibling/root rejection, logger integration, rotation, crash recovery, domain separation, order dependence

#### Advanced Authorization — ABAC, Least-Agency, Federation, Continuous Auth (Phase 21.1–21.4)
- **ABAC types** — `AbacPolicy`, `AbacEntity`, `AbacEffect` (Permit/Forbid), `AbacOp` (10 operators), `PrincipalConstraint`, `ActionConstraint`, `ResourceConstraint`, `AbacCondition`, `RiskScore`, `RiskFactor`, `FederationTrustAnchor`, `IdentityMapping`, `PermissionUsage`, `LeastAgencyReport`, `AgencyRecommendation` (`vellaveto-types/src/abac.rs`)
- **AbacConfig** — `LeastAgencyConfig`, `FederationConfig`, `ContinuousAuthConfig` with validation (policy count bounds MAX_ABAC_POLICIES=512, entity count MAX_ENTITIES=4096, duplicate ID detection, threshold range checks) (`vellaveto-config/src/abac.rs`)
- **AbacEngine** — Compiled ABAC policies with pre-compiled pattern matchers, forbid-overrides evaluation (any forbid wins over all permits, Cedar semantics), `AbacDecision::Allow/Deny/NoMatch` (`vellaveto-engine/src/abac.rs`)
- **EntityStore** — In-memory entity store with transitive group membership lookup (bounded depth=16), `from_entities()` constructor
- **Condition evaluation** — 10 comparison operators (Eq, Ne, In, NotIn, Contains, StartsWith, Gt, Lt, Gte, Lte) evaluated against action parameters
- **Two-phase evaluation** — PolicyEngine runs first (coarse filter), AbacEngine refines Allow verdicts; if PolicyEngine says Deny, ABAC doesn't run
- **LeastAgencyTracker** — Per-agent-session permission usage tracking with `register_grants()`, `record_usage()`, `check_unused()`, `generate_report()`, `recommend_narrowing()` (`vellaveto-engine/src/least_agency.rs`)
- **4-tier recommendation system** — Optimal (>80%), ReviewGrants (50–80%), NarrowScope (20–50%), Critical (<20% usage ratio)
- **Identity federation** — `FederationTrustAnchor` with JWKS URI, issuer patterns, `IdentityMapping` (external JWT claims → internal principal via id_template)
- **Continuous authorization** — `ContinuousAuthConfig` with `risk_threshold`, `degradation_threshold`, `reevaluation_interval_secs`; `RiskScore` with weighted `RiskFactor` list
- **Transport wiring** — ABAC refinement integrated across HTTP handlers, WebSocket, and gRPC transports; deny with audit trail when forbid matches
- **ProxyState extended** — `abac_engine: Option<Arc<AbacEngine>>`, `least_agency: Option<Arc<LeastAgencyTracker>>`, `continuous_auth_config: Option<ContinuousAuthConfig>`
- **SessionState extended** — `risk_score: Option<RiskScore>`, `abac_granted_policies: Vec<String>`
- **Full backward compatibility** — `abac.enabled = false` (default) makes behavior identical to pre-Phase 21
- **~49 new tests** — 5 types + 6 config + 27 engine + 8 least-agency + 3 proxy wiring
- **No new dependencies** — Reuses existing serde, glob matchers, HashMap from workspace

#### Capability-Based Delegation Tokens (Phase 21.0)
- **CapabilityToken type** — Ed25519-signed tokens with delegation chain, depth budget, grants, and expiry (`vellaveto-types/src/capability.rs`)
- **CapabilityGrant** — Tool/function glob patterns with path and domain constraints and invocation limits
- **Token issuance** — `issue_capability_token()` creates root tokens with Ed25519 signature over length-prefixed canonical content (`vellaveto-mcp/src/capability_token.rs`)
- **Monotonic attenuation** — `attenuate_capability_token()` enforces: depth decrements, grants must be subset of parent, expiry clamped to parent's expiry; escalation rejected
- **Token verification** — `verify_capability_token()` validates signature, expiry, and holder match
- **Grant coverage** — `check_grant_coverage()` matches token grants against `Action` tool/function/paths/domains with glob support
- **RequireCapabilityToken policy condition** — Fail-closed evaluation in `vellaveto-engine/src/context_check.rs`; missing token = Deny, invalid holder/issuer = Deny, insufficient depth = Deny
- **Policy compilation** — `require_capability_token` condition compiled in `vellaveto-engine/src/policy_compile.rs` with `required_issuers`, `min_remaining_depth`, and `deny_reason`
- **EvaluationContext extended** — `capability_token: Option<CapabilityToken>` field added to `vellaveto-types/src/identity.rs` with builder support
- **Structural validation** — `validate_structure()` enforces MAX_GRANTS=64, MAX_DELEGATION_DEPTH=16, MAX_TOKEN_SIZE=65536, rejects empty fields
- **31 unit tests** — 4 types tests (serde, validation), 5 engine tests (context condition), 22 mcp tests (sign/verify, attenuation, grant coverage, expiry, holder/issuer mismatch)
- **No new dependencies** — Reuses ed25519-dalek, hex, serde already in workspace

#### CoSAI/Adversa Threat Coverage Registries (Phase 19.3)
- **CoSAI 12-category threat registry** — 38 threats across all 12 Coalition for Secure AI categories with `VellavetoDetection` runtime mappings and structural mitigation coverage (`vellaveto-audit/src/cosai.rs`)
- **Adversa AI TOP 25 coverage matrix** — All 25 ranked MCP vulnerabilities (Critical/High/Medium) with detection mappings and mitigation tracking (`vellaveto-audit/src/adversa_top25.rs`)
- **Cross-framework gap analysis** — Unified report across 7 frameworks (MITRE ATLAS, NIST AI RMF, ISO 27090, EU AI Act, CoSAI, Adversa TOP 25, ISO 42001) with weighted-average coverage, identified gaps, and recommendations (`vellaveto-audit/src/gap_analysis.rs`)
- **Threat coverage API endpoint** — `GET /api/compliance/threat-coverage` returns ATLAS, CoSAI, and Adversa coverage summaries
- **Gap analysis API endpoint** — `GET /api/compliance/gap-analysis` returns consolidated 7-framework gap report
- **100% CoSAI coverage** (38/38 threats across 12/12 categories), **100% Adversa TOP 25 coverage** (25/25 vulnerabilities)
- **35 unit tests** — 14 CoSAI (registry, categories, detection mappings, coverage report, serde), 14 Adversa (registry, ranks, mitigations, matrix, serde), 7 gap analysis (generation, framework presence, coverage threshold, recommendations, serde)
- **No new dependencies** — Reuses serde, chrono, HashMap from existing audit crate

#### Compliance Evidence Generation (Phase 19.1 / 19.4)
- **Shared compliance types** — `AiActRiskClass` (Minimal/Limited/HighRisk/Unacceptable) and `TrustServicesCategory` (CC1-CC9) in `vellaveto-types/src/compliance.rs` (leaf crate, no dependency violations)
- **ComplianceConfig** — `EuAiActConfig` and `Soc2Config` with validation (MAX_HUMAN_OVERSIGHT_TOOLS=500, MIN_RETENTION_DAYS=30, MAX_SOC2_CATEGORIES=9) (`vellaveto-config/src/compliance.rs`)
- **EU AI Act registry** — `EuAiActRegistry` with 10 obligations (Art 5, 6, 9, 12, 13, 14, 15, 43, 50(1), 50(2)) and 18 capability mappings across `TransparencyCapability` enum (`vellaveto-audit/src/eu_ai_act.rs`)
- **EU AI Act conformity assessment** — `generate_assessment(risk_class, deployer_name, system_id)` produces `ConformityAssessmentReport` with compliance percentage, applicable/compliant/partial articles
- **EU AI Act entry classification** — `classify_entry_transparency()` classifies audit entries at read-time into transparency records
- **SOC 2 registry** — `Soc2Registry` with 22 criteria across CC1-CC9 and ~30 capability mappings with `ReadinessLevel` (NotStarted through Optimizing, scored 0-5) (`vellaveto-audit/src/soc2.rs`)
- **SOC 2 evidence report** — `generate_evidence_report(org_name, period_start, period_end, tracked_categories)` produces `Soc2EvidenceReport` with overall readiness, scores, and gaps
- **SOC 2 coverage analysis** — `coverage_by_category()` returns per-category coverage with readiness levels
- **SOC 2 entry classification** — `classify_entry()` classifies audit entries at read-time into evidence records
- **Compliance API endpoints** — Three new routes registered in `vellaveto-server`:
  - `GET /api/compliance/status` — Overall compliance posture (EU AI Act + SOC 2 + optional NIST RMF + ISO 27090)
  - `GET /api/compliance/eu-ai-act/report` — Full conformity assessment report per Art 43
  - `GET /api/compliance/soc2/evidence?category=CC1` — SOC 2 evidence collection with optional category filter
- **PolicySnapshot extended** — `compliance_config` field for atomic policy reload with compliance configuration
- **34 unit tests** — 9 config tests (defaults, validation, TOML parsing, serde roundtrip), 11 EU AI Act tests (registry, assessment, entry classification), 14 SOC 2 tests (registry, evidence report, coverage, entry classification, category filtering)
- **No new dependencies** — Reuses serde, serde_json, sha2 already in workspace

- Docker Compose for local deployment (`docker-compose.yml`)
- Docker image build and publish workflow (GHCR + Trivy scanning)
- GitHub release automation workflow (static binaries, checksums, SBOM, provenance)
- Rustdoc GitHub Pages deployment workflow
- CONTRIBUTING.md with development rules and release checklist
- LICENSING.md with dual license terms and AI training opt-out
- 5 new fuzz targets: agent card URL/parse, A2A classify, homoglyph, attestation verify (15 → 20 total, now 21 with Phase 17.1)
- Machine-readable AI training opt-out (`.well-known/ai-policy.txt`)
- GitHub issue templates (bug report, feature request) with structured forms
- GitHub pull request template with testing checklist
- Python SDK test suite: 86 tests covering types, client, langchain, and langgraph modules
- crates.io publishing workflow (manual trigger, dependency-ordered, dry-run support)
- PyPI publishing workflow (tag trigger, trusted publishing OIDC, multi-version matrix)
- Security Model document (`docs/SECURITY_MODEL.md`): trust boundaries, data flows, storage guarantees, residual risks
- Benchmark guide (`docs/BENCHMARKS.md`): reproducible performance benchmarks with methodology and CI integration
- 5 curated policy presets: `dev-laptop`, `ci-agent`, `rag-agent`, `database-agent`, `browser-agent`
- Framework quickstart guide (`docs/QUICKSTART.md`): step-by-step Anthropic, OpenAI, LangChain, LangGraph, MCP proxy integration
- Python SDK parameter redaction (`vellaveto.redaction`): client-side secret stripping with 3 modes (keys_only, values, all), 56 tests
- `.dockerignore` for faster, smaller Docker builds
- OCI image labels on Dockerfile (title, description, source, license, vendor)
- Helm NetworkPolicy template with configurable ingress/egress rules
- Helm PodDisruptionBudget template for HA during K8s maintenance
- Helm ServiceMonitor template for Prometheus metrics discovery

### Changed

- Docker Compose: added resource limits (1 CPU, 256MB) and log rotation (10MB x 3 files)

- Default server port standardized from 8080 to 3000 across CLI, SDK, and documentation

- License switched from Apache-2.0 to AGPL-3.0 dual license
- All crate versions synced from 2.0.0 to 2.2.1
- Helm chart version synced to 2.2.1, license annotation corrected
- Python SDK version synced to 2.2.1 (including `__init__.py`)

## [2.2.1] - 2026-02-13

### Security

- **Adversarial Audit Hardening (FIND-055–074)**:
  - FIND-055 (P1): Agent card SSRF prevention — `validate_agent_card_base_url()` rejects non-HTTPS schemes, localhost, private IPs, IPv6 private ranges, path traversal, and userinfo-based host spoofing (9 tests)
  - FIND-057 (P2): Bounded stack size in `collect_string_leaves()` (MAX_STACK_SIZE=10,000) to prevent memory exhaustion from wide JSON fan-out in A2A messages
  - FIND-063 (P2): Regex pattern length validation (MAX_PATTERN_LEN=2,048) for DLP and PII patterns before regex compilation to prevent ReDoS
  - FIND-065 (P3): Audit log file permission failures now logged as `tracing::warn!` instead of silently ignored with `let _ =`
  - FIND-068 (P3): Accountability attestation `sign_attestation()` rejects empty agent_id, statement, and policy_hash (3 tests)
  - FIND-071 (P3): `ObservabilityExporterConfig` validation with MAX_BATCH_SIZE=10,000 and timeout_secs>0 bounds (5 tests)
  - FIND-074 (P3): Audit logger now rejects ALL control characters (U+0000–U+009F) in tool/function names, not just \n, \r, and \0 — prevents log injection via tabs, backspaces, escape sequences
  - Updated 4 integration test files to match new control character rejection behavior

- **Adversarial Pentest Round 3 Fixes (FIND-077–084)**:
  - FIND-077 (P1): Circuit breaker case-sensitivity bypass — tool names normalized to lowercase before all HashMap operations, preventing evasion via case variation (`MyTool` vs `mytool`)
  - FIND-078 (P1): Circuit breaker HalfOpen state never entered — `can_proceed()` now transitions Open→HalfOpen via double-check locking (read→write lock upgrade) when open duration expires, enforcing `half_open_max_requests` limit
  - FIND-079 (P1): Circuit breaker no exponential backoff — added `trip_count: u32` to `CircuitStats` with `#[serde(default)]`, incremented on HalfOpen→Open transitions, `effective_open_duration = base * 2^trip_count` (max 32x), reset on full recovery
  - FIND-080 (P2): Behavioral EMA gradual ramp evasion — added `absolute_ceiling: Option<u64>` to `BehavioralConfig`, produces `Critical` alert when tool call count exceeds ceiling regardless of EMA baseline
  - FIND-081 (P2): Behavioral cold-start baseline poisoning — added `max_initial_ema: Option<f64>` to `BehavioralConfig`, caps first observation's EMA to prevent artificially high baselines
  - FIND-082 (P2): Deputy re-delegation scope overwrite — `register_delegation()` now intersects requested `allowed_tools` with parent's granted scope, enforcing monotonic attenuation
  - FIND-083 (P2): Capability grant path traversal — `normalize_path_for_grant()` resolves `.`/`..` components before matching; null bytes and above-root traversal fail-closed
  - FIND-084 (P3): Fullwidth digit SSN bypass — NFKC normalization via `unicode-normalization` crate before PII regex matching converts fullwidth digits (U+FF10–FF19) to ASCII
  - Updated 8 pentest tests across 4 integration test files to verify all fixes

### Testing

- **Adversarial Audit Test Coverage (FIND-043–054)**:
  - 4,300+ tests total (up from 4,200+), 18 audit rounds (up from 17)
  - FIND-043 (P1): 25 context condition tests covering all 10 condition types (MaxChainDepth, AgentIdentityMatch, AsyncTaskPolicy, ResourceIndicator, CapabilityRequired, StepUpAuth, CircuitBreaker, DeputyValidation, SchemaPoisoningCheck, ShadowAgentCheck)
  - FIND-044 (P1): Circuit breaker HalfOpen→Closed recovery and Open→HalfOpen auto-transition tests
  - FIND-045 (P1): 16 end-to-end OAuth JWT validation tests with mock JWKS server (sign → fetch → verify flow covering expiry, algorithm confusion, issuer/audience/scope/resource enforcement, kid matching, signature tampering, DPoP mode, RFC 7235 case-insensitivity)
  - FIND-046 (P2): Domain homoglyph tests (Cyrillic, zero-width, fullwidth, mixed-script, combining diacritics)
  - FIND-047 (P2): Windows path normalization tests (UNC paths, drive letters, mixed separators)
  - FIND-048 (P2): Audit rotation manifest tamper detection tests (entry deletion, reordering)
  - FIND-049 (P2): Memory tracker fingerprint evasion tests (case sensitivity, percent-encoding, query param reordering)
  - FIND-050 (P2): 13 semantic scanner Unicode evasion tests documenting known gaps (fullwidth Latin, Cyrillic homoglyphs, zero-width insertion, combining diacritics, RTL override, mixed-script, superscript digits, chaos inputs)
  - FIND-051 (P2): Agent card URL edge case tests (file:// scheme, internal IPs, path traversal, trailing slashes, case-sensitive cache keys, XSS in name)
  - FIND-052 (P3): Behavioral EMA edge case tests (epsilon guard, u64::MAX, overflow, saturation)
  - FIND-053 (P3): Output validation depth bomb tests (nested schemas at and beyond MAX_VALIDATION_DEPTH=32)
  - FIND-054 (P3): Elicitation rate limit boundary tests (u32::MAX, exact boundary, boundary minus one)

### Changed

- **Server Route Modularization (IMP-001)**:
  - Extracted 17 route handler modules from `routes/main.rs` (~800 lines removed)
  - Created dedicated modules: approval, audit, auth_level, circuit_breaker, deputy, etdi, exec_graph, memory, nhi, observability, policy, registry, sampling, schema_lineage, shadow_agent, task_state, tenant
  - Improved code organization and maintainability

- **Documentation Sync**:
  - Updated `README.md` to reflect v2.2.1 metadata, MCP `2025-11-25` support (with compatibility notes), current container tags, and roadmap link.
  - Updated `ROADMAP.md` to mark Phase 15 complete and v2.2 timeline complete.
  - Expanded `README.md` with a full workspace module architecture map and feature ownership matrix (owners, entrypoints, and primary tests).
  - Expanded `README.md` project structure coverage to include SDK, Helm, docs, policies, security testing, and local collaboration surfaces.
  - Updated `ROADMAP.md` with an explicit Phase 16.6 architecture split/modularization track.
  - Added `MODULE_EXTRACTION_PLAYBOOK.md` and linked it from `README.md`; marked Phase 16.6 playbook/contract-check tasks complete in `ROADMAP.md`.
  - Added a post-quantum readiness section to `README.md` with standards status and migration milestones (2028/2031/2035 alignment).
  - Added Phase 16.7 post-quantum cryptography transition track to `ROADMAP.md` with TLS policy, observability, and rollout tasks.
  - Published `docs/quantum-migration.md` runbook with staged `tls.kex_policy` rollout/rollback guidance and canary verification steps.
  - Clarified OPA runtime status in `README.md` and `ROADMAP.md`: request-path enforcement is active with fail-open/fail-closed controls and runtime observability.
  - Added 2026-02-11 research-backed hardening backlog updates across `README.md`, `ROADMAP.md`, and `docs/SECURITY.md`:
    - P0 CI supply-chain hardening pack
    - P0 sender-constrained OAuth (DPoP) enforcement path in `vellaveto-http-proxy`
    - P1 `cargo-deny` policy gate and OPA runtime decision-path completion

### Added

- **CI Supply-Chain Baseline Hardening**:
  - Added Dependabot config for Cargo and GitHub Actions (`.github/dependabot.yml`)
  - Added PR dependency review workflow (`.github/workflows/dependency-review.yml`)
  - Added `cargo-deny` policy workflow (`.github/workflows/cargo-deny.yml`) with baseline config in `deny.toml`
  - Added provenance + SBOM workflow (`.github/workflows/provenance-sbom.yml`) with immutable action pins, lockfile immutability checks, release attestations, and CycloneDX artifact publishing
  - Added attestation verification gate in provenance workflow using `gh attestation verify` for release binaries
  - Added OpenSSF Scorecard workflow (`.github/workflows/scorecard.yml`) with SARIF upload for continuous repository hardening visibility
  - Added CODEOWNERS policy (`.github/CODEOWNERS`) for workflow and security-sensitive paths

- **Post-Quantum TLS KEX Policy (initial implementation)**:
  - Added `tls.kex_policy` to `TlsConfig` with values:
    - `classical_only`
    - `hybrid_preferred`
    - `hybrid_required_when_supported`
  - Added config validation guardrails:
    - Hybrid policies require `tls.mode` to be `tls` or `mtls`
    - Hybrid policies require `tls.min_version = "1.3"`
    - `tls.min_version` now validates accepted values (`"1.2"` or `"1.3"`)
  - Added rustls provider KEX-group policy application in `vellaveto-server` TLS setup with explicit downgrade warnings when hybrid is requested but unavailable.
  - Added example config snippet documenting `tls.kex_policy` usage.

- **Source distribution packaging**:
  - Added repository source ZIP artifact under `dist/` generated from tracked files at `HEAD` (`git archive`).
  - Added README guidance for generating and checksumming source distribution ZIPs locally.

### Refactor

- **HTTP proxy modularization**:
  - Split `vellaveto-http-proxy/src/proxy.rs` (6,712 lines) into 8 focused submodules under `proxy/`
  - Created: `mod.rs` (187), `handlers.rs` (2,082), `tests.rs` (1,729), `inspection.rs` (817), `upstream.rs` (805), `call_chain.rs` (464), `auth.rs` (395), `helpers.rs` (195), `origin.rs` (174)
  - Public API unchanged: `ProxyState`, `handle_mcp_post`, `handle_mcp_delete`, `handle_protected_resource_metadata`, `TrustedProxyContext`, `McpQueryParams`, `PrivilegeEscalationCheck`
  - All 169 proxy unit tests pass, zero clippy warnings
  - Follows the `vellaveto-mcp/src/proxy/bridge/` split pattern

- **DPoP audit function parameter consolidation**:
  - Introduced `DpopAuditParams` struct to group OAuth DPoP audit parameters
  - Reduces `audit_dpop_validation_failure()` function arguments from 8 to 2
  - Fixes `clippy::too_many_arguments` warning

- **Scanner infrastructure consolidation (IMP-002)**:
  - Added `scanner_base.rs` module with shared types for DLP and injection scanning
  - New unified `ScanFinding` type for consistent finding representation across scanners
  - New `ScannerType` enum for categorizing findings by scanner
  - Shared `MAX_SCAN_DEPTH` constant (32) replaces per-module depth limits
  - Common utilities: `normalize_text`, `traverse_json_strings`, `extract_response_text`, `extract_notification_text`
  - Added `to_scan_finding()` conversion methods to `DlpFinding` and `ToolDescriptionFinding`
  - Refactored `scan_response_for_injection()` to use shared `extract_response_text()` utility
  - Added `traverse_json_strings_with_keys()` for security scanning that includes object keys (R42-MCP-1)
  - Refactored `scan_notification_for_injection()` to use shared key-scanning utility
  - Reduces code duplication while maintaining security properties across scanners

- **HTTP proxy test helper simplification**:
  - Reduced `build_oauth_test_state_full` argument count in `vellaveto-http-proxy` integration tests.
  - Improves maintainability and readability of OAuth test setup paths.

- **MCP code hygiene cleanup**:
  - Removed unnecessary `#[allow(dead_code)]` annotations where no longer needed.

### Style

- **Format string interpolation**:
  - Replaced `format!("{}", var)` with `format!("{var}")` across core crates
  - Applied to vellaveto-types, vellaveto-engine, vellaveto-audit, vellaveto-approval, vellaveto-mcp
  - Cleaner, more readable format strings
  - Fixes `clippy::uninlined_format_args` pedantic warnings

- **Option chain simplification**:
  - Replaced `map().unwrap_or()` with `map_or()` for cleaner Option handling
  - Applied to vellaveto-types, vellaveto-engine (deputy, legacy, lib)
  - Fixes `clippy::map_unwrap_or` pedantic warnings

- **Numeric literal formatting**:
  - Added digit separators to large numeric literals for improved readability
  - Timestamps: `1704067200` → `1_704_067_200`
  - Time durations: `604800` → `604_800`
  - IP addresses: `167772160` → `167_772_160`
  - File sizes: `1048576` → `1_048_576`
  - Fixes `clippy::unreadable_literal` pedantic warnings

- **Documentation formatting**:
  - Added backticks around code items in doc comments (types, fields, algorithms)
  - Improves rustdoc rendering and consistency

### Performance

- **Pre-compiled regex optimization (IMP-007)**:
  - Moved base64 detection regex in `output_security.rs` to static `OnceLock`
  - Eliminates per-call regex compilation in steganography detection

- **Runtime allocation tuning**:
  - Added bounded `HashMap::with_capacity` hints in `vellaveto-mcp` runtime/session managers:
    - `token_security`
    - `task_state`
    - `auth_level`
    - `output_validation`
    - `workflow_tracker`
  - Updated `PolicyEngine` constructors to initialize `domain_norm_cache` using `MAX_DOMAIN_NORM_CACHE_ENTRIES`-bounded capacity.

### Security

- **Call-chain header hardening (`vellaveto-http-proxy`)**:
  - Enforced fail-closed `X-Upstream-Agents` validation across MCP method paths.
  - Added explicit rejection for headers whose entry count exceeds `limits.max_call_chain_length` (instead of truncation).
  - Added regression coverage for malformed and over-limit call-chain headers on tool-call, pass-through, sampling, resource, and task paths.

- **OPA runtime decision enforcement (`vellaveto-server`)**:
  - Runtime OPA verdict wiring is active in evaluation request paths with fail-open/fail-closed controls and runtime query/error metrics.
  - Added route-level regression coverage for fail-open and fail-closed behavior when OPA is unreachable.
  - Added `opa.require_https` hardening control to require `https://` OPA endpoints.
  - Added config validation for OPA endpoint URL shape (scheme, host, and userinfo rejection) and startup/runtime rejection when `require_https=true` is paired with plaintext OPA endpoints.
  - Added startup security warnings for plaintext OPA control-plane traffic and remote OPA endpoints configured without auth headers.

- **OPA fail-closed defaults hardening (R43-OPA-1)**:
  - Changed `opa.require_https` default from `false` to `true` (encrypt policy decisions in transit)
  - Added `opa.fail_open_acknowledged` field requiring explicit acknowledgment to enable `fail_open=true`
  - Validation now rejects `fail_open=true` without `fail_open_acknowledged=true`
  - Changed `injection.block_on_injection` default from `false` to `true` (fail-closed behavior)
  - Prevents accidental misconfiguration that could allow bypass during OPA unavailability

- **Provenance verification hardening (CI)**:
  - Strengthened `gh attestation verify` checks to require the expected signer workflow path and exact source ref (`GITHUB_REF`), and deny attestations generated on self-hosted runners.

- **Dependency audit policy hygiene**:
  - Removed stale `RUSTSEC-2024-0384` ignore from `.cargo/audit.toml`; lockfile no longer includes the affected transitive crate.

- **DPoP failure observability (`vellaveto-http-proxy`)**:
  - Added dedicated DPoP counters: `vellaveto_oauth_dpop_failures_total` (reason-labeled) and `vellaveto_oauth_dpop_replay_total`.
  - Added explicit audit events for DPoP validation failures with `dpop_reason`, `dpop_mode`, `oauth_subject`, and header/session context.
  - Added integration coverage for missing-proof and replay-detected audit paths.

- **OAuth/DPoP startup and replay hardening (`vellaveto-http-proxy`)**:
  - Added startup guardrails for pass-through mode: `--oauth-pass-through` now requires explicit `--unsafe-oauth-pass-through`, RFC 8707 expected resource binding, and DPoP `required` mode.
  - Added hardened OAuth profile support (`--oauth-security-profile hardened`) to enforce sender-constrained posture at startup.
  - Added startup warnings when OAuth is enabled with weak defaults (`dpop_mode=off` or missing expected resource) in standard profile.
  - Enforced sender-constrained token binding in DPoP `required` mode: access tokens must contain `cnf.jkt`, and runtime now verifies `cnf.jkt` against the presented DPoP proof key thumbprint (RFC 7638).
  - Hardened DPoP replay cache input handling by bounding untrusted `jti`/replay-key size and keying replays by `jti:ath` when token binding is available.

- **TLS metadata observability (`vellaveto-server`)**:
  - Added evaluate-path extraction of sanitized forwarded TLS handshake metadata (`protocol`, `cipher`, `kex_group`).
  - Trusted forwarded TLS metadata headers only when the direct connection peer is a configured trusted proxy.
  - Trusted `X-Forwarded-Proto` for HSTS decisions only when the direct connection peer is a configured trusted proxy.
  - Fixed `X-Principal` trust check to use direct trusted-proxy peer identity (not derived client IP), preserving per-principal rate-limit attribution behind trusted proxy chains.
  - Added per-principal rate-limit integration coverage for trusted proxy + `X-Forwarded-For` chains with stable `X-Principal` identity.
  - Rejected control characters in trusted `X-Principal` header values before principal-key derivation.
  - Treated missing trusted-proxy request context as untrusted when evaluating forwarded TLS metadata (fail-safe default).
  - Added `vellaveto_forwarded_header_rejections_total{header=...}` metric and incremented it when untrusted `X-Forwarded-Proto` or forwarded TLS metadata headers are ignored.
  - Included TLS metadata in audit entry metadata for `/api/evaluate` decisions.

- **HTTP proxy request-id hardening (`vellaveto-http-proxy`)**:
  - Rejected control characters in client-supplied `X-Request-Id` values before echoing to response headers.

- **HTTP proxy forwarded-header trust hardening (`vellaveto-http-proxy`)**:
  - Added trusted-proxy context propagation based on direct peer IP (`ConnectInfo`) and `VELLAVETO_TRUSTED_PROXIES`.
  - Trusted `X-Forwarded-Proto` for HSTS decisions only when the direct connection peer is a configured trusted proxy.
  - Trusted `X-Forwarded-Proto` / `X-Forwarded-Host` for OAuth effective request URI construction only when the direct connection peer is a configured trusted proxy.
  - Added regression coverage for trusted vs untrusted forwarded-header URI reconstruction and trusted-proxy peer detection helpers.
  - Added the same TLS attributes to observability spans when exporters are enabled.
  - Added unit/integration coverage for TLS metadata extraction and audit emission.
  - Hardened extraction to reject ambiguous duplicate/alias values for each TLS metadata field (fail-closed on conflicts).
  - Preserved fallback to lower-priority alias headers when a higher-priority alias is malformed.
  - Added route-level audit integration coverage for conflicting alias/duplicate TLS protocol headers and safe fallback behavior.
  - Added TLS KEX negotiation integration tests for `classical_only`, `hybrid_preferred`, and `hybrid_required_when_supported` including classical-only client failure-mode coverage when PQ/hybrid groups are available.

- **Workspace outbound TLS backend standardization**:
  - Standardized workspace `reqwest` backend to rustls by setting `default-features = false` and enabling `rustls-tls` at the workspace dependency root.
  - Keeps outbound HTTP client behavior consistent across `vellaveto-server`, `vellaveto-http-proxy`, `vellaveto-audit` exporters, and `vellaveto-mcp` cloud backends.
  - Updated `vellaveto-server` TLS provider selection to explicitly use rustls `aws-lc-rs` provider, avoiding runtime panics when multiple rustls providers are enabled in the dependency graph.
  - Verified compile coverage for key reqwest consumers, including `vellaveto-audit --features observability-exporters` and `vellaveto-mcp --features llm-cloud`.

- **DLP pattern validation at startup (SEC-006)**:
  - Both `vellaveto-server` and `vellaveto-http-proxy` now validate all DLP patterns compile successfully during startup
  - If any pattern fails to compile, the application fails to start rather than silently skipping secret detection
  - Prevents silent gaps in DLP coverage from malformed patterns

- **Injection pattern validation at startup**:
  - Added `validate_injection_patterns()`, `is_injection_available()`, and `injection_pattern_count()` functions
  - Both server and proxy now validate injection patterns compile at startup
  - Consistent with DLP validation for defense-in-depth

- **Health endpoint security scanning status (SEC-006)**:
  - Enhanced `/health` endpoint in both `vellaveto-server` and `vellaveto-http-proxy` to report scanning subsystem availability
  - New response fields: `scanning.dlp_available` and `scanning.injection_available`
  - Health status reports "degraded" if either DLP or injection detection is unavailable
  - Provides visibility into security posture for monitoring and alerting

- **Metrics endpoint scanning pattern counts**:
  - Extended `/api/metrics` JSON response to include scanning subsystem details
  - New fields: `scanning.dlp.available`, `scanning.dlp.pattern_count`, `scanning.injection.available`, `scanning.injection.pattern_count`
  - Provides operational visibility into active pattern counts for monitoring

### Dependencies

- **Minor/patch updates (IMP-006)**:
  - `proptest` 1.9.0 → 1.10.0
  - `regex` 1.12.2 → 1.12.3
  - `tempfile` 3.24.0 → 3.25.0
  - `clap` 4.5.56 → 4.5.57
  - `criterion` 0.8.1 → 0.8.2
  - `x509-parser` 0.17 → 0.18 (ASN.1 parsing improvements)
  - `metrics-exporter-prometheus` 0.16 → 0.18 (metrics 0.24 ecosystem)
  - `serde_json_canonicalizer` 0.3.1 → 0.3.2
  - `toml` 0.9 → 1.0 (first stable release)

- **GitHub Actions updates**:
  - `actions/checkout` 4.3.1 → 6.0.2
  - `actions/cache` 4.3.0 → 5.0.3
  - `actions/upload-artifact` 4.6.2 → 6.0.0
  - `Swatinem/rust-cache`, `actions/dependency-review-action`, `actions/attest-build-provenance`, `ossf/scorecard-action`, `github/codeql-action` — commit hash updates
  - All actions pinned to specific commit SHAs for supply chain security

## [2.2.1] - 2026-02-10

### Changed

- **MCP Protocol Version**: Updated from `2025-06-18` to `2025-11-25` with backwards compatibility for `2025-06-18` and `2025-03-26`
- **DELETE Session Termination**: Changed response from 200 OK to 204 No Content per MCP specification
- **Memory Tracking Configuration**: `MAX_FINGERPRINTS` and `MIN_TRACKABLE_LENGTH` are now configurable via `MemorySecurityConfig.max_fingerprints` and `MemorySecurityConfig.min_trackable_length`
- **Dependency Updates**:
  - Upgraded `jsonwebtoken` from 9 to 10 with `aws_lc_rs` feature (FIPS-validated cryptography)
  - Upgraded `notify` from 7 to 8
  - Note: `rand` 0.8 → 0.9 blocked by ed25519-dalek incompatibility (deferred)

### Added

#### Protocol Version Validation
- Validate `MCP-Protocol-Version` header on incoming requests
- Accept versions: `2025-11-25`, `2025-06-18`, `2025-03-26`
- Return 400 Bad Request for unrecognized protocol versions

#### RFC 9728 OAuth Protected Resource Metadata
- Added `GET /.well-known/oauth-protected-resource` endpoint
- Returns `resource`, `authorization_servers`, `scopes_supported` when OAuth configured
- Returns 404 when OAuth not configured

#### AI Service Credential DLP Patterns (OWASP ASI03)
- `anthropic_api_key` — Anthropic API keys (`sk-ant-api...`)
- `openai_api_key` — OpenAI API keys (`sk-`, `sk-proj-`)
- `huggingface_token` — HuggingFace tokens (`hf_...`)
- `cohere_api_key` — Cohere API keys
- `replicate_token` — Replicate tokens (`r8_...`)
- `together_api_key` — Together.ai API keys
- `groq_api_key` — Groq API keys (`gsk_...`)

#### MCPTox Directive Injection Detection
- Added directive insertion patterns: `IMPORTANT:`, `NOTE:`, `REQUIRED:`, `CRITICAL:`, `WARNING:`, `ATTENTION:`, `MUST:`

#### Phonetic/Emoji Encoding Detection
- NATO phonetic alphabet decoding (`alpha bravo charlie` → `abc`)
- Common emoji command decoding (`🐱📁` → `cat file`)
- Integrated into injection detection pipeline

#### Mixed-Script Spoofing Detection
- New `SquattingKind::MixedScript` for detecting tool names with mixed Unicode scripts
- Detects Latin + Cyrillic, Latin + Greek, Latin + Mathematical combinations
- Higher priority detection than homoglyph normalization

#### Multimodal Content Safety (Phase 1)
- `MultimodalScanner` for detecting injection attempts in non-text content
- `ContentType` enum with magic byte and MIME type detection (Image, Audio, PDF, Video)
- `scan_blob_for_injection()` for scanning MCP resource.blob fields
- OCR integration placeholder (feature-gated with `multimodal` feature)
- Steganography detection scaffolding

#### Hallucination/Grounding Detection (Phase 1)
- `GroundingChecker` for validating LLM responses against RAG context
- Lexical overlap scoring (Jaccard similarity) as NLI fallback
- `GroundingResult` with claim scores, contradictions, and source attributions
- Sentence-based claim extraction with configurable min/max thresholds
- `GroundingConfig` in `RagDefenseConfig` for runtime configuration

#### Python SDK (Phase 1)
- New `sdk/python/vellaveto` package for LangChain/LangGraph integration
- `VellavetoClient` — Sync/async HTTP client supporting httpx and requests backends
- `VellavetoCallbackHandler` — LangChain callback for intercepting tool calls
- `VellavetoToolGuard` — Decorator for guarding individual tools
- `create_guarded_toolkit()` — Wraps existing LangChain toolkits with Vellaveto guards
- `create_vellaveto_node()` — LangGraph node factory for policy evaluation
- `create_vellaveto_tool_node()` — Combined tool execution + policy evaluation node

#### API Stability (Phase 2)
- Added `#[non_exhaustive]` to core enums for forward compatibility:
  - `Verdict` — Allow/Deny/RequireApproval variants
  - `PolicyType` — Allow/Deny/Conditional variants
  - `ApprovalStatus` — Pending/Approved/Denied/Expired variants
  - `SquattingKind` — Levenshtein/Homoglyph/MixedScript variants
- All match statements updated with fail-closed wildcard patterns for unknown variants

#### MCP Tasks Primitive Support (Phase 2)
- Extended `MessageType::TaskRequest` classification to include:
  - `tasks/list` — List active tasks
  - `tasks/resubscribe` — Resume task event subscriptions
- Full parity with MCP 2025-11-25 task primitives

#### Configuration Validation (Phase 2)
- Added Ed25519 public key format validation at config load time
- Validates trusted_keys are exactly 64 hex characters (32 bytes)
- Returns descriptive error messages for invalid key formats

#### Additional DLP Patterns (Phase 3)
- `supabase_api_key` — Supabase API keys (`sbp_...`)
- `vercel_token` — Vercel tokens (`vercel_`, `vc_...`)
- `databricks_token` — Databricks tokens (`dapi...`)
- `linear_api_key` — Linear API keys (`lin_api_...`)
- `planetscale_token` — Planetscale tokens (`pscale_...`)
- `neon_token` — Neon database tokens

#### Additional Injection Detection Patterns (Phase 3)
- Gemma format: `<start_of_turn>`, `<end_of_turn>`
- Phi format: `<|endoftext|>`
- DeepSeek format: `<|begin▁of▁sentence|>`, `<|end▁of▁sentence|>`
- Command R format: `<|start_header_id|>`, `<|end_header_id|>`, `<|eot_id|>`

#### Tool Squatting Detection Improvement (FIND-005)
- Increased Levenshtein distance threshold from 2 to 3 for tool names > 8 characters
- Catches typosquats like `read_files` vs `read_file` or `write_filed` vs `write_file`

#### DLP Pattern Validation at Config Load (FIND-002)
- Added regex validation for `dlp.extra_patterns` at config load time
- Invalid regex patterns now fail startup instead of being silently skipped
- Added `regex` dependency to `vellaveto-config`

#### Call Chain Security Hardening
- Added `MAX_CALL_CHAIN_LENGTH` (20) and `MAX_CALL_CHAIN_HEADER_SIZE` (8KB) limits
- New `validate_call_chain_header()` rejects oversized/malformed headers fail-closed
- Prevents CPU exhaustion in privilege-escalation checks
- Prevents memory exhaustion from oversized JSON header values

#### A2A Proxy Security Improvements
- Use shared injection/DLP scanners for consistency with MCP proxy
- Handle `#[non_exhaustive]` Verdict fail-closed (unknown variants → deny)
- Scan data/file/error-data text surfaces for injection

### Fixed

- **Error Handling**: Added logging for previously silent error discards in:
  - Config reload channel send failures
  - Telemetry provider shutdown errors
  - Added TODO documentation for deferred structured content validation
- **Zero unwrap() in library code**: Removed 2 remaining unwrap() calls:
  - `injection.rs`: Replaced with safe if-let in emoji variation selector handling
  - `idempotency.rs`: Replaced builder unwrap() with Response::new() in error fallback

### Security

- **RUSTSEC-2023-0071 (Marvin Attack)**: Switched `jsonwebtoken` from `rust_crypto` to `aws_lc_rs` backend to eliminate timing side-channel vulnerability in RSA PKCS#1 v1.5 decryption. The `rsa` crate (used by `rust_crypto`) was vulnerable to Marvin Attack timing oracle; AWS-LC provides constant-time RSA operations.

---

## [2.2.0] - 2026-02-09

### Changed

- **Dependency cleanup**: Removed `rustls-pemfile` crate, now using `rustls::pki_types::pem::PemObject` trait for PEM parsing
- **JSON-RPC error code consolidation**: Moved hardcoded error codes into `vellaveto-types/src/json_rpc.rs` module with named constants for all standard JSON-RPC 2.0 codes and Vellaveto application-specific codes (-32001 to -32021)
- **OpenTelemetry upgrade**: Upgraded from 0.22 to 0.30, eliminating major dependency duplicates (axum 0.6→0.8, hyper 0.14→1.x, http 0.2→1.x, h2 0.3→0.4, tower 0.4→0.5)
- **Workspace dependency unification**: Unified reqwest to 0.13 as workspace dependency with "json" and "query" features
- **Security manager initialization**: Phase 1-10 security managers (task_state, circuit_breaker, auth_level, deputy, shadow_agent, schema_lineage, sampling_detector, etdi, memory_security, nhi) now properly initialized from PolicyConfig instead of TODO placeholders
- **Crate metadata**: Added description field to all 9 crates that were missing it (vellaveto-types, vellaveto-engine, vellaveto-audit, vellaveto-mcp, vellaveto-canonical, vellaveto-config, vellaveto-approval, vellaveto-proxy, vellaveto-integration)

### Added

- **Bracket notation for parameter paths**: Support `params.items[0].value` syntax in parameter constraints for array element access
- **Evaluation tracing**: Add `?trace=true` query parameter to get full OPA-style decision traces
- **Audit heartbeat entries**: Periodic heartbeat entries for detecting log truncation/deletion attacks
- **DLP observability metrics**: `vellaveto_dlp_findings_total`, `vellaveto_dlp_scan_duration_seconds` histograms
- **Anomaly detection metrics**: `vellaveto_anomaly_detections_total` counter with agent/tool labels
- **Circuit breaker metrics**: `vellaveto_circuit_breaker_state_changes_total`, state duration histograms
- **DlpConfig**: Configurable DLP scanning with `enabled`, `block_on_finding`, `max_decode_depth`, `time_budget_ms`, `extra_patterns`, `disabled_patterns`

### Security

#### DLP Hardening
- **Unicode NFKC Normalization** — DLP scanning now applies NFKC normalization to detect secrets obfuscated with Unicode homoglyphs (e.g., Cyrillic 'а' vs Latin 'a') and fullwidth characters
- **2-Part JWT Detection** — Extended JWT pattern to detect header.payload tokens without signature, which still contain sensitive claims attackers could exfiltrate and re-sign
- **Size Limit Protection** — Added 1MB (`MAX_DLP_STRING_SIZE`) limit to prevent CPU exhaustion from regex scanning very large strings; truncated strings still scanned with warning logged
- **New Tests**: `test_dlp_detects_aws_key_with_fullwidth_unicode`, `test_dlp_detects_jwt_without_signature`

#### Legacy Policy Path Security Fix (P0)
- **Policy Bypass Fix** — Legacy policy evaluation path (`apply_policy`) now enforces `path_rules`, `network_rules`, and `ip_rules` before returning verdicts, matching compiled policy behavior
- **Path Rules Enforcement** — Added `check_path_rules_legacy()` with glob matching, path normalization, and fail-closed behavior for invalid patterns
- **Network Rules Enforcement** — Added `check_network_rules_legacy()` with IDNA normalization and domain pattern matching
- **IP Rules Enforcement** — Added `check_ip_rules_legacy()` with DNS rebinding protection, IPv6 transition mechanism canonicalization, and CIDR enforcement
- **Invalid Glob Handling** — Malformed glob patterns now produce `Deny` verdicts instead of 500 errors (fail-closed)

#### Code Quality Fixes
- **FIND-027** — Eliminated `expect()`/`unwrap()` violations in `vellaveto-mcp` library code per no-panic policy:
  - `cache.rs`: Replaced `expect()` with const `FALLBACK_CACHE_SIZE` and `unwrap_or()`
  - `task_security.rs`: Changed `generate_resume_token` to return `Result`, propagating HMAC and RNG errors
- **FIND-021/FIND-002** — Standardized workspace dependency management:
  - `vellaveto-config`: Use `workspace = true` for serde, serde_json
  - `vellaveto-audit`: Use `workspace = true` for tokio, tracing
  - `vellaveto-proxy`: Use `workspace = true` for tracing

### Added

#### Phase 14: A2A Protocol Security
- **A2A Message Classification** — Parse and classify A2A JSON-RPC messages (message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe) with method normalization to prevent Unicode bypass attacks
- **Action Extraction** — Convert A2A messages to Vellaveto Actions for policy evaluation using tool pattern "a2a" with function-specific mapping (message_send, message_stream, task_get, task_cancel, task_resubscribe)
- **Agent Card Handling** — Fetch, parse, and cache A2A Agent Cards from `/.well-known/agent.json` with TTL-based expiration, capability validation, and authentication scheme detection
- **A2A Proxy Service** — HTTP proxy for A2A traffic with policy evaluation, security scanning integration (DLP, injection detection), circuit breaker support, and configurable task operation restrictions
- **Batch Rejection** — JSON-RPC batch requests rejected at transport layer to prevent TOCTOU attacks (matching MCP security pattern)
- **Security Integration** — Reuse existing security managers (circuit breaker, shadow agent detection, DLP scanning, injection detection) for A2A traffic
- **New Types**: `A2aMessageType`, `TaskState`, `PartContent`, `FileContent`, `MessagePart`, `A2aMessage`, `AgentCard`, `AgentCardCache`, `A2aProxyService`, `A2aProxyConfig`, `A2aProxyDecision`
- **New Config**: `A2aConfig` with upstream URL, listen address, agent card verification, auth method filtering, security feature toggles, message size limits, and task operation restrictions
- **New Errors**: `A2aError` with variants for invalid messages, agent card failures, authentication, task operations, policy denial, security violations, and upstream errors
- **Feature Flag**: `a2a`

#### Phase 13: RAG Poisoning Defense
- **Document Verification** — Trust scoring with age bonuses (+0.1/week, capped at 0.3), admin approval (+0.2), Ed25519 signature verification (+0.2), version stability bonuses, and mutation penalties (-0.3 per change)
- **Document Provenance** — SHA-256 content hashing, version chain tracking, source attribution, and timestamp management for knowledge base documents
- **Retrieval Security** — Inspection of retrieval results with configurable limits, DLP scanning integration, and result filtering for sensitive data
- **Diversity Enforcement** — Jaccard similarity-based duplicate detection to prevent context flooding with near-identical content
- **Embedding Anomaly Detection** — Per-agent baseline tracking with cosine similarity comparison, configurable thresholds, and automatic anomaly flagging
- **Context Budget Enforcement** — Token-based budget tracking per session with per-retrieval limits, total session limits, and configurable enforcement modes (truncate/reject/warn)
- **RagDefenseService** — High-level facade combining document verification, retrieval inspection, embedding anomaly detection, and context budget tracking
- **New Types**: `DocumentMetadata`, `DocumentTrustScore`, `TrustFactor`, `DocumentVerifier`, `RetrievalResult`, `RetrievalInspection`, `RetrievalInspector`, `RagDlpFinding`, `EmbeddingVector`, `EmbeddingBaseline`, `AnomalyDetection`, `EmbeddingAnomalyDetector`, `BudgetUsage`, `BudgetEnforcement`, `ContextBudgetTracker`, `RagDefenseService`
- **New Config**: `RagDefenseConfig` with `DocumentVerificationConfig`, `RetrievalSecurityConfig`, `EmbeddingAnomalyConfig`, `ContextBudgetConfig`
- **New Errors**: `RagDefenseError` with variants for low trust scores, content hash mismatches, retrieval limits, embedding anomalies, budget exceeded, and more
- **Feature Flag**: `rag-defense`

#### Phase 12: Semantic Guardrails (LLM-Based Policy Evaluation)
- **Intent Classification** — Structured taxonomy of action intents (DataRead, DataWrite, SystemExecute, NetworkFetch, CredentialAccess, etc.) with confidence scoring and risk category detection
- **Natural Language Policies** — Define policies in plain English with glob-based tool/function matching, compiled to efficient matchers
- **LLM Evaluator Interface** — Pluggable backend abstraction supporting cloud (OpenAI, Anthropic) and local (GGUF, ONNX) model evaluation
- **Evaluation Caching** — LRU + TTL cache for LLM evaluations to minimize latency and cost on repeated patterns
- **Jailbreak Detection** — LLM-based detection of adversarial prompts resistant to pattern evasion, with configurable thresholds
- **Intent Chain Tracking** — Per-session tracking of action intents to detect suspicious patterns like reconnaissance→exfiltration sequences
- **SemanticGuardrailsService** — High-level service combining evaluator, cache, intent tracking, and NL policies
- **Mock Backend** — Configurable mock implementation for testing with pattern-based response rules and simulated latency
- **New Types**: `Intent`, `IntentClassification`, `IntentChain`, `RiskCategory`, `SuspiciousPattern`, `LlmEvalInput`, `LlmEvaluation`, `LlmEvaluator`, `NlPolicy`, `NlPolicyCompiler`, `JailbreakDetection`, `FallbackBehavior`
- **New Config**: `SemanticGuardrailsConfig` with OpenAI/Anthropic backend configs, intent classification settings, jailbreak detection thresholds, cache TTL, and fallback behavior
- **Feature Flag**: `semantic-guardrails` (core), `llm-cloud` (OpenAI/Anthropic), `llm-local-gguf`, `llm-local-onnx`

#### Phase 11: MCP Tasks Primitive Security
- **Task State Encryption** — ChaCha20-Poly1305 AEAD encryption for task state data, protecting sensitive information at rest
- **Resume Token Authentication** — HMAC-SHA256 tokens for authenticated task resumption, preventing unauthorized access to long-running tasks
- **Hash Chain Integrity** — SHA-256 hash chain tracking all state transitions with sequence numbers, timestamps, and agent IDs for tamper detection
- **Checkpoint Verification** — Ed25519 signed checkpoints of task state for non-repudiation and point-in-time verification
- **Replay Protection** — Nonce-based anti-replay with configurable FIFO eviction (default 1000 nonces per task)
- **SecureTaskManager** — New manager combining encryption, integrity, and authentication for MCP Tasks primitive
- **New Types**: `SecureTask`, `TaskStateTransition`, `TaskCheckpoint`, `TaskResumeRequest`, `TaskResumeResult`, `TaskIntegrityResult`, `SecureTaskStats`
- **New Config**: Extended `AsyncTaskConfig` with `encrypt_state`, `enable_hash_chain`, `require_resume_token`, `replay_protection`, `max_nonces`, `enable_checkpoints`, `checkpoint_interval`, `task_retention_secs`

#### Phase 10: NHI (Non-Human Identity) Lifecycle Management
- **Agent Identity Registration** — Multiple attestation types (JWT, mTLS, SPIFFE, DPoP, API key) with configurable TTL, public key binding, and metadata tags
- **Identity Lifecycle States** — Full lifecycle management: Probationary → Active → Suspended → Revoked → Expired with automatic status transitions
- **Behavioral Attestation** — Continuous authentication via behavioral baselines using Welford's online variance algorithm for request intervals, tool call patterns, and source IP tracking
- **Anomaly Detection** — Configurable anomaly thresholds with recommendations (Allow, AllowWithLogging, StepUpAuth, Suspend, Revoke) based on deviation severity
- **Delegation Chains** — Agent-to-agent permission delegation with scope constraints, depth limits, and chain resolution for accountability tracking
- **Credential Rotation** — Automatic credential lifecycle with expiration warnings, rotation history, and thumbprint tracking
- **DPoP Support** — RFC 9449 Demonstration of Proof-of-Possession with nonce generation, replay prevention, and access token hash binding
- **NHI API Endpoints**:
  - `GET/POST /api/nhi/agents` — List and register agent identities
  - `GET/DELETE /api/nhi/agents/{id}` — Get or revoke agent identity
  - `POST /api/nhi/agents/{id}/activate` — Activate probationary identity
  - `POST /api/nhi/agents/{id}/suspend` — Suspend active identity
  - `GET /api/nhi/agents/{id}/baseline` — Get behavioral baseline
  - `POST /api/nhi/agents/{id}/check` — Check behavior against baseline
  - `GET/POST /api/nhi/delegations` — List and create delegations
  - `GET/DELETE /api/nhi/delegations/{from}/{to}` — Get or revoke delegation
  - `GET /api/nhi/delegations/{id}/chain` — Resolve full delegation chain
  - `POST /api/nhi/agents/{id}/rotate` — Rotate credentials
  - `GET /api/nhi/expiring` — Get identities expiring soon
  - `POST /api/nhi/dpop/nonce` — Generate DPoP nonce
  - `GET /api/nhi/stats` — NHI statistics
- **New Types**: `NhiAgentIdentity`, `NhiIdentityStatus`, `NhiAttestationType`, `NhiBehavioralBaseline`, `NhiBehavioralCheckResult`, `NhiBehavioralDeviation`, `NhiBehavioralRecommendation`, `NhiDelegationLink`, `NhiDelegationChain`, `NhiDpopProof`, `NhiDpopVerificationResult`, `NhiCredentialRotation`, `NhiStats`
- **New Config**: `NhiConfig`, `DpopConfig` with comprehensive defaults for credential TTL, attestation types, anomaly thresholds, delegation limits, and rotation warnings

#### Phase 9: MINJA (Memory Injection Defense)
- **Taint Propagation** — Data from untrusted sources tagged with taint labels (`UserInput`, `ExternalApi`, `AgentOutput`, `DerivedData`, `Sanitized`) that propagate to derived data automatically
- **Provenance Graph** — DAG tracking data lineage with FIFO eviction, detects suspicious patterns (notification→replay chains, feedback loops, data laundering)
- **Trust Decay** — Exponential decay with configurable λ (default 0.029 for 24-hour half-life), time-based trust erosion for stale data
- **Quarantine Management** — Automatic quarantine on injection detection, manual quarantine/release via API, detection metadata tracking
- **Namespace Isolation** — Per-agent namespaces with configurable isolation levels:
  - `Session` — Data isolated per session
  - `Agent` — Data isolated per agent identity
  - `Shared` — Explicit sharing with approval
- **Sharing Approval** — Cross-namespace data sharing requires explicit approval with access type specification (Read/Write/Admin)
- **Memory Security API Endpoints**:
  - `GET /api/memory/entries` — List memory entries with taint filtering
  - `GET /api/memory/entries/{id}` — Get memory entry details
  - `GET /api/memory/entries/{id}/provenance` — Get provenance chain for entry
  - `POST /api/memory/quarantine/{id}` — Quarantine a memory entry
  - `DELETE /api/memory/quarantine/{id}` — Release entry from quarantine
  - `GET /api/memory/quarantine` — List quarantined entries
  - `GET /api/memory/namespaces` — List namespaces
  - `POST /api/memory/namespaces/{ns}/share` — Request namespace sharing
  - `POST /api/memory/namespaces/{ns}/share/approve` — Approve sharing request
  - `GET /api/memory/stats` — Get memory security statistics
- **New Types**: `TaintLabel`, `MemoryEntry`, `ProvenanceNode`, `ProvenanceEventType`, `QuarantineEntry`, `QuarantineDetection`, `MemoryNamespace`, `NamespaceIsolation`, `MemoryAccessDecision`, `NamespaceSharingRequest`, `NamespaceAccessType`, `MemorySecurityStats`
- **New Config**: `MemorySecurityConfig`, `NamespaceConfig` with decay λ, max provenance depth, quarantine policies

#### Phase 8: ETDI Cryptographic Tool Security
- **Tool Signature Verification** — Ed25519/ECDSA P-256 cryptographic signing of tool definitions with trusted signer allowlists (fingerprints + SPIFFE IDs) and expiration support
- **Attestation Chain** — Provenance tracking for tool definitions with initial registration, version updates, and chain integrity verification
- **Version Pinning** — Semantic versioning constraints (`^1.0.0`, `~2.1.0`, exact) with hash-based drift detection for rug-pull prevention
- **ETDI Store** — Persistent storage for signatures, attestations, and pins with optional HMAC integrity protection
- **ETDI API Endpoints**:
  - `GET /api/etdi/signatures` — List all tool signatures
  - `GET /api/etdi/signatures/{tool}` — Get signature for a tool
  - `POST /api/etdi/signatures/{tool}/verify` — Verify tool signature
  - `GET /api/etdi/attestations` — List all attestations
  - `GET /api/etdi/attestations/{tool}` — Get attestation chain for a tool
  - `GET /api/etdi/attestations/{tool}/verify` — Verify attestation chain integrity
  - `GET/POST/DELETE /api/etdi/pins/{tool}` — Manage version pins
- **Tool Registry Integration** — Signature verification on tool registration with configurable `require_signatures` mode for fail-closed enforcement
- **ETDI CLI Commands**:
  - `vellaveto generate-key` — Generate Ed25519 keypair for tool signing
  - `vellaveto sign-tool` — Sign a tool definition with expiration support
  - `vellaveto verify-signature` — Verify a tool signature against its definition

### Security

- **R33-001**: Add monotonic sequence counter to audit hash chain to prevent collision attacks under high load
- **R33-002**: Add per-line size limits (64KB checkpoints, 1MB audit entries) to prevent memory exhaustion attacks
- **R33-003**: Use safe string slicing with char-based truncation to prevent UTF-8 boundary panics
- **R33-004**: Increase injection detection depth from 10 to 32 levels for deeply nested payloads
- **R33-005**: Add triple-encoding detection layers (6-8) to DLP for double-base64 and mixed encoding evasion
- **R33-006**: Store actual schema content for real field-level diff detection in schema poisoning

### Changed

- Security audit rounds: 34 → 35
- Test suite: 3,343 → 3,643 tests

### Documentation

- **ROADMAP.md**: Added v2.1 and v2.2 roadmap based on security research
  - Phase 8: ETDI Cryptographic Tool Security
  - Phase 9: Memory Injection Defense (MINJA)
  - Phase 10: Non-Human Identity (NHI) Lifecycle
  - Phase 11: MCP Tasks Primitive
  - Phase 12: Semantic Guardrails (LLM-based)
  - Phase 13: RAG Poisoning Defense
  - Phase 14: A2A Protocol Security
  - Phase 15: Observability Platform Integration
- Updated gap analysis vs competitor landscape (NeMo Guardrails, Guardrails AI, Zenity, Prisma AIRS)
- Added research bibliography with 10 academic/industry references

---

## [2.0.0] - 2026-02-08

### Added

#### Phase 6: Observability & Tooling
- **Execution Graph Data Model** — Comprehensive call chain visualization with `ExecutionNode` (tool, function, verdict, timing, depth), `ExecutionEdge` (call/data-flow/delegation edges), and `ExecutionGraph` (session-scoped graphs with metadata)
- **Execution Graph Store** — In-memory store with configurable max graphs and age limits, session-based lookup, node lifecycle tracking (add, complete), and automatic cleanup
- **Graph Export Formats** — DOT (Graphviz) and JSON export with color-coded verdicts (green=allow, red=deny), edge styling by type, and full graph statistics
- **Graph Export API** — RESTful endpoints for graph management:
  - `GET /api/graphs` — List sessions with pagination and tool filtering
  - `GET /api/graphs/{session}` — Get graph in JSON format
  - `GET /api/graphs/{session}/dot` — Get graph in DOT (Graphviz) format
  - `GET /api/graphs/{session}/stats` — Get graph statistics (node count, depths, tool distribution)
- **Policy Validation CLI** — Enhanced `vellaveto check` command with:
  - `--strict` mode (warnings become errors)
  - `--format json|text` output format
  - `--no-best-practices` to skip best practice checks
  - `--no-security-checks` to skip security checks
  - Shadow policy, wide pattern, and dangerous configuration detection
- **Attack Simulation Framework** — Automated red-teaming based on OWASP ASI Top 10 and MCPTox benchmarks:
  - 10 attack categories (Prompt Injection, Data Disclosure, Sandboxing, etc.)
  - 40+ built-in attack payloads with severity ratings
  - Multi-step attack sequences, schema mutations, parameter manipulation
  - Result summarization by category and severity
  - JSON import/export for custom scenarios

#### Phase 5.5: Enterprise Hardening (Runtime)
- **TLS/mTLS Runtime** — TLS termination via tokio-rustls with client certificate extraction, SPIFFE identity parsing from X.509 SAN URIs, and configurable TLS/mTLS modes
- **OPA Client Runtime** — Async HTTP client for Open Policy Agent with LRU decision caching (configurable TTL), fail-open/fail-closed modes, and structured decision parsing
- **Threat Intelligence Runtime** — Full TAXII 2.1 (STIX format) and MISP client implementations with custom REST endpoint support, confidence filtering, and configurable actions on IOC match
- **JIT Access Runtime** — Session-based temporary elevated permissions with approval workflows, per-principal session limits, auto-revocation on security alerts, and permission/tool access checking

#### Phase 5: Enterprise Hardening (Configuration)
- **TLS/mTLS Configuration** — Server-side TLS and mutual TLS support with configurable cert paths, client CA verification, CRL/OCSP revocation checking, minimum TLS version, and cipher suite selection
- **SPIFFE/SPIRE Integration** — Zero-trust workload identity configuration with trust domain, workload API socket, allowed SPIFFE IDs allowlist, and ID-to-role mapping for RBAC
- **OPA Integration** — Open Policy Agent configuration for external policy evaluation with endpoint URL, decision path, caching (TTL), timeout, fail-open/closed mode, and local bundle support
- **Threat Intelligence Feeds** — Configuration for TAXII, MISP, and custom threat intelligence providers with IOC type filtering, confidence thresholds, refresh intervals, and configurable actions (deny/alert/require_approval)
- **Just-In-Time Access** — Temporary elevated permissions with configurable TTL, max sessions per principal, approval requirements, automatic revocation on security events, and notification webhooks

#### Phase 4.1: Standards Alignment
- **MITRE ATLAS Threat Mapping** — Registry of 14 ATLAS techniques (AML.T0051-T0065) with detection mappings for 30+ Vellaveto detection types, coverage reports, and audit event enrichment
- **OWASP AIVSS Integration** — AI Vulnerability Scoring System with CVSS-style base scores plus AI-specific multipliers (autonomy, persistence, reversibility), severity levels (None/Low/Medium/High/Critical), vector string parsing, and predefined profiles for common detections
- **NIST AI RMF Alignment** — Complete mapping to all 4 RMF functions (Govern, Map, Measure, Manage) with 25+ subcategory mappings, coverage statistics, compliance reports, and audit metadata enrichment
- **ISO/IEC 27090 Preparation** — Readiness assessment for 5 control domains (Data Security, Model Security, Operational Security, Supply Chain Security, Privacy & Ethics), gap analysis, recommendations engine, and certification readiness scoring

#### Phase 3.3: Advanced Threat Detection
- **Goal State Tracking** (ASI01) — Detects objective drift mid-session with similarity-based alignment checks, manipulation keyword detection, and configurable drift thresholds
- **Workflow Intent Tracking** — Long-horizon attack detection with step budget enforcement, cumulative effect analysis, and suspicious exfiltration pattern detection
- **Tool Namespace Security** (ASI03) — Prevents tool shadowing attacks via Levenshtein distance typosquatting detection, protected name patterns, and collision detection (exact, similar, version, trust)
- **Output Security Analysis** (ASI07) — Covert channel detection including steganography (zero-width chars, homoglyphs, invisible Unicode), Shannon entropy analysis, and output normalization
- **Token Security Analysis** — Token-level attack detection including special token injection (`<|endoftext|>`, etc.), context flooding/budget tracking, glitch token patterns (SolidGoldMagikarp, etc.), and Unicode normalization attacks
- **AdvancedThreatConfig** — Configuration for all advanced threat detection features with goal drift threshold, workflow step budget, context budget, and protected tool patterns

#### Phase 3.2: Cross-Agent Security
- **Agent Trust Graph** — Multi-agent trust relationship tracking with privilege levels (None, Basic, Standard, Elevated, Admin), delegation chain validation, and escalation detection
- **Inter-Agent Message Signing** — Ed25519 signed message envelopes with nonce-based anti-replay protection for secure inter-agent communication
- **Privilege Escalation Detector** — Second-order prompt injection detection with configurable thresholds, Unicode manipulation checks, delimiter injection detection, and suspicious agent pair tracking
- **CrossAgentConfig** — Configuration for cross-agent security features including message signing requirements, chain depth limits, trusted agents, nonce expiry, and escalation thresholds

#### Phase 3.1: Runtime Integration for Security Managers
- **Admin API endpoints** for all Phase 1 & 2 security managers:
  - Circuit breaker: `GET/POST /api/circuit-breaker/*` (list, stats, get state, reset)
  - Shadow agent: `GET/POST/PUT/DELETE /api/shadow-agents/*` (list, register, update trust)
  - Schema lineage: `GET/PUT/DELETE /api/schema-lineage/*` (list, get, reset trust, remove)
  - Task state: `GET/POST /api/tasks/*` (list, stats, get, cancel)
  - Auth level: `GET/POST/DELETE /api/auth-levels/*` (get, upgrade, clear)
  - Sampling detection: `GET/POST /api/sampling/*` (stats, reset)
  - Deputy validation: `GET/POST/DELETE /api/deputy/delegations/*` (list, register, remove)
- **Audit event helpers** for security events:
  - `log_circuit_breaker_event` - tracks open/closed/half-open/rejected states
  - `log_deputy_event` - tracks delegation and validation failures
  - `log_shadow_agent_event` - tracks agent impersonation detection
  - `log_schema_event` - tracks schema poisoning alerts
  - `log_task_event` - tracks async task lifecycle
  - `log_auth_event` - tracks step-up authentication
  - `log_sampling_event` - tracks sampling request denials
- **HTTP proxy integration** with circuit breaker check before forwarding tool calls
- Security managers integrated into ProxyBridge and AppState for runtime enforcement

#### Phase 2: Advanced Threat Detection (OWASP ASI Top 10)
- **Circuit Breaker** (ASI08) — Cascading failure prevention with configurable thresholds
- **Confused Deputy Prevention** (ASI02) — Delegation chain validation with depth limits
- **Shadow Agent Detection** — Agent fingerprinting and impersonation alerts
- **Schema Poisoning Detection** (ASI05) — Schema lineage tracking with mutation thresholds
- **Sampling Attack Detection** — Rate limiting and content inspection for sampling requests

#### Phase 1: MCP 2025-11-25 Compliance
- **Async Tasks Security** — Task state manager with lifecycle tracking
- **OAuth Resource Indicators** — RFC 8707 parsing and validation
- **CIMD** — Capability-indexed message dispatch routing
- **Step-Up Authentication** — Auth level tracking with upgrade flow

### Security
- Fix timing side-channel in CORS origin validation (R33-001) - origin matching now checks all configured origins to prevent timing-based enumeration

### Changed
- Security audit rounds: 32 → 33

---

## [1.0.0] - 2026-02-08

Initial production release of Vellaveto, a runtime security engine for AI agent tool calls.

### Core Features

#### Policy Engine
- Glob and regex-based policy matching for tools and functions
- Parameter constraint evaluation with multiple operators (glob, regex, domain_match, domain_in, domain_not_in)
- Priority-based policy ordering with deterministic evaluation
- Path traversal-safe normalization for filesystem rules
- RFC 1035-compliant domain validation for network rules
- Context-aware policies with time windows, call limits, and action sequences

#### Network Security
- DNS rebinding protection with private IP blocking
- CIDR-based allow/block lists for resolved IPs
- Domain allowlisting and blocklisting
- Carrier-grade NAT (100.64.0.0/10) blocking

#### Authentication & Authorization
- API key authentication for admin endpoints
- OAuth 2.1 / JWT support with JWKS validation
- Role-based access control (RBAC) with Admin, Operator, Auditor, and Viewer roles
- Agent identity attestation via signed JWTs
- Per-endpoint and per-principal rate limiting

#### Audit System
- Tamper-evident audit logging with SHA-256 hash chain
- Ed25519 signed checkpoints for integrity verification
- Configurable PII redaction (Off, Low, High)
- Audit log rotation support
- Multiple export formats: JSON Lines, CEF, syslog (RFC 5424)
- SIEM integrations: Splunk HEC, Datadog, Elasticsearch, webhook

#### Human-in-the-Loop Approvals
- Approval queue for dangerous operations
- Deduplication of pending approvals
- Full audit trail for approval decisions
- Configurable approval timeouts

#### Detection & Prevention
- Prompt injection scanning with Aho-Corasick pattern matching
- Unicode NFKC normalization for homoglyph attack prevention
- Semantic injection detection via n-gram TF-IDF similarity
- Data Loss Prevention (DLP) with 5-layer decode pipeline (raw, base64, percent, combinations)
- Rug-pull detection for tool schema changes
- Tool squatting detection via Levenshtein distance + homoglyph analysis
- Memory poisoning defense with cross-request data tracking
- Behavioral anomaly detection using EMA-based frequency tracking

#### Multi-Tenancy
- Tenant isolation for policy, audit, and approval data
- Tenant extraction from JWT claims, headers, or subdomains
- Per-tenant quotas and rate limiting
- Tenant management API endpoints

#### Observability
- Prometheus metrics endpoint with 24+ metrics
- OpenTelemetry instrumentation for distributed tracing
- Health and readiness endpoints
- Admin dashboard with server-rendered HTML

### Deployment

#### Docker
- Multi-stage Dockerfile for optimized builds
- Static musl-linked binaries (<50MB images)
- Non-root user execution
- Health checks included

#### Kubernetes
- Helm chart with comprehensive values.yaml
- Horizontal Pod Autoscaler support
- Ingress configuration
- Security contexts and pod disruption budgets

#### Clustering
- Redis backend for distributed state
- Shared approval state across instances
- Global rate limiting

### Security Hardening

- Fail-closed design: errors, missing policies, and unresolved context produce Deny
- Zero `unwrap()` in library code
- Constant-time API key comparison
- CSRF defense-in-depth via Origin/Referer validation
- Idempotency keys for at-most-once semantics
- 1MB request body limit
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
- CORS configuration
- 33 rounds of adversarial security audits

### Testing

- 3,167 tests across all crates
- Property-based testing with proptest
- Fuzz targets for:
  - JSON-RPC framing
  - Path normalization
  - Domain extraction
  - CIDR parsing
  - Message classification
  - Parameter scanning
  - Semantic similarity
- Criterion benchmarks for performance-critical paths
- Integration tests for OWASP MCP Top 10

### Documentation

- Comprehensive deployment guide (Docker, Kubernetes, bare metal)
- Operations runbook with troubleshooting procedures
- Security hardening guide
- Complete API reference
- Production configuration examples

### Breaking Changes from 0.x

This is the initial stable release. No breaking changes from previous versions.

---

## [0.1.0] - 2026-01-15

### Added
- Initial development release
- Core policy engine with basic glob matching
- Simple audit logging
- HTTP API server
- Stdio proxy mode
- Basic DLP scanning

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

[Unreleased]: https://github.com/paolovella/vellaveto/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/paolovella/vellaveto/compare/v2.2.1...v3.0.0
[2.2.1]: https://github.com/paolovella/vellaveto/compare/v2.0.0...v2.2.1
[2.0.0]: https://github.com/paolovella/vellaveto/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/paolovella/vellaveto/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/paolovella/vellaveto/releases/tag/v0.1.0
