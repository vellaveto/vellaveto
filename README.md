<p align="center">
  <h1 align="center">🛡️ Vellaveto</h1>
  <p align="center">
    <strong>Runtime security engine for AI agent tool calls</strong>
  </p>
  <p align="center">
    🔍 Intercept &middot; ⚖️ Evaluate &middot; 🚫 Enforce &middot; 📋 Audit
  </p>
  <p align="center">
    <a href="https://github.com/paolovella/vellaveto/releases"><img src="https://img.shields.io/badge/version-4.0.0--dev-blue.svg" alt="Version 4.0.0-dev"></a>
    <a href="https://github.com/paolovella/vellaveto/actions/workflows/ci.yml"><img src="https://github.com/paolovella/vellaveto/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
    <a href="https://github.com/paolovella/vellaveto/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-2021_edition-orange.svg" alt="Rust 2021"></a>
    <img src="https://img.shields.io/badge/tests-6%2C501_passing-brightgreen.svg" alt="Tests: 6,501 passing">
    <img src="https://img.shields.io/badge/clippy-zero_warnings-brightgreen.svg" alt="Clippy: zero warnings">
    <a href="audits/README.md"><img src="https://img.shields.io/badge/adversarial_testing-48_rounds%2C_400%2B_findings-informational.svg" alt="Adversarial Testing: 48 rounds, 400+ findings"></a>
    <a href="https://modelcontextprotocol.io/specification/2025-11-25"><img src="https://img.shields.io/badge/MCP-2025--11--25-blueviolet.svg" alt="MCP 2025-11-25"></a>
    <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"><img src="https://img.shields.io/badge/OWASP-Agentic_Top_10-red.svg" alt="OWASP Agentic Top 10"></a>
  </p>
  <p align="center">
    <a href="#-quick-start">Quick Start</a> &middot;
    <a href="#-features">Features</a> &middot;
    <a href="#-deployment-modes">Deployment</a> &middot;
    <a href="#-http-api-reference">API</a> &middot;
    <a href="#-audit-system">Audit</a> &middot;
    <a href="#-security-properties">Security</a> &middot;
    <a href="#-documentation">Docs</a>
  </p>
</p>

---

Vellaveto is a lightweight, high-performance firewall that sits between AI agents and their tools. It intercepts [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) and function-calling requests, enforces security policies on paths, domains, and actions, and maintains a [tamper-evident audit trail](docs/SECURITY_GUARANTEES.md#g3-audit-integrity-tamper-detection) with SHA-256 hash chains and Ed25519 checkpoint signatures. See [Security Guarantees](docs/SECURITY_GUARANTEES.md) for the full normative contract and [Assurance Case](docs/ASSURANCE_CASE.md) for the Claim → Evidence map.

## Core Guarantees

- **Complete mediation**: request and response paths are evaluated before tool execution and before model return.
- **Fail-closed policy decisions**: no policy match, missing context, or evaluation error results in `Deny`.
- **Tamper-evident audit trail**: SHA-256 hash chain + signed checkpoints with verification endpoints and CLI flows.
- **Public security contract**: [Security Guarantees](docs/SECURITY_GUARANTEES.md) + [Assurance Case](docs/ASSURANCE_CASE.md) with reproducible evidence.

<table>
<tr><td>🏷️ <strong>Version</strong></td><td>4.0.0-dev</td></tr>
<tr><td>🦀 <strong>Language</strong></td><td>Rust</td></tr>
<tr><td>✅ <strong>Test suite</strong></td><td>6,501+ tests, 0 failures, 0 warnings</td></tr>
<tr><td>⚡ <strong>Evaluation latency</strong></td><td>&lt;5ms P99</td></tr>
<tr><td>💾 <strong>Memory baseline</strong></td><td>&lt;50MB</td></tr>
<tr><td>🔌 <strong>MCP version</strong></td><td>2025-11-25 (backwards compatible with 2025-06-18 and 2025-03-26)</td></tr>
<tr><td>📄 <strong>License</strong></td><td>AGPL-3.0 (dual license available)</td></tr>
</table>

## Recent Updates (2026-02-19)

- **Feb 19 Hardening Follow-up** — Configuration loading is now explicitly fail-closed: `PolicyConfig::load_file` rejects empty/whitespace-only files and enforces supported extensions (`.toml`, `.json`). Config validation coverage was expanded with stricter bounds/control-character checks for A2A, cluster, semantic templates, cross-agent trusted IDs, memory-security limits, and schema-poisoning observation thresholds. Integration tests that bind local sockets now skip only on `PermissionDenied` in restricted sandboxes and still panic on unexpected bind failures.
- **Phase 38: SOC 2 Type II Access Review Reports** — Dynamic report generation scanning audit entries and cross-referencing with least-agency data to produce CC6-focused access review reports. 7 new types (`AttestationStatus`, `ReviewerAttestation`, `AccessReviewEntry`, `Cc6Evidence`, `AccessReviewReport`, `ReviewSchedule`, `ReportExportFormat`), `Soc2AccessReviewConfig` with scheduled generation (Daily/Weekly/Monthly), `GET /api/compliance/soc2/access-review` (JSON/HTML output), HTML renderer with escaped user data, SDK methods in Python/TypeScript/Go. ~75 new tests. 6,103 Rust + 298 Python + 64 TypeScript + 40 Go tests passing.
- **Round 47 Adversarial Audit** — Full-codebase gap analysis: 67 findings identified and ALL resolved (3 P0, 12 P1, 30 P2, 22 P3). P0: unbounded intent_chains capped, SDK payload format mismatch fixed, async response body size limit. P1: ZK witness restore-on-failure, ES retry/partial failure detection, ABAC CompiledPathMatcher, MINJA trust decay fail-closed, SDK approval paths/evaluate/ZK methods. P2/P3: ABAC IDNA normalization, RwLock poison recovery, max_calls_in_window overflow error, validate_finite for 5 types, Policy/UpstreamBackend validation, webhook/streaming URL scheme validation, redaction fail-closed at max depth, ZK scheduler backoff, MAX_COMPILED_POLICIES 10K, serialization errors return HTTP 500, MAX_DASHBOARD_AUDIT_ENTRIES 1K, MAX_DISCOVERED_TOOLS_PER_SESSION 10K, proxy env clearing. 6,103 Rust + 298 Python + 64 TypeScript + 40 Go tests passing.
- **Round 46 Adversarial Audit** — Full-codebase adversarial audit with ~177 findings resolved (21 P1, 66 P2, ~90 P3). Fail-closed defaults hardened across ToolSensitivity (Low→High), NhiIdentityStatus (Active→Probationary), ABAC NotIn (fail-open→fail-closed). MemoryEntry trust/taint consistency (Untrusted entries start at 0.5 trust). `deny_unknown_fields` on security-critical serde structs. Relay channel bounds (256→64, 4MB message limit). Merkle rotation and verification hardened. SDK hardening: API key redaction in `__repr__`/error messages, exponential retry backoff, input validation, thread-safe call chains, circular reference protection in scanner, `VellavetoConnectionError` (no stdlib shadow), baseUrl validation, Action.Validate(). Config: pattern length limits (4096), empty pattern rejection, unknown extension errors, batch_size>0 validation. Server: JSON depth validation (max 32), token budget cap (1M), audit error logging. 6,042 Rust + 288 Python + 34 TypeScript + 33 Go tests passing.
- **Codebase Improvement Campaign** — 6-phase quality and hardening sweep: ~165 new engine/relay/audit unit tests (engine 687, MCP 1,083, audit 441), 14 Criterion benchmarks (ABAC evaluation, Merkle proofs, injection/DLP long text, E2E pipeline), TLA+ RequireApproval invariant S7 + VERIFIED source markers linking to 8 formal properties, 4 new CI jobs (cargo-vet supply chain audit, cargo-semver-checks, MSRV 1.75.0 enforcement, feature flag matrix). Relay security hardening: `VELLAVETO_AGENT_ID` env var for stdio proxy, channel buffer bounds (64 slots, 4MB message limit).
- **Phase 37: Zero-Knowledge Audit Trails** — Two-tier privacy-preserving audit: inline Pedersen commitments (~50µs per entry via `curve25519-dalek` Ristretto) for cryptographic binding without revealing entry contents, plus offline Groth16 batch proofs (`ark-groth16`/`ark-bn254`) proving hash-chain and Merkle tree correctness over groups of entries. `PedersenCommitter` with domain-separated generators (G, H), `WitnessStore` with bounded capacity, `AuditChainCircuit` (R1CS constraints for hash-chain + commitment verification), `ZkBatchProver` (trusted setup, prove, verify with key serialization), `ZkBatchScheduler` (async batch loop with size/interval triggers and graceful shutdown). `ZkAuditConfig` with validation (batch_size 10–10,000, key path validation). REST API: `GET /api/zk-audit/status`, `GET /api/zk-audit/proofs` (paginated), `POST /api/zk-audit/verify`, `GET /api/zk-audit/commitments` (range-bounded). Python SDK methods (sync+async): `zk_status()`, `zk_proofs()`, `zk_verify()`, `zk_commitments()`. Feature-gated behind `zk-audit`. ~190 new tests.
- **Phase 35: Model Projector** — Model-agnostic tool schema projection across 5 LLM families (Claude, OpenAI, DeepSeek, Qwen, Generic). `ModelProjection` trait with `ProjectorRegistry` for schema transformation, call parsing, and response formatting. `SchemaCompressor` with 5 progressive strategies reduces token cost (strip root type, inline enums, truncate descriptions, collapse objects, remove optional descriptions). `CallRepairer` fixes malformed tool calls via type coercion, default injection, Levenshtein fuzzy matching, and DeepSeek markdown extraction. REST API: `GET /api/projector/models`, `POST /api/projector/transform`. Feature-gated behind `projector`. ~230 new tests.
- **Phase 34: Tool Discovery Service** — Pure Rust TF-IDF inverted index for natural language tool search across MCP servers (zero new dependencies). `DiscoveryEngine` with cosine similarity scoring, policy filtering, and token budget enforcement. Session-scoped TTL lifecycle for discovered tools (record, expire, evict, re-discover). REST API: `POST /api/discovery/search`, `GET /api/discovery/index/stats`, `POST /api/discovery/reindex`, `GET /api/discovery/tools`. SDK methods in Python, TypeScript, and Go. Feature-gated behind `discovery`. ~260 new tests.
- **Phase 29: Cross-Transport Smart Fallback** — Ordered transport fallback chain (gRPC → WebSocket → HTTP → stdio) with per-transport circuit breakers. When an upstream transport fails, the proxy automatically tries the next transport in priority order. Per-tool glob-based transport overrides, client preference header support, and full audit trail of fallback negotiations. Default off (`cross_transport_fallback: false`) for backward compatibility. Fail-closed: all transports failed → deny. 71 new tests.
- **Phase 28: Distributed Tracing & Observability** — W3C Trace Context (`traceparent`/`tracestate`) propagation across all four transports (HTTP, WebSocket, gRPC, A2A). `TraceContext` parsing, child span generation, and upstream header injection with <200ns overhead. Gateway mode creates per-backend child spans for multi-backend trace correlation. GenAI semantic convention attributes (`gen_ai.agent.id`) on security spans. Vellaveto verdict injected into `tracestate` for cross-service observability. Fail-open for tracing (missing context generates a new trace). `SpanKind::Gateway` for gateway-specific spans. Compatible with Jaeger, Grafana Tempo, Datadog, and any OTLP collector.
- **Phase 27: Kubernetes-Native Deployment** — `LeaderElection` trait with `LocalLeaderElection` (always-leader standalone mode) for single-instance deployments. `ServiceDiscovery` trait with `StaticServiceDiscovery` (explicit endpoint list) and `DnsServiceDiscovery` (tokio `lookup_host` with periodic refresh). `DeploymentConfig` with mode/leader-election/service-discovery/instance-id validation. `GET /api/deployment/info` endpoint. Health endpoint extended with `leader_status`, `instance_id`, and `discovered_endpoints`. Helm chart v4.0.0 with StatefulSet, PVC for audit persistence, init container, log-shipping sidecar, headless Service, and gRPC/WebSocket port support. Audit event helpers for leader election and service discovery lifecycle events. ~45 new tests.
- **Phase 26: Shadow AI Detection & Governance Visibility** — Detects unauthorized ("shadow") AI tool usage across the organization, surfaces unregistered tool invocations, enforces governance policies on unsanctioned agents, and provides visibility dashboards for security and compliance teams. Integrates with the existing audit trail and compliance registries for centralized governance reporting.
- **Phase 25.1/25.2: Audio & Video Metadata Inspection** — Pure-Rust parsers for WAV (RIFF/LIST/INFO), MP3 (ID3v2 with syncsafe integers, 4 text encodings), MP4 (ISO BMFF moov/udta/meta/ilst), and WebM (EBML/Matroska tags). Extracted text feeds into the existing injection detection pipeline. FLAC, OGG, and AVI magic bytes detection. All parsers bounded (max iterations, max aggregate text, max nesting depth). 27 new tests.
- **Phase 25.6: Stateless Protocol Abstraction** — `RequestContext` trait abstracts session state access for policy evaluation, enabling both stateful (current) and stateless HTTP modes (future MCP June 2026). `StatefulContext` wraps `SessionState` for zero-cost migration. `StatelessContextBlob` defines the signed per-request context format with HMAC-SHA256 verification and 5-minute expiry. 8 new tests.
- **Phase 24: EU AI Act Final Compliance** — Closes the two remaining EU AI Act gaps before the August 2, 2026 enforcement deadline:
  - **Art 50(2) — Automated decision explanations**: `VerdictExplanation` transforms `EvaluationTrace` into consumer-facing explanations at configurable verbosity (`None`, `Summary`, `Full`). Injected into `_meta.vellaveto_decision_explanation` on JSON-RPC responses via the proxy bridge. New `ExplanationVerbosity` config field on `EuAiActConfig`.
  - **Art 10 — Data governance record keeping**: `DataGovernanceRegistry` with tool-to-classification mappings (`DataClassification`: Training, Input, Output, Testing, Operational, Personal, NonPersonal), `ProcessingPurpose` tracking, provenance strings, and configurable retention. `GET /api/compliance/data-governance` endpoint. Default mappings for filesystem, database, HTTP, and vellaveto tool patterns.
  - Both Art 50(2) and Art 10 now report `ComplianceStatus::Compliant`. 45 new tests.
- **Go SDK** — Zero-dependency Go client (`sdk/go/`) with full API parity (12 methods), functional options, `context.Context` on all methods, fail-closed verdict parsing (unknown → Deny), 28 table-driven tests using `httptest`. Go 1.21+.
- **HTTP Proxy Benchmarks** — 35 Criterion benchmarks for the production hot path (`vellaveto-http-proxy/benches/http_proxy.rs`): origin validation (<440ns), HMAC signing/verification (<1.6µs), call chain parsing (<3.8µs), privilege escalation detection (<76ns), audit context building (<1.1µs).
- **Phase 17 Complete** — All 6 exit criteria delivered. Phase 17.3 (Async Operations) adds TaskRequest policy enforcement across all 4 transports (HTTP, WebSocket, gRPC, stdio) with fail-closed semantics, `ProgressNotification` classification for `notifications/progress`. Phase 17.4 (Protocol Extensions) adds `ExtensionHandler` trait with lifecycle hooks, `ExtensionRegistry` with thread-safe registration and glob-based negotiation, `x-` prefix method routing through policy evaluation, and `AuditQueryExtension` example handling `x-vellaveto-audit/stats`. 50+ new tests. New types: `ExtensionDescriptor`, `ExtensionResourceLimits`, `ExtensionConfig`.
- **Phase 19: Regulatory Compliance Complete** — All 9 exit criteria delivered:
  - **Compliance dashboard** — Real-time status cards (EU AI Act %, SOC 2 %, Framework Coverage %, Critical Gaps) and 7-framework coverage table with color-coded thresholds in the admin dashboard.
  - **EU AI Act Article 50 transparency** — `mark_ai_mediated()` injects `_meta.vellaveto_ai_mediated` into tool responses. `requires_human_oversight()` triggers audit events for configured tool patterns via glob matching. Art 50(1) status upgraded to Compliant. 11 tests.
  - **Immutable audit log archive** — gzip compression of rotated logs + retention enforcement (delete archives older than `retention_days`). Feature-gated behind `archive`. 9 tests.
  - **OTLP export with GenAI semantic conventions** — `OtlpExporter` maps `SecuritySpan` to OpenTelemetry spans with `gen_ai.system`, `gen_ai.operation.name`, and `vellaveto.*` attributes. Feature-gated behind `otlp-exporter`. 11 tests.
  - **OtlpConfig** added to vellaveto-config with endpoint/protocol/headers validation.
- **Phase 19.3: CoSAI/Adversa Threat Coverage** — CoSAI 12-category registry (38 threats, 100% coverage), Adversa AI TOP 25 matrix (25/25, 100% coverage), cross-framework gap analysis across 7 frameworks (ATLAS, NIST RMF, ISO 27090, EU AI Act, CoSAI, Adversa TOP 25, ISO 42001). New endpoints: `GET /api/compliance/threat-coverage`, `GET /api/compliance/gap-analysis`. 35 tests.
- **Phase 19.1: EU AI Act Compliance Evidence** — Registry-based conformity assessment with 10 obligations (Art 5–50), 18 capability mappings, and `AiActRiskClass` enum. `GET /api/compliance/eu-ai-act/report` generates conformity assessment per Art 43. Read-time entry classification via `classify_entry_transparency()`. 11 tests.
- **Phase 19.4: SOC 2 Evidence + Merkle Proofs** — SOC 2 registry with 22 criteria across CC1-CC9, ~30 capability mappings, and 5-level `ReadinessLevel` scoring. `GET /api/compliance/soc2/evidence` with category filter. Append-only Merkle tree with RFC 6962 domain separation, inclusion proof generation/verification, audit logger integration, checkpoint integration, crash recovery. 38 tests (14 SOC 2 + 24 Merkle).
- **Phase 21: Advanced Authorization Complete** — Cedar-style ABAC engine with forbid-overrides evaluation, `AbacEngine` compiled policies + `EntityStore` with transitive group membership (bounded depth=16). `LeastAgencyTracker` for per-agent-session permission usage tracking with 4-tier recommendations (Optimal/ReviewGrants/NarrowScope/Critical). Identity federation via `FederationTrustAnchor` with JWT claim-to-principal mapping. Continuous authorization via `RiskScore`-based per-request deny. ABAC wired across HTTP/WebSocket/gRPC transports. Full backward compat when disabled. ~80 tests (31 Phase 21.0 + 49 Phase 21.1–21.4).
- **Phase 23: Research & Future** — Multimodal injection detection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM text extraction, LSB steganography), autonomous red teaming (8 mutation types, coverage tracking, `POST /api/simulator/red-team`), FIPS 140-3 compliance mode (ECDSA P-256 behind `fips` feature, algorithm validation), Sigstore/Rekor transparency log integration (RFC 6962 Merkle proof verification), stateful session reasoning guards (5-state machine with WorkflowTracker/GoalTracker integration). 71 new tests.
- **Phase 22: Developer Experience** — Policy simulator API (single/batch/validate/diff endpoints), CLI `simulate` subcommand for batch evaluation from file, GitHub Action for CI policy gates, dashboard SVG charts (verdict distribution sparkline, policy type pie chart). TypeScript SDK with native `fetch()`, zero runtime deps, full API parity with Python SDK. 13 new Rust tests + 15 TypeScript tests.
- **Phase 21.0: Capability-Based Delegation Tokens** — Ed25519-signed `CapabilityToken` with monotonic attenuation (depth decrements, grants subset, expiry clamped). `RequireCapabilityToken` policy condition with fail-closed semantics. Grant coverage matching via glob patterns on tool/function/paths/domains. Structural validation (MAX_GRANTS=64, MAX_DEPTH=16). 31 tests.
- **Phase 17.2: gRPC Transport (Google Proposal)** — Protocol Buffers-based MCP transport on separate port (50051) via tonic 0.13, feature-gated behind `grpc`. Full policy enforcement pipeline (classify → evaluate → audit → forward → DLP/injection scan), depth-bounded proto↔JSON conversion (MAX_DEPTH=64), constant-time auth interceptor, gRPC Health v1, bidirectional streaming with per-message evaluation, gRPC-to-HTTP fallback for existing HTTP MCP servers. 46 unit tests + `fuzz_grpc_proto` fuzz target. New CLI args: `--grpc`, `--grpc-port`, `--grpc-max-message-size`, `--upstream-grpc-url`.
- **Phase 17.1: WebSocket Transport (SEP-1288)** — Bidirectional MCP-over-WebSocket reverse proxy at `/mcp/ws` with full policy enforcement, DLP/injection response scanning, TOCTOU-safe canonicalization, per-connection rate limiting, idle timeout, session binding, and fail-closed semantics. 29 unit tests + `fuzz_ws_frame` fuzz target. New CLI args: `--ws-max-message-size`, `--ws-idle-timeout`, `--ws-message-rate-limit`.
- **Production-ready CI/CD** — 11 GitHub Actions workflows: CI, security audit, cargo-deny, dependency review, scorecard, provenance/SBOM, Docker publish (GHCR + Trivy), release automation (static binaries, checksums, SBOM, provenance), rustdoc Pages, PyPI publish (trusted OIDC), and crates.io publish (dependency-ordered).
- **Python SDK** — 288 tests covering types, sync/async client, LangChain, LangGraph, Composio, ZK audit, and parameter redaction. Client-side secret stripping via `ParameterRedactor` with 3 modes. **Composio integration** — `ComposioGuard` with `before_execute`/`after_execute` modifier factories for universal Composio provider support (OpenAI, LangChain, CrewAI, AutoGen, Google ADK), client-side response DLP + injection scanning (NFKC normalization, invisible char stripping, secret redaction), TOCTOU-safe standalone execute, thread-safe call chain tracking, fail-closed semantics. 84 Composio tests (49 adversarial). Works with any of Composio's 500+ tool connectors.
- **Framework quickstart guides** — Step-by-step integration for Anthropic SDK, OpenAI SDK, LangChain, LangGraph, and MCP proxy.
- **Policy presets** — 5 curated configurations for dev-laptop, CI/CD, RAG, database, and browser agent scenarios.
- **AGPL-3.0 dual license** — Switched from Apache-2.0 to AGPL-3.0 with commercial license option. Machine-readable AI training opt-out for EU CDSM Article 4 compliance.
- **Phase 14: A2A Protocol Security** — Full Google A2A protocol security with message classification, action extraction, Agent Card caching/validation, HTTP proxy service, batch rejection for TOCTOU prevention.
- **Phase 15: AI Observability Platform Integration** — Langfuse, Arize, Helicone, and Webhook exporters with `SecuritySpan` tracing.
- **Identity Verification Primitives** — DID:PLC generation, ordered verification tiers with fail-closed enforcement, Ed25519-signed accountability attestations, `min_verification_tier` policy condition.
- **Adversarial Audit Hardening (FIND-055–074)** — Agent card SSRF prevention, bounded JSON traversal, control character rejection, regex pattern length limits, observability exporter bounds, attestation validation, audit log permission warnings.
- **Adversarial Pentest Round 3 (FIND-077–084)** — Circuit breaker case normalization, HalfOpen state transition fix, exponential backoff enforcement, behavioral absolute ceiling, cold-start EMA cap, deputy re-delegation scope intersection, capability grant path normalization, fullwidth digit NFKC normalization.
- **RwLock Poisoning Hardening** — All lock acquisition patterns across 12 modules replaced with explicit match blocks and fail-closed defaults.
- **24 fuzz targets** — Coverage for JSON-RPC framing, path normalization, domain extraction, CIDR parsing, DLP scanning, injection detection, agent card URL/parse, A2A classification, homoglyph normalization, attestation verification, WebSocket frame parsing, gRPC proto conversion.
- See `CHANGELOG.md` for full release and patch details.

## 🧪 Post-Quantum Readiness (Research Track)

- Vellaveto tracks NIST PQC standards: `FIPS 203 (ML-KEM)`, `FIPS 204 (ML-DSA)`, `FIPS 205 (SLH-DSA)`, plus migration guidance in `NIST SP 800-227` (finalized on 2025-08-13).
- TLS post-quantum key exchange for TLS 1.3 is still draft-stage in IETF (hybrid and pure ML-KEM drafts), so Vellaveto keeps a crypto-agile migration posture until RFCs and ecosystem support stabilize.
- Implemented controls:
  - Configurable `tls.kex_policy` (`classical_only`, `hybrid_preferred`, `hybrid_required_when_supported`) in `TlsConfig`
  - Validation guardrails: hybrid policies require `tls.mode` enabled and `tls.min_version = "1.3"`
  - Negotiate and emit TLS metadata (`protocol`, `cipher`, `kex_group`) to audit and observability contexts
  - Standardize workspace outbound `reqwest` TLS backend to rustls
  - Fail-closed handling for ambiguous forwarded TLS metadata aliases/duplicates
- Migration runbook:
  - `docs/quantum-migration.md` includes phased rollout, canary gates, and rollback procedure
- Vellaveto roadmap now tracks external migration milestones (goals by 2028, high-priority migration by 2031, full migration by 2035). See `ROADMAP.md`.

## ❓ Why Vellaveto?

AI agents with tool access can read files, make HTTP requests, execute commands, and modify data. Without guardrails, a prompt injection or misbehaving agent can:

- 🔑 **Exfiltrate credentials** (`~/.aws/credentials`, `~/.ssh/id_rsa`)
- 🌐 **Call unauthorized APIs** (sending data to `*.ngrok.io` or `*.requestbin.com`)
- 💥 **Execute destructive commands** (`rm -rf /`)
- 🎭 **Bypass restrictions** via Unicode tricks, path traversal, or tool annotation changes
- 🧪 **Launder data** by planting instructions in tool responses for later execution
- 👥 **Impersonate tools** via name squatting with homoglyphs or typos

Vellaveto enforces security policies on every tool call before it reaches the tool server, and logs every decision to a tamper-evident audit trail.

## ✨ Features

### 🎯 Core Policy Engine
- **Policy evaluation** with glob, regex, and domain matching on tool calls and parameters
- **Parameter constraints** with deep recursive JSON scanning across nested objects and arrays
- **Context-aware policies** with time windows, per-session call limits, agent ID restrictions, and action sequence enforcement
- **Human-in-the-loop approvals** with deduplication, expiry, and audit trail
- **Pre-compiled patterns** with zero allocations on the evaluation hot path
- **Evaluation traces** for full decision explainability (OPA-style)
- **Canonical presets** for common security scenarios (dangerous tools, network allowlisting, etc.)

### 🕵️ Threat Detection (OWASP Agentic Top 10)
- **Injection detection** (ASI01) — Aho-Corasick multi-pattern scanning with Unicode NFKC normalization and configurable blocking
- **Tool squatting detection** (ASI03) — Flags tools with names similar to known tools via Levenshtein distance and homoglyph analysis (Cyrillic, Greek, mathematical confusables)
- **Rug-pull detection** (ASI03) — Alerts on MCP tool annotation changes, schema mutations, tool removals, and new tool additions with persistent flagging
- **Schema poisoning detection** (ASI05) — Schema lineage tracking with mutation thresholds and trust scoring
- **Confused deputy prevention** (ASI02) — Delegation chain validation with configurable depth limits
- **Circuit breaker** (ASI08) — Cascading failure prevention with failure budgets and automatic recovery
- **Shadow agent detection** — Agent fingerprinting and impersonation alerts for multi-agent environments
- **Memory poisoning defense** (ASI06) — Cross-request data flow tracking detects when tool response data is replayed verbatim in subsequent tool call parameters
- **Memory injection defense** (ASI06) — Taint propagation with provenance graphs, exponential trust decay, quarantine management, and agent namespace isolation
- **DLP response scanning** — Detects secrets (AWS keys, GitHub tokens, JWTs, private keys, Slack tokens) in tool responses through 5 decode layers
- **Elicitation interception** (MCP 2025-11-25) — Validates `elicitation/create` requests, blocks sensitive field types, enforces per-session rate limits
- **Sampling policy enforcement** — Configurable policies for `sampling/createMessage` with content inspection and model filtering
- **Sampling attack detection** — Rate limiting, prompt length validation, and sensitive content detection for sampling requests
- **Cross-agent security** — Agent trust graph with privilege levels, Ed25519 signed inter-agent messages, and second-order prompt injection detection for multi-agent systems
- **Goal state tracking** (ASI01) — Detects objective drift mid-session with similarity-based alignment and manipulation keyword detection
- **Workflow intent tracking** — Long-horizon attack detection with step budgets, cumulative effect analysis, and suspicious pattern detection
- **Tool namespace security** (ASI03) — Prevents shadowing via Levenshtein typosquatting detection, protected name patterns, and collision detection
- **Output security analysis** (ASI07) — Covert channel detection including steganography, entropy analysis, and output normalization
- **Token security analysis** — Special token injection, context flooding, glitch token patterns, and Unicode normalization attack detection

### 🚀 Deployment & Operations
- **Six deployment modes**: HTTP API server, MCP stdio proxy, HTTP reverse proxy, WebSocket reverse proxy, gRPC proxy (feature-gated), MCP gateway (multi-backend routing)
- **Prometheus metrics** at `/metrics` with evaluation latency histograms, verdict counters, and DLP finding counts
- **Hot policy reload** via SIGHUP signal or filesystem watching with atomic swap and audit trail
- **SIEM export** in CEF (Common Event Format) and JSON Lines for integration with Splunk, ArcSight, Elasticsearch, and Datadog
- **Tamper-evident audit logging** with SHA-256 hash chains, Merkle tree inclusion proofs, Ed25519 signed checkpoints, and rotation chain continuity
- **Structured output validation** via OutputSchemaRegistry against declared `outputSchema`

### 🔐 Authentication & Access Control
- **OAuth 2.1 / JWT** validation with JWKS and scope enforcement (RS256, ES256, EdDSA)
- **ABAC engine** — Cedar-style attribute-based access control with permit/forbid policies, principal/action/resource matching, entity store with transitive group membership, and forbid-overrides evaluation
- **Least-agency enforcement** — Per-session permission usage tracking with unused-permission detection and 4-tier narrowing recommendations
- **Continuous authorization** — Risk-score-based per-request re-evaluation with configurable thresholds and progressive degradation
- **Capability delegation tokens** — Ed25519-signed tokens with monotonic attenuation, depth budgets, and grant coverage matching
- **Identity federation** — Cross-organization trust anchors with JWT claim-to-principal identity mapping
- **CSRF protection** via Origin header validation on mutating endpoints
- **Rate limiting** per-IP, per-principal, and per-endpoint with configurable burst
- **Security headers** including HSTS, CSP, X-Frame-Options, and X-Permitted-Cross-Domain-Policies
- **Constant-time auth** comparison to prevent timing attacks

### 🌐 Network & Path Security
- **Path normalization** with multi-layer percent-decode, `..` resolution, and null byte stripping
- **Domain normalization** with trailing dot, case folding, scheme/port stripping, and RFC 1035 validation
- **DNS rebinding protection** with IP-level access control (block private IPs, CIDR allow/blocklists)
- **Supply chain verification** with SHA-256 hash checking of MCP server binaries
- **MCP 2025-11-25 compliance** with protocol version header, RFC 8707 resource indicators, and `_meta` preservation (with backwards compatibility for 2025-06-18 and 2025-03-26)

### 🔐 ETDI: Cryptographic Tool Security
- **Tool signature verification** — Ed25519/ECDSA P-256 cryptographic signing of tool definitions with trusted signer allowlists (fingerprints + SPIFFE IDs)
- **Attestation chain** — Provenance tracking with initial registration, version updates, and chain integrity verification
- **Version pinning** — Semantic versioning constraints (`^1.0.0`, `~2.1.0`, exact) with hash-based drift detection for rug-pull prevention
- **ETDI persistent store** — Signatures, attestations, and pins with optional HMAC integrity protection
- **ETDI API** — Full REST API for signature verification, attestation chain management, and version pin operations

### 🧠 MINJA: Memory Injection Defense
- **Taint propagation** — Track tainted data across memory operations with configurable severity thresholds and propagation rules
- **Provenance graph** — DAG-based data lineage tracking with node ancestry, trust inheritance, and graph traversal queries
- **Trust decay** — Exponential decay of data trust scores over time with configurable half-life and minimum trust floors
- **Quarantine management** — Isolate suspicious data with severity-based quarantine policies and safe release workflows
- **Namespace isolation** — Strict memory isolation between agents with namespace-scoped access control and cross-namespace violation detection
- **MINJA API** — 10 REST endpoints for taint tracking, provenance queries, trust scoring, quarantine operations, and namespace management

### 🤖 NHI: Non-Human Identity Lifecycle
- **Agent identity registration** — Multiple attestation types (JWT, mTLS, SPIFFE, DPoP, API key) with configurable TTL and public key binding
- **Identity lifecycle** — Full state machine: Probationary → Active → Suspended → Revoked → Expired with automatic transitions
- **Behavioral attestation** — Continuous authentication via behavioral baselines using Welford's online variance algorithm
- **Delegation chains** — Agent-to-agent permission delegation with scope constraints, depth limits, and accountability tracking
- **Credential rotation** — Automatic lifecycle with expiration warnings, rotation history, and DPoP (RFC 9449) support
- **NHI API** — 16 REST endpoints for identity registration, lifecycle management, behavioral checks, delegations, and credential rotation

### ⏱️ MCP Tasks Security
- **Task state encryption** — ChaCha20-Poly1305 AEAD encryption for sensitive task state data at rest
- **Resume authentication** — HMAC-SHA256 tokens prevent unauthorized access to long-running tasks
- **Hash chain integrity** — SHA-256 chain of state transitions with tamper detection and verification
- **Checkpoint verification** — Ed25519 signed snapshots for non-repudiation and point-in-time verification
- **Replay protection** — Nonce tracking with configurable FIFO eviction prevents request replay attacks

### 🧠 Semantic Guardrails (LLM-Based)
- **Intent classification** — Structured taxonomy beyond pattern matching (DataRead, DataWrite, SystemExecute, NetworkFetch, CredentialAccess, etc.)
- **Natural language policies** — Define policies in plain English with glob-based tool/function matching
- **Jailbreak detection** — LLM-based detection resistant to adversarial prompt evasion
- **Intent chain tracking** — Per-session tracking to detect suspicious patterns (reconnaissance→exfiltration)
- **Evaluation caching** — LRU + TTL cache minimizes latency and cost on repeated patterns
- **Pluggable backends** — Support for cloud (OpenAI, Anthropic) and local (GGUF, ONNX) models
- **Fail-closed design** — Errors, timeouts, and low confidence all result in denial

### 🔍 Adaptive Tool Layer
- **Tool Discovery** — Pure Rust TF-IDF inverted index with cosine similarity scoring for natural language tool search across MCP servers. Policy-filtered results with configurable token budgets. Auto-indexing from `tools/list` responses. Session-scoped TTL lifecycle (discover → use → expire → re-discover). Feature-gated behind `discovery`.
- **Model Projector** — Model-agnostic tool schema projection with `ModelProjection` trait and `ProjectorRegistry`. Built-in projections for Claude (tool_use format, cache_control hints), OpenAI (functions format), DeepSeek (think-block stripping, markdown extraction), Qwen (CJK-aware truncation), and Generic (passthrough). Schema compression with 5 progressive strategies. Call repair for malformed tool calls (type coercion, default injection, fuzzy name matching). Feature-gated behind `projector`.

### 📚 RAG Poisoning Defense
- **Document verification** — Trust scoring with age bonuses, admin approval, signature verification, and mutation penalties
- **Document provenance** — SHA-256 content hashing, version chain tracking, and source attribution
- **Retrieval security** — Result count limits, DLP scanning, and sensitive data filtering
- **Diversity enforcement** — Jaccard similarity detection prevents context flooding with duplicate content
- **Embedding anomaly detection** — Per-agent baseline tracking with cosine similarity comparison
- **Context budget enforcement** — Token-based limits per retrieval and per session with truncate/reject/warn modes

### 🤝 A2A Protocol Security
- **Message classification** — Parse and classify A2A JSON-RPC messages (message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe)
- **Action extraction** — Convert A2A messages to Vellaveto Actions for policy evaluation with tool pattern "a2a"
- **Agent Card handling** — Fetch, cache, and validate A2A Agent Cards from `/.well-known/agent.json` with TTL-based expiration
- **Proxy service** — HTTP proxy for A2A traffic with policy evaluation, DLP scanning, injection detection, and circuit breaker
- **Batch rejection** — JSON-RPC batch requests rejected to prevent TOCTOU attacks (matching MCP security pattern)
- **Authentication validation** — Validate request authentication against agent card supported schemes (API key, Bearer, OAuth 2.0, mTLS)
- **Task operation restrictions** — Configurable allowlist for task operations (get, cancel, resubscribe)

### 🪪 Identity Verification
- **DID:PLC generation** — Deterministic decentralized identifiers from SHA-256 + Base32 encoding of canonicalized genesis operations
- **Verification tiers** — Ordered enum (Unverified, SelfAsserted, ThirdPartyAttested, CryptographicallyVerified, FullyVerified) with fail-closed policy enforcement when tier is missing
- **Accountability attestations** — Ed25519 signed, length-prefixed content with constant-time public key verification (`subtle::ConstantTimeEq`)
- **Policy condition: `min_verification_tier`** — Fail-closed when verification tier is absent from evaluation context

### 🏢 Enterprise Features
- **mTLS / SPIFFE-SPIRE** — Mutual TLS with client certificate verification, SPIFFE identity extraction from X.509 SAN URIs, trust domains, workload identity, and ID-to-role mapping
- **OPA Integration** — Runtime decision enforcement is active in server evaluation paths with merge semantics (OPA deny overrides allow), fail-open/fail-closed controls, query/error latency metrics, and optional `opa.require_https` enforcement for OPA control-plane transport
- **Threat Intelligence** — TAXII 2.1 (STIX), MISP, and custom REST threat feed integration with IOC matching, confidence filtering, and configurable actions (deny/alert/require_approval)
- **Just-In-Time Access** — Session-based temporary elevated permissions with approval workflows, per-principal session limits, auto-revocation on security alerts, and permission/tool access checking

### 📊 Observability & Tooling
- **AI Observability Exporters** — Langfuse, Arize Phoenix, Helicone, Webhook, and **OTLP** backends with `SecuritySpan` tracing for streaming security events to observability platforms in real time
- **OTLP Export with GenAI Semantic Conventions** — Maps `SecuritySpan` to OpenTelemetry spans with `gen_ai.system`, `gen_ai.operation.name`, and `vellaveto.*` attributes. Compatible with Jaeger, Grafana Tempo, Datadog, and any OTLP collector. Feature-gated behind `otlp-exporter`
- **Execution Graphs** — Visual call chain tracking with DOT (Graphviz) and JSON export, color-coded verdicts, parent-child relationships, and graph statistics API
- **Policy Validation CLI** — Enhanced `vellaveto check` with strict mode, JSON/text output, best-practice and security checks, shadow policy detection, and wide pattern warnings
- **Attack Simulation** — Automated red-teaming framework with 40+ OWASP ASI Top 10 attack payloads, multi-step sequences, schema mutations, and result summarization

## 📦 Installation

### Docker (Recommended)

```bash
# Pull the latest release
docker pull ghcr.io/paolovella/vellaveto:latest

# Run with a policy config
docker run -p 3000:3000 \
  -v /path/to/config.toml:/etc/vellaveto/config.toml:ro \
  ghcr.io/paolovella/vellaveto:latest
```

### Kubernetes (Helm)

```bash
# Install with Helm
helm install vellaveto ./helm/vellaveto \
  --namespace vellaveto \
  --create-namespace \
  -f values-production.yaml
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for complete deployment instructions.

### Build from Source

```bash
# Clone and build
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto
cargo build --release

# Binaries in target/release/
ls target/release/vellaveto target/release/vellaveto-http-proxy
```

### Source Distribution (ZIP)

```bash
mkdir -p dist
git archive --format=zip --prefix=vellaveto/ -o dist/vellaveto-main-$(date +%Y%m%d-%H%M%S).zip HEAD
sha256sum dist/vellaveto-main-*.zip
```

- Uses `git archive`, so only tracked files are included.
- Local-only files ignored by Git (for example `.collab/`) are excluded automatically.
- Keep generated ZIPs under `dist/` for release handling.

## 🚀 Quick Start

### Docker (recommended)

```bash
# Clone and start with docker compose
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto
export VELLAVETO_API_KEY=$(openssl rand -hex 32)
docker compose up -d

# Evaluate a tool call
curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
```

### From Source

```bash
# Build
cargo build --release

# Create a policy config (deny-by-default baseline)
cat > policy.toml << 'EOF'
# SECURITY: Deny-by-default. Only explicitly allowed tools are permitted.
# Higher priority = matched first. Deny rules should have highest priority.

[[policies]]
name = "Block dangerous tools"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 1000  # High priority — always checked first

[[policies]]
name = "Allow file reads in /tmp"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 100
[policies.path_rules]
allowed_globs = ["/tmp/**"]

[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 0  # Lowest priority — catches everything not explicitly allowed
EOF

# Start the server
VELLAVETO_API_KEY=your-secret vellaveto serve --config policy.toml --port 3000

# Evaluate a tool call (another terminal)
curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
# -> {"verdict":"Allow", ...}  (allowed by "Allow file reads in /tmp")

curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/etc/passwd"}}' | jq .
# -> {"verdict":{"Deny":{"reason":"..."}}, ...}  (denied — path not in /tmp)

curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"bash","function":"exec","parameters":{"cmd":"ls"}}' | jq .
# -> {"verdict":{"Deny":{"reason":"Denied by policy 'Block dangerous tools'"}}, ...}
```

## ⚙️ How It Works

```
                    +------------------+
  AI Agent -------->|   🛡️ Vellaveto   |--------> Tool Server
                    |                  |
                    |  1. Parse action |
                    |  2. Match policy |
                    |  3. Evaluate     |
                    |     constraints  |
                    |  4. Allow / Deny |
                    |  5. Audit log    |
                    +--------+---------+
                             |
                    Tamper-evident log
                    (SHA-256 chain +
                     Ed25519 signatures)
```

Vellaveto supports six deployment modes:

| Mode | Binary | Use Case |
|------|--------|----------|
| 🖥️ **HTTP API** | `vellaveto serve` | Standalone policy server; agents call `/api/evaluate` |
| 📡 **Stdio Proxy** | `vellaveto-proxy` | Wraps a local MCP server; intercepts stdin/stdout |
| 🔄 **HTTP Proxy** | `vellaveto-http-proxy` | Reverse proxy for remote MCP servers (Streamable HTTP + SSE) |
| 🔌 **WebSocket Proxy** | `vellaveto-http-proxy` | WebSocket reverse proxy at `/mcp/ws` for bidirectional MCP |
| ⚡ **gRPC Proxy** | `vellaveto-http-proxy --grpc` | gRPC transport on port 50051 (requires `grpc` feature) |
| 🌐 **MCP Gateway** | `vellaveto-http-proxy` | Multi-backend routing with health checks and session affinity |

## 📝 Policy Configuration

Policies are defined in TOML (or JSON). Each policy matches tool calls by tool and function name, with optional parameter constraints. Policies are evaluated in priority order (highest first); the first match wins.

### Basic Policies

```toml
# Allow all file reads
[[policies]]
name = "Allow file reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 10

# Block all bash execution
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100
```

### Parameter Constraints

Conditional policies inspect parameter values using constraint operators:

```toml
# Block access to credential files
[[policies]]
name = "Block credential access"
tool_pattern = "file_system"
function_pattern = "read_file"
priority = 200
id = "file_system:read_file"

[policies.policy_type.Conditional.conditions]
parameter_constraints = [
  { param = "path", op = "glob", pattern = "/home/*/.aws/**", on_match = "deny" },
  { param = "path", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny" },
]
```

#### Available Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `glob` | Glob pattern match on file paths | `pattern = "/home/*/.aws/**"` |
| `not_glob` | Allow only paths matching a set of globs | `patterns = ["/safe/**"]` |
| `regex` | Regular expression match | `pattern = "(?i)rm\\s+-rf"` |
| `domain_match` | Domain wildcard match (handles subdomains) | `pattern = "*.example.com"` |
| `domain_not_in` | Domain allowlist (deny if not in list) | `patterns = ["api.example.com"]` |
| `eq` / `ne` | Exact value match / not-match | `value = "production"` |
| `one_of` / `none_of` | Value in / not in a set | `values = ["a", "b", "c"]` |

Each constraint specifies `on_match`: `"deny"`, `"allow"`, or `"require_approval"`.
Missing parameters default to `"deny"` (fail-closed), overridable with `on_missing: "skip"`.

### 🔍 Wildcard Parameter Scanning

Use `param = "*"` to recursively scan **all** string values in the parameters JSON, regardless of nesting depth:

```toml
# Scan every parameter value for credential paths
[[policies]]
name = "Deep credential scan"
tool_pattern = "*"
function_pattern = "*"
priority = 250

[policies.policy_type.Conditional.conditions]
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.aws/**", on_match = "deny" },
]
```

### ✋ Require Approval

Policies can require human-in-the-loop approval:

```toml
[[policies]]
name = "Network requires approval"
tool_pattern = "network"
function_pattern = "*"
priority = 150

[policies.policy_type.Conditional]
conditions = { require_approval = true }
```

When triggered, the evaluation response includes an `approval_id`. Use the approval endpoints to approve or deny:

```bash
# Approve
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "alice@example.com"}'

# Deny
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/deny \
  -H "Authorization: Bearer $VELLAVETO_API_KEY"
```

Pending approvals expire after 15 minutes by default.

### 📦 Canonical Presets

Built-in policy presets for common scenarios:

```bash
vellaveto policies --preset dangerous   # Blocks bash, shell, exec tools
vellaveto policies --preset network     # Domain allowlisting for HTTP
vellaveto policies --preset development # Project-directory-scoped file access
vellaveto policies --preset deny-all    # Deny everything by default
vellaveto policies --preset allow-all   # Allow everything (testing only)
```

### 🗳️ Elicitation & Sampling Policies

Control how Vellaveto handles MCP elicitation (server-initiated user prompts) and sampling (LLM re-invocation) requests:

```toml
[elicitation]
enabled = false                        # Block all elicitations by default
blocked_field_types = ["password", "ssn", "credit_card"]
max_per_session = 5

[sampling]
enabled = false                        # Block all sampling by default
allowed_models = []                    # Empty = any model when enabled
block_if_contains_tool_output = true   # Prevent exfiltration via sampling
```

### 💉 Injection Scanning

Configure how the injection scanner handles detected prompt injection patterns:

```toml
[injection]
enabled = true
block_on_injection = true    # true = block response (default), false = log only
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
```

When `block_on_injection` is `true`, responses matching injection patterns are replaced with a JSON-RPC error (`-32005`) instead of being forwarded.

### 🔒 DLP Response Scanning

Vellaveto scans tool **responses** for leaked secrets using 7 built-in patterns:

| Pattern | Example Match |
|---------|--------------|
| AWS Access Key | `AKIA...` (20-char uppercase) |
| AWS Secret Key | 40-char base64 after known key names |
| GitHub Token | `ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_` prefixes |
| Generic API Key | `sk-`, `api_key`, `token` followed by 20+ chars |
| Private Key Header | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| Slack Token | `xoxb-`, `xoxp-`, `xoxs-` prefixes |
| JWT | `eyJ...` base64-encoded JSON header with payload |

DLP scanning uses a 5-layer decode pipeline (raw, base64, percent-encoded, and both combinations) to catch obfuscated secrets.

### 🚦 Rate Limiting

```toml
[rate_limit]
evaluate_rps = 1000
evaluate_burst = 50
admin_rps = 20
admin_burst = 5
readonly_rps = 200
readonly_burst = 20
per_ip_rps = 100
per_ip_burst = 10
per_ip_max_capacity = 100000
per_principal_rps = 50
per_principal_burst = 10
```

Per-principal rate limiting keys requests by identity: the `X-Principal` header if present, then the Bearer token from the `Authorization` header, falling back to client IP.

> **⚠️ Note:** The `X-Principal` header is client-supplied and can be spoofed. For production deployments, enable OAuth 2.1 so the principal is derived from a validated JWT `sub` claim.

### 📋 Audit Configuration

```toml
[audit]
redaction_level = "KeysAndPatterns"  # Off | KeysOnly | KeysAndPatterns

# Custom PII patterns for domain-specific redaction
[[audit.custom_pii_patterns]]
name = "credit_card"
pattern = "\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}"
```

### 🔗 Supply Chain Verification

```toml
[supply_chain]
enabled = true

[supply_chain.allowed_servers]
"/usr/local/bin/my-mcp" = "sha256hexdigest..."
```

## 🏗️ Deployment Modes

### 🖥️ HTTP API Server

The primary mode. Runs a standalone HTTP server that agents call to evaluate tool calls.

```bash
VELLAVETO_API_KEY=your-secret vellaveto serve \
  --config policy.toml \
  --port 3000 \
  --bind 127.0.0.1
```

### 📡 MCP Stdio Proxy

Wraps a local MCP server process. Intercepts JSON-RPC messages over stdin/stdout.

```bash
vellaveto-proxy --config policy.toml -- /path/to/mcp-server --arg1 --arg2
```

Features:
- Intercepts `tools/call` and `resources/read` requests
- Configurable elicitation and sampling policy enforcement
- Scans responses for prompt injection patterns (log-only or blocking mode)
- Detects tool annotation and inputSchema rug-pull attacks
- Persists flagged tools across restarts (JSONL)
- Detects child process crashes and flushes pending requests with errors
- Configurable request timeout (`--timeout 30`)

### 🔄 Streamable HTTP Reverse Proxy

Sits between clients and a remote MCP server over HTTP. Supports SSE streaming and session management per the MCP Streamable HTTP transport spec.

```bash
VELLAVETO_API_KEY=your-secret vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001
```

Features:
- MCP Streamable HTTP transport (2025-11-25) with protocol version negotiation and backwards compatibility
- Session management with inactivity timeout and absolute session lifetime
- CSRF protection via Origin header validation
- SSE streaming passthrough for long-running operations
- Tool annotation and schema tracking with rug-pull detection
- OAuth 2.1 token validation with JWKS support
- Response body size limits to prevent upstream DoS
- DLP scanning of responses and SSE streams
- DNS rebinding protection with IP-level access control

#### 🔌 WebSocket Transport (SEP-1288)

The HTTP reverse proxy also supports WebSocket transport at `/mcp/ws` for bidirectional, session-persistent MCP communication:

```bash
# WebSocket is available on the same binary — connect at /mcp/ws
vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001 \
  --ws-max-message-size 1048576 \
  --ws-idle-timeout 300 \
  --ws-message-rate-limit 100
```

Features:
- Full policy enforcement on every WebSocket message (not just per-connection)
- DLP scanning and injection detection on upstream responses
- TOCTOU-safe JSON canonicalization before forwarding
- Per-connection rate limiting with sliding window
- Session binding (one session per WebSocket connection)
- Binary frame rejection (close code 1003), invalid JSON rejection (close code 1008)
- Idle timeout enforcement with configurable duration
- Metrics: `vellaveto_ws_connections_total`, `vellaveto_ws_messages_total`

#### 🔑 OAuth 2.1

```bash
vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --oauth-issuer https://auth.example.com \
  --oauth-audience mcp-server \
  --oauth-scopes mcp:read,mcp:write \
  --oauth-security-profile hardened \
  --oauth-expected-resource https://mcp.example.com
```

Supports RS256, ES256, and EdDSA algorithms. Algorithm confusion attacks are prevented by restricting to asymmetric algorithms only. The `--oauth-expected-resource` flag enables RFC 8707 resource indicator validation, preventing token replay attacks.

Security defaults and guardrails:
- `--oauth-security-profile hardened` enforces sender-constrained posture by requiring RFC 8707 resource binding and DPoP (`required` mode).
- `--oauth-pass-through` is guarded; enabling it requires explicit `--unsafe-oauth-pass-through` plus `--oauth-expected-resource` and `--oauth-dpop-mode required`.
- In DPoP `required` mode, access tokens must include `cnf.jkt`, and it must match the presented DPoP proof key thumbprint.

## 📡 HTTP API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Health check |
| `GET` | `/metrics` | No | Prometheus metrics (text exposition format) |
| `GET` | `/api/metrics` | No | Server metrics (JSON) |
| `POST` | `/api/evaluate` | Yes | Evaluate a tool call against loaded policies |
| `GET` | `/api/policies` | Yes | List all loaded policies |
| `POST` | `/api/policies` | Yes | Add a new policy at runtime |
| `DELETE` | `/api/policies/:id` | Yes | Remove a policy by ID |
| `POST` | `/api/policies/reload` | Yes | Reload policies from config file |
| `GET` | `/api/audit/entries` | Yes | List audit log entries (paginated) |
| `GET` | `/api/audit/report` | Yes | Audit summary report |
| `GET` | `/api/audit/verify` | Yes | Verify hash chain integrity |
| `GET` | `/api/audit/export` | Yes | Export entries in CEF or JSON Lines format |
| `GET` | `/api/audit/checkpoints` | Yes | List signed checkpoints |
| `GET` | `/api/audit/checkpoints/verify` | Yes | Verify checkpoint signatures |
| `POST` | `/api/audit/checkpoint` | Yes | Create a signed checkpoint |
| `GET` | `/api/approvals/pending` | Yes | List pending approvals |
| `GET` | `/api/approvals/:id` | Yes | Get approval details |
| `POST` | `/api/approvals/:id/approve` | Yes | Approve a pending request |
| `POST` | `/api/approvals/:id/deny` | Yes | Deny a pending request |
| `GET` | `/api/circuit-breaker` | Yes | List circuit breaker states |
| `POST` | `/api/circuit-breaker/:tool/reset` | Yes | Reset circuit breaker for tool |
| `GET` | `/api/shadow-agents` | Yes | List known agents |
| `POST` | `/api/shadow-agents` | Yes | Register agent fingerprint |
| `GET` | `/api/schema-lineage` | Yes | List tracked schemas |
| `GET` | `/api/tasks` | Yes | List async task states |
| `GET` | `/api/auth-levels/:session` | Yes | Get session auth level |
| `GET` | `/api/deputy/delegations` | Yes | List delegation chains |
| `GET` | `/api/etdi/signatures` | Yes | List all tool signatures |
| `GET` | `/api/etdi/signatures/:tool` | Yes | Get signature for a tool |
| `POST` | `/api/etdi/signatures/:tool/verify` | Yes | Verify tool signature |
| `GET` | `/api/etdi/attestations` | Yes | List all attestations |
| `GET` | `/api/etdi/attestations/:tool` | Yes | Get attestation chain for a tool |
| `GET` | `/api/etdi/attestations/:tool/verify` | Yes | Verify attestation chain integrity |
| `GET` | `/api/etdi/pins` | Yes | List all version pins |
| `GET` | `/api/etdi/pins/:tool` | Yes | Get version pin for a tool |
| `POST` | `/api/etdi/pins/:tool` | Yes | Create version pin |
| `DELETE` | `/api/etdi/pins/:tool` | Yes | Remove version pin |
| `GET` | `/api/minja/taint/:id` | Yes | Get taint status for a data item |
| `POST` | `/api/minja/taint` | Yes | Mark data as tainted with severity |
| `GET` | `/api/minja/provenance/:id` | Yes | Get provenance graph for data |
| `POST` | `/api/minja/provenance` | Yes | Record data lineage relationship |
| `GET` | `/api/minja/trust/:id` | Yes | Get current trust score with decay |
| `POST` | `/api/minja/trust/:id/refresh` | Yes | Refresh trust score timestamp |
| `GET` | `/api/minja/quarantine` | Yes | List quarantined data items |
| `POST` | `/api/minja/quarantine/:id` | Yes | Quarantine a data item |
| `DELETE` | `/api/minja/quarantine/:id` | Yes | Release data from quarantine |
| `GET` | `/api/minja/namespaces/:agent` | Yes | Get namespace isolation status |
| `GET` | `/api/nhi/agents` | Yes | List registered agent identities |
| `POST` | `/api/nhi/agents` | Yes | Register a new agent identity |
| `GET` | `/api/nhi/agents/:id` | Yes | Get agent identity details |
| `DELETE` | `/api/nhi/agents/:id` | Yes | Revoke agent identity |
| `POST` | `/api/nhi/agents/:id/activate` | Yes | Activate probationary identity |
| `POST` | `/api/nhi/agents/:id/suspend` | Yes | Suspend active identity |
| `GET` | `/api/nhi/agents/:id/baseline` | Yes | Get behavioral baseline |
| `POST` | `/api/nhi/agents/:id/check` | Yes | Check behavior against baseline |
| `GET` | `/api/nhi/delegations` | Yes | List all delegations |
| `POST` | `/api/nhi/delegations` | Yes | Create a delegation |
| `GET` | `/api/nhi/delegations/:from/:to` | Yes | Get delegation details |
| `DELETE` | `/api/nhi/delegations/:from/:to` | Yes | Revoke delegation |
| `GET` | `/api/nhi/delegations/:id/chain` | Yes | Resolve full delegation chain |
| `POST` | `/api/nhi/agents/:id/rotate` | Yes | Rotate agent credentials |
| `GET` | `/api/nhi/expiring` | Yes | Get identities expiring soon |
| `POST` | `/api/nhi/dpop/nonce` | Yes | Generate DPoP nonce |
| `GET` | `/api/nhi/stats` | Yes | Get NHI statistics |
| `GET` | `/api/compliance/status` | Yes | Overall compliance posture (EU AI Act + SOC 2 + NIST + ISO + ISO 42001) |
| `GET` | `/api/compliance/eu-ai-act/report` | Yes | EU AI Act conformity assessment report (Art 43) |
| `GET` | `/api/compliance/soc2/evidence` | Yes | SOC 2 evidence collection with optional `?category=CC1` filter |
| `GET` | `/api/compliance/iso42001/report` | Yes | ISO/IEC 42001 AI Management System evidence report |
| `GET` | `/api/compliance/threat-coverage` | Yes | Threat coverage across ATLAS, CoSAI, and Adversa TOP 25 |
| `GET` | `/api/compliance/gap-analysis` | Yes | Cross-framework gap analysis (7 frameworks) |
| `GET` | `/api/compliance/data-governance` | Yes | Data governance registry (Art 10) with tool classifications |
| `GET` | `/api/deployment/info` | Yes | Deployment mode, leader status, and discovered endpoints |

All endpoints except `/health`, `/metrics`, and `/api/metrics` require a `Bearer` token matching `VELLAVETO_API_KEY`. Use `--allow-anonymous` to disable authentication for development.

### Example: Evaluate

```bash
curl -X POST http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -d '{
    "tool": "file_system",
    "function": "read_file",
    "parameters": {"path": "/home/user/.aws/credentials"}
  }'
```

```json
{
  "verdict": {
    "Deny": {
      "reason": "Parameter 'path' path '/home/user/.aws/credentials' matches glob '/home/*/.aws/**' (policy 'Block credential access')"
    }
  },
  "action": {
    "tool": "file_system",
    "function": "read_file",
    "parameters": { "path": "/home/user/.aws/credentials" }
  },
  "approval_id": null
}
```

### Example: Prometheus Metrics

```bash
curl http://localhost:3000/metrics
```

```
# HELP vellaveto_evaluations_total Total policy evaluations
# TYPE vellaveto_evaluations_total counter
vellaveto_evaluations_total{verdict="allow"} 1042
vellaveto_evaluations_total{verdict="deny"} 87
vellaveto_evaluations_total{verdict="require_approval"} 12
# HELP vellaveto_evaluation_duration_seconds Policy evaluation latency
# TYPE vellaveto_evaluation_duration_seconds histogram
vellaveto_evaluation_duration_seconds_bucket{le="0.001"} 1129
...
```

### Example: SIEM Export

```bash
# Export in CEF format
curl "http://localhost:3000/api/audit/export?format=cef&limit=100" \
  -H "Authorization: Bearer $VELLAVETO_API_KEY"

# Export in JSON Lines format
curl "http://localhost:3000/api/audit/export?format=jsonl&since=2026-02-04T00:00:00Z" \
  -H "Authorization: Bearer $VELLAVETO_API_KEY"
```

## 📋 Audit System

Every policy decision is logged to a tamper-evident audit trail.

### Properties

- 📄 **JSONL format** — one JSON entry per line, streamable and easy to ingest
- 🔗 **SHA-256 hash chain** — each entry includes the hash of the previous entry; any tampering breaks the chain
- 🌲 **Merkle tree inclusion proofs** — append-only Merkle tree with RFC 6962 domain separation; generate and verify inclusion proofs for any audit entry without full log access
- 🔄 **Rotation chain continuity** — when logs rotate, a rotation manifest links files together with tail hashes
- ✍️ **Ed25519 signed checkpoints** — periodic cryptographic snapshots of chain state with Merkle root for independent verification
- 🙈 **Sensitive value redaction** — API keys, tokens, passwords, and secrets are automatically redacted before logging
- 📊 **SIEM integration** — export entries in CEF or JSON Lines format via API or configurable webhook
- 🔁 **Duplicate entry detection** — detects replayed or duplicated audit entries
- ✅ **Approval audit trail** — approve/deny decisions are logged with resolver identity, original tool, and approval ID
- 📦 **Immutable archive** — gzip compression of rotated logs with configurable retention policies (feature-gated behind `archive`)

### Verification

```bash
# Via CLI (offline verification)
vellaveto verify --audit audit.log

# Via API (live verification)
curl http://localhost:3000/api/audit/verify \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" | jq .
# -> {"valid": true, "entries_checked": 142, "first_broken_at": null}

# Verify checkpoint signatures
curl http://localhost:3000/api/audit/checkpoints/verify \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" | jq .
```

### 🔑 Signing Key

```bash
# Use a persistent key (hex-encoded 32-byte Ed25519 seed)
export VELLAVETO_SIGNING_KEY="a1b2c3d4..."

# Or let Vellaveto auto-generate one (public key logged at startup)
```

Checkpoints are created every 300 seconds by default (configurable via `VELLAVETO_CHECKPOINT_INTERVAL`).

## 🔎 Evaluation Traces

Request a full decision trace showing which policies were checked and why:

```bash
curl -X POST "http://localhost:3001/mcp?trace=true" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"ls"}}}'
```

The trace includes:
- Number of policies checked and matched
- Per-policy constraint evaluations (parameter tested, expected vs. actual, pass/fail)
- Final verdict with reason
- Evaluation duration in microseconds

## 🌍 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VELLAVETO_API_KEY` | *(required)* | Bearer token for all authenticated endpoints |
| `VELLAVETO_SIGNING_KEY` | *(auto-generated)* | Hex-encoded 32-byte Ed25519 seed for audit checkpoints |
| `VELLAVETO_CHECKPOINT_INTERVAL` | `300` | Seconds between automatic audit checkpoints (0 to disable) |
| `VELLAVETO_TRUSTED_PROXIES` | *(none)* | Comma-separated trusted proxy IPs for X-Forwarded-For |
| `VELLAVETO_CORS_ORIGINS` | *(localhost)* | Comma-separated allowed CORS origins (`*` for any) |
| `VELLAVETO_LOG_MAX_SIZE` | `104857600` | Max audit log size in bytes before rotation (0 to disable) |
| `VELLAVETO_NO_CANONICALIZE` | `false` | Disable JSON-RPC re-serialization before forwarding |
| `RUST_LOG` | `info` | Log level filter (`tracing` / `env_logger` syntax) |

Rate limiting environment variables: `VELLAVETO_RATE_EVALUATE`, `VELLAVETO_RATE_EVALUATE_BURST`, `VELLAVETO_RATE_ADMIN`, `VELLAVETO_RATE_ADMIN_BURST`, `VELLAVETO_RATE_READONLY`, `VELLAVETO_RATE_READONLY_BURST`, `VELLAVETO_RATE_PER_IP`, `VELLAVETO_RATE_PER_IP_BURST`, `VELLAVETO_RATE_PER_IP_MAX_CAPACITY`, `VELLAVETO_RATE_PER_PRINCIPAL`, `VELLAVETO_RATE_PER_PRINCIPAL_BURST`.

Environment variables override values set in the config file.

## 🛡️ Security Properties

| Property | Implementation |
|----------|---------------|
| 🚪 **Fail-closed** | Empty policy set, missing parameters, and evaluation errors all produce `Deny` |
| ✅ **Input validation** | Action names validated (no empty strings, null bytes, max 256 chars); domain patterns validated per RFC 1035 |
| 🛑 **ReDoS protection** | Regex patterns reject nested quantifiers (`(a+)+`) and overlength (>1024 chars) |
| 📂 **Path normalization** | Resolves `..`, `.`, percent-encoding (multi-layer), null bytes; prevents traversal |
| 🌐 **Domain normalization** | Trailing dots, case folding, `@` in authority, scheme/port stripping; RFC 1035 label validation |
| 💉 **Injection detection** | Aho-Corasick with Unicode NFKC normalization, zero-width/bidi/tag character stripping |
| 👥 **Tool squatting** | Levenshtein distance + homoglyph detection against known tool names |
| 🔄 **Rug-pull detection** | Alerts on annotation changes, schema mutations, tool removals/additions; persistent flagging |
| 🧠 **Memory poisoning** | Cross-request SHA-256 fingerprint tracking detects data laundering from tool responses |
| 🔒 **DLP scanning** | 5-layer decode pipeline (raw, base64, percent, and combinations) for secret detection |
| 🗳️ **Elicitation guard** | Field type blocking, per-session rate limits, configurable allow/deny |
| 🤖 **Sampling guard** | Content inspection, model filtering, tool-output exfiltration prevention |
| ⚡ **Circuit breaker** | Cascading failure prevention with failure budgets and automatic recovery |
| 👤 **Shadow agent detection** | Agent fingerprinting and impersonation alerts |
| 🔗 **Deputy validation** | Delegation chain tracking with depth limits (confused deputy prevention) |
| 📋 **Schema poisoning** | Schema lineage tracking with mutation thresholds |
| 🤝 **Cross-agent security** | Agent trust graph, Ed25519 message signing, privilege escalation detection |
| 🛡️ **CSRF protection** | Origin header validation on POST/DELETE endpoints |
| ⏱️ **Constant-time auth** | API key comparison uses `subtle::ConstantTimeEq` |
| 📋 **Tamper-evident audit** | SHA-256 hash chain + Merkle tree inclusion proofs + Ed25519 checkpoints + rotation manifests |
| 🌍 **DNS rebinding** | IP-level access control blocks private/reserved IPs and custom CIDR ranges |
| 🔑 **OAuth 2.1** | JWT/JWKS validation, algorithm confusion prevention, scope enforcement |
| 🚦 **Rate limiting** | Per-IP, per-principal, per-endpoint with burst support and capacity bounds |
| 🔗 **Supply chain** | SHA-256 hash verification of MCP server binaries before spawn |
| 🔏 **ETDI tool signing** | Ed25519/ECDSA tool signatures with attestation chains and version pinning |
| 🧠 **MINJA memory defense** | Taint propagation, provenance graphs, trust decay, quarantine, and namespace isolation |
| 🤖 **NHI lifecycle** | Agent identity attestation, behavioral baselines, delegation chains, credential rotation, and DPoP |
| 🎫 **Capability delegation** | Ed25519-signed capability tokens with monotonic attenuation, grant coverage matching, depth-limited delegation chains, fail-closed policy condition |
| ⏱️ **Task security** | ChaCha20-Poly1305 encryption, HMAC resume tokens, SHA-256 hash chains, Ed25519 checkpoints, replay protection |

### 🔬 Security Audit

Vellaveto has undergone 43 rounds of adversarial security audit covering 31+ attack classes mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

| Metric | Value |
|--------|-------|
| Audit rounds completed | 43 |
| Attack classes tested | 31+ |
| Total findings triaged | 450+ |
| Findings fixed | 380+ |
| Critical/HIGH findings fixed | 100+ |
| Test count post-audit | 5,190+ |

Key areas covered: tool poisoning, prompt injection, path traversal, SSRF/domain bypass, session fixation, JSON parsing, memory poisoning, elicitation social engineering, audit log tampering, OAuth/JWT validation, SIEM export injection, rug-pull detection, tool squatting, DLP bypass, SSE transport parity, config reload races, Unicode case-folding, IPv6 transition mechanisms, CEF/SIEM injection, and webhook SSRF.

### 📋 Standards Compliance

Vellaveto provides built-in compliance mapping and reporting for major AI security standards:

| Standard | Module | Coverage |
|----------|--------|----------|
| **EU AI Act** | `vellaveto-audit/src/eu_ai_act.rs` | Evidence packs mapped to Art 9, 13-15, 26; readiness gap analysis (not certification), Art 50(2) decision explanations, Art 10 data governance |
| **SOC 2** | `vellaveto-audit/src/soc2.rs` | 22 criteria across CC1-CC9, ~30 capability mappings, evidence reports |
| **MITRE ATLAS** | `vellaveto-audit/src/atlas.rs` | 14 techniques (AML.T0051-T0065), 30+ detection mappings |
| **OWASP AIVSS** | `vellaveto-audit/src/aivss.rs` | Full severity scoring with AI-specific multipliers |
| **NIST AI RMF** | `vellaveto-audit/src/nist_rmf.rs` | All 4 functions (Govern, Map, Measure, Manage) |
| **ISO/IEC 27090** | `vellaveto-audit/src/iso27090.rs` | 5 control domains, readiness assessment |
| **CoSAI** | `vellaveto-audit/src/cosai.rs` | 12 threat categories, 38 threats mapped (see module for coverage matrix) |
| **Adversa AI TOP 25** | `vellaveto-audit/src/adversa_top25.rs` | 25 ranked vulnerabilities mapped (see module for coverage matrix) |
| **ISO/IEC 42001** | `vellaveto-audit/src/iso42001.rs` | AI Management System controls, clause coverage, evidence reports |
| **Cross-Framework** | `vellaveto-audit/src/gap_analysis.rs` | Unified gap analysis across all 7 frameworks |

Generate compliance reports programmatically:
```rust
use vellaveto_audit::{
    eu_ai_act::EuAiActRegistry, soc2::Soc2Registry,
    atlas::AtlasRegistry, nist_rmf::NistRmfRegistry, iso27090::Iso27090Registry,
    cosai::CosaiRegistry, adversa_top25::AdversaTop25Registry,
    iso42001::Iso42001Registry,
    gap_analysis::generate_gap_analysis,
};

// EU AI Act conformity assessment
let eu = EuAiActRegistry::new();
let assessment = eu.generate_assessment(
    vellaveto_types::AiActRiskClass::HighRisk, "Acme Corp", "vellaveto-v3",
);

// SOC 2 evidence report
let soc2 = Soc2Registry::new();
let report = soc2.generate_evidence_report(
    "Acme Corp", "2026-01-01", "2026-12-31",
    &[vellaveto_types::TrustServicesCategory::CC1, vellaveto_types::TrustServicesCategory::CC6],
);

// MITRE ATLAS coverage
let atlas = AtlasRegistry::new();
let coverage = atlas.generate_coverage_report();

// CoSAI threat coverage (12 categories, 38 threats)
let cosai = CosaiRegistry::new();
let cosai_report = cosai.generate_coverage_report();

// Adversa AI TOP 25 coverage matrix
let adversa = AdversaTop25Registry::new();
let adversa_report = adversa.generate_coverage_report();

// ISO/IEC 42001 AI Management System
let iso42001 = Iso42001Registry::new();
let iso42001_report = iso42001.generate_evidence_report();

// Cross-framework gap analysis (all 7 frameworks)
let gap_report = generate_gap_analysis();
println!("Overall coverage: {:.1}%", gap_report.overall_coverage_percent);
```

### ⚠️ Known Limitations

- **Injection detection is a pre-filter, not a security boundary.** Pattern-based detection catches known signatures but can be evaded by encoding, typoglycemia, or paraphrasing. It is one layer in a defense-in-depth strategy.

- **DNS rebinding protection requires HTTP proxy mode.** The HTTP proxy resolves target domains and checks IPs against rules. Not available in stdio proxy mode since the client makes the connection.

- **DLP does not detect split secrets.** Secrets split across multiple JSON fields or fragmented within a field are not reassembled. Treat DLP as a best-effort safety net.

- **No TLS termination.** Use a reverse proxy (nginx, Caddy) in front of Vellaveto for HTTPS.

- **Distributed clustering is opt-in.** The `vellaveto-cluster` crate supports Redis-backed state sharing (approvals, rate limits) across instances, but audit logs remain local to each process. Enable with the `redis` feature flag.

- **Path normalization decode limit.** `normalize_path()` iteratively decodes up to 20 layers, then fails-closed to `"/"` to prevent CPU exhaustion.

- **Checkpoint trust anchor.** Checkpoint signatures use self-embedded Ed25519 keys (TOFU model). Pin a trusted key via `VELLAVETO_TRUSTED_KEY` for stronger guarantees.

## 🏛️ Architecture

```
vellaveto-types             Core types: Action, Policy, Verdict, EvaluationTrace
       |
  +----+----+
  |         |
vellaveto-  vellaveto-       Config parser (TOML/JSON) and built-in presets
config     canonical
  |
vellaveto-engine            Policy evaluation with pre-compiled patterns
  |
  +--------+--------+
  |        |        |
vellaveto- vellaveto- vellaveto-
audit     approval  mcp        Audit logging, approval store, MCP protocol
  |        |        |
  +--------+--------+
           |
     vellaveto-cluster          Distributed state sharing (local + Redis)
           |
  +--------+--------+
  |        |        |
vellaveto-  vellaveto- vellaveto-
server     proxy     http-proxy   HTTP API, stdio proxy, HTTP reverse proxy
```

### Full Workspace Module Map (v4.0)

| Module | Type | Path | Responsibility | Verify |
|--------|------|------|----------------|--------|
| `vellaveto-types` | library | `vellaveto-types/` | Shared contracts (`Action`, `Policy`, `Verdict`, context types) | `cargo test -p vellaveto-types` |
| `vellaveto-engine` | library | `vellaveto-engine/` | Policy compilation/evaluation, constraint matching, normalization | `cargo test -p vellaveto-engine` |
| `vellaveto-config` | library | `vellaveto-config/` | TOML/JSON config parsing, validation, safety defaults | `cargo test -p vellaveto-config` |
| `vellaveto-canonical` | library | `vellaveto-canonical/` | Built-in policy presets and deterministic serialization | `cargo test -p vellaveto-canonical` |
| `vellaveto-audit` | library | `vellaveto-audit/` | Tamper-evident audit chain, checkpoints, SIEM export, observability exporters | `cargo test -p vellaveto-audit` |
| `vellaveto-approval` | library | `vellaveto-approval/` | Human approval queue, deduplication, expiry, resolver audit hooks | `cargo test -p vellaveto-approval` |
| `vellaveto-mcp` | library | `vellaveto-mcp/` | MCP/A2A security managers, inspection, threat detection, ETDI/MINJA/NHI | `cargo test -p vellaveto-mcp` |
| `vellaveto-cluster` | library | `vellaveto-cluster/` | Shared runtime state backend (local and Redis-backed) | `cargo test -p vellaveto-cluster` |
| `vellaveto-server` | binary | `vellaveto-server/` | HTTP API/CLI runtime, RBAC, authn/authz, policy lifecycle endpoints | `cargo test -p vellaveto-server` |
| `vellaveto-proxy` | binary | `vellaveto-proxy/` | Stdio MCP proxy enforcement runtime | `cargo test -p vellaveto-proxy` |
| `vellaveto-http-proxy` | binary | `vellaveto-http-proxy/` | Streamable HTTP + WebSocket MCP reverse proxy with OAuth, session, SSE controls | `cargo test -p vellaveto-http-proxy` |
| `vellaveto-integration` | test-suite | `vellaveto-integration/` | Cross-crate regression, adversarial, and conformance tests | `cargo test -p vellaveto-integration` |
| `sdk/python` | sdk | `sdk/python/` | Python client + LangChain/LangGraph/Composio adapters | `cd sdk/python && pytest` |
| `helm/vellaveto` | deployment | `helm/vellaveto/` | Kubernetes packaging and values templates | `helm lint helm/vellaveto` |
| `fuzz` | fuzzing | `fuzz/` | 24 fuzz targets for parser/protocol/security boundary hardening | `cd fuzz && cargo +nightly fuzz list` |
| `security-testing` | security | `security-testing/` | Pentest harnesses and red-team scenarios | `bash security-testing/run-shannon-pentest.sh` |
| `policies` | config samples | `policies/` | Example and baseline policy bundles | load with `--config policies/*.toml` |
| `examples` | examples | `examples/` | Demo configs and workflows | run `vellaveto serve --config examples/*.toml` |
| `scripts` | tooling | `scripts/` | Automation helpers for local and CI checks | `bash scripts/<script>.sh` |
| `docs` | docs | `docs/` | API, deployment, operations, security guidance | n/a |

### Full Feature Ownership Map

| Feature | Owning module(s) | Runtime entrypoint(s) | Primary tests |
|--------|-------------------|-----------------------|---------------|
| Policy evaluation and constraints | `vellaveto-engine`, `vellaveto-types` | `/api/evaluate`, `vellaveto evaluate` | `vellaveto-engine/tests/`, `vellaveto-integration/tests/` |
| Config parsing and policy loading | `vellaveto-config`, `vellaveto-canonical` | server/proxy startup + reload | `vellaveto-config/tests/`, `vellaveto-server/tests/test_config_*` |
| Tamper-evident audit trail and SIEM export | `vellaveto-audit`, `vellaveto-server` | `/api/audit/*`, `vellaveto verify` | `vellaveto-audit/tests/`, `vellaveto-integration/tests/audit_*` |
| Human-in-the-loop approvals | `vellaveto-approval`, `vellaveto-server` | `/api/approvals/*` | `vellaveto-approval/tests/`, `vellaveto-server/tests/test_routes_*` |
| MCP protocol guardrails and inspection | `vellaveto-mcp`, `vellaveto-proxy`, `vellaveto-http-proxy` | stdio + HTTP proxy tool calls | `vellaveto-mcp/tests/`, `vellaveto-http-proxy/tests/proxy_integration.rs` |
| Streaming SSE schema enforcement | `vellaveto-http-proxy`, `vellaveto-mcp` | Streamable HTTP responses | `vellaveto-http-proxy/tests/proxy_integration.rs` |
| OAuth/JWT and API auth controls | `vellaveto-http-proxy`, `vellaveto-server` | proxy auth middleware, server RBAC routes | `vellaveto-http-proxy/tests/proxy_integration.rs`, `vellaveto-server/tests/test_rbac.rs` |
| Network/path/DNS rebinding defenses | `vellaveto-engine`, `vellaveto-server`, `vellaveto-http-proxy` | path and domain constraints on evaluation | `vellaveto-engine/src/domain.rs`, `vellaveto-integration/tests/path_domain_security.rs` |
| ETDI cryptographic tool trust | `vellaveto-mcp`, `vellaveto-server` | ETDI APIs and CLI signing/verification | `vellaveto-integration/tests/etdi_test.rs` |
| MINJA memory injection defense | `vellaveto-mcp` | memory inspection managers in proxy bridge | `vellaveto-integration/tests/minja_tests.rs` |
| NHI lifecycle and behavioral attestation | `vellaveto-mcp`, `vellaveto-server` | NHI APIs and identity middleware | `vellaveto-integration/tests/nhi_test.rs` |
| Async task security primitives | `vellaveto-mcp`, `vellaveto-http-proxy` | `tasks/*` policy path enforcement | `vellaveto-http-proxy/tests/proxy_integration.rs` |
| Semantic guardrails (LLM-based) | `vellaveto-mcp` | semantic evaluation pipeline | `vellaveto-mcp/src/semantic/`, integration coverage in `vellaveto-integration/tests/` |
| RAG poisoning defense | `vellaveto-mcp` | grounding/retrieval defense path | `vellaveto-mcp/src/rag_defense/` tests |
| A2A protocol security | `vellaveto-mcp` | A2A message classification and proxy service | `vellaveto-mcp/src/a2a.rs` tests, `vellaveto-integration/tests/owasp_mcp_top10.rs` |
| Enterprise controls (mTLS/SPIFFE/OPA/JIT/Threat Intel) | `vellaveto-server`, `vellaveto-mcp`, `vellaveto-cluster` | server runtime integrations and policy hooks (OPA runtime enforcement active) | `vellaveto-server/src/threat_intel.rs` tests, `vellaveto-server/tests/` |
| Observability exporters and traces | `vellaveto-audit`, `vellaveto-integration` | exporter backends and trace propagation | `vellaveto-integration/tests/observability_test.rs`, `vellaveto-audit/tests/proptest_observability.rs` |
| Python SDK integrations (LangChain, LangGraph, Composio) | `sdk/python` | SDK client APIs, middleware callbacks, Composio modifiers | `sdk/python` test suite |
| TypeScript SDK | `sdk/typescript` | HTTP client, types, simulator methods | `sdk/typescript` test suite |
| Go SDK | `sdk/go` | HTTP client, types, functional options | `sdk/go` test suite |
| Policy simulator API | `vellaveto-server` | Evaluate/batch/validate/diff endpoints | `vellaveto-server/src/routes/simulator.rs` tests |
| Fuzzing and adversarial validation | `fuzz`, `security-testing`, `vellaveto-integration` | fuzz targets + red-team scripts | `fuzz/*`, `vellaveto-integration/tests/full_attack_battery.rs` |

### Design Principles

- 🚪 **Fail-closed** — errors, missing policies, and missing parameters all result in denial
- ⚡ **Pre-compiled patterns** — all glob, regex, and domain patterns compiled at policy load time; the evaluation hot path has zero mutex acquisitions and zero regex compilation
- 🗂️ **Tool-indexed evaluation** — policies indexed by tool name at load time for O(matching) instead of O(all policies)
- 🚫 **Zero `unwrap()` in library code** — all error paths return typed errors; panics are reserved for tests only

### ⚡ Performance

All patterns are pre-compiled at load time using:
- **Aho-Corasick automaton** for multi-pattern injection scanning (40 patterns in a single pass)
- **Compiled glob matchers** and **compiled regex** for constraint evaluation
- **Cow-based normalization** to avoid allocations when no transformation is needed
- **Pre-computed verdict reason strings** to eliminate `format!()` on the hot path
- **ASCII fast-path** for Unicode sanitization (skips NFKC for >95% of inputs)

Benchmark results (criterion, single-threaded):

| Scenario | Latency |
|----------|---------|
| Single policy evaluation | 7–31 ns |
| 100 policies | ~1.2 μs |
| 1,000 policies | ~12 μs |
| Origin validation (loopback) | ~10 ns |
| Origin validation (allowlist) | ~440 ns |
| HMAC-SHA256 sign + verify | ~600 ns–1.6 μs |
| Call chain parsing (5 entries) | ~3.8 μs |
| Privilege escalation check | 16–76 ns |
| Audit context build (with OAuth) | ~360 ns |

## 💻 CLI Reference

```bash
# HTTP policy server
vellaveto serve --config policy.toml [--port 3000] [--bind 127.0.0.1] [--allow-anonymous]

# One-shot evaluation (no server needed)
vellaveto evaluate --tool file --function read \
  --params '{"path":"/tmp/x"}' --config policy.toml

# Validate a config file
vellaveto check --config policy.toml

# Output canonical presets as TOML
vellaveto policies --preset dangerous

# Verify audit log integrity
vellaveto verify --audit audit.log [--list-rotated]

# ETDI: Generate Ed25519 keypair for tool signing
vellaveto generate-key --private-key key.priv --public-key key.pub

# ETDI: Sign a tool definition
vellaveto sign-tool --tool read_file --definition schema.json \
  --key key.priv --output signature.json [--expires-in-days 365]

# ETDI: Verify a tool signature
vellaveto verify-signature --tool read_file --definition schema.json \
  --signature signature.json

# Stdio MCP proxy
vellaveto-proxy --config policy.toml [--strict] [--timeout 30] [--trace] \
  -- ./mcp-server --arg1

# HTTP reverse proxy (Streamable HTTP + WebSocket)
vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  [--listen 127.0.0.1:3001] \
  [--session-timeout 1800] \
  [--session-max-lifetime 86400] \
  [--max-sessions 1000] \
  [--audit-log audit.log] \
  [--strict] \
  [--allow-anonymous] \
  [--canonicalize] \
  [--ws-max-message-size 1048576] \
  [--ws-idle-timeout 300] \
  [--ws-message-rate-limit 100] \
  [--grpc] \
  [--grpc-port 50051] \
  [--grpc-max-message-size 4194304] \
  [--upstream-grpc-url <url>]
```

## 🧑‍💻 Development

```bash
# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets

# Format
cargo fmt --check

# Security audit
cargo audit

# Run criterion benchmarks
cargo bench --workspace

# Build release (thin LTO, single codegen unit, stripped)
cargo build --release

# Fuzz testing (requires nightly)
cd fuzz && cargo +nightly fuzz list
cargo +nightly fuzz run fuzz_json_rpc_framing -- -max_total_time=60

# Reload policies without restart
kill -HUP $(pidof vellaveto-server)
```

### 🔄 CI Pipeline

11 workflows cover CI, security, publishing, and deployment:

| Workflow | Trigger | Description |
|----------|---------|-------------|
| 🧹 **CI** | push, PR, manual | `cargo fmt`, `cargo check`, `cargo clippy`, `cargo test`, `unwrap()` hygiene, fuzz compilation, benchmarks, release build |
| 🔐 **Security Audit** | push, PR, schedule | `cargo audit` for dependency CVEs |
| 🚫 **Cargo Deny** | push, PR | License and advisory checks |
| 📋 **Dependency Review** | PR | New dependency risk assessment |
| 🔒 **Scorecard** | push, schedule | OpenSSF supply-chain scorecard |
| 📦 **Provenance & SBOM** | push (main) | SLSA provenance attestation + CycloneDX SBOM |
| 🐳 **Docker Publish** | push (main, tags) | Multi-stage build, GHCR push, Trivy vulnerability scan |
| 🏷️ **Release** | tag push (`v*`) | Static musl binaries, checksums, SBOM, GitHub Release |
| 📖 **Docs** | push (main) | Rustdoc build and GitHub Pages deployment |
| 🐍 **PyPI Publish** | tag push (`v*`) | Python SDK test matrix (3.9–3.12), trusted publishing |
| 📦 **crates.io Publish** | manual | Dependency-ordered workspace crate publishing |

## 📁 Project Structure

| Path | Role |
|------|------|
| `vellaveto-types/` | Core contracts and shared runtime types |
| `vellaveto-engine/` | Policy evaluation and constraint execution |
| `vellaveto-audit/` | Audit chain, checkpoints, SIEM export, observability |
| `vellaveto-approval/` | Approval queue lifecycle and persistence |
| `vellaveto-config/` | Config parsing and validation |
| `vellaveto-canonical/` | Canonical policy presets |
| `vellaveto-mcp/` | MCP/A2A security managers and inspection |
| `vellaveto-cluster/` | Shared state backends (local/Redis) |
| `vellaveto-server/` | HTTP API server + CLI binary |
| `vellaveto-proxy/` | Stdio MCP proxy binary |
| `vellaveto-http-proxy/` | Streamable HTTP reverse proxy binary |
| `vellaveto-integration/` | Cross-crate adversarial and integration tests |
| `sdk/python/` | Python SDK and framework adapters |
| `sdk/typescript/` | TypeScript SDK (zero runtime deps) |
| `sdk/go/` | Go SDK (zero external deps, stdlib only) |
| `policies/` | Policy samples and templates |
| `examples/` | Demo workflows and reference configs |
| `fuzz/` | 22 fuzzing harnesses and targets |
| `helm/` | Kubernetes chart packaging |
| `scripts/` | Project automation scripts |
| `docs/` | Operations/API/security documentation |
| `dist/` | Source distribution artifacts (zip) |

### Repository Hygiene

- GitHub-facing source stays in product modules, `docs/`, CI workflows, and release metadata.
- Local collaboration/planning artifacts are intentionally kept out of Git history and ignored (`.collab/`, `CODEX_PLAN.md`, `IMPROVEMENT_PLAN.md`, `SWARM_FINDINGS_PLAN.md`, `TASKS.md`, `CLAUDE.md`).
- Large or ephemeral outputs (logs, local DBs, fuzz/build artifacts) are ignored by default.

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [Framework Quickstart](docs/QUICKSTART.md) | Integration guides for Anthropic, OpenAI, LangChain, LangGraph, MCP |
| [15-Minute Secure Start](docs/SECURE_QUICKSTART_15_MIN.md) | End-to-end deny-by-default walkthrough with audit verification |
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, Kubernetes (Helm), and bare metal installation |
| [Operations Runbook](docs/OPERATIONS.md) | Monitoring, troubleshooting, and maintenance procedures |
| [Security Model](docs/SECURITY_MODEL.md) | Trust boundaries, data flows, storage, and residual risks |
| [Security Hardening](docs/SECURITY.md) | Security configuration best practices |
| [Security Guarantees](docs/SECURITY_GUARANTEES.md) | Normative, falsifiable security contract |
| [Assurance Case](docs/ASSURANCE_CASE.md) | Claim -> evidence -> reproduce map |
| [Verify Release Artifacts](docs/VERIFY_RELEASE_ARTIFACTS.md) | Checksums, SBOM, and provenance verification playbook |
| [Strategic Review](docs/STRATEGIC_REVIEW_POSITIONING_TRUST_GROWTH.md) | Positioning, trust, and growth execution plan |
| [Session Auth and Passkey Plan](docs/SESSION_AUTH_PASSKEY_PLAN.md) | Phased integration plan for OAuth sessions, secure token storage, and passkey onboarding |
| [Quantum Migration Runbook](docs/quantum-migration.md) | Phased TLS PQ rollout and rollback gates |
| [Benchmarks](docs/BENCHMARKS.md) | Reproducible performance benchmarks and methodology |
| [API Reference](docs/API.md) | Complete HTTP API documentation |
| [MCPSEC Benchmark](mcpsec/README.md) | MCP Security Benchmark Framework (Apache-2.0) |
| [Roadmap](ROADMAP.md) | Current release status and upcoming phases |
| [Changelog](CHANGELOG.md) | Version history and release notes |
| [Contributing](CONTRIBUTING.md) | Development rules, commit format, release checklist |

## 📚 References

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP](https://arxiv.org/pdf/2504.08623)

## 📄 License

This project is dual-licensed under the [GNU Affero General Public License v3.0](LICENSE) and a commercial license. See [LICENSING.md](LICENSING.md) for details.

If you modify Vellaveto and offer it as a network service, the AGPL-3.0 requires you to make your source code available. For proprietary use or managed service offerings without source disclosure, contact **paolovella1993@gmail.com** for a commercial license.
