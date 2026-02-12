# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
    - P0 sender-constrained OAuth (DPoP) enforcement path in `sentinel-http-proxy`
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
  - Added rustls provider KEX-group policy application in `sentinel-server` TLS setup with explicit downgrade warnings when hybrid is requested but unavailable.
  - Added example config snippet documenting `tls.kex_policy` usage.

- **Source distribution packaging**:
  - Added repository source ZIP artifact under `dist/` generated from tracked files at `HEAD` (`git archive`).
  - Added README guidance for generating and checksumming source distribution ZIPs locally.

### Refactor

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
  - Reduced `build_oauth_test_state_full` argument count in `sentinel-http-proxy` integration tests.
  - Improves maintainability and readability of OAuth test setup paths.

- **MCP code hygiene cleanup**:
  - Removed unnecessary `#[allow(dead_code)]` annotations where no longer needed.

### Style

- **Format string interpolation**:
  - Replaced `format!("{}", var)` with `format!("{var}")` across core crates
  - Applied to sentinel-types, sentinel-engine, sentinel-audit, sentinel-approval, sentinel-mcp
  - Cleaner, more readable format strings
  - Fixes `clippy::uninlined_format_args` pedantic warnings

- **Option chain simplification**:
  - Replaced `map().unwrap_or()` with `map_or()` for cleaner Option handling
  - Applied to sentinel-types, sentinel-engine (deputy, legacy, lib)
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
  - Added bounded `HashMap::with_capacity` hints in `sentinel-mcp` runtime/session managers:
    - `token_security`
    - `task_state`
    - `auth_level`
    - `output_validation`
    - `workflow_tracker`
  - Updated `PolicyEngine` constructors to initialize `domain_norm_cache` using `MAX_DOMAIN_NORM_CACHE_ENTRIES`-bounded capacity.

### Security

- **Call-chain header hardening (`sentinel-http-proxy`)**:
  - Enforced fail-closed `X-Upstream-Agents` validation across MCP method paths.
  - Added explicit rejection for headers whose entry count exceeds `limits.max_call_chain_length` (instead of truncation).
  - Added regression coverage for malformed and over-limit call-chain headers on tool-call, pass-through, sampling, resource, and task paths.

- **OPA runtime decision enforcement (`sentinel-server`)**:
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

- **DPoP failure observability (`sentinel-http-proxy`)**:
  - Added dedicated DPoP counters: `sentinel_oauth_dpop_failures_total` (reason-labeled) and `sentinel_oauth_dpop_replay_total`.
  - Added explicit audit events for DPoP validation failures with `dpop_reason`, `dpop_mode`, `oauth_subject`, and header/session context.
  - Added integration coverage for missing-proof and replay-detected audit paths.

- **OAuth/DPoP startup and replay hardening (`sentinel-http-proxy`)**:
  - Added startup guardrails for pass-through mode: `--oauth-pass-through` now requires explicit `--unsafe-oauth-pass-through`, RFC 8707 expected resource binding, and DPoP `required` mode.
  - Added hardened OAuth profile support (`--oauth-security-profile hardened`) to enforce sender-constrained posture at startup.
  - Added startup warnings when OAuth is enabled with weak defaults (`dpop_mode=off` or missing expected resource) in standard profile.
  - Enforced sender-constrained token binding in DPoP `required` mode: access tokens must contain `cnf.jkt`, and runtime now verifies `cnf.jkt` against the presented DPoP proof key thumbprint (RFC 7638).
  - Hardened DPoP replay cache input handling by bounding untrusted `jti`/replay-key size and keying replays by `jti:ath` when token binding is available.

- **TLS metadata observability (`sentinel-server`)**:
  - Added evaluate-path extraction of sanitized forwarded TLS handshake metadata (`protocol`, `cipher`, `kex_group`).
  - Trusted forwarded TLS metadata headers only when the direct connection peer is a configured trusted proxy.
  - Trusted `X-Forwarded-Proto` for HSTS decisions only when the direct connection peer is a configured trusted proxy.
  - Fixed `X-Principal` trust check to use direct trusted-proxy peer identity (not derived client IP), preserving per-principal rate-limit attribution behind trusted proxy chains.
  - Added per-principal rate-limit integration coverage for trusted proxy + `X-Forwarded-For` chains with stable `X-Principal` identity.
  - Rejected control characters in trusted `X-Principal` header values before principal-key derivation.
  - Treated missing trusted-proxy request context as untrusted when evaluating forwarded TLS metadata (fail-safe default).
  - Added `sentinel_forwarded_header_rejections_total{header=...}` metric and incremented it when untrusted `X-Forwarded-Proto` or forwarded TLS metadata headers are ignored.
  - Included TLS metadata in audit entry metadata for `/api/evaluate` decisions.

- **HTTP proxy request-id hardening (`sentinel-http-proxy`)**:
  - Rejected control characters in client-supplied `X-Request-Id` values before echoing to response headers.

- **HTTP proxy forwarded-header trust hardening (`sentinel-http-proxy`)**:
  - Added trusted-proxy context propagation based on direct peer IP (`ConnectInfo`) and `SENTINEL_TRUSTED_PROXIES`.
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
  - Keeps outbound HTTP client behavior consistent across `sentinel-server`, `sentinel-http-proxy`, `sentinel-audit` exporters, and `sentinel-mcp` cloud backends.
  - Updated `sentinel-server` TLS provider selection to explicitly use rustls `aws-lc-rs` provider, avoiding runtime panics when multiple rustls providers are enabled in the dependency graph.
  - Verified compile coverage for key reqwest consumers, including `sentinel-audit --features observability-exporters` and `sentinel-mcp --features llm-cloud`.

- **DLP pattern validation at startup (SEC-006)**:
  - Both `sentinel-server` and `sentinel-http-proxy` now validate all DLP patterns compile successfully during startup
  - If any pattern fails to compile, the application fails to start rather than silently skipping secret detection
  - Prevents silent gaps in DLP coverage from malformed patterns

- **Injection pattern validation at startup**:
  - Added `validate_injection_patterns()`, `is_injection_available()`, and `injection_pattern_count()` functions
  - Both server and proxy now validate injection patterns compile at startup
  - Consistent with DLP validation for defense-in-depth

- **Health endpoint security scanning status (SEC-006)**:
  - Enhanced `/health` endpoint in both `sentinel-server` and `sentinel-http-proxy` to report scanning subsystem availability
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
- New `sdk/python/sentinel` package for LangChain/LangGraph integration
- `SentinelClient` — Sync/async HTTP client supporting httpx and requests backends
- `SentinelCallbackHandler` — LangChain callback for intercepting tool calls
- `SentinelToolGuard` — Decorator for guarding individual tools
- `create_guarded_toolkit()` — Wraps existing LangChain toolkits with Sentinel guards
- `create_sentinel_node()` — LangGraph node factory for policy evaluation
- `create_sentinel_tool_node()` — Combined tool execution + policy evaluation node

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
- Added `regex` dependency to `sentinel-config`

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
- **JSON-RPC error code consolidation**: Moved hardcoded error codes into `sentinel-types/src/json_rpc.rs` module with named constants for all standard JSON-RPC 2.0 codes and Sentinel application-specific codes (-32001 to -32021)
- **OpenTelemetry upgrade**: Upgraded from 0.22 to 0.30, eliminating major dependency duplicates (axum 0.6→0.8, hyper 0.14→1.x, http 0.2→1.x, h2 0.3→0.4, tower 0.4→0.5)
- **Workspace dependency unification**: Unified reqwest to 0.13 as workspace dependency with "json" and "query" features
- **Security manager initialization**: Phase 1-10 security managers (task_state, circuit_breaker, auth_level, deputy, shadow_agent, schema_lineage, sampling_detector, etdi, memory_security, nhi) now properly initialized from PolicyConfig instead of TODO placeholders
- **Crate metadata**: Added description field to all 9 crates that were missing it (sentinel-types, sentinel-engine, sentinel-audit, sentinel-mcp, sentinel-canonical, sentinel-config, sentinel-approval, sentinel-proxy, sentinel-integration)

### Added

- **Bracket notation for parameter paths**: Support `params.items[0].value` syntax in parameter constraints for array element access
- **Evaluation tracing**: Add `?trace=true` query parameter to get full OPA-style decision traces
- **Audit heartbeat entries**: Periodic heartbeat entries for detecting log truncation/deletion attacks
- **DLP observability metrics**: `sentinel_dlp_findings_total`, `sentinel_dlp_scan_duration_seconds` histograms
- **Anomaly detection metrics**: `sentinel_anomaly_detections_total` counter with agent/tool labels
- **Circuit breaker metrics**: `sentinel_circuit_breaker_state_changes_total`, state duration histograms
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
- **FIND-027** — Eliminated `expect()`/`unwrap()` violations in `sentinel-mcp` library code per no-panic policy:
  - `cache.rs`: Replaced `expect()` with const `FALLBACK_CACHE_SIZE` and `unwrap_or()`
  - `task_security.rs`: Changed `generate_resume_token` to return `Result`, propagating HMAC and RNG errors
- **FIND-021/FIND-002** — Standardized workspace dependency management:
  - `sentinel-config`: Use `workspace = true` for serde, serde_json
  - `sentinel-audit`: Use `workspace = true` for tokio, tracing
  - `sentinel-proxy`: Use `workspace = true` for tracing

### Added

#### Phase 14: A2A Protocol Security
- **A2A Message Classification** — Parse and classify A2A JSON-RPC messages (message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe) with method normalization to prevent Unicode bypass attacks
- **Action Extraction** — Convert A2A messages to Sentinel Actions for policy evaluation using tool pattern "a2a" with function-specific mapping (message_send, message_stream, task_get, task_cancel, task_resubscribe)
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
  - `sentinel generate-key` — Generate Ed25519 keypair for tool signing
  - `sentinel sign-tool` — Sign a tool definition with expiration support
  - `sentinel verify-signature` — Verify a tool signature against its definition

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
- **Policy Validation CLI** — Enhanced `sentinel check` command with:
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
- **MITRE ATLAS Threat Mapping** — Registry of 14 ATLAS techniques (AML.T0051-T0065) with detection mappings for 30+ Sentinel detection types, coverage reports, and audit event enrichment
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

Initial production release of Sentinel, a runtime security engine for AI agent tool calls.

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

[1.0.0]: https://github.com/paolovella/sentinel/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/paolovella/sentinel/releases/tag/v0.1.0
