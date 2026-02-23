# CLAUDE.md — Vellaveto Project Instructions

> **Project:** Vellaveto — MCP Tool Firewall
> **State:** v4.0.0-dev (Phases 1–25.1/25.2/25.6 + 26 + 27 + 29 + 30 + 33 + 34 + 35 + 37 + 38 + 39 + 40 + 41 + 43 complete, 194 audit rounds)
> **Version:** 4.0.0-dev
> **License:** AGPL-3.0 dual license (see LICENSING.md)
> **Tests:** 7,338 Rust tests + 361 Python SDK tests + 106 Go SDK tests + 111 TypeScript SDK tests, zero warnings, zero `unwrap()` in library code
> **Fuzz targets:** 24
> **CI workflows:** 12 (16 jobs)
> **Domain:** [www.vellaveto.online](https://www.vellaveto.online) (Cloudflare Pages)
> **Updated:** 2026-02-23

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
| Audit Store: AuditStoreBackend, AuditQueryParams, AuditQueryResult, AuditStoreStatus | `vellaveto-types/src/audit_store.rs` |
| Time utilities: parse_iso8601_secs | `vellaveto-types/src/time_util.rs` |
| Tests (~180) | `vellaveto-types/src/tests.rs` |
| **vellaveto-engine** | |
| Policy evaluation | `vellaveto-engine/src/lib.rs` |
| ABAC engine + Cedar-style evaluation | `vellaveto-engine/src/abac.rs` |
| Least-agency tracker | `vellaveto-engine/src/least_agency.rs` |
| **vellaveto-audit** | |
| Module root + AuditLogger + rotation + verification | `vellaveto-audit/src/lib.rs` |
| Redaction, checkpoints, Merkle proofs, events | `vellaveto-audit/src/*.rs` |
| Compliance registries: EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, OWASP ASI, gap analysis | `vellaveto-audit/src/{eu_ai_act,soc2,cosai,adversa_top25,iso42001,owasp_asi,gap_analysis}.rs` |
| Data governance registry (Art 10) | `vellaveto-audit/src/data_governance.rs` |
| ZK audit: Pedersen commitments, witness store, Groth16 circuit, batch prover, scheduler | `vellaveto-audit/src/zk/{mod,pedersen,witness,circuit,prover,scheduler}.rs` |
| Audit sink trait + PostgreSQL sink (feature-gated) | `vellaveto-audit/src/sink.rs`, `vellaveto-audit/src/sink/postgres.rs` |
| Audit query trait + file/PostgreSQL backends | `vellaveto-audit/src/query.rs`, `vellaveto-audit/src/query/{file,postgres}.rs` |
| Access review report generator + HTML renderer | `vellaveto-audit/src/access_review.rs` |
| OTLP exporter, archive | `vellaveto-audit/src/observability/otlp.rs`, `vellaveto-audit/src/archive.rs` |
| Tests (~421) | `vellaveto-audit/src/tests.rs` |
| **vellaveto-config** | |
| Module root + PolicyConfig + validation | `vellaveto-config/src/lib.rs`, `vellaveto-config/src/config_validate.rs` |
| Detection, enterprise, ETDI, MCP protocol, threat detection | `vellaveto-config/src/*.rs` |
| Advanced: ABAC, compliance, extension, FIPS, gateway, gRPC, transport | `vellaveto-config/src/*.rs` |
| Governance config | `vellaveto-config/src/governance.rs` |
| Audit store config (PostgreSQL dual-write) | `vellaveto-config/src/audit_store.rs` |
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
| Audit store API routes (search, status, entry by ID) | `vellaveto-server/src/routes/audit_store.rs` |
| SOC 2 Access Review route (JSON/HTML) | `vellaveto-server/src/routes/compliance.rs` |
| Dashboard | `vellaveto-server/src/dashboard.rs` |
| Setup wizard | `vellaveto-server/src/setup_wizard.rs` |
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
| Workflow DAG constraints (S8–S9) | `formal/tla/WorkflowConstraint.tla` + `.cfg` |

---

## What's Done (DO NOT rebuild)

All 24 phases + Phase 25 (sub-phases 25.1/25.2/25.6) + Phase 26 + Phase 27 + Phase 29 + Phase 30 + Phase 33 + Phase 34 + Phase 35 + Phase 37 + Phase 38 + Phase 40 + Phase 41 + Phase 43 implemented, tested, and hardened through 194 audit rounds. Details in CHANGELOG.md.

- **Core Engine:** Policy evaluation with glob/regex/domain matching, path traversal protection, DNS rebinding defense, context-aware policies (time windows, call limits, agent ID, action sequences)
- **Audit:** Tamper-evident logging (SHA-256 chain, Merkle proofs, Ed25519 checkpoints, rotation), export (CEF/JSONL/webhook/syslog), immutable archive with retention, centralized audit store with PostgreSQL dual-write (Phase 43)
- **Security Detections:** Injection (Aho-Corasick + NFKC), rug-pull, DLP (5-layer decode), tool squatting (Levenshtein + homoglyph), memory poisoning, semantic injection (TF-IDF), behavioral anomaly (EMA), cross-request exfiltration tracking, multimodal injection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM + stego)
- **Auth & Transport:** OAuth 2.1/JWT/JWKS, CSRF, rate limiting, MCP 2025-06-18 compliance, 6 deployment modes (HTTP, stdio, HTTP proxy, WebSocket proxy, gRPC proxy, MCP gateway)
- **Advanced Authorization (Phase 21):** ABAC with forbid-overrides, capability-based delegation tokens, least-agency tracking, identity federation, continuous authorization
- **MCP Gateway (Phase 20):** Multi-backend routing, health state machine, session affinity, tool conflict detection
- **Compliance (Phase 19):** EU AI Act registry + Art 50 transparency marking, SOC 2 evidence, CoSAI 38/38, Adversa TOP 25 25/25, 8-framework gap analysis, OTLP export, Merkle inclusion proofs
- **EU AI Act Final Compliance (Phase 24):** Art 50(2) automated decision explanations (VerdictExplanation at configurable verbosity), Art 10 data governance registry (DataGovernanceRecord with classification/purpose/provenance/retention), decision explanation injection into `_meta`
- **MCP Ecosystem:** Tool registry with trust scoring, elicitation interception, sampling enforcement, semantic guardrails (LLM-based), A2A protocol security
- **Transport (Phases 17–18):** WebSocket bidirectional proxy, gRPC reverse proxy (tonic), extension registry, transport discovery/negotiation/fallback
- **Research (Phase 23):** Red team mutation engine, FIPS 140-3 mode, Rekor transparency log, stateful session guards
- **Audio/Video Inspection (Phase 25.1/25.2):** WAV LIST/INFO metadata extraction, MP3 ID3v2 tag parsing (text/comment/lyrics frames, syncsafe integers, 4 encodings), MP4 moov/udta/meta/ilst metadata, WebM EBML tag extraction, FLAC/OGG/AVI magic bytes detection
- **Stateless Protocol Abstraction (Phase 25.6):** `RequestContext` trait for session-agnostic policy evaluation, `StatefulContext` adapter for SessionState, `StatelessContextBlob` struct for future stateless HTTP mode (signed per-request context with HMAC-SHA256, expiry)
- **Developer Experience (Phase 22):** Policy simulator API, CLI simulate, GitHub Action, dashboard SVG charts
- **Adversarial Hardening:** 5 pentest rounds (FIND-043–084 + Phase 23 Critical/High + Medium), RwLock poisoning hardened, PDF byte-level parsing, session guard fail-closed, Rekor canonical JSON, JPEG stego loop bound, PDF 4096-byte dict look-back, whitespace-normalized injection scan, EXIF 4-char min extraction, PDF hex string parsing, stego limitations documented, Phase 27 adversarial audit (FIND-P27-001–007: DNS amplification DoS on /health cached, mutex poisoning propagated, SSRF dns_name validation, instance_id dot validation, effective_instance_id cached at startup), Phase 29 adversarial audit round 41 (FIND-R41-001–015: header allowlist on forwarded requests, shell injection prevention for stdio command, circuit breaker OOM bound, response body size limit, stdio zombie process kill-on-timeout, exec graph node limit, gateway URL scheme validation, transport overrides count bound, stderr capture, control character log injection, glob key validation), Round 42 (FIND-R42-002–020: transport preference header dedup+cap, URL host parser SSRF via userinfo/@/IPv6, circuit breaker capacity fail-closed, exec graph metadata-before-bounds-check, agent trust graph session limit, backend URL scheme validation, wildcard glob coexistence rejection, half-open thundering herd prevention, DOT language injection escaping, failure_count saturating arithmetic, duplicate protocol validation, clock error logging, path parameter length validation, self-delegation rejection, fallback response body bounded, rotation manifest start_hash), Round 43 (FIND-R43-001–035: stdio pipe deadlock fixed via concurrent stdout read, subprocess environment cleared, kill_on_drop(true), 5xx circuit breaker corrected, stale Open→HalfOpen success discarded, Merkle leaf pruning exclusion, manifest skip-missing-files verification, NHI terminal-state enforcement, unbounded trust_edges/privilege_levels/trusted_agents capped, cleanup() auto-invoked, Unicode format char validation, case-insensitive self-delegation, match-all glob pattern rejection, URL-encoded %40 userinfo, IPv6 gRPC URL brackets, gateway counter saturating_add, WebSocket URL prefix-only replacement, dangerous status code blocking, exec_graph edge validation/dedup/self-loop rejection, escape_dot pipe+null, roots dedup, NHI body field validation, TOCTOU delegation fix, DeputyError redaction, backend ID validation, tool prefix uniqueness, UTF-8 safe gateway truncation), Round 44 (FIND-R44-001–008), Round 45 (FIND-R45-001–015: GET /mcp full security parity with POST — session ownership binding, agent identity validation, call chain validation, audit logging, rug-pull detection in GET SSE path, output schema validation, gateway mode rejection, session touch/request_count, error message normalization, Last-Event-ID generic errors), Round 46 (~177 findings across P1/P2/P3: fail-closed defaults for ToolSensitivity/NhiIdentityStatus/ABAC NotIn, MemoryEntry trust consistency, deny_unknown_fields on security structs, relay channel bounds, Merkle rotation hardening, SDK input validation/redaction/thread safety, config pattern length limits, JSON depth validation, token budget caps), Round 47 (3 P0 + 12 P1: unbounded intent_chains capped at 10K, SDK payload format mismatch fixed — Python/Go/TS now send flattened fields matching server's `#[serde(flatten)]`, async response body size limit, ZK witness restore-on-failure, ES retry with exponential backoff, OTLP stub error on non-empty batch, ES partial failure detection, ABAC CompiledPathMatcher with globset parity, MINJA trust decay fail-closed on corrupt timestamps, ZK commitments endpoint bounded at 500K entries, SDK approval API paths corrected, TS evaluate extracts verdict fields, Go/TS ZK Audit methods added, 30 P2 + 22 P3: ABAC IDNA normalization, RwLock poison recovery, max_calls_in_window overflow error, no-op context warn!, infix wildcard warning, validate_finite for 5 types, Policy::validate(), UpstreamBackend::validate(), LeastAgencyTracker poisoned lock logging, MAX_PARAMETERS_SIZE 1MB, webhook/streaming URL scheme validation, redaction fail-closed at max depth, ZK scheduler exponential backoff, MAX_COMPILED_POLICIES 10K, FallbackBehavior::Allow warning, serialization errors return HTTP 500, MAX_DASHBOARD_AUDIT_ENTRIES 1K, MAX_DISCOVERED_TOOLS_PER_SESSION 10K, proxy env clearing), Round 48 (2 P1 + 10 P2 + 4 P3: WS canonicalization fail-closed across 6 message types closing TOCTOU gap, Action::validate() fail-closed on serialization failure, ABAC NaN risk.score treated as max risk preventing Forbid bypass, ProvenanceNode/AbacEntity/NhiAgentIdentity/NhiDelegationLink/MemoryNamespace/NhiBehavioralBaseline validate() bounds on deserialized collections, exec graph session path validation, discovery sensitivity param validation, SamplingStats flagged_patterns truncated at 1K, Policy deny_unknown_fields, truncate_for_log max_len<4 guard, WS extract_strings_recursive parts bounded at 1K), Round 49 (6 P1 + 22 P2 + 17 P3: EvaluationContext/StatelessContextBlob collection bounds enforced preventing pre-sanitization OOM, AccessReviewEntry.usage_ratio validate_finite preventing NaN threshold bypass, ZK audit mutex poison details redacted from client responses, list_graphs tool filter iteration capped at 10K, session guard violation/anomaly counters saturating_add preventing overflow lock bypass, ETDI is_expired() UTC-only validation preventing timezone bypass, AgentIdentity.claims bounded at 64, ShadowAiReport/governance vectors bounded matching runtime caps, FederationTrustAnchor.identity_mappings bounded at 64, ABAC path normalization uses bounded iterations, MaxChainDepth off-by-one fixed to >= for consistency, circuit breaker saturating arithmetic, dashboard error leak + control char validation, audit export parameter validation, shadow AI discovery lock poisoning fail-closed, access review timestamp UTC normalization, SOC 2 access review entry count guard, ZkVerifyRequest deny_unknown_fields, legacy infix wildcard fail-closed, ABAC absent claim returns false not empty string, AbacPolicy/PrincipalConstraint/ActionConstraint/ResourceConstraint validate() bounds, FederationTrustAnchor comprehensive validate(), MAX_ATTESTATION_CHAIN_DEPTH constant, html_escape '/' per OWASP, dashboard/audit MAX_LOADED_ENTRIES 500K guards, BehavioralAnomaly MAX_DECAY_SESSIONS eviction, AsyncTaskPolicy error log upgrade, strict UTF-8 domain normalization, build_tool_index sorted invariant asserts, no-op condition compile-time warnings, InjectionDetector from_config None warning, FallbackBehavior::Allow tracing::error, session guard transition history bounds, 19 POST body structs deny_unknown_fields), Round 50 (6 P1 + 12 P2 + 10 P3: Policy::validate() fail-closed on Conditional serialization failure, NhiDelegationChain.max_depth hard-capped at 20 preventing attacker bypass, TS SDK evaluate() target_paths/target_domains added, federation JWT nbf+aud validation enabled, federation JWKS OOM via bounded chunked read, SecureTask state_chain/seen_nonces bounded, CapabilityGrant allowed_paths/domains bounded at 1000, DidPlcGenesisOperation 4-vector validate(), ToolSignature.rekor_entry 64KB bound, identity mapping template injection sanitized, unverified JWT issuer re-checked post-verification, kidless JWK wildcard match rejected, JWK algorithm explicit enum mapping, issuer_pattern length-bounded/bare-* rejected, jwks_uri SSRF private IP validation, OAuth JWKS OOM bounded, issuer_pattern consecutive wildcard normalization, SecureTask/TaskResumeRequest resume_token Debug redacted, active_hours 0-23 validation, AbacCondition.value 8KB bound, FederatedClaims extra bounded at 50, RwLock write-poisoning clears cache, call_chain serialization error logged, SSE injection all_matches capped at 1000, JWKS cache TTL/timeout minimums enforced, extract_claim_value per-element bounds), Round 51 (2 P1 + 14 P2 + 11 P3: float scores [0.0,1.0] range-validated across 6 types files preventing negative threshold bypass, ToolSignature.is_expired() ISO 8601 format validation preventing malformed never-expire timestamps, SessionState backend_sessions/gateway_tools/abac_granted_policies/known_tools/flagged_tools bounded, request_count/elicitation_count saturating_add, origin wildcard warning, FederationConfig expected_audience validated, governance config control character validation, Python async client retry with exponential backoff, Content-Length malformed value handling, call_chain entry validation, StatelessContextBlob signature format validation, CapabilityToken temporal ordering, NhiDelegationLink self-delegation+temporal ordering, UpstreamBackend SSRF validation, ExtensionDescriptor/ProvenanceNode/ToolMetadata/projector types bounded, JitAccessManager global cap+field bounds, tenant ID not leaked), Round 52 (8 P1 + 18 P2 + 11 P3: EvaluationContext previous_actions control char validation preventing ForbiddenActionSequence bypass, call_chain Unicode format char detection (zero-width/bidi/BOM), StatelessContextBlob lowercase-only hex signature canonicalization, WebSocket DLP parameter scanning + memory poisoning + OAuth expiry parity with HTTP handler, SessionState pub→pub(crate) preventing bounded-method bypass, A2A response body MAX_A2A_RESPONSE_SIZE=16MB, shadow_ai_discovery lock fail-closed unwrap_or(true), ToolSignature Debug redaction of signature+public_key, audit sequence counters Relaxed→SeqCst preventing duplicate sequence numbers, Merkle verify_proof MAX_PROOF_DEPTH=64, archive MAX_ARCHIVE_FILE_SIZE=512MB, access_review NaN/Infinity HTML guard + MAX_PER_AGENT_SET_SIZE, call_counts key length validation, StatelessContextBlob per-entry MAX_ENTRY_LEN=256, NhiBehavioralDeviation severity [0.0,1.0] + MAX_DEVIATIONS=256, RiskFactor weight/value [0.0,1.0] range validation, RiskScore MAX_FACTORS=256, C1 control chars (0x80-0x9F) added to governance/abac/transport config validation, relay Allow/Forward audit logging + orphaned pending_requests cleanup, semantic guardrails intent_chains LRU eviction, ToolSignature validate() string field bounds), Round 53 (2 P0 + 8 P1: constant_time_eq HMAC verification compiler optimization bypass via black_box, tier_override silent license bypass logged, LicensingConfig Debug redaction, SystemTime fail-closed on expiry, generate_license_key test-only, webhook timestamp replay 300s window, billing webhook rate limiting, BillingConfig/LicensingConfig validate() wired, CSP meta tag, email entity encoding, deny_unknown_fields on 5 billing structs, LicensingConfig validate() with C0/C1/DEL rejection), Round 55 (72 P2: setup wizard CSRF+session+TOML generation, SDK Go ProjectSchema validation, gRPC transport parity for injection/DLP/behavioral, RAG defense config bounds, least-agency tracker bounds, injection detection improvements, route handler hardening), Round 56 (91 P3, ~72 fixed: deny_unknown_fields on 20+ config structs, custom Debug impls redacting secrets on 6 types — AgentFingerprint/SessionGuardConfig/SessionEvent/FederationResolver/BillingState/WizardSession, saturating_add on tool_namespace access_count, MAX_DLP_FINDINGS=1000 cap, MAX_SESSIONS=100K in sampling_detector, MultimodalConfig validate()+deny_unknown_fields, safe u128→u64 conversions in red_team/multimodal, #[must_use] on evaluate_action methods, #[non_exhaustive] on AbacDecision, code deduplication — is_unicode_format_char/derive_resolver_identity/default_true, constant extraction — MAX_CONDITIONS_SIZE/MAX_TIMESTAMP_LEN/MAX_CALL_CHAIN_FIELD_LEN/MAX_REQUEST_BODY_SIZE/MAX_SESSION_ID_LENGTH/THRESHOLD_OPTIMAL/DEFAULT_AUTO_REVOKE_SECS, GrpcTransportConfig validate() with MAX_GRPC_MESSAGE_SIZE=256MB, federation failure events fail-closed Deny, SDK timeout alignment 10s, pub(crate) visibility tightening, OWASP html_escape '/' addition, CORS PUT method, validate_path_param in governance routes), Round 57 (100 P4, ~84 fixed: glob_match deduplicated into shared util.rs from 4 copies across transparency/extension_registry/capability_token/nl_policy, html_escape deduplicated — dashboard pub(crate) with setup_wizard delegating, FORWARDED_HEADERS/MAX_RESPONSE_BODY_BYTES centralized in proxy/mod.rs, validate_path_param_core extracted, parse_iso8601_secs shared in new time_util.rs replacing minja.rs inline parser, governor_check_to_retry_after extracted deduplicating rate limiter check() logic, thiserror migration for AttestationError/NamespaceError/SamplingDenied, deny_unknown_fields on ~25 config structs — GatewayConfig/BackendConfig/FipsConfig + 8 detection + 5 enterprise + 4 ETDI, validate() added on ZkBatchProof/ZkVerifyResult/ZkSchedulerStatus/DeploymentInfo/ServiceEndpoint/NhiStats/NhiCredentialRotation/ToolAttestation/FipsConfig, validate_finite()→validate() normalized on UnregisteredAgent/ShadowAiReport/NhiBehavioralBaseline/NhiBehavioralCheckResult/DiscoveredTool with #[deprecated] aliases, named constants — MAX_SIGNATURE_ID_LEN=256/MAX_SIGNATURE_LEN=512/MAX_PUBLIC_KEY_LEN=512/MAX_ANALYSIS_CACHE_SIZE=10K/SUSPICION_SATURATION_COUNT=10.0/TRUST_DECAY_FACTOR=0.5/CAPACITY_EXCEEDED_RETRY_SECS=60/MAX_FORM_FIELDS=100, #[deprecated] on check_auto_revoke→revoke_stale_permissions, custom Debug on EscalationDetector, PartialEq+Eq on FipsConfig/GrpcTransportConfig/LimitsConfig, Display for InjectionAlert, saturating_add on suspicious pair counter, pub(crate) visibility on MAX_CONDITIONS_SIZE/html_escape, removed placeholder "2026-06" protocol version, removed unused grpc_requests_count(), SDK fixes — Python format→export_format in soc2_access_review + async docstrings + TS format validation + Go EvaluateOrError doc, comprehensive doc comments on Action/Verdict/Policy/PolicyType/McpServer/ToolSignature fields/PermissionTracker/TransportCircuitStats/AgentAccumulator)
- Round 58 (78 findings — 3 P1 + 24 P2 + 18 P3 + 11 P4: Redis self-approval homoglyph bypass via missing normalize_homoglyphs() — Cyrillic homoglyphs bypassed NFKC+case-fold comparison, Redis self-denial prevention entirely absent — any requester could deny their own request breaking separation-of-privilege, TS SDK Action missing resolved_ips field — SDK parity gap preventing DNS rebinding defense, engine from_snapshot unbounded agents/tools OOM, validate_regex_safety negative paren_depth + unclosed parentheses, circuit_breaker/traced summary counters saturating_add, ABAC Forbid early return optimization, OutputSecurityAnalyzer session_baselines unbounded HashMap capped at MAX_SESSION_BASELINES=100K, TokenSecurityAnalyzer session_contexts bounded with auto-cleanup, request_count/sample_count/total_tokens saturating_add across 4 counters, detect_homoglyph_stego division-by-zero on empty input, DataFlowConfig deny_unknown_fields + max_findings upper bound, GoalTrackerConfig/TokenSecurityConfig/OutputSecurityConfig validate() with float threshold validation, GoalTracker post-cleanup capacity re-check, homoglyph detection OnceLock+HashSet for O(1) lookup, export.rs serialization failure returns error JSON, Tenant RFC 3339 timestamp validation + control char validation + metadata bounds, ThreatIndicator tags bounded at MAX_INDICATOR_TAGS=50, TelemetryConfig validate() with URL scheme + sampling ratio + control chars, JIT request control char validation, OPA context size MAX_OPA_CONTEXT_SIZE=1MB, deny_unknown_fields on ~28 config structs — A2aConfig/ClusterConfig/6 observability/5 memory-NHI/10 threat-detection/ToolRegistryConfig, A2aConfig/ClusterConfig validate() with bounds, MemorySecurityConfig validate() for trust_decay_rate/trust_threshold, ToolRegistryConfig validate() for trust_threshold, ObservabilityConfig sample_rate NaN check, BehavioralDetectionConfig/SemanticDetectionConfig/SchemaPoisoningConfig/CrossAgentConfig validate() with float range validation, Go SDK retry with exponential backoff on 429/502/503/504, TS SDK retry with exponential backoff parity, compliance config structs PartialEq derive, PatternMatcher case-sensitivity contract documented)
- Rounds 80-84 (Phase 41 hardening: UTF-8 is_char_boundary truncation guards in threat.rs, OWASP ASI config gating on `owasp_asi.enabled`, AsiCoverageReport::validate() bounds, deny_unknown_fields on 14+ structs across audit/config/MCP, `is_unicode_format_char()` promoted to pub API with expanded ranges covering soft hyphen/interlinear annotations/TAG characters, 6 crate-local copies replaced with canonical import, NlPolicyConfig::validate() with field bounds, allowed_task_operations Unicode format char parity, Python SDK period validation)
- Rounds 85-99 (DLP scan `result` field in passthrough responses across all transports — HTTP/gRPC/WS/stdio parity, zero cache/renewal TTL rejection in A2A config, call_chain timestamp validation parity, SDK type validation improvements)
- Round 100 (12 adversarial + 15 improvement findings: SemanticGuardrailsConfig backend SSRF validation — OpenAI/Anthropic endpoint URLs checked for loopback/metadata/link-local/userinfo bypass, model/cache_ttl/cache_max_size/max_latency/max_tokens bounds, fallback_on_timeout whitelist, NlPolicyConfig Unicode format char validation on id/name/statement/tool_patterns, deny_unknown_fields added to SupplyChainConfig/ManifestConfig/PolicyRule/ExtensionConfig, dns_name length+control+Unicode format char validation in deployment.rs, 5 missing validate() calls wired into PolicyConfig — memory_security/behavioral/semantic_detection/schema_poisoning/cross_agent, deny_unknown_fields on ABAC types — AbacPolicy/PrincipalConstraint/ActionConstraint/ResourceConstraint/AbacCondition/RiskScore/RiskFactor, AuditExportConfig validate() with batch_size bounds, SDK resolved_ips parity for Python/TypeScript)
- Round 102 (10 adversarial + 15 improvement findings: is_unicode_format_char() checks added to PolicyRule/ExtensionConfig/NhiConfig/VerificationConfig/DpopConfig validate() methods closing zero-width/bidi bypass, ManifestConfig trusted_keys per-element validation (empty/length/hex-only), deny_unknown_fields on ManifestAnnotations/ManifestToolEntry/ToolManifest, ToolManifest::from_tools_list() bounded at MAX_MANIFEST_TOOLS=10K, MemorySecurityConfig::validate() bounds on max_memory_age_hours/max_entries_per_session/max_provenance_nodes/max_fingerprints, NamespaceConfig::validate() with isolation value/max_namespaces/format char checks, ThreatIntelConfig custom Debug redacts api_key, PolicyRule PartialEq derive, NhiConfig→VerificationConfig/DpopConfig validate() wiring, 32 new tests)
- Round 104 (9 adversarial + 7 improvement findings: simulator compile_from_toml_bounded/validate/diff now call PolicyConfig::validate() preventing unbounded collection OOM and invalid float bypass, setup wizard apply handler validates config semantics before writing to disk, ToolManifest::load_pinned_manifest() enforces 16MB file size + MAX_MANIFEST_TOOLS count bound, ContextBudgetTracker bounded at MAX_BUDGET_SESSIONS=100K + MAX_RETRIEVALS_PER_SESSION=10K + saturating_add on total_tokens, NhiAgentIdentity/NhiDpopProof/ToolManifest custom Debug redacts cryptographic material, ETDI sign_tool() timestamp format fixed to strict ISO 8601, Go SDK redirect scheme validation + parameters size + eval context validation, 8 new tests)
- Round 106 (5 adversarial + 6 improvement findings: Tenant route handler enforces Tenant::validate() before store write, RagDefenseConfig::validate() adds upper bounds on 11 integer fields, DocumentVerifier trust_cache bounded at MAX_TRUST_CACHE_SIZE=100K, ContextBudgetTracker stats() uses u64 accumulation preventing u32 overflow, is_unsafe_char deduplicated from 6 copies to 1 canonical pub(crate) fn in routes/mod.rs, NHI error messages no longer echo raw user input, zero-TTL rejection for SPIFFE SVID/NHI credentials/threat intel cache/RAG defense cache, TS SDK validateContext() parity with Go SDK, 8 new tests)
- Round 108 (7 adversarial + 8 improvement findings: #[must_use = "security verdicts must not be discarded"] added to Verdict enum/AbacDecision enum/evaluate_action_traced()/AbacEngine::evaluate()/DeputyGuard::validate_action(), call_counts += 1 replaced with saturating_add across HTTP/WebSocket/gRPC transports preventing u64 overflow resetting call-limit policies)
- Round 110 (28 P2 findings: enterprise/ETDI validate() wiring, schema depth limits, A2A response bounds, relay input sanitization, route handler Content-Type validation, path parameter bounds across 10 route modules)
- Round 111 (1 P1 + 26 P2: RequireCapabilityToken holder bypass when agent_id absent — capability token theft vector closed with explicit None→Deny, DLP pattern name leakage to clients in HTTP/gRPC generic messages, audit sequence number reset across rotations via global AtomicU64, audit rotation sub-second filename collision via monotonic counter, AgentIdentity claims per-key/value length bounds, AbacEngine entity validation on construction, policy compile conditions size canonical constant, unbounded required_claims/agents/issuers/subjects/resources bounded, CapabilityRequired CSV MAX_DECLARED_CAPABILITIES=256, DLP OnceLock atomic initialization, SessionGuardConfig zero threshold rejection, capability_token issued_at future-date check, sampling_detector MAX_SCAN_MATCHES=1000, extension_registry TOCTOU write-lock re-check, rug_pull HashSet dedup, Redis approval MAX_REASON_LEN=4096, cluster redis_url empty check, SDK discovery/approval/zk param validation parity)
- Rounds 128–131 (DLP NFKC→NFKD combining mark stripping, JSON key scanning, extension registry per-method/name/version content validation, projector `estimate_tokens()` fail-closed with FAILSAFE_TOKEN_ESTIMATE=100K, semantic guardrails MAX_SESSION_ID_LEN + policy validation before insertion)
- Round 130 WS+gRPC injection scanning parity (4 findings: WS PassThrough injection scanning added, WS+gRPC upstream tools/list tool-description injection scanning, WS `extract_scannable_text()` rewritten to delegate to shared `extract_text_from_result()` covering resource.blob/annotations/_meta)
- Rounds 133–140 (proxy bridge relay input sanitization — request ID key length/method name truncation/log injection prevention/agent_id bounds, config per-entry validation for PII patterns/resource indicators/CIMD capabilities/trigger tools/async nonces, compliance format allowlisting preventing log injection, ZK proofs offset info disclosure, behavioral engine call_counts map cap + EMA non-finite clamp, least-agency unbounded growth prevention, Merkle leaf fail-closed on wrong-length hash, audit manifest line size limit)
- Rounds 141–149 (types validation: EvaluationContext timestamp/AgentIdentity audience/ToolSignature/ToolAttestation control+format char checks, capability token parent expiry verification, approval empty `requested_by`/`by` rejection, DLP combining mark ranges extended, injection scan final truncation, NHI create_delegation link validation/rotate_credentials validate-before-mutate, governance info disclosure — enforcement_mode removed + auto_revoke_candidates count-only, semantic guardrails evaluate() input validation + data flow pattern name bounds + A2A parts iteration bounded, ABAC path normalization fail-closed, HTTP ProgressNotification DLP+injection scanning parity)
- Rounds 154–162 (injection key scanning parity: WS/HTTP/gRPC/A2A all scan JSON object keys, MAX_DEPTH 10→32 across all transports, combining mark ranges extended, NHI Debug redaction, embedding lock fail-closed, task security SeqCst parity, gRPC TOCTOU atomic session+eval+update, sanitize_for_log dedup, resolve_domains cap)
- Rounds 164–178 (OAuth/DPoP control char validation, A2A DLP text extraction, WS non-JSON DLP/injection scanning, gRPC error.data scanning, Redis approval UTF-8 truncation, DLP response content bounds, semantic guardrail input validation, NaN drift fail-closed, session_id validation, extension rollback, agent card chars, FIPS config validation, red team coverage bounds, session_guard has_dangerous_chars, Rekor validate, WitnessStore cap)
- **Canonical `has_dangerous_chars()` dedup campaign:** ~100 inline char validation patterns replaced with `vellaveto_types::has_dangerous_chars()` across ~35 files (types 82, config 71, mcp 7), removing 4 local helper functions and upgrading control-only checks to also reject Unicode format chars
- **CI/CD:** 11 workflows, Docker/GHCR, release automation, SBOM, provenance attestation
- **SDKs:** Python (sync+async, LangChain/LangGraph/Composio, 361 tests), TypeScript (fetch-based, 111 tests), Go (stdlib-only, 106 tests)
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
- **Agent Identity Federation (Phase 39, placeholder):** `FederationResolver` type with config/status methods, `FederationConfig` with trust anchor validation, dashboard federation section, server/proxy federation API routes (`/api/federation/status`, `/api/federation/trust-anchors`), SDK methods (Python/TypeScript/Go), audit events for federation lifecycle
- **Workflow-Level Policy Constraints (Phase 40):** Three new `CompiledContextCondition` variants in vellaveto-engine: `RequiredActionSequence` (ordered/unordered multi-tool prerequisites, max 20 steps, fail-closed on short history), `ForbiddenActionSequence` (ordered/unordered forbidden pattern detection for exfiltration — e.g. read_secret→http_request), `WorkflowTemplate` (DAG-based tool transition enforcement with Kahn's algorithm cycle detection at compile time, entry point validation, strict/warn modes, max 50 steps). Case-insensitive matching. TLA+ spec (S8 WorkflowPredecessor, S9 AcyclicDAG). 55 new tests.
- **OWASP Agentic Security Index (Phase 41):** `OwaspAsiRegistry` with 10 categories (ASI01–ASI10), 33 controls, 100% coverage via `VellavetoDetection` mappings. `AsiCoverageReport` with per-category breakdown and control matrix. Wired as 8th framework in gap analysis. `OwaspAsiConfig` with `enabled` flag, `deny_unknown_fields`, `validate()`. `GET /api/compliance/owasp-agentic` endpoint with cache. SDK methods: Python (sync+async), TypeScript, Go with input validation. Dashboard compliance table includes OWASP ASI. ~30 new tests (Rust + SDKs).
- **Centralized Audit Store (Phase 43):** `AuditSink` trait for pluggable external stores, `PostgresAuditSink` with mpsc channel + background batch INSERT (exponential backoff retry, `ON CONFLICT DO NOTHING`), `AuditQueryService` trait with `FileAuditQuery` (in-memory filtering) and `PostgresAuditQuery` (SQL with bind parameters, GIN indexes on metadata). `AuditStoreConfig` with SSRF validation (private/loopback/metadata host rejection), SQL identifier validation for table_name, `deny_unknown_fields`, custom Debug redacting `database_url`. REST API: `GET /api/audit/search` (paginated, time/tool/verdict/agent/text filters), `GET /api/audit/store/status`, `GET /api/audit/entry/{id}`. Feature-gated behind `postgres-store` (sqlx). Dual-write: file log remains source of truth, PostgreSQL sink optional and non-fatal by default. ~55 new tests.
- **Interactive Setup Wizard:** Web-based 7-step configuration wizard at `/setup` (Welcome → Security → Policies → Detection → Audit → Compliance → Review/Apply). Server-side rendered HTML matching dashboard dark theme, POST/redirect/GET forms, CSRF protection, bounded session management (MAX_WIZARD_SESSIONS=100, 1hr TTL), TOML config generation with live apply and hot-reload. Guard middleware locks wizard after initial configuration via `.setup-complete` marker file. 28 unit tests.
- **Cloudflare Pages Deployment:** Site at [www.vellaveto.online](https://www.vellaveto.online), Astro static build deployed via `deploy-site.yml` workflow, `_redirects` (apex → www 301), `_headers` (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
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

### Discovered from 116 audit rounds (top causes of breakage)
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
