# Security Audit Log

> **Living document** tracking all adversarial security audit findings and fixes.
> Updated after each audit round. See also `CHANGELOG.md` for feature changes.
>
> **Last updated:** 2026-02-22 (Round 182)
> **Total audit rounds:** 182
> **Cumulative findings fixed:** 618+

---

## Round 169+170 — Audit File Permissions + Merkle Leaf TOCTOU (3 findings fixed)

**Subsystem:** `vellaveto-audit/src/merkle.rs`, `vellaveto-audit/src/rotation.rs`
**Commit:** `522cb5f`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R170-001 | P1 | `merkle.rs:144` | Merkle leaf file now gets `0o600` permissions after creation — parity with audit log and checkpoint files |
| FIND-R170-002 | P1 | `rotation.rs:254` | Rotation manifest file now gets `0o600` permissions after creation — parity with audit log and checkpoint files |
| FIND-R170-003 | P2 | `rotation.rs:164` | Removed `exists()` check before Merkle leaf rename, eliminating TOCTOU gap; `NotFound` handled explicitly; error level upgraded from `warn!` to `error!` |

R169 (http-proxy+server): PASSED — no genuine findings.

---

## Round 167+168 — Semantic Guardrails Config Validation Gaps (3 findings fixed + 5 tests)

**Subsystem:** `vellaveto-mcp/src/semantic_guardrails/cache.rs`, `vellaveto-mcp/src/semantic_guardrails/mod.rs`
**Commit:** `6ef92cc`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R168-001 | P2 | `cache.rs:106` | `CacheConfig::validate()` now rejects `ttl_secs` exceeding `MAX_TTL_SECS` (7 days) at config load time — fail-closed instead of runtime clamping |
| FIND-R168-002 | P2 | `cache.rs:106` | `CacheConfig::validate()` rejects `ttl_secs=0` with `enabled=true` — prevents silent no-op cache |
| FIND-R168-003 | P3 | `mod.rs:183` | `ServiceConfig::validate()` caps `max_latency_ms` at 300,000ms (5 min) |

R167 (engine+types): PASSED — no genuine findings. Codebase thoroughly hardened from prior 166 rounds.

5 new tests: 3 cache config validation (TTL exceeds max, zero TTL enabled, zero TTL disabled ok), 2 service config (max latency exceeds bound, default passes).

---

## Round 182 — Code Block Size, Tokenize Cap, Explanation Bound, Rate Limit Fail-Closed, WS Metrics Saturating (5 findings fixed)

**Subsystem:** `vellaveto-mcp/src/projector/repair.rs`, `vellaveto-mcp/src/discovery/index.rs`, `vellaveto-mcp/src/transparency.rs`, `vellaveto-http-proxy/src/proxy/websocket/mod.rs`
**Commits:** `f858f98`, pending

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R182-002 | P2 | `repair.rs` | `extract_json_from_code_block()` rejects input >1MB (`MAX_CODE_BLOCK_INPUT_SIZE`) preventing unbounded clone on attacker-controlled repair input |
| FIND-R182-004 | P3 | `index.rs` | `tokenize()` capped at `MAX_TOKENS_PER_TEXT=512` preventing unbounded allocation on large tool descriptions |
| FIND-R182-005 | P3 | `transparency.rs` | `inject_decision_explanation()` bounded at 64KB with automatic fallback to Summary when Full verbosity exceeds cap |
| FIND-R182-006 | P3 | `websocket/mod.rs` | `check_rate_limit()` returns `false` (deny) when `max_per_sec==0` — fail-closed instead of unlimited |
| FIND-R182-003 | P3 | `websocket/mod.rs` | WS metrics counters (`WS_CONNECTIONS_TOTAL`, `WS_MESSAGES_TOTAL`, rate limit counter) switched from `fetch_add` to `fetch_update` with `saturating_add` |

Deferred: FIND-R182-001 (P2, WS idle_timeout design — max-lifetime vs true idle), FIND-R182-007 (P4, discovery tag substring matching).

---

## Round 180 — Extension Poisoning Parity, Guardrails Validation, Action Name Bounds (4 findings fixed + 12 tests + IMP-R178-008 panic fix)

**Subsystem:** `vellaveto-mcp/src/proxy/bridge/relay.rs`, `vellaveto-mcp/src/semantic_guardrails/evaluator.rs`, `vellaveto-mcp/src/did_plc.rs`, `vellaveto-audit/src/observability/otlp.rs`, `vellaveto-audit/src/data_governance.rs`
**Commits:** `3f55cd7`, `b7050dd`, `3a39c70`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R180-001 | P2 | `relay.rs` | Extension method handler now calls `check_parameters()` before `extract_from_value()` — transport parity with tool calls/resource reads/tasks for memory poisoning detection |
| FIND-R180-002 | P3 | `evaluator.rs` | `session_id`/`principal` validated for length (256) and `has_dangerous_chars()` in `LlmEvalInput::validate()` |
| FIND-R180-003 | P3 | `evaluator.rs` | `metadata` bounded at `MAX_METADATA_SIZE=64KB` preventing OOM via oversized JSON |
| FIND-R180-004 | P3 | `relay.rs` | `record_forwarded_action()` truncates action names to 256 chars before `call_counts`/`action_history` storage |
| IMP-R178-008 | P2 | `did_plc.rs` | `validate_did_plc()` `&did[..60]` replaced with `is_char_boundary()` loop to prevent panic on multi-byte UTF-8 |
| IMP-R178-007 | P4 | `observability/` | Deduplicated `MAX_SPAN_ATTRIBUTES=128` into shared constant |

12 new tests: 7 DID:PLC (oversized key/algorithm/genesis, at-max bounds, multibyte UTF-8), 3 data governance (tool name at/over MAX_TOOL_NAME_LEN), 2 OTLP (attribute cap on builder and span_to_otel).

R178 verification: All 5 R178 fixes confirmed VERIFIED.

---

## Round 178 — DID Genesis Validate, Data Governance Tool Name Bound, Sampling Patterns, OTLP Attributes (6 findings fixed)

**Subsystem:** `vellaveto-mcp/src/did_plc.rs`, `vellaveto-audit/src/data_governance.rs`, `vellaveto-mcp/src/sampling_detector.rs`, `vellaveto-audit/src/observability/otlp.rs`
**Commits:** `75974eb`, `b2b5a75`, `3a39c70`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R178-001 | P2 | `did_plc.rs` | `genesis.validate()` called before clone+serialize; `generate_did_plc_from_key` bounded key/algorithm lengths (1024/64) |
| FIND-R178-002 | P2 | `data_governance.rs` | `MAX_TOOL_NAME_LEN=256` guard in `get_record()` before O(p*t) DP glob matching |
| FIND-R178-003 | P3 | `sampling_detector.rs` | `add_sensitive_pattern()` bounded at `MAX_SENSITIVE_PATTERNS=1000`, pattern length at 256 |
| FIND-R178-004 | P3 | `otlp.rs` | `span_to_otel_attributes()` caps custom attribute iteration at 128; builder `attribute()` drops beyond 128 |
| FIND-R178-005 | P3 | `did_plc.rs` | `validate_did_plc()` truncates DID to 60 chars in error message preventing oversized errors |

R176 verification: All 6 R176 fixes confirmed VERIFIED.

---

## Round 165+166 — unreachable!() Panics + Archive Retention Data Loss (3 findings fixed)

**Subsystem:** `vellaveto-mcp/src/proxy/bridge/relay.rs`, `vellaveto-audit/src/archive.rs`
**Commit:** `6dd69f9`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R166-001 | P1 | `relay.rs:1645` | `unreachable!()` in task request Verdict match — Verdict is `#[non_exhaustive]`, future variants would panic. Replaced with safe fallback |
| FIND-R166-002 | P1 | `relay.rs:1922` | Same `unreachable!()` in extension method Verdict match |
| FIND-R165-001 | P2 | `archive.rs:151` | `enforce_retention(0)` computed cutoff = now, deleting ALL archives. Doc says "keep forever". Added early return guard |

**Tests:** All 1,195 MCP + 441 audit tests pass.

---

## Round 176 — Extension Rollback, Agent Card Chars, FIPS Config, Red Team Validation (6 findings fixed + 11 tests)

**Subsystem:** `vellaveto-mcp/src/extension_registry.rs`, `vellaveto-mcp/src/a2a/agent_card.rs`, `vellaveto-config/src/fips.rs`, `vellaveto-mcp/src/red_team.rs`, `vellaveto-mcp/src/session_guard.rs`
**Commits:** `1c81e37`, `824c25a`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R176-001 | P2 | `extension_registry.rs` | Method routes rolled back on failed extension insert (capacity/duplicate) to prevent orphaned route entries |
| FIND-R176-002 | P2 | `a2a/agent_card.rs` | `validate_agent_card()` checks `has_dangerous_chars()` on name/url/version/description/provider fields |
| FIND-R176-003 | P2 | `fips.rs` (config) | FIPS validation rejects `ed25519` when `enabled=true` — only `ecdsa-p256` allowed, matching runtime controller |
| FIND-R176-004 | P2 | `red_team.rs` | `CoverageReport::validate()` with `MAX_COVERAGE_ENTRIES=1000` for by_category/by_mutation maps |
| FIND-R176-005 | P2 | `red_team.rs` | `block_rate` fields validated `[0.0, 1.0]` + `is_finite()` in CoverageReport/CategoryCoverage/MutationCoverage |
| FIND-R176-008 | P3 | `red_team.rs` | `deny_unknown_fields` on 5 red team structs (RedTeamReport, BypassFinding, CoverageReport, CategoryCoverage, MutationCoverage) |
| FIND-R172-005 | P3 | `dlp.rs` | `scan_text_for_secrets` per-call findings cap via `truncate(MAX_DLP_FINDINGS)` |

11 new tests added for R174 validations: session_id empty/overlong/control/format, RepeatedViolation count=0 in Active/Suspicious, NaN/negative goal drift, truncate_event_field under/over/multibyte.

R174 verification: All 7 R174 fixes (FIND-R174-001 through R174-007) confirmed VERIFIED.

---

## Round 174 — NaN Drift Fail-Closed, Session ID Validation, Event Field Bounds (7 findings fixed)

**Subsystem:** `vellaveto-mcp/src/session_guard.rs`, `vellaveto-mcp/src/accountability.rs`, `vellaveto-types/src/gateway.rs`, `vellaveto-types/src/capability.rs`
**Commit:** `63e4338`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R174-001 | P2 | `session_guard.rs` | `integrate_goal_drift` NaN/Infinity/negative similarity now fail-closed to `AnomalySeverity::Critical` instead of falling through to `Low` |
| FIND-R174-002 | P2 | `session_guard.rs` | `process_event_at` session_id validated for empty/length(256)/control chars/Unicode format chars before HashMap insertion |
| FIND-R174-003 | P3 | `session_guard.rs` | `RepeatedViolation{count:0}` is now a no-op in Active and Suspicious states, preventing spurious state escalation |
| FIND-R174-004 | P3 | `gateway.rs` | `UpstreamBackend.id` (256) and `tool_prefixes` (count:1000, len:256) validated for length bounds and dangerous characters |
| FIND-R174-005 | P3 | `capability.rs` | `CapabilityGrant.tool_pattern`/`function_pattern` bounded at `MAX_PATTERN_LEN=1024` |
| FIND-R174-006 | P3 | `session_guard.rs` | TransitionAction message/reason strings truncated at `MAX_EVENT_FIELD_LEN=1024` (UTF-8-safe) |
| FIND-R174-007 | P3 | `accountability.rs` | `sign_attestation` did field bounded at `MAX_DID_LEN=512` |

R172 verification: All 4 R172 fixes (FIND-R172-001/002/003/004) confirmed VERIFIED.

---

## Round 172 — DLP Response Content Bounds + Semantic Guardrail Input Validation (4 findings fixed + 2 improvements)

**Subsystem:** `vellaveto-mcp/src/inspection/dlp.rs`, `vellaveto-mcp/src/semantic_guardrails/evaluator.rs`, `vellaveto-mcp/src/inspection/scanner_base.rs`, `vellaveto-cluster/src/redis_backend.rs`, `vellaveto-http-proxy/src/proxy/grpc/service.rs`, `vellaveto-http-proxy/src/proxy/websocket/mod.rs`
**Commits:** `db63e87`, `c855d2e`, `3d973c3`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R172-001 | P2 | `dlp.rs` | `scan_response_for_secrets` bounded by `MAX_RESPONSE_CONTENT_ITEMS=1000` + `MAX_DLP_FINDINGS` cap checks between all scan blocks |
| FIND-R172-002 | P2 | `evaluator.rs` | `LlmEvalInput::validate()` bounds individual nl_policies (64KB), context role (32 chars), content (32KB), parameters JSON (1MB), plus control/format char validation on role |
| FIND-R172-003 | P3 | `dlp.rs` | `scan_notification_for_secrets` checks findings cap before method name scan |
| FIND-R172-004 | P3 | `evaluator.rs` | Context message role validated for control/format characters |
| FIND-R168-005 | P3 | `grpc/service.rs`, `websocket/mod.rs` | gRPC/WS `error.data` scanning uses `as_str()` first to avoid JSON quoting |
| IMP-R170-005 | P3 | `scanner_base.rs` | Test for `MAX_TRAVERSE_ELEMENTS` element count bound |
| IMP-R170-007 | P3 | `redis_backend.rs` | Extracted `validate_resolver_identity()` deduplicating 24 lines from approve/deny |

R170 verification: All 5 R170 fixes (FIND-R170-001/002/003/004/005) confirmed VERIFIED.

---

## Round 170 — Redis Approval Parity + Deny Validation + UTF-8 Truncation + Traverse Bounds (5 findings fixed)

**Subsystem:** `vellaveto-cluster/src/redis_backend.rs`, `vellaveto-server/src/routes/approval.rs`, `vellaveto-server/src/routes/simulator.rs`, `vellaveto-mcp/src/inspection/scanner_base.rs`
**Commit:** `2967e61`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R170-002 | P1 | `redis_backend.rs` | Redis `approval_approve`/`approval_deny` now reject empty `by` string — parity with local ApprovalStore (FIND-R143-005) |
| FIND-R170-003 | P2 | `redis_backend.rs` | Redis `approval_create` rejects empty `requested_by` — prevents self-approval check bypass via empty requester identity |
| FIND-R170-001 | P2 | `approval.rs` | `deny_approval` route handler maps `Validation` errors to `403 Forbidden`, mirroring `approve_approval` handler |
| FIND-R170-004 | P2 | `simulator.rs` | Batch error truncation uses char-boundary-aware slicing to prevent UTF-8 panic on multi-byte strings |
| FIND-R170-005 | P3 | `scanner_base.rs` | `traverse_json_strings_impl` bounded by `MAX_TRAVERSE_ELEMENTS=10,000` total callback invocations |

R168 verification: All 3 R168 fixes (FIND-R168-001/002/003) confirmed FIXED. IMP-R166-001 dedup confirmed FIXED.

---

## Round 168 — WS Non-JSON Audit Trail + Engine Stack Bounds + json_has_dangerous_chars Dedup (7 findings fixed)

**Subsystem:** `vellaveto-http-proxy/src/proxy/websocket/mod.rs`, `vellaveto-engine/src/lib.rs`, `vellaveto-types/src/core.rs`, `vellaveto-http-proxy/src/proxy/grpc/service.rs`, `vellaveto-mcp/src/a2a/proxy.rs`
**Commits:** `7d7c03a`, `b399b04`, `5fcb5a1`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R166-001 | P2 | `websocket/mod.rs` | WS upstream non-JSON text frames now scanned for DLP/injection before forwarding (previously bypassed all security checks) |
| FIND-R166-003 | P3 | `websocket/mod.rs` | Log injection in `convert_to_ws_url` sanitized via `sanitize_for_log()` |
| FIND-R166-004 | P3 | `a2a/proxy.rs` | `collect_string_leaves` stack push loops now check MAX_STACK_SIZE inside inner loops |
| IMP-R166-002 | P2 | `grpc/service.rs` | gRPC `extract_scannable_text` delegates to shared `extract_text_from_result()` for full scan coverage (resource.blob, annotations, _meta) |
| IMP-R166-001 | P2 | `core.rs` | `json_has_dangerous_chars` extracted to vellaveto-types, deduplicating from gRPC + A2A |
| FIND-R168-001 | P2 | `websocket/mod.rs` | WS non-JSON DLP/injection detections now create audit log entries (was missing audit trail) |
| FIND-R168-002 | P2 | `websocket/mod.rs` | WS non-JSON injection now logs in both blocking and log-only modes |
| FIND-R168-003 | P3 | `engine/lib.rs` | `collect_all_string_values` stack bounded by MAX_STACK_SIZE=10,000 inside push loops |

R166 verification: FIND-R166-001 partially fixed (audit gaps), completed in R168. FIND-R166-002/003/004 confirmed FIXED.

---

## Round 164 — OAuth/DPoP Control Char Validation + A2A DLP Text Extraction (6 findings fixed)

**Subsystem:** `vellaveto-http-proxy/src/oauth.rs`, `vellaveto-mcp/src/a2a/proxy.rs`
**Commit:** `511be9f`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R164-001 | P2 | `oauth.rs` | OAuth `resource` claim missing control/format char validation — log injection via ResourceMismatch error |
| FIND-R164-002 | P3 | `oauth.rs` | OAuth `cnf.jkt` missing control/format char validation |
| FIND-R164-003 | P2 | `oauth.rs` | DPoP `htm`/`htu`/`jti` claims missing control/format char validation — log injection via crafted DPoP proofs |
| FIND-R164-004 | P3 | `oauth.rs` | `DpopClaims` missing `deny_unknown_fields` — field injection via unrecognized JWT fields |
| FIND-R164-005 | P2 | `a2a/proxy.rs` | A2A PassThrough DLP scan was no-op — `run_security_scans` returned empty Vec for non-MessageSend/TaskGet types; now uses `collect_string_leaves` |
| FIND-R164-006 | P3 | `oauth.rs` | DPoP `htu` URL comparison was case-sensitive on scheme+host — normalized per RFC 3986 §6.2.2.1 |

---

## Round 163+164 — IPv6 ULA Rejection + DNS Discovery Input Validation (2 findings fixed)

**Subsystem:** `vellaveto-cluster/src/discovery_dns.rs`, `vellaveto-server/src/main.rs`
**Commit:** `3045b06`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R163-003 | P2 | `discovery_dns.rs` | `is_safe_addr()` did not reject IPv6 Unique Local Addresses (fc00::/7) — IPv6 equivalent of IPv4 private ranges |
| FIND-R163-006 | P2 | `discovery_dns.rs` | `DnsServiceDiscovery::new()` accepted dns_name without validation — now rejects empty/oversized/control+format chars; returns `Result` |

R161 (R117 backlog): All items already resolved in prior rounds.
R162 (inspection): No genuine P1/P2 — MP4 extended box size handled by checked_add, chi-squared overflow infeasible, PDF lookback is design choice.
R164 (server admin): NHI audit logging gap is known backlog (R117-SP-004); other findings are design observations.

**Tests added:** 2 (DNS discovery validation rejection tests)

---

## Round 162 — gRPC TOCTOU Fix + sanitize_for_log Dedup + resolve_domains Cap (10 findings fixed)

**Subsystem:** `vellaveto-http-proxy/src/proxy/grpc/service.rs`, `vellaveto-types/src/core.rs`, `vellaveto-mcp/src/proxy/bridge/relay.rs`, `vellaveto-http-proxy/src/proxy/helpers.rs`, `vellaveto-mcp/src/task_security.rs`
**Commit:** `2821050`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R160-001 | P1 | `grpc/service.rs` | gRPC handle_tool_call/resource_read/task_request/extension_method TOCTOU — context+eval+update now atomic (DashMap shard lock held). Parity with WS FIND-R130-002 |
| FIND-R160-004 | P2 | `task_security.rs` | `checkpoints_created` + `stats()` loads upgraded Relaxed→SeqCst for consistency |
| IMP-R154-001 | P3 | `core.rs`, `relay.rs`, `federation.rs` | Added `sanitize_for_log(s, max_len)` to vellaveto-types; replaced 7 duplicate sites |
| IMP-R160-003 | P2 | `helpers.rs` | HTTP `resolve_domains()` capped at MAX_RESOLVED_IPS=100 — parity with stdio relay |
| IMP-R160-007 | P4 | `websocket/mod.rs` | Removed duplicate doc comment line |

**Also committed in prior batch (b96c20d):**

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R154-001 | P2 | `injection.rs` | `sanitize_stripped()` adds 4 missing combining char ranges |
| FIND-R154-003 | P2 | `websocket/mod.rs` | `extract_strings_recursive` scans object keys |
| FIND-R154-004 | P2 | `websocket/mod.rs` | `schema_violation_found` guards memory tracker |
| FIND-R154-005 | P3 | `websocket/mod.rs` | Extract depth limit 10→32 matching MAX_SCAN_DEPTH |
| FIND-R155-001/002 | P2 | `handlers.rs`, `grpc/service.rs` | HTTP+gRPC key scanning + depth 32 parity |

**Open (deferred to future rounds):**
- FIND-R160-002 (P2): A2A PassThrough DLP/injection scanning bypass
- FIND-R160-003 (P2): A2A missing control/format char validation
- FIND-R160-005 (P3): A2A traceparent format validation
- IMP-R160-001 (P2): Triplicated extract_strings_for_injection across transports
- IMP-R160-006 (P3): MAX_RESPONSE_BODY_BYTES 16MB vs config 10MB inconsistency

**Tests:** 7,085+ Rust tests pass, 0 failures.

---

## Round 159+160 — DELETE Call Chain Parity + WebSocket Agent Identity Storage (2 findings fixed)

**Subsystem:** `vellaveto-http-proxy/src/proxy/handlers.rs`, `vellaveto-http-proxy/src/proxy/websocket/mod.rs`
**Commit:** `1b629e7`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R159-001 | P1 | `handlers.rs` | DELETE handler skipped `validate_call_chain_header()` — parity gap with POST and GET allowing oversized/malformed X-Upstream-Agents headers |
| FIND-R159-003 | P2 | `websocket/mod.rs` | WebSocket handler validated `agent_identity` but discarded it (`let _agent_identity`) — ABAC policies evaluated against None for WS connections |

R160 (SDKs): No genuine P1/P2 — TS approval methods already exist, Python redaction correct, Go NaN handled by json.Marshal error.

**Tests:** 95 http-proxy tests pass, 0 failures.

---

## Round 155+156+157+158 — Config Unicode Format Char Bypass + Compliance Error Normalization (2 findings fixed)

**Subsystem:** `vellaveto-config/src/mcp_protocol.rs`, `vellaveto-config/src/zk_audit.rs`, `vellaveto-config/src/projector.rs`, `vellaveto-server/src/routes/compliance.rs`
**Commits:** `bd3ce67`, `972c678`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R158-001 | P1 | `mcp_protocol.rs`, `zk_audit.rs`, `projector.rs` | 9 config validators used `char::is_control()` instead of canonical `has_dangerous_chars()` — zero-width/bidi/BOM format chars bypassed validation |
| FIND-R155-003 | P2 | `compliance.rs` | `parse_period()` error echoed user value and `MAX_PERIOD_DAYS` constant — replaced with generic message |

R155 server/proxy: 4/5 findings dismissed as false positives (NHI routes already use typed structs, ZK offset message already generic, DELETE handler already has session ID validation).
R156 types+engine: PASSED — no P1/P2 findings.
R157 mcp: DPoP O(n) JTI scan is known backlog (FIND-R116-005). No new genuine P1/P2.

**Tests:** 780 config tests pass, 0 failures.

---

## Round 153+154 — DLP Hex Threshold + Simulator Truncation + ZK Error Normalization (3 findings fixed)

**Subsystem:** `vellaveto-mcp/src/inspection/dlp.rs`, `vellaveto-server/src/routes/simulator.rs`, `vellaveto-server/src/routes/zk_audit.rs`
**Commit:** `142ac93`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R154-001 | P1 | `dlp.rs` | Hex decode threshold lowered from 32 to 16 chars — catches short hex-encoded secrets (AWS AKIA prefix = 20 hex chars, Twilio SK = 32 hex chars) |
| FIND-R153-006 | P2 | `simulator.rs` | Error message truncation uses UTF-8 safe `is_char_boundary()` loop — `String::truncate()` panics on non-char-boundary indices |
| FIND-R153-001 | P2 | `zk_audit.rs` | ZK commitments error messages normalized — don't echo user-supplied `from`/`to` values or internal `MAX_ENTRY_RANGE_SPAN` bounds |

**Tests added:** 1 (hex decode at 16-char threshold)

---

## Round 151+152 — Access Review Sanitization + Gateway Config Bounds (4 findings fixed)

**Subsystem:** `vellaveto-audit/src/access_review.rs`, `vellaveto-config/src/gateway.rs`
**Commit:** `d86d0af`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R151-001 | P2 | `access_review.rs` | `period_start`/`period_end` sanitized before `tracing::error!` — prevents log injection from API callers |
| FIND-R151-002 | P2 | `access_review.rs` | `agent_id`/`session_id` strings bounded at 1024 chars during extraction — prevents OOM from adversarial entries |
| FIND-R152-001 | P2 | `gateway.rs` | `transport_urls` bounded at 10 per backend — prevents unbounded HashMap growth |
| FIND-R152-002 | P2 | `gateway.rs` | `tool_prefixes` bounded at 1000 per backend — prevents memory exhaustion |

**Tests added:** 0 (14 gateway + access review tests continue to pass)

---

## Round 150 — Relay Audit Metadata Sanitization + PendingRequest Truncation (5 findings fixed)

**Subsystem:** `vellaveto-mcp/src/proxy/bridge/relay.rs`
**Commit:** `64a74df`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R150-001 | P2 | `relay.rs` | Tool description injection detection now sanitizes child-provided `tool_name` before logging |
| FIND-R150-002 | P2 | `relay.rs` | `task_method`/`extension_method` consistently truncated to 256 chars before PendingRequest storage |
| FIND-R150-003 | P2 | `relay.rs` | `tool_name` in handle_tool_call truncated before PendingRequest tracking |
| FIND-R150-004 | P2 | `relay.rs` | Task request handler uses sanitized `safe_task_method`/`safe_task_id` in all audit metadata JSON |
| FIND-R150-005 | P2 | `relay.rs` | Extension method handler uses sanitized `safe_extension_id`/`safe_ext_method` in all audit metadata JSON |

**Tests added:** 0 (11 relay tests continue to pass)

---

## Round 148+149 — ABAC Path Normalization + HTTP ProgressNotification Parity (2 findings fixed)

**Subsystem:** `vellaveto-engine/src/abac.rs`, `vellaveto-http-proxy/src/proxy/handlers.rs`
**Commit:** `3c262eb`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R149-006 | P2 | `abac.rs` | `matches_resource` path normalization error now skips path (fail-closed) instead of falling back to `"/"` which could match broad Permit patterns |
| FIND-R148-002 | P2 | `handlers.rs` | HTTP `ProgressNotification` merged into `PassThrough` arm — DLP + injection scanning parity with WS and gRPC handlers |

**Tests added:** 0 (95 HTTP proxy + 687 engine tests continue to pass)

---

## Round 146+147 — Semantic Guardrails + Data Flow + A2A (5 findings fixed)

**Subsystem:** `vellaveto-mcp/src/semantic_guardrails/`, `vellaveto-mcp/src/data_flow.rs`, `vellaveto-mcp/src/a2a/proxy.rs`
**Commit:** `5cb350f`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R146-001 | P1 | `mod.rs` (semantic) | `SemanticGuardrailsService::evaluate()` now calls `input.validate()` — prevents unbounded memory in cache/intent chains |
| FIND-R147-001 | P1 | `data_flow.rs` | Pattern name length capped at 256 bytes; `MAX_ACTIVE_PATTERNS=10K` prevents unbounded HashMap key growth |
| FIND-R147-002 | P1 | `proxy.rs` (A2A) | `extract_request_text_content` parts iteration bounded with `.take(MAX_HISTORY_ENTRIES)` |
| FIND-R147-014 | P3 | `proxy.rs` (A2A) | Response `artifacts` and inner `parts` iterations bounded with `.take()` |

**Tests added:** 0 (27 data flow + semantic guardrails tests continue to pass)

---

## Round 144+145 — NHI Validation + Governance Info Disclosure (6 findings fixed)

**Subsystem:** `vellaveto-mcp/src/nhi.rs`, `vellaveto-server/src/routes/governance.rs`
**Commit:** `805201b`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R145-001 | P1 | `nhi.rs` | `create_delegation` now calls `link.validate()` before insert — unbounded permissions/scope_constraints bypass closed |
| FIND-R145-002 | P1 | `nhi.rs` | `rotate_credentials` validates inputs BEFORE mutating identity — prevents corrupted state on validation failure |
| FIND-R145-008 | P2 | `nhi.rs` | `register_identity` validates `public_key` (8192 max) and `key_algorithm` (64 max) for length + control/format chars |
| FIND-R144-005 | P2 | `governance.rs` | Removed `enforcement_mode` from least-agency API response — was leaking security posture |
| FIND-R144-010 | P2 | `governance.rs` | Replaced `auto_revoke_candidates` policy ID list with count-only field |
| FIND-R145-002 | P2 | `nhi.rs` | `rotate_credentials` validates `trigger` (256 max) and `new_key_algorithm` (64 max) for dangerous chars |

**Tests added:** 0 (existing 49 NHI tests continue to pass)

---

## Round 141+143 — Types Validation + Approval/Capability Hardening (10 findings fixed)

**Subsystem:** `vellaveto-types/`, `vellaveto-approval/`, `vellaveto-mcp/src/capability_token.rs`
**Commit:** `c3a5fad`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R141-001 | P2 | `identity.rs` | `EvaluationContext.timestamp` now validated for length (64), control chars, Unicode format chars |
| FIND-R141-002 | P2 | `identity.rs` | `AgentIdentity.audience` per-entry length (1024) + control/format char validation; `issuer` + `subject` validated |
| FIND-R141-003 | P2 | `etdi.rs` | `ToolSignature::validate()` control/format char checks on `signature_id`, `signed_at`, `expires_at`, `key_fingerprint`, `signer_spiffe_id` |
| FIND-R141-004 | P2 | `etdi.rs` | `ToolAttestation::validate()` control/format char checks on all 7 string fields |
| FIND-R141-005 | P2 | `identity.rs` | `EvaluationContext::validate()` now validates nested `CapabilityToken` via `validate_structure()` |
| FIND-R143-002 | P1 | `capability_token.rs` | `attenuate_capability_token` verifies parent token not expired before issuing child |
| FIND-R143-004 | P2 | `lib.rs` (approval) | Empty `requested_by` (`Some("")`) rejected — was bypassing self-approval check |
| FIND-R143-005 | P2 | `lib.rs` (approval) | Empty `by` string rejected in `approve()` and `deny()` — prevents unaccountable resolutions |

**Tests added:** 17 (14 types validation + 3 approval empty-string tests)

---

## Round 142 — DLP + Injection Inspection (4 findings fixed)

**Subsystem:** `vellaveto-mcp/src/inspection/`
**Commit:** `af364a9`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R142-001 | P2 | `injection.rs` | `sanitize_stripped` missing post-NFKC combining mark strip — parity with `sanitize_for_injection_scan` |
| FIND-R142-009 | P2 | `dlp.rs`, `injection.rs` | Extended Unicode combining mark ranges (U+1AB0-U+1AFF, U+1DC0-U+1DFF, U+20D0-U+20FF, U+FE20-U+FE2F) added to stripping |
| FIND-R142-011 | P3 | `multimodal.rs` | `mp4_extract_legacy_udta_texts` now handles extended 64-bit box sizes (raw_size == 1) |
| FIND-R142-013 | P3 | `injection.rs` | `InjectionScanner::scan_response` final truncation to `MAX_SCAN_MATCHES` |

**Tests added:** 1 (extended combining marks DLP test)

---

## Round 139+140 — Behavioral Engine + Audit Logger (6 findings fixed)

**Subsystem:** `vellaveto-engine/`, `vellaveto-audit/`
**Commit:** `2ba3ebc`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R139-001 | P2 | `behavioral.rs` | `call_counts` map iteration capped at `MAX_CALL_COUNT_ENTRIES=10K` |
| FIND-R139-002 | P2 | `behavioral.rs` | `agent_id` length (512) + control/format char validation on live path |
| FIND-R139-003 | P3 | `behavioral.rs` | EMA non-finite clamp — reset to current count if +Infinity |
| FIND-R139-L1/L2 | P2 | `least_agency.rs` | `record_usage` requires `policy_id` in granted set; prevents unbounded `tracker.used` growth + corrupted Optimal recommendations |
| FIND-R140-002 | P2 | `logger.rs` | Merkle tree leaf fail-closed on wrong-length hash decode (was silently zero-padded) |
| FIND-R140-004 | P2 | `rotation.rs` | Manifest line per-line size limit (64 KB) |

**Tests added:** 4 (behavioral validation tests)

---

## Round 137+138 — Config Validation + Server Routes (7 findings fixed)

**Subsystem:** `vellaveto-config/`, `vellaveto-server/`
**Commit:** `904701e`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R137-002 | P2 | `config_validate.rs` | `custom_pii_patterns[i].name` validated for empty/length/control chars |
| FIND-R137-003 | P2 | `mcp_protocol.rs` | `resource_indicator.allowed_resources` per-entry validation (empty = match all) |
| FIND-R137-004 | P2 | `mcp_protocol.rs` | CIMD `required/blocked_capabilities` per-entry validation |
| FIND-R137-005 | P2 | `mcp_protocol.rs` | `step_up_auth.trigger_tools` per-entry validation |
| FIND-R137-006 | P2 | `mcp_protocol.rs` | `async_tasks.max_nonces=0` rejected when `replay_protection=true` |
| FIND-R138-001 | P1 | `compliance.rs` | `format` query param allowlisted before audit log entry — prevents log injection |
| FIND-R138-002 | P2 | `zk_audit.rs` | ZK proofs offset error no longer discloses exact proof count |

**Tests added:** 8 (config per-entry validation tests)

---

## Round 136 — Proxy Bridge (4 findings fixed)

**Subsystem:** `vellaveto-mcp/src/proxy/bridge/`
**Commit:** `d16161e`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R136-001 | P2 | `relay.rs` | Passthrough request ID key length guard (`MAX_REQUEST_ID_KEY_LEN=1024`) + method name truncation (256) |
| FIND-R136-002 | P2 | `relay.rs` | `negotiated_protocol_version` capped at 64 chars + control/format char filtering |
| FIND-R136-003 | P2 | `relay.rs` | Log injection via `task_method`, `extension_id`, `uri` — sanitized before tracing |
| FIND-R136-004 | P2 | `helpers.rs` | `extract_agent_id()` capped at 256 chars + control/format char rejection |

**Tests added:** 5 (extract_agent_id validation tests)

---

## Round 133 — Cluster + Server Routes (1 finding fixed)

**Commit:** `9abd741`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R133-001 | P2 | `routes/projector.rs` | `schema.description` control char validation added (was missing vs `schema.name`) |

**Also fixed:** Pre-existing `test_verify_accepts_issued_at_within_skew` failure (re-sign token after modifying `issued_at`).

---

## Round 131 — Projector + Data Flow (1 finding fixed)

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R131-001 | P2 | `projector/*.rs` | `estimate_tokens()` fail-closed: `FAILSAFE_TOKEN_ESTIMATE=100K` on serialization failure (was `unwrap_or_default()` returning 0) |

---

## Round 130 — Semantic Guardrails + WS/gRPC Injection Scanning Parity (6 findings fixed)

**Subsystem:** `vellaveto-mcp/src/semantic_guardrails/`, `vellaveto-http-proxy/src/proxy/websocket/mod.rs`, `vellaveto-http-proxy/src/proxy/grpc/service.rs`
**Commits:** (semantic guardrails), `14085ed` (WS+gRPC injection parity)

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R130-001 | P1 | `websocket/mod.rs` | WS PassThrough arm missing injection scanning — injection payloads in `prompts/get`, `completion/complete` passed undetected while HTTP and gRPC both had the check |
| FIND-R130-002 | P2 | `semantic_guardrails/mod.rs` | `MAX_SESSION_ID_LEN=256` bounds check before HashMap insertion |
| FIND-R130-003 | P2 | `websocket/mod.rs`, `grpc/service.rs` | WS+gRPC upstream `tools/list` response handlers missing tool-description injection scanning — malicious MCP servers could embed injection in tool descriptions |
| FIND-R130-003 | P2 | `semantic_guardrails/nl_policy.rs` | `policy.validate()` called in `add_policy()` before insertion |
| FIND-R130-004 | P2 | `websocket/mod.rs` | WS `extract_scannable_text()` rewritten to delegate to shared `inspection::extract_text_from_result()` — now covers `resource.text`, `resource.blob` (base64), `annotations`, `_meta` (previously missing) |

**Also this session:** Canonical `has_dangerous_chars()` adoption across ~35 files (~100 inline patterns replaced), upgrading control-only checks to also reject Unicode format characters.

**Tests added:** 0 (existing proxy + engine tests continue to pass)

---

## Round 129 — Extension Registry (1 finding fixed)

**Commit:** `e982b0b`

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R129-002 | P2 | `extension.rs` | Per-method/name/version/id content validation with control char rejection, empty capability rejection |

**Tests added:** 12 (ExtensionDescriptor validation tests)

---

## Round 128 — DLP Inspection (2 findings fixed)

| ID | Sev | File | Fix |
|----|-----|------|-----|
| FIND-R128-001 | P2 | `dlp.rs` | NFKC→NFKD for combining mark stripping (NFKC composes marks, making them unstrippable) |
| FIND-R128-002 | P2 | `dlp.rs` | JSON object key scanning added to `scan_value_for_secrets()` |

---

## Audit Round Summary (Rounds 1–152)

| Category | Cumulative |
|----------|-----------|
| Rounds completed | 152 |
| P0 (Critical) findings fixed | 3 |
| P1 (High) findings fixed | 37+ |
| P2 (Medium) findings fixed | 377+ |
| P3 (Low) findings fixed | 151+ |
| Tests added from audits | 220+ |
| CLEAN rounds (no findings) | ~25 |
| Subsystems audited | All 12 crates + 3 SDKs |

### Key Security Patterns Enforced

- **Fail-closed:** Errors produce `Deny`, not `Allow`; missing values default to restrictive behavior
- **No unwrap():** Zero `unwrap()`/`expect()` in library code
- **Input validation:** All external data validated for length, control chars, Unicode format chars
- **Bounded collections:** All HashMaps/Vecs capped with explicit `MAX_*` constants
- **Log injection prevention:** All untrusted strings sanitized before `tracing::*` calls
- **Float safety:** NaN/Infinity checks on all threshold comparisons
- **Atomic operations:** SeqCst ordering on security-critical counters
- **deny_unknown_fields:** On all security-relevant request/config structs
- **Debug redaction:** Sensitive fields (keys, signatures, tokens) redacted in Debug output
