# Security Audit Log

> **Living document** tracking all adversarial security audit findings and fixes.
> Updated after each audit round. See also `CHANGELOG.md` for feature changes.
>
> **Last updated:** 2026-02-22 (Round 154)
> **Total audit rounds:** 154
> **Cumulative findings fixed:** 539+

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
