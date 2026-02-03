# Instance A — Status

## Identity
I am the instance that ran baseline checks and handles testing, CI, and validation.

## Current status: C-16.1 — README Update + Collab Sync COMPLETE

## Completed work (chronological)
- Fixed P0 warnings (strict_mode, unused Deserialize)
- Installed clippy
- Fixed normalize_path bug (root escape)
- 66 unit tests for constraint operators (sentinel-engine)
- 15 integration tests for security scenarios (sentinel-integration)
- Security finding: narrow globs vulnerable to traversal, documented with tests
- Fixed compile break from Instance B's approval changes (3 files)
- **Task A1:** Created `.github/workflows/ci.yml` + fixed all clippy warnings across workspace (~30 fixes)
- **Task A2:** Created `parameter_constraints_e2e.rs` — 16 E2E tests (config→engine→audit pipeline)
- **Task A3:** Created `approval_flow.rs` — 8 approval workflow tests
- **Task A4:** Updated TASKS.md progress tracking
- **Directive C-3:** Fix #7 (server auth), Fix #26 (default bind), 32 security regression tests
- **Directive C-7:** Fix #31 (rate limiting), 8 property-based tests (proptest), ArcSwap migration fixes
- **Directive C-8.4:** OWASP MCP Top 10 test coverage — 39 tests in `owasp_mcp_top10.rs`
- **Directive C-10 A1:** Rate limit polish — /health exempt, Retry-After header, CORS max_age
- **Directive C-10 A2:** Cross-review of Instance B's code → `.collab/review-b-by-a.md`
- **Directive C-10 A3:** Criterion benchmarks — 22 benchmarks in `sentinel-engine/benches/evaluation.rs`
- **Should Fix #5:** Audit trail for policy mutations (add/remove/reload) + 2 tests
- **Phase 9.1:** Created `sentinel-http-proxy` crate — Streamable HTTP reverse proxy
  - `src/main.rs`: CLI entry point with clap, policy loading, session store, axum router, graceful shutdown
  - `src/proxy.rs`: POST /mcp handler (classify → evaluate → forward/block), DELETE /mcp, upstream forwarding with SSE support, injection scanning, annotation extraction, rug-pull detection
  - `src/session.rs`: DashMap-backed concurrent session store, expiry, server-generated IDs
  - 24 unit tests + 19 integration tests = 43 total
  - Restructured to lib+bin for integration test access
  - Fixed ArcSwap mismatch in sentinel-server test files
  - Fixed `build_tool_index` in sentinel-engine (Phase 10.5 tool index)
  - Created meetup sync doc at `.collab/meetup-phase9-sync.md`
- **C-12 Task #1:** Integration tests — 22 integration tests for sentinel-http-proxy
- **C-12 Task #2:** Rug-pull detection parity — tool removal, addition, annotation change detection in HTTP proxy
  - Added `tools_list_seen` field to SessionState
  - Rewrote `extract_annotations_from_response` with 3 detection types + audit logging
  - 3 stateful mock server integration tests with AtomicUsize counters
- **C-12 Task #3:** Phase 10.4 Evaluation Trace — OPA-style decision explanations
  - `EvaluationTrace`, `ActionSummary`, `PolicyMatch`, `ConstraintResult` types in sentinel-types
  - `evaluate_action_traced()` method in sentinel-engine (9 unit tests)
  - `?trace=true` query parameter on POST /mcp in sentinel-http-proxy
  - Denied responses include `trace` field in JSON body
  - Allowed responses include `X-Sentinel-Trace` header with JSON trace
  - 5 integration tests (deny trace, allow trace, no-trace default, resource trace, constraint details)

## Directive C-8.4 — OWASP MCP Top 10 Coverage
39 tests across all 10 OWASP MCP risks:

| OWASP Risk | Tests | Status |
|------------|-------|--------|
| MCP01 Token Mismanagement | 4 tests (key redaction, prefix redaction, nested, hash chain) | GOOD |
| MCP02 Tool Access Control | 5 tests (deny, no-match, empty, wildcard, priority) | GOOD |
| MCP03 Tool Poisoning | 1 placeholder (awaiting C8-B1) | PARTIAL |
| MCP04 Privilege Escalation | 4 tests (deny-override, priority, require_approval, forbidden_params) | GOOD |
| MCP05 Command Injection | 5 tests (traversal, regex, domain, deep scan, encoded) | GOOD |
| MCP06 Prompt Injection | 1 placeholder (awaiting C8-B2) | PARTIAL |
| MCP07 Auth | 8 tests (evaluate, mutation, deletion, approval, wrong key, correct, GET open) | GOOD |
| MCP08 Audit & Telemetry | 4 tests (tampering, hashes, encoding, verify API) | EXCELLENT |
| MCP09 Insufficient Logging | 4 tests (all verdicts, deny reason, details, report) | GOOD |
| MCP10 Denial of Service | 4 tests (oversized, rate limit, normal, disabled) | GOOD |

## Files I own / have touched
- .github/workflows/ci.yml (NEW)
- sentinel-integration/tests/parameter_constraints_e2e.rs (NEW)
- sentinel-integration/tests/approval_flow.rs (NEW)
- sentinel-integration/tests/fixtures/test-policy.toml (NEW)
- sentinel-integration/tests/path_domain_security.rs (NEW)
- sentinel-integration/tests/security_regression.rs (auth tests, AppState updates)
- sentinel-integration/tests/owasp_mcp_top10.rs (NEW — C-8.4)
- sentinel-integration/Cargo.toml (added sentinel-config, sentinel-approval deps)
- sentinel-engine/Cargo.toml (added proptest dev-dep)
- sentinel-engine/tests/proptest_properties.rs (NEW — 8 property tests)
- sentinel-engine/src/lib.rs (tests + normalize_path fix)
- sentinel-server/Cargo.toml (added governor)
- sentinel-server/src/lib.rs (RateLimits struct)
- sentinel-server/src/routes.rs (rate_limit middleware)
- sentinel-server/src/main.rs (rate limit env config)
- sentinel-server/tests/test_routes_*.rs (AppState updates)
- TASKS.md (progress update)
- .collab/* (collab channel)

## Files I created (Phase 9.1)
- sentinel-http-proxy/Cargo.toml (NEW)
- sentinel-http-proxy/src/main.rs (replaced stub)
- sentinel-http-proxy/src/proxy.rs (NEW)
- sentinel-http-proxy/src/session.rs (NEW)
- sentinel-http-proxy/src/lib.rs (NEW)
- sentinel-http-proxy/tests/proxy_integration.rs (NEW — 27 integration tests)

## Files modified (Phase 10.4)
- sentinel-types/src/lib.rs (added EvaluationTrace, ActionSummary, PolicyMatch, ConstraintResult)
- sentinel-engine/src/lib.rs (added evaluate_action_traced, collect_candidate_indices, constraint_matches_value + helper fns, 9 tests)
- sentinel-http-proxy/src/proxy.rs (added McpQueryParams, ?trace=true, attach_trace_header)

## Phase 9.3: OAuth 2.1 — COMPLETE
- **`sentinel-http-proxy/src/oauth.rs`** (NEW, 510 lines):
  - `OAuthConfig` with issuer, audience, JWKS URI, scopes, pass-through, allowed-algorithms
  - `OAuthValidator` with JWKS caching (5-min TTL), RS256/ES256/EdDSA support
  - `OAuthClaims` with custom `aud` deserializer (string or array)
  - `OAuthError` with distinct error types (MissingToken, InvalidFormat, JwtError, InsufficientScope, JwksFetchFailed, NoMatchingKey, DisallowedAlgorithm, MissingKid)
  - Algorithm confusion attack prevention (asymmetric-only allow list)
  - `key_algorithm_to_algorithm()` explicit mapping (no Debug format comparison)
  - `validate_nbf` enabled for not-before claim
  - 11 unit tests
- **`sentinel-http-proxy/src/main.rs`** (+44 lines): CLI args `--oauth-issuer`, `--oauth-audience`, `--oauth-jwks-uri`, `--oauth-scopes`, `--oauth-pass-through`
- **`sentinel-http-proxy/src/proxy.rs`** (+191 lines):
  - `validate_oauth()` middleware on POST /mcp and DELETE /mcp
  - `build_audit_context()` includes OAuth subject + scopes in audit entries
  - Auth header pass-through to upstream when configured
  - Session-level OAuth subject tracking for audit trail
  - Session ownership enforcement on DELETE /mcp
- **`sentinel-http-proxy/src/session.rs`** (+4 lines): `oauth_subject` field
- **`sentinel-http-proxy/tests/proxy_integration.rs`** (+450 lines): 11 OAuth integration tests:
  - `oauth_enabled_no_token_returns_401`
  - `oauth_enabled_invalid_token_returns_401`
  - `oauth_enabled_expired_token_returns_401`
  - `oauth_enabled_valid_token_forwards_request`
  - `oauth_insufficient_scope_returns_403`
  - `oauth_valid_scopes_allows_request`
  - `oauth_subject_stored_in_session`
  - `oauth_delete_mcp_requires_token`
  - `oauth_pass_through_forwards_auth_header`
  - `oauth_no_pass_through_strips_auth_header`
  - `oauth_denied_tool_audit_includes_subject`

## C-15 Phase 2+3 Pentest Fixes — COMPLETE

Instance A worked on the following C-15 exploit fixes in its files:

### Exploit #9: Rug-pull detection enforcement
- **`sentinel-http-proxy/src/session.rs`**: Added `flagged_tools: HashSet<String>` to `SessionState`
- **`sentinel-http-proxy/src/proxy.rs`**:
  - `extract_annotations_from_response()` populates `flagged_tools` when annotation changes or new tools detected
  - `handle_mcp_post()` checks `flagged_tools` before policy evaluation, blocks with -32001 error
- **`sentinel-http-proxy/tests/proxy_integration.rs`**: 2 new integration tests:
  - `rug_pull_annotation_change_blocks_tool_call` — annotation change → tool blocked
  - `rug_pull_tool_addition_blocks_tool_call` — new tool after initial list → blocked, original tools still allowed

### Exploit #6: SSE injection scanning (implemented by linter, verified by Instance A)
- `scan_sse_events_for_injection()` buffers SSE, parses events, scans data payloads
- 7 unit tests covering JSON data, raw text, multiple events, system tags, empty data

### Exploit #15: Audit flush on HTTP proxy shutdown
- `main.rs`: `shutdown_audit.sync().await` + `create_checkpoint()` on graceful shutdown
- Matches sentinel-server pattern with checkpoint for full audit trail parity

## C-16.1: README Update + Collab Sync — COMPLETE

Instance A executed C-16.1 (issued by Controller):

**README.md updates:**
- Updated key numbers: ~53,000 → ~60,000 lines, 1,500+ → 1,780+ tests
- Fixed Quick Start: added `--allow-anonymous` flag (required since API key enforcement)
- Fixed `SENTINEL_API_KEY` description: now marked as required (was "if unset, no auth")
- Fixed CLI reference: `--session_timeout` → `--session-timeout`, added `--audit-log`, `--strict`, `--allow-anonymous`
- Added `sentinel verify --audit audit.log` command
- Added OAuth 2.1 CLI example with `--oauth-issuer`, `--oauth-audience`, `--oauth-scopes`
- Added `--trace` flag to sentinel-proxy reference
- Added 3 new Security Properties rows: SSE body limits, OAuth 2.1, adversarial hardening
- Added HTTP proxy features: OAuth 2.1 and response body size limits
- Verified all CLI flags against actual `--help` output for all 3 binaries

**Collab sync:**
- Updated instance-a.md with current test counts and C-16 completion

## Available for
- All C-15 and C-16.1 work complete
- Available for any new directives

## Test counts
- sentinel-http-proxy: 36 unit + 42 integration = 78 total
- Full workspace: **1,786 tests, 0 failures**
- Clippy: 0 warnings
- Fmt: clean

## Last updated: 2026-02-03
