# Tasks for Instance A

## READ THIS FIRST

**CONTROLLER DIRECTIVE C-1 IS ACTIVE: All feature work is halted. Security fixes only.**

Check `controller/directives.md` for full details. These tasks implement **Directive C-3**.

Update `.collab/instance-a.md` after each task.

---

## COMPLETED TASKS (for reference)
- [x] Task A1: Create CI workflow -- DONE (.github/workflows/ci.yml)
- [x] Path/domain integration tests -- DONE (15 tests in sentinel-integration)
- [x] 16 parameter constraints E2E tests -- DONE
- [x] 8 approval flow tests -- DONE
- [x] TASKS.md update -- DONE
- [x] Fixed compile break from Instance B's approval changes

---

## ACTIVE SECURITY TASKS (Directive C-3)

### Task S-A1: Add Server Authentication (CRITICAL #7)
**Priority: CRITICAL -- No auth on any endpoint**
**Directive:** C-3

Add API key authentication as Tower middleware:

1. Create auth middleware that checks `Authorization: Bearer <key>` header
2. Apply to ALL mutating endpoints (`POST`, `PUT`, `DELETE`)
3. Read-only endpoints (`GET /api/health`, `GET /api/audit/entries`) may remain unauthenticated
4. API key configurable via:
   - Environment variable `SENTINEL_API_KEY`
   - Config file field `server.api_key`
5. Replace `CorsLayer::permissive()` with `CorsLayer::new()` with explicit allowed origins (configurable via `server.cors_origins` in config)
6. Return `401 Unauthorized` for missing/invalid auth
7. Return `403 Forbidden` if key doesn't match

**Files to modify:**
- `sentinel-server/src/lib.rs` — add auth middleware, update AppState
- `sentinel-server/src/routes.rs` — apply middleware selectively
- `sentinel-server/src/main.rs` — read API key from env/config
- `sentinel-server/example-config.toml` — add auth config example

**Test:** Must include unit test for middleware and integration test showing unauthenticated mutating requests are rejected.

---

### Task S-A2: Default Bind to 127.0.0.1 (HIGH)
**Priority: HIGH**
**Directive:** C-3

Change the default bind address:

1. Default from `0.0.0.0` to `127.0.0.1` in `sentinel-server/src/main.rs`
2. Keep `0.0.0.0` available via CLI flag `--bind` for explicit opt-in
3. Document the change in example config

---

### Task S-A3: Security Regression Test Suite (CRITICAL)
**Priority: CRITICAL -- Validates ALL security fixes**
**Directive:** C-3

Create `sentinel-integration/tests/security_regression.rs` with tests for ALL 14 CRITICAL/HIGH findings.

Each test MUST:
1. Demonstrate the vulnerability (the attack succeeds before the fix)
2. Verify the fix blocks the attack
3. Have a clear name indicating which finding it covers

**Required tests:**

| Finding | Test |
|---------|------|
| #1 Hash chain bypass | Verify hashless entries rejected after chain starts |
| #2 Hash field separators | Verify field-boundary-shift collisions are impossible |
| #3 initialize_chain trusts file | Verify tampered file is detected on init |
| #4 last_hash before write | Verify I/O failure doesn't advance hash state |
| #5 Empty tool name | Verify empty/missing tool name is handled safely |
| #6 Unbounded read_line | Verify oversized messages are rejected |
| #7 No auth | Verify unauthenticated mutating requests return 401 |
| #8 `@` bypass | Verify `?email=user@safe.com` doesn't bypass domain check |
| #9 normalize_path empty | Verify empty normalization returns `/` not raw input |
| #10 Approval persistence | Verify approvals survive restart |
| #11 unwrap_or_default | Verify malformed requests return 400 not default |
| #12 Approval creation failure | Verify failure results in deny |
| #13 Audit wrong verdict | Verify RequireApproval is recorded correctly |
| #14 Empty line proxy | Verify empty lines don't terminate proxy |

**Note:** Some tests may need to be written as "expected behavior" tests if the fix hasn't landed yet. Coordinate with Instance B — their fixes (findings 1-6, 8, 9, 14) must be in place for those regression tests to verify the fix.

---

## PAUSED TASKS (Resume after Phase 0 complete)

These tasks from the improvement plan are ON HOLD per Directive C-1:

- ~~Task A2: MCP Proxy Integration Tests~~ — resume as Phase 5 work
- ~~Task A3: Property-Based Tests~~ — resume as Phase 7 work
- ~~Task A4: Criterion Benchmarks~~ — resume as Phase 7 work

---

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. **Check `controller/directives.md` before starting new work**
4. **Security tasks take absolute priority over everything else**
5. Your file ownership: `.github/`, `sentinel-integration/tests/`, TASKS.md, `sentinel-server/` (for auth work)
