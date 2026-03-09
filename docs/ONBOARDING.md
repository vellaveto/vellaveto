# Mandatory Codebase Orientation Protocol

Every instance — agent, Claude Code session, or contributor — MUST follow this
protocol before modifying any code. Compiling and running tests is necessary but
not sufficient. You must **understand** before you **change**.

This protocol exists because 250 adversarial audit rounds exposed a recurring
pattern: breakage caused by assumptions rather than verified understanding.

---

## 1. Read-Before-Touch Protocol

These rules are non-negotiable. Violating them is how tests break.

### Before modifying any file
- **Read the entire file** (or at minimum the surrounding 100 lines), not just the
  line you want to change. Context determines correctness.

### Before modifying any type, function, or method
- Read all callers: `grep -rn 'function_name' vellaveto-*/src/`
- Read all tests that reference it: `grep -rn 'function_name' vellaveto-*/src/tests.rs`
- Read integration tests: `grep -rn 'function_name' vellaveto-integration/tests/`

### Before modifying an error message string
- **Grep for the exact old string in all test files.** Tests assert on error
  message content. If you change the message without updating the assertions,
  tests will fail.
  ```bash
  grep -rn "old error text" vellaveto-*/src/tests.rs vellaveto-integration/tests/
  ```

### Before using a constant
- Verify it is the **semantically correct** constant, not just a name-similar one.
  Example: `MAX_ID_LENGTH (256)` vs `MAX_SERVER_ID_LENGTH (512)` are different
  constants for different domains. Using the wrong one silently rejects valid input.

### Before adding a dependency
- Check if an existing crate already provides the functionality.
- Justify the addition in the commit message.
- Verify the crate's security record and maintenance status.
- Every dependency is attack surface.

---

## 2. Cross-Reference Checklist

Run this checklist **before committing** any change. Not all items apply to every
change — use the ones relevant to what you modified.

### Type changes (`vellaveto-types`)
- [ ] Check every crate that imports the changed type (`grep -rn 'TypeName' vellaveto-*/src/`)
- [ ] If you added/removed a field: update `validate()`, update `deny_unknown_fields` if present
- [ ] If you changed a field type: check all serialization/deserialization sites
- [ ] If you changed an enum variant: check all `match` arms across the workspace

### Error message changes
- [ ] Grep for the **exact old string** in `tests.rs` files and integration tests
- [ ] Update every assertion that matches on the old message text
- [ ] Verify the new message is consistent with similar messages in the same module

### New struct fields
- [ ] Add bounds in `validate()` (max length, max count, range for numerics)
- [ ] Add `#[serde(deny_unknown_fields)]` if the struct is deserialized from external input
- [ ] Add unit test for the validation
- [ ] Add adversarial test with boundary values
- [ ] If the field is a collection: add a `MAX_*` constant and enforce it

### Feature additions (HTTP handler, proxy, etc.)
- [ ] Verify **all transports** have parity (see Section 4)
- [ ] If HTTP handler has it, WebSocket handler must too
- [ ] If server has it, SDKs (Python/TypeScript/Go) must match

### SDK changes
- [ ] Verify all 3 SDKs (Python/TypeScript/Go) send the same payload format
- [ ] Verify the payload matches the server's expected `#[serde(flatten)]` or nested structure
- [ ] Run SDK-specific tests (`pytest`, `npm test`, `go test`)

### Configuration changes
- [ ] Validate new config fields in `validate()` with bounds
- [ ] Reject control characters in string config fields
- [ ] Add default that is **fail-closed** (Deny), not fail-open (Allow)
- [ ] Document the field in the config struct's doc comment

### Security-critical paths
- [ ] Verify error paths produce `Deny`, not `Allow`
- [ ] Verify RwLock poisoning is handled (not `unwrap()`)
- [ ] Verify no secrets leak in error messages, Debug output, or logs
- [ ] Verify arithmetic uses `saturating_add` / `saturating_sub` for counters

---

## 3. The 17 Assumption Traps

These are the most common mistakes from 250 audit rounds. Each one has caused
real CI failures or security findings. Read them. Memorize them.

### Trap 1: Wrong constant for the domain
**BEFORE** using a constant, **VERIFY** its doc comment describes your exact use
case. `MAX_ID_LENGTH` and `MAX_SERVER_ID_LENGTH` are not interchangeable.

### Trap 2: Changed message, forgot the tests
**BEFORE** changing any error message string, **GREP** for the old string in all
test files. Tests assert on exact substrings.

### Trap 3: Unbounded collection
**BEFORE** adding a `Vec`, `HashMap`, `HashSet`, or `BTreeMap` field to any
struct, **ADD** a `MAX_*` constant and enforce it in `validate()`. Attacker-
controlled input will maximize it.

### Trap 4: Unbounded numeric field
**BEFORE** adding a `f64` or `f32` field, **ADD** range validation (typically
`[0.0, 1.0]` for scores, `> 0` for counts). Check for `NaN` and `Infinity`
with `validate_finite()` or equivalent. Negative values bypass threshold checks.

### Trap 5: Fail-open default
**BEFORE** adding a default value or `Default` impl for a security type,
**VERIFY** the default is fail-closed. `ToolSensitivity::default()` must be
restrictive. Error branches must produce `Deny`.

### Trap 6: Leaking secrets in Debug
**BEFORE** adding `#[derive(Debug)]` to a type with keys, tokens, signatures,
or credentials, **IMPLEMENT** a custom `Debug` that redacts sensitive fields.
`ToolSignature { signature: "[REDACTED]", .. }`.

### Trap 7: Missing transport parity
**BEFORE** finishing a feature on one transport (HTTP), **CHECK** Section 4's
parity matrix. WebSocket, gRPC, stdio, and SSE handlers must have the same
security checks. Round 52 found 7 parity gaps.

### Trap 8: Relaxed atomics on security counters
**BEFORE** using `Ordering::Relaxed` on an atomic counter, **VERIFY** the
counter does not affect security decisions (rate limits, sequence numbers,
circuit breakers). Use `SeqCst` for security-critical counters.

### Trap 9: Wrapping arithmetic on counters
**BEFORE** using `+= 1` or `.fetch_add(1, ...)` on a counter, **USE**
`saturating_add` instead. Overflow wraps to zero, which resets rate limits
and bypasses circuit breakers.

### Trap 10: Public mutable fields on security types
**BEFORE** making a field `pub` on a security-critical struct, consider
`pub(crate)` with accessor methods that enforce invariants. Direct mutation
bypasses `validate()` bounds.

### Trap 11: Serialization errors silently swallowed
**BEFORE** calling `.ok()` or `.unwrap_or_default()` on a serialization
result, **PROPAGATE** the error. Silent serialization failure in policy
evaluation means implicit Allow.

### Trap 12: Missing control/format character validation
**BEFORE** accepting a string from external input (agent IDs, tenant IDs,
tool names), **VALIDATE** it rejects both ASCII control characters
(`c.is_control()`) and Unicode format characters (zero-width, bidi overrides,
BOM). Use `is_unicode_format_char()` from `EvaluationContext`.

### Trap 13: SDK payload format mismatch
**BEFORE** changing the server's request/response format, **UPDATE** all 3
SDKs. The server uses `#[serde(flatten)]` in some structs — SDKs must send
flattened fields, not nested objects.

### Trap 14: Missing depth/size limits on recursive structures
**BEFORE** adding recursive parsing (Merkle proofs, delegation chains, JSON
nesting), **ADD** `MAX_DEPTH` and `MAX_SIZE` constants enforced at parse time.
Attacker input will maximize nesting.

### Trap 15: Template/format string injection
**BEFORE** interpolating user-controlled strings into output (logs, HTML,
config, error messages), **SANITIZE** the input. Strip control characters,
escape for the output context (HTML entities, shell escaping, etc.).

### Trap 16: Tooling version drift from CI
**BEFORE** assuming local checks are sufficient, **VERIFY** your local
`rustfmt`, `clippy`, and `cargo-deny` versions match CI. Format rules and
lint rules change between versions. Run with `--locked` to match CI.

### Trap 17: Protocol compliance assumed, not validated
**BEFORE** accepting a JWT, ISO 8601 timestamp, MCP tool name, or any
standards-defined value, **ADD** explicit format validation. Parse success
does not mean standards compliance. Validate `nbf`/`aud` on JWTs, format on
timestamps, character set on tool names.

---

## 4. Transport / SDK Parity Matrix

When adding or modifying a security feature, verify it exists across ALL
applicable transports and SDKs. A check mark means the feature MUST be present.

### Security Features × Transports

| Feature                    | HTTP | WebSocket | gRPC | stdio | SSE GET |
|----------------------------|------|-----------|------|-------|---------|
| DLP parameter scanning     |  Y   |     Y     |  Y   |   Y   |    Y    |
| Injection detection        |  Y   |     Y     |  Y   |   Y   |    Y    |
| Memory poisoning detection |  Y   |     Y     |  Y   |   Y   |    -    |
| OAuth token expiry check   |  Y   |     Y     |  Y   |   -   |    Y    |
| Session ownership binding  |  Y   |     Y     |  -   |   -   |    Y    |
| Agent identity validation  |  Y   |     Y     |  Y   |   Y   |    Y    |
| Call chain validation      |  Y   |     Y     |  Y   |   Y   |    Y    |
| Audit logging              |  Y   |     Y     |  Y   |   Y   |    Y    |
| Rug-pull detection         |  Y   |     Y     |  Y   |   Y   |    Y    |
| Rate limiting              |  Y   |     Y     |  Y   |   -   |    Y    |
| Output schema validation   |  Y   |     Y     |  Y   |   Y   |    Y    |
| Request body size limit    |  Y   |     Y     |  Y   |   Y   |    -    |
| Control char validation    |  Y   |     Y     |  Y   |   Y   |    Y    |

### SDK Method Parity

| Feature                | Python (sync) | Python (async) | TypeScript | Go  |
|------------------------|---------------|----------------|------------|-----|
| evaluate()             |       Y       |       Y        |     Y      |  Y  |
| approve/deny           |       Y       |       Y        |     Y      |  Y  |
| audit export           |       Y       |       Y        |     Y      |  Y  |
| discovery search       |       Y       |       Y        |     Y      |  Y  |
| projector transform    |       Y       |       Y        |     Y      |  Y  |
| zk_status/proofs/verify|       Y       |       Y        |     Y      |  Y  |
| access review          |       Y       |       Y        |     Y      |  Y  |
| federation status      |       Y       |       Y        |     Y      |  Y  |
| Input validation       |       Y       |       Y        |     Y      |  Y  |
| Retry with backoff     |       Y       |       Y        |     Y      |  Y  |

When you add a new SDK method to one language, add it to ALL languages.

---

## 5. Verification Gates

Run these **before every commit**. This is the expanded version of the
"Before Every Session" check from CLAUDE.md.

```bash
# 1. Compile the workspace
cargo check --workspace

# 2. Run all tests (catches assertion mismatches, logic errors)
cargo test --workspace --no-fail-fast

# 3. Clippy with CI-exact flags (catches lint regressions)
cargo clippy --workspace --all-targets --locked -- -D warnings

# 4. Format check (catches rustfmt version drift)
cargo fmt --all -- --check

# 5. No unwrap()/expect() in library code (CI rejects this)
find vellaveto-*/src/ -name '*.rs' \
  -not -name 'main.rs' -not -name 'tests.rs' -not -name '*_tests.rs' \
  | xargs awk 'FNR==1 { skip=0 }
    /^#\[cfg\(test\)\]/ { skip=1 }
    skip==0 && /^[[:space:]]*(\/\/!|\/\/\/)/ { next }
    skip==0 && /\.unwrap\(\)/ { printf "%s:%d: %s\n", FILENAME, FNR, $0; found=1 }
    skip==0 && /\.expect\(/ { printf "%s:%d: %s\n", FILENAME, FNR, $0; found=1 }
    END { exit found ? 1 : 0 }'

# 6. If you changed an error message, verify no test asserts on the old text
grep -rn "<your_old_message_text>" vellaveto-*/src/tests.rs vellaveto-integration/tests/
```

In restricted sandboxes/containers, local socket binds may fail with
`PermissionDenied`. Integration tests that require `127.0.0.1:0` should skip
only that path and still fail fast on any other bind error.

If ANY gate fails, fix it before committing. Do not push with known failures.

---

## Quick Reference: Session Startup

Every session, every instance, every time:

```bash
# 1. Check repo state
git status

# 2. Compile
cargo check --workspace 2>&1 | head -50

# 3. Run tests — if these fail, STOP and fix before doing anything else
cargo test --workspace --no-fail-fast 2>&1 | tail -5

# 4. Lint
cargo clippy --workspace

# 5. Read this file and CLAUDE.md
# 6. If working on a specific crate, read its src/lib.rs and src/tests.rs
# 7. If working on a type, grep for all usages before modifying
```

**If tests fail at session start: STOP. Diagnose and fix before proceeding.**
Do not assume someone else will fix it. Do not work around it. Fix it.
