<p align="center">
  <h1 align="center">Sentinel</h1>
  <p align="center">
    <strong>Runtime policy engine for AI agent tool calls</strong>
  </p>
  <p align="center">
    Intercept &middot; Evaluate &middot; Enforce &middot; Audit
  </p>
</p>

---

Sentinel is a lightweight, high-performance firewall that sits between AI agents and their tools. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies on paths, domains, and actions, and maintains a tamper-evident audit trail with cryptographic guarantees.

**Key numbers:** ~60,000 lines of Rust | 1,780+ tests | <5ms P99 evaluation latency | <50MB memory baseline

## Why Sentinel?

AI agents with tool access can read files, make HTTP requests, execute commands, and modify data. Without guardrails, a prompt injection or misbehaving agent can:

- **Exfiltrate credentials** (`~/.aws/credentials`, `~/.ssh/id_rsa`)
- **Call unauthorized APIs** (sending data to `*.ngrok.io` or `*.requestbin.com`)
- **Execute destructive commands** (`rm -rf /`)
- **Bypass restrictions** via Unicode tricks, path traversal, or tool annotation changes

Sentinel enforces security policies on every tool call before it reaches the tool server, and logs every decision to a tamper-evident audit trail.

## Quick Start

```bash
# Build
cargo build --release

# Create a policy config
cat > policy.toml << 'EOF'
[[policies]]
name = "Allow file reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 10

[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 100

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
EOF

# Start the server (--allow-anonymous skips API key requirement for quick testing)
./target/release/sentinel serve --config policy.toml --port 8080 --allow-anonymous

# Evaluate a tool call (another terminal)
curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
# -> {"verdict":"Allow", ...}

curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"bash","function":"exec","parameters":{"cmd":"ls"}}' | jq .
# -> {"verdict":{"Deny":{"reason":"Denied by policy 'Block bash'"}}, ...}
```

## How It Works

```
                    +------------------+
  AI Agent -------->|    Sentinel      |--------> Tool Server
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

Sentinel supports three deployment modes:

| Mode | Binary | Use Case |
|------|--------|----------|
| **HTTP API** | `sentinel serve` | Standalone policy server; agents call `/api/evaluate` |
| **Stdio Proxy** | `sentinel-proxy` | Wraps a local MCP server; intercepts stdin/stdout |
| **HTTP Proxy** | `sentinel-http-proxy` | Reverse proxy for remote MCP servers (Streamable HTTP + SSE) |

## Policy Configuration

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

### Wildcard Parameter Scanning

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

### Require Approval

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
curl -X POST http://localhost:8080/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $SENTINEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "alice@example.com"}'

# Deny
curl -X POST http://localhost:8080/api/approvals/$APPROVAL_ID/deny \
  -H "Authorization: Bearer $SENTINEL_API_KEY"
```

Pending approvals expire after 15 minutes by default.

### Canonical Presets

Built-in policy presets for common scenarios:

```bash
sentinel policies --preset dangerous   # Blocks bash, shell, exec tools
sentinel policies --preset network     # Domain allowlisting for HTTP
sentinel policies --preset development # Project-directory-scoped file access
sentinel policies --preset deny-all    # Deny everything by default
sentinel policies --preset allow-all   # Allow everything (testing only)
```

## Deployment Modes

### HTTP API Server

The primary mode. Runs a standalone HTTP server that agents call to evaluate tool calls.

```bash
SENTINEL_API_KEY=your-secret sentinel serve --config policy.toml --port 8080 --bind 127.0.0.1
```

### MCP Stdio Proxy

Wraps a local MCP server process. Intercepts JSON-RPC messages over stdin/stdout.

```bash
sentinel-proxy --config policy.toml -- /path/to/mcp-server --arg1 --arg2
```

Features:
- Intercepts `tools/call` and `resources/read` requests
- Blocks `sampling/createMessage` requests (exfiltration vector)
- Scans responses for prompt injection patterns (OWASP MCP06)
- Detects tool annotation rug-pull attacks
- Configurable request timeout (`--timeout 30`)

### Streamable HTTP Reverse Proxy

Sits between clients and a remote MCP server over HTTP. Supports SSE streaming and session management per the MCP 2025-11-25 spec.

```bash
SENTINEL_API_KEY=your-secret sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001
```

Features:
- Session management with server-generated IDs and timeout eviction
- SSE streaming passthrough for long-running operations
- `?trace=true` query parameter for evaluation trace output
- Tool annotation tracking and rug-pull detection
- OAuth 2.1 token validation with JWKS support (`--oauth-issuer`)
- Response body size limits (10MB) to prevent upstream DoS

## HTTP API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Health check |
| `POST` | `/api/evaluate` | Yes | Evaluate a tool call against loaded policies |
| `GET` | `/api/policies` | No | List all loaded policies |
| `POST` | `/api/policies` | Yes | Add a new policy at runtime |
| `DELETE` | `/api/policies/:id` | Yes | Remove a policy by ID |
| `POST` | `/api/policies/reload` | Yes | Reload policies from config file |
| `GET` | `/api/audit/entries` | No | List audit log entries |
| `GET` | `/api/audit/report` | No | Audit summary report |
| `GET` | `/api/audit/verify` | No | Verify hash chain integrity |
| `GET` | `/api/audit/checkpoints` | No | List signed checkpoints |
| `GET` | `/api/audit/checkpoints/verify` | No | Verify checkpoint signatures |
| `POST` | `/api/audit/checkpoint` | Yes | Create a signed checkpoint |
| `GET` | `/api/approvals/pending` | No | List pending approvals |
| `GET` | `/api/approvals/:id` | No | Get approval details |
| `POST` | `/api/approvals/:id/approve` | Yes | Approve a pending request |
| `POST` | `/api/approvals/:id/deny` | Yes | Deny a pending request |
| `GET` | `/api/metrics` | No | Server metrics (evaluations, allow/deny counts, uptime) |

**Auth:** Endpoints marked "Yes" require a `Bearer` token when `SENTINEL_API_KEY` is set. GET endpoints are always open.

### Example: Evaluate

```bash
curl -X POST http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SENTINEL_API_KEY" \
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

## Audit System

Every policy decision is logged to a tamper-evident audit trail.

### Properties

- **JSONL format** -- one JSON entry per line, easy to ingest and stream
- **SHA-256 hash chain** -- each entry includes the hash of the previous entry; any tampering breaks the chain
- **Ed25519 signed checkpoints** -- periodic cryptographic snapshots of chain state for independent verification
- **Sensitive value redaction** -- API keys, tokens, passwords, and secrets are automatically redacted before logging

### Verification

```bash
# Verify the full hash chain (detects any inserted, deleted, or modified entries)
curl http://localhost:8080/api/audit/verify | jq .
# -> {"valid": true, "entries_checked": 142, "first_broken_at": null}

# Verify checkpoint signatures
curl http://localhost:8080/api/audit/checkpoints/verify | jq .
```

### Signing Key

```bash
# Use a persistent key (hex-encoded 32-byte Ed25519 seed)
export SENTINEL_SIGNING_KEY="a1b2c3d4..."

# Or let Sentinel auto-generate one (public key logged at startup)
```

Checkpoints are created every 300 seconds by default (configurable via `SENTINEL_CHECKPOINT_INTERVAL`).

## Evaluation Traces

Request a full decision trace showing which policies were checked and why:

```bash
# HTTP proxy with trace
curl -X POST "http://localhost:3001/mcp?trace=true" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"ls"}}}'
```

The trace includes:
- Number of policies checked and matched
- Per-policy constraint evaluations (parameter tested, expected vs. actual, pass/fail)
- Final verdict with reason
- Evaluation duration in microseconds

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_API_KEY` | *(unset)* | Bearer token for mutating endpoints. If unset, no auth required. |
| `SENTINEL_SIGNING_KEY` | *(auto-generated)* | Hex-encoded 32-byte Ed25519 seed for audit checkpoints |
| `SENTINEL_CHECKPOINT_INTERVAL` | `300` | Seconds between automatic audit checkpoints (0 to disable) |
| `SENTINEL_RATE_EVALUATE` | *(disabled)* | Requests/sec limit for the evaluate endpoint |
| `SENTINEL_RATE_ADMIN` | *(disabled)* | Requests/sec limit for admin (mutation) endpoints |
| `SENTINEL_RATE_READONLY` | *(disabled)* | Requests/sec limit for read-only endpoints |
| `SENTINEL_CORS_ORIGINS` | *(localhost)* | Comma-separated allowed origins (`*` for any) |
| `RUST_LOG` | `info` | Log level filter (uses `tracing` / `env_logger` syntax) |

## Architecture

Sentinel is structured as a workspace of focused crates with a strict dependency graph:

```
sentinel-types             Core types: Action, Policy, Verdict, EvaluationTrace
       |
  +----+----+
  |         |
sentinel-  sentinel-       Config parser (TOML/JSON) and built-in presets
config     canonical
  |
sentinel-engine            Policy evaluation engine with pre-compiled patterns
  |
  +--------+--------+
  |        |        |
sentinel- sentinel- sentinel-
audit     approval  mcp        Audit logging, approval store, MCP protocol
  |        |        |
  +--------+--------+
           |
  +--------+--------+
  |        |        |
sentinel-  sentinel- sentinel-
server     proxy     http-proxy   HTTP API, stdio proxy, HTTP reverse proxy
```

### Design Principles

- **Fail-closed** -- errors, missing policies, and missing parameters all result in denial
- **Pre-compiled patterns** -- all glob, regex, and domain patterns are compiled at policy load time; the evaluation hot path has zero mutex acquisitions and zero regex compilation
- **Tool-indexed evaluation** -- policies are indexed by tool name at load time for O(matching) instead of O(all policies)
- **Zero `unwrap()` in library code** -- all error paths return typed errors; panics are reserved for tests only

### Performance

All patterns are pre-compiled at load time using:
- **Aho-Corasick automaton** for multi-pattern injection scanning (15 patterns in a single pass)
- **Compiled glob matchers** and **compiled regex** for constraint evaluation
- **Cow-based path/domain normalization** to avoid allocations when no transformation is needed
- **Pre-computed verdict reason strings** to eliminate `format!()` on the hot path
- **ASCII fast-path** for Unicode sanitization (skips NFKC for >95% of responses)

Benchmark results (from criterion, single-threaded):
- Single policy evaluation: **7-31 ns**
- 100 policies: **~1.2 us**
- 1,000 policies: **~12 us**

## Security Properties

| Property | Implementation |
|----------|---------------|
| **Fail-closed** | Empty policy set, missing parameters, and evaluation errors all produce `Deny` |
| **Path normalization** | Resolves `..`, `.`, percent-encoding (multi-layer), null bytes; prevents traversal |
| **Domain normalization** | Handles trailing dots, case folding, `@` in authority, scheme/port stripping |
| **Injection detection** | Aho-Corasick multi-pattern matching with Unicode evasion resistance (NFKC normalization, zero-width/bidi/tag character stripping) |
| **Rug-pull detection** | Alerts when MCP servers change tool annotations, remove tools, or add new tools after initial handshake |
| **Sampling interception** | Blocks `sampling/createMessage` (known exfiltration vector in MCP) |
| **Constant-time auth** | API key comparison uses `subtle::ConstantTimeEq` to prevent timing attacks |
| **Tamper-evident audit** | SHA-256 hash chain with Ed25519 signed checkpoints; any modification breaks the chain |
| **Sensitive redaction** | 15 key patterns and 10 value prefixes automatically redacted before audit logging |

### Known Limitations

- **Injection detection is a pre-filter, not a security boundary.** Pattern-based injection detection catches known attack signatures but can be evaded by motivated attackers using encoding, typoglycemia, semantic synonyms, or novel phrasing. It is one layer in a defense-in-depth strategy and should not be relied upon as the sole protection against prompt injection.

- **TOCTOU (Time-of-Check to Time-of-Use).** The proxy evaluates a parsed representation of the JSON-RPC message. JSON round-tripping (duplicate keys, numeric precision) is handled deterministically by `serde_json` (last-key-wins, IEEE 754), but this represents a known limitation: the serialized bytes forwarded to upstream are the original request bytes, not a re-serialized copy, which mitigates but does not fully eliminate divergence risks.

- **Action model design.** Path and domain enforcement is implemented via parameter constraints (`parameters` JSON deep scanning) rather than dedicated `Action` struct fields. This enables recursive inspection of arbitrary nested JSON parameters without requiring tool-specific schema knowledge. The tradeoff is that policies must express path/domain rules as parameter matchers rather than first-class fields.

- **Checkpoint trust anchor.** Checkpoint signatures use self-embedded Ed25519 public keys by default (TOFU model). For stronger guarantees, pin a trusted verifying key via the `SENTINEL_TRUSTED_KEY` environment variable to prevent an attacker with file write access from forging checkpoints with their own keypair.

## CLI Reference

```bash
# HTTP policy server
sentinel serve --config policy.toml [--port 8080] [--bind 127.0.0.1] [--allow-anonymous]

# One-shot evaluation (no server needed)
sentinel evaluate --tool file --function read \
  --params '{"path":"/tmp/x"}' --config policy.toml

# Validate a config file
sentinel check --config policy.toml

# Output canonical presets as TOML
sentinel policies --preset dangerous

# Verify audit log integrity
sentinel verify --audit-log audit.log

# Stdio MCP proxy (wraps a local MCP server)
sentinel-proxy --config policy.toml [--strict] [--timeout 30] [--trace] \
  -- ./mcp-server --arg1

# HTTP reverse proxy (for remote MCP servers)
sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  [--listen 127.0.0.1:3001] \
  [--session-timeout 1800] \
  [--max-sessions 1000] \
  [--audit-log audit.log] \
  [--strict] \
  [--allow-anonymous]

# HTTP reverse proxy with OAuth 2.1
sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --oauth-issuer https://auth.example.com \
  --oauth-audience mcp-server \
  --oauth-scopes mcp:read,mcp:write \
  [--oauth-pass-through]
```

## Development

```bash
# Run all tests (~1,500+)
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets

# Build optimized release (thin LTO, single codegen unit)
cargo build --release

# Run criterion benchmarks
cargo bench -p sentinel-engine

# Check for unwrap() in library code (should be zero)
rg '\.unwrap\(\)' --type rust -g '!**/tests/*' -g '!**/main.rs' -g '!**/bench*'
```

## Project Structure

```
sentinel/
  sentinel-types/          Core shared types
  sentinel-engine/         Policy evaluation engine
  sentinel-audit/          Tamper-evident audit logging
  sentinel-approval/       Human-in-the-loop approval store
  sentinel-config/         TOML/JSON config parser
  sentinel-canonical/      Built-in policy presets
  sentinel-mcp/            MCP protocol handling + injection scanning
  sentinel-server/         HTTP API server binary
  sentinel-proxy/          Stdio MCP proxy binary
  sentinel-http-proxy/     Streamable HTTP reverse proxy binary
  sentinel-integration/    Integration and E2E tests
```

## License

See LICENSE file.
