<p align="center">
  <h1 align="center">Sentinel</h1>
  <p align="center">
    <strong>Runtime security engine for AI agent tool calls</strong>
  </p>
  <p align="center">
    Intercept &middot; Evaluate &middot; Enforce &middot; Audit
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#policy-configuration">Policies</a> &middot;
    <a href="#deployment-modes">Deployment</a> &middot;
    <a href="#http-api-reference">API</a> &middot;
    <a href="#audit-system">Audit</a>
  </p>
</p>

---

Sentinel is a lightweight, high-performance firewall that sits between AI agents and their tools. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies on paths, domains, and actions, and maintains a tamper-evident audit trail with cryptographic guarantees.

| Metric | Value |
|--------|-------|
| Language | Rust |
| Test suite | 2,400+ tests |
| Evaluation latency | <5ms P99 |
| Memory baseline | <50MB |
| License | MIT |

## Why Sentinel?

AI agents with tool access can read files, make HTTP requests, execute commands, and modify data. Without guardrails, a prompt injection or misbehaving agent can:

- **Exfiltrate credentials** (`~/.aws/credentials`, `~/.ssh/id_rsa`)
- **Call unauthorized APIs** (sending data to `*.ngrok.io` or `*.requestbin.com`)
- **Execute destructive commands** (`rm -rf /`)
- **Bypass restrictions** via Unicode tricks, path traversal, or tool annotation changes

Sentinel enforces security policies on every tool call before it reaches the tool server, and logs every decision to a tamper-evident audit trail.

## Features

- **Policy engine** with glob, regex, and domain matching on tool calls and parameters
- **Three deployment modes**: HTTP API server, MCP stdio proxy, and HTTP reverse proxy
- **Parameter constraints** with deep recursive JSON scanning
- **Human-in-the-loop approvals** with deduplication and audit trail
- **Tamper-evident audit logging** with SHA-256 hash chains, Ed25519 signed checkpoints, and rotation chain continuity
- **Injection detection** via Aho-Corasick multi-pattern scanning with Unicode normalization and configurable blocking mode
- **Rug-pull detection** for MCP tool annotation changes, schema mutations, and persistent flagging across restarts
- **Child process crash detection** with pending request flush and audit logging
- **OAuth 2.1 / JWT** validation with JWKS and scope enforcement
- **CSRF protection** via Origin header validation on mutating endpoints
- **Rate limiting** per-IP, per-principal, and per-endpoint with configurable burst
- **Security headers** including HSTS, CSP, X-Frame-Options, and X-Permitted-Cross-Domain-Policies
- **Input validation** with ReDoS protection, action name validation, and RFC 1035 domain pattern checking
- **Absolute session lifetime** enforcement alongside inactivity timeout
- **Evaluation traces** for full decision explainability (OPA-style)
- **Pre-compiled patterns** with zero allocations on the evaluation hot path
- **Canonical presets** for common security scenarios (dangerous tools, network allowlisting, etc.)
- **DLP response scanning** — detects secrets (AWS keys, GitHub tokens, JWTs, etc.) in tool responses, not just request parameters
- **Structured output validation** — OutputSchemaRegistry validates `structuredContent` against declared `outputSchema`, preventing response injection (puppet attacks)
- **MCP 2025-06-18 compliance** — MCP-Protocol-Version header, RFC 8707 resource indicators, `_meta` field preservation, tool title tracking
- **Context-aware policies** — time windows, per-session call limits, agent ID restrictions, and action sequence enforcement
- **Custom PII patterns** — user-defined regex patterns for audit log redaction
- **TOCTOU canonicalization** — re-serialization of JSON-RPC messages before forwarding (on by default; opt out with `--no-canonicalize`)
- **Task request enforcement** — `tasks/get` and `tasks/cancel` evaluated through full policy engine
- **CI security scanning** with `cargo audit` and library code hygiene checks

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

# Start the server
SENTINEL_API_KEY=your-secret sentinel serve --config policy.toml --port 8080

# Evaluate a tool call (another terminal)
curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
# -> {"verdict":"Allow", ...}

curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
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

### Rate Limiting

Rate limits can be configured in the TOML config file. Environment variables override config values when set.

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

Per-principal rate limiting keys requests by identity: the `X-Principal` header if present, then the Bearer token from the `Authorization` header, falling back to client IP. This allows rate limiting individual API consumers even when they share an IP (e.g., behind a load balancer).

> **Trustworthy principal identification:** The `X-Principal` header is client-supplied and can be spoofed. For production deployments, enable OAuth 2.1 so the principal is derived from a validated JWT `sub` claim:
>
> ```toml
> [rate_limit]
> per_principal_rps = 50
> per_principal_burst = 10
> ```
>
> ```bash
> sentinel-http-proxy \
>   --upstream http://localhost:8000/mcp \
>   --config policy.toml \
>   --oauth-issuer https://auth.example.com \
>   --oauth-audience mcp-server
> ```
>
> With OAuth enabled, the Bearer token is validated and its subject is used for rate limiting instead of the untrusted `X-Principal` header.

### Injection Scanning

Configure how the injection scanner handles detected prompt injection patterns:

```toml
[injection]
enabled = true
block_on_injection = false   # true = block response, false = log only (default)
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
```

When `block_on_injection` is `true`, responses matching injection patterns are replaced with a JSON-RPC error (`-32005`) instead of being forwarded. When `false` (default), matches are logged but the response passes through.

### DLP Response Scanning

Sentinel scans tool **responses** for leaked secrets using 7 built-in patterns:

| Pattern | Example Match |
|---------|--------------|
| AWS Access Key | `AKIA...` (20-char uppercase) |
| AWS Secret Key | 40-char base64 after known key names |
| GitHub Token | `ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_` prefixes |
| Generic API Key | `sk-`, `api_key`, `token` followed by 20+ chars |
| Private Key Header | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| Slack Token | `xoxb-`, `xoxp-`, `xoxs-` prefixes |
| JWT | `eyJ...` base64-encoded JSON header with payload |

DLP scanning is enabled by default in both the HTTP proxy and stdio proxy. Detected secrets are logged as warnings. To block responses containing secrets, enable blocking mode in the injection config (`block_on_injection = true`). Both JSON responses and SSE event streams are scanned.

### Audit Configuration

Control how aggressively the audit logger redacts sensitive data:

```toml
[audit]
redaction_level = "KeysAndPatterns"  # Off | KeysOnly | KeysAndPatterns
```

| Level | Behavior |
|-------|----------|
| `Off` | No redaction -- raw values logged as-is |
| `KeysOnly` | Redacts sensitive keys (passwords, tokens) and known value prefixes |
| `KeysAndPatterns` | Redacts keys, prefixes, and PII-like patterns (default) |

Custom PII patterns can be added for domain-specific redaction:

```toml
[[audit.custom_pii_patterns]]
name = "credit_card"
pattern = "\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}"
```

### Supply Chain Verification

Verify SHA-256 hashes of MCP server binaries before spawning them:

```toml
[supply_chain]
enabled = true

[supply_chain.allowed_servers]
"/usr/local/bin/my-mcp" = "sha256hexdigest..."
```

When enabled, any binary not in the allowlist or with a hash mismatch is rejected.

## Deployment Modes

### HTTP API Server

The primary mode. Runs a standalone HTTP server that agents call to evaluate tool calls.

```bash
SENTINEL_API_KEY=your-secret sentinel serve \
  --config policy.toml \
  --port 8080 \
  --bind 127.0.0.1
```

### MCP Stdio Proxy

Wraps a local MCP server process. Intercepts JSON-RPC messages over stdin/stdout.

```bash
sentinel-proxy --config policy.toml -- /path/to/mcp-server --arg1 --arg2
```

Features:
- Intercepts `tools/call` and `resources/read` requests
- Blocks `sampling/createMessage` requests (exfiltration vector)
- Scans responses for prompt injection patterns (log-only or blocking mode)
- Detects tool annotation and inputSchema rug-pull attacks
- Persists flagged tools across restarts (JSONL)
- Detects child process crashes and flushes pending requests with errors
- Configurable request timeout (`--timeout 30`)

### Streamable HTTP Reverse Proxy

Sits between clients and a remote MCP server over HTTP. Supports SSE streaming and session management per the MCP Streamable HTTP transport spec.

```bash
SENTINEL_API_KEY=your-secret sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001
```

Session timeout options: `--session-timeout` controls inactivity timeout (seconds since last request), while `--session-max-lifetime` sets an absolute cap regardless of activity. Both can be used together.

Features:
- MCP Streamable HTTP transport (2025-06-18) with protocol version negotiation
- Session management with server-generated IDs, inactivity timeout, and absolute session lifetime
- CSRF protection via Origin header validation
- SSE streaming passthrough for long-running operations
- `?trace=true` query parameter for evaluation trace output
- Tool annotation and schema tracking with rug-pull detection
- OAuth 2.1 token validation with JWKS support
- Response body size limits to prevent upstream DoS
- DLP scanning of responses and SSE streams for leaked secrets

#### OAuth 2.1

```bash
sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --oauth-issuer https://auth.example.com \
  --oauth-audience mcp-server \
  --oauth-scopes mcp:read,mcp:write \
  --oauth-expected-resource https://mcp.example.com
```

Supports RS256, ES256, and EdDSA algorithms. Algorithm confusion attacks are prevented by restricting to asymmetric algorithms only. The `--oauth-expected-resource` flag enables RFC 8707 resource indicator validation, which prevents token replay attacks by verifying that the JWT's `aud` or resource claim matches the expected MCP server URL.

## HTTP API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Health check |
| `GET` | `/api/metrics` | No | Server metrics (evaluations, allow/deny counts, uptime) |
| `POST` | `/api/evaluate` | Yes | Evaluate a tool call against loaded policies |
| `GET` | `/api/policies` | Yes | List all loaded policies |
| `POST` | `/api/policies` | Yes | Add a new policy at runtime |
| `DELETE` | `/api/policies/:id` | Yes | Remove a policy by ID |
| `POST` | `/api/policies/reload` | Yes | Reload policies from config file |
| `GET` | `/api/audit/entries` | Yes | List audit log entries |
| `GET` | `/api/audit/report` | Yes | Audit summary report |
| `GET` | `/api/audit/verify` | Yes | Verify hash chain integrity |
| `GET` | `/api/audit/checkpoints` | Yes | List signed checkpoints |
| `GET` | `/api/audit/checkpoints/verify` | Yes | Verify checkpoint signatures |
| `POST` | `/api/audit/checkpoint` | Yes | Create a signed checkpoint |
| `GET` | `/api/approvals/pending` | Yes | List pending approvals |
| `GET` | `/api/approvals/:id` | Yes | Get approval details |
| `POST` | `/api/approvals/:id/approve` | Yes | Approve a pending request |
| `POST` | `/api/approvals/:id/deny` | Yes | Deny a pending request |

All endpoints except `/health` and `/api/metrics` require a `Bearer` token matching `SENTINEL_API_KEY`. Use `--allow-anonymous` to disable authentication for development.

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

- **JSONL format** -- one JSON entry per line, streamable and easy to ingest
- **SHA-256 hash chain** -- each entry includes the hash of the previous entry; any tampering breaks the chain
- **Rotation chain continuity** -- when logs rotate, a rotation manifest links files together with tail hashes; `verify_across_rotations()` detects missing or tampered rotated files
- **Ed25519 signed checkpoints** -- periodic cryptographic snapshots of chain state for independent verification; checkpoint files are written with `sync_data()` and restrictive permissions (0o600 on Unix)
- **Sensitive value redaction** -- API keys, tokens, passwords, and secrets are automatically redacted before logging
- **Duplicate entry detection** -- detects replayed or duplicated audit entries
- **Approval audit trail** -- approve/deny decisions are logged with resolver identity, original tool, and approval ID

### Verification

```bash
# Via CLI (offline verification)
sentinel verify --audit audit.log

# Via API (live verification)
curl http://localhost:8080/api/audit/verify | jq .
# -> {"valid": true, "entries_checked": 142, "first_broken_at": null}

# Verify checkpoint signatures
curl http://localhost:8080/api/audit/checkpoints/verify | jq .
```

Exit codes for `sentinel verify`: 0 = valid, 1 = chain/checkpoint failure, 2 = duplicate entry IDs detected.

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
| `SENTINEL_API_KEY` | *(required)* | Bearer token for all authenticated endpoints. Use `--allow-anonymous` to opt out. |
| `SENTINEL_SIGNING_KEY` | *(auto-generated)* | Hex-encoded 32-byte Ed25519 seed for audit checkpoints |
| `SENTINEL_CHECKPOINT_INTERVAL` | `300` | Seconds between automatic audit checkpoints (0 to disable) |
| `SENTINEL_TRUSTED_PROXIES` | *(none)* | Comma-separated trusted proxy IPs for X-Forwarded-For handling |
| `SENTINEL_RATE_EVALUATE` | *(disabled)* | Requests/sec limit for the evaluate endpoint |
| `SENTINEL_RATE_EVALUATE_BURST` | *(disabled)* | Burst allowance above evaluate rate |
| `SENTINEL_RATE_ADMIN` | *(disabled)* | Requests/sec limit for admin (mutation) endpoints |
| `SENTINEL_RATE_ADMIN_BURST` | *(disabled)* | Burst allowance above admin rate |
| `SENTINEL_RATE_READONLY` | *(disabled)* | Requests/sec limit for read-only endpoints |
| `SENTINEL_RATE_READONLY_BURST` | *(disabled)* | Burst allowance above readonly rate |
| `SENTINEL_RATE_PER_IP` | *(disabled)* | Requests/sec limit per unique client IP |
| `SENTINEL_RATE_PER_IP_BURST` | *(disabled)* | Burst allowance per IP |
| `SENTINEL_RATE_PER_IP_MAX_CAPACITY` | `100000` | Maximum unique IPs tracked simultaneously |
| `SENTINEL_RATE_PER_PRINCIPAL` | *(disabled)* | Requests/sec limit per principal (X-Principal header, Bearer token, or IP) |
| `SENTINEL_RATE_PER_PRINCIPAL_BURST` | *(disabled)* | Burst allowance per principal |
| `SENTINEL_CORS_ORIGINS` | *(localhost)* | Comma-separated allowed CORS origins (`*` for any) |
| `SENTINEL_LOG_MAX_SIZE` | `104857600` | Max audit log size in bytes before rotation (0 to disable) |
| `SENTINEL_NO_CANONICALIZE` | `false` | Set to `true` to disable JSON-RPC re-serialization before forwarding (not recommended) |
| `RUST_LOG` | `info` | Log level filter (`tracing` / `env_logger` syntax) |

Environment variables **override** values set in the config file. See below for config-file based rate limiting.

## Security Properties

| Property | Implementation |
|----------|---------------|
| **Fail-closed** | Empty policy set, missing parameters, and evaluation errors all produce `Deny` |
| **Input validation** | Action tool/function names validated (no empty strings, null bytes, max 256 chars); domain patterns validated per RFC 1035 at policy compile time |
| **ReDoS protection** | Legacy regex path rejects patterns with nested quantifiers (`(a+)+`) and overlength (>1024 chars) |
| **Path normalization** | Resolves `..`, `.`, percent-encoding (multi-layer), null bytes; prevents traversal |
| **Domain normalization** | Handles trailing dots, case folding, `@` in authority, scheme/port stripping; labels validated 1-63 chars, alphanumeric + hyphen |
| **Injection detection** | Aho-Corasick multi-pattern matching with Unicode evasion resistance (NFKC normalization, zero-width/bidi/tag character stripping); configurable blocking mode |
| **Rug-pull detection** | Alerts when MCP servers change tool annotations, inputSchema hashes, remove tools, or add new tools; flagged tools persist across restarts |
| **Child crash detection** | Detects MCP child process termination; flushes pending requests with JSON-RPC error (-32003) and audit logs the event |
| **Sampling interception** | Blocks `sampling/createMessage` (known exfiltration vector in MCP) |
| **CSRF protection** | Origin header validation on POST/DELETE endpoints; configurable allowlist or same-origin enforcement |
| **Security headers** | X-Content-Type-Options, X-Frame-Options, CSP, Cache-Control, X-Permitted-Cross-Domain-Policies on all responses; HSTS on HTTPS |
| **Constant-time auth** | API key comparison uses `subtle::ConstantTimeEq` to prevent timing attacks |
| **Tamper-evident audit** | SHA-256 hash chain with Ed25519 signed checkpoints; rotation manifest links rotated files with tail hashes; checkpoint files synced and permission-restricted (0o600) |
| **Approval hardening** | Deduplication prevents duplicate pending approvals via SHA-256 keyed index; approve/deny decisions linked to audit trail with resolver identity |
| **Sensitive redaction** | Configurable three-level redaction (Off/KeysOnly/KeysAndPatterns); 15 key patterns and 10 value prefixes redacted before audit logging |
| **Response body limits** | Configurable response size limits prevent upstream DoS via unbounded streams |
| **OAuth 2.1** | JWT validation with JWKS, algorithm confusion prevention (asymmetric-only), scope enforcement |
| **Rate limiting** | Per-IP, per-principal (X-Principal / Bearer / IP fallback), and per-endpoint rate limiting with burst support, trusted proxy handling, and capacity bounds |
| **Session management** | Inactivity timeout and absolute session lifetime; configurable max concurrent sessions with eviction |
| **Approval capacity limits** | Pending approval store has a configurable max capacity (default 10,000) to prevent memory exhaustion; write-lock acquired before persistence to prevent visibility gaps |
| **Supply chain verification** | Optional SHA-256 hash verification of MCP server binaries before spawn |
| **CI security scanning** | `cargo audit` for dependency vulnerabilities; `unwrap()` hygiene check in library code |

### Known Limitations

- **Injection detection is a pre-filter, not a security boundary.** Pattern-based injection detection catches known attack signatures but can be evaded by motivated attackers using encoding, typoglycemia, semantic synonyms, or novel phrasing. Even in blocking mode (`block_on_injection = true`), it is one layer in a defense-in-depth strategy.

- **No DNS rebinding protection.** Domain rules match DNS name patterns but do not pin resolved IP addresses. An upstream server's DNS record could change between policy evaluation and the proxied network connection.

- **TOCTOU mitigated by default.** Both proxies re-serialize parsed JSON before forwarding, ensuring the upstream server sees exactly what was evaluated. The HTTP proxy can opt out via `--no-canonicalize`; in that mode, duplicate keys are still rejected but other parse ambiguities (key ordering, Unicode escapes) could differ between evaluation and upstream interpretation.

- **Path normalization decode limit.** `normalize_path()` iteratively decodes percent-encoding up to 20 layers (configurable via `PolicyEngine::set_max_path_decode_iterations`), then fails-closed to `"/"` and emits a warning. Paths exceeding the limit will match root rather than their intended target. This is intentional to prevent CPU exhaustion from adversarial inputs.

- **DLP scanning is single-pass per encoding layer.** DLP detects secrets in raw, base64-decoded, and percent-decoded forms, but does not handle split secrets across multiple fields or multi-step encoding chains (e.g., base64-of-URL-encoded). Treat DLP as a best-effort safety net, not a guarantee.

- **Checkpoint trust anchor.** Checkpoint signatures use self-embedded Ed25519 public keys by default (TOFU model). For stronger guarantees, pin a trusted verifying key via the `SENTINEL_TRUSTED_KEY` environment variable.

- **Per-principal rate limiting relies on client-supplied headers.** When using `X-Principal` for rate limit keying, clients can choose their own identity. Enable OAuth 2.1 to derive principal identity from validated JWTs instead (see [Rate Limiting](#rate-limiting)).

- **Stdio proxy always re-serializes JSON.** The stdio proxy canonicalizes every message via `serde_json`. Upstream servers that depend on exact byte-for-byte forwarding (preserving key order or whitespace) are not supported in stdio mode.

- **No TLS termination.** Sentinel does not terminate TLS. Use a reverse proxy (nginx, Caddy) in front of Sentinel for HTTPS.

- **No clustering / HA.** Single-process deployment only. Session state and audit logs are local to the process.

## Architecture

```
sentinel-types             Core types: Action, Policy, Verdict, EvaluationTrace
       |
  +----+----+
  |         |
sentinel-  sentinel-       Config parser (TOML/JSON) and built-in presets
config     canonical
  |
sentinel-engine            Policy evaluation with pre-compiled patterns
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
- **Pre-compiled patterns** -- all glob, regex, and domain patterns compiled at policy load time; the evaluation hot path has zero mutex acquisitions and zero regex compilation
- **Tool-indexed evaluation** -- policies indexed by tool name at load time for O(matching) instead of O(all policies)
- **Zero `unwrap()` in library code** -- all error paths return typed errors; panics are reserved for tests only

### Performance

All patterns are pre-compiled at load time using:
- **Aho-Corasick automaton** for multi-pattern injection scanning (15 patterns in a single pass)
- **Compiled glob matchers** and **compiled regex** for constraint evaluation
- **Cow-based path/domain normalization** to avoid allocations when no transformation is needed
- **Pre-computed verdict reason strings** to eliminate `format!()` on the hot path
- **ASCII fast-path** for Unicode sanitization (skips NFKC for >95% of responses)

Benchmark results (criterion, single-threaded):
- Single policy evaluation: **7-31 ns**
- 100 policies: **~1.2 us**
- 1,000 policies: **~12 us**

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
sentinel verify --audit audit.log [--list-rotated]

# Stdio MCP proxy
sentinel-proxy --config policy.toml [--strict] [--timeout 30] [--trace] \
  -- ./mcp-server --arg1

# HTTP reverse proxy
sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  [--listen 127.0.0.1:3001] \
  [--session-timeout 1800] \
  [--session-max-lifetime 86400] \
  [--max-sessions 1000] \
  [--audit-log audit.log] \
  [--strict] \
  [--allow-anonymous] \
  [--canonicalize]
```

The `--canonicalize` flag re-serializes parsed JSON-RPC messages before forwarding them upstream, closing TOCTOU gaps from duplicate keys or non-standard formatting in the original request bytes.

## Development

```bash
# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets

# Format
cargo fmt --check

# Security audit (checks dependencies for known vulnerabilities)
cargo install cargo-audit && cargo audit

# Build release (thin LTO, single codegen unit)
cargo build --release

# Run criterion benchmarks
cargo bench -p sentinel-engine
```

CI runs all of the above plus a library code hygiene check for `unwrap()` calls on every push and pull request.

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

This project is licensed under the [MIT License](LICENSE-MIT).
