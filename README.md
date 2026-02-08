<p align="center">
  <h1 align="center">🛡️ Sentinel</h1>
  <p align="center">
    <strong>Runtime security engine for AI agent tool calls</strong>
  </p>
  <p align="center">
    🔍 Intercept &middot; ⚖️ Evaluate &middot; 🚫 Enforce &middot; 📋 Audit
  </p>
  <p align="center">
    <a href="https://github.com/paolovella/sentinel/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version 1.0.0"></a>
    <a href="https://github.com/paolovella/sentinel/actions/workflows/ci.yml"><img src="https://github.com/paolovella/sentinel/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
    <a href="https://github.com/paolovella/sentinel/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-2021_edition-orange.svg" alt="Rust 2021"></a>
    <img src="https://img.shields.io/badge/tests-3%2C425_passing-brightgreen.svg" alt="Tests: 3,425 passing">
    <img src="https://img.shields.io/badge/clippy-zero_warnings-brightgreen.svg" alt="Clippy: zero warnings">
    <img src="https://img.shields.io/badge/security_audit-33_rounds%2C_380%2B_findings-informational.svg" alt="Security Audit: 33 rounds, 380+ findings">
    <a href="https://modelcontextprotocol.io/specification/2025-06-18"><img src="https://img.shields.io/badge/MCP-2025--06--18-blueviolet.svg" alt="MCP 2025-06-18"></a>
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

Sentinel is a lightweight, high-performance firewall that sits between AI agents and their tools. It intercepts [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) and function-calling requests, enforces security policies on paths, domains, and actions, and maintains a tamper-evident audit trail with cryptographic guarantees.

<table>
<tr><td>🏷️ <strong>Version</strong></td><td>1.0.0</td></tr>
<tr><td>🦀 <strong>Language</strong></td><td>Rust</td></tr>
<tr><td>✅ <strong>Test suite</strong></td><td>3,425 tests, 0 failures, 0 warnings</td></tr>
<tr><td>⚡ <strong>Evaluation latency</strong></td><td>&lt;5ms P99</td></tr>
<tr><td>💾 <strong>Memory baseline</strong></td><td>&lt;50MB</td></tr>
<tr><td>🔌 <strong>MCP version</strong></td><td>2025-06-18 (Streamable HTTP)</td></tr>
<tr><td>📄 <strong>License</strong></td><td>Apache 2.0</td></tr>
</table>

## ❓ Why Sentinel?

AI agents with tool access can read files, make HTTP requests, execute commands, and modify data. Without guardrails, a prompt injection or misbehaving agent can:

- 🔑 **Exfiltrate credentials** (`~/.aws/credentials`, `~/.ssh/id_rsa`)
- 🌐 **Call unauthorized APIs** (sending data to `*.ngrok.io` or `*.requestbin.com`)
- 💥 **Execute destructive commands** (`rm -rf /`)
- 🎭 **Bypass restrictions** via Unicode tricks, path traversal, or tool annotation changes
- 🧪 **Launder data** by planting instructions in tool responses for later execution
- 👥 **Impersonate tools** via name squatting with homoglyphs or typos

Sentinel enforces security policies on every tool call before it reaches the tool server, and logs every decision to a tamper-evident audit trail.

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
- **DLP response scanning** — Detects secrets (AWS keys, GitHub tokens, JWTs, private keys, Slack tokens) in tool responses through 5 decode layers
- **Elicitation interception** (MCP 2025-06-18) — Validates `elicitation/create` requests, blocks sensitive field types, enforces per-session rate limits
- **Sampling policy enforcement** — Configurable policies for `sampling/createMessage` with content inspection and model filtering
- **Sampling attack detection** — Rate limiting, prompt length validation, and sensitive content detection for sampling requests
- **Cross-agent security** — Agent trust graph with privilege levels, Ed25519 signed inter-agent messages, and second-order prompt injection detection for multi-agent systems
- **Goal state tracking** (ASI01) — Detects objective drift mid-session with similarity-based alignment and manipulation keyword detection
- **Workflow intent tracking** — Long-horizon attack detection with step budgets, cumulative effect analysis, and suspicious pattern detection
- **Tool namespace security** (ASI03) — Prevents shadowing via Levenshtein typosquatting detection, protected name patterns, and collision detection
- **Output security analysis** (ASI07) — Covert channel detection including steganography, entropy analysis, and output normalization
- **Token security analysis** — Special token injection, context flooding, glitch token patterns, and Unicode normalization attack detection

### 🚀 Deployment & Operations
- **Three deployment modes**: HTTP API server, MCP stdio proxy, HTTP reverse proxy
- **Prometheus metrics** at `/metrics` with evaluation latency histograms, verdict counters, and DLP finding counts
- **Hot policy reload** via SIGHUP signal or filesystem watching with atomic swap and audit trail
- **SIEM export** in CEF (Common Event Format) and JSON Lines for integration with Splunk, ArcSight, Elasticsearch, and Datadog
- **Tamper-evident audit logging** with SHA-256 hash chains, Ed25519 signed checkpoints, and rotation chain continuity
- **Structured output validation** via OutputSchemaRegistry against declared `outputSchema`

### 🔐 Authentication & Access Control
- **OAuth 2.1 / JWT** validation with JWKS and scope enforcement (RS256, ES256, EdDSA)
- **CSRF protection** via Origin header validation on mutating endpoints
- **Rate limiting** per-IP, per-principal, and per-endpoint with configurable burst
- **Security headers** including HSTS, CSP, X-Frame-Options, and X-Permitted-Cross-Domain-Policies
- **Constant-time auth** comparison to prevent timing attacks

### 🌐 Network & Path Security
- **Path normalization** with multi-layer percent-decode, `..` resolution, and null byte stripping
- **Domain normalization** with trailing dot, case folding, scheme/port stripping, and RFC 1035 validation
- **DNS rebinding protection** with IP-level access control (block private IPs, CIDR allow/blocklists)
- **Supply chain verification** with SHA-256 hash checking of MCP server binaries
- **MCP 2025-06-18 compliance** with protocol version header, RFC 8707 resource indicators, and `_meta` preservation

### 🏢 Enterprise Features
- **mTLS / SPIFFE-SPIRE** — Mutual TLS with client certificate verification, SPIFFE identity extraction from X.509 SAN URIs, trust domains, workload identity, and ID-to-role mapping
- **OPA Integration** — External policy evaluation via Open Policy Agent with async HTTP client, LRU decision caching (configurable TTL), fail-open/closed modes, and structured decision parsing
- **Threat Intelligence** — TAXII 2.1 (STIX), MISP, and custom REST threat feed integration with IOC matching, confidence filtering, and configurable actions (deny/alert/require_approval)
- **Just-In-Time Access** — Session-based temporary elevated permissions with approval workflows, per-principal session limits, auto-revocation on security alerts, and permission/tool access checking

## 📦 Installation

### Docker (Recommended)

```bash
# Pull the latest release
docker pull ghcr.io/paolovella/sentinel:1.0.0

# Run with a policy config
docker run -p 3000:3000 \
  -v /path/to/config.toml:/etc/sentinel/config.toml:ro \
  ghcr.io/paolovella/sentinel:1.0.0
```

### Kubernetes (Helm)

```bash
# Install with Helm
helm install sentinel ./helm/sentinel \
  --namespace sentinel \
  --create-namespace \
  -f values-production.yaml
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for complete deployment instructions.

### Build from Source

```bash
# Clone and build
git clone https://github.com/paolovella/sentinel.git
cd sentinel
cargo build --release

# Binaries in target/release/
ls target/release/sentinel target/release/sentinel-http-proxy
```

## 🚀 Quick Start

```bash
# Build (if not using Docker)
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
SENTINEL_API_KEY=your-secret sentinel serve --config policy.toml --port 8080

# Evaluate a tool call (another terminal)
curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
# -> {"verdict":"Allow", ...}  (allowed by "Allow file reads in /tmp")

curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/etc/passwd"}}' | jq .
# -> {"verdict":{"Deny":{"reason":"..."}}, ...}  (denied — path not in /tmp)

curl -s http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret" \
  -d '{"tool":"bash","function":"exec","parameters":{"cmd":"ls"}}' | jq .
# -> {"verdict":{"Deny":{"reason":"Denied by policy 'Block dangerous tools'"}}, ...}
```

## ⚙️ How It Works

```
                    +------------------+
  AI Agent -------->|   🛡️ Sentinel   |--------> Tool Server
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
| 🖥️ **HTTP API** | `sentinel serve` | Standalone policy server; agents call `/api/evaluate` |
| 📡 **Stdio Proxy** | `sentinel-proxy` | Wraps a local MCP server; intercepts stdin/stdout |
| 🔄 **HTTP Proxy** | `sentinel-http-proxy` | Reverse proxy for remote MCP servers (Streamable HTTP + SSE) |

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
curl -X POST http://localhost:8080/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $SENTINEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "alice@example.com"}'

# Deny
curl -X POST http://localhost:8080/api/approvals/$APPROVAL_ID/deny \
  -H "Authorization: Bearer $SENTINEL_API_KEY"
```

Pending approvals expire after 15 minutes by default.

### 📦 Canonical Presets

Built-in policy presets for common scenarios:

```bash
sentinel policies --preset dangerous   # Blocks bash, shell, exec tools
sentinel policies --preset network     # Domain allowlisting for HTTP
sentinel policies --preset development # Project-directory-scoped file access
sentinel policies --preset deny-all    # Deny everything by default
sentinel policies --preset allow-all   # Allow everything (testing only)
```

### 🗳️ Elicitation & Sampling Policies

Control how Sentinel handles MCP elicitation (server-initiated user prompts) and sampling (LLM re-invocation) requests:

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
block_on_injection = false   # true = block response, false = log only (default)
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
```

When `block_on_injection` is `true`, responses matching injection patterns are replaced with a JSON-RPC error (`-32005`) instead of being forwarded.

### 🔒 DLP Response Scanning

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
SENTINEL_API_KEY=your-secret sentinel serve \
  --config policy.toml \
  --port 8080 \
  --bind 127.0.0.1
```

### 📡 MCP Stdio Proxy

Wraps a local MCP server process. Intercepts JSON-RPC messages over stdin/stdout.

```bash
sentinel-proxy --config policy.toml -- /path/to/mcp-server --arg1 --arg2
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
SENTINEL_API_KEY=your-secret sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001
```

Features:
- MCP Streamable HTTP transport (2025-06-18) with protocol version negotiation
- Session management with inactivity timeout and absolute session lifetime
- CSRF protection via Origin header validation
- SSE streaming passthrough for long-running operations
- Tool annotation and schema tracking with rug-pull detection
- OAuth 2.1 token validation with JWKS support
- Response body size limits to prevent upstream DoS
- DLP scanning of responses and SSE streams
- DNS rebinding protection with IP-level access control

#### 🔑 OAuth 2.1

```bash
sentinel-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --oauth-issuer https://auth.example.com \
  --oauth-audience mcp-server \
  --oauth-scopes mcp:read,mcp:write \
  --oauth-expected-resource https://mcp.example.com
```

Supports RS256, ES256, and EdDSA algorithms. Algorithm confusion attacks are prevented by restricting to asymmetric algorithms only. The `--oauth-expected-resource` flag enables RFC 8707 resource indicator validation, preventing token replay attacks.

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

All endpoints except `/health`, `/metrics`, and `/api/metrics` require a `Bearer` token matching `SENTINEL_API_KEY`. Use `--allow-anonymous` to disable authentication for development.

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

### Example: Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

```
# HELP sentinel_evaluations_total Total policy evaluations
# TYPE sentinel_evaluations_total counter
sentinel_evaluations_total{verdict="allow"} 1042
sentinel_evaluations_total{verdict="deny"} 87
sentinel_evaluations_total{verdict="require_approval"} 12
# HELP sentinel_evaluation_duration_seconds Policy evaluation latency
# TYPE sentinel_evaluation_duration_seconds histogram
sentinel_evaluation_duration_seconds_bucket{le="0.001"} 1129
...
```

### Example: SIEM Export

```bash
# Export in CEF format
curl "http://localhost:8080/api/audit/export?format=cef&limit=100" \
  -H "Authorization: Bearer $SENTINEL_API_KEY"

# Export in JSON Lines format
curl "http://localhost:8080/api/audit/export?format=jsonl&since=2026-02-04T00:00:00Z" \
  -H "Authorization: Bearer $SENTINEL_API_KEY"
```

## 📋 Audit System

Every policy decision is logged to a tamper-evident audit trail.

### Properties

- 📄 **JSONL format** — one JSON entry per line, streamable and easy to ingest
- 🔗 **SHA-256 hash chain** — each entry includes the hash of the previous entry; any tampering breaks the chain
- 🔄 **Rotation chain continuity** — when logs rotate, a rotation manifest links files together with tail hashes
- ✍️ **Ed25519 signed checkpoints** — periodic cryptographic snapshots of chain state for independent verification
- 🙈 **Sensitive value redaction** — API keys, tokens, passwords, and secrets are automatically redacted before logging
- 📊 **SIEM integration** — export entries in CEF or JSON Lines format via API or configurable webhook
- 🔁 **Duplicate entry detection** — detects replayed or duplicated audit entries
- ✅ **Approval audit trail** — approve/deny decisions are logged with resolver identity, original tool, and approval ID

### Verification

```bash
# Via CLI (offline verification)
sentinel verify --audit audit.log

# Via API (live verification)
curl http://localhost:8080/api/audit/verify \
  -H "Authorization: Bearer $SENTINEL_API_KEY" | jq .
# -> {"valid": true, "entries_checked": 142, "first_broken_at": null}

# Verify checkpoint signatures
curl http://localhost:8080/api/audit/checkpoints/verify \
  -H "Authorization: Bearer $SENTINEL_API_KEY" | jq .
```

### 🔑 Signing Key

```bash
# Use a persistent key (hex-encoded 32-byte Ed25519 seed)
export SENTINEL_SIGNING_KEY="a1b2c3d4..."

# Or let Sentinel auto-generate one (public key logged at startup)
```

Checkpoints are created every 300 seconds by default (configurable via `SENTINEL_CHECKPOINT_INTERVAL`).

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
| `SENTINEL_API_KEY` | *(required)* | Bearer token for all authenticated endpoints |
| `SENTINEL_SIGNING_KEY` | *(auto-generated)* | Hex-encoded 32-byte Ed25519 seed for audit checkpoints |
| `SENTINEL_CHECKPOINT_INTERVAL` | `300` | Seconds between automatic audit checkpoints (0 to disable) |
| `SENTINEL_TRUSTED_PROXIES` | *(none)* | Comma-separated trusted proxy IPs for X-Forwarded-For |
| `SENTINEL_CORS_ORIGINS` | *(localhost)* | Comma-separated allowed CORS origins (`*` for any) |
| `SENTINEL_LOG_MAX_SIZE` | `104857600` | Max audit log size in bytes before rotation (0 to disable) |
| `SENTINEL_NO_CANONICALIZE` | `false` | Disable JSON-RPC re-serialization before forwarding |
| `RUST_LOG` | `info` | Log level filter (`tracing` / `env_logger` syntax) |

Rate limiting environment variables: `SENTINEL_RATE_EVALUATE`, `SENTINEL_RATE_EVALUATE_BURST`, `SENTINEL_RATE_ADMIN`, `SENTINEL_RATE_ADMIN_BURST`, `SENTINEL_RATE_READONLY`, `SENTINEL_RATE_READONLY_BURST`, `SENTINEL_RATE_PER_IP`, `SENTINEL_RATE_PER_IP_BURST`, `SENTINEL_RATE_PER_IP_MAX_CAPACITY`, `SENTINEL_RATE_PER_PRINCIPAL`, `SENTINEL_RATE_PER_PRINCIPAL_BURST`.

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
| 📋 **Tamper-evident audit** | SHA-256 hash chain + Ed25519 checkpoints + rotation manifests |
| 🌍 **DNS rebinding** | IP-level access control blocks private/reserved IPs and custom CIDR ranges |
| 🔑 **OAuth 2.1** | JWT/JWKS validation, algorithm confusion prevention, scope enforcement |
| 🚦 **Rate limiting** | Per-IP, per-principal, per-endpoint with burst support and capacity bounds |
| 🔗 **Supply chain** | SHA-256 hash verification of MCP server binaries before spawn |

### 🔬 Security Audit

Sentinel has undergone 33 rounds of adversarial security audit covering 31+ attack classes mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

| Metric | Value |
|--------|-------|
| Audit rounds completed | 33 |
| Attack classes tested | 31+ |
| Total findings triaged | 380+ |
| Findings fixed | 300+ |
| Critical/HIGH findings fixed | 80+ |
| Test count post-audit | 3,167 |

Key areas covered: tool poisoning, prompt injection, path traversal, SSRF/domain bypass, session fixation, JSON parsing, memory poisoning, elicitation social engineering, audit log tampering, OAuth/JWT validation, SIEM export injection, rug-pull detection, tool squatting, DLP bypass, SSE transport parity, config reload races, Unicode case-folding, IPv6 transition mechanisms, CEF/SIEM injection, and webhook SSRF.

### 📋 Standards Compliance

Sentinel provides built-in compliance mapping and reporting for major AI security standards:

| Standard | Module | Coverage |
|----------|--------|----------|
| **MITRE ATLAS** | `sentinel-audit/src/atlas.rs` | 14 techniques (AML.T0051-T0065), 30+ detection mappings |
| **OWASP AIVSS** | `sentinel-audit/src/aivss.rs` | Full severity scoring with AI-specific multipliers |
| **NIST AI RMF** | `sentinel-audit/src/nist_rmf.rs` | All 4 functions (Govern, Map, Measure, Manage) |
| **ISO/IEC 27090** | `sentinel-audit/src/iso27090.rs` | 5 control domains, readiness assessment |

Generate compliance reports programmatically:
```rust
use sentinel_audit::{atlas::AtlasRegistry, nist_rmf::NistRmfRegistry, iso27090::Iso27090Registry};

// MITRE ATLAS coverage
let atlas = AtlasRegistry::new();
let coverage = atlas.generate_coverage_report();

// NIST AI RMF compliance
let rmf = NistRmfRegistry::new();
let report = rmf.generate_report();

// ISO 27090 readiness
let iso = Iso27090Registry::new();
let assessment = iso.generate_assessment();
```

### ⚠️ Known Limitations

- **Injection detection is a pre-filter, not a security boundary.** Pattern-based detection catches known signatures but can be evaded by encoding, typoglycemia, or paraphrasing. It is one layer in a defense-in-depth strategy.

- **DNS rebinding protection requires HTTP proxy mode.** The HTTP proxy resolves target domains and checks IPs against rules. Not available in stdio proxy mode since the client makes the connection.

- **DLP does not detect split secrets.** Secrets split across multiple JSON fields or fragmented within a field are not reassembled. Treat DLP as a best-effort safety net.

- **No TLS termination.** Use a reverse proxy (nginx, Caddy) in front of Sentinel for HTTPS.

- **Distributed clustering is opt-in.** The `sentinel-cluster` crate supports Redis-backed state sharing (approvals, rate limits) across instances, but audit logs remain local to each process. Enable with the `redis` feature flag.

- **Path normalization decode limit.** `normalize_path()` iteratively decodes up to 20 layers, then fails-closed to `"/"` to prevent CPU exhaustion.

- **Checkpoint trust anchor.** Checkpoint signatures use self-embedded Ed25519 keys (TOFU model). Pin a trusted key via `SENTINEL_TRUSTED_KEY` for stronger guarantees.

## 🏛️ Architecture

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
     sentinel-cluster          Distributed state sharing (local + Redis)
           |
  +--------+--------+
  |        |        |
sentinel-  sentinel- sentinel-
server     proxy     http-proxy   HTTP API, stdio proxy, HTTP reverse proxy
```

### Design Principles

- 🚪 **Fail-closed** — errors, missing policies, and missing parameters all result in denial
- ⚡ **Pre-compiled patterns** — all glob, regex, and domain patterns compiled at policy load time; the evaluation hot path has zero mutex acquisitions and zero regex compilation
- 🗂️ **Tool-indexed evaluation** — policies indexed by tool name at load time for O(matching) instead of O(all policies)
- 🚫 **Zero `unwrap()` in library code** — all error paths return typed errors; panics are reserved for tests only

### ⚡ Performance

All patterns are pre-compiled at load time using:
- **Aho-Corasick automaton** for multi-pattern injection scanning (15 patterns in a single pass)
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

## 💻 CLI Reference

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
kill -HUP $(pidof sentinel-server)
```

### 🔄 CI Pipeline

CI runs 6 parallel jobs on every push and pull request:

| Job | Description |
|-----|-------------|
| 🧹 **Check & Lint** | `cargo fmt`, `cargo check`, `cargo clippy`, `unwrap()` hygiene scan |
| 🧪 **Test Suite** | `cargo test --workspace`, doc build verification |
| 🔐 **Security Audit** | `cargo audit` via `rustsec/audit-check` for dependency CVEs |
| 🐛 **Fuzz Targets** | Compiles all 7 fuzz targets on nightly to catch build regressions |
| 📈 **Benchmarks** | Runs criterion benchmarks with cached baselines (main branch only) |
| 📦 **Release Build** | Full LTO release build with 50MB binary size guard |

## 📁 Project Structure

```
sentinel/
  sentinel-types/          Core shared types (Action, Policy, Verdict)
  sentinel-engine/         Policy evaluation engine with pre-compiled patterns
  sentinel-audit/          Tamper-evident audit logging + SIEM export
  sentinel-approval/       Human-in-the-loop approval store
  sentinel-config/         TOML/JSON config parser
  sentinel-canonical/      Built-in policy presets
  sentinel-mcp/            MCP protocol, injection/DLP scanning, rug-pull detection
  sentinel-cluster/        Distributed state sharing (local + Redis backends)
  sentinel-server/         HTTP API server + Prometheus metrics + admin dashboard
  sentinel-proxy/          Stdio MCP proxy binary
  sentinel-http-proxy/     Streamable HTTP reverse proxy binary
  sentinel-integration/    Integration and E2E tests (98 test files)
  fuzz/                    7 fuzz targets for parser boundary code
  examples/                Example configs and demo scripts
  scripts/                 Benchmark regression scripts
```

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, Kubernetes (Helm), and bare metal installation |
| [Operations Runbook](docs/OPERATIONS.md) | Monitoring, troubleshooting, and maintenance procedures |
| [Security Hardening](docs/SECURITY.md) | Security configuration best practices |
| [API Reference](docs/API.md) | Complete HTTP API documentation |
| [Changelog](CHANGELOG.md) | Version history and release notes |

## 📚 References

- [MCP Specification 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP](https://arxiv.org/pdf/2504.08623)

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
