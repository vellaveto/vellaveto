# Policy Configuration

Policies are defined in TOML (or JSON). Each policy matches tool calls by tool and function name, with optional parameter constraints. Policies are evaluated in priority order (highest first); the first match wins.

## Basic Policies

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

## Parameter Constraints

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

### Available Operators

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

## Wildcard Parameter Scanning

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

## Require Approval

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
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "alice@example.com"}'

# Deny
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/deny \
  -H "Authorization: Bearer $VELLAVETO_API_KEY"
```

Pending approvals expire after 15 minutes by default.

## Canonical Presets

Built-in policy presets for common scenarios:

```bash
vellaveto policies --preset dangerous   # Blocks bash, shell, exec tools
vellaveto policies --preset network     # Domain allowlisting for HTTP
vellaveto policies --preset development # Project-directory-scoped file access
vellaveto policies --preset deny-all    # Deny everything by default
vellaveto policies --preset allow-all   # Allow everything (testing only)
```

See [`examples/presets/`](../examples/presets/) for additional preset templates including consumer shield, MCP 2025-11-25, production, and SANDWORM hardening configurations.

## Elicitation & Sampling Policies

Control how Vellaveto handles MCP elicitation (server-initiated user prompts) and sampling (LLM re-invocation) requests:

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

## Injection Scanning

Configure how the injection scanner handles detected prompt injection patterns:

```toml
[injection]
enabled = true
block_on_injection = true    # true = block response (default), false = log only
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
```

When `block_on_injection` is `true`, responses matching injection patterns are replaced with a JSON-RPC error (`-32005`) instead of being forwarded.

## DLP Response Scanning

Vellaveto scans tool **responses** for leaked secrets using 7 built-in patterns:

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

## Rate Limiting

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

> **Note:** The `X-Principal` header is client-supplied and can be spoofed. For production deployments, enable OAuth 2.1 so the principal is derived from a validated JWT `sub` claim.

## Audit Configuration

```toml
[audit]
redaction_level = "KeysAndPatterns"  # Off | KeysOnly | KeysAndPatterns

# Custom PII patterns for domain-specific redaction
[[audit.custom_pii_patterns]]
name = "credit_card"
pattern = "\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}"
```

## Supply Chain Verification

```toml
[supply_chain]
enabled = true

[supply_chain.allowed_servers]
"/usr/local/bin/my-mcp" = "sha256hexdigest..."
```

## Policy Lifecycle Management

Vellaveto supports versioned policies with a Draft → Staging → Active → Archived lifecycle:

- **Multi-approver workflows** with self-approval prevention (NFKC + homoglyph normalization)
- **Staging shadow evaluation** — non-blocking verdict comparison before going live
- **Structural diffs** between versions
- **Rollback** — create a draft from any previous version

See the [API Reference](API.md) for the 9 lifecycle REST endpoints.

## Cedar Policy Compatibility

Import and export Cedar policy files for AWS AgentCore and CNCF Cedar interoperability:

```toml
[cedar]
enabled = true
policy_file = "policies/cedar/main.cedar"
```

## Wasm Policy Plugins

User-extensible policy evaluation via Wasmtime with WIT interface:

```toml
[wasm]
enabled = true
fuel_limit = 100000
memory_limit_bytes = 10485760

[[wasm.plugins]]
name = "custom-checker"
path = "plugins/custom-checker.wasm"
```

Plugins implement a WIT interface and are hot-reloadable. Fuel metering prevents runaway execution.
