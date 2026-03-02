# Policy Cookbook

Practical, copy-paste-ready policy recipes for common Vellaveto deployment scenarios. Each recipe is a self-contained TOML snippet you can drop into your configuration file. For full syntax reference, see [POLICY.md](POLICY.md).

Policies are evaluated in priority order (highest first); the first match wins. Use `on_no_match = "continue"` on conditional policies so they skip to the next policy when none of their constraints fire.

---

## Table of Contents

1. [Block Credential File Access](#1-block-credential-file-access)
2. [Allow Only Specific Domains](#2-allow-only-specific-domains)
3. [Rate Limit Tool Calls](#3-rate-limit-tool-calls)
4. [Require Approval for Destructive Operations](#4-require-approval-for-destructive-operations)
5. [Block Prompt Injection in Tool Descriptions](#5-block-prompt-injection-in-tool-descriptions)
6. [Time-Window Restrictions](#6-time-window-restrictions)
7. [Per-Agent Policies](#7-per-agent-policies)
8. [Deny-by-Default with Exceptions](#8-deny-by-default-with-exceptions)
9. [Tips](#tips)

---

## 1. Block Credential File Access

Deny any tool call whose parameters reference credential or secret files. Uses `param = "*"` to recursively scan all parameter values regardless of nesting depth.

```toml
[[policies]]
name = "Block credential file access"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "*:*:block-credentials"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.aws/**",         on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**",         on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env",                 on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env.*",               on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials.json",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets.yaml",         on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets.json",         on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/id_rsa",               on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/id_ed25519",           on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.kube/config",    on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.npmrc",          on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.netrc",          on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.config/gcloud/**", on_match = "deny", on_missing = "skip" },
]
```

**How it works:** The `param = "*"` wildcard recursively walks every string value in the tool call's parameters JSON. If any value matches a credential path glob, the call is denied. The `on_missing = "skip"` ensures tools that do not take path parameters are not blocked. The `on_no_match = "continue"` lets the request fall through to lower-priority policies when no credential path is found.

---

## 2. Allow Only Specific Domains

Restrict network-accessing tools to a whitelist of approved API domains. All other domains are implicitly blocked by the `allowed_domains` list.

```toml
# --- Domain allowlist for API tools ---
[[policies]]
name = "Allow only approved API domains"
tool_pattern = "*"
function_pattern = "*"
priority = 250
id = "*:*:domain-allowlist"
policy_type = "Allow"

[policies.network_rules]
allowed_domains = [
  "api.github.com",
  "api.openai.com",
  "registry.npmjs.org",
]
blocked_domains = []

[policies.network_rules.ip_rules]
block_private = true
```

**How it works:** When `allowed_domains` is populated, any tool call targeting a domain not in the list is denied. Setting `block_private = true` in `ip_rules` additionally prevents calls to RFC 1918 addresses (10.x, 172.16.x, 192.168.x) and link-local ranges, blocking SSRF attacks against internal services.

To also block known exfiltration domains regardless of the allowlist, add a higher-priority deny policy:

```toml
[[policies]]
name = "Block exfiltration domains"
tool_pattern = "*"
function_pattern = "*"
priority = 275
id = "*:*:block-exfil-domains"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "regex", pattern = "pastebin\\.com",   on_match = "deny", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "transfer\\.sh",    on_match = "deny", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "webhook\\.site",   on_match = "deny", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "file\\.io",        on_match = "deny", on_missing = "skip" },
]
```

---

## 3. Rate Limit Tool Calls

Limit how many times any single tool can be called per session, preventing runaway agents from making excessive requests.

```toml
[[policies]]
name = "Rate limit: max 10 calls per tool"
tool_pattern = "*"
function_pattern = "*"
priority = 150
id = "*:*:rate-limit-per-tool"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "max_calls", tool_pattern = "*", max = 10 },
]
```

**How it works:** The `max_calls` context condition tracks per-tool invocation counts across the session. Once any tool exceeds 10 calls, subsequent calls are denied. The `tool_pattern` inside the condition uses the same glob syntax as policy-level patterns -- set it to a specific tool name to limit only that tool.

For a sliding-window approach that counts calls within the last N actions (instead of the whole session), use `max_calls_in_window`:

```toml
[[policies]]
name = "Rate limit: max 10 calls per tool in last 60 actions"
tool_pattern = "*"
function_pattern = "*"
priority = 150
id = "*:*:rate-limit-sliding-window"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "max_calls_in_window", tool_pattern = "*", max = 10, window = 60 },
]
```

You can also set server-wide HTTP rate limits (independent of policy evaluation) for the API itself:

```toml
[rate_limit]
evaluate_rps = 1000
evaluate_burst = 50
per_principal_rps = 50
per_principal_burst = 10
```

---

## 4. Require Approval for Destructive Operations

Flag destructive commands for human-in-the-loop approval instead of silently allowing or denying them. The agent's call is paused until a human approves or denies it via the approval API.

```toml
[[policies]]
name = "Require approval for destructive operations"
tool_pattern = "*"
function_pattern = "*"
priority = 200
id = "*:*:destructive-approval"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "regex", pattern = "rm\\s+-rf\\s+/",                          on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "(?i)DROP\\s+(TABLE|DATABASE|INDEX|VIEW)",  on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "(?i)TRUNCATE\\s+",                        on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "git\\s+push\\s+--force",                  on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "git\\s+reset\\s+--hard",                  on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "git\\s+branch\\s+-D",                     on_match = "require_approval", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "chmod\\s+-R\\s+777",                      on_match = "require_approval", on_missing = "skip" },
]
```

**How it works:** When a parameter value matches one of the destructive patterns, Vellaveto returns a `RequireApproval` verdict with an `approval_id`. The calling system must then hit the approval endpoint to proceed:

```bash
# Approve a pending request
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/approve \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "alice@example.com"}'

# Deny a pending request
curl -X POST http://localhost:3000/api/approvals/$APPROVAL_ID/deny \
  -H "Authorization: Bearer $VELLAVETO_API_KEY"
```

Pending approvals expire after 15 minutes by default.

---

## 5. Block Prompt Injection in Tool Descriptions

Enable Vellaveto's built-in injection scanner to detect and block prompt injection attacks in tool descriptions, responses, and parameters.

```toml
# --- Injection scanning (blocking mode) ---
[injection]
enabled = true
block_on_injection = true
extra_patterns = ["transfer funds", "send bitcoin", "ignore previous"]
disabled_patterns = []

# --- DLP credential scanning (blocking mode) ---
[dlp]
enabled = true
block_on_finding = true

# --- Shadow agent detection ---
[shadow_agent]
enabled = true
```

**How it works:** The injection scanner uses Aho-Corasick multi-pattern matching with NFKC Unicode normalization to detect prompt injection attempts across all transports (HTTP, WebSocket, gRPC, stdio, SSE). When `block_on_injection = true`, matching responses are replaced with a JSON-RPC error (`-32005`) instead of being forwarded to the agent.

The `extra_patterns` list adds domain-specific patterns on top of the built-in set. The `disabled_patterns` list suppresses specific built-in patterns that produce false positives in your environment.

DLP scanning runs a 5-layer decode pipeline (raw, base64, percent-encoded, and combinations) against tool responses to catch leaked AWS keys, GitHub tokens, private keys, JWTs, and other secrets. Shadow agent detection flags attempts to spawn hidden sub-agents.

---

## 6. Time-Window Restrictions

Restrict production-facing tools to business hours only. Calls outside the allowed window are denied.

```toml
[[policies]]
name = "Production tools: business hours only"
tool_pattern = "production_*"
function_pattern = "*"
priority = 200
id = "production_*:*:business-hours"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "time_window", start_hour = 9, end_hour = 18, days = [1, 2, 3, 4, 5] },
]
```

**How it works:** The `time_window` context condition checks the current wall-clock hour (UTC) against the allowed range. Hours use 24-hour format (0-23). The `days` array uses ISO weekday numbers: 1 = Monday through 7 = Sunday. Omitting `days` allows all days. In this example, production tools are permitted Monday through Friday, 09:00-18:00 UTC only.

To allow different time windows for different environments:

```toml
# Allow staging tools 24/7
[[policies]]
name = "Staging tools: always allowed"
tool_pattern = "staging_*"
function_pattern = "*"
priority = 200
id = "staging_*:*:always-on"
policy_type = "Allow"

# Restrict production tools to business hours on weekdays
[[policies]]
name = "Production tools: business hours only"
tool_pattern = "production_*"
function_pattern = "*"
priority = 200
id = "production_*:*:business-hours"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "time_window", start_hour = 9, end_hour = 18, days = [1, 2, 3, 4, 5] },
]
```

---

## 7. Per-Agent Policies

Apply different security rules to different agents by matching on agent identity. This lets you give a code-writing agent broad file access while restricting a data-processing agent to read-only database queries.

```toml
# --- Code agent: allow file operations, block network exfil ---
[[policies]]
name = "Code agent: allow file ops"
tool_pattern = "file_*"
function_pattern = "*"
priority = 200
id = "file_*:*:code-agent-allow"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "agent_id", allowed = ["code-agent"] },
]

# --- Data agent: allow database reads only ---
[[policies]]
name = "Data agent: allow DB reads"
tool_pattern = "database_*"
function_pattern = "query"
priority = 200
id = "database_*:query:data-agent-allow"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "agent_id", allowed = ["data-agent"] },
]

# --- Data agent: block file access ---
[[policies]]
name = "Data agent: deny file access"
tool_pattern = "file_*"
function_pattern = "*"
priority = 250
id = "file_*:*:data-agent-deny"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "agent_id", allowed = ["data-agent"] },
]
parameter_constraints = [
  { param = "*", op = "glob", pattern = "**", on_match = "deny", on_missing = "skip" },
]

# --- Block unknown agents entirely ---
[[policies]]
name = "Block unrecognized agents"
tool_pattern = "*"
function_pattern = "*"
priority = 100
id = "*:*:block-unknown-agents"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
context_conditions = [
  { type = "agent_id", blocked = ["*"] },
]

# --- Default deny ---
[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
priority = 1
id = "*:*:default-deny"
policy_type = "Deny"
```

**How it works:** The `agent_id` context condition matches against the agent identity provided in the `EvaluationContext`. The `allowed` list specifies which agents can trigger the policy. The `blocked` list specifies which agents are denied. Agent IDs are normalized to lowercase with homoglyph detection at compile time to prevent bypass via Cyrillic or mixed-case variations.

The agent identity is set by the calling application -- in proxy mode, it comes from the authenticated session (JWT `sub` claim or `X-Agent-Id` header).

---

## 8. Deny-by-Default with Exceptions

Start from a fully locked-down posture (vault mode) and add specific Allow rules for exactly what your agents need. This is the most secure configuration pattern.

```toml
# =====================================================================
# DENY-BY-DEFAULT (Vault Mode) with Targeted Exceptions
# =====================================================================
# Priority ordering:
#   300 - Credential blocks (highest, never overridden)
#   250 - Dangerous command blocks
#   200 - Allow exceptions for specific operations
#   100 - Allow exceptions for specific tools
#     1 - Default deny (catches everything else)
# =====================================================================

# --- Block credentials (highest priority, never overridden) ---
[[policies]]
name = "Block credential files"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "*:*:vault-block-creds"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.aws/**",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env",             on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env.*",           on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets.*",        on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials*",     on_match = "deny", on_missing = "skip" },
]

# --- Block dangerous commands ---
[[policies]]
name = "Block dangerous commands"
tool_pattern = "*"
function_pattern = "*"
priority = 250
id = "*:*:vault-block-dangerous"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "regex", pattern = "rm\\s+-rf\\s+/",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "curl.*\\|.*sh",      on_match = "deny", on_missing = "skip" },
  { param = "*", op = "regex", pattern = "chmod\\s+-R\\s+777", on_match = "deny", on_missing = "skip" },
]

# --- EXCEPTION: Allow file reads within the project directory ---
[[policies]]
name = "Allow project file reads"
tool_pattern = "file_*"
function_pattern = "read*"
priority = 200
id = "file_*:read*:vault-allow-project-reads"
policy_type = "Allow"

[policies.path_rules]
allowed = ["/home/user/projects/myapp/**"]

# --- EXCEPTION: Allow specific API calls ---
[[policies]]
name = "Allow approved API calls"
tool_pattern = "http_*"
function_pattern = "*"
priority = 200
id = "http_*:*:vault-allow-apis"
policy_type = "Allow"

[policies.network_rules]
allowed_domains = ["api.github.com", "api.openai.com"]
blocked_domains = []

[policies.network_rules.ip_rules]
block_private = true

# --- EXCEPTION: Allow database reads ---
[[policies]]
name = "Allow database queries"
tool_pattern = "database_*"
function_pattern = "query"
priority = 200
id = "database_*:query:vault-allow-db-read"
policy_type = "Allow"

# --- DEFAULT DENY (lowest priority, catches everything) ---
[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
priority = 1
id = "*:*:vault-default-deny"
policy_type = "Deny"

# --- Enable all scanning ---
[injection]
enabled = true
block_on_injection = true

[dlp]
enabled = true
block_on_finding = true

[shadow_agent]
enabled = true

[audit]
redaction_level = "KeysAndPatterns"
```

**How it works:** The `Default deny` policy at priority 1 catches every tool call that was not explicitly allowed by a higher-priority policy. To grant access to a new tool or operation, add an Allow policy with a priority between 2 and 249. Credential blocks and dangerous command blocks sit at priorities 250-300, ensuring they cannot be overridden by any Allow exception.

This is the pattern used by the built-in `vault` protection level (`vellaveto-proxy --protect vault`).

---

## Tips

**Priority ordering matters.** Policies are evaluated highest-priority first, and the first match wins. A common layout:

| Priority Range | Purpose |
|----------------|---------|
| 300 | Hard blocks (credentials, AI config) |
| 250-280 | Dangerous command blocks |
| 200 | Approval gates and specific allow/deny rules |
| 100-150 | Context conditions (time, agent, rate limits) |
| 1 | Default policy (Allow or Deny) |

**Start with a preset.** Before writing custom policies, try the built-in protection levels:

```bash
vellaveto-proxy --protect shield   -- ./mcp-server    # 8 policies: credentials, SANDWORM, exfil, system files
vellaveto-proxy --protect fortress -- ./mcp-server    # 11 policies: shield + package configs, sudo, memory tracking
vellaveto-proxy --protect vault    -- ./mcp-server    # 11 policies: deny-by-default, reads allowed, writes need approval
```

**Use `on_no_match = "continue"` on conditional policies.** Without this, a conditional policy that matches no constraints returns Allow by default. With `"continue"`, it skips to the next policy, which is almost always what you want for deny-list style rules.

**Use `on_missing = "skip"` on parameter constraints.** This prevents tools that lack a particular parameter from being falsely denied. Only tools that actually have the matching parameter will be evaluated.

**Use `param = "*"` for deep scanning.** Rather than guessing which parameter name holds a file path or URL, the wildcard recursively checks every string value in the parameters JSON.

**Combine recipes.** These recipes are designed to be composed. You can include multiple conditional policies at different priorities, mixing credential blocks, domain restrictions, rate limits, and approval gates in one configuration file.

**Test before deploying.** Use `block_on_injection = false` (log-only mode) during initial rollout to observe what would be blocked without disrupting your agents. Flip to `true` once you have confidence in the policy set.

**See the presets for more examples.** The [`examples/presets/`](../examples/presets/) directory contains 17 complete, production-tested configurations for common deployment scenarios including database agents, CI/CD pipelines, financial services, healthcare, and SANDWORM-hardened setups.
