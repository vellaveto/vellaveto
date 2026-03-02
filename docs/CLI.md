# CLI Reference

## vellaveto (HTTP API Server)

```bash
# Start the HTTP policy server
vellaveto serve --config policy.toml [--port 3000] [--bind 127.0.0.1] [--allow-anonymous] [--open]

# One-shot evaluation (no server needed)
vellaveto evaluate --tool file --function read \
  --params '{"path":"/tmp/x"}' --config policy.toml

# Validate a config file
vellaveto check --config policy.toml

# Output canonical presets as TOML
vellaveto policies --preset dangerous

# Verify audit log integrity
vellaveto verify --audit audit.log [--list-rotated]
```

## vellaveto-proxy (Stdio MCP Proxy)

Wraps a local MCP server process. Intercepts JSON-RPC messages over stdin/stdout.

### Protection Levels (easiest way to get started)

```bash
# Pick a level — no config file needed:
vellaveto-proxy --protect shield   -- ./mcp-server    # 8 policies: credentials, SANDWORM, exfil, system files
vellaveto-proxy --protect fortress -- ./mcp-server    # 11 policies: shield + package configs, sudo, memory tracking
vellaveto-proxy --protect vault    -- ./mcp-server    # 11 policies: deny-by-default, reads allowed, writes need approval
```

| Level | Default | What it defends against |
|-------|---------|------------------------|
| `shield` | Allow | Credential theft, SANDWORM (AI config injection), exfil domains, git hooks, system files, dangerous commands, injection, DLP; approval for destructive git ops |
| `fortress` | Allow | Everything in Shield + package config tampering, privilege escalation approval, memory poisoning detection, shadow agent detection |
| `vault` | **Deny** | Everything — nothing runs without permission. Source reads + safe git commands allowed; file writes require approval |

### Named Presets

```bash
vellaveto-proxy --preset dev-laptop -- ./mcp-server
vellaveto-proxy --list-presets                          # Show all available presets
```

### Custom Config

```bash
vellaveto-proxy --config policy.toml -- ./mcp-server
vellaveto-proxy init --preset fortress -o vellaveto.toml  # Generate a starter config
```

### All Options

```bash
vellaveto-proxy \
  [--protect shield|fortress|vault] \
  [--preset <NAME>] \
  [--config policy.toml] \
  [--strict] \
  [--timeout 30] \
  [--trace] \
  [--list-presets] \
  -- ./mcp-server --arg1
```

`--config`, `--preset`, and `--protect` are mutually exclusive — use one only.

## vellaveto-http-proxy (HTTP/WebSocket/gRPC Reverse Proxy)

```bash
vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  [--listen 127.0.0.1:3001] \
  [--session-timeout 1800] \
  [--session-max-lifetime 86400] \
  [--max-sessions 1000] \
  [--audit-log audit.log] \
  [--strict] \
  [--allow-anonymous] \
  [--canonicalize] \
  [--ws-max-message-size 1048576] \
  [--ws-idle-timeout 300] \
  [--ws-message-rate-limit 100] \
  [--grpc] \
  [--grpc-port 50051] \
  [--grpc-max-message-size 4194304] \
  [--upstream-grpc-url <url>]
```

## vellaveto-shield (Consumer Shield)

```bash
vellaveto-shield --config policy.toml --passphrase "your-secret" -- /path/to/mcp-server
```

PII-sanitizing MCP proxy for consumer AI interactions.

## ETDI Tool Signing

```bash
# Generate Ed25519 keypair
vellaveto generate-key --private-key key.priv --public-key key.pub

# Sign a tool definition
vellaveto sign-tool --tool read_file --definition schema.json \
  --key key.priv --output signature.json [--expires-in-days 365]

# Verify a tool signature
vellaveto verify-signature --tool read_file --definition schema.json \
  --signature signature.json
```

## OAuth 2.1

```bash
vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --oauth-issuer https://auth.example.com \
  --oauth-audience mcp-server \
  --oauth-scopes mcp:read,mcp:write \
  --oauth-security-profile hardened \
  --oauth-expected-resource https://mcp.example.com
```

Supports RS256, ES256, and EdDSA algorithms. The `--oauth-security-profile hardened` flag enforces sender-constrained posture with RFC 8707 resource binding and DPoP.

## Batch Evaluation

```bash
# Simulate a batch of tool calls from a file
vellaveto simulate --config policy.toml --input batch.json --output results.json
```

## Policy Reload

```bash
# Hot-reload policies without restart
kill -HUP $(pidof vellaveto-server)
```
