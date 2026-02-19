# Vellaveto

[![CI](https://github.com/paolovella/vellaveto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/paolovella/vellaveto/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

Vellaveto is a runtime security engine for AI agent tool calls.

It sits between agents and tools (MCP, function-calling, and proxy transports), evaluates every request against policy, enforces deny/approval decisions, and records a tamper-evident audit trail.

## What It Provides

- Inline policy enforcement before tool execution
- Fail-closed evaluation model (`no match`, `invalid input`, or `evaluation error` => deny)
- Request/response inspection hooks for security controls
- Tamper-evident audit logging with integrity verification flows
- Tool discovery search and model projector APIs for MCP tool usage
- Multiple runtime surfaces:
  - HTTP API server (`vellaveto-server`)
  - stdio MCP proxy (`vellaveto-proxy`)
  - Streamable HTTP MCP reverse proxy (`vellaveto-http-proxy`)

## Security Properties

Vellaveto publishes an explicit security contract and evidence set:

- Security guarantees: `docs/SECURITY_GUARANTEES.md`
- Assurance case: `docs/ASSURANCE_CASE.md`
- Threat model: `docs/THREAT_MODEL.md`
- Security model and TCB notes: `docs/SECURITY_MODEL.md`, `docs/TCB.md`
- Formal artifacts: `formal/`

## Architecture (High Level)

```text
Agent/LLM Client
    |
    v
Vellaveto Enforcement Boundary (server/proxy)
    |- classify + normalize action
    |- evaluate policy (allow/deny/require approval)
    |- log decision + evidence
    v
Upstream Tool/MCP Server
```

## Repository Layout

- `vellaveto-types/` shared contracts (`Action`, `Policy`, `Verdict`, etc.)
- `vellaveto-engine/` policy compiler/evaluator
- `vellaveto-audit/` audit chain and verification primitives
- `vellaveto-mcp/` MCP-specific security/inspection components
- `vellaveto-config/` configuration parsing and validation
- `vellaveto-server/` CLI + HTTP API runtime
- `vellaveto-proxy/` stdio proxy runtime
- `vellaveto-http-proxy/` HTTP MCP reverse proxy runtime
- `vellaveto-integration/` cross-crate integration tests
- `docs/` API, deployment, operations, and security documentation

## Quick Start

### Prerequisites

- Rust `1.88+`
- `cargo`

### 1) Start the HTTP server

```bash
export VELLAVETO_API_KEY=dev-secret
cargo run -p vellaveto-server -- serve --config vellaveto-server/example-config.toml
```

### 2) Evaluate an action

```bash
curl -sS http://127.0.0.1:3000/api/evaluate \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "tool": "file",
    "function": "delete",
    "parameters": {"path": "/tmp/example.txt"}
  }'
```

### 3) Validate a policy config before rollout

```bash
cargo run -p vellaveto-server -- check --config vellaveto-server/example-config.toml
```

### 4) Discover tools by intent

```bash
curl -sS http://127.0.0.1:3000/api/discovery/search \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "read config file",
    "max_results": 5
  }'
```

### 5) Project a tool schema for a model family

```bash
curl -sS http://127.0.0.1:3000/api/projector/transform \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "schema": {
      "name": "file_read",
      "description": "Read file contents",
      "input_schema": {
        "type": "object",
        "properties": { "path": { "type": "string" } },
        "required": ["path"]
      },
      "output_schema": null
    },
    "model_family": "openai"
  }'
```

## Other Runtime Modes

### Stdio MCP proxy

```bash
cargo run -p vellaveto-proxy -- \
  --config vellaveto-server/example-config.toml \
  -- /path/to/mcp-server [args...]
```

### Streamable HTTP MCP reverse proxy

```bash
cargo run -p vellaveto-http-proxy -- \
  --upstream http://127.0.0.1:8000/mcp \
  --config vellaveto-server/example-config.toml
```

## Development Workflow

Run local quality gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For focused work, start with crate-local tests first:

```bash
cargo test -p vellaveto-engine
cargo test -p vellaveto-server
```

## Documentation

- API reference: `docs/API.md`
- Deployment guide: `docs/DEPLOYMENT.md`
- Operations runbook: `docs/OPERATIONS.md`
- Secure quickstart: `docs/SECURE_QUICKSTART_15_MIN.md`
- Release verification: `docs/VERIFY_RELEASE_ARTIFACTS.md`
- Changelog: `CHANGELOG.md`

## License

Vellaveto is licensed under AGPL-3.0 (`LICENSE`).

Commercial licensing is available for organizations that cannot adopt AGPL terms; see `LICENSING.md`.

## Contributing

Please read `CONTRIBUTING.md` and `SECURITY.md` before opening pull requests or reporting security issues.
