<p align="center">
  <h1 align="center">Vellaveto</h1>
  <p align="center">
    <strong>Runtime security engine for AI agent tool calls</strong>
  </p>
  <p align="center">
    Intercept &middot; Evaluate &middot; Enforce &middot; Audit
  </p>
  <p align="center">
    <a href="https://github.com/paolovella/vellaveto/actions/workflows/ci.yml"><img src="https://github.com/paolovella/vellaveto/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
    <a href="https://github.com/paolovella/vellaveto/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
    <a href="https://securityscorecards.dev/viewer/?uri=github.com/paolovella/vellaveto"><img src="https://api.securityscorecards.dev/projects/github.com/paolovella/vellaveto/badge" alt="OpenSSF Scorecard"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-2021_edition-orange.svg" alt="Rust 2021"></a>
    <img src="https://img.shields.io/badge/tests-4%2C892_passing-brightgreen.svg" alt="Tests: 4,892 passing">
    <a href="https://modelcontextprotocol.io/specification/2025-11-25"><img src="https://img.shields.io/badge/MCP-2025--11--25-blueviolet.svg" alt="MCP 2025-11-25"></a>
  </p>
</p>

---

Vellaveto is a lightweight, high-performance firewall that sits between AI agents and their tools. It intercepts [MCP](https://modelcontextprotocol.io/) tool calls, enforces security policies, and maintains a tamper-evident audit trail with cryptographic guarantees.

**EU AI Act compliant before August 2, 2026.**

```bash
docker run -p 3000:3000 ghcr.io/paolovella/vellaveto:latest
```

```bash
# Test it — evaluate a tool call
curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}' | jq .
# => {"verdict":"Allow", ...}

curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/home/user/.ssh/id_rsa"}}' | jq .
# => {"verdict":{"Deny":{"reason":"Denied by policy 'Block credential files'"}}, ...}
```

Zero config. Deny-by-default policy baked in. Under 60 seconds.

## Why Vellaveto?

AI agents with tool access can read files, make HTTP requests, execute commands, and modify data. Without guardrails, a prompt injection or misbehaving agent can exfiltrate credentials, call unauthorized APIs, or execute destructive commands.

**Three reasons to choose Vellaveto over alternatives:**

1. **Deep inspection, not just allowlists.** Parameter-level constraints with recursive JSON scanning, injection detection (Aho-Corasick, 40+ patterns), DLP response scanning (5-layer decode pipeline), and tool annotation rug-pull detection. Most gateways only match tool names.

2. **Cryptographic audit trail.** Every decision is logged to a tamper-evident chain: SHA-256 hash chain, Merkle tree inclusion proofs, Ed25519 signed checkpoints. You can prove what was allowed and what was denied, in court if needed.

3. **Sub-millisecond, zero-allocation hot path.** Pre-compiled glob, regex, and domain patterns. Tool-indexed policy lookup. 7-31ns single policy evaluation, <5ms P99 at scale. No GC, no runtime, no cold starts. Written in Rust.

### Comparison

| Capability | Vellaveto | MintMCP | Lasso | Docker MCP Gateway | AWS AgentCore |
|------------|-----------|---------|-------|--------------------|---------------|
| Policy evaluation | Glob + regex + domain + parameter constraints | Allowlist-based | Allowlist-based | K8s policy | Managed rules |
| Parameter-level inspection | Recursive JSON scanning with 6 operators | No | No | No | Limited |
| Injection detection | Aho-Corasick, 40+ patterns, NFKC normalization | No | No | No | Basic |
| DLP response scanning | 7 secret patterns, 5-layer decode | No | No | No | No |
| Rug-pull detection | Schema lineage, annotation tracking | No | No | No | No |
| Audit trail | SHA-256 chain + Merkle proofs + Ed25519 | Logs | Logs | K8s audit | CloudTrail |
| Human-in-the-loop approvals | Built-in with dedup + expiry | No | No | No | Manual |
| ABAC (Cedar-style) | Permit/forbid, entity store, group membership | No | No | No | IAM |
| EU AI Act evidence | Art 5-50 conformity assessment | No | No | No | No |
| OWASP ASI Top 10 coverage | 40+ detections (all 10 categories) | Partial | Partial | No | Partial |
| Deployment modes | 6 (HTTP, stdio, HTTP proxy, WS, gRPC, gateway) | 1 | 1 | 1 | 1 |
| Latency (single eval) | 7-31 ns | N/A | N/A | N/A | N/A |
| Open source | AGPL-3.0 | Proprietary | Proprietary | MIT | Proprietary |

### Used By

Building with Vellaveto? [Open an issue](https://github.com/paolovella/vellaveto/issues) or [start a discussion](https://github.com/paolovella/vellaveto/discussions) to get listed here.

## Quick Start

### Docker (zero config)

```bash
docker run -p 3000:3000 ghcr.io/paolovella/vellaveto:latest
```

Ships with a deny-by-default policy that blocks credential access, exfiltration domains, and destructive commands while allowing safe file reads and search operations.

### Custom policy

```bash
docker run -p 3000:3000 \
  -v ./policy.toml:/etc/vellaveto/config.toml:ro \
  ghcr.io/paolovella/vellaveto:latest
```

### Build from source

```bash
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto
cargo build --release
VELLAVETO_API_KEY=your-secret ./target/release/vellaveto serve --config examples/default.toml --port 3000
```

### Kubernetes

```bash
helm install vellaveto ./helm/vellaveto --namespace vellaveto --create-namespace
```

## How It Works

```
                    +------------------+
  AI Agent -------->|    Vellaveto     |--------> Tool Server
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

Six deployment modes:

| Mode | Binary | Use Case |
|------|--------|----------|
| **HTTP API** | `vellaveto serve` | Standalone policy server; agents call `/api/evaluate` |
| **Stdio Proxy** | `vellaveto-proxy` | Wraps a local MCP server; intercepts stdin/stdout |
| **HTTP Proxy** | `vellaveto-http-proxy` | Reverse proxy for remote MCP servers (Streamable HTTP) |
| **WebSocket** | `vellaveto-http-proxy` | Bidirectional MCP at `/mcp/ws` |
| **gRPC** | `vellaveto-http-proxy --grpc` | Protocol Buffers transport on port 50051 |
| **MCP Gateway** | `vellaveto-http-proxy` | Multi-backend routing with health checks |

## Features

### Core Policy Engine
- Policy evaluation with glob, regex, and domain matching
- Parameter constraints with recursive JSON scanning (6 operators)
- Context-aware policies: time windows, rate limits, action sequences
- Human-in-the-loop approvals with deduplication and expiry
- Pre-compiled patterns (zero allocations on hot path)
- Canonical presets for common scenarios

### Threat Detection (OWASP Agentic Top 10)
- Injection detection (ASI01) with Aho-Corasick + Unicode NFKC normalization
- Tool squatting and rug-pull detection (ASI03) via Levenshtein + homoglyph analysis
- Confused deputy prevention (ASI02) with delegation chain validation
- Memory poisoning defense (ASI06) with taint propagation and provenance graphs
- DLP response scanning: 7 secret patterns through 5 decode layers
- Goal drift detection, shadow agent fingerprinting, output covert channel analysis

### Authentication and Access Control
- OAuth 2.1 / JWT with JWKS, RS256/ES256/EdDSA
- Cedar-style ABAC engine with forbid-overrides
- Capability delegation tokens (Ed25519, monotonic attenuation)
- Identity federation, continuous authorization, least-agency tracking

### Cryptographic Audit Trail
- SHA-256 hash chain with Merkle tree inclusion proofs
- Ed25519 signed checkpoints with rotation chain continuity
- SIEM export (CEF, JSON Lines)
- Immutable archive with gzip compression and retention enforcement

### Compliance
- EU AI Act: Art 5-50 conformity assessment, automated decision explanations, data governance
- SOC 2 evidence collection (22 criteria, 5-level readiness scoring)
- NIST RMF, ISO 27090, ISO 42001, CoSAI (100%), Adversa TOP 25 (100%)

### Enterprise
- ETDI: Cryptographic tool signing (Ed25519/ECDSA P-256)
- MINJA: Memory injection defense with taint propagation
- NHI: Non-human identity lifecycle with behavioral attestation
- mTLS/SPIFFE, OPA integration, Just-In-Time access, threat intelligence feeds

### SDKs
- **Python** — sync/async client, LangChain + LangGraph adapters (130 tests)
- **TypeScript** — zero-dependency, native `fetch()` (15 tests)
- **Go** — zero-dependency, `context.Context` on all methods (28 tests)

## Policy Example

```toml
# Block credential files (highest priority)
[[policies]]
name = "Block credentials"
tool_pattern = "*"
function_pattern = "*"
priority = 300

[policies.policy_type.Conditional.conditions]
parameter_constraints = [
  { param = "*", op = "glob", pattern = "**/.ssh/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.aws/**", on_match = "deny", on_missing = "skip" },
]

# Allow file reads
[[policies]]
name = "Allow reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 100

# Default deny everything else
[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 0
```

See [Policy Configuration](docs/POLICY.md) for the full reference (6 operators, approval flows, presets).

## API

```bash
# Evaluate a tool call
curl -s http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}'

# Health check
curl -s http://localhost:3000/health

# Prometheus metrics
curl -s http://localhost:3000/metrics

# Audit log
curl -s http://localhost:3000/api/audit/entries?limit=10

# Approve a pending action
curl -X POST http://localhost:3000/api/approvals/$ID/approve \
  -H "Content-Type: application/json" \
  -d '{"resolved_by":"alice@example.com"}'
```

Full API reference: [docs/API.md](docs/API.md)

## Performance

All patterns pre-compiled at load time. Zero allocations on the evaluation hot path.

| Scenario | Latency |
|----------|---------|
| Single policy evaluation | 7-31 ns |
| 100 policies | ~1.2 us |
| 1,000 policies | ~12 us |
| HMAC-SHA256 sign + verify | ~1.6 us |
| Privilege escalation check | 16-76 ns |

## Architecture

```
vellaveto-types             Core types: Action, Policy, Verdict
       |
vellaveto-config            Config parsing (TOML/JSON)
vellaveto-canonical         Built-in presets
       |
vellaveto-engine            Policy evaluation (pre-compiled patterns)
       |
vellaveto-audit             Tamper-evident logging
vellaveto-approval          Human-in-the-loop approvals
vellaveto-mcp              MCP protocol security
       |
vellaveto-cluster           Distributed state (local + Redis)
       |
vellaveto-server            HTTP API + CLI
vellaveto-proxy             Stdio MCP proxy
vellaveto-http-proxy        HTTP/WS/gRPC reverse proxy
```

12 workspace crates. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full module map.

## Documentation

| Document | Description |
|----------|-------------|
| [Policy Reference](docs/POLICY.md) | Operators, constraints, presets, approval flows |
| [API Reference](docs/API.md) | All HTTP endpoints with examples |
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, Kubernetes, systemd, configuration |
| [Security Model](docs/SECURITY.md) | Threat model, design principles, vulnerability reporting |
| [Audit Operations](docs/AUDIT.md) | Log verification, SIEM export, Merkle proofs |
| [EU AI Act Compliance](docs/EU-AI-ACT.md) | Art 5-50 evidence, conformity assessment |
| [SDK Guides](docs/SDKS.md) | Python, TypeScript, Go integration |
| [CHANGELOG](CHANGELOG.md) | Full release history |
| [ROADMAP](ROADMAP.md) | v4.0 public roadmap (Q2 2026 - Q1 2027) |

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development guide and CLA.

## License

[AGPL-3.0](LICENSE) with [commercial license](LICENSING.md) available.

Open source under AGPL-3.0. Organizations that cannot comply with the AGPL copyleft requirements (e.g., embedding in proprietary software or offering as a managed service) can obtain a commercial license.

Contact: **paolovella1993@gmail.com**

---

Built by [Paolo Vella](https://github.com/paolovella).
