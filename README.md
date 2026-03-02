<div align="center">
  <br>
  <img src="vellaveto_brandkit/docs/readme-header.png" alt="VellaVeto — Agentic Security Control Plane" width="720">
  <br><br>
  <p>
    <a href="https://github.com/vellaveto/vellaveto/releases"><img src="https://img.shields.io/badge/version-6.0.0-blue.svg" alt="Version 6.0.0"></a>
    <a href="https://github.com/vellaveto/vellaveto/actions/workflows/ci.yml"><img src="https://github.com/vellaveto/vellaveto/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
    <a href="https://github.com/vellaveto/vellaveto/stargazers"><img src="https://img.shields.io/github/stars/vellaveto/vellaveto?style=flat&logo=github&label=stars" alt="GitHub Stars"></a>
    <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-MPL--2.0_/_Apache--2.0_/_BUSL--1.1-blue.svg" alt="License: Three-tier"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/MSRV-1.88.0-orange.svg?logo=rust" alt="MSRV 1.88.0"></a>
    <img src="https://img.shields.io/badge/tests-9%2C600%2B_passing-brightgreen.svg" alt="Tests: 9,600+ passing">
    <img src="https://img.shields.io/badge/clippy-zero_warnings-brightgreen.svg" alt="Clippy: zero warnings">
    <a href="docs/SECURITY_GUARANTEES.md"><img src="https://img.shields.io/badge/internal_security_audits-232_rounds-orange.svg" alt="232 Internal Security Audit Rounds"></a>
    <a href="formal/"><img src="https://img.shields.io/badge/formal_verification-TLA%2B_%7C_Lean_4_%7C_Coq-blueviolet.svg" alt="Formal Verification: TLA+ | Lean 4 | Coq"></a>
    <a href="https://modelcontextprotocol.io/specification/2025-11-25"><img src="https://img.shields.io/badge/MCP-2025--11--25-blueviolet.svg" alt="MCP 2025-11-25"></a>
    <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"><img src="https://img.shields.io/badge/OWASP-Agentic_Top_10-red.svg" alt="OWASP Agentic Top 10"></a>
    <a href="https://github.com/vellaveto/vellaveto/actions/workflows/provenance-sbom.yml"><img src="https://img.shields.io/badge/SLSA-Level_3-green.svg" alt="SLSA Level 3"></a>
    <a href="https://github.com/vellaveto/vellaveto/actions/workflows/codeql.yml"><img src="https://github.com/vellaveto/vellaveto/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
  </p>
  <p>
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="#key-capabilities">Capabilities</a> &middot;
    <a href="#whats-next">What's Next</a> &middot;
    <a href="#security">Security</a> &middot;
    <a href="#documentation">Docs</a>
  </p>
</div>

---

VellaVeto is a security-first control plane for agentic systems. It combines an [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) policy gateway, centralized governance APIs, topology discovery, and a tamper-evident audit trail so teams can control how AI agents use tools across local and deployed environments.

Deploy it as a stdio or HTTP gateway, run it as a multi-tenant control plane, extend policy with Cedar-compatible rules and Wasm plugins, and ship verifiable evidence through audit, compliance, and incident workflows.

The v6 foundation is complete. The next planning cycle focuses on turning that shipped platform into the default enterprise control plane for MCP and tool-calling agents through stronger registry trust, delegated identity, evidence automation, and easier managed onboarding. See [ROADMAP.md](ROADMAP.md).

**Core guarantees:**
- **Complete mediation** — request and response paths evaluated before tool execution and before model return
- **Fail-closed** — no policy match, missing context, or evaluation error results in `Deny`
- **Tamper-evident audit** — SHA-256 hash chain + Merkle proofs + Ed25519 signed checkpoints
- **Public security contract** — [Security Guarantees](docs/SECURITY_GUARANTEES.md) + [Assurance Case](docs/ASSURANCE_CASE.md) with reproducible evidence

## What's New

- **v6 foundation complete** — Phases 36-72 are shipped across runtime enforcement, IAM, discovery, analytics, compliance, and deployment surfaces. [Roadmap reset](ROADMAP.md)
- **Consumer Shield** (Phase 67) — New deployment mode for consumer AI interactions. PII sanitization, encrypted local audit, session isolation, warrant canary. [Details](CHANGELOG.md)
- **Three-tier licensing** — MPL-2.0 (core + consumer), Apache-2.0 (canary + benchmark), BUSL-1.1 (enterprise, converts to MPL-2.0 after 3 years). [Details](LICENSING.md)
- **232 adversarial audit rounds** — 1,550+ findings resolved across engine, MCP, server, audit, proxy, and discovery
- **9,600+ tests passing** across Rust, Python, Go, TypeScript, Java, Terraform, React, shell + 24 fuzz targets

See [CHANGELOG.md](CHANGELOG.md) for full history.

## What's Next

The next roadmap is not about adding more generic gateway features. The core runtime is already in place. The current planning cycle is aimed at the control-plane layer above the gateway.

- **Verified registry and connector trust** — make the registry a runtime trust boundary, not just a catalog
- **Delegated identity and access graph** — turn existing OIDC, SAML, DPoP, M2M, and step-up auth into one visible access plane
- **Inventory and posture views** — turn topology, drift, and policy coverage into operator-facing exposure reporting
- **Hosted onboarding and managed deployment paths** — reduce friction against managed MCP gateway competitors
- **Evidence automation** — turn audit and control mapping into reusable customer-grade evidence packs

The forward plan is documented in [ROADMAP.md](ROADMAP.md), covering planned phases 73-81.

## Why VellaVeto?

AI agents with tool access can read files, make HTTP requests, execute commands, modify data, and trigger long-running workflows across multiple services. Without centralized controls, a prompt injection or misbehaving agent can exfiltrate credentials, call unauthorized APIs, bypass restrictions via Unicode tricks or path traversal, impersonate tools, or drift into unsafe cross-tool behavior that no single SDK sees.

VellaVeto gives you one place to enforce policy, govern identity, inventory tools, approve risky actions, and audit every decision. The gateway mediates each tool call before execution, the control plane manages policy and runtime state, and the evidence layer turns security decisions into traceable records. Trust math, not promises.

The four strategic moats for the next cycle are: identity, registry and inventory, evidence, and distribution.

## Quick Start

### Setup Wizard

```bash
npx create-vellaveto
```

### MCP Stdio Proxy (Claude Desktop, local MCP servers)

```bash
cargo install vellaveto-proxy
vellaveto-proxy --config policy.toml -- /path/to/mcp-server
```

### HTTP Reverse Proxy (deployed MCP servers)

```bash
cargo install vellaveto-http-proxy
VELLAVETO_API_KEY=$(openssl rand -hex 32) vellaveto-http-proxy \
  --upstream http://localhost:8000/mcp \
  --config policy.toml \
  --listen 127.0.0.1:3001
```

### Docker

```bash
docker pull ghcr.io/vellaveto/vellaveto:latest
docker run -p 3000:3000 \
  -v /path/to/config.toml:/etc/vellaveto/config.toml:ro \
  ghcr.io/vellaveto/vellaveto:latest
```

### Minimal Policy (deny-by-default)

```toml
[[policies]]
name = "Allow file reads in /tmp"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 100
[policies.path_rules]
allowed = ["/tmp/**"]

[[policies]]
name = "Default deny"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Deny"
priority = 0
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for framework integration guides (Anthropic, OpenAI, LangChain, LangGraph, CrewAI).

## How It Works

```
                    +------------------+
  AI Agent -------->|    VellaVeto     |--------> Tool Server
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

## Architecture

```mermaid
graph TD
    subgraph "Policy Core"
        VT[vellaveto-types] --> VCfg[vellaveto-config]
        VT --> VCan[vellaveto-canonical]
        VT --> VE[vellaveto-engine]
        VT --> VDisc[vellaveto-discovery]
        VE --> VA[vellaveto-audit]
        VE --> VAppr[vellaveto-approval]
    end

    subgraph "Gateway & Control Plane"
        VA --> VMCP[vellaveto-mcp]
        VCfg --> VP[vellaveto-proxy]
        VMCP --> VP
        VMCP --> VHP[vellaveto-http-proxy]
        VMCP --> VServer[vellaveto-server]
        VCfg --> VCluster[vellaveto-cluster]
        VCluster --> VOp[vellaveto-operator]
    end

    subgraph "Consumer & Ecosystem"
        VS[vellaveto-shield] --> MS[vellaveto-mcp-shield]
        VS --> HS[vellaveto-http-proxy-shield]
        VS --> VC[vellaveto-canary]
        MCPSEC[mcpsec]
    end

    MS --> VMCP
    HS --> VHP
    VC --> VA
```

Lower crates never depend on higher crates. `vellaveto-operator` is standalone (kube-rs, no internal deps). License tiers are documented separately in [LICENSING.md](LICENSING.md). See [CLAUDE.md](CLAUDE.md) for the full crate dependency graph.

## Key Capabilities

| Capability | What | Key Tech | Docs |
|---|---|---|---|
| **Policy Engine** | Glob/regex/domain matching, parameter constraints, time windows, call limits, action sequences, Cedar-style ABAC | Pre-compiled patterns, <5ms P99, decision cache, Wasm plugins | [Policy](docs/POLICY.md) |
| **Threat Detection** | Injection, tool squatting, rug pulls, schema poisoning, confused deputy, DLP, memory poisoning, multi-agent collusion | OWASP Agentic Top 10 coverage, Aho-Corasick, NFKC, Levenshtein | [Threat Model](docs/THREAT_MODEL.md) |
| **Auth & Access** | OAuth 2.1/JWT, ABAC with forbid-overrides, capability delegation, DPoP (RFC 9449), identity federation, least-agency, NHI lifecycle | Ed25519, OIDC/SAML, RBAC, continuous authorization | [IAM](docs/IAM.md) |
| **Audit & Compliance** | Tamper-evident logs, ZK proofs (Pedersen+Groth16), EU AI Act, SOC 2, DORA/NIS2, NIST AI 600-1, ISO 42001, OWASP MCP Top 10 | SHA-256 chains, Merkle proofs, ML-DSA-65 (PQC), evidence packs | [Security Guarantees](docs/SECURITY_GUARANTEES.md) |
| **Consumer Shield** | PII sanitization, encrypted local audit, session isolation, warrant canary | XChaCha20-Poly1305, Argon2id, per-session PII mapping | [Consumer Shield](examples/presets/consumer-shield.toml) |
| **Deployment** | 6 modes (HTTP, stdio, WebSocket, gRPC, gateway, consumer shield), K8s operator (3 CRDs), Helm, Terraform | All MCP transports, cross-transport fallback, distributed tracing | [Deployment](docs/DEPLOYMENT.md) |

## Security

VellaVeto has undergone **232 rounds of adversarial security auditing** covering 31+ attack classes mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

- **Fail-closed everywhere** — empty policy sets, missing parameters, lock poisoning, capacity exhaustion, and evaluation errors all produce `Deny`
- **Zero `unwrap()` in library code** — all error paths return typed errors; panics reserved for tests only
- **Formal verification** — TLA+ (policy engine, ABAC, workflow, task lifecycle, cascading failure), Alloy (capability delegation), Kani (5 proof harnesses)
- **Post-quantum ready** — Hybrid Ed25519 + ML-DSA-65 (FIPS 204) audit signatures, feature-gated behind `pqc-hybrid`

**Known limitations:** Injection detection is a pre-filter, not a security boundary. DLP does not detect split secrets. No TLS termination (use a reverse proxy). See [Security Guarantees](docs/SECURITY_GUARANTEES.md) for the full normative contract.

Full details: [Security Guarantees](docs/SECURITY_GUARANTEES.md) | [Threat Model](docs/THREAT_MODEL.md) | [Assurance Case](docs/ASSURANCE_CASE.md)

## Deployment Modes

| Mode | Command | Use Case |
|---|---|---|
| HTTP API Server | `vellaveto serve` | Dashboard, REST API, policy management |
| MCP Stdio Proxy | `vellaveto-proxy` | Claude Desktop, local MCP servers |
| HTTP Reverse Proxy | `vellaveto-http-proxy` | Deployed MCP servers, SSE/Streamable HTTP |
| WebSocket Proxy | `vellaveto-http-proxy` | Bidirectional MCP-over-WS at `/mcp/ws` |
| gRPC Proxy | `vellaveto-http-proxy --grpc` | High-throughput, protobuf-native (feature-gated) |
| Consumer Shield | `vellaveto-shield` | User-side PII protection |

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for configuration details.

## Documentation

### Getting Started

| Document | Description |
|---|---|
| [Quick Start](docs/QUICKSTART.md) | Framework integration guides (Anthropic, OpenAI, LangChain, LangGraph, MCP) |
| [15-Minute Secure Start](docs/SECURE_QUICKSTART_15_MIN.md) | End-to-end deny-by-default walkthrough with audit verification |
| [Policy Configuration](docs/POLICY.md) | Policy syntax, operators, presets, elicitation, sampling, DLP |
| [CLI Reference](docs/CLI.md) | All binaries and commands |
| [Environment Variables](docs/ENV.md) | Configuration via environment |

### Security & Compliance

| Document | Description |
|---|---|
| [Security Guarantees](docs/SECURITY_GUARANTEES.md) | Normative, falsifiable security contract |
| [Threat Model](docs/THREAT_MODEL.md) | Trust boundaries, attack surfaces, mitigations |
| [Assurance Case](docs/ASSURANCE_CASE.md) | Claim -> evidence -> reproduce map |
| [Security Hardening](docs/SECURITY.md) | Security configuration best practices |
| [Quantum Migration](docs/quantum-migration.md) | PQC rollout and rollback gates |

### Operations & Architecture

| Document | Description |
|---|---|
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, Kubernetes (Helm), bare metal |
| [Operations Runbook](docs/OPERATIONS.md) | Monitoring, troubleshooting, maintenance |
| [API Reference](docs/API.md) | Complete HTTP API (135+ endpoints) |
| [Audit Log](docs/AUDIT_LOG.md) | Audit system internals, verification, SIEM export |
| [IAM](docs/IAM.md) | OIDC, SAML, RBAC, session management |
| [Benchmarks](docs/BENCHMARKS.md) | Reproducible performance benchmarks |
| [Evaluation Traces](docs/EVALUATION_TRACES.md) | Decision explainability and execution graphs |

### SDKs

| SDK | Path | Tests |
|---|---|---|
| Python (sync + async, LangChain, LangGraph, CrewAI, Composio, Claude Agent, Strands) | [sdk/python/](sdk/python/) | 433 |
| TypeScript | [sdk/typescript/](sdk/typescript/) | 119 |
| Go | [sdk/go/](sdk/go/) | 127 |
| Java | [sdk/java/](sdk/java/) | 120 |

## Development

```bash
# Build
cargo build --release

# Test
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets

# Format
cargo fmt --check

# Security audit
cargo audit

# Benchmarks
cargo bench --workspace

# Fuzz (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_json_rpc_framing -- -max_total_time=60
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules and commit format.

## License

| Tier | License | Crates |
|---|---|---|
| Core + Consumer | MPL-2.0 | types, engine, audit, config, canonical, discovery, approval, proxy, mcp-shield, shield |
| Canary + Benchmark | Apache-2.0 | canary, mcpsec |
| Enterprise | BUSL-1.1 → MPL-2.0 | server, http-proxy, mcp, cluster, operator, integration |

Enterprise crates are free for production use at ≤3 nodes / ≤25 endpoints. Each version converts to MPL-2.0 after 3 years. See [LICENSING.md](LICENSING.md) for full details. For managed service offerings or above-threshold deployments, contact **paolovella1993@gmail.com**.

## References

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP](https://arxiv.org/pdf/2504.08623)
