# MCPSEC: MCP Security Benchmark Framework

**Version 1.1.0** | **Apache-2.0 License**

MCPSEC is an open, vendor-neutral security benchmark for evaluating MCP (Model Context Protocol) gateway security. It defines 10 formal security properties and 91 reproducible attack test cases across 16 attack classes, derived from real-world penetration testing of MCP deployments.

## Why MCPSEC?

AI agents with tool access are a new attack surface. OWASP defined the ASVS for web apps — MCPSEC does the same for MCP gateways.

Most MCP gateways offer tool-level allowlists and nothing more. MCPSEC tests for what actually matters: injection evasion, encoded exfiltration, schema mutation, confused deputy attacks, audit tampering, and more.

## Quick Start

```bash
# Build the benchmark harness
cargo build -p mcpsec

# Run against a gateway
cargo run -p mcpsec -- --target http://localhost:3000 --output results/my-gateway.json

# Run with markdown report
cargo run -p mcpsec -- --target http://localhost:3000 --format markdown
```

## What It Tests

### 10 Security Properties (P1-P10)

| ID | Property | What It Means |
|----|----------|---------------|
| P1 | Tool-Level Access Control | Unmatched actions are denied by default |
| P2 | Parameter Constraint Enforcement | Parameter values are validated against constraints |
| P3 | Priority Monotonicity | Higher-priority policies are evaluated first |
| P4 | Injection Resistance | Known injection patterns are detected in all encodings |
| P5 | Schema Integrity | Tool schema mutations are detected between sessions |
| P6 | Response Confidentiality | Secrets in responses are detected even when encoded |
| P7 | Audit Immutability | Audit logs are tamper-evident via hash chains |
| P8 | Delegation Monotonicity | Delegated tokens cannot exceed parent permissions |
| P9 | Unicode Normalization | Unicode-obfuscated inputs are normalized before evaluation |
| P10 | Temporal Consistency | Time-windowed policies are enforced correctly |

See [PROPERTIES.md](PROPERTIES.md) for formal definitions.

### 16 Attack Classes (A1-A16)

| # | Class | Tests | OWASP Ref |
|---|-------|-------|-----------|
| A1 | Prompt Injection Evasion | 15 | ASI01 |
| A2 | Tool Poisoning & Rug-Pull | 7 | ASI03 |
| A3 | Parameter Constraint Bypass | 6 | ASI01 |
| A4 | Encoded Exfiltration (DLP) | 9 | ASI04 |
| A5 | Confused Deputy | 5 | ASI02 |
| A6 | Memory Poisoning (MINJA) | 5 | ASI06 |
| A7 | Tool Squatting | 5 | ASI03 |
| A8 | Audit Tampering | 4 | MCP08 |
| A9 | SSRF & Domain Bypass | 8 | MCP05 |
| A10 | DoS & Resource Exhaustion | 4 | MCP10 |
| A11 | Credential Elicitation | 3 | - |
| A12 | Sampling & Covert Channels | 3 | - |
| A13 | Cross-Call Secret Splitting | 4 | - |
| A14 | Schema Pattern Bypass | 4 | - |
| A15 | Agent Identity Spoofing | 5 | ASI02 |
| A16 | Circuit Breaker Evasion | 4 | MCP10 |

**Total: 91 test cases.** See [ATTACKS.md](ATTACKS.md) for full catalog.

## Scoring

| Tier | Score | Meaning |
|------|-------|---------|
| Tier 0: Unsafe | 0-19% | No meaningful security |
| Tier 1: Basic | 20-39% | Allowlist-only |
| Tier 2: Moderate | 40-59% | Some parameter inspection |
| Tier 3: Strong | 60-79% | Injection + DLP + audit |
| Tier 4: Comprehensive | 80-94% | Full threat coverage |
| Tier 5: Hardened | 95-100% | All properties verified |

See [SCORING.md](SCORING.md) for weights and methodology.

## Gateway Interface

MCPSEC tests any gateway that exposes an HTTP evaluation endpoint. The harness sends crafted payloads and checks whether the gateway correctly identifies or blocks each attack.

```
POST /api/evaluate
Content-Type: application/json

{"tool":"bash","function":"exec","parameters":{"command":"..."}}
```

The gateway should return a JSON response with a `verdict` field indicating `Allow`, `Deny`, or equivalent.

## Project Structure

```
mcpsec/
├── README.md              # This file
├── PROPERTIES.md          # 10 formal security properties
├── ATTACKS.md             # 16 attack classes, 91 test cases
├── METHODOLOGY.md         # How to run, how to score
├── SCORING.md             # Scoring rubric and tiers
├── Cargo.toml             # Standalone Rust crate
├── src/
│   ├── lib.rs             # Public API
│   ├── runner.rs          # HTTP client for gateway testing
│   ├── report.rs          # JSON/Markdown report generation
│   ├── scoring.rs         # Score calculation
│   └── attacks/           # 16 attack modules (a01-a16)
├── tests/
│   └── self_test.rs       # Validate harness logic
└── results/               # Reference benchmark results
```

## Philosophy

1. **Open and reproducible.** Every test case is documented with exact payloads and pass/fail criteria. No black-box scoring.
2. **Vendor-neutral.** Any MCP gateway can be benchmarked. The harness tests observable behavior, not implementation details.
3. **Derived from real attacks.** Every test case corresponds to a real attack vector discovered through penetration testing of MCP deployments.
4. **No security theater.** We test what competitors miss: Unicode homoglyphs, multi-layer encoding, schema mutation, audit chain integrity — not just "does the allowlist work."

## Contributing

MCPSEC is open to contributions. To propose a new attack class or security property:

1. Open an issue describing the attack vector
2. Include a proof-of-concept payload
3. Define clear pass/fail criteria
4. Reference relevant OWASP or CVE identifiers

## License

Apache-2.0 — use it, fork it, benchmark your competitors.

The benchmark framework itself is Apache-2.0 to encourage adoption. The Vellaveto gateway is licensed under a three-tier model (MPL-2.0 / Apache-2.0 / BUSL-1.1) — see [LICENSING.md](../LICENSING.md).
