# OSTIF Audit Application — Scope Document

## Project Overview

**Vellaveto** is an agent interaction firewall for AI tool calls. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies, and maintains a tamper-evident audit trail with ACIS decision envelopes.

- **Version:** 6.0.0-dev
- **Language:** Rust (100% safe code in library crates, zero `unwrap()`)
- **Tests:** 8,970+ unit + integration tests
- **License:** Three-tier (MPL-2.0 / Apache-2.0 / BUSL-1.1)

## Security-Critical Crates (Priority Order)

| Crate | LOC (approx) | Role | Key Concerns |
|-------|-------------|------|-------------|
| `vellaveto-engine` | ~4,500 | Policy evaluation, path/domain matching | Fail-closed guarantees, regex safety, IDNA handling |
| `vellaveto-mcp` | ~18,000 | MCP protocol handling, injection/DLP scanning | Pattern evasion, cross-call DLP, schema validation |
| `vellaveto-audit` | ~8,000 | Tamper-evident logging, Merkle proofs, ZK | Hash chain integrity, Ed25519 signing, PQC |
| `vellaveto-server` | ~7,000 | HTTP API, authentication, RBAC, TLS | Auth bypass, SAML/OIDC, rate limiting |
| `vellaveto-config` | ~3,000 | Configuration parsing and validation | Fail-open defaults, unbounded collections |

## Architecture for Auditors

```
Client → [vellaveto-http-proxy / vellaveto-server]
              ↓
         [vellaveto-mcp] ← injection/DLP scanning
              ↓
         [vellaveto-engine] ← policy evaluation
              ↓
         [vellaveto-audit] ← tamper-evident logging
              ↓
         Upstream MCP Server
```

All verdicts are **fail-closed**: errors, missing policies, and unresolved context produce `Deny`.

## Internal Audit Summary

- **250 adversarial audit rounds** completed (Feb 2025 – Mar 2026)
- **1,700+ findings** identified and resolved
- Categories: injection evasion (23%), policy bypass (18%), authentication (15%), information disclosure (12%), SSRF (8%), DLP bypass (7%), audit tampering (5%), other (12%)
- Resolution rate: 100% of CRITICAL/HIGH, 98% of MEDIUM, 95% of LOW

## Formal Verification Map

| Property | Verification Method | Status |
|----------|-------------------|--------|
| Fail-closed (S1) | Lean 4 theorem, TLA+ model | Proven |
| Determinism (S5) | Lean 4 theorem | Proven |
| Path idempotence | Lean 4 theorem | Proven |
| ABAC forbid-override (S7-S10) | Coq theorems | Proven |
| Capability attenuation (S11-S16) | Coq theorems | Proven |
| Policy engine liveness | TLA+ model | Checked |
| Task lifecycle safety | TLA+ model | Checked |
| Cascading failure recovery | TLA+ model | Checked |
| Memory safety (select functions) | Kani proof harnesses (5) | Verified |

## What an Audit Should Focus On

1. **Policy evaluation correctness** — verify that the engine cannot be tricked into producing `Allow` for disallowed actions
2. **Injection scanner coverage** — identify evasion techniques not covered by the 175+ pattern Aho-Corasick scanner
3. **Cryptographic audit chain** — verify Merkle proof generation and Ed25519 checkpoint signing
4. **Authentication boundaries** — test OAuth/JWKS/SAML/DPoP flows for bypass opportunities
5. **Cross-call DLP** — verify overlap buffer tracking correctly detects split secrets (Phase 71)
6. **Schema validation** — verify JSON Schema pattern enforcement is complete (Phase 72)

## Contact

security@vellaveto.online
