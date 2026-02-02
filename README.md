# Sentinel

A modular policy engine workspace for evaluating actions against configurable security policies with full audit logging.

## Architecture

Sentinel is organized as a Rust workspace with the following crates:

| Crate | Purpose |
|---|---|
| `sentinel-types` | Shared types: `Action`, `Policy`, `PolicyType`, `Verdict` |
| `sentinel-core` | Core policy logic and rule definitions |
| `sentinel-engine` | `PolicyEngine` — evaluates actions against policy sets |
| `sentinel-audit` | `AuditLogger` — async audit trail with report generation |
| `sentinel-policy` | Policy storage and management |
| `sentinel-integration` | Cross-crate integration tests exercising the full pipeline |

## Key APIs

### PolicyEngine