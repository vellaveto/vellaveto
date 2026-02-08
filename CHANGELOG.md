# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-08

Initial production release of Sentinel, a runtime security engine for AI agent tool calls.

### Core Features

#### Policy Engine
- Glob and regex-based policy matching for tools and functions
- Parameter constraint evaluation with multiple operators (glob, regex, domain_match, domain_in, domain_not_in)
- Priority-based policy ordering with deterministic evaluation
- Path traversal-safe normalization for filesystem rules
- RFC 1035-compliant domain validation for network rules
- Context-aware policies with time windows, call limits, and action sequences

#### Network Security
- DNS rebinding protection with private IP blocking
- CIDR-based allow/block lists for resolved IPs
- Domain allowlisting and blocklisting
- Carrier-grade NAT (100.64.0.0/10) blocking

#### Authentication & Authorization
- API key authentication for admin endpoints
- OAuth 2.1 / JWT support with JWKS validation
- Role-based access control (RBAC) with Admin, Operator, Auditor, and Viewer roles
- Agent identity attestation via signed JWTs
- Per-endpoint and per-principal rate limiting

#### Audit System
- Tamper-evident audit logging with SHA-256 hash chain
- Ed25519 signed checkpoints for integrity verification
- Configurable PII redaction (Off, Low, High)
- Audit log rotation support
- Multiple export formats: JSON Lines, CEF, syslog (RFC 5424)
- SIEM integrations: Splunk HEC, Datadog, Elasticsearch, webhook

#### Human-in-the-Loop Approvals
- Approval queue for dangerous operations
- Deduplication of pending approvals
- Full audit trail for approval decisions
- Configurable approval timeouts

#### Detection & Prevention
- Prompt injection scanning with Aho-Corasick pattern matching
- Unicode NFKC normalization for homoglyph attack prevention
- Semantic injection detection via n-gram TF-IDF similarity
- Data Loss Prevention (DLP) with 5-layer decode pipeline (raw, base64, percent, combinations)
- Rug-pull detection for tool schema changes
- Tool squatting detection via Levenshtein distance + homoglyph analysis
- Memory poisoning defense with cross-request data tracking
- Behavioral anomaly detection using EMA-based frequency tracking

#### Multi-Tenancy
- Tenant isolation for policy, audit, and approval data
- Tenant extraction from JWT claims, headers, or subdomains
- Per-tenant quotas and rate limiting
- Tenant management API endpoints

#### Observability
- Prometheus metrics endpoint with 24+ metrics
- OpenTelemetry instrumentation for distributed tracing
- Health and readiness endpoints
- Admin dashboard with server-rendered HTML

### Deployment

#### Docker
- Multi-stage Dockerfile for optimized builds
- Static musl-linked binaries (<50MB images)
- Non-root user execution
- Health checks included

#### Kubernetes
- Helm chart with comprehensive values.yaml
- Horizontal Pod Autoscaler support
- Ingress configuration
- Security contexts and pod disruption budgets

#### Clustering
- Redis backend for distributed state
- Shared approval state across instances
- Global rate limiting

### Security Hardening

- Fail-closed design: errors, missing policies, and unresolved context produce Deny
- Zero `unwrap()` in library code
- Constant-time API key comparison
- CSRF defense-in-depth via Origin/Referer validation
- Idempotency keys for at-most-once semantics
- 1MB request body limit
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
- CORS configuration
- 17 rounds of adversarial security audits

### Testing

- 2,400+ tests across all crates
- Property-based testing with proptest
- Fuzz targets for:
  - JSON-RPC framing
  - Path normalization
  - Domain extraction
  - CIDR parsing
  - Message classification
  - Parameter scanning
  - Semantic similarity
- Criterion benchmarks for performance-critical paths
- Integration tests for OWASP MCP Top 10

### Documentation

- Comprehensive deployment guide (Docker, Kubernetes, bare metal)
- Operations runbook with troubleshooting procedures
- Security hardening guide
- Complete API reference
- Production configuration examples

### Breaking Changes from 0.x

This is the initial stable release. No breaking changes from previous versions.

---

## [0.1.0] - 2026-01-15

### Added
- Initial development release
- Core policy engine with basic glob matching
- Simple audit logging
- HTTP API server
- Stdio proxy mode
- Basic DLP scanning

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

[1.0.0]: https://github.com/paolovella/sentinel/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/paolovella/sentinel/releases/tag/v0.1.0
