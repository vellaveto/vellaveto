# Sentinel Roadmap

> **Version:** 1.0.0
> **Generated:** 2026-02-08
> **Status:** ✅ All phases complete - v1.0.0 released
> **Based on:** Multi-agent research analysis (security, architecture, features, testing)

---

## Executive Summary

Sentinel is a production-ready MCP firewall with excellent security posture (33 audit rounds, 3,167 tests, zero P0/P1 vulnerabilities). This roadmap documents the completed implementation phases that led to the v1.0.0 release.

**Key Themes:**
1. **Enterprise Auth & Multi-tenancy** — Enable shared deployments
2. **Observability & Integration** — Meet enterprise logging/tracing requirements
3. **Code Quality & Maintainability** — Reduce technical debt
4. **Testing & Hardening** — Increase confidence through property-based testing and fuzzing

---

## Phase 1: Foundation & Quick Wins (Weeks 1-2)

*Focus: Code quality, testing infrastructure, deployment basics*

### 1.1 Architecture Cleanup

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Split `sentinel-mcp/src/inspection.rs` (3,373 LOC) into modules | HIGH | 3 days | — |
| Split `sentinel-mcp/src/proxy.rs` (3,294 LOC) into modules | HIGH | 3 days | — |
| Consolidate error handling (thiserror only, remove anyhow from libs) | MEDIUM | 2 days | — |
| Extract `ProxyConfig` struct from 15 builder methods | MEDIUM | 1 day | — |

**Suggested module structure:**
```
sentinel-mcp/src/
├── inspection/
│   ├── mod.rs           # Re-exports, coordination
│   ├── dlp_scanner.rs   # Secret detection patterns
│   ├── injection.rs     # Injection pattern matching
│   ├── decode.rs        # 5-layer decode pipeline
│   └── output.rs        # Output schema validation
├── proxy/
│   ├── mod.rs           # Re-exports
│   ├── bridge.rs        # ProxyBridge core
│   ├── message.rs       # JSON-RPC message handling
│   ├── session.rs       # Session management
│   └── evaluation.rs    # Policy evaluation integration
```

### 1.2 Testing Infrastructure

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add `proptest` dependency to workspace | HIGH | 0.5 days | — |
| Create property tests for policy evaluation invariants | HIGH | 2 days | proptest |
| Add `fuzz_output_schema_validation.rs` target | MEDIUM | 1 day | — |
| Add `fuzz_dlp_inspection.rs` target | MEDIUM | 1 day | — |
| Add `fuzz_policy_regex_compilation.rs` target | MEDIUM | 1 day | — |
| Add end-to-end HTTP→audit pipeline test | HIGH | 1 day | — |

**Property test invariants to implement:**
```rust
// sentinel-engine/tests/proptest_invariants.rs
proptest! {
    #[test]
    fn evaluate_never_panics(action: Action, policies: Vec<Policy>) {
        let engine = PolicyEngine::with_policies(policies);
        let _ = engine.evaluate_action(&action); // Should never panic
    }

    #[test]
    fn higher_priority_always_wins(policies: Vec<Policy>, action: Action) {
        // Verify priority ordering is always respected
    }

    #[test]
    fn normalized_paths_never_contain_dotdot(path: String) {
        if let Ok(normalized) = normalize_path(&path) {
            prop_assert!(!normalized.contains(".."));
        }
    }
}
```

### 1.3 Deployment Basics

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create multi-stage Dockerfile | HIGH | 0.5 days | — |
| Publish Docker images to GitHub Container Registry | HIGH | 0.5 days | Dockerfile |
| Create basic Helm chart (Deployment, Service, ConfigMap) | HIGH | 2 days | Docker images |
| Add Helm chart documentation | MEDIUM | 0.5 days | Helm chart |

**Dockerfile structure:**
```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin sentinel --bin sentinel-http-proxy

# Runtime stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/release/sentinel /usr/local/bin/
COPY --from=builder /build/target/release/sentinel-http-proxy /usr/local/bin/
ENTRYPOINT ["sentinel"]
```

### Phase 1 Deliverables
- [ ] Modular `sentinel-mcp` crate structure
- [ ] Property-based testing suite
- [ ] 3 new fuzz targets
- [ ] Docker images on GHCR
- [ ] Helm chart v0.1.0

**Estimated Duration:** 2 weeks
**Team Size:** 1-2 engineers

---

## Phase 2: Enterprise Authentication (Weeks 3-5)

*Focus: RBAC, key management, identity provider integration*

### 2.1 Role-Based Access Control (RBAC)

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define role and permission model | HIGH | 1 day | — |
| Extend JWT claims parsing for roles | HIGH | 1 day | — |
| Implement role middleware in routes.rs | HIGH | 2 days | Role model |
| Create endpoint permission matrix | HIGH | 1 day | Role middleware |
| Add RBAC integration tests | HIGH | 1 day | All above |

**Permission model:**
```rust
pub enum Permission {
    // Policy management
    PolicyRead,
    PolicyWrite,
    PolicyReload,

    // Approvals
    ApprovalRead,
    ApprovalResolve,

    // Audit
    AuditRead,
    AuditExport,
    AuditCheckpoint,

    // Admin
    MetricsRead,
    DashboardAccess,
    ConfigReload,
}

pub enum Role {
    Admin,      // All permissions
    Operator,   // PolicyRead, ApprovalResolve, AuditRead, MetricsRead
    Auditor,    // AuditRead, AuditExport
    Viewer,     // PolicyRead, AuditRead
}
```

**Endpoint permission matrix:**

| Endpoint | Admin | Operator | Auditor | Viewer |
|----------|-------|----------|---------|--------|
| POST /api/evaluate | ✓ | ✓ | ✗ | ✗ |
| GET /api/policies | ✓ | ✓ | ✓ | ✓ |
| POST /api/policies | ✓ | ✗ | ✗ | ✗ |
| DELETE /api/policies/:id | ✓ | ✗ | ✗ | ✗ |
| POST /api/policies/reload | ✓ | ✓ | ✗ | ✗ |
| GET /api/approvals/pending | ✓ | ✓ | ✓ | ✗ |
| POST /api/approvals/:id/approve | ✓ | ✓ | ✗ | ✗ |
| GET /api/audit/* | ✓ | ✓ | ✓ | ✓ |
| POST /api/audit/checkpoint | ✓ | ✗ | ✗ | ✗ |
| GET /metrics | ✓ | ✓ | ✗ | ✗ |
| GET /dashboard | ✓ | ✓ | ✓ | ✓ |

### 2.2 Key Rotation & Management

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design key versioning schema | HIGH | 0.5 days | — |
| Implement key rotation scheduler | HIGH | 2 days | — |
| Add key version to checkpoint signatures | HIGH | 1 day | Key versioning |
| Support old key verification (grace period) | MEDIUM | 1 day | Key versioning |
| Add key rotation audit events | MEDIUM | 0.5 days | — |
| Create key rotation CLI command | MEDIUM | 1 day | All above |

**Configuration:**
```toml
[keys]
# Ed25519 signing key (hex-encoded seed)
signing_key = "a1b2c3d4..."

# Automatic rotation
rotation_interval = "90d"    # Rotate every 90 days
grace_period = "7d"          # Accept old key for 7 days after rotation
rotation_warning = "14d"     # Warn 14 days before expiry

# Key history (for verification of old checkpoints)
max_historical_keys = 10
```

### 2.3 Secret Manager Integration

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define `SecretProvider` trait | HIGH | 0.5 days | — |
| Implement `EnvSecretProvider` (current behavior) | HIGH | 0.5 days | Trait |
| Implement `VaultSecretProvider` | HIGH | 2 days | Trait |
| Implement `AwsSecretsManagerProvider` | MEDIUM | 2 days | Trait |
| Add secret refresh/lease management | MEDIUM | 1 day | Providers |

**Trait design:**
```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get_secret(&self, key: &str) -> Result<Secret, SecretError>;
    async fn refresh(&self) -> Result<(), SecretError>;
}

pub struct Secret {
    pub value: SecretString,
    pub expires_at: Option<DateTime<Utc>>,
    pub version: Option<String>,
}
```

**Configuration:**
```toml
[secrets]
provider = "vault"  # env | vault | aws | azure

[secrets.vault]
address = "https://vault.example.com"
auth_method = "approle"
role_id_env = "VAULT_ROLE_ID"
secret_id_env = "VAULT_SECRET_ID"
secret_path = "secret/data/sentinel"
```

### Phase 2 Deliverables
- [ ] RBAC with 4 built-in roles
- [ ] Automatic key rotation
- [ ] HashiCorp Vault integration
- [ ] AWS Secrets Manager integration (optional)

**Estimated Duration:** 3 weeks
**Team Size:** 1-2 engineers

---

## Phase 3: Multi-Tenancy (Weeks 6-8)

*Focus: Tenant isolation for SaaS deployments*

### 3.1 Tenant Model

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design tenant data model | HIGH | 1 day | — |
| Add `tenant_id` to EvaluationContext | HIGH | 1 day | Model |
| Implement tenant middleware (extract from JWT/header) | HIGH | 2 days | Model |
| Namespace policies by tenant | HIGH | 2 days | Middleware |
| Partition audit logs by tenant | HIGH | 2 days | Middleware |
| Extend Redis backend for tenant isolation | MEDIUM | 2 days | All above |

**Tenant extraction priority:**
1. JWT claim: `tenant_id` or `org_id`
2. Header: `X-Tenant-ID`
3. Subdomain: `{tenant}.sentinel.example.com`
4. Default tenant (for single-tenant mode)

**Policy namespacing:**
```
# Before (single-tenant)
policy_id = "file_system:read_file"

# After (multi-tenant)
policy_id = "{tenant_id}:file_system:read_file"

# Shared policies (cross-tenant)
policy_id = "_global_:dangerous_tools_block"
```

### 3.2 Tenant Administration

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create tenant management API endpoints | HIGH | 2 days | Tenant model |
| Implement tenant quota enforcement | MEDIUM | 2 days | Tenant API |
| Add tenant-scoped rate limiting | MEDIUM | 1 day | Quotas |
| Create tenant dashboard view | MEDIUM | 1 day | Tenant API |

**New endpoints:**
```
POST   /api/tenants                  # Create tenant (super-admin only)
GET    /api/tenants                  # List tenants
GET    /api/tenants/:id              # Get tenant details
PUT    /api/tenants/:id              # Update tenant
DELETE /api/tenants/:id              # Delete tenant
GET    /api/tenants/:id/policies     # List tenant policies
GET    /api/tenants/:id/audit        # Tenant audit log
GET    /api/tenants/:id/metrics      # Tenant metrics
```

**Quota configuration:**
```toml
[tenants.defaults]
max_policies = 1000
max_evaluations_per_minute = 10000
max_approvals_pending = 100
max_audit_retention_days = 90

[tenants.overrides."tenant-123"]
max_policies = 5000
max_evaluations_per_minute = 50000
```

### 3.3 Tenant Isolation Testing

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Cross-tenant policy isolation tests | HIGH | 1 day | Multi-tenancy |
| Cross-tenant audit isolation tests | HIGH | 1 day | Multi-tenancy |
| Tenant quota enforcement tests | MEDIUM | 1 day | Quotas |
| Tenant deletion cascade tests | MEDIUM | 0.5 days | Tenant API |

### Phase 3 Deliverables
- [ ] Multi-tenant data isolation
- [ ] Tenant management API
- [ ] Tenant quotas and rate limiting
- [ ] 100% tenant isolation test coverage

**Estimated Duration:** 3 weeks
**Team Size:** 2 engineers

---

## Phase 4: Observability & Integration (Weeks 9-12)

*Focus: Enterprise logging, tracing, and cloud integrations*

### 4.1 OpenTelemetry Integration

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add opentelemetry dependencies | HIGH | 0.5 days | — |
| Instrument policy evaluation with spans | HIGH | 1 day | OTEL deps |
| Instrument HTTP handlers with spans | HIGH | 1 day | OTEL deps |
| Add W3C Trace Context propagation | HIGH | 1 day | Spans |
| Configure OTLP exporter | HIGH | 1 day | Spans |
| Add trace sampling configuration | MEDIUM | 0.5 days | Exporter |

**Span hierarchy:**
```
sentinel.http_request
├── sentinel.auth_validation
├── sentinel.policy_evaluation
│   ├── sentinel.path_matching
│   ├── sentinel.network_matching
│   └── sentinel.context_evaluation
├── sentinel.dlp_scanning
├── sentinel.audit_logging
└── sentinel.upstream_proxy (if proxying)
```

**Configuration:**
```toml
[telemetry]
enabled = true
service_name = "sentinel"
exporter = "otlp"  # otlp | jaeger | zipkin | stdout

[telemetry.otlp]
endpoint = "http://otel-collector:4317"
protocol = "grpc"  # grpc | http

[telemetry.sampling]
strategy = "parent_based"  # always_on | always_off | parent_based | ratio
ratio = 0.1  # Sample 10% of traces (if ratio strategy)
```

### 4.2 SIEM Integrations

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define `SiemExporter` trait | HIGH | 0.5 days | — |
| Implement Splunk HEC exporter | HIGH | 2 days | Trait |
| Implement Datadog exporter | HIGH | 2 days | Trait |
| Implement Elasticsearch exporter | MEDIUM | 2 days | Trait |
| Implement generic webhook exporter | MEDIUM | 1 day | Trait |
| Add async batching and retry logic | HIGH | 2 days | Exporters |
| Implement syslog (RFC 5424) exporter | MEDIUM | 1 day | Trait |

**Trait design:**
```rust
#[async_trait]
pub trait SiemExporter: Send + Sync {
    fn name(&self) -> &str;
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError>;
    async fn health_check(&self) -> Result<(), ExportError>;
}

pub struct ExporterConfig {
    pub batch_size: usize,        // Default: 100
    pub flush_interval: Duration, // Default: 5s
    pub max_retries: u32,         // Default: 3
    pub retry_backoff: Duration,  // Default: 1s
}
```

**Configuration:**
```toml
[audit.export]
enabled = true
exporters = ["splunk", "datadog"]

[audit.export.splunk]
endpoint = "https://splunk.example.com:8088/services/collector"
token_env = "SPLUNK_HEC_TOKEN"
index = "sentinel"
source = "sentinel-prod"
batch_size = 100
flush_interval = "5s"

[audit.export.datadog]
endpoint = "https://http-intake.logs.datadoghq.com/v1/input"
api_key_env = "DD_API_KEY"
service = "sentinel"
source = "sentinel"
tags = ["env:production", "team:security"]
```

### 4.3 Enhanced Metrics

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add `sentinel_approval_pending_count` gauge | HIGH | 0.5 days | — |
| Add `sentinel_approval_resolution_time_seconds` histogram | HIGH | 0.5 days | — |
| Add `sentinel_dlp_findings_by_type` counter | HIGH | 0.5 days | — |
| Add `sentinel_injection_detections_total` counter | MEDIUM | 0.5 days | — |
| Add `sentinel_policy_compilation_errors_total` counter | MEDIUM | 0.5 days | — |
| Add `sentinel_cluster_backend_latency_seconds` histogram | MEDIUM | 0.5 days | — |
| Add per-tenant metrics (if multi-tenant) | MEDIUM | 1 day | Phase 3 |

### 4.4 Cloud Provider Integrations

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create `sentinel-cloud` crate | HIGH | 0.5 days | — |
| Implement AWS EC2 metadata client | MEDIUM | 1 day | Crate |
| Implement AWS Secrets Manager provider | MEDIUM | 2 days | Crate |
| Implement AWS CloudWatch Logs exporter | MEDIUM | 2 days | Crate |
| Implement GCP Secret Manager provider | MEDIUM | 2 days | Crate |
| Implement GCP Cloud Logging exporter | MEDIUM | 2 days | Crate |
| Implement Azure Key Vault provider | MEDIUM | 2 days | Crate |
| Implement Azure Monitor Logs exporter | MEDIUM | 2 days | Crate |

### Phase 4 Deliverables
- [ ] OpenTelemetry with OTLP export
- [ ] Splunk HEC integration
- [ ] Datadog integration
- [ ] Elasticsearch integration
- [ ] 10 new Prometheus metrics
- [ ] AWS, GCP, Azure integrations

**Estimated Duration:** 4 weeks
**Team Size:** 2 engineers

---

## Phase 5: Advanced Security (Weeks 13-14)

*Focus: Security hardening based on research findings*

### 5.1 Security Enhancements

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add Referer header validation (CSRF defense-in-depth) | MEDIUM | 1 day | — |
| Implement idempotency keys for mutating endpoints | MEDIUM | 2 days | — |
| Add per-endpoint rate limit configuration | MEDIUM | 1 day | — |
| Implement optional response signing (X-Verdict-Signature) | LOW | 1 day | — |
| Add mTLS support for client certificates | LOW | 3 days | — |
| Implement replay protection (nonce/sequence) | LOW | 2 days | — |

### 5.2 Additional Fuzz Targets

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add `fuzz_semantic_similarity.rs` | MEDIUM | 1 day | — |
| Add benchmark for DLP decode pipeline | MEDIUM | 1 day | — |
| Add benchmark for rug-pull detection | MEDIUM | 1 day | — |
| Add benchmark for audit export throughput | LOW | 0.5 days | — |

### 5.3 Error Path Testing

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add filesystem error handling tests | MEDIUM | 1 day | — |
| Add network error handling tests | MEDIUM | 1 day | — |
| Add policy compilation error tests | MEDIUM | 1 day | — |
| Add policy reload race condition tests | MEDIUM | 1 day | — |
| Add approval concurrency stress tests | MEDIUM | 1 day | — |

### Phase 5 Deliverables
- [ ] Defense-in-depth security hardening
- [ ] Complete fuzz target coverage
- [ ] Error path test coverage
- [ ] Concurrency stress tests

**Estimated Duration:** 2 weeks
**Team Size:** 1 engineer

---

## Phase 6: Documentation & Polish (Week 15)

*Focus: Production readiness documentation*

### 6.1 Documentation

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create deployment guide (Docker, K8s, bare metal) | HIGH | 2 days | — |
| Create operations runbook (monitoring, troubleshooting) | HIGH | 2 days | — |
| Create security hardening guide | HIGH | 1 day | — |
| Create integration guides (Vault, AWS, Splunk) | MEDIUM | 2 days | — |
| Update API reference documentation | HIGH | 1 day | — |
| Create migration guide (version upgrades) | MEDIUM | 1 day | — |

### 6.2 Release Preparation

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create CHANGELOG.md | HIGH | 0.5 days | — |
| Version bump to 1.0.0 | HIGH | 0.5 days | — |
| Create GitHub release with binaries | HIGH | 0.5 days | — |
| Publish Helm chart to artifact hub | MEDIUM | 0.5 days | — |
| Create announcement blog post | MEDIUM | 1 day | — |

### Phase 6 Deliverables
- [ ] Complete documentation suite
- [ ] v1.0.0 release
- [ ] Helm chart on Artifact Hub
- [ ] Docker images tagged 1.0.0

**Estimated Duration:** 1 week
**Team Size:** 1 engineer

---

## Timeline Summary

```
Week 1-2:   Phase 1 — Foundation & Quick Wins
Week 3-5:   Phase 2 — Enterprise Authentication
Week 6-8:   Phase 3 — Multi-Tenancy
Week 9-12:  Phase 4 — Observability & Integration
Week 13-14: Phase 5 — Advanced Security
Week 15:    Phase 6 — Documentation & Polish
```

**Total Duration:** 15 weeks (~4 months)
**Team Size:** 1-2 engineers

---

## Resource Estimates

| Phase | Engineering Days | Dependencies |
|-------|------------------|--------------|
| Phase 1 | 15-20 days | None |
| Phase 2 | 20-25 days | Phase 1 |
| Phase 3 | 15-20 days | Phase 2 |
| Phase 4 | 25-30 days | Phase 1 |
| Phase 5 | 10-15 days | Phase 1 |
| Phase 6 | 8-10 days | All phases |
| **Total** | **93-120 days** | — |

---

## Success Metrics

### Phase 1 Exit Criteria
- [ ] `sentinel-mcp` split into 8+ focused modules
- [ ] 10+ property-based tests passing
- [ ] 9 fuzz targets (up from 6)
- [ ] Docker images < 50MB
- [ ] Helm chart deployable to K8s

### Phase 2 Exit Criteria
- [ ] RBAC with 4 roles functional
- [ ] Key rotation working with 7-day grace period
- [ ] Vault integration tested in staging

### Phase 3 Exit Criteria
- [ ] 100 tenants supported with isolation
- [ ] Cross-tenant access blocked (verified by tests)
- [ ] Tenant quota enforcement functional

### Phase 4 Exit Criteria
- [ ] Traces visible in Jaeger/Datadog
- [ ] Audit logs streaming to Splunk
- [ ] 20+ Prometheus metrics exposed

### Phase 5 Exit Criteria
- [ ] All P2 security gaps closed
- [ ] 0 panics in 1M fuzz iterations per target
- [ ] Error path coverage > 80%

### Phase 6 Exit Criteria
- [ ] v1.0.0 released
- [ ] All docs reviewed and published
- [ ] No open P0/P1 issues

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Multi-tenancy complexity | Medium | High | Start with simple JWT-based tenant ID; defer subdomain routing |
| SIEM integration variability | Medium | Medium | Generic webhook as fallback; specific integrations as stretch goals |
| Key rotation backward compat | Low | High | Long grace period (7 days); extensive testing |
| OpenTelemetry overhead | Low | Medium | Configurable sampling; benchmark before/after |

---

## Dependencies & Prerequisites

### External Dependencies
- HashiCorp Vault (optional, for Phase 2)
- Redis (optional, for clustering)
- OTEL Collector (for Phase 4)
- Kubernetes cluster (for Helm chart testing)

### Crate Dependencies to Add
```toml
# Phase 1
proptest = "1.4"

# Phase 2
vault = "0.4"            # HashiCorp Vault client
aws-sdk-secretsmanager = "1.0"

# Phase 4
opentelemetry = "0.22"
opentelemetry-otlp = "0.15"
tracing-opentelemetry = "0.23"
```

---

## Appendix: Research Agent IDs

For follow-up work, these agent sessions can be resumed:

| Agent | ID | Focus |
|-------|-----|-------|
| Security Auditor | a346fbe | Security gaps, OWASP coverage |
| Architecture Reviewer | a4dcf60 | Code structure, dependencies |
| Feature Analyst | a942446 | Enterprise features, integrations |
| Test Coverage Analyst | abe7f3d | Testing gaps, fuzz targets |

---

*This roadmap is a living document. Update as priorities change.*
