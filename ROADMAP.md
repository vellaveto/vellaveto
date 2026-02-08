# Sentinel Roadmap v2.0

> **Version:** 2.0.0 (Planning)
> **Generated:** 2026-02-08
> **Status:** Research complete, implementation pending
> **Based on:** Multi-agent research (MCP spec, OWASP, enterprise features, competitor analysis)

---

## Executive Summary

Sentinel v1.0.0 is production-ready with 33 audit rounds and 3,167 tests. This roadmap defines v2.0 priorities based on:

1. **MCP 2025-11-25 Protocol Compliance** — Async Tasks, Resource Indicators, CIMD
2. **Advanced Threat Detection** — Shadow agents, full schema poisoning, cascading failures
3. **Standards Alignment** — MITRE ATLAS, OWASP ASI Top 10, NIST AI Profile
4. **Enterprise Hardening** — mTLS/SPIFFE, OPA integration, threat intelligence

**Research Sources:**
- MCP Specification 2025-11-25 updates
- OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)
- CoSAI MCP Security Whitepaper (12 threat categories, ~40 threats)
- MITRE ATLAS agentic AI techniques (14 new entries)
- Competitor analysis (Zenity, Lasso, Operant AI, NeMo Guardrails)

---

## Priority Matrix

| Priority | Theme | Business Value |
|----------|-------|----------------|
| **P0** | MCP 2025-11-25 Compliance | Protocol compatibility |
| **P1** | Advanced Threat Detection | Close security gaps |
| **P2** | Standards & Compliance | Enterprise adoption |
| **P3** | Enterprise Features | Feature parity |
| **P4** | Observability & Tooling | Operational excellence |

---

## Phase 1: MCP 2025-11-25 Compliance (Weeks 1-4) ✅ COMPLETE

*Focus: Protocol updates for Async Tasks, Resource Indicators, CIMD*

> **Status:** Implemented in commit `fad480c`. All deliverables complete.

### 1.1 Async Tasks Security

The MCP 2025-11-25 spec introduces async task execution. This creates new attack vectors:
- Task state manipulation during long-running operations
- Unauthorized task cancellation/resumption
- Task result tampering

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define `AsyncTaskPolicy` type | P0 | 1 day | — |
| Implement task state validation middleware | P0 | 3 days | Policy type |
| Add task lifecycle audit events | P0 | 1 day | Middleware |
| Implement task cancellation authorization | P0 | 2 days | Middleware |
| Add task timeout enforcement | P0 | 1 day | — |
| Create async task fuzz target | P0 | 1 day | All above |

**New policy configuration:**
```toml
[policies.async_tasks]
enabled = true
max_task_duration = "1h"
max_concurrent_tasks = 100
allow_cancellation = ["admin", "operator"]
require_completion_signature = true
```

### 1.2 OAuth Resource Indicators (RFC 8707)

MCP 2025-11-25 requires resource indicator support for OAuth flows.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse resource indicators from OAuth requests | P0 | 1 day | — |
| Validate resource scope against policy | P0 | 2 days | Parsing |
| Add resource indicator to audit context | P0 | 0.5 days | Validation |
| Support multiple resource servers | P1 | 2 days | — |
| Add resource indicator integration tests | P0 | 1 day | All above |

### 1.3 CIMD (Capability-Indexed Message Dispatch)

New MCP routing mechanism requiring policy enforcement.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Parse CIMD capability headers | P0 | 1 day | — |
| Define capability-based routing policies | P0 | 2 days | Parsing |
| Implement capability inheritance validation | P1 | 2 days | Policies |
| Add capability attestation verification | P1 | 2 days | — |

### 1.4 Step-Up Authentication

MCP 2025-11-25 defines step-up auth for sensitive operations.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define step-up auth policy triggers | P1 | 1 day | — |
| Implement auth level tracking per session | P1 | 2 days | Triggers |
| Add step-up challenge/response flow | P1 | 3 days | Tracking |
| Integrate with human-in-the-loop approvals | P1 | 2 days | Challenge flow |

### Phase 1 Deliverables
- [x] Async task policy enforcement
- [x] OAuth resource indicator validation
- [x] CIMD capability-based routing
- [x] Step-up authentication flow

**Estimated Duration:** 4 weeks
**Completed:** 2026-02-07

---

## Phase 2: Advanced Threat Detection (Weeks 5-8) ✅ COMPLETE

*Focus: Close gaps identified in CoSAI whitepaper and OWASP ASI Top 10*

> **Status:** Implemented in commit `e4deb2d`. All deliverables complete.

### 2.1 Shadow Agent Discovery (ASI02)

Detect unauthorized/rogue agents operating in the environment.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement agent fingerprinting | P1 | 2 days | — |
| Create agent registry with known-good baseline | P1 | 2 days | Fingerprinting |
| Add anomaly detection for unknown agents | P1 | 3 days | Registry |
| Implement agent behavior profiling | P1 | 3 days | — |
| Alert on shadow agent detection | P1 | 1 day | All above |

**Detection signals:**
- Unknown JWT issuers
- Unusual tool call patterns
- Unregistered client certificates
- Anomalous request origins

### 2.2 Full Schema Poisoning Detection

Extend rug-pull detection for complete schema replacement attacks.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Detect wholesale schema replacement | P1 | 2 days | — |
| Track schema lineage across versions | P1 | 2 days | Detection |
| Add schema signing/verification (optional) | P2 | 3 days | Lineage |
| Implement gradual schema change thresholds | P1 | 2 days | — |
| Add schema poisoning adversarial tests | P1 | 1 day | All above |

**Thresholds:**
```toml
[detection.schema_poisoning]
max_field_additions_per_update = 5
max_field_removals_per_update = 2
max_type_changes_per_update = 1
require_announcement_period = "24h"
```

### 2.3 Cascading Failure Protection (OWASP ASI08)

Prevent chain reactions when one agent fails.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement circuit breaker per upstream tool | P1 | 2 days | — |
| Add failure budget tracking | P1 | 2 days | Circuit breaker |
| Implement graceful degradation policies | P1 | 2 days | — |
| Add cascade detection alerts | P1 | 1 day | — |
| Create chaos testing framework | P2 | 3 days | All above |

**Circuit breaker configuration:**
```toml
[resilience.circuit_breaker]
failure_threshold = 5       # failures before opening
recovery_timeout = "30s"    # wait before half-open
success_threshold = 3       # successes to close
```

### 2.4 Sampling-Based Attack Detection

New attack vector from MCP sampling endpoint.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add sampling request rate limiting | P1 | 1 day | — |
| Detect sampling exfiltration patterns | P1 | 2 days | — |
| Validate sampling context constraints | P1 | 2 days | — |
| Add sampling to DLP inspection pipeline | P1 | 2 days | — |

### 2.5 Confused Deputy Prevention (ASI05)

Strengthen agent identity and authorization checks.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Implement strict principal binding | P1 | 2 days | — |
| Add request origin chain validation | P1 | 2 days | Binding |
| Enforce capability-based delegation | P1 | 3 days | — |
| Add confused deputy test suite | P1 | 2 days | All above |

### Phase 2 Deliverables
- [x] Shadow agent detection and alerting
- [x] Full schema poisoning detection
- [x] Circuit breaker with cascade protection
- [x] Sampling attack detection
- [x] Confused deputy prevention

**Estimated Duration:** 4 weeks
**Completed:** 2026-02-07

---

## Phase 3.1: Runtime Integration (Week 9) ✅ COMPLETE

*Focus: Wire Phase 1 & 2 security modules into runtime enforcement*

> **Status:** Implemented in commits `05364be` and `7a3c52d`. All deliverables complete.

### 3.1.1 Completed Tasks
- [x] ProxyBridge manager integration (circuit breaker, shadow agent, deputy, schema lineage, auth level, sampling detector)
- [x] Enforcement calls at request evaluation points
- [x] AppState manager fields for sentinel-server
- [x] Admin API endpoints (25+ routes for security manager management)
- [x] Audit event generation helpers (7 event types with comprehensive tests)
- [x] HTTP proxy integration with circuit breaker check

### 3.1.2 Files Modified
- `sentinel-mcp/src/proxy/bridge.rs` — Manager fields and enforcement
- `sentinel-server/src/lib.rs` — AppState integration
- `sentinel-server/src/routes.rs` — Admin API endpoints
- `sentinel-audit/src/lib.rs` — Security event helpers
- `sentinel-http-proxy/src/proxy.rs` — HTTP proxy integration

**Completed:** 2026-02-08

---

## Phase 3.2: Standards Alignment (Weeks 10-12)

*Focus: MITRE ATLAS, OWASP AIVSS, NIST alignment*

### 3.1 MITRE ATLAS Threat Mapping

Map Sentinel detections to MITRE ATLAS techniques.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create ATLAS technique registry | P2 | 1 day | — |
| Map existing detections to ATLAS IDs | P2 | 2 days | Registry |
| Add ATLAS technique ID to audit events | P2 | 1 day | Mapping |
| Generate ATLAS coverage report | P2 | 2 days | All above |
| Document unmapped techniques as gaps | P2 | 1 day | Coverage |

**ATLAS techniques to map:**
- AML.T0060: Agent Manipulation
- AML.T0061: Tool Poisoning
- AML.T0062: Memory Injection
- AML.T0063: Privilege Escalation (Agent)
- AML.T0064: Data Exfiltration (Agent)
- (14 new agentic AI techniques total)

### 3.2 OWASP AIVSS Integration

Prepare for AI Vulnerability Scoring System (expected RSA 2026).

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design severity scoring framework | P2 | 2 days | — |
| Implement AIVSS score calculation | P2 | 3 days | Framework |
| Add severity to finding reports | P2 | 1 day | Calculation |
| Create AIVSS-formatted exports | P2 | 2 days | — |

### 3.3 NIST AI RMF Alignment

Align with NIST AI Risk Management Framework.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Document NIST MAP function coverage | P2 | 2 days | — |
| Document NIST MEASURE function coverage | P2 | 2 days | — |
| Document NIST MANAGE function coverage | P2 | 2 days | — |
| Create NIST compliance report generator | P2 | 3 days | All above |

### 3.4 ISO/IEC 27090 Preparation

Prepare for AI security standard (expected mid-2026).

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Review draft 27090 requirements | P3 | 1 day | — |
| Gap analysis against current implementation | P3 | 2 days | Review |
| Document compliance mapping | P3 | 2 days | Gap analysis |

### Phase 3 Deliverables
- [ ] MITRE ATLAS threat mapping
- [ ] AIVSS severity scoring
- [ ] NIST AI RMF compliance documentation
- [ ] ISO 27090 readiness assessment

**Estimated Duration:** 4 weeks
**Risk:** Standards not finalized; may require updates post-release

---

## Phase 4: Enterprise Hardening (Weeks 13-16)

*Focus: mTLS, OPA, threat intelligence, JIT access*

### 4.1 mTLS / SPIFFE-SPIRE Integration

Zero-trust workload identity.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Add mTLS configuration options | P2 | 2 days | — |
| Implement SPIFFE ID extraction from X.509 | P2 | 2 days | mTLS |
| Add SPIFFE-based policy matching | P2 | 3 days | ID extraction |
| Integrate with SPIRE for workload attestation | P3 | 3 days | — |
| Add mTLS revocation checking | P2 | 2 days | — |

**Configuration:**
```toml
[tls]
mode = "mtls"  # none | tls | mtls
client_ca = "/etc/sentinel/client-ca.pem"
require_client_cert = true

[identity.spiffe]
enabled = true
trust_domain = "example.org"
workload_socket = "unix:///var/run/spire/agent.sock"
```

### 4.2 OPA / Rego Policy Integration

External policy evaluation for complex rules.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design OPA integration architecture | P2 | 1 day | — |
| Implement OPA client with caching | P2 | 3 days | Architecture |
| Add OPA policy reference in Sentinel policies | P2 | 2 days | Client |
| Support Rego policy bundles | P3 | 2 days | — |
| Add OPA decision audit logging | P2 | 1 day | Client |

**Usage:**
```toml
[policies.external]
provider = "opa"

[policies.external.opa]
endpoint = "http://opa:8181/v1/data/sentinel/allow"
cache_ttl = "60s"
timeout = "100ms"
```

### 4.3 Threat Intelligence Integration

Enrich decisions with external threat feeds.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define threat intelligence provider trait | P2 | 1 day | — |
| Implement STIX/TAXII consumer | P3 | 3 days | Trait |
| Implement MISP integration | P3 | 3 days | Trait |
| Add IOC matching to network rules | P2 | 2 days | Provider |
| Cache threat data with TTL | P2 | 1 day | — |

### 4.4 Just-In-Time Access

Temporary elevated permissions with auto-expiry.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Design JIT access model | P2 | 1 day | — |
| Implement JIT token issuance | P2 | 3 days | Model |
| Add JIT access to human-in-the-loop flow | P2 | 2 days | Token issuance |
| Implement automatic access revocation | P2 | 2 days | — |
| Add JIT access audit trail | P2 | 1 day | All above |

### 4.5 FIPS 140-2 Compliance Mode

For regulated environments.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Evaluate FIPS-compliant Rust crypto libraries | P3 | 2 days | — |
| Add FIPS mode configuration flag | P3 | 1 day | Evaluation |
| Replace crypto primitives in FIPS mode | P3 | 5 days | Flag |
| Document FIPS compliance scope | P3 | 1 day | All above |

### Phase 4 Deliverables
- [ ] mTLS with SPIFFE-SPIRE support
- [ ] OPA/Rego policy integration
- [ ] Threat intelligence feeds
- [ ] JIT access with auto-expiry
- [ ] FIPS 140-2 compliance mode (optional)

**Estimated Duration:** 4 weeks
**Risk:** FIPS compliance adds complexity; consider separate build

---

## Phase 5: Observability & Tooling (Weeks 17-18)

*Focus: Execution graphs, CI/CD integration, red-teaming*

### 5.1 Execution Graph Visualization

Visual representation of agent call chains.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Define execution graph data model | P3 | 1 day | — |
| Capture parent-child relationships in audit | P3 | 2 days | Model |
| Add graph export endpoint (DOT/JSON) | P3 | 2 days | Capture |
| Create web-based graph viewer | P4 | 3 days | Export |

### 5.2 CI/CD Pipeline Integration

Security scanning for development workflows.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create policy validation CLI command | P3 | 1 day | — |
| Add schema validation CLI command | P3 | 1 day | — |
| Create GitHub Action for policy checks | P3 | 2 days | CLI |
| Add GitLab CI template | P3 | 1 day | CLI |
| Document CI/CD integration guide | P3 | 1 day | All above |

### 5.3 Automated Red-Teaming

Self-testing against known attack patterns.

| Task | Priority | Effort | Depends On |
|------|----------|--------|------------|
| Create attack simulation framework | P3 | 3 days | — |
| Implement MCPTox benchmark attacks | P3 | 3 days | Framework |
| Add scheduled red-team runs | P4 | 2 days | — |
| Generate red-team reports | P3 | 2 days | Runs |

### Phase 5 Deliverables
- [ ] Execution graph visualization
- [ ] CI/CD integration (GitHub Actions, GitLab)
- [ ] Red-team automation framework
- [ ] MCPTox benchmark coverage

**Estimated Duration:** 2 weeks

---

## Phase 6: Documentation & Release (Week 19-20)

### 6.1 Documentation Updates

| Task | Priority | Effort |
|------|----------|--------|
| Update deployment guide with new features | HIGH | 2 days |
| Create threat model documentation | HIGH | 2 days |
| Document MITRE ATLAS coverage | MEDIUM | 1 day |
| Create migration guide (v1 → v2) | HIGH | 2 days |
| Update API reference | HIGH | 1 day |

### 6.2 Release Preparation

| Task | Priority | Effort |
|------|----------|--------|
| Version bump to 2.0.0 | HIGH | 0.5 days |
| Update CHANGELOG.md | HIGH | 1 day |
| Create GitHub release | HIGH | 0.5 days |
| Publish updated Helm chart | HIGH | 0.5 days |

---

## Timeline Summary

```
Weeks 1-4:   Phase 1 — MCP 2025-11-25 Compliance
Weeks 5-8:   Phase 2 — Advanced Threat Detection
Weeks 9-12:  Phase 3 — Standards Alignment
Weeks 13-16: Phase 4 — Enterprise Hardening
Weeks 17-18: Phase 5 — Observability & Tooling
Weeks 19-20: Phase 6 — Documentation & Release
```

**Total Duration:** 20 weeks (~5 months)
**Team Size:** 2-3 engineers

---

## Success Metrics

### Phase 1 Exit Criteria
- [ ] MCP 2025-11-25 protocol compliance verified
- [ ] Async task policy enforcement functional
- [ ] OAuth resource indicator validation passing

### Phase 2 Exit Criteria
- [ ] Shadow agent detection with <1% false positive rate
- [ ] Schema poisoning blocks 100% of MCPTox test cases
- [ ] Circuit breaker prevents cascade in chaos tests

### Phase 3 Exit Criteria
- [ ] 80%+ MITRE ATLAS technique coverage
- [ ] AIVSS scores generated for all findings
- [ ] NIST AI RMF documentation complete

### Phase 4 Exit Criteria
- [ ] mTLS/SPIFFE working in Kubernetes
- [ ] OPA integration tested with complex policies
- [ ] JIT access functional with audit trail

### Phase 5 Exit Criteria
- [ ] Execution graphs visible in dashboard
- [ ] GitHub Action published and documented
- [ ] MCPTox benchmark 95%+ detection rate

---

## Research Agent References

The following research agents provided input for this roadmap:

| Agent | Focus Area | Key Findings |
|-------|------------|--------------|
| MCP Security | Protocol updates | MCP 2025-11-25 (Async Tasks, CIMD, Resource Indicators) |
| AI Threats | Attack vectors | MCPTox benchmark, tool poisoning 72% success rate |
| Enterprise | Gateway features | mTLS, OPA, SPIFFE-SPIRE integration patterns |
| OWASP | Standards | AIVSS, NIST AI RMF, ISO 27090 timeline |
| Competitor | Market analysis | Shadow agent discovery, execution graphs as gaps |

---

## Appendix: OWASP ASI Top 10 Coverage

| ID | Threat | Sentinel Coverage |
|----|--------|-------------------|
| ASI01 | Prompt Injection | ✅ Injection detection (v1.0) |
| ASI02 | Sensitive Data Disclosure | ✅ DLP scanning (v1.0), Deputy validation (Phase 2) |
| ASI03 | Inadequate Sandboxing | ⚠️ Path/network rules (partial) |
| ASI04 | Privilege Escalation | ✅ RBAC, approval flow (v1.0) |
| ASI05 | Confused Deputy | ✅ Deputy validation with delegation chains (Phase 2) |
| ASI06 | Excessive Agency | ✅ Policy engine (v1.0) |
| ASI07 | Insecure Plugins | ✅ Rug-pull detection (v1.0), Schema poisoning (Phase 2) |
| ASI08 | Cascading Failures | ✅ Circuit breaker with failure budget (Phase 2) |
| ASI09 | Over-reliance on Agent | ⚠️ Human-in-the-loop (partial) |
| ASI10 | Inadequate Monitoring | ✅ Audit logging (v1.0), Security event helpers (Phase 3.1) |

---

## Appendix: Known CVEs Addressed

| CVE | Description | Sentinel Mitigation |
|-----|-------------|---------------------|
| CVE-2025-68143 | Git MCP Server path traversal | Path normalization (v1.0) |
| CVE-2025-68144 | Git MCP Server arbitrary read | Path rules, DLP (v1.0) |
| CVE-2025-68145 | Git MCP Server secret exposure | DLP scanning (v1.0) |
| CVE-2025-6514 | mcp-remote SSRF | DNS rebinding protection (v1.0) |

---

*This roadmap is a living document. Update as standards finalize and priorities shift.*
