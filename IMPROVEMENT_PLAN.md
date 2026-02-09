# Sentinel Improvement Plan

> **Generated:** 2026-02-09
> **Based on:** Multi-agent swarm analysis (security, coverage, quality, deps, architecture)
> **Status:** Draft for review

---

## Executive Summary

A comprehensive swarm analysis identified **17 actionable findings** across 5 categories:
- **4 P1 Security/Observability gaps** requiring immediate attention
- **4 P1 Test coverage gaps** in Phase 8-9 features
- **3 P2 Testing gaps** for error paths
- **6 P3 Quality/Dependency improvements**

The most critical issue is **observability blindness**: DLP findings, behavioral anomalies, and circuit breaker events are detected but never logged or metered, violating the project's "Observable" principle.

---

## Phase 1: Observability Fixes (P1) — Week 1

### 1.1 Add DLP Logging and Metrics

**Problem:** `scan_parameters_for_secrets()` and `scan_response_for_secrets()` return findings but never log or meter them.

**Files:**
- `sentinel-mcp/src/inspection/dlp.rs`
- `sentinel-server/src/metrics.rs`

**Tasks:**
```
[ ] Add tracing::warn!() when DLP findings detected
[ ] Call increment_dlp_findings() from scan functions
[ ] Add DLP scan latency histogram metric
[ ] Add integration test verifying metrics increment
```

**Effort:** 1 day

### 1.2 Add Behavioral Anomaly Metrics

**Problem:** `BehavioralTracker` has zero `tracing::` calls and metrics are defined but never called.

**Files:**
- `sentinel-engine/src/behavioral.rs`
- `sentinel-server/src/metrics.rs`

**Tasks:**
```
[ ] Add tracing::warn!() when anomaly threshold exceeded
[ ] Add tracing::debug!() for cold-start transitions
[ ] Increment sentinel_anomaly_detections_total when anomaly detected
[ ] Add gauge for agents in cold-start state
```

**Effort:** 1 day

### 1.3 Add Circuit Breaker Logging

**Problem:** Circuit breaker state transitions (Closed→Open→HalfOpen) are invisible.

**Files:**
- `sentinel-engine/src/circuit_breaker.rs`
- `sentinel-server/src/metrics.rs`

**Tasks:**
```
[ ] Add tracing::warn!() when circuit opens
[ ] Add tracing::info!() on state transitions
[ ] Add sentinel_circuit_breaker_state_changes_total counter
[ ] Add sentinel_circuit_breaker_open_duration_seconds histogram
```

**Effort:** 0.5 day

### 1.4 Add DLP Configuration

**Problem:** DLP has no config despite being security-critical. All thresholds hardcoded.

**Files:**
- `sentinel-config/src/lib.rs`
- `sentinel-mcp/src/inspection/dlp.rs`

**Tasks:**
```
[ ] Create DlpConfig struct (enabled, block_on_finding, max_depth, time_budget_ms)
[ ] Add to PolicyConfig
[ ] Wire config to scan functions
[ ] Add disabled_patterns and extra_patterns like InjectionConfig
```

**Effort:** 1 day

---

## Phase 2: Security Hardening (P1) — Week 1-2

### 2.1 Call Chain Replay Protection

**Problem:** Call chain entries have timestamp but it's never validated for freshness.

**File:** `sentinel-http-proxy/src/proxy.rs`

**Tasks:**
```
[ ] Add MAX_CALL_CHAIN_AGE constant (e.g., 300 seconds)
[ ] Validate entry.timestamp against current time in verify_call_chain_entry()
[ ] Reject entries older than MAX_CALL_CHAIN_AGE
[ ] Add test for replay attack with stale timestamp
```

**Effort:** 0.5 day

### 2.2 Call Chain Header DoS Protection

**Problem:** `extract_call_chain_from_headers()` has no limits on header size or entry count.

**File:** `sentinel-http-proxy/src/proxy.rs`

**Tasks:**
```
[ ] Add MAX_CALL_CHAIN_HEADER_SIZE (8KB)
[ ] Add MAX_CALL_CHAIN_ENTRIES (20)
[ ] Validate header size before parsing
[ ] Reject chains exceeding entry limit
[ ] Add test for oversized header attack
```

**Effort:** 0.5 day

---

## Phase 3: Test Coverage (P1) — Week 2

### 3.1 ETDI Module Tests

**Problem:** `sentinel-mcp/src/etdi/` has zero tests for attestation, store, version_pin.

**Files:**
- `sentinel-mcp/src/etdi/attestation.rs`
- `sentinel-mcp/src/etdi/store.rs`
- `sentinel-mcp/src/etdi/version_pin.rs`

**Tasks:**
```
[ ] test_attestation_chain_valid_signature_sequence()
[ ] test_attestation_chain_rejects_invalid_signature()
[ ] test_etdi_store_persists_signatures()
[ ] test_etdi_store_rejects_duplicate_signatures()
[ ] test_version_pin_allows_exact_match()
[ ] test_version_pin_rejects_downgrade()
```

**Effort:** 2 days

### 3.2 Memory Security Tests

**Problem:** `memory_security.rs` has only benches, no unit tests.

**File:** `sentinel-mcp/src/memory_security.rs`

**Tasks:**
```
[ ] test_memory_security_detects_direct_injection()
[ ] test_memory_security_detects_indirect_injection()
[ ] test_memory_security_fails_closed_on_invalid_json()
[ ] test_memory_security_rejects_oversized_payload()
```

**Effort:** 1 day

### 3.3 DLP Error Path Tests

**Problem:** No tests for timeout, size limit, malformed Unicode paths.

**File:** `sentinel-mcp/src/inspection/dlp.rs`

**Tasks:**
```
[ ] test_dlp_respects_decode_time_budget()
[ ] test_dlp_rejects_oversized_strings_gracefully()
[ ] test_dlp_handles_invalid_utf8_after_decode()
[ ] test_dlp_max_recursion_depth_prevents_stack_overflow()
```

**Effort:** 1 day

---

## Phase 4: Fuzz Targets (P2) — Week 3

### 4.1 New Fuzz Targets

**Problem:** Missing fuzz coverage for critical parsing functions.

**Directory:** `fuzz/fuzz_targets/`

**Tasks:**
```
[ ] fuzz_dlp_decoding.rs — Multi-layer decode pipeline
[ ] fuzz_policy_compilation.rs — PolicyEngine::compile_policies()
[ ] fuzz_injection_detection.rs — Unicode normalization bypass
[ ] fuzz_output_validation.rs — Schema mutation detection
[ ] fuzz_etdi_signature.rs — Signature verification
```

**Effort:** 2 days

---

## Phase 5: Code Quality (P3) — Week 3-4

### 5.1 Extract JSON-RPC Error Codes

**Problem:** Error codes (-32700, -32001, etc.) scattered across proxy.rs.

**Tasks:**
```
[ ] Create sentinel-types/src/json_rpc.rs with error code constants
[ ] Replace hardcoded values in sentinel-http-proxy/src/proxy.rs
[ ] Replace hardcoded values in sentinel-mcp/src/proxy/bridge.rs
```

**Effort:** 0.5 day

### 5.2 Wire Phase 1-2 Security Managers

**Problem:** 4 TODO comments in main.rs for uninitialized security managers.

**File:** `sentinel-server/src/main.rs` (lines 671-691)

**Tasks:**
```
[ ] Initialize task_state manager from config
[ ] Initialize circuit_breaker from CircuitBreakerConfig
[ ] Initialize ETDI from config.etdi
[ ] Initialize memory_security from config.memory_security
[ ] Initialize NHI from config.nhi
```

**Effort:** 1 day

### 5.3 Add Crate Descriptions

**Problem:** 9/12 crates missing description field in Cargo.toml.

**Tasks:**
```
[ ] sentinel-types: "Core type definitions for Sentinel policy engine"
[ ] sentinel-engine: "Policy evaluation engine with glob, regex, and domain matching"
[ ] sentinel-audit: "Tamper-evident audit logging with hash chains"
[ ] sentinel-mcp: "MCP protocol security: DLP, injection detection, tool registry"
[ ] sentinel-canonical: "Canonical security policy presets"
[ ] sentinel-config: "Configuration parsing for Sentinel policies"
[ ] sentinel-approval: "Human-in-the-loop approval workflow"
[ ] sentinel-proxy: "MCP stdio proxy mode"
[ ] sentinel-integration: "Integration test suite"
```

**Effort:** 0.5 day

---

## Phase 6: Dependency Cleanup (P3) — Week 4

### 6.1 Eliminate Duplicate Dependencies

**Problem:** axum 0.6/0.8 and reqwest 0.12/0.13 duplicates.

**Tasks:**
```
[ ] Evaluate OpenTelemetry 0.24 migration (eliminates axum 0.6)
[ ] Unify reqwest version to 0.12 or 0.13
[ ] Run cargo tree to verify no duplicates remain
```

**Effort:** 1 day (research + migration)

### 6.2 Monitor rustls-pemfile

**Problem:** Unmaintained but functional.

**Tasks:**
```
[ ] Track RUSTSEC-2025-0134 status
[ ] Evaluate rustls-pemfile 3.x or fork when available
```

**Effort:** Ongoing monitoring

---

## Summary

| Phase | Focus | Priority | Effort | Week |
|-------|-------|----------|--------|------|
| 1 | Observability (logging, metrics, config) | P1 | 3.5 days | 1 |
| 2 | Security (replay, DoS protection) | P1 | 1 day | 1-2 |
| 3 | Test Coverage (ETDI, memory, DLP) | P1 | 4 days | 2 |
| 4 | Fuzz Targets | P2 | 2 days | 3 |
| 5 | Code Quality (constants, TODOs, descriptions) | P3 | 2 days | 3-4 |
| 6 | Dependency Cleanup | P3 | 1 day | 4 |

**Total Estimated Effort:** 13.5 days (~3 weeks)

---

## Success Metrics

After implementation:
- [ ] All DLP/injection/anomaly detections appear in logs
- [ ] Prometheus metrics increment for all security events
- [ ] ETDI module has >90% test coverage
- [ ] Memory security has unit tests
- [ ] No P1 security gaps remain
- [ ] No duplicate major dependency versions
- [ ] All crates have description metadata
