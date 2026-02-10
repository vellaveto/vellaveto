# Swarm Findings Implementation Plan

> **Generated:** 2026-02-10
> **Source:** 3-agent adversarial swarm analysis
> **Total Findings:** 31 (4 Security, 15 Gaps, 12 Improvements)

---

## Executive Summary

Three specialized agents analyzed the Sentinel codebase:
- **Security Analyst**: Found 4 vulnerabilities (1 High, 1 Medium, 2 Low)
- **Gap Hunter**: Found 15 gaps (5 P2, 10 P3)
- **Improvement Scout**: Found 12 improvement opportunities

This plan organizes remediation into 4 phases by priority.

---

## Phase 1: Critical Security Fixes (P0)

**Timeline:** Immediate
**Effort:** 1-2 days

### SEC-001: OPA Fail-Open Configuration [HIGH]
**Location:** `sentinel-config/src/lib.rs:3529-3532`, `sentinel-server/src/opa.rs:286-288`

**Problem:** The `fail_open = true` option allows bypassing all OPA policies when OPA is unreachable.

**Tasks:**
- [ ] Add startup warning log when `fail_open = true` is configured
- [ ] Add runtime metrics counter for fail-open decisions
- [ ] Update documentation with security implications
- [ ] Consider deprecating or requiring explicit `I_UNDERSTAND_THE_RISK = true`

```rust
// sentinel-server/src/opa.rs
if config.fail_open {
    tracing::warn!(
        "OPA fail_open=true is configured. Policy decisions will default to ALLOW \
         when OPA is unreachable. This violates fail-closed security principles."
    );
    metrics::counter!("sentinel.opa.fail_open_configured").increment(1);
}
```

### SEC-006: DLP Pattern Compilation Silent Failures [MEDIUM]
**Location:** `sentinel-mcp/src/inspection/dlp.rs:26-41`

**Problem:** Failed DLP patterns are silently skipped, creating detection gaps.

**Tasks:**
- [ ] Add startup validation that fails if any default pattern fails to compile
- [ ] Add metrics for pattern compilation failures
- [ ] Return error from `get_dlp_regexes()` if critical patterns fail

```rust
// sentinel-mcp/src/inspection/dlp.rs
pub fn validate_dlp_patterns() -> Result<(), DlpError> {
    let failures: Vec<_> = DLP_PATTERNS.iter()
        .filter_map(|(name, pattern)| {
            Regex::new(pattern).err().map(|e| (name, e))
        })
        .collect();

    if !failures.is_empty() {
        return Err(DlpError::PatternCompilation(failures));
    }
    Ok(())
}
```

---

## Phase 2: Reliability & Security Hardening (P1)

**Timeline:** Week 1
**Effort:** 3-4 days

### SEC-002: Remove expect() in OPA Cache Size
**Location:** `sentinel-server/src/opa.rs:103`

**Task:**
- [ ] Replace `.expect()` with safe alternative

```rust
// Before
let cache_size = NonZeroUsize::new(1000).expect("1000 is non-zero");

// After
const DEFAULT_CACHE_SIZE: NonZeroUsize =
    NonZeroUsize::new(1000).expect("compile-time constant");
// Or use NonZeroUsize::MIN as fallback
```

### SEC-009: Agent Card Cache Size Limit
**Location:** `sentinel-mcp/src/a2a/agent_card.rs:149-186`

**Task:**
- [ ] Add `MAX_CACHE_ENTRIES` constant (e.g., 10,000)
- [ ] Evict oldest entries when limit reached

```rust
const MAX_CACHE_ENTRIES: usize = 10_000;

impl AgentCardCache {
    fn insert(&self, url: &str, card: AgentCard) {
        // Evict if at capacity
        if self.cache.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = self.find_oldest_entry() {
                self.cache.remove(&oldest);
            }
        }
        self.cache.insert(url.to_string(), CacheEntry::new(card));
    }
}
```

### GAP-002: OPA Client Retry Logic
**Location:** `sentinel-server/src/opa.rs:146-184`

**Task:**
- [ ] Add retry with exponential backoff (follow webhook exporter pattern)
- [ ] Make retries configurable in `OpaConfig`

```rust
pub struct OpaConfig {
    // ... existing fields ...
    pub max_retries: u32,           // default: 3
    pub retry_backoff_ms: u64,      // default: 100
}
```

---

## Phase 3: Test Coverage Expansion (P2)

**Timeline:** Week 2
**Effort:** 4-5 days

### GAP-001: OPA Async Integration Tests
**Location:** `sentinel-server/src/opa.rs`

**Tasks:**
- [ ] Add `#[tokio::test]` tests with wiremock
- [ ] Test timeout handling
- [ ] Test retry logic (after GAP-002)
- [ ] Test cache behavior under concurrent load

### GAP-003: Observability Exporter Async Tests
**Location:** `sentinel-audit/src/observability/`

**Tasks:**
- [ ] Add async tests for `health_check()`
- [ ] Add async tests for `export_batch()`
- [ ] Test rate limiting (429) handling
- [ ] Test retry behavior

### GAP-005: ProxyBridge Security Manager Integration Tests
**Location:** `sentinel-mcp/src/proxy/bridge.rs`

**Tasks:**
- [ ] Add tests for ETDI + proxy integration
- [ ] Add tests for circuit breaker + proxy integration
- [ ] Add tests for full pipeline with all managers enabled

### GAP-015: OPA + Semantic Guardrails Combined Tests
**Location:** New file: `sentinel-integration/tests/combined_evaluation_test.rs`

**Tasks:**
- [ ] Test combined OPA + semantic guardrails evaluation
- [ ] Test precedence when both return verdicts
- [ ] Test failure modes when one subsystem fails

### GAP-007: A2A Proxy Upstream Timeout
**Location:** `sentinel-mcp/src/a2a/proxy.rs`

**Tasks:**
- [ ] Verify HTTP client uses `request_timeout_ms`
- [ ] Add test for upstream timeout behavior

---

## Phase 4: Quick Win Improvements (P2)

**Timeline:** Week 2 (parallel with Phase 3)
**Effort:** 2-3 days

### IMP-002: HashMap/Vec Capacity Hints [ROI: 3.0]
**Location:** Multiple files (30+ occurrences)

**Tasks:**
- [ ] Add capacity hints in hot paths:
  - `sentinel-server/src/routes.rs`
  - `sentinel-audit/src/exec_graph.rs`
  - `sentinel-types/src/lib.rs`

### IMP-003: Deduplicate try_base64_decode [ROI: 2.0]
**Location:** `sentinel-mcp/src/inspection/dlp.rs`, `injection.rs`

**Tasks:**
- [ ] Create `sentinel-mcp/src/inspection/util.rs`
- [ ] Move `try_base64_decode` to shared module
- [ ] Update imports in dlp.rs and injection.rs

### IMP-008: OPA Cache Size Configurable [ROI: 2.0]
**Location:** `sentinel-server/src/opa.rs`

**Tasks:**
- [ ] Add `cache_size` to `OpaConfig`
- [ ] Use config value instead of hardcoded 1000

### IMP-009: EvaluationContext Builder [ROI: 3.0]
**Location:** `sentinel-types/src/lib.rs` or `sentinel-engine/src/lib.rs`

**Tasks:**
- [ ] Add `EvaluationContext::builder()` method
- [ ] Implement builder pattern with sensible defaults

---

## Phase 5: Documentation & Observability (P3)

**Timeline:** Week 3
**Effort:** 2-3 days

### GAP-010: Semantic Guardrails Documentation
**Location:** `sentinel-mcp/src/semantic_guardrails/mod.rs`

**Tasks:**
- [ ] Add doc comments to all public methods
- [ ] Add usage examples
- [ ] Document configuration options

### GAP-011: Circuit Breaker Metrics
**Location:** `sentinel-engine/src/circuit_breaker.rs`

**Tasks:**
- [ ] Add histogram for check latency
- [ ] Add counter for rejection reasons
- [ ] Add gauge for time in each state

### Remaining P3 Gaps
- [ ] GAP-004: Semantic guardrails backend mocked tests
- [ ] GAP-006: Multimodal scanner edge case tests
- [ ] GAP-008: Health check degraded state tests
- [ ] GAP-009: Schema versioning concurrent tests
- [ ] GAP-012: BehavioralTracker persistence integration test
- [ ] GAP-013: Agent card cache TTL expiration test
- [ ] GAP-014: Webhook compression round-trip test

---

## Phase 6: Architecture Improvements (P3)

**Timeline:** Future sprints
**Effort:** 1-2 weeks

### IMP-001: Split sentinel-engine/src/lib.rs (14,118 lines)

**Proposed structure:**
```
sentinel-engine/src/
├── lib.rs              (re-exports, ~100 lines)
├── engine.rs           (PolicyEngine core)
├── constraint/
│   ├── mod.rs
│   ├── compiled.rs     (CompiledConstraint types)
│   └── evaluate.rs     (constraint evaluation)
├── path.rs             (path normalization, glob)
├── network.rs          (domain/IP rules, CIDR)
├── context.rs          (TimeWindow, MaxCalls, etc.)
└── legacy.rs           (deprecated evaluation paths)
```

### IMP-006: Split sentinel-server/src/routes.rs (5,437 lines)

**Proposed structure:**
```
sentinel-server/src/routes/
├── mod.rs              (router building)
├── auth.rs             (API key, rate limiting)
├── policies.rs         (policy CRUD)
├── audit.rs            (audit log endpoints)
├── approvals.rs        (approval workflow)
├── admin.rs            (security manager APIs)
├── etdi.rs             (ETDI endpoints)
└── nhi.rs              (NHI endpoints)
```

---

## Tracking

### By Priority

| Phase | Priority | Items | Status |
|-------|----------|-------|--------|
| 1 | P0 (Critical) | 2 | ⬜ Not Started |
| 2 | P1 (High) | 4 | ⬜ Not Started |
| 3 | P2 (Medium) | 5 | ⬜ Not Started |
| 4 | P2 (Quick Wins) | 4 | ⬜ Not Started |
| 5 | P3 (Low) | 10 | ⬜ Not Started |
| 6 | P3 (Architecture) | 2 | ⬜ Not Started |

### By Category

| Category | Count | Critical |
|----------|-------|----------|
| Security | 4 | SEC-001 (High) |
| Reliability | 2 | GAP-002 |
| Test Coverage | 12 | - |
| Improvements | 12 | - |
| Documentation | 1 | - |

---

## Definition of Done

For each finding:
- [ ] Code changes implemented
- [ ] Tests added/updated
- [ ] Documentation updated (if applicable)
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` clean
- [ ] PR reviewed and merged

---

## References

- Security Analysis: `/tmp/claude/-home-paolo--vella-workspace-sentinel/tasks/a2bd9c0.output`
- Gap Analysis: `/tmp/claude/-home-paolo--vella-workspace-sentinel/tasks/a2ceef1.output`
- Improvement Analysis: `/tmp/claude/-home-paolo--vella-workspace-sentinel/tasks/acc7c42.output`
