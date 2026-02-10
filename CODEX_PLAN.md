# Codex Implementation Plan — Sentinel Post-Phase 15

> **Generated:** 2026-02-10
> **State:** Phase 15 (Observability) complete, 3,725+ tests passing
> **Target:** Address security gaps, test coverage, and improvements identified by swarm analysis
> **Swarm Analysis:** 3 agents completed (Security, Gap-Hunter, Improvement-Scout)

---

## Active Work Assignment

| Agent | Tasks | Status |
|-------|-------|--------|
| **Claude (Main)** | Tasks 2, 3, 4, 5 (P1 low-effort tests) | IN PROGRESS |
| **Codex** | Task 1, Tasks 6-8 (P1 medium-effort) | ASSIGNED |

**Claude working on:** Redaction boundary tests, TraceContext W3C tests, SpanSampler determinism, Rate limit edge cases
**Codex should work on:** Async integration tests for exporters, then Phase 15.6 security hardening

---

## Mission for Codex

Execute the prioritized tasks below autonomously. Follow the project rules in CLAUDE.md strictly:
- Run pre-session checks before starting
- Never use `unwrap()` in library code
- Fail-closed on all errors
- Commit frequently with proper format

---

## Phase 15.5: Observability Hardening (Priority: P1)

### Task 1: Async Integration Tests for Exporters
**Effort:** Medium | **Impact:** High | **Source:** GAP-001

Create `#[tokio::test]` async integration tests for ObservabilityExporter implementations:

```rust
// sentinel-integration/tests/observability_async_test.rs
```

Tests needed:
- [ ] Mock HTTP endpoints using mockito for each exporter
- [ ] Test `export_batch()` with various span counts (1, 10, 100)
- [ ] Test `health_check()` failures and error propagation
- [ ] Test retry behavior with rate limiting (429 responses)
- [ ] Test concurrent batch chunk processing
- [ ] Test timeout scenarios for slow endpoints

### Task 2: Redaction Boundary Testing
**Effort:** Low | **Impact:** High | **Source:** GAP-002

```rust
// sentinel-audit/src/observability/mod.rs - add tests
```

Tests for `RedactionConfig.redact_recursive()`:
- [ ] Exactly 50-depth nested JSON (should work)
- [ ] 51-depth nested JSON (should not recurse further)
- [ ] Very large arrays with nested objects
- [ ] Mixed array/object nesting patterns

### Task 3: TraceContext W3C Compliance
**Effort:** Low | **Impact:** Medium | **Source:** GAP-005

```rust
// sentinel-audit/src/observability/mod.rs - add tests
```

Tests for `TraceContext.parse_traceparent()`:
- [ ] Uppercase hex strings (00-AABBCC...)
- [ ] Mixed case hex strings
- [ ] All-zeros trace ID (00000000000000000000000000000000)
- [ ] All-zeros span ID (0000000000000000)
- [ ] Leading zeros preservation

### Task 4: SpanSampler Determinism Tests
**Effort:** Low | **Impact:** High | **Source:** GAP-011

```rust
// sentinel-audit/src/observability/mod.rs - add tests
```

Tests for sampling determinism:
- [ ] Same trace_id always gives same sampling decision (10 runs)
- [ ] Distribution uniformity: sample 1000 traces at 50%, verify ~500 sampled (±10%)
- [ ] Edge case trace IDs: empty string, very long, special chars
- [ ] sample_rate=0.0 never samples, sample_rate=1.0 always samples

### Task 5: Rate Limit Header Edge Cases
**Effort:** Low | **Impact:** Medium | **Source:** GAP-008

Add tests across all exporters for retry-after header handling:
- [ ] Non-numeric retry-after values → default to 60s
- [ ] Negative retry-after → default to 60s
- [ ] Extremely large retry-after (86400+) → cap or handle
- [ ] Missing header → default to 60s

---

## Phase 15.6: Security Hardening (Priority: P1)

### Task 6: Add Logging for Redaction/Sampling Decisions
**Effort:** Low | **Impact:** Medium | **Source:** GAP-004, GAP-012, GAP-013

Add debug/trace logging:

```rust
// sentinel-audit/src/observability/mod.rs
```

- [ ] `RedactionConfig.redact_recursive()`: log fields redacted and depth
- [ ] `SpanSampler.should_sample()`: log hash value, threshold, decision rationale
- [ ] Enable users to understand sampling determinism via debug logging

### Task 7: Response Body Error Handling
**Effort:** Low | **Impact:** Medium | **Source:** GAP-003

Test and harden `unwrap_or_default()` on response.text().await:
- [ ] Test with non-UTF8 response bodies
- [ ] Test with HTML error pages instead of JSON
- [ ] Test with truncated/incomplete responses
- [ ] Verify error logging doesn't panic on malformed responses

### Task 8: Enhanced Config Validation
**Effort:** Medium | **Impact:** Medium | **Source:** GAP-006

```rust
// sentinel-config/src/observability.rs
```

Enhance validation:
- [ ] Verify batch_size > 0 for each exporter
- [ ] Verify timeout_secs > 0
- [ ] Check for nonsensical combinations (sample_rate=0 with always_sample_denies=false)
- [ ] Document and validate flush_interval_secs > 0
- [ ] Add test for zero-valued configs

---

## Phase 16: Test Coverage (Priority: P2)

### Task 9: ArizeExporter Edge Cases
**Effort:** Medium | **Impact:** Medium | **Source:** GAP-007, GAP-012

```rust
// sentinel-audit/src/observability/arize.rs
```

Tests needed:
- [ ] Invalid ISO8601 timestamps → should produce 0 nanos
- [ ] Boundary timestamps (epoch, year 2038, year 9999)
- [ ] Invalid hex strings in trace/span IDs → should hash to bytes
- [ ] Very long trace IDs
- [ ] All SecuritySpan fields mapped to OTLP output
- [ ] Large attributes HashMap (100+ entries)
- [ ] Empty target_paths/domains handling

### Task 10: LangfuseExporter Edge Cases
**Effort:** Low | **Impact:** Medium | **Source:** GAP-014

```rust
// sentinel-audit/src/observability/langfuse.rs
```

Tests needed:
- [ ] Span with both parent_span_id AND span_kind == Chain (which precedence?)
- [ ] Span with zero detections but high severity
- [ ] Verify event count is exactly 1 or 2, no stray events

### Task 11: Private IP Validation Coverage
**Effort:** Medium | **Impact:** High | **Source:** GAP-009

```rust
// sentinel-config/src/observability.rs
```

Comprehensive tests for private IP rejection:
- [ ] All reserved IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 0.0.0.0/8)
- [ ] IPv6 loopback (::1)
- [ ] IPv6 unspecified (::)
- [ ] IPv6 ULA (fc00::/7)
- [ ] IPv6 link-local edge cases (fe80::, feff::)

### Task 12: SecuritySpanBuilder Tests
**Effort:** Low | **Impact:** Low | **Source:** GAP-016, GAP-018

```rust
// sentinel-audit/src/observability/mod.rs
```

Tests for builder defaults:
- [ ] Consecutive builds produce different span IDs
- [ ] Timestamps are recent (within last second)
- [ ] Duration defaults to 0 if not set
- [ ] new_span_id() generates 16-char valid hex (test 1000 for uniqueness)

### Task 13: has_enabled_exporters Combinations
**Effort:** Low | **Impact:** Low | **Source:** GAP-020

```rust
// sentinel-config/src/observability.rs
```

Test all combinations:
- [ ] master=true, all exporters=false → returns false
- [ ] master=false, exporter=true → returns false
- [ ] master=true, one exporter=true → returns true
- [ ] All combinations without false positives/negatives

---

## Phase 17: Documentation (Priority: P2)

### Task 14: RedactionConfig Documentation
**Effort:** Low | **Impact:** Medium | **Source:** GAP-010, GAP-015

Add doc comments to `sentinel-audit/src/observability/mod.rs`:
- [ ] Explain substring matching behavior with examples
- [ ] Document that enabled=false overrides all field configs
- [ ] Explain why redaction_text is configurable (compliance)
- [ ] Document performance implications of deep recursion
- [ ] Document SpanSampler hash determinism, distribution, implementation

### Task 15: Helper Function Documentation
**Effort:** Low | **Impact:** Low | **Source:** GAP-019

```rust
// sentinel-audit/src/observability/arize.rs
```

Add doc comments:
- [ ] `parse_iso8601_to_nanos`: explain it returns 0 on parse failure
- [ ] `hex_to_bytes`: explain it hashes invalid hex to consistent bytes

---

## Phase 18: Performance Improvements (Priority: P2)

### Task 16: Add GlobMatcher Caching in PolicyEngine
**Effort:** Medium | **Impact:** High | **Source:** IMP-003, ROI: 7.5

```rust
// sentinel-engine/src/lib.rs
```

Currently GlobMatcher compilation happens on every evaluate_action call:
- Add `Arc<DashMap<String, GlobMatcher>>` in PolicyEngine
- Populate during `policy_from_config`
- Cache key: pattern string
- Expected: ~99% hit rate, 5-15% faster evaluation latency

### Task 17: HashMap Capacity Hints
**Effort:** Low | **Impact:** Medium | **Source:** IMP-004, ROI: 7.0

103 HashMap::new() calls without capacity hints in sentinel-mcp:
- Add `.with_capacity()` hints based on typical usage
- Focus on hot paths: DLP/injection scanning
- Expected: ~2-5% allocation overhead reduction

### Task 18: Domain Normalization Cache
**Effort:** Medium | **Impact:** Medium | **Source:** IMP-012, ROI: 6.5

```rust
// sentinel-engine/src/lib.rs
```

Domain normalization is deterministic and repeated:
- Add `Arc<DashMap<String, String>>` domain_norm_cache
- Expected: ~98% hit rate, 5-10% faster network rule evaluation

---

## Phase 19: Code Quality (Priority: P3)

### Task 19: Consolidate DLP/Injection Scanning Infrastructure
**Effort:** Medium | **Impact:** Medium | **Source:** IMP-002, ROI: 8.0

```rust
// sentinel-mcp/src/inspection/scanner_base.rs (new)
```

dlp.rs (1,782 LOC) and injection.rs (1,698 LOC) have similar patterns:
- Extract common scanning infrastructure into scanner_base.rs
- Create trait `ScannerPattern { patterns() -> Vec<(name, regex)>; check(text) -> Vec<Finding> }`
- Implement for DlpScanner, InjectionScanner
- Expected: ~200 LOC reduction, easier to add new scanners

### Task 20: Unified Scanning API
**Effort:** Medium | **Impact:** Medium | **Source:** IMP-008, ROI: 7.0

```rust
// sentinel-mcp/src/inspection/mod.rs
```

Current API has 9+ procedural scanning functions:
- Create `inspection::ScannerContext { text/value, location, source_type }`
- Create `inspection::scan(context) -> Vec<ScanResult>`
- Unifies all scanners behind one call
- Expected: 15% reduction in proxy/bridge.rs scanning code

### Task 21: Pre-compile Remaining Dynamic Regexes
**Effort:** Low | **Impact:** Low | **Source:** IMP-007, ROI: 5.5

```rust
// sentinel-mcp/src/output_security.rs line 372
```

- Wrap base64 regex in OnceLock
- Consistency with DLP pattern handling

---

## Phase 20: Dependency Updates (Priority: P3)

### Task 22: Minor Dependency Updates
**Effort:** Low | **Impact:** Medium | **Source:** IMP-006

```bash
cargo update
cargo test --workspace
cargo clippy --workspace
```

Low-risk updates:
- proptest 1.9.0 → 1.10.0
- regex 1.12.2 → 1.12.3
- tempfile 3.24.0 → 3.25.0
- clap 4.5.56 → 4.5.57

### Task 23: Evaluate Major Version Upgrades
**Effort:** Medium | **Impact:** Medium

Requires separate PR with thorough testing:
- rand 0.8.5 → 0.10.0 (major version)
- getrandom 0.2.17 → 0.4.1 (major version)
- redis 0.27 → 1.0 (sentinel-cluster)
- metrics-exporter-prometheus 0.16 → 0.18

---

## Phase 21: Large Refactoring (Priority: P4, Optional)

### Task 24: Split sentinel-engine/src/lib.rs
**Effort:** High | **Impact:** High | **Source:** IMP-001, ROI: 8.5

Currently 14,065 lines containing:
- PatternMatcher, CompiledToolMatcher
- CompiledConstraint
- PolicyEngine core
- Evaluation logic
- Time conditions

Proposed split:
- `pattern_matching.rs` (~400 LOC)
- `constraints.rs` (~600 LOC)
- `policy_engine.rs` (~2000 LOC)
- `evaluation.rs` (~3000+ LOC)
- `time_conditions.rs` (~400 LOC)
- Keep `lib.rs` as module aggregator (~500 LOC)

Benefits: Faster incremental compilation, better discoverability, easier testing

### Task 25: Add HTTP Proxy Benchmarks
**Effort:** Medium | **Impact:** Medium | **Source:** IMP-010, ROI: 6.5

```rust
// sentinel-http-proxy/benches/proxy_throughput.rs
```

No benchmarks exist for proxy request/response flow:
- Baseline: forward request/response unchanged
- With policy eval: measure overhead of policy engine
- With DLP: measure DLP scanning cost
- With approval: measure approval path latency
- Target: establish P50/P95/P99 baseline for 10k RPS

### Task 26: Add Semantic Guardrails Fuzz Target
**Effort:** Medium | **Impact:** Medium | **Source:** IMP-015, ROI: 6.0

```rust
// fuzz/fuzz_targets/fuzz_target_intent_classification.rs
```

Intent classification must not crash on adversarial input:
- Fuzz arbitrary IntentInput → IntentClassification
- Target: 10k iterations catching panics

---

## Execution Protocol

### Before Each Task
```bash
git status
cargo check --workspace
cargo test --workspace --lib
```

### After Each Task
```bash
cargo test --workspace
cargo clippy --workspace
git add <changed files>
git commit -m "<type>(<scope>): <description>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

### Quality Gates
- [ ] All tests pass
- [ ] Zero clippy warnings
- [ ] No new `unwrap()` in library code
- [ ] Documentation for public APIs

---

## Swarm Analysis Summary

### Security Agent Findings (15 items)
| Priority | Count | Examples |
|----------|-------|----------|
| P1 | 3 | Credentials in plaintext, SSRF vulnerability, unbounded retries |
| P2 | 7 | Hex decode fallback, timestamp parsing, nested JSON DoS |
| P3 | 5 | Non-cryptographic sampling, W3C validation gaps |

### Gap-Hunter Findings (20 items)
| Priority | Count | Examples |
|----------|-------|----------|
| P1 | 2 | Missing async export tests, redaction boundary testing |
| P2 | 10 | Response handling, HTTP status, config validation |
| P3 | 8 | Documentation, edge case testing |

### Improvement-Scout Findings (15 items)
| Category | Count | Top ROI |
|----------|-------|---------|
| Code Quality | 4 | Engine modularization (8.5), DLP consolidation (8.0) |
| Performance | 5 | Glob caching (7.5), capacity hints (7.0) |
| Testing | 2 | HTTP proxy benchmarks (6.5) |
| Dependencies | 1 | Minor updates (6.5) |

---

## Success Criteria

1. **Observability Hardening Complete**
   - All async exporter tests passing
   - Boundary/edge case tests for sampling, redaction
   - <5ms overhead on hot path maintained

2. **Test Coverage > 90%**
   - All observability types tested
   - Property-based tests for core invariants
   - Integration tests for each exporter

3. **Security Gaps Addressed**
   - Response handling hardened
   - Config validation comprehensive
   - Logging for security decisions

4. **Performance Improved**
   - GlobMatcher caching implemented
   - HashMap capacity hints added
   - Benchmarks for HTTP proxy

---

## Appendix: File Reference

| Component | Location |
|-----------|----------|
| Observability types | `sentinel-audit/src/observability/mod.rs` |
| Langfuse exporter | `sentinel-audit/src/observability/langfuse.rs` |
| Arize exporter | `sentinel-audit/src/observability/arize.rs` |
| Helicone exporter | `sentinel-audit/src/observability/helicone.rs` |
| Webhook exporter | `sentinel-audit/src/observability/webhook.rs` |
| Observability config | `sentinel-config/src/observability.rs` |
| Policy engine | `sentinel-engine/src/lib.rs` |
| DLP scanning | `sentinel-mcp/src/inspection/dlp.rs` |
| Injection scanning | `sentinel-mcp/src/inspection/injection.rs` |
| Server routes | `sentinel-server/src/routes.rs` |
| HTTP proxy | `sentinel-http-proxy/src/proxy.rs` |

---

## Notes for Codex

1. **Priority order matters** - Complete P1 tasks before P2
2. **Test first** - Write tests before fixing issues when possible
3. **Small commits** - One logical change per commit
4. **Ask if unclear** - Better to clarify than assume
5. **Update CLAUDE.md** - After Phase 15.5 completion, update the "What's Done" section
6. **ROI-driven** - Higher ROI tasks within same priority tier should be done first
7. **Security focus** - Any P1 security findings take precedence over P2 improvements
