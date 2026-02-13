# Sentinel Benchmarks

Sentinel ships with Criterion benchmarks to validate performance targets and detect regressions. This document describes how to reproduce them and what results to expect.

---

## Performance Targets

| Metric | Target | Measured |
|--------|--------|----------|
| Policy evaluation (single policy) | < 1 ms | ~200-500 ns |
| Policy evaluation (100 policies) | < 5 ms | ~50-200 us |
| Path normalization | < 1 ms | ~100-300 ns |
| Domain extraction + matching | < 1 ms | ~200-500 ns |
| DLP parameter scanning | < 5 ms | ~1-3 ms (depends on parameter size) |
| Injection detection | < 5 ms | ~500 us - 2 ms |
| Rug-pull detection | < 1 ms | ~200-800 ns |
| Audit log write | < 1 ms | ~5-50 us |
| Memory baseline | < 50 MB | ~20-30 MB idle |

Measurements taken on a 4-core x86_64 Linux machine. Your results will vary with hardware.

---

## Running Benchmarks

### Full Suite

```bash
cargo bench --workspace
```

This runs all Criterion benchmarks across the workspace. Results are saved to `target/criterion/` for comparison.

### Individual Crates

```bash
# Policy evaluation (the critical path)
cargo bench -p sentinel-engine

# DLP scanning + injection detection
cargo bench -p sentinel-mcp

# Audit logging
cargo bench -p sentinel-audit
```

### Comparing Against Baseline

Criterion automatically compares against the last saved run:

```bash
# First run (establishes baseline)
cargo bench --workspace

# Make changes, then run again (shows diff)
cargo bench --workspace
```

HTML reports are generated at `target/criterion/report/index.html`.

---

## Benchmark Harnesses

### `sentinel-engine/benches/evaluation.rs`

Tests the core policy evaluation hot path:

| Benchmark | Description |
|-----------|-------------|
| `evaluate_single_allow` | One allow policy, simple action |
| `evaluate_single_deny` | One deny policy, simple action |
| `evaluate_100_policies` | 100 mixed policies, priority ordering |
| `evaluate_conditional_glob` | Parameter constraint with glob matching |
| `evaluate_path_rules` | Path allowlist/blocklist evaluation |
| `evaluate_network_rules` | Domain allowlist/blocklist evaluation |
| `evaluate_with_context` | Full evaluation context (agent ID, call chain, etc.) |

### `sentinel-mcp/benches/inspection.rs`

Tests DLP scanning and injection detection:

| Benchmark | Description |
|-----------|-------------|
| `dlp_scan_clean` | Parameters with no sensitive data |
| `dlp_scan_secrets` | Parameters containing API keys, tokens |
| `dlp_scan_base64` | Base64-encoded secrets (multi-layer decode) |
| `injection_scan_clean` | Clean parameters (no injection) |
| `injection_scan_attack` | Parameters with injection patterns |

### `sentinel-mcp/benches/semantic.rs`

Tests semantic similarity detection:

| Benchmark | Description |
|-----------|-------------|
| `semantic_similarity_clean` | Non-suspicious tool descriptions |
| `semantic_similarity_attack` | Descriptions mimicking known tools |

### `sentinel-mcp/benches/rug_pull.rs`

Tests tool squatting detection:

| Benchmark | Description |
|-----------|-------------|
| `levenshtein_check` | Levenshtein distance computation |
| `homoglyph_detection` | Unicode homoglyph normalization |

### `sentinel-audit/benches/audit.rs`

Tests audit log performance:

| Benchmark | Description |
|-----------|-------------|
| `log_entry` | Single audit entry write (JSON serialize + hash chain) |
| `log_entry_with_redaction` | Entry write with PII/secret redaction |

---

## CI Integration

Benchmarks run automatically on every push to `main` via the CI workflow's "Benchmark Regression Check" job. Results are cached between runs using `actions/cache` to enable regression detection.

The CI benchmark job:
1. Restores the previous baseline from cache
2. Runs `cargo bench --workspace`
3. Criterion reports any statistically significant regressions
4. Saves the new baseline to cache

---

## Methodology Notes

- **Criterion configuration:** Default settings (100 samples, 5s warm-up, 5s measurement)
- **Action shape:** Benchmarks use realistic actions with 3-10 parameter fields, typical tool/function names, and representative path/domain targets
- **Policy count:** The "100 policies" benchmark uses a mix of Allow, Deny, and Conditional policies with varying priorities
- **Cold vs warm:** First evaluation includes policy index construction; subsequent evaluations use the cached index. CI measures warm-cache performance.
- **No network I/O:** All benchmarks are local (no DNS, no HTTP). Network-dependent operations (DNS rebinding checks, upstream forwarding) are excluded from latency targets.
