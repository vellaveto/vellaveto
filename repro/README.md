# Reproducibility Kit

This directory contains everything needed to independently reproduce Vellaveto's published performance numbers.

## Quick Start

```bash
# Option 1: Docker (recommended — fully isolated)
docker build -t vellaveto-bench -f repro/Dockerfile .
docker run --rm vellaveto-bench

# Option 2: Local (requires Rust 1.82+)
./repro/bench.sh

# Option 3: Compare against pinned results
./repro/bench.sh --compare
```

## What Gets Benchmarked

| Suite | Crate | What it measures |
|-------|-------|------------------|
| `evaluation` | vellaveto-engine | Policy evaluation hot path (single, 100, 1000 policies) |
| `inspection` | vellaveto-mcp | Injection scanning, DLP, duplicate key detection |
| `rug_pull` | vellaveto-mcp | Tool squatting and rug-pull detection |
| `audit` | vellaveto-audit | Hash chain logging, CEF/JSONL export, redaction |
| `http_proxy` | vellaveto-http-proxy | Origin validation, HMAC, privilege escalation detection |

All benchmarks use [Criterion.rs](https://github.com/bheisler/criterion.rs) v0.8 with HTML reports.

## Methodology

### Environment Controls

The `bench.sh` script and Dockerfile enforce:

1. **CPU isolation.** Docker: `--cpus=2`. Local: advises `taskset -c 0-1` if available.
2. **No frequency scaling.** Docker: performance governor. Local: warns if not set.
3. **Release profile.** `lto = "thin"`, `codegen-units = 1`, `opt-level = 3` (from workspace `Cargo.toml`).
4. **Warm-up.** Criterion's default 3-second warm-up per benchmark group.
5. **Sample size.** Criterion's default: 100 samples per benchmark.
6. **No other load.** Docker container runs nothing else. Local: script warns about load average.

### What the Numbers Mean

- **7-31 ns (single policy evaluation):** Time for `PolicyEngine::evaluate_with_compiled` with one pre-compiled policy. Lower bound is an exact tool match (index hit); upper bound is a wildcard with path + domain rules.
- **~1.2 us (100 policies):** First-match scan with fallthrough to ~50th policy (typical worst case with tool indexing).
- **~12 us (1,000 policies):** Full scan with no match (all policies checked, default deny).
- **~1.6 us (HMAC-SHA256):** Sign + verify cycle for call-chain integrity.
- **16-76 ns (privilege escalation):** 0-hop to 10-hop chain detection.

### Statistical Rigor

Criterion reports:
- **Point estimate:** Mean of 100 samples
- **Confidence interval:** 95% CI (default)
- **Outlier detection:** Mild and severe outliers reported separately
- **Change detection:** Automatic comparison against previous baseline (`target/criterion/`)

## Files

| File | Purpose |
|------|---------|
| `README.md` | This document |
| `bench.sh` | Runner script: environment checks, benchmark execution, result extraction |
| `Dockerfile` | Isolated benchmark environment (Rust 1.93 + Alpine) |
| `pinned-results.json` | Reference results from CI (system info + numbers) |
| `verify.sh` | Compare local results against pinned results; flag regressions |

## Reproducing Published Numbers

The numbers in `README.md` and `docs/BENCHMARKS.md` were produced on:

- **CPU:** AMD EPYC 7R13 (c6a.2xlarge), 3.6 GHz boost
- **OS:** Amazon Linux 2023
- **Rust:** 1.93.0 (nightly features not required)
- **Profile:** Release with `lto = "thin"`, `codegen-units = 1`

Your numbers will differ based on CPU architecture and frequency. The `verify.sh` script uses relative thresholds (2x tolerance) rather than absolute values.

## CI Integration

Benchmarks run on every push to `main` via GitHub Actions. The workflow:

1. Builds in release mode
2. Runs `cargo bench --workspace`
3. Archives `target/criterion/` as build artifact
4. Compares against previous run; flags >10% regressions as warnings
