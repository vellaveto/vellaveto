# Load Testing & Performance SLO

This document defines Vellaveto's canonical performance SLO and provides
reproducible load test procedures for validating it under realistic conditions.

For microbenchmark methodology, see [docs/BENCHMARKS.md](../docs/BENCHMARKS.md).
For the reproducibility kit, see [repro/](../repro/).

---

## Canonical Performance SLO

> **P99 policy evaluation latency < 5ms** for requests meeting the following
> conditions:
>
> - Payload size: ≤ 64 KB (JSON-RPC body)
> - Policy count: ≤ 1,000
> - Concurrency: ≤ 500 concurrent requests
> - Reference hardware: 2 vCPU, 4 GB RAM (e.g., AWS c6a.large)
> - Measurement point: `/api/evaluate` endpoint, measured from request
>   receipt to response send, **excluding upstream tool latency**
> - Warm cache: policy index pre-compiled (not first request after startup)

### What This SLO Covers

The 5ms budget includes:
- JSON-RPC parsing and validation
- Policy engine evaluation (first-match-wins scan)
- Path normalization and domain extraction
- Context evaluation (time windows, call limits, agent identity)
- Verdict serialization and response

### What This SLO Excludes

- **Upstream tool latency** — time spent forwarding to and receiving from the
  MCP server. This is pass-through and outside Vellaveto's control.
- **TLS termination** — handled by upstream infrastructure.
- **DLP scanning** — adds 1–3ms depending on parameter size. Included in
  the proxy pipeline but not in the core evaluation SLO.
- **Injection detection** — adds 0.5–2ms. Same caveat.
- **Network I/O** — client-to-proxy and proxy-to-tool round trips.

### Measured Performance

From Criterion microbenchmarks on AMD EPYC 7R13 (c6a.2xlarge):

| Scenario | P50 | P99 | Notes |
|----------|-----|-----|-------|
| 1 policy, exact match | 7 ns | 31 ns | Index hit |
| 100 policies, ~50th match | 50 µs | 200 µs | First-match with tool indexing |
| 1,000 policies, no match | 8 µs | 12 µs | Full scan, default deny |
| Full pipeline (eval + DLP + injection) | ~2 ms | ~4 ms | Estimated from component sums |

The 5ms SLO has >10x headroom for the core evaluation path and ~1.25x headroom
for the full pipeline including DLP and injection scanning.

---

## Load Test Procedure

### Prerequisites

Install a load testing tool. Any of these work:

```bash
# Option A: vegeta (Go, recommended)
go install github.com/tsenart/vegeta@latest

# Option B: wrk2 (C, constant-throughput)
# brew install wrk2  # macOS
# apt install wrk2   # Debian/Ubuntu

# Option C: k6 (JavaScript, scriptable)
# brew install k6
```

### Step 1: Start Vellaveto

```bash
# Minimal config for load testing (no auth, no DLP, no injection)
cat > /tmp/vellaveto-loadtest.toml <<'EOF'
[[policies]]
name = "allow-all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
EOF

cargo run --release -- --config /tmp/vellaveto-loadtest.toml --bind 127.0.0.1:3000
```

### Step 2: Run Load Test

#### With vegeta (recommended)

```bash
# Generate attack file
echo 'POST http://127.0.0.1:3000/api/evaluate
Content-Type: application/json
@/tmp/vellaveto-payload.json' > /tmp/vellaveto-attack.txt

# Create test payload
echo '{"tool":"file","function":"read","parameters":{"path":"/tmp/test.txt"}}' \
  > /tmp/vellaveto-payload.json

# Run: 1000 req/s for 30 seconds
vegeta attack -targets=/tmp/vellaveto-attack.txt \
  -rate=1000/s -duration=30s | \
  vegeta report -type=text

# For detailed latency distribution:
vegeta attack -targets=/tmp/vellaveto-attack.txt \
  -rate=1000/s -duration=30s | \
  vegeta report -type='hist[0,1ms,2ms,3ms,4ms,5ms,10ms,50ms]'

# Save results as JSON for evidence:
vegeta attack -targets=/tmp/vellaveto-attack.txt \
  -rate=1000/s -duration=30s | \
  vegeta report -type=json > perf/results/loadtest-$(date +%Y%m%d).json
```

#### With wrk2

```bash
# 500 concurrent connections, 1000 req/s, 30 seconds
wrk2 -t4 -c500 -R1000 -d30s \
  -s perf/wrk2-evaluate.lua \
  http://127.0.0.1:3000/api/evaluate
```

Create `perf/wrk2-evaluate.lua`:

```lua
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"tool":"file","function":"read","parameters":{"path":"/tmp/test.txt"}}'
```

#### With k6

```bash
k6 run perf/k6-evaluate.js
```

Create `perf/k6-evaluate.js`:

```javascript
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    constant_rate: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 500,
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<5'],  // P99 < 5ms
  },
};

export default function () {
  const res = http.post(
    'http://127.0.0.1:3000/api/evaluate',
    JSON.stringify({
      tool: 'file',
      function: 'read',
      parameters: { path: '/tmp/test.txt' },
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  check(res, { 'status 200': (r) => r.status === 200 });
}
```

### Step 3: Validate Results

The P99 latency from the load test should be < 5ms. If it exceeds 5ms:

1. Check if the machine is under other load (`top`, `vmstat`)
2. Ensure release mode (`--release`)
3. Ensure the policy set size matches the SLO parameters (≤ 1,000)
4. Check for garbage collection pauses (Vellaveto is Rust — no GC, but the
   OS page cache can cause latency spikes)

---

## Results Directory

Store load test results in `perf/results/` for historical tracking:

```
perf/
  LOADTEST.md          ← This file
  wrk2-evaluate.lua    ← wrk2 script (optional)
  k6-evaluate.js       ← k6 script (optional)
  results/
    loadtest-YYYYMMDD.json
```

---

## CI Integration

To add load test gating to CI:

1. Start Vellaveto in the background during the CI job
2. Run a short load test (10s at 500 req/s)
3. Assert P99 < 5ms in the load test output
4. Archive the results JSON as a build artifact

Example GitHub Actions step:

```yaml
- name: Load test
  run: |
    cargo run --release -- --config tests/fixtures/loadtest.toml &
    sleep 2
    echo 'POST http://127.0.0.1:3000/api/evaluate
    Content-Type: application/json
    {"tool":"file","function":"read","parameters":{}}' | \
      vegeta attack -rate=500/s -duration=10s | \
      vegeta report -type=json > loadtest-results.json
    P99=$(jq '.latencies."99th"' loadtest-results.json)
    echo "P99 latency: ${P99}ns"
    # 5ms = 5,000,000 ns
    if [ "$P99" -gt 5000000 ]; then
      echo "FAIL: P99 ${P99}ns exceeds 5ms SLO"
      exit 1
    fi
```
