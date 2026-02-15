# Assurance Case

Structured Claim → Evidence map for Vellaveto's public security claims.
Each claim includes scope, assumptions, evidence pointers, and a single
reproduction command.

For the normative definition of each guarantee, see
[SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md).

---

## Claims

### C1. "Fail-closed: errors and missing policies produce Deny"

| Field | Value |
|-------|-------|
| **Scope** | `PolicyEngine::evaluate` and `AbacEngine::evaluate` code paths |
| **Assumptions** | Engine is called for every tool call (complete mediation) |
| **Formal evidence** | TLA+ invariants S1, S5, S6 (`formal/tla/MCPPolicyEngine.tla`); Lean 4 proof (`formal/lean/Vellaveto/FailClosed.lean`) |
| **Test evidence** | `vellaveto-engine/src/lib.rs` — `test_no_matching_policy_denies`, `test_empty_engine_denies`, `test_error_in_context_denies`; `vellaveto-integration/tests/` — negative integration tests |
| **Negative tests** | Tests that verify `Allow` is never produced without an explicit `Allow` policy match |
| **Reproduce** | `cargo test -p vellaveto-engine -- fail_closed && cd formal/tla && java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla` |

### C2. "<5ms P99 policy evaluation latency"

| Field | Value |
|-------|-------|
| **Scope** | `PolicyEngine::evaluate_with_compiled` hot path. Excludes upstream tool latency, TLS termination, network I/O, DLP scanning, and injection detection. |
| **Assumptions** | Payload ≤ 64 KB; policies ≤ 1,000; pre-compiled policy index; warm cache; reference hardware (see below) |
| **Benchmark evidence** | `vellaveto-engine/benches/evaluation.rs` — 7 Criterion benchmarks; measured 7–31 ns (1 policy), ~1.2 µs (100 policies), ~12 µs (1,000 policies) |
| **Reference hardware** | AMD EPYC 7R13 (c6a.2xlarge), 3.6 GHz boost, Amazon Linux 2023, Rust 1.93.0, release profile with `lto = "thin"` |
| **Reproducibility kit** | `repro/` directory with `bench.sh`, `Dockerfile`, `pinned-results.json`, `verify.sh` |
| **CI gate** | Benchmark regression check on every push to `main`; >10% regression flagged |
| **Reproduce** | `./repro/bench.sh` or `docker build -t vellaveto-bench -f repro/Dockerfile . && docker run --rm vellaveto-bench` |

**Note:** The "<5ms P99" claim is conservative. Measured P99 for the full evaluation path
(including path normalization, domain extraction, and context evaluation) is under 15 µs
for 1,000 policies — two orders of magnitude below the 5ms target. The claim refers to the
`/api/evaluate` hot path excluding network I/O.

For load testing under concurrency, see [perf/LOADTEST.md](../perf/LOADTEST.md).

### C3. "Tamper-evident audit trail with cryptographic integrity"

| Field | Value |
|-------|-------|
| **Scope** | Append-only audit log with SHA-256 hash chain, Ed25519 checkpoint signatures, Merkle inclusion proofs |
| **Assumptions** | Filesystem not actively compromised during writes; Ed25519/SHA-256 primitives are correct; signing key not compromised |
| **What "tamper-evident" means** | Tampering is *detected* on verification, not *prevented*. Truncation is detectable. Silent modification of individual entries breaks the hash chain. |
| **What it does NOT mean** | An attacker with write access cannot be prevented from deleting the log entirely. Forward to external SIEM for tamper-resistant archival. |
| **Test evidence** | `vellaveto-audit/src/tests.rs` — hash chain verification, corruption detection, checkpoint validation, Merkle proof verification; `vellaveto-integration/tests/` — audit integrity tests |
| **Reproduce** | `cargo test -p vellaveto-audit -- chain && cargo test -p vellaveto-audit -- checkpoint && cargo test -p vellaveto-audit -- merkle` |

### C4. "MCP 2025-11-25 compliance with backwards compatibility"

| Field | Value |
|-------|-------|
| **Scope** | JSON-RPC 2.0 message handling, MCP method routing, capability negotiation, elicitation/sampling interception |
| **Assumptions** | Upstream MCP server is spec-compliant |
| **Test evidence** | `vellaveto-mcp/src/tests.rs` — protocol conformance tests; `vellaveto-integration/tests/` — transport-specific tests for HTTP, stdio, WebSocket, gRPC |
| **Backwards compat** | Tested against 2025-03-26 and 2025-06-18 message formats |
| **Reproduce** | `cargo test -p vellaveto-mcp -- protocol && cargo test -p vellaveto-integration` |

### C5. "EU AI Act compliance (Art 50(2) + Art 10)"

| Field | Value |
|-------|-------|
| **Scope** | Art 50(2): automated decision explanations injected into `_meta.vellaveto_decision_explanation`. Art 10: data governance registry with classification, purpose, provenance, retention. Art 50(1): transparency marking via `_meta.vellaveto_ai_mediated`. |
| **Assumptions** | Operator configures appropriate explanation verbosity and data governance mappings |
| **Test evidence** | `vellaveto-mcp/src/transparency.rs` — Art 50(1) tests; `vellaveto-server/src/routes/compliance.rs` — API tests; `vellaveto-audit/src/eu_ai_act.rs` — registry tests; `vellaveto-audit/src/data_governance.rs` — Art 10 tests |
| **Reproduce** | `cargo test -p vellaveto-audit -- eu_ai_act && cargo test -p vellaveto-audit -- data_governance && cargo test -p vellaveto-mcp -- transparency` |

### C6. "39 audit rounds, 400+ findings"

| Field | Value |
|-------|-------|
| **Scope** | Internal adversarial testing using automated multi-agent protocol (Bottega). Not external third-party audits. |
| **Methodology** | Automated adversarial agent generates attack payloads against running instance; findings triaged by severity (P0–P3); fixes verified by re-running attack corpus |
| **Evidence** | `SWARM_FINDINGS_PLAN.md` — consolidated finding list; `CHANGELOG.md` — per-phase finding counts and fix PRs; `security-testing/` — pentest harness |
| **Clarification** | These are *internal automated audit iterations*, not external penetration tests by a third-party firm. The badge text reflects this. |
| **Reproduce** | Finding verification: `cargo test -p vellaveto-integration -- regression` |

### C7. "19 formally verified properties"

| Field | Value |
|-------|-------|
| **Scope** | 16 safety properties + 3 liveness properties across TLA+ (S1–S10, L1–L3) and Alloy (S11–S16). 3 additional Lean 4 lemmas (determinism, fail-closed, path normalization idempotence). |
| **Assumptions** | Bounded model checking (finite state spaces). Properties are structural and do not depend on bound values. Pattern matching abstracted to wildcard + exact. |
| **What is NOT verified** | Pattern compilation, cryptographic primitives, timing, concurrency, network properties, serialization. See [FORMAL_SCOPE.md](FORMAL_SCOPE.md). |
| **Test evidence** | `formal/README.md` — property catalog with source traceability |
| **Reproduce** | `cd formal/tla && java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla && java -jar tla2tools.jar -config AbacForbidOverrides.cfg MC_AbacForbidOverrides.tla` |

---

## Evidence Summary

| Verification Layer | Method | Count |
|--------------------|--------|-------|
| Unit + integration tests | Rust `#[test]` | 5,003+ |
| SDK tests | Python / Go / TypeScript | 173 |
| Fuzz targets | `cargo fuzz` | 24 |
| Property-based tests | `proptest` | ~50 |
| Formal specs (TLA+ / Alloy) | Model checking | 19 properties |
| Formal proofs (Lean 4) | Type checking | 3 lemmas |
| Criterion benchmarks | Statistical microbenchmark | 51 benchmarks |
| Reproducibility kit | Docker + pinned results | `repro/` |
| CI gates | GitHub Actions | 11 workflows |

---

## Reproducing the Full Evidence Bundle

```bash
make verify
```

This runs all verification steps and produces a JSON evidence bundle.
See the root [Makefile](../Makefile) for details.
