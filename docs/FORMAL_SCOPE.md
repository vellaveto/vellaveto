# Formal Verification Scope

What is proven, what is tested, and what is assumed.

For the full property catalog with source traceability, see
[formal/README.md](../formal/README.md).

---

## What Is Formally Verified

| Property | Framework | ID | Status |
|----------|-----------|-----|--------|
| Fail-closed (no match → Deny) | TLA+, Lean 4 | S1 | Verified |
| Priority ordering | TLA+ | S2 | Verified |
| Blocked paths override allowed | TLA+ | S3 | Verified |
| Blocked domains override allowed | TLA+ | S4 | Verified |
| Allow requires matching Allow policy | TLA+, Lean 4 | S5 | Verified |
| Missing context → Deny | TLA+ | S6 | Verified |
| ABAC forbid dominance | TLA+ | S7 | Verified |
| ABAC forbid ignores priority | TLA+ | S8 | Verified |
| ABAC permit requires no forbid | TLA+ | S9 | Verified |
| ABAC no match → NoMatch | TLA+ | S10 | Verified |
| Capability monotonic attenuation | Alloy | S11 | Verified |
| Capability transitive attenuation | Alloy | S12 | Verified |
| Capability depth budget | Alloy | S13 | Verified |
| Capability temporal monotonicity | Alloy | S14 | Verified |
| Terminal cannot delegate | Alloy | S15 | Verified |
| Issuer chain integrity | Alloy | S16 | Verified |
| Eventual verdict (liveness) | TLA+ | L1 | Verified |
| No stuck states (liveness) | TLA+ | L2 | Verified |
| ABAC eventual decision (liveness) | TLA+ | L3 | Verified |
| Evaluation determinism | Lean 4 | — | Verified |
| Path normalization idempotence | Lean 4 | — | Partial (2 `sorry` markers) |

**Total: 19 model-checked properties + 3 Lean 4 lemmas.**

---

## What Is Tested But Not Formally Verified

These properties are covered by the test suite (5,003+ tests, 24 fuzz targets,
~50 proptest generators) but not by formal specifications:

| Property | Coverage |
|----------|----------|
| Glob/regex pattern compilation correctness | 24 fuzz targets, ~200 unit tests |
| Path traversal normalization | Unit tests + proptest + fuzz |
| DNS rebinding / IP resolution | Unit tests |
| DLP multi-layer decode (base64, percent, combos) | Unit tests + fuzz |
| Injection detection (Aho-Corasick + NFKC + semantic) | Unit tests + fuzz |
| Tool squatting (Levenshtein + homoglyph) | Unit tests |
| Multimodal inspection (PNG/JPEG/PDF/WAV/MP3/MP4/WebM) | Unit tests |
| Audit log rotation and continuity | Unit tests |
| OAuth 2.1 / JWT validation | Unit tests |
| Rate limiting correctness | Unit tests |
| MCP protocol conformance | Integration tests |
| Transport-specific behavior (HTTP/stdio/WS/gRPC) | Integration tests |

---

## What Is Assumed (Not Verified or Tested)

| Assumption | Rationale |
|------------|-----------|
| **Ed25519 signature correctness** | Uses `ed25519-dalek`, a widely-audited implementation. Cryptographic primitive verification is outside project scope. |
| **SHA-256 / HMAC-SHA256 correctness** | Uses `ring` (BoringSSL-derived). Same rationale. |
| **Rust memory safety** | No `unsafe` in library code. Relies on the Rust compiler and standard library. |
| **TLS correctness** | TLS termination is handled by upstream infrastructure (nginx, Caddy, cloud LB). |
| **OS filesystem semantics** | `write()` + `fsync()` provide the expected durability guarantees. |
| **Clock monotonicity** | Timestamps use `std::time::Instant` (monotonic) for durations and `SystemTime` for wall clock. NTP jumps could affect wall-clock ordering of audit entries. |
| **DNS resolver correctness** | System DNS resolver returns accurate results. DNS poisoning is mitigated by private-IP blocking but not eliminated. |

---

## Known Abstraction Gaps in Formal Models

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob patterns abstracted to wildcard + exact | Cannot detect glob-specific matching bugs | 24 fuzz targets cover pattern compilation |
| Path/domain subset uses set identity, not glob matching | Alloy model is more restrictive than Rust implementation | Sound over-approximation (security-safe direction) |
| ABAC CHOOSE vs priority-ordered selection | Reported `policy_id` may differ from Rust | Does not affect Deny/Allow decision |
| Conditional policies simplified to fire/no-fire | Constraint-level deny paths not modeled | Covered by 5,003+ unit tests |
| `RequireApproval` verdict not modeled in TLA+ | Approval flow not formally verified | Covered by integration tests |
| `max_invocations` not checked during attenuation | Child could inherit unlimited invocations | Known implementation gap, tracked |
| Small model bounds (3 policies, 2 actions) | Exhaustive for structural properties | Properties are independent of bound values |
| Lean 4 `sorry` markers (2) | Path normalization sub-lemmas incomplete | Property validated by proptest (10,000+ inputs) + fuzzing |

---

## Verification in CI

Formal checks are **not** currently run in CI because they require:

- Java 11+ and `tla2tools.jar` (TLA+)
- Alloy Analyzer JAR (Alloy)
- Lean 4 toolchain (Lean)

These are available via `make formal` for local verification.

To add formal checks to CI, install the required toolchains in the CI
environment and add `make formal` as a workflow step. The `make verify`
target already includes formal checks when tools are available and skips
gracefully when they are not.

---

## Relation to Other Verification

| Layer | What It Catches | What It Misses |
|-------|----------------|----------------|
| **Formal specs** | Algorithmic correctness violations across *all* possible inputs | Implementation bugs, concurrency, I/O |
| **Fuzz testing** | Edge cases in parsing, encoding, pattern matching | Algorithmic design flaws |
| **Property tests** | Statistical coverage of invariants | Adversarial inputs (not guided) |
| **Unit tests** | Known-input regression | Novel inputs, emergent behavior |
| **Integration tests** | End-to-end transport/protocol correctness | Performance, scale |

Together, these layers provide defense in depth. No single layer is sufficient.
