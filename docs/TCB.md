# Trusted Computing Base (TCB)

This document defines Vellaveto's Trusted Computing Base — the minimal set of code whose correctness is required for the system's security guarantees to hold. Everything outside the TCB may have bugs without violating security invariants (it may break features, performance, or usability, but not security).

## Scope

The TCB consists of three components totaling approximately **3,350 lines of non-test Rust** (excluding tests, comments, and blank lines):

1. **Policy Evaluation Core** (`vellaveto-engine`)
2. **Canonicalization** (`vellaveto-engine`)
3. **Audit Integrity** (`vellaveto-audit`)

## 1. Policy Evaluation Core

The code that decides Allow / Deny / RequireApproval for a given action.

| File | Lines | Responsibility |
|------|-------|----------------|
| `vellaveto-engine/src/lib.rs` | ~900 | `PolicyEngine::evaluate_action`, `evaluate_with_compiled`, first-match-wins loop, default-deny fallback |
| `vellaveto-engine/src/compiled.rs` | ~440 | `CompiledPolicy`, pre-compiled pattern structures, constraint dispatch |
| `vellaveto-engine/src/matcher.rs` | ~207 | `PatternMatcher`, glob/regex/exact matching, tool pattern resolution |
| `vellaveto-engine/src/rule_check.rs` | ~238 | `check_path_rules`, `check_domain_rules` — blocked-overrides-allowed semantics |
| `vellaveto-engine/src/constraint_eval.rs` | ~523 | Parameter constraint evaluation (6 operators), recursive JSON scanning |
| `vellaveto-engine/src/error.rs` | ~104 | `EngineError` — every error variant must map to Deny (fail-closed) |

**Security invariants maintained by this component:**

- **S1 (Fail-closed):** Empty policy set or no match produces `Verdict::Deny`
- **S2 (Priority ordering):** Policies evaluated in priority-descending order; deny-first at equal priority
- **S3 (Blocked paths override):** A blocked path match produces Deny regardless of allowed paths
- **S4 (Blocked domains override):** A blocked domain match produces Deny regardless of allowed domains
- **S5 (Allow requires match):** Allow verdict can only come from an explicit Allow policy
- **S6 (Missing context → Deny):** Context-dependent policy without context produces Deny

**Formal verification:** TLA+ model `formal/tla/MCPPolicyEngine.tla` verifies S1–S6 + liveness L1–L2.

## 2. Canonicalization

Input normalization that runs before policy matching. If canonicalization is wrong, policy rules can be bypassed.

| File | Lines | Responsibility |
|------|-------|----------------|
| `vellaveto-engine/src/path.rs` | ~304 | `normalize_path` — percent-decode loop, null-byte rejection, backslash normalization, `..`/`.` resolution, absolute path enforcement |
| `vellaveto-engine/src/domain.rs` | ~540 | `normalize_domain_for_match` — IDNA normalization, trailing dot removal, case folding, fail-closed on IDNA failure |
| `vellaveto-engine/src/ip.rs` | ~437 | `extract_embedded_ipv4` — IPv6 transition mechanism canonicalization (IPv4-mapped, 6to4, Teredo, NAT64) |

**Security invariants maintained by this component:**

- **Idempotence:** `normalize(normalize(x)) = normalize(x)` (proven by proptest + Lean 4)
- **Fail-closed on decode limit:** Exceeding `max_iterations` percent-decode loops returns error (→ Deny)
- **Null-byte rejection:** Inputs containing `\0` at any decode stage are rejected
- **Backslash normalization inside decode loop:** Prevents `%255C`-based traversals (R35-ENG-1)
- **IPv6 canonicalization:** Embedded IPv4 extracted before CIDR matching (R24-ENG-1, R29-ENG-1)
- **IDNA fail-closed:** Non-ASCII domains that fail IDNA normalization are denied (R30-ENG-2)

**Formal verification:** Lean 4 lemmas `formal/lean/Vellaveto/PathNormalization.lean` prove idempotence. Property-based tests (`proptest`) verify on random inputs. Fuzz target `fuzz/fuzz_targets/fuzz_normalize_path.rs` continuously tests.

## 3. Audit Integrity

The code that guarantees tamper-evidence of the decision log.

| File | Lines | Responsibility |
|------|-------|----------------|
| `vellaveto-audit/src/logger.rs` | ~534 | `AuditLogger::log` — SHA-256 hash chain, append-only writes, `fsync` on Deny verdicts |
| `vellaveto-audit/src/verification.rs` | ~241 | `verify_chain` — hash chain verification, tamper detection, file size limits |
| `vellaveto-audit/src/merkle.rs` | ~435 | `MerkleTree` — RFC 6962 domain separation, inclusion proofs, peak-based O(log n) append |
| `vellaveto-audit/src/checkpoints.rs` | ~372 | `create_checkpoint`, `verify_checkpoints` — Ed25519 signed checkpoints, trusted key pinning |

**Security invariants maintained by this component:**

- **S7 (Hash chain integrity):** Every entry chains to its predecessor via `SHA-256(prev_hash || entry_data)`
- **S8 (Tamper detection):** Modifying any entry breaks the chain at the modification point
- **S9 (Domain separation):** Leaf hash `SHA-256(0x00 || data)` vs internal `SHA-256(0x01 || left || right)` (RFC 6962)
- **S10 (Checkpoint authenticity):** Ed25519 signatures on chain state; trusted key pinning prevents forgery
- **S11 (Length-prefixed encoding):** Prevents hash collision from boundary ambiguity (`{tool:"ab", func:"cd"}` vs `{tool:"abc", func:"d"}`)

**Formal verification:** TLA+ model `formal/tla/MCPPolicyEngine.tla` includes audit chain properties. Adversarial tests in `vellaveto-integration/tests/full_attack_battery.rs`.

## What Is NOT in the TCB

Everything else. Bugs in these components cannot bypass security invariants:

| Component | Why it's outside the TCB |
|-----------|--------------------------|
| `vellaveto-server` | HTTP layer; a bug may cause crashes or API errors, but cannot change verdicts |
| `vellaveto-proxy`, `vellaveto-http-proxy` | Transport layers; forward parsed messages to the engine |
| `vellaveto-config` | Parses TOML/JSON into policy structures; a parsing bug produces invalid policies (caught by validation), not silent bypasses |
| `vellaveto-canonical` | Preset policy definitions; convenience, not enforcement |
| `vellaveto-cluster` | Distributed state sync; availability concern, not integrity |
| `vellaveto-approval` | Human-in-the-loop workflow; operates on top of verdicts |
| `vellaveto-mcp` (inspection) | Injection/DLP scanning provides defense-in-depth signals but does not override policy verdicts |
| `vellaveto-engine/src/abac.rs` | ABAC engine; important but operates as a separate evaluation layer with its own TLA+ model (S7–S10 in `AbacForbidOverrides.tla`) |
| `vellaveto-engine/src/behavioral.rs` | Anomaly detection; observational, does not block actions |
| `vellaveto-engine/src/circuit_breaker.rs` | Availability control; fails open to Deny (safe direction) |
| `vellaveto-engine/src/legacy.rs` | Backward-compatible policy evaluation; delegates to TCB functions |
| `vellaveto-engine/src/traced.rs` | Tracing wrapper; adds observability without changing verdicts |
| `vellaveto-engine/src/policy_compile.rs` | Compiles policies into `CompiledPolicy`; a compilation bug produces invalid compiled form (caught by tests), but the evaluation logic in `compiled.rs` + `lib.rs` is the actual TCB |
| `vellaveto-engine/src/deputy.rs` | Confused deputy prevention; defense-in-depth |
| `vellaveto-engine/src/least_agency.rs` | Least privilege tracking; advisory |
| `vellaveto-engine/src/context_check.rs` | Context condition evaluation; supplements policy decisions but fail-closed on error |
| Compliance modules (`eu_ai_act.rs`, `soc2.rs`, etc.) | Reporting and evidence generation; no enforcement role |
| SDKs (Python, TypeScript, Go) | Client libraries; cannot weaken server-side enforcement |

## TCB Reduction Strategy

The TCB is intentionally narrow:

1. **No network code.** The TCB never opens sockets, parses HTTP, or handles TLS. Network input reaches the TCB only as validated `Action` structs.
2. **No serialization in the hot path.** Policy evaluation operates on pre-parsed, pre-compiled structures. JSON parsing happens outside the TCB.
3. **No dynamic memory allocation on the evaluation hot path.** Pre-compiled patterns use stack-allocated matching. This eliminates allocator bugs as an attack surface.
4. **No unsafe code.** The TCB files contain zero `unsafe` blocks. Memory safety is guaranteed by the Rust compiler.
5. **Fail-closed by default.** Every error path in the TCB produces `Verdict::Deny`. There is no error path that produces `Verdict::Allow`.

## Verification Coverage

| Verification Method | Coverage |
|---------------------|----------|
| TLA+ model checking | S1–S6 (policy core), S7–S10 (ABAC) |
| Alloy bounded model checking | S11–S16 (capability delegation) |
| Lean 4 theorem proving | Determinism, fail-closed, path normalization idempotence |
| Property-based testing (proptest) | Idempotence, traversal prevention, deterministic evaluation |
| Fuzzing (cargo-fuzz) | `normalize_path`, `normalize_path_bounded` |
| Unit tests | ~8,500 tests in `engine_tests.rs` alone |
| Integration tests | ~100 test files in `vellaveto-integration/tests/` |
| Adversarial tests | 60+ attack scenarios in `full_attack_battery.rs` |
