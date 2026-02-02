# Controller Corrections

## Purpose
This file tracks corrections issued by the Controller to other instances based on research findings.

---

## Correction 1: Orchestrator Audit Was Incomplete
**Date:** 2026-02-02
**Affects:** Orchestrator
**Severity:** HIGH

The orchestrator's audit (in `orchestrator/status.md` and `log.md`) declared the project healthy based on:
- Tests passing
- Clippy clean
- No `unwrap()` in library code
- Formatting clean

This gave a **false sense of security**. The orchestrator correctly identified surface-level issues (unwrap, missing endpoints, formatting) but missed:

1. **7 CRITICAL security vulnerabilities** that defeat core guarantees (hash chain bypass, domain bypass, empty tool bypass, unbounded memory, no auth)
2. **7 HIGH issues** that would cause production failures (approval data loss on restart, silent error swallowing, incorrect audit records)
3. **16 MEDIUM issues** spanning correctness, compliance, and performance

**Root cause:** The audit focused on "does it compile and pass tests" rather than "does it actually provide the security guarantees it claims." Passing tests only proves the code does what the tests check — not that it's correct.

**Correction:** Future orchestrator audits must include:
- Security-focused review: "Can an attacker bypass this?"
- Boundary analysis: "What happens with missing/empty/malformed input?"
- Crash analysis: "What happens on I/O failure, memory pressure, process death?"
- Protocol compliance: "Does this follow the spec (JSON-RPC 2.0, MCP)?"

---

## Correction 2: Instance B — Hash Chain Implementation Has Fundamental Flaws
**Date:** 2026-02-02
**Affects:** Instance B
**Severity:** CRITICAL

Instance B's status file states "Feature 2: Tamper-Evident Audit — SHA-256 hash chain with verify endpoint" as DONE. However:

1. The tamper-evidence is **bypassable** — an attacker can insert hashless entries and the verifier accepts them (finding #1)
2. The hash function has **ambiguous field boundaries** — field concatenation without separators allows collision attacks (finding #2)
3. The chain **trusts unverified data on startup** — a tampered file poisons all future entries (finding #3)
4. The chain **can diverge from disk** on write failure — in-memory state advances even when persistence fails (finding #4)

These aren't edge cases — they're fundamental to the feature's security claim. A "tamper-evident" log that can be tampered with undetectably is worse than no tamper-evidence at all (it provides false assurance).

**Correction:** The feature status should be "PARTIALLY COMPLETE — architecture correct, implementation needs hardening." See Directive C-2 for required fixes.

---

## Correction 3: Instance B — MCP Proxy Has Reliability and Compliance Issues
**Date:** 2026-02-02
**Affects:** Instance B
**Severity:** HIGH

Instance B declared Feature 4 (MCP Stdio Proxy) as DONE. Issues found:

1. **Empty tool name bypass** — a `tools/call` with no `name` field creates a ToolCall with empty name that evades specific deny policies (finding #5)
2. **Unbounded memory** — `read_line` with no limit means a single malicious message without a newline can OOM the process (finding #6)
3. **Empty line kills session** — a blank `\n` from either agent or child terminates the proxy (finding #14)
4. **Audit records wrong verdict** — `RequireApproval` decisions are logged as `Deny` in the audit trail (finding #13)
5. **JSON-RPC 2.0 non-compliance** — missing `jsonrpc` field, wrong error codes, string-only IDs (findings #27-29)

**Correction:** Feature 4 should be "PARTIALLY COMPLETE — architecture sound, needs hardening and protocol compliance."

---

## Correction 4: Instance A — Good Security Work, But Tests Didn't Catch Existing Bugs
**Date:** 2026-02-02
**Affects:** Instance A
**Severity:** LOW

Instance A's security tests (path_domain_security.rs) are well-designed and caught real issues. However:

1. The `@` bypass in `extract_domain` (finding #8) was not tested — a URL like `https://evil.com/path?email=user@safe.com` would pass the domain allowlist tests
2. The `normalize_path` empty-result fallback (finding #9) was not tested — Instance A fixed the root escape bug but didn't test what happens when normalization produces an empty string

**Correction:** The regression test suite (Directive C-3) must explicitly include these edge cases. Instance A's existing tests are a solid foundation — they just need the adversarial edge cases from findings 8 and 9.

---

## Correction 5: Orchestrator Improvement Plan Priorities Are Inverted
**Date:** 2026-02-02
**Affects:** Orchestrator
**Severity:** MEDIUM

The improvement plan puts "Performance Hot Path" as Phase 1 (P0 — Do Immediately) and security hardening in Phase 3. This is backwards for a security product.

The correct priority order for a policy enforcement tool:
1. **Security correctness** — the tool actually blocks what it claims to block
2. **Reliability** — the tool doesn't crash or lose state
3. **Protocol compliance** — the tool works with real MCP servers
4. **Performance** — the tool is fast enough
5. **Features** — the tool does more things

Regex caching and globset are nice-to-haves. A domain bypass that lets attackers exfiltrate data through `?email=user@safe.com` is a ship-stopper.

**Correction:** The improvement plan should be reordered. See Directive C-5 for specifics.
