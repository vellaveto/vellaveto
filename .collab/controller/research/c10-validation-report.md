# C-10.4 C1: Architectural Decision Validation Report

**Author:** Controller
**Date:** 2026-02-02
**Directive:** C-10.4 Task C1
**Method:** Web research via 5 dedicated research agents + direct code review

---

## Executive Summary

All 5 architectural decisions validated. No changes required to core technology choices. Two actionable findings: (1) `governor` should be upgraded from 0.6 to 0.10, (2) injection detection needs Unicode control character sanitization. One security finding from code review: API key comparison is not constant-time.

---

## 1. `arc-swap` for Lock-Free Policy Reads

**Verdict: KEEP — No changes needed**

### Findings

- **Latest version:** 1.7.1 on crates.io (Sentinel uses 1.8.1 from Cargo.lock — possibly a pre-release or recent publish).
- **Maintenance:** Actively maintained by vorner. 143M+ total downloads. Issues triaged as of January 2026.
- **Security:** One historical advisory (RUSTSEC-2020-0091, fixed in 1.1.0). No CVEs since 2020. Passes Miri validation.
- **Pattern validation:** `Arc<ArcSwap<Vec<Policy>>>` is the correct and canonical wrapping. `ArcSwap<T>` internally stores `Arc<T>`, so the outer `Arc` is needed for `Clone` (Axum state extraction).
- **Access patterns:** `load()` for reads (lock-free, mostly wait-free), `rcu()` for atomic updates, `store()` for direct replacement — all correct.

### Alternatives Evaluated

| Alternative | Why Not |
|-------------|---------|
| `left-right` | 2x memory, overkill for Vec replacement |
| `DashMap` | Wrong granularity — Sentinel replaces entire Vec, not individual keys |
| `tokio::sync::watch` | Internal RwLock, not lock-free |
| `std::sync::RwLock` | Readers can block writers, performance degrades under contention |

### Minor Finding

`remove_policy()` in `sentinel-server/src/routes.rs:282-287` uses `load()` then `store()` — not atomic with respect to concurrent writers (TOCTOU). `add_policy()` correctly uses `rcu()`. Low risk since admin operations are rare and typically single-operator, but inconsistent. Recommend switching `remove_policy` to `rcu()` for consistency.

---

## 2. SHA-256 for Audit Hash Chain

**Verdict: KEEP — Do not switch to BLAKE3**

### Findings

- Both SHA-256 and BLAKE3 provide 128-bit collision resistance (birthday bound on 256-bit output). Security-equivalent for this use case.
- **Performance is irrelevant:** Hashing a few hundred bytes per audit entry costs <1μs either way. JSON serialization and file I/O dominate.
- **Industry standard:** Certificate Transparency (RFC 6962/9162), Sigstore/Rekor, Google Trillian, and Git all use SHA-256. Only one project (Spine) uses BLAKE3 for audit logs.
- **FIPS compliance:** SHA-256 is NIST FIPS 180-4. BLAKE3 is NOT FIPS-approved — would disqualify government/regulated-industry users.
- **Interoperability:** External auditors can verify with `sha256sum`. BLAKE3 requires specialized tooling (`b3sum`).
- **Length extension:** SHA-256's Merkle-Damgard construction is theoretically vulnerable to length extension attacks, but Sentinel's hash chain uses length-prefixed fields (not H(secret||message)), so this is not exploitable.

### Reference Project

**Spine** (github.com/EulBite/spine-oss): Open-source tamper-evident audit logging using BLAKE3 + Ed25519. Interesting validation of the overall approach but uses BLAKE3 primarily for performance in high-throughput logging scenarios that don't apply to Sentinel's workload.

---

## 3. `governor` for GCRA Rate Limiting

**Verdict: KEEP — Upgrade version from 0.6 to 0.10**

### Findings

- **Latest version:** 0.10.4 (January 2026). Sentinel uses 0.6.3 — **4 major versions behind**.
- **Maintenance:** 7+ releases in 2025 alone. 40M+ all-time downloads.
- **Security:** Zero CVEs, zero RustSec advisories.
- **GCRA still best practice:** Used by Cloudflare, Stripe. 64-bit state per key (just a TAT timestamp). Thread-safe via CAS, ~10x faster than mutex alternatives.
- **API stability:** `DefaultDirectRateLimiter`, `Quota::per_second()`, `RateLimiter::direct()`, `.check()` all confirmed present in 0.10.x.
- **DashMap concern:** Only affects keyed rate limiters. Sentinel uses direct (non-keyed) limiters — single 64-bit cell, no DashMap, no memory growth.

### Alternatives Evaluated

| Alternative | Why Not |
|-------------|---------|
| `tower-governor` | Requires axum 0.8 (Sentinel is on 0.7). Useful if adding per-IP limiting later. |
| `tower::limit::RateLimitLayer` | Too basic — no per-key, no GCRA, no burst config |
| `axum-governor` | Token bucket, not GCRA. Less battle-tested. |

### Action Required

```toml
# sentinel-server/Cargo.toml
# Before
governor = "0.6"
# After
governor = "0.10"
```

Low-risk change — core API surface is stable. Verify with `cargo check -p sentinel-server` after bumping.

---

## 4. Prompt Injection Detection Patterns

**Verdict: Current 15 patterns are ADEQUATE for v1 — Enhancement needed for v2**

### Current State

15 hardcoded patterns in `sentinel-mcp/src/proxy.rs:280-296`, covering:
- Instruction override (4 patterns)
- Identity hijack (3 patterns)
- System prompt manipulation (4 patterns)
- Tag injection (3 patterns)
- Escaped newline system prompt (1 pattern)

### Research Findings

2025 research (Mindgard, Cisco, Keysight, AWS, Palo Alto Unit 42) identifies multiple evasion techniques that bypass pattern-based detection:

| Attack Type | Success Rate vs. Guardrails | Sentinel Vulnerable? |
|-------------|---------------------------|---------------------|
| Base64 encoding | 64-94% | **Yes** — no encoding detection |
| Homoglyphs (Cyrillic/Latin) | Up to 92% | **Yes** — ASCII-only matching |
| Zero-width characters | ~54% | **Yes** — no Unicode sanitization |
| Unicode tag chars (U+E0000-E007F) | High (varies) | **Yes** — invisible to pattern matching |
| Variation selectors | Emerging | **Yes** — no handling |
| Emoji smuggling | Up to 100% | **Yes** — no handling |

### Recommendation for v2 Enhancement

Add a pre-processing step before pattern matching:

1. **Strip Unicode control characters:** Remove U+E0000-E007F (tags), U+200B-U+200F (zero-width), U+202A-U+202E (bidi overrides), U+FE00-U+FE0F (variation selectors).
2. **Apply NFKC normalization:** Canonicalize homoglyphs and fullwidth characters.
3. **Detect Base64 in responses:** Flag strings matching `^[A-Za-z0-9+/]{20,}={0,2}$` that decode to injection patterns.

This is additive — existing patterns remain, preprocessing catches obfuscated variants.

### Known Limitation

The `\\n\\nsystem:` pattern at line 295 matches literal backslash-n characters, not actual newlines. This is technically correct for JSON string content (where real newlines would be `\n` escape sequences), but the double-escaping is confusing. Confirmed by Instance A's cross-review (finding #6). Recommend adding a code comment explaining the intent.

---

## 5. MCP Protocol Specification Status

**Verdict: Sentinel is well-aligned with current spec. No breaking changes needed.**

### Spec Status

- **Current version:** 2025-11-25 (unchanged since Sentinel's implementation).
- **Next version:** Tentatively planned for June 2026 (SEPs being finalized Q1 2026).
- **Governance:** MCP donated to AAIF (Agentic AI Foundation) under Linux Foundation in December 2025. Technical direction unchanged — existing maintainers via SEP process.

### Key Spec Features (2025-11-25)

| Feature | Sentinel Status |
|---------|----------------|
| Tool annotations (readOnlyHint, destructiveHint, etc.) | **Implemented** — rug-pull detection |
| sampling/createMessage | **Blocked** — correct security posture |
| Protocol version negotiation | **Tracked** — version stored and audited |
| Streamable HTTP transport | **Not implemented** — biggest market gap |
| OAuth 2.1 authorization | **Not implemented** — needed for Streamable HTTP |
| Async Tasks primitive | **Not handled** — new in 2025-11-25 |
| Enhanced sampling (tool calling within sampling) | **Blocked wholesale** — may need nuance for trusted servers |

### MCP Apps Extension (SEP-1865, January 2026)

New extension enabling interactive UIs via `ui://` URI scheme. Supported in Claude, ChatGPT, Goose, VS Code. Uses `postMessage` transport in sandboxed iframes. **Low priority for Sentinel** — MCP Apps is UI-focused, not tool-call focused. Monitor but don't implement yet.

### Notable Security Incidents (2025-2026)

| Incident | Root Cause | Sentinel Mitigation |
|----------|-----------|---------------------|
| GitHub MCP Server data exfiltration | Over-privileged PAT + untrusted content | Policy-based tool restriction |
| WhatsApp history stolen via tool poisoning | Cross-server tool poisoning | Rug-pull detection + per-tool policies |
| CVE-2025-6514 (mcp-remote RCE, CVSS 9.6) | Command injection in mcp-remote | Parameter constraint validation |
| ~7,000 MCP servers exposed on web | No authentication | Auth middleware + bind 127.0.0.1 default |
| Malicious npm MCP server (email exfil) | Supply chain attack | Audit logging + tool allowlisting |

These incidents **validate Sentinel's architecture**. The most common attack patterns (over-privileged access, tool poisoning, command injection, no auth) are directly addressed.

### Recommended Future Work

1. **Tasks primitive support:** Intercept `tasks/get`, `tasks/cancel`, apply policies to task results.
2. **Nuanced sampling policy:** Allow sampling from trusted servers but strip/validate tool definitions.
3. **Streamable HTTP transport:** Single biggest market-relevance gap. Plan in Phase 9.
4. **MCP01 (Token Exposure):** Detect API keys/tokens in tool call parameters before forwarding.

---

## Additional Finding: Controller Code Review

### Security Finding: Non-Constant-Time API Key Comparison

**File:** `sentinel-server/src/routes.rs:128` (approx)
**Severity:** LOW (timing side-channel)

The `require_api_key` middleware compares the bearer token using `token == api_key.as_str()`, which is a standard string equality check (short-circuits on first mismatch). This is theoretically vulnerable to timing side-channel attacks where an attacker can determine how many leading characters of the API key are correct by measuring response time.

**Practical risk:** Very low. The timing difference is nanoseconds over a network connection with milliseconds of jitter. Exploiting this requires millions of precisely-timed requests, and the rate limiter would throttle the attacker long before meaningful information leaks. Additionally, the API key is typically a high-entropy random string, making character-by-character brute force infeasible.

**Recommendation:** Use `subtle::ConstantTimeEq` from the `subtle` crate (already in the dependency tree via `sha2` → `digest` → `subtle`) for defense in depth, even though the practical risk is minimal.

### Cross-Review Finding: Instance A's Review Corroborates Research

Instance A's review (`review-b-by-a.md`) independently identified finding #6: "Injection patterns are ASCII-only (no Unicode homoglyph detection)." This aligns with the research agent's findings on Unicode evasion techniques. Both sources converge on the same recommendation: add Unicode normalization/sanitization as a preprocessing step.

---

## Summary of Actions

| # | Action | Priority | Owner | Impact |
|---|--------|----------|-------|--------|
| 1 | Upgrade governor 0.6 → 0.10 | MEDIUM | Instance A or B | 4 major versions behind, bug fixes |
| 2 | Add Unicode sanitization to injection scanner | MEDIUM | Instance B | Addresses 5+ evasion techniques |
| 3 | Switch `remove_policy` to `rcu()` | LOW | Instance A | Consistency with `add_policy` |
| 4 | Add constant-time API key comparison | LOW | Instance A | Defense in depth |
| 5 | Add comment to `\\n\\nsystem:` pattern | LOW | Instance B | Code clarity |
| 6 | Plan Tasks primitive interception | FUTURE | Orchestrator | New spec feature |
| 7 | Plan Streamable HTTP transport | FUTURE | Orchestrator | Biggest market gap |

**All core technology choices are validated. No architectural changes needed.**
