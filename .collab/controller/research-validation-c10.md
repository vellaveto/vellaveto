# Controller Research Validation — Directive C-10

**Date:** 2026-02-02
**Purpose:** Validate Sentinel's architectural decisions against current best practices via web research.

---

## 1. ArcSwap for Lock-Free Policy Reads

**Decision:** Replaced `Arc<RwLock<Vec<Policy>>>` with `Arc<ArcSwap<Vec<Policy>>>`.

**Findings:**
- `arc-swap` remains the standard crate for this pattern. Read operations are wait-free most of the time, with `usize::MAX / 4` wait-free accesses guaranteed between potential waits.
- Performance is similar to uncontended Mutex for baseline, but `load()` suffers no contention from concurrent reads and only slight contention during updates — ideal for read-heavy policy evaluation.
- Two newer alternatives exist: `arcshift` (proposed as Crate of the Week Dec 2025, slightly different API, not Arc-compatible) and `swap-arc` (claims faster on x86_64).
- Writer performance is intentionally slow (not lock-free) — this is fine for our use case where writes (policy reload) are rare admin operations.

**Recommendation: KEEP.** `arc-swap` is battle-tested, well-documented, and fits our read-heavy workload. The `Cache` module could be explored for even faster reads in hot paths if benchmarks show it's needed. No action needed.

**Sources:**
- [arc-swap docs](https://docs.rs/arc-swap)
- [arc-swap performance](https://docs.rs/arc-swap/latest/arc_swap/docs/performance/index.html)
- [arcshift alternative](https://crates.io/crates/arcshift)

---

## 2. SHA-256 Hash Chain for Tamper-Evident Audit Logs

**Decision:** SHA-256 with length-prefixed field encoding and `prev_hash` chaining.

**Findings:**
- SHA-256 remains the standard for tamper-evident audit logging, especially in regulated industries (EU AI Act Article 12, MiFID II, SEC Rule 17a-4).
- BLAKE3 is ~14x faster than SHA-256 (especially for large data, parallel hashing), but is not yet as standardized for compliance-sensitive deployments.
- The VeritasChain Protocol proposes a 3-layer architecture: (1) SHA-256 hash chain + Ed25519 signatures, (2) Merkle trees with Signed Tree Heads, (3) external blockchain anchoring. Our current implementation covers Layer 1.
- Length-prefixed encoding (our approach) is correct — prevents field boundary collision attacks.
- Key gap: We don't have Ed25519 signatures on entries (Layer 1 enhancement) or Merkle tree anchoring (Layer 2). These are in the improvement plan as Phase 10.3 (signed checkpoints).

**Recommendation: KEEP SHA-256, plan BLAKE3 as optional.** SHA-256 is correct for compliance. BLAKE3 could be offered as a configuration option for high-throughput deployments. The signed checkpoint design (Ed25519, Phase 10.3) should proceed — it fills the gap between our Layer 1 and Layer 2 coverage.

**Sources:**
- [Building Tamper-Evident Audit Logs with SHA-256](https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b)
- [SHA-256 vs BLAKE3](https://mojoauth.com/compare-hashing-algorithms/sha-256-vs-blake3)
- [Choosing a Hash for 2030+](https://kerkour.com/fast-secure-hash-function-sha256-sha512-sha3-blake3)

---

## 3. Governor Rate Limiter with Axum

**Decision:** `governor = "0.6"` for per-category rate limiting.

**Findings:**
- `governor` remains the dominant rate-limiting library for Rust. `tower-governor` wraps it for Tower/Axum integration and is the most popular choice.
- Alternatives emerging: `axum_gcra` (per-route GCRA, composite keys), `axum-governor` (confusingly named, uses `lazy-limit` instead, Rust 2024, memory-safe GC), `axum_rate_limiter` (multi-strategy).
- Our direct `governor` usage (not via `tower-governor`) gives us more control over category-based limiting, which is correct for our use case (evaluate/admin/readonly categories).
- Gap identified: No per-IP rate limiting. `tower-governor` supports `PeerIpKeyExtractor` out of the box. For our use case, per-category is sufficient for now, but per-IP could be added for the evaluate endpoint.

**Recommendation: KEEP.** Direct `governor` usage is appropriate for category-based limiting. Consider adding per-IP limiting for the evaluate endpoint in a future phase if abuse is observed. The `Retry-After` header improvement (Task A1) is aligned with best practices.

**Sources:**
- [tower-governor](https://github.com/benwis/tower-governor)
- [Rate Limiting in Rust (Shuttle)](https://www.shuttle.dev/blog/2024/02/22/api-rate-limiting-rust)
- [Production REST APIs in Rust with Axum](https://oneuptime.com/blog/post/2026-01-07-rust-axum-rest-api/view)

---

## 4. Prompt Injection Detection Patterns

**Decision:** 15 regex patterns scanning tool responses for injection indicators.

**Findings:**
- OWASP MCP06:2025 recommends monitoring for: unexpected tool invocation after document retrieval, semantic anomalies (retrieved content mapping to tool calls), behavioral shifts with new content sources, and imperative verb-plus-API-name patterns.
- OWASP recommends NLP-based detectors scanning for instruction-like phrases: "ignore previous", "delete", "export", "send to" — this aligns with our regex-based approach.
- The field is moving toward layered defense: (1) input sanitization (strip metadata, invisible chars, control sequences), (2) NLP-based pattern detection, (3) output schema validation, (4) provenance tracking with trust scores.
- Real-world incidents validate our approach: GitHub Copilot CVE-2025-53773 (injection via code comments), Supabase Cursor agent exploitation (SQL injection via support tickets), 43% of MCP servers have command injection flaws.
- Gap: Our 15 regex patterns are a solid first layer, but OWASP recommends also checking for invisible characters, control sequences, and metadata manipulation. We should consider adding Unicode control character detection.
- Specialized tools exist: MCPTox, MindGuard for MCP-specific monitoring. These could be referenced as complementary to our built-in scanning.

**Recommendation: IMPROVE.** Our 15 patterns are a good start and align with OWASP recommendations. Enhancements to consider:
1. Add invisible/zero-width character detection (Unicode U+200B, U+200C, U+200D, U+FEFF)
2. Add metadata stripping (PDF properties, docx custom props) — relevant if tools return file content
3. Consider configurable pattern sets (allow users to add domain-specific patterns)
4. Add provenance tracking (source trust score per tool)

**Sources:**
- [OWASP MCP06:2025](https://owasp.org/www-project-mcp-top-10/2025/MCP06-2025%E2%80%93Prompt-InjectionviaContextual-Payloads)
- [Practical DevSecOps MCP Security](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Lakera Indirect Prompt Injection](https://www.lakera.ai/blog/indirect-prompt-injection)

---

## 5. MCP Protocol Version

**Decision:** Implemented support for version 2025-11-25.

**Findings:**
- The latest published MCP spec is **2025-11-25** — we are current.
- No 2026 version has been released yet.
- MCP was donated to the Agentic AI Foundation (AAIF) under the Linux Foundation in Dec 2025, co-founded by Anthropic, Block, and OpenAI.
- Active development continues with 5 focus areas: async operations, protocol extensions, SDK tiering, transport improvements, server discovery via .well-known URLs.
- MCP Apps Extension is now live — tools can return interactive UI components (dashboards, forms, visualizations).
- Stats: 97M+ monthly SDK downloads, 10,000+ active servers, supported by ChatGPT, Claude, Cursor, Gemini, Microsoft Copilot, VS Code.
- June 2025 spec update added: structured tool outputs, OAuth 2.1 as Resource Servers (RFC 8707), elicitation capability.

**Recommendation: KEEP, monitor.** We are on the latest spec. Key items to watch:
1. Async operations (will require proxy changes for long-running tool calls)
2. MCP Apps Extension (may need UI component pass-through in proxy)
3. .well-known server discovery (Phase 9.4 in our plan)
4. OAuth 2.1 Resource Server requirements (Phase 9.3)

**Sources:**
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP Next Version Update](https://modelcontextprotocol.info/blog/mcp-next-version-update/)
- [MCP Spec Updates June 2025](https://auth0.com/blog/mcp-specs-update-all-about-auth/)
- [MCP Wikipedia](https://en.wikipedia.org/wiki/Model_Context_Protocol)

---

## Summary

| Area | Decision | Verdict | Action |
|------|----------|---------|--------|
| ArcSwap | Lock-free policy reads | **KEEP** | No changes needed |
| SHA-256 Hash Chain | Tamper-evident audit | **KEEP** | Plan BLAKE3 option, proceed with signed checkpoints |
| Governor | Rate limiting | **KEEP** | Add Retry-After header (Task A1), consider per-IP later |
| Injection Detection | 15 regex patterns | **IMPROVE** | Add Unicode control chars, configurable patterns |
| MCP Protocol | Version 2025-11-25 | **KEEP** | Monitor for async ops, MCP Apps, .well-known |

All core architectural decisions are validated. No fundamental changes needed. Two improvement areas identified (injection detection enhancement, BLAKE3 option) — both are additive, not corrective.
