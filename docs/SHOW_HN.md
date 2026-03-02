# Show HN Launch Kit

## Title Options

Pick one (recommendation: Option 1 for understated technical tone):

1. `Show HN: VellaVeto – Runtime security engine for AI agent tool calls (Rust)`
2. `Show HN: VellaVeto – Open-source security control plane for MCP and AI agents`
3. `Show HN: VellaVeto – We built a fail-closed security engine for AI tool calls, with Coq proofs`

**Link to:** `https://github.com/vellaveto/vellaveto`

## First Comment (post immediately after submission)

---

Hi HN, I'm Paolo.

I built VellaVeto because AI agents with tool access — reading files, making HTTP requests, executing commands — have no standard security layer. MCP gives agents a protocol to call tools, but the protocol itself has no policy enforcement, no audit trail, and no identity model. In the last 15 months, the ecosystem has accumulated 30+ CVEs: tool poisoning, rug-pull attacks, path traversal in Anthropic's own reference servers, command injection via OAuth endpoints in mcp-remote (CVSS 9.6).

**What VellaVeto does:** It sits between AI agents and tool servers as a runtime security engine. Every tool call is evaluated against policy before execution. It's deny-by-default — no policy match, missing context, or any evaluation error produces `Deny`. It works across MCP (stdio, HTTP, WebSocket, gRPC, SSE) and function-calling APIs. Beyond the gateway, it includes topology discovery (auto-inventorying MCP servers and tools), identity-aware access control (OIDC/SAML/RBAC/capability delegation), and a tamper-evident audit trail with evidence packs for compliance frameworks.

**Technical approach:** Written in Rust with a synchronous policy engine. <5ms P99 evaluation latency, <50MB memory baseline. The policy DSL supports glob/regex/domain matching, parameter constraints, time windows, call sequences, Cedar-style ABAC, and Wasm plugins for custom logic.

**What I think is genuinely different:**

- *Formal verification.* We wrote TLA+ specs, Lean 4 proofs, and Coq theorems proving fail-closed behavior, evaluation determinism, and that capability delegation can't escalate privileges. I haven't seen this in other security tools in this space. The proofs are in `formal/` — they're real, not marketing.

- *Depth of threat detection.* Not just regex patterns — 20+ detection layers including Aho-Corasick pattern matching, NFKC Unicode normalization, ROT13/base64/leetspeak obfuscation decode, mathematical alphanumeric symbol normalization, emoji smuggling via regional indicators, schema poisoning detection, memory poisoning detection, multi-agent collusion analysis. Each layer was added because we found real bypasses.

- *Consumer privacy shield.* A deployment mode that runs on the user's device and sanitizes PII before it reaches any server. Bidirectional — replaces PII with placeholders outbound, restores them inbound. Includes stylometric fingerprint resistance and session unlinkability.

- *Transport parity.* Every security check works identically across HTTP, WebSocket, gRPC, stdio, and SSE. We maintain a 13-feature parity matrix and verify it on every change.

**Honest caveats:**

- The 232 security audit rounds are **internal** — systematic red-teaming where we attack our own code. They are not third-party audits. The methodology and all findings are documented in the changelog and security review docs. We'd welcome independent review.
- Injection detection is a pre-filter, not a security boundary. A sufficiently novel injection will get through.
- DLP does not detect secrets split across multiple tool calls.
- The project is complex (19 Rust crates). If you just need a quick guard on a single Claude Desktop session, simpler tools like Agent-Wall (`npm install -g`) or PipeLock (single Go binary) may be better fits.
- Enterprise crates use BUSL-1.1, which is not OSI-approved open source. Core crates (types, engine, audit, config, discovery) are MPL-2.0. Each BSL version converts to MPL-2.0 after 3 years. Free for ≤3 nodes.

I'd particularly value feedback on:
- The threat model (`docs/THREAT_MODEL.md`) — what are we missing?
- The policy DSL — is the TOML syntax intuitive or would you prefer something else?
- Whether the formal verification approach adds real value or is over-engineering

Happy to discuss design decisions, tradeoffs, or anything else.

---

## Timing

**Best days:** Tuesday, Wednesday, or Thursday
**Best time:** 8:00–10:00 AM US Eastern (1:00–3:00 PM UTC)

## Preparation Checklist

- [ ] Test `docker pull ghcr.io/vellaveto/vellaveto:latest && docker run` on a fresh machine
- [ ] Test `cargo install vellaveto-proxy` compiles cleanly on fresh Rust install
- [ ] Verify README renders correctly on GitHub (images, badges, mermaid diagram)
- [ ] Set GitHub social preview image (Settings → Social preview → Upload vellaveto_brandkit/social/og-card.png)
- [ ] Have 3-5 people ready to try it and leave honest comments (NOT upvote — comment)
- [ ] Block calendar for 4-6 hours after posting
- [ ] Prepare responses for common objections (see below)

## Expected Objections and Responses

### "BUSL-1.1 is not open source"

You're right — BUSL-1.1 is not OSI-approved. We use it for enterprise crates (server, http-proxy, operator) to sustain development. Core security crates — types, engine, audit, config, discovery — are MPL-2.0. Every BSL version converts to MPL-2.0 after 3 years. Free for ≤3 nodes / ≤25 endpoints. We chose this over AGPL because AGPL's network-use clause creates uncertainty for proxy deployments.

### "232 audit rounds — by whom?"

Internal red-teaming, not third-party. We attack our own code systematically: pick an attack class, enumerate vectors, write exploits, document findings, fix them, write regression tests, verify fixes. It's documented in the changelog (every round has a commit) and docs/SECURITY_REVIEW.md. We'd welcome independent review — if a security firm wants to audit it, we'll make it easy.

### "Why not just use Agent-Wall / PipeLock?"

Great tools for quick single-agent setups. If you need centralized governance across multiple agents, compliance evidence for regulated industries, multi-transport coverage, or formal verification of security properties, VellaVeto covers that. We link to both in our comparison table and recommend them for simpler use cases.

### "This is over-engineered"

For a single developer running Claude Desktop, yes. VellaVeto is designed for teams deploying multiple agents across production environments where you need audit trails, compliance evidence, and centralized policy. We offer simpler entry points (stdio proxy, Docker one-liner) but the full control plane is intentionally comprehensive.

### "Why Rust?"

Fail-closed security engine needs: no panics (we enforce zero `unwrap()` in library code), predictable latency (no GC pauses), memory safety without runtime overhead. Rust's type system also makes it harder to accidentally pass unvalidated input to security-critical functions. The tradeoff is compile time and ecosystem complexity.

### "Formal verification of what exactly?"

Specific properties, not the entire system. TLA+ verifies the policy engine's state machine is deterministic and that ABAC forbid-overrides work correctly. Lean 4 proves that error paths always produce Deny (fail-closed). Coq proves capability delegation can't escalate privileges. These are the properties where bugs would be hardest to detect through testing alone. The proofs are in `formal/` — we'd love feedback on whether we're proving the right things.
