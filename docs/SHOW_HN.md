# Show HN Launch Kit

## Title Options

Pick one (recommendation: Option 1 — concrete, visceral, demo-first):

1. `Show HN: VellaVeto – Firewall that blocks AI agents from reading your credentials (Rust, <5ms)`
2. `Show HN: VellaVeto – Runtime firewall for AI agent tool calls, with formal proofs it can't fail open`
3. `Show HN: VellaVeto – We wrote Coq proofs that our MCP firewall always denies on error`
4. `Show HN: VellaVeto – One flag to stop AI agents from exfiltrating your AWS credentials`

Avoid: "security engine", "control plane", "governance layer", "policy engine" — these are abstract and HN Show HNs with them consistently get 1-5 points. Lead with what it **blocks**, not what it **is**.

**Link to:** `https://github.com/vellaveto/vellaveto`

## First Comment (post immediately after submission)

---

Hi HN, I'm Paolo.

I built VellaVeto because AI agents with tool access — reading files, making HTTP requests, executing commands — have no standard security layer. MCP gives agents a protocol to call tools, but the protocol itself has no policy enforcement, no audit trail, and no identity model. In the last 15 months, the ecosystem has accumulated 30+ CVEs: command injection in `mcp-remote` (CVE-2025-6514, CVSS 9.6), path traversal in Anthropic's own Git MCP server (CVE-2025-68143/44/45), SANDWORM npm supply-chain worms injecting rogue MCP servers into AI configs, and 8,000+ MCP servers found exposed with no authentication.

**What VellaVeto does:** It sits between AI agents and tool servers as a runtime security engine. Every tool call is evaluated against policy before execution. No policy match, missing context, or any evaluation error produces `Deny`. It works across MCP (stdio, HTTP, WebSocket, gRPC, SSE) and function-calling APIs.

**Try it in 30 seconds:**

```
cargo install vellaveto-proxy
vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp
```

That's it — credentials blocked, dangerous commands blocked, injection scanning on, DLP on. Three protection levels: `shield` (just works), `fortress` (adds exfil domain blocking + AI config protection), `vault` (default deny). No YAML, no config files, no security domain knowledge needed. Works with Claude Desktop, Cursor, Windsurf, or any MCP client — just wrap the server command.

Beyond the one-liner, VellaVeto includes topology discovery (auto-inventorying MCP servers and tools), identity-aware access control (OIDC/SAML/RBAC/capability delegation), and a tamper-evident audit trail with evidence packs for compliance frameworks.

**Technical approach:** Written in Rust with a synchronous policy engine. <5ms P99 evaluation latency, <50MB memory baseline. The policy DSL supports glob/regex/domain matching, parameter constraints, time windows, call sequences, Cedar-style ABAC, and Wasm plugins for custom logic.

**What I think is genuinely different:**

- *Consumer privacy shield.* When AI providers process your tool calls, they see your file paths, credentials, browsing patterns, and work context. The Consumer Shield is a user-side deployment mode that strips PII before it reaches any provider — bidirectional replacement with placeholders outbound, restoration inbound. It also includes encrypted local audit (so you have a provable record of what was shared), session unlinkability (provider can't link your sessions to build a profile), credential vault (tool credentials never reach the provider), and stylometric fingerprint resistance. This was built before recent news about AI providers partnering with enterprises for broad data access — but that kind of arrangement is exactly why users need their own controls. Licensed MPL-2.0, no enterprise license required.

- *Formal verification.* We wrote TLA+ specs, Lean 4 proofs, and Coq theorems proving fail-closed behavior, evaluation determinism, and that capability delegation can't escalate privileges. I haven't seen this in other security tools in this space. The proofs are in `formal/` — they're real, not marketing.

- *Depth of threat detection.* Not just regex patterns — 20+ detection layers including Aho-Corasick pattern matching, NFKC Unicode normalization, ROT13/base64/leetspeak obfuscation decode, mathematical alphanumeric symbol normalization, emoji smuggling via regional indicators, schema poisoning detection, memory poisoning detection, multi-agent collusion analysis. Each layer was added because we found real bypasses.

- *Transport parity.* Every security check works identically across HTTP, WebSocket, gRPC, stdio, and SSE. We maintain a 13-feature parity matrix and verify it on every change.

- *Open security benchmark.* We built [MCPSEC](mcpsec/), an open, vendor-neutral security benchmark for MCP gateways (Apache-2.0). It defines 10 formal security properties and 64 reproducible attack test cases across 12 attack classes. Run it against any gateway — including ours — and get a Tier 0-5 security score. We score 100/100 (Tier 5: Hardened, 64/64 tests passed). Run `cargo run -p mcpsec -- --target http://localhost:3000` to verify.

**Honest caveats:**

- The 232 security audit rounds are **internal** — systematic red-teaming where we attack our own code. They are not third-party audits. The methodology and all findings are documented in the changelog and security review docs. We'd welcome independent review.
- Injection detection is a pre-filter, not a security boundary. A sufficiently novel injection will get through.
- DLP does not detect secrets split across multiple tool calls.
- The project is complex (19 Rust crates), but you don't need to understand any of it — `--protect shield` gives you solid defaults in one flag. If you want something simpler, [PipeLock](https://github.com/luckyPipewrench/pipelock) (single Go binary) is a good alternative.
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
- [ ] Test `vellaveto-proxy --protect shield -- echo test` works after install
- [ ] Test `vellaveto-proxy --list-presets` shows grouped output (protection levels first)
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

### "Why not just use AgentGateway / MCP-Scan / PipeLock?"

Different tools, different problems. AgentGateway (~1,800 stars, Linux Foundation) is a connectivity proxy for routing agent traffic — great infrastructure, but no runtime policy engine. MCP-Scan (~1,700 stars, Snyk) scans MCP server configs for vulnerabilities — great for static analysis, but doesn't block at runtime. PipeLock (Go, single binary) is a simpler agent firewall — good for quick single-agent setups. VellaVeto is the runtime policy engine: fine-grained allow/deny rules, compliance evidence packs, multi-transport parity, formal verification. We link to all of them in our comparison table.

### "This is over-engineered"

The full control plane is designed for teams deploying multiple agents in production. But you don't need to use any of that to get value. `vellaveto-proxy --protect shield` gives you credential protection, injection scanning, and DLP with zero config — one flag, no TOML files, no security domain knowledge. If you later need ABAC policies, compliance evidence, or multi-transport governance, it's all there. You don't have to start with it.

### "Why Rust?"

Fail-closed security engine needs: no panics (we enforce zero `unwrap()` in library code), predictable latency (no GC pauses), memory safety without runtime overhead. Rust's type system also makes it harder to accidentally pass unvalidated input to security-critical functions. The tradeoff is compile time and ecosystem complexity.

### "Why should I care about the Consumer Shield?"

If you use Claude, ChatGPT, or any AI assistant with tool access, the provider sees every file path you open, every URL you visit, every database query you run. Even if you trust the provider today, their terms change, they get acquired, or they partner with third parties. The Shield gives you a cryptographic proof of what was shared and what was stripped. It runs on your machine — the provider never sees the original PII. You don't need to trust the provider's privacy policy when you can enforce your own.

### "Formal verification of what exactly?"

Specific properties, not the entire system. TLA+ verifies the policy engine's state machine is deterministic and that ABAC forbid-overrides work correctly. Lean 4 proves that error paths always produce Deny (fail-closed). Coq proves capability delegation can't escalate privileges. These are the properties where bugs would be hardest to detect through testing alone. The proofs are in `formal/` — we'd love feedback on whether we're proving the right things.
