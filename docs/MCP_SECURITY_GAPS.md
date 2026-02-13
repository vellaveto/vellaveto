# The open frontiers of MCP runtime security

**The MCP security landscape has critical, well-defined gaps across formal verification, cryptographic audit, multi-agent authorization, supply chain integrity, performance characterization, protocol design, compliance mapping, and incident tracking.** No one has formally verified MCP policy enforcement in any theorem prover. No production-grade cryptographic audit trail exists for agent tool calls. The confused deputy problem remains unsolved at the protocol level. Only **14% of organizations running agents in production have runtime guardrails** (Lakera, Q4 2025). These gaps represent both acute security risks and extraordinary research/product opportunities for a Rust-based runtime firewall.

The MCP specification — now under the Agentic AI Foundation (Linux Foundation) — was not designed with security as a first-class concern. The community joke "the S in MCP stands for security" reflects a real architectural deficit. Real-world incidents are accelerating: **CVE-2025-6514** (CVSS 9.6 RCE in `mcp-remote`, 437K downloads), the first malicious MCP server in the wild (`postmark-mcp`, September 2025), and 492 unauthenticated MCP servers found exposed on the internet by Trend Micro. What follows is a gap-by-gap analysis with severity assessments, active work inventory, and strategic recommendations.

---

## 1. Formal verification of MCP is a completely empty field

**No formal model of the MCP protocol exists in any framework — TLA+, Alloy, Lean, Coq, or Isabelle.** No one has specified, let alone verified, safety, liveness, or complete mediation properties for MCP policy enforcement. The arXiv paper "Securing the Model Context Protocol" (2511.20920, November 2025) explicitly calls out formal verification as an open research question, noting that "MCP-based agents violate [traditional formal method] assumptions through adaptive behavior, tool composition, and natural language interfaces."

Two adjacent pieces of work exist but fall short. **Invariant Labs** (ETH Zurich spinoff, ICML 2024) built an information-flow analyzer for agent traces with formal guarantees — but it verifies trace properties, not the enforcement mechanism itself. **VeriGuard** (Google DeepMind/Cloud AI Research, arXiv:2510.05156, October 2025) uses the Nagini/Viper verifier to prove Hoare-logic properties of Python safety policies — but targets generated policy code, not MCP protocol interactions. **Allegrini et al.** (arXiv:2510.14133, October 2025) defined **31 formal properties** for agentic AI in CTL/LTL temporal logic, but these remain purely specifications — no one has model-checked them against any real system.

The foundational research gap is clear: no one has built a formal model of MCP client-server interactions and proven that a reference monitor correctly mediates all tool calls. A TLA+ or Alloy specification of MCP, combined with Lean/Coq proofs of a Rust policy engine's correctness, would be a **first-of-its-kind contribution** with strong publication potential (targeting USENIX Security, CCS, or S&P).

- **Severity:** Critical for academic credibility and high-assurance deployments
- **Active work:** Invariant Labs (trace analysis), Google (VeriGuard) — neither targets MCP directly
- **Difficulty:** High (12-18 months for meaningful formal model + verified implementation)
- **Defensibility:** Extremely high — formal proofs are durable competitive moats

---

## 2. Cryptographic audit trails exist only as prototypes

The MCP specification includes a basic `logging` capability that is optional, unstandardized, and has **zero cryptographic integrity guarantees**. Client and server logs are disconnected. No cross-server correlation, no hash chains, no digital signatures, no Merkle trees. The most detailed architectural blueprint is Andrew Stevens' "Missing Primitives for Trustworthy AI Agents" series (Sakura Sky, November 2025) — design documents with Python reference code for SHA-256 hash chains, Merkle trees, and Ed25519 signatures bound to SPIFFE identities. But it remains unimplemented in any shipping product.

Three early-stage implementations exist. **Clawprint** (cyntrisec/clawprint) is a Rust-based tamper-evident audit daemon using SHA-256 hash chains, specifically for OpenClaw — but has zero community adoption and lacks Merkle trees or digital signatures. **AgentLens** (amitpaz/agentlens) is a TypeScript MCP-native observability tool with per-session hash chains but no signatures. **VeritasChain VCP-RTA** implements SHA-256 chains, Ed25519 signatures, and Merkle trees — but only for financial trading agents.

The academic frontier includes **zk-MCP** (arXiv:2512.14737, Jing & Qi, December 2025), proposing ZK-SNARK-based privacy-preserving audit for MCP with <4.14% overhead demonstrated in a Circom prototype. The "Constant-Size Cryptographic Evidence Structures" paper (arXiv:2511.17118, Codebat Technologies) proposes compact hash-chain evidence items for regulated AI. Neither is production-ready.

**Nobody has combined a runtime firewall with cryptographic audit logging.** These are treated as separate concerns everywhere. A Rust crate providing append-only hash-chained logs + Merkle tree inclusion proofs + Ed25519 agent-identity binding — integrated into an MCP intercepting proxy — would be genuinely novel.

- **Severity:** Critical for compliance (SOC 2, EU AI Act Article 12/19) and non-repudiation
- **Active work:** Sakura Sky (design only), Clawprint (early Rust), zk-MCP (academic)
- **Difficulty:** Medium (well-understood cryptographic primitives; integration is the hard part)
- **Defensibility:** High — first production implementation sets the standard

---

## 3. Multi-agent security has no protocol-level solution

When Agent A calls Agent B which calls a tool, **Agent B's own credentials are used, the originating user's identity is lost, and no delegation chain is tracked.** This is the confused deputy problem, and it is trivially exploitable today. Quarkslab built a concrete PoC (FailMed AI) demonstrating confused deputy in a medical agent. HashiCorp notes that "more agents = more applications = more data and a chain of system calls that are often using their own permissions."

Neither MCP nor Google's A2A protocol solves this. MCP has **no concept of "on behalf of"** — authentication is client-to-server only. A2A v0.3 added signed security cards and JWT/OIDC authentication but lists authorization as a TODO. Three promising proposals exist but none is adopted:

- **AAP (Agent Authorization Profile)** at aap-protocol.org — the most complete spec, extending OAuth 2.0 with structured JWT claims for agent identity, capabilities with constraints, task purpose-binding, delegation chain tracking with max depth, and human oversight requirements
- **OIDC-A 1.0** (Subramanya N, April 2025) — OpenID Connect extension defining `delegation_chain` and `agent_attestation` claims
- **MIT Media Lab paper** (arXiv:2501.09674, South et al.) — translates natural-language permissions into XACML configs with delegation tokens

The strongest theoretical argument comes from Niki Niyikiza's "Capabilities Are the Only Way to Secure Agent Delegation" (December 2025), applying object-capability theory from Mark Miller and Tyler Close's "ACLs Don't" proof. The core insight: IAM is fundamentally wrong for agents because **delegation is an operation on authority itself, not an attribute of identity.** Capability tokens with cryptographic holder binding, monotonic scope attenuation, and short expiry solve this — but no shipping implementation exists.

- **Severity:** Critical — this is the #1 architectural gap in the entire ecosystem
- **Active work:** AAP Protocol, OIDC-A (proposals only), Niyikiza (theory only)
- **Difficulty:** High (requires protocol-level changes + runtime enforcement + identity infrastructure)
- **Defensibility:** Extremely high — first working capability-based delegation system for agents

---

## 4. MCP supply chain security is fragmented and incomplete

The first malicious MCP server (`postmark-mcp`) was discovered by Koi Security in September 2025 — a trojanized npm package that silently BCC'd every email to `phan@giftshop.club` after 15 benign versions. A second discovery found **126 packages from a single publisher with dual reverse shells** (86,000 downloads). CVE-2025-6514 in `mcp-remote` (CVSS 9.6, 437K downloads) enabled full RCE through OAuth proxy exploitation. Smithery's hosting platform leaked a Fly.io API token controlling 3,000+ MCP server apps via path traversal (June 2025).

The official MCP Registry (registry.modelcontextprotocol.io, launched September 2025) is a **metaregistry** — it stores metadata pointing to npm, PyPI, and Docker Hub but hosts no code and performs no verification. **No cryptographic signing is required to publish.** Docker's MCP Catalog is the most secure option, with signed images, commit pinning, and AI-audited code reviews — but it covers only containerized servers, which are a minority of the ecosystem.

**ToolHive by Stacklok** is the most advanced supply chain solution, integrating Sigstore and GitHub Attestations for provenance verification of container images. Chainguard's dfc-mcp image ships with cosign-verifiable signatures and SLSA provenance attestations. But these solutions cover only containers. The vast majority of MCP servers distributed via `npx`/`uvx` have **zero provenance, zero signing, zero SBOM.**

Critical gaps for a runtime firewall include: tool definition integrity (no hash or signature mechanism in the protocol), rug pull detection (no change notification when tool definitions mutate), behavioral drift monitoring (no standard for runtime behavioral analysis), and no transparency log for MCP tool publications.

- **Severity:** Critical — active exploitation in the wild
- **Active work:** ToolHive/Stacklok (containers), Docker (containers), Cisco MCP Scanner (static)
- **Difficulty:** Medium for tool-definition pinning/hashing; high for full SLSA ecosystem
- **Defensibility:** High — runtime enforcement of supply chain integrity is differentiated

---

## 5. Performance benchmarking is almost nonexistent

**No rigorous benchmark exists measuring security enforcement overhead in MCP request pipelines.** The user's sub-5ms P99 latency is unprecedented in published literature — there is literally nothing to compare it against in peer-reviewed work.

The closest data points span a wide latency spectrum. **MCP-Guard** (arXiv:2508.10991) reports ~1.8ms average for lightweight syntactic filtering (Stage 1) but ~456ms for the full pipeline including LLM arbitration. **Envoy AI Gateway** benchmarks show ~0.38ms per operation with tuned encryption. **TrueFoundry MCP Gateway** claims sub-3ms under load. **OPA** evaluates RBAC policies in ~43us per operation in isolation but adds milliseconds when deployed with Envoy gRPC. **Cedar** (AWS, written in Rust) claims "sub-millisecond" evaluation but publishes no P99 numbers. On the guardrails side, BERT-based classifiers add ~50ms, while LLM-as-judge approaches cost **5,000-8,600ms** — three orders of magnitude slower than deterministic enforcement.

No one has published: a standardized MCP proxy benchmark suite, P99 tail latency distributions for security proxies under realistic concurrent load, the cumulative cost of TLS + JSON-RPC parsing + schema validation + RBAC + content policy + audit logging in a single pipeline, or a formal comparison of deterministic vs. probabilistic enforcement with controlled experiments.

A rigorous benchmarking paper — measuring each component of the security pipeline independently and in combination, comparing Rust deterministic enforcement against LLM-based guardrails on identical workloads, and characterizing tail latency behavior — would fill a **major void** in the literature. Target venues: OSDI, NSDI, or MLSys.

- **Severity:** Important for credibility and adoption; critical for academic publication
- **Active work:** No one is doing rigorous MCP security benchmarking
- **Difficulty:** Low-medium (benchmarking methodology is well-understood; the hard part is already done)
- **Defensibility:** Medium — benchmarks are replicable, but first-mover sets the standard

---

## 6. The MCP specification has fundamental protocol-level security deficits

The MCP spec (now at version 2025-11-25) has received two major security revisions but retains deep architectural gaps. **No formal security audit of the protocol specification itself has ever been conducted** — all audits target implementations, not the protocol design.

The most critical protocol-level gaps, which **cannot be fully fixed at the application layer**, include:

- **Tool definitions are unsigned and mutable.** No hash, signature, or version-pinning mechanism exists. Rug pull attacks — where a server silently changes tool behavior after approval — are a direct consequence. The ETDI paper (arXiv:2506.01333) proposes cryptographic identity verification and immutable versioned tool definitions as spec extensions, but these remain unimplemented.
- **Tool annotations are advisory, not enforceable.** `readOnlyHint` and `destructiveHint` are hints only. The protocol has no mechanism to enforce them.
- **Session IDs in URLs** violate security best practices, exposing them in logs and enabling session hijacking.
- **Stdio transport has zero authentication or encryption** — plaintext stdin/stdout with arbitrary command execution. LibreChat's RCE (GHSA-cxhj-j78r-p88f) proved this leads to root-level compromise.
- **No namespace isolation** — tool name collisions across servers enable shadowing attacks where a malicious tool impersonates a legitimate one.
- **OAuth adoption is critically low** — **53% of MCP servers still use static API keys, 79% store credentials in environment variables** (2025 ecosystem study).

The OAuth 2.1 framework (June 2025 revision) was a significant improvement — reclassifying MCP servers as Resource Servers, mandating PKCE, and requiring Protected Resource Metadata (RFC 9728). But it still lacks client authentication for public clients, agent-to-agent auth, and revocation propagation. Christian Posta (Solo.io) called the implementation "a mess" noting that enterprises reject Dynamic Client Registration's anonymous registration model.

- **Severity:** Critical — these are architectural deficits affecting every MCP deployment
- **Active work:** OWASP MCP Top 10 (taxonomy, not fixes), spec committee (incremental improvements)
- **Defensibility:** A firewall that enforces unsigned-spec-level guarantees (tool pinning, namespace isolation, annotation enforcement) creates immediate value

---

## 7. Compliance frameworks were designed for static AI, not dynamic agents

**No compliance framework adequately addresses runtime tool-calling governance.** The EU AI Act (Regulation 2024/1689) assumes fixed configurations, predictable tool interactions, and human-visible decision paths — all three assumptions are violated by MCP-mediated agents that dynamically discover and invoke tools. The Future Society's "Ahead of the Curve" (June 2025) is the first comprehensive analysis, concluding "the AI Act was not originally designed with AI agents in mind." Michael Hannecke's "Agentic Tool Sovereignty" concept notes that **18 months after the Act entered force, no implementing act or position paper from the EU AI Office addresses autonomous tool usage.**

Article 14's human oversight requirement is physically impossible at agent speeds. Agents execute tool calls in milliseconds; meaningful human review at that granularity cannot scale. The Singapore IMDA Model AI Governance Framework for Agentic AI (v1.0, January 2026) — the **world's first government-issued governance framework specifically for agentic AI** — acknowledges this, discussing checkpoint-based oversight for high-risk actions only. But it is voluntary and non-binding.

For SOC 2, the gap is equally stark. **No Trust Services Criteria specifically addresses AI agent workflows.** The AICPA has not updated TSC for agentic AI. IBM flags the core problem: "During SOC 2 audit, the auditor asks 'Who authorized this rollback decision?' Your team lead points to the AI. The auditor stops writing." No standard audit procedure exists for verifying agent decision chains or tool call authorization.

A runtime firewall generating structured, immutable audit logs with decision context, user attribution, risk classification, and human approval chains would directly fill the SOC 2 evidence gap and provide continuous conformity evidence for EU AI Act Article 43. Mapping firewall controls to ISO 42001 annexes and NIST AI RMF functions — specifically filling the agent/tool-calling gaps these standards don't address — creates significant market positioning.

- **Severity:** Critical for enterprise adoption; will become mandatory as enforcement begins (August 2026)
- **Active work:** Singapore IMDA framework (voluntary), Policy Cards (arXiv, academic)
- **Difficulty:** Medium (the compliance mapping is straightforward; generating the evidence is the hard part)
- **Defensibility:** High — compliance certifications are expensive moats

---

## 8. Real incidents are mounting but tracking infrastructure doesn't exist

The real-world MCP threat landscape has materialized faster than the security community anticipated. AuthZed compiled the first consolidated breach timeline, documenting **8+ major incidents** through early 2026:

- **WhatsApp MCP Exfiltration** (April 2025) — Invariant Labs demonstrated silent chat history theft via tool poisoning
- **GitHub MCP Data Heist** (May 2025) — prompt injection in public issues hijacked AI assistants to steal private repo data through the official GitHub MCP server (14,000+ stars)
- **Asana MCP Cross-Tenant Exposure** (June 2025) — logic flaw leaked data between organizations
- **CVE-2025-49596** (June 2025, CVSS 9.4) — RCE in Anthropic's own MCP Inspector, 560 exposed instances on Shodan
- **CVE-2025-6514** (July 2025, CVSS 9.6) — full system compromise via `mcp-remote` OAuth proxy
- **Anthropic Filesystem MCP Sandbox Escape** (August 2025, CVE-2025-53109/53110)
- **postmark-mcp supply chain attack** (September 2025) — ~300 organizations compromised
- **1,000+ exposed AI agent deployments** found in January 2026 with unauthenticated MCP endpoints

Despite this, **no centralized MCP vulnerability database exists.** CVE/NVD tracks some MCP flaws when they map to conventional vulnerability classes (command injection, RCE), but **no CWE entries exist for AI-native vulnerability classes** — tool poisoning, rug pulls, context over-sharing, preference manipulation, and agent goal hijacking have no standard identifiers. OWASP's MCP Top 10 (beta) and Agentic Applications Top 10 provide risk taxonomies but no automated enforcement or scanning tools comparable to ZAP for web applications.

Adversa AI published an informal "MCP Security TOP 25 Vulnerabilities" list, Backslash Security tracks 7,000+ MCP servers on their Security Hub, and NIST issued an RFI on AI agent security in January 2026 (deadline March 9, 2026). But the ecosystem lacks a CERT/CC equivalent, a coordinated disclosure framework for third-party MCP servers, and quantified attack probability models.

- **Severity:** Critical — active exploitation with no systematic tracking
- **Active work:** OWASP MCP Top 10, Backslash Security Hub, vendor-specific tracking
- **Difficulty:** Low-medium for contributing to tracking; high for building the infrastructure
- **Defensibility:** Medium — community infrastructure, but first-mover advantage in tooling

---

## Strategic gap prioritization for a Rust-based runtime firewall

Based on this analysis, gaps are ranked by the intersection of severity, tractability, and competitive defensibility:

| Rank | Gap | Severity | Tractability | Defensibility | Research paper potential |
|------|-----|----------|-------------|---------------|------------------------|
| 1 | **Multi-agent delegation/capability enforcement** | Critical | Hard | Extremely high | Top-tier security venue |
| 2 | **Cryptographic audit trail (Merkle + signatures)** | Critical | Medium | High | Systems venue (OSDI/NSDI) |
| 3 | **Tool definition integrity/rug pull prevention** | Critical | Medium | High | Industry track paper |
| 4 | **Formal verification of policy enforcement** | Critical | Hard | Extremely high | Top-tier (S&P/CCS/USENIX) |
| 5 | **Performance benchmarking paper** | Important | Low | Medium | MLSys/NSDI/benchmarking |
| 6 | **Compliance evidence generation (EU AI Act/SOC 2)** | Critical | Medium | High | Regulatory/policy venue |
| 7 | **Supply chain provenance for non-container MCP** | Critical | Medium | Medium | Industry track |
| 8 | **MCP vulnerability taxonomy/tracking** | Important | Low | Low | Workshop paper |

The single most impactful combination: **formal verification of a Rust policy engine's complete mediation property + cryptographic audit trail + deterministic performance characterization.** This trifecta — provably correct enforcement, tamper-evident logging, and rigorous latency guarantees — does not exist anywhere in the ecosystem. Building and publishing it would establish the definitive reference implementation for MCP runtime security, with results targeting top-tier venues like USENIX Security or IEEE S&P.

## Conclusion

The MCP security landscape in February 2026 is characterized by a sharp asymmetry: **threat sophistication is advancing far faster than defensive infrastructure.** Real exploits are shipping while formal verification is nonexistent, audit trails lack cryptographic integrity, multi-agent delegation has no protocol-level solution, supply chain protections cover only containers, no one has rigorously benchmarked security enforcement, the spec has fundamental architectural deficits, compliance frameworks don't address dynamic tool discovery, and incident tracking is ad hoc.

A Rust-based runtime firewall with 33,000 lines of code and 4,278+ tests is already ahead of published work. The most defensible research contributions would be: (1) a TLA+ or Alloy formal model of MCP with verified properties, (2) a capability-based delegation system replacing ambient authority, (3) a Merkle-tree transparency log for agent actions integrated with the enforcement layer, and (4) a rigorous performance characterization paper proving that deterministic enforcement at sub-5ms P99 is achievable. Each of these would be a genuine first in the literature. The window for establishing these foundations — before the ecosystem ossifies around weaker solutions — is approximately 12-18 months.
