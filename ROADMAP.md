# Vellaveto Roadmap

> **Version:** 8.0.0-planning
> **Updated:** 2026-03-11
> **Status:** shared substrate shipped; 2026 execution roadmap
> **Current focus:** close the dirty worktree, finish transport convergence, then expand runtime, product, research, compliance, and supply-chain coverage
> **Strategic position:** fail-closed control plane for MCP and tool-calling agents

---

## Executive Summary

The next roadmap does not start from zero. Vellaveto already has the core provenance, containment, mediation, audit, approval, discovery, and identity substrate in-tree. The 2026 plan starts from the real repo state:

1. finish the current worktree bundles cleanly;
2. complete protocol-level runtime enforcement across MCP and HTTP transports;
3. ship the buyer-facing controls competitors already expose;
4. fund multi-agent and advanced containment research as product epics;
5. turn compliance mapping into generated evidence artifacts;
6. strengthen supply-chain trust and ecosystem reputation handling.

This roadmap is therefore execution-first, not a fresh foundation plan.

---

## Planning Assumptions

- Shared provenance and containment primitives already exist in `vellaveto-types`.
- Canonical request hashing and mediation scaffolding already exist in `vellaveto-canonical` and `vellaveto-mcp`.
- ACIS already carries provenance, lineage, sink, trust, and containment metadata.
- NHI, MINJA, discovery, approval, cluster state, and runtime transport surfaces already exist and should be extended rather than rebuilt.
- Research-heavy items are funded epics in the main roadmap, but they must ship behind explicit benchmarks, regression suites, and rollout gates before becoming defaults.

---

## What Is Already Shipped

The following are treated as foundation, not backlog:

- Shared provenance, workload, trust, taint, lineage, and containment models
- Canonical request and lineage hashing
- Shared mediation pipeline and ACIS decision envelopes
- NHI and MINJA substrate
- Approval, audit, discovery, and cluster/runtime state foundations
- MCP, HTTP proxy, server, stdio proxy, and shield transport surfaces
- Formal and adversarial verification programs substantial enough to support incremental proof targets instead of greenfield formalization

The roadmap below assumes those pieces are extended in place.

---

## Immediate Worktree Priorities

Before opening large new tracks, the current dirty worktree should be reduced into clean, reviewable slices.

### Bundle A: HTTP proxy transport convergence

**Primary modules**
- `vellaveto-http-proxy`
- `vellaveto-mcp`
- `vellaveto-engine`
- `vellaveto-audit`

**Current scope**
- Finish unified HTTP and WebSocket mediation on the shared runtime-security-context path
- Make transport evidence complete: signature status, replay result, canonical binding, workload binding, and origin lineage
- Extend parity coverage to sampling, elicitation, tasks, and extension methods

**Exit criteria**
- `cargo fmt --check`
- `cargo test -p vellaveto-http-proxy`
- no legacy HTTP admission path remains for policy-evaluated actions

### Bundle B: formal/docs/paper consolidation

**Primary modules**
- `formal/`
- top-level metadata and release docs

**Current scope**
- Align proof counts, verification claims, manuscript direction, and inventory references
- Complete migration away from the old paper entrypoint
- Keep changelog, roadmap, assurance, and trusted-computing claims internally consistent

**Exit criteria**
- proof counts and manuscript references are internally consistent
- no stale roadmap or inventory claims remain in the edited doc set

### Bundle C: site/domain/package cleanup

**Primary modules**
- `site/`
- `packages/create-vellaveto`
- `sdk/typescript`

**Current scope**
- Finish apex/canonical routing and generated robots/sitemap assets
- Align package metadata and site copy with the current product position

**Exit criteria**
- canonical site routing is internally consistent
- package metadata matches current branding and deployment URLs

---

## 2026 Execution Map

### Phase 0: Sprint 2 Closeout and Worktree Cleanup

**Window**
- March 2026

**Goal**
- Cleanly land the active worktree and rebaseline planning around the code that actually exists.

**Primary modules**
- `vellaveto-http-proxy`
- `formal/`
- `site/`
- top-level release and planning docs

**Deliverables**
- HTTP proxy transport convergence committed in reviewable slices
- formal/docs/site/package bundles split and landed cleanly
- roadmap, changelog, and planning artifacts updated to the post-substrate reality

**Why this phase exists**
- The current worktree already contains the next increment of the roadmap. Shipping it is higher leverage than inventing new quarter labels while the repo is still dirty.

---

### Phase 1: Protocol-Complete Runtime Enforcement

**Window**
- Q2 2026

**Goal**
- Make Vellaveto's shared mediation path protocol-complete across MCP and HTTP, including the newer attack and protocol surfaces that the current threat model only partially covers.

**Primary modules**
- `vellaveto-http-proxy`
- `vellaveto-mcp`
- `vellaveto-engine`
- `vellaveto-config`
- `vellaveto-audit`
- `vellaveto-types`

**Required epics**
- Sampling-with-tools interception and tool allowlisting inside `sampling/createMessage`
- Elicitation URL policy, rate limiting, domain validation, and audit evidence
- Resource and prompt metadata normalization to neutralize poisoning attempts
- Task lifecycle enforcement and durable security context across polling and deferred retrieval
- Extension security policy so non-core methods do not bypass transport-neutral mediation
- Stronger HTTP provenance evidence: detached request signatures where applicable, workload claims, replay cache coordination, target binding, and canonical hash binding
- Continuous security-context propagation across tool chains and transport boundaries
- Cross-tool lineage graph propagation for parasitic toolchain and Living-Off-AI style escalations

**Exit criteria**
- Sampling, elicitation, tasks, and extension methods are all policy-addressable through the shared mediation path
- High-risk sinks fail closed when provenance or containment evidence is missing
- Replay and target-binding failures are first-class audit outcomes, not opaque transport errors

---

### Phase 2: Policy, Approval, and Operator Productization

**Window**
- Q2-Q3 2026

**Goal**
- Turn the existing security core into a product surface buyers can operate without needing to understand every internal primitive.

**Primary modules**
- `vellaveto-approval`
- `vellaveto-server`
- `vellaveto-config`
- `vellaveto-engine`
- `vellaveto-audit`
- discovery and operator-facing inventory surfaces

**Required epics**
- Human-in-the-loop approval workflows for privileged sinks and destructive actions
- Declarative policy DSL that compiles to the current formal/runtime policy substrate
- ReBAC and ABAC with argument flattening for enterprise authorization use cases
- Per-tool rate limiting and quotas as explicit policy controls
- Secret substitution before model visibility, with late restore at execution boundaries
- OpenTelemetry-native tracing alongside existing audit exports
- Curated registry and server reputation scoring built on discovery, trust metadata, attestation inputs, and behavioral baselines
- AI asset inventory expansion so discovery becomes an operator-facing AI BOM, not only an MCP topology graph

**Exit criteria**
- Operators can author common rules without hand-editing low-level structures
- High-risk flows can require explicit human approval with canonical fact summaries
- Registry and discovery produce both runtime trust decisions and operator-facing posture views

---

### Phase 3: Multi-Agent and Advanced Containment

**Window**
- Q3 2026

**Goal**
- Close the gap between single-agent request mediation and adversarial multi-agent orchestration, where current guardrails are easiest to route around.
- Turn the existing provenance and containment type system into a unified enforcement framework for cross-server information flow, causal containment, and semantic output contracts.

**Primary modules**
- `vellaveto-types`
- `vellaveto-engine`
- `vellaveto-mcp`
- `vellaveto-http-proxy`
- `vellaveto-approval`
- `vellaveto-cluster`
- adversarial and formal verification suites

**Funded research epics**
- Control-flow graph enforcement for multi-agent orchestration and cross-server delegation
- Per-value capability metadata where taint labels are too coarse for safe sink decisions
- Multi-agent indirect prompt injection calibration and containment thresholds
- Context-learning contagion controls for tool-generated or model-generated follow-on actions
- Approval invalidation on lineage drift, trust downgrade, or provenance drift
- Masked re-execution and counterfactual validation for suspicious trajectories
- Cryptographic inter-agent token experiments for bounded delegation chains

**Semantic containment integration program**

This is a mainline research-and-delivery track, not a side experiment. The
existing types already exist in-tree: `RuntimeSecurityContext`,
`SemanticTaint`, `TrustTier`, `SinkClass`, `ContainmentMode`, `ContextChannel`,
and `LineageRef`. The roadmap work is to turn those types into the first
integrated framework that combines information-flow control, counterfactual
containment, semantic output typing, and a formal MCP attacker model.

**Work package 3A — formal trust lattice for MCP servers**
- Formalize `TrustTier` as a lattice with join/meet operations and explicit
  information-flow rules.
- Treat `SinkClass` as the integrity/privilege ordering and define the product
  lattice `TrustTier × SinkClass` as the runtime enforcement space.
- Define cross-server composition rules using Lagois-style connections where
  trust domains must be composed across MCP server boundaries.
- Deliverables: formal spec in `formal/` plus mediation hooks that evaluate
  flow admissibility using the already-threaded `RuntimeSecurityContext`.

**Work package 3B — mandatory inter-server information-flow control**
- Enforce cross-server flow checks whenever tainted or lineage-tagged content
  reaches a tool invocation boundary.
- Deny or escalate when data from a lower-trust source reaches a higher-privilege
  sink without explicit declassification policy.
- Use `SemanticTaint`, `LineageRef`, and `RuntimeSecurityContext` as the shared
  contract across MCP and HTTP mediation paths instead of creating a parallel
  taint system.
- Deliverables: mediation-pipeline enforcement, regression tests for
  untrusted-to-privileged flow blocking, and Kani harnesses for the flow-check
  logic.

**Work package 3C — taint-triggered counterfactual containment**
- Invoke counterfactual or attribution-style checks only when taint is crossing
  a privilege boundary, rather than on every tool call.
- Use `ContainmentMode::RequireApproval` and `semantic_risk_score` to carry the
  causal-attribution result into runtime decisions and audit.
- Treat "tainted data was causally necessary for a privileged action" as the
  enforcement predicate for escalation, denial, or explicit approval.
- Deliverables: runtime attribution gate at privilege boundaries plus Verus
  proofs for the enforcement logic that mediates taint, privilege, and approval.

**Work package 3D — semantic output contracts**
- Formalize `ContextChannel` as an output-type system rather than a loose
  classifier vocabulary.
- Require MCP tools and connectors to declare expected output semantic types
  and compare those declarations against observed response classifications at
  runtime.
- Escalate or quarantine when a tool typed as `Data` produces `CommandLike`,
  `ApprovalPrompt`, `Url`, or other semantically incompatible output.
- Deliverables: output-type contract spec, response-path classification and
  enforcement, and regression cases for rug-pull, schema-compliant malicious
  content, and semantic type violations.

**Work package 3E — Dolev-Yao model for prompt injection over MCP**
- Formalize an attacker that controls designated low-trust content channels
  such as untrusted tool responses, resource content, and elicitation payloads,
  but does not break the structural isolation enforced by the proxy.
- Make the trust lattice and containment gates the axioms that bound attacker
  reachability into privileged sinks.
- Use the model to express and verify the security claim that untrusted content
  cannot silently drive privileged effects without triggering flow control,
  counterfactual escalation, or explicit policy override.
- Deliverables: TLA+ or Alloy attacker model, proof obligations for key
  safety properties, and a paper-grade formal threat model for MCP prompt
  injection and tool-calling systems.

**Delivery rule**
- These are funded product epics, not a watchlist, but they ship behind feature flags, benchmark thresholds, and explicit rollback paths.

**Exit criteria**
- Cross-server and multi-agent flows can be constrained by explicit orchestration policy
- High-risk delegations are explainable as bounded control-flow transitions, not emergent tool hopping
- Cross-server information flows are mediated by a formal trust lattice and sink policy, not by ad hoc handler heuristics
- Privileged sink decisions can escalate based on taint-triggered counterfactual evidence when untrusted input is causally necessary
- Tool and connector responses can be checked against semantic output contracts before they silently change privilege-relevant meaning
- At least one research-heavy containment mechanism graduates from prototype to supported feature

---

### Phase 4: Compliance Evidence Factory

**Window**
- Q3-Q4 2026

**Goal**
- Convert compliance mapping into generated evidence and document outputs that regulated buyers can actually use.

**Primary modules**
- `vellaveto-audit`
- `vellaveto-server`
- reporting and export surfaces
- top-level compliance and operational docs

**Required epics**
- Annex IV technical documentation package generation
- Article 73 incident-report exports with routing-ready metadata and timing classes
- Quality Management System support for the security, monitoring, and control-enforcement sections Vellaveto can substantiate directly
- Post-market monitoring plan generation tied to runtime evidence and policy posture
- EU Declaration of Conformity support artifacts
- FRIA-oriented data export for deployer workflows

**Exit criteria**
- Runtime evidence can be exported as structured compliance artifacts, not only raw logs
- Serious-incident evidence packs can be generated without reconstructing provenance manually
- Compliance documents are generated from the same control and audit substrate used at runtime

---

### Phase 5: Supply-Chain and Ecosystem Trust

**Window**
- Q4 2026

**Goal**
- Raise trust from runtime-only enforcement to ecosystem-aware admission, reputation, and provenance handling.

**Primary modules**
- discovery and trust inventory surfaces
- `vellaveto-server`
- `vellaveto-mcp`
- `vellaveto-http-proxy`
- `vellaveto-audit`

**Required epics**
- Sigstore, attestation, and SBOM ingestion where registries or publishers provide them
- Signed tool-description and connector-baseline verification to detect rug pulls and malicious drift
- Reputation scoring that combines registry metadata, attestations, behavioral history, and trust downgrades
- Stronger transport trust defaults, including mTLS-ready pathways and tighter authorization metadata validation
- Client metadata and enterprise authorization support for newer MCP authorization patterns
- Runtime containment hooks that can react to supply-chain trust degradation without waiting for manual review

**Exit criteria**
- Connector trust can be downgraded or blocked using signed or attestable provenance inputs
- Discovery, registry, and runtime trust state converge on one operator-visible source of truth
- Supply-chain trust changes can trigger policy outcomes and audit evidence automatically

---

## Cross-Cutting Verification Track

Every phase above carries explicit regression and proof work. The platform should not ship major new controls without adversarial tests, canary scenarios, and narrowly scoped formal invariants where the property is crisp enough to prove.

**Required cross-cutting work**
- Extend `mcpsec` and related adversarial suites for sampling abuse, replay, retargeting, metadata poisoning, approval contamination, and multi-agent escalation
- Add canary scenarios for provenance drift, semantic drift, and cross-server delegation abuse
- Add focused formal invariants for replay non-admission, monotonic taint propagation, approval invalidation, and fail-closed unknown-provenance handling
- Add formal lattice, noninterference, and flow-admissibility specs for `TrustTier × SinkClass` enforcement
- Add proofs and executable checks for counterfactual escalation gates and semantic output-contract violations
- Add an MCP attacker model for prompt injection that treats structural channel isolation and mediation guarantees as proof assumptions
- Keep operator and audit surfaces aligned with new verdict types, quarantine paths, and containment transitions

---

## Portfolio Rules

- Do not rebuild shared substrate that already exists unless a concrete design defect requires it.
- Runtime enforcement, buyer-facing controls, and compliance evidence must all ship in 2026; none of the three can be deferred to a "later" bucket.
- Research-heavy work belongs on the main roadmap, but only with bounded prototypes, benchmarks, and rollout gates.
- New transport or protocol features must enter through shared mediation rather than ad hoc handler logic.
- Compliance artifacts must be generated from runtime evidence wherever possible to avoid manual drift.
- Registry, discovery, and supply-chain trust should converge into one trust model instead of parallel catalogs.

---

## 2026 Success Criteria

By the end of 2026, Vellaveto should be able to claim all of the following with code, tests, and evidence:

- Every mediated high-risk action is both cryptographically attributable and semantically contained
- Sampling, elicitation, tasks, and extension flows are all enforced through shared runtime mediation
- Operators can define common controls, approvals, quotas, and trust policy without editing low-level internals
- Multi-agent delegation paths can be bounded, explained, and invalidated when provenance or lineage changes
- Cross-server flows are enforced by a formal trust lattice, with taint and lineage surviving tool-to-tool propagation unless explicitly cleared
- Semantic output contracts can detect when tools drift from declared `ContextChannel` behavior into privilege-relevant content classes
- Compliance evidence can be generated directly from runtime facts for regulated buyer workflows
- Connector and server trust decisions can incorporate supply-chain provenance, drift, and reputation inputs

That is the 2026 bar: not just a stronger MCP firewall, but a complete control plane that makes runtime enforcement, buyer usability, compliance evidence, and ecosystem trust reinforce each other.
