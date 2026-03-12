# Vellaveto Roadmap

> **Version:** 8.0.0-planning
> **Updated:** 2026-03-12
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

**Progress update (Mar 2026)**
- Shared containment-aware secondary ACIS coverage is now in place for almost all
  HTTP proxy request, response, discovery, guard, and protocol control events
  across HTTP, WebSocket, and gRPC.
- Smart-fallback and gateway availability outcomes are now on the same structured
  containment-aware audit path as the rest of the transport handlers.
- OAuth DPoP failures and SSE inspection helper events are now on the same path
  as well, so `vellaveto-http-proxy` no longer has any plain
  `build_secondary_acis_envelope(...)` sites remaining.
- The runtime-security-context helper now uses explicit OAuth/DPoP validation
  evidence rather than inferring signature and replay state from raw headers,
  and verified agent identity is promoted into transport workload identity and
  workload-binding status.
- Verified custom `X-Agent-Identity` claims now survive validation, so HTTP
  transport provenance can populate richer workload fields as well as
  `session_key_scope` and `execution_is_ephemeral` from authenticated identity
  claims instead of relying on metadata-only overrides.
- Authenticated HTTP transport now accepts an explicit `x-workload-claims`
  header as a second workload-provenance source, allowing allowlisted
  workload metadata to be carried even when `X-Agent-Identity` is absent and
  taking precedence over bearer-token custom claims when both are present.
- HTTP and WebSocket provenance also ingest a detached `x-request-signature`
  header for request-signature metadata, preserving non-DPoP signature inputs
  in `client_provenance` while still treating them as non-authoritative unless
  separately verified.
- Detached request signatures can now also be verified against configured
  trusted signer keys across HTTP, WebSocket, and gRPC. The HTTP proxy now
  binds those checks to the canonical request preimage and fails closed on
  unknown key IDs, malformed signatures, and canonical-binding errors instead
  of silently treating them as transport metadata. Verified detached
  signatures now also feed session-local replay status, so mediation can deny
  repeated signed nonces the same way it already denies DPoP replay.
- Trusted detached signers can now also project signer-scoped provenance into
  verified requests, including session key scope, ephemeral execution, and
  workload-identity expectations. Conflicts between verified transport
  workload evidence and signer workload expectations now surface as
  `workload_binding_status = mismatch` instead of disappearing in transport
  normalization.
- Verified detached signer workload expectations now also project
  `workload_binding_status = bound` when the signer-pinned workload identity is
  satisfied, so `require_workload_binding` can admit detached-signer flows on
  verified signer provenance instead of treating that metadata as audit-only.
- Verified detached signer workload mismatches now also downgrade the effective
  trust tier to `untrusted`, so privileged sink trust-floor checks can still
  gate mismatched signer provenance even when the explicit workload-binding
  admission switch is left off.
- Replayed verified detached signatures now also downgrade the effective trust
  tier to `quarantined`, so replayed provenance cannot retain a verified trust
  floor on the semantic-containment path when the explicit replay-deny switch
  is disabled.
- Expired detached signatures now also downgrade the effective trust tier to
  `quarantined`, and `invalid` or verification-error detached signatures
  downgrade to `untrusted`, so broken detached provenance cannot retain a
  useful trust floor simply because other transport hints are present.
- Transport-inferred trust floors now also clamp explicit runtime
  `effective_trust_tier` metadata instead of only supplying a default, so
  caller-provided security context cannot override replay, mismatch, expiry,
  or invalid-signature downgrades on the HTTP proxy path.
- Transport-negative detached provenance now also clamps explicit
  `client_provenance` metadata itself, so caller-supplied `signature_status`
  or `replay_status` values cannot override invalid-signature or replay
  outcomes before the transport trust floor is derived.
- Conflicting authenticated transport workload identity now also clamps
  caller-supplied `client_provenance.workload_identity`, so `_meta`
  provenance cannot override real transport workload evidence or keep a
  privileged request in a `bound` state after a mismatch.
- Caller-supplied `client_provenance.session_key_scope` and
  `execution_is_ephemeral` now also clamp to authenticated transport scope, so
  ephemeral-only policy checks can no longer be bypassed by `_meta`
  provenance that disagrees with the verified transport identity.
- Runtime-owned provenance fields now also ignore caller-supplied `_meta`
  values: `session_scope_binding` is sourced from the transport session, and
  `canonical_request_hash` is recomputed from the live request instead of
  preserving an untrusted caller-provided hash.
- Transport-provided `client_key_id` and detached `request_signature` fields
  now also clamp `_meta.client_provenance`, so caller-supplied provenance
  cannot override the key id, nonce, timestamp, or detached signature bytes
  that the HTTP proxy actually received. WebSocket now threads upgrade headers
  into the same runtime-security-context path, and regression coverage locks
  the same behavior on HTTP, WebSocket, and gRPC entrypoints.
- WebSocket parity now also covers runtime-owned provenance fields, so
  caller-supplied `_meta.client_provenance.session_scope_binding` and
  `_meta.client_provenance.canonical_request_hash` cannot override the live
  session binding or the recomputed canonical hash on WS request paths. gRPC
  regression coverage now locks the same runtime-owned provenance rule across
  all three transport entrypoints.
- Session-scope trust clamping now also has explicit WebSocket and gRPC
  regression coverage, so `_meta.client_provenance.session_key_scope` and
  `execution_is_ephemeral` cannot override persisted transport scope outside
  the HTTP entrypoint either.
- Approval-containment derivation now also has WebSocket and gRPC regression
  coverage for those clamped scope fields, so reviewer-visible provenance
  summary follows transport truth rather than `_meta` scope claims.
- Secondary ACIS envelope derivation now also has WebSocket and gRPC
  regression coverage for those same clamped provenance fields, so approval-
  gate audit events preserve transport-owned signature data, runtime-owned
  scope/hash bindings, and persisted session-scope clamping instead of
  replaying spoofed `_meta.client_provenance` values.
- Approval-context derivation from those secondary ACIS envelopes now also has
  explicit WebSocket and gRPC regression coverage, so reviewer-facing approval
  summaries remain aligned with clamped transport provenance even after the
  audit-envelope conversion step.
- Stored pending-approval records now also have explicit WebSocket and gRPC
  regression coverage for that same provenance summary, so the
  `create_pending_approval_with_context(...)` path preserves opaque session
  binding and clamped signer/scope fields all the way into reviewer state.
- Live tool-registry approval gates now also merge transport-derived runtime
  provenance into their approval context before ACIS emission and persistence,
  so HTTP, WebSocket, and gRPC unknown/untrusted-tool approval paths no longer
  shed detached-signature, scope, or canonical-binding fields at the last hop.
  gRPC unary service coverage now locks the end-to-end stored-approval path,
  direct HTTP handler coverage locks the same POST `/mcp` approval-gate
  persistence path, and live WebSocket integration coverage now locks the real
  `/mcp/ws` approval path too. That live-path coverage now includes both the
  first-seen unknown-tool branch and the already-registered untrusted-tool
  branch across HTTP, WebSocket, and gRPC.
  Those same live-path tests now also assert the emitted ACIS audit envelope,
  so approval-gate audit JSONL entries and stored pending approvals stay in
  lockstep on transport-clamped `client_provenance`.
- Live HTTP POST, WebSocket `/mcp/ws`, and gRPC unary coverage now also proves
  one-shot presented-approval consumption on the real handler path: an
  approved `approval_id` forwards exactly once, transitions to `Consumed`, and
  then fails closed on replay with `Denied by policy`, while the replay denial
  audit entry preserves the same transport-clamped provenance fields.
- The same replay-denial audit treatment now covers resource, task, and
  extension approval consumption across HTTP, WebSocket, and gRPC, so the
  remaining non-tool presented-approval flows no longer fall back to
  context-free denial handling after the approval has already been consumed.
  gRPC and WebSocket now have seeded replay tests on live non-tool paths, and
  HTTP has deterministic consumed-approval matching coverage on the shared
  approval gate.
- Approval escalation and resolution now also preserve provenance summary, so
  reviewer-facing `containment_context` and approval-resolution ACIS events can
  show the same signature status, workload-binding status, key scope, and
  ephemeral-execution state that drove the original admission gate.
- Trusted detached signers now also fail closed on explicit transport
  key-scope conflicts, so persisted versus ephemeral session-key evidence
  cannot be silently merged into a single verified provenance record.
- ACIS now also rejects duplicate `trusted_request_signers.key_id` entries, so
  trusted detached signer config cannot silently collapse into last-wins map
  behavior during HTTP proxy startup. It also rejects duplicate trusted signer
  public keys, closing the aliasing path where one detached signer could be
  configured under multiple local key IDs.
- Shared HTTP-proxy unit and mediation coverage now locks in the detached
  signer provenance-guard outcomes for workload mismatch and key-scope
  conflict, so those enforcement paths are verified above the raw helper layer
  without relying on flaky router integration timing. gRPC runtime-security-
  context coverage now also locks in signer metadata projection, workload-
  mismatch propagation, and scope-conflict invalidation on the transport-parity
  path.
- Shared mediation now also supports an ephemeral-client provenance
  requirement, so captured signer/transport metadata can drive a fail-closed
  admission check instead of remaining audit-only. HTTP detached signer
  projection now has direct policy value when operators require ephemeral
  execution context at the provenance gate.
- Verified detached request signatures now also enforce bounded `created_at`
  freshness, so stale or excessively future-skewed signed requests surface as
  `expired` transport provenance instead of remaining valid indefinitely after
  the signature check succeeds. Verified detached signatures now also require
  `created_at` and `nonce` to reach the replay/freshness path at all, and
  those freshness windows are policy-driven via ACIS config rather than
  hardcoded in the HTTP proxy runtime.
- gRPC session identity now uses the same validated claim-merging path as
  HTTP/WS, so explicit workload claims and verified bearer-token custom claims
  no longer disappear on the gRPC transport before policy evaluation.
- gRPC now ingests detached `x-request-signature` metadata too, and the final
  tool/resource/task/extension verdict envelopes refresh against a transport-
  derived runtime security context instead of auditing only the session-level
  identity snapshot.
- Canonical request binding and approval scope no longer derive persisted
  session scope from transport-facing session IDs. The HTTP proxy session store
  and stdio relay now mint opaque `session_scope_binding` values, preserve them
  in `client_provenance`, and use them for approval scope and canonical hash
  inputs instead of hashing or persisting raw session identifiers.
- The HTTP provenance helper path now uses typed allowlisted workload-claims
  decoding rather than reading generic OAuth claim maps in-place. Explicit
  workload claims win over projected transport identity for workload binding,
  while bearer-token custom claims are projected into session `agent_identity`
  before mediation rather than being pulled directly into audit context.
- HTTP transport runtime security contexts now also seal
  `client_provenance.canonical_request_hash` at build time, so pre-mediation
  deny, approval, and control-plane audit events carry the same opaque
  canonical request binding as the final mediated verdict path.
- Session-miss fallbacks in HTTP request mediation now preserve the current
  transport-authenticated identity instead of collapsing to an empty evaluation
  context.

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
