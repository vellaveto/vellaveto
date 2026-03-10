# Vellaveto Formal Verification Paper

Draft artifact paper for the formal verification work in this repository.

Snapshot date: March 9, 2026
Repository scope: the proofs, models, scripts, and supporting documentation
checked into this repository at that date
Live inventory: [README.md](README.md)

## Abstract

Vellaveto is a runtime security boundary for Model Context Protocol (MCP) tool
invocations and related agent actions. Its security posture depends on a small
set of safety-critical invariants: policy evaluation must fail closed, explicit
denies must dominate implicit or derived allows, delegated capabilities must
attenuate rather than expand, approval tokens must be scope-bound and single
use, and audit evidence must be tamper evident. This artifact describes the
multi-method formal verification strategy used to justify those invariants.

The repository combines TLA+ model checking, Alloy bounded relational models,
Lean 4 and Coq theorem proving, Verus deductive verification over production
Rust kernels, and Kani bounded model checking over production Rust code. The
verification stack is intentionally layered: abstract models capture protocol
and state-machine behavior, while implementation-oriented proofs target the
actual Rust kernels that compute verdicts, normalize paths, process approvals,
project security context, and validate audit structures. The repository also
ships an explicit trusted-assumption inventory, a refinement map between the
policy-engine model and the traced evaluator, and a Dockerized reproduction
environment with pinned toolchains.

This paper does not claim that the entire system is end-to-end mechanically
proved. Instead, it states a narrower and more defensible claim: the
security-critical pure logic at the runtime boundary is covered by a
complementary proof mesh, and the remaining trust assumptions are explicit.

## 1. Introduction

MCP gateways and agent firewalls sit on a difficult boundary. They parse
untrusted requests, decide whether a side effect may proceed, project identity
and session context across transports, and record evidence that later security
or compliance workflows will rely on. A bug in this layer is disproportionately
expensive because it can turn a policy engine into an implicit capability
escalation mechanism.

Traditional test suites are necessary but not sufficient here. They are strong
at regression prevention and interoperability checks, but they are weaker at
answering the questions that matter most for a policy boundary:

- Can an unmatched action ever produce `Allow`?
- Can a delegated capability become broader than its parent?
- Can a consumed approval token be replayed?
- Can parser or normalization edge cases open a path around a deny rule?
- Can audit verification silently accept a malformed chain?

The formal work in this repository aims to answer those questions with proof
artifacts instead of prose. The result is not one monolithic proof, but a
verification architecture that uses different tools for different kinds of
claims.

## 2. System Scope

The verification scope is the runtime boundary implemented by the Vellaveto
workspace. At a high level, a request enters through one of the supported
surfaces, is normalized into an action, is evaluated against policy and related
security state, and yields an `Allow`, `Deny`, or `RequireApproval` decision
plus audit metadata.

The proof-relevant subsystems include:

- Policy evaluation and rule override behavior in `vellaveto-engine`.
- Capability delegation, deputy validation, and transport context projection in
  `vellaveto-mcp`.
- Approval scope binding and consumption gates shared across runtime paths.
- Audit append, audit verification, Merkle proof structure, and rotation
  manifest linkage in `vellaveto-audit`.
- Input normalization kernels such as path normalization, IDNA handling, and
  DLP buffer arithmetic.
- Selected state machines such as task lifecycle, credential-vault behavior,
  and cascading-failure control flow.

The repository-wide inventory of models and proof kernels is maintained in
[README.md](README.md). The trusted boundary is described in
[../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md).

## 3. Verification Goals

The formal work is organized around a small set of security claims:

1. Fail-closed mediation. Missing policy, missing context, malformed
   intermediate state, or explicit deny conditions must never produce `Allow`.
2. Monotonic delegation. Capability grants and delegated identity chains may
   attenuate privileges but may not expand them.
3. Approval safety. Approval tokens must be bound to the correct action and
   session and must not be reusable after consumption.
4. Tamper-evident evidence. Audit verification logic must reject malformed hash
   chains, malformed Merkle proofs, and inconsistent rotation manifests.
5. Safe normalization. Normalization and parsing helpers must not create a
   bypass channel around the policy boundary by silently widening a path,
   domain, or payload interpretation.

These goals are narrower than "the entire program is verified", but they are
the right goals for a security boundary. They target the decisions whose
failure would most directly violate the product's security contract.

## 4. Multi-Method Verification Architecture

### 4.1 TLA+

TLA+ models the protocol and state-machine level behavior:

- Policy-engine safety and fail-closed defaults.
- ABAC forbid-override behavior.
- Task lifecycle safety.
- Cascading-failure state transitions.
- Capability-delegation invariants.
- Credential-vault state transitions.
- Audit-chain integrity.

This level is useful when the claim is about whole-machine behavior rather than
an individual Rust helper. It answers questions such as whether terminal task
states are absorbing or whether a credential-vault epoch can move backward.

### 4.2 Alloy

Alloy is used for compact bounded models where relational structure matters more
than operational control flow. In this repository it is primarily used for
delegation attenuation and ABAC combining logic.

### 4.3 Lean 4 and Coq

Lean 4 and Coq provide theorem-proved semantic properties over abstract models,
including fail-closed behavior, determinism, path normalization, ABAC
forbid-override, and capability attenuation.

These proofs provide a clean semantic baseline, but by themselves they do not
eliminate the refinement gap between abstract models and the implementation.
That gap is addressed separately.

### 4.4 Verus

Verus is the implementation-facing core of the stack. It proves properties over
production Rust kernels rather than over a separate reference implementation.
Representative proof families include:

- Core verdict computation and rule override behavior.
- Constraint-evaluation fail-closed control flow.
- Approval scope binding and consumption gates.
- Approval-ID validation for transport and server paths.
- Capability matching, subset checks, grant coverage, and identity-chain
  guards.
- Deputy and principal handoff logic.
- Audit append and verification guards.
- Merkle append, fold, path, and rotation-manifest structure.
- Cross-call DLP arithmetic and path normalization.
- ACIS envelope validation.

This is the strongest evidence in the repository because it operates on the
same Rust kernels that ship in the workspace, rather than on a handwritten
mathematical abstraction.

### 4.5 Kani

Kani complements Verus by model checking concrete Rust code within bounded
domains. Its harnesses are used both for standalone implementation properties
and as bridges around deductive proof preconditions. For example, Kani can show
that a sorting routine establishes the precondition needed by a Verus proof of
priority-sensitive verdict behavior.

The Kani harnesses also target areas where bounded exhaustive exploration is a
good fit:

- IP classification.
- Cache safety.
- Constraint-evaluation edge cases.
- Unicode and IDNA normalization.
- RwLock poisoning fail-closed behavior.
- Sanitizer round-trip properties.
- Cascading-failure finite-state-machine transitions.

## 5. Representative Verified Properties

The repository contains a large inventory of individual proof obligations. This
paper groups them by security meaning rather than by file count.

### 5.1 Fail-Closed Policy Evaluation

The core claim is that the policy engine cannot produce `Allow` without an
explicit, matching allow path. This claim is backed at multiple levels:

- TLA+ models fail-closed defaults and priority ordering.
- Lean 4 and Coq prove the abstract fail-closed semantics.
- Verus proves the core Rust verdict computation for all inputs.
- Kani checks bounded concrete harnesses, including error and edge cases.

This is the central claim for the runtime boundary because almost every other
security property depends on it.

### 5.2 Delegation and Identity Attenuation

Capability and identity delegation are classic escalation surfaces. The proof
stack covers attenuation from multiple angles:

- Abstract monotonic attenuation in TLA+, Alloy, Lean 4, and Coq.
- Concrete matching, subset, grant-coverage, and identity-chain checks in
  Verus.
- Bounded checks for grant subset behavior and normalization in Kani.

The important result is not only that delegation is modeled, but that the
concrete Rust guards used by the runtime are themselves proof targets.

### 5.3 Approval Safety

Approval flows are vulnerable to replay, cross-session reuse, and path
inconsistency across transports. The implementation-facing proofs cover:

- Action-fingerprint and session binding.
- Single-use consumption gates.
- Presented approval-ID validation on transport paths.
- Server approval-ID validation on HTTP-facing paths.

These proofs are deliberately scoped to the fail-closed gate conditions that
separate "approval exists" from "approval is valid for this action now".

### 5.4 Audit Integrity

The audit subsystem is security-critical because later non-repudiation claims
depend on it. The verified pieces include:

- Append and recovery counter transitions.
- Hash-chain verification guards.
- Merkle proof shape and fold invariants.
- Cross-rotation manifest linkage.
- ACIS envelope validation helpers.

The proof claim here is structural integrity, not cryptographic primitive
correctness. Primitive correctness remains an explicit trust assumption.

### 5.5 Normalization and Parser Boundaries

Several recent security findings in agent tooling have involved Unicode, path,
or multi-step decoding edge cases. This repository therefore treats
normalization kernels as first-class proof targets:

- Path normalization idempotence and no-traversal.
- DLP buffer arithmetic and overlap safety.
- IDNA fail-closed handling.
- Homoglyph normalization and confusable collapse.
- Lock-poisoning handlers that must never degrade to stale `Allow`.

This is one of the most practical strengths of the artifact: it focuses formal
effort on the helpers most likely to create security boundary bypasses.

## 6. Refinement Story

The repository does not claim a complete machine-checked forward simulation from
the TLA+ models to the entire Rust implementation. Instead, it makes the
refinement boundary explicit in
[refinement/MCPPolicyEngine.md](refinement/MCPPolicyEngine.md).

That artifact provides:

- An abstraction function from concrete traced evaluation artifacts to TLA
  state.
- Per-transition simulation obligations.
- Executable witness tests for the highest-risk safety transitions.
- An explicit list of what is still not proved, including tool-index stuttering
  and full submachine refinement.

This is an important engineering choice. A weak paper would blur the line
between abstract models and implementation proofs. This artifact does the
opposite: it names the gap, narrows it with implementation-level proofs, and
documents the remaining obligations.

## 7. Trusted Assumptions and TCB Discipline

The project treats the Trusted Computing Base as part of the artifact, not as a
footnote. The canonical boundary is documented in
[../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md), and the
trusted-assumption inventory is checked by
`formal/tools/check-formal-trusted-assumptions.sh`.

The trusted portion includes, among other things:

- Compiler and proof-tool correctness.
- Cryptographic primitive implementations.
- Operating-system and filesystem semantics.
- DNS and external network infrastructure.
- The assumption that runtime entrypoints actually mediate the relevant actions.

The repository's formal claim is therefore conditional but explicit: verified
logic plus enumerated trusted assumptions, rather than an implied proof of the
entire deployed environment.

## 8. Reproducibility

The artifact is intended to be rerun, not merely read.

Top-level entrypoints:

```bash
make formal
make verify
```

Tool-specific entrypoints:

```bash
make formal-tla
make formal-alloy
make formal-lean
make formal-coq
make formal-kani
make formal-verus
make formal-trusted-assumptions
```

Dockerized reproduction:

```bash
docker build -t vellaveto-formal formal/
docker run --rm -v "$(pwd):/workspace" vellaveto-formal
```

The Docker image in [Dockerfile](Dockerfile) pins the formal toolchain versions
used by the repository's verification environment, including Rust toolchains,
Verus, Kani, TLA+, and Lean tooling.

## 9. Limitations

This paper makes a strong but bounded claim.

It does not claim:

- A full end-to-end proof of the entire workspace.
- A machine-checked refinement proof from every abstract model to all runtime
  code paths.
- Proof of cryptographic primitives, network behavior, timing behavior, or the
  operating system.
- Proof that every transport integration preserves complete mediation under all
  possible deployment mistakes.

It also relies on the standard limitations of its constituent tools:

- TLA+ is exhaustive only within declared model bounds.
- Kani is bounded model checking, not unbounded proof.
- Lean 4 and Coq proofs target abstract semantics rather than the full Rust
  runtime.
- Verus proofs focus on extracted or isolated Rust kernels, not every line of
  glue code.

These limits are not hidden. They are part of the documented artifact contract.

## 10. Why This Matters

Formal verification is most valuable when it is pointed at the narrow waist of
a security architecture: the small amount of logic that decides whether
side-effecting actions may proceed. That is the design principle behind this
artifact.

Instead of trying to prove everything badly, the repository proves the parts
whose failure would directly break the security boundary:

- verdict computation,
- delegation attenuation,
- approval gates,
- audit verification,
- normalization kernels, and
- security context projection.

The result is not a proof that the whole system is perfect. It is a stronger
and more practical claim: the logic that must fail closed has been singled out,
specified, checked with multiple methods, and tied to an explicit trust
boundary.

## 11. Artifact References

- Live proof inventory: [README.md](README.md)
- Trusted computing base: [../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md)
- Scope and non-goals: [../docs/FORMAL_SCOPE.md](../docs/FORMAL_SCOPE.md)
- Assurance case: [../docs/ASSURANCE_CASE.md](../docs/ASSURANCE_CASE.md)
- Refinement map: [refinement/MCPPolicyEngine.md](refinement/MCPPolicyEngine.md)
- Verus guide: [verus/README.md](verus/README.md)
- Kani guide: [kani/README.md](kani/README.md)
- Reproducible formal environment: [Dockerfile](Dockerfile)
