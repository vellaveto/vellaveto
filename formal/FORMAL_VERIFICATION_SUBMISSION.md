# Formal Verification of a Runtime Security Boundary for Model Context Protocol Tool Calls

Paolo Vella
Vellaveto
`security@vellaveto.online`

## Abstract

Runtime mediation for AI agents is security-critical because the mediator
decides whether side-effecting tool invocations may proceed. A mediator that
fails open ceases to be a meaningful security control. This paper presents the
formal verification program for Vellaveto, a runtime security boundary for
Model Context Protocol (MCP) tool calls and adjacent agent actions. The work
combines TLA+ model checking, Alloy bounded relational modeling, Lean 4 and
Coq theorem proving, Verus deductive verification over production Rust
kernels, and Kani bounded model checking over production Rust code. The
objective is not a monolithic proof of the entire system, but a layered proof
architecture for the narrow waist of the security design: fail-closed verdict
computation, delegation attenuation, approval safety, audit-chain integrity,
and normalization kernels that could otherwise create bypass channels. The
repository further exposes a checked trusted-assumption inventory, an explicit
refinement map from abstract policy models to traced Rust evaluation, and
pinned reproducibility entrypoints. The resulting claim is intentionally
narrow: the security-critical pure logic at the runtime boundary is covered by
a complementary proof mesh, and the remaining trust assumptions are explicit.

## Keywords

formal verification, MCP, agent security, policy enforcement, Rust, Verus,
Kani, TLA+, audit integrity, capability delegation

## 1. Introduction

Model Context Protocol servers and agent frameworks increase the set of actions
large-language-model-based systems can take on the world. Those actions include
filesystem access, network calls, command execution, resource reads, and other
operations with persistent or externally visible consequences. The natural place
to enforce security policy is the runtime boundary between an agent and the tool
or service it invokes.

That boundary is a difficult verification target. It is not enough to show that
the policy language is expressive, or that common attacks are covered by a test
suite. The crucial question is whether the implementation can make the wrong
decision under edge conditions:

- Can an unmatched request ever produce `Allow`?
- Can a delegated capability become broader than the parent that issued it?
- Can approval tokens be replayed across sessions or across different actions?
- Can normalization or decoding corner cases create a bypass around a deny
  rule?
- Can audit verification silently accept malformed state and thereby undermine
  later integrity claims?

This paper argues that such a boundary benefits from a layered proof strategy.
Abstract state-machine models are necessary, but insufficient on their own. The
implementation must also be targeted directly, especially the pure kernels that
compute verdicts, validate structure, and project sensitive context.

The work described here is implemented in the `formal/` subtree of the
repository and targets the runtime security logic in the Vellaveto workspace.
The verified claims are narrower than "the whole system is proved", but they
cover the logic whose failure would most directly invalidate the system's
security contract.

The paper makes three main claims. First, the repository contains a
multi-method verification architecture in which each proof technology is used
for the class of property it models well. Second, the strongest proof layer is
implementation-facing: Verus and Kani target production Rust kernels rather
than a separate executable specification. Third, the artifact states its proof
boundary explicitly through a refinement map and a checked trusted-assumption
inventory, rather than leaving that boundary implicit.

## 2. Problem Statement

An MCP security boundary is only meaningful if it fails closed and preserves
monotonicity across derived security state. In practice, that means at least
the following properties:

1. Missing policy, missing context, malformed derived state, or explicit deny
   conditions must not produce `Allow`.
2. Capability delegation must only attenuate privilege, never expand it.
3. Approval gates must be tied to the intended action and session and must not
   be reusable after successful consumption.
4. Audit verification must reject malformed chains, malformed Merkle proofs,
   inconsistent rotation manifests, and malformed structured decision metadata.
5. Parser, normalization, and decoding helpers must not create alternate
   interpretations that widen access beyond what policy intended.

These are implementation-facing safety obligations. They cannot be discharged by
benchmark numbers, API documentation, or integration tests alone.

## 3. Scope

The proof scope is the runtime security boundary implemented by the Vellaveto
workspace. At a high level, requests arrive through one of several transport
surfaces, are normalized into actions, are evaluated against policy and
security-relevant context, and yield a verdict plus audit metadata.

The proof-relevant subsystems include:

- policy evaluation and rule override behavior in `vellaveto-engine`,
- capability delegation, deputy validation, and context projection in
  `vellaveto-mcp`,
- approval scope binding and approval consumption gates,
- audit append and verification logic in `vellaveto-audit`,
- normalization kernels such as path normalization, IDNA handling, and DLP
  buffer arithmetic, and
- selected state machines such as task lifecycle, credential-vault behavior,
  and cascading-failure transitions.

The proof inventory is maintained in [README.md](README.md). The trusted
boundary is documented in
[../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md).

## 4. Contributions

This work makes five concrete contributions.

### 4.1 A multi-method verification architecture

The repository combines TLA+, Alloy, Lean 4, Coq, Verus, and Kani rather than
depending on a single proof technology. Each tool is assigned the kind of claim
it handles well: state-machine properties, relational attenuation, abstract
semantics, deductive Rust-kernel proofs, or bounded model checking of concrete
code.

### 4.2 Implementation-facing deductive proofs over production Rust kernels

The strongest component of the artifact is the Verus suite, which targets
production Rust kernels rather than a separate reference implementation. This
includes verdict computation, constraint evaluation, approval gates, capability
checks, audit verification, Merkle structure, path normalization, DLP
arithmetic, and ACIS envelope validation.

### 4.3 Bridge harnesses between abstract and concrete proof layers

Kani harnesses are used not only for standalone properties, but also to bridge
preconditions around deductive proofs. For example, bounded model checking is
used to establish ordering properties that support proofs of priority-sensitive
verdict behavior.

### 4.4 An explicit refinement and trust-boundary story

The repository does not hand-wave correspondence between abstract models and
implementation logic. Instead, it includes a refinement map in
[refinement/MCPPolicyEngine.md](refinement/MCPPolicyEngine.md) and a checked
trusted-assumption inventory. This makes the proof boundary inspectable.

### 4.5 Reproducibility infrastructure

The repository exposes top-level reproduction entrypoints through `make formal`
and `make verify`, and ships a pinned Docker image in [Dockerfile](Dockerfile)
for replaying the formal environment.

## 5. Verification Architecture

### 5.1 TLA+

TLA+ is used for operational state-machine and protocol properties, including:

- fail-closed policy-engine behavior,
- ABAC forbid-override semantics,
- task lifecycle safety,
- cascading-failure control flow,
- capability-delegation invariants,
- credential-vault transitions, and
- audit-chain integrity.

This layer is best suited to properties about allowed transitions and global
invariants rather than line-by-line implementation behavior.

### 5.2 Alloy

Alloy is used for compact bounded relational models, especially around
capability attenuation and ABAC combining logic. These models are useful where
structure matters more than stepwise control flow.

### 5.3 Lean 4 and Coq

Lean 4 and Coq encode semantic properties over abstract models, including
fail-closed evaluation, determinism, path normalization, ABAC
forbid-override, and delegation attenuation. These proofs establish clean
semantic baselines, but do not by themselves eliminate the refinement gap to
the Rust implementation.

### 5.4 Verus

Verus is the implementation-oriented core of the stack. It proves properties
over extracted or isolated Rust kernels from the production codebase. Examples
include:

- core verdict computation and rule overrides,
- constraint-evaluation fail-closed control flow,
- approval binding and single-use consumption gates,
- approval-ID validation on transport and server paths,
- capability matching, subset, grant-coverage, and identity-chain guards,
- deputy and principal handoff logic,
- audit append and audit verification guards,
- Merkle append, fold, path, and rotation-manifest structure,
- cross-call DLP arithmetic,
- path normalization, and
- ACIS envelope validation.

This is the layer that most directly supports the claim that the runtime
boundary's security-critical pure logic has proof coverage on actual Rust code.

### 5.5 Kani

Kani complements Verus by exploring bounded concrete execution spaces in actual
Rust code. It is well suited for finite-state and edge-condition properties,
including:

- IP classification,
- cache safety,
- grant subset behavior,
- constraint edge cases,
- Unicode and IDNA normalization,
- RwLock poisoning fail-closed behavior,
- sanitizer inversion properties, and
- cascading-failure finite-state-machine transitions.

## 6. Representative Verified Properties

The repository contains many individual proof obligations. For exposition, they
are grouped here by security meaning.

### 6.1 Fail-closed verdict computation

The central safety claim is that unmatched or malformed evaluation state must
not yield `Allow`. This is supported at multiple levels:

- TLA+ models fail-closed defaults and priority ordering.
- Lean 4 and Coq prove abstract fail-closed semantics.
- Verus proves the core Rust verdict kernel for all inputs.
- Kani checks bounded concrete harnesses, including error and edge cases.

This property is the cornerstone of the entire runtime boundary. If it fails,
the rest of the design is largely moot.

### 6.2 Rule override and deny dominance

Security boundaries often fail not because the base policy is wrong, but
because an override path is mishandled. The proofs therefore isolate path and
network block behavior and ensure that rule-level deny conditions dominate the
final verdict when triggered.

### 6.3 Delegation attenuation

Capability and identity delegation are first-class escalation surfaces. The
proof stack covers them through abstract attenuation models and concrete Rust
guards for matching, subset checks, grant coverage, identity-chain continuity,
and depth restrictions.

### 6.4 Approval safety

Approval paths are verified as gates, not merely as workflow artifacts. The
implementation-facing proofs target session binding, action-fingerprint binding,
single-use consumption, and the validation of approval identifiers carried
through transport and HTTP-facing paths.

### 6.5 Audit integrity

Tamper evidence is structurally verified through audit append and recovery
counters, hash-chain verification guards, Merkle proof structure, rotation
manifest linkage, and structured envelope validation. The verified claim is
structural integrity, not proof of underlying cryptographic primitives.

### 6.6 Safe normalization and decoding

Several recent attack classes against agent tooling depend on alternate parsing
or normalization paths. This repository therefore treats helpers such as path
normalization, DLP buffer arithmetic, homoglyph collapse, IDNA fail-closed
handling, and lock-poisoning handlers as proof-relevant kernels.

## 7. Refinement Boundary

This work does not claim a complete machine-checked forward simulation from the
TLA+ models to the full Rust implementation. Instead, it documents the
refinement boundary explicitly in
[refinement/MCPPolicyEngine.md](refinement/MCPPolicyEngine.md).

That artifact defines:

- an abstraction function from traced Rust evaluation to abstract TLA state,
- per-transition simulation obligations,
- executable witness tests for selected high-risk safety transitions, and
- explicit non-claims, including unfinished obligations such as full
  stuttering-refinement coverage.

This is a deliberate methodological choice. The artifact narrows the gap rather
than pretending the gap does not exist.

## 8. Trusted Assumptions

The verified claims in this paper are conditional on a named trust boundary.
The relevant assumptions include:

- compiler and proof-tool correctness,
- cryptographic primitive correctness,
- operating-system and filesystem semantics,
- DNS and network infrastructure behavior, and
- the assumption that the runtime boundary is actually invoked for the actions
  being controlled.

The repository treats this as an auditable part of the artifact through
[../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md) and the
checked assumption inventory under `formal/tools/`.

## 9. Reproducibility

The artifact can be replayed using the repository entrypoints:

```bash
make formal
make verify
```

Tool-specific targets:

```bash
make formal-tla
make formal-alloy
make formal-lean
make formal-coq
make formal-kani
make formal-verus
make formal-trusted-assumptions
```

Pinned Docker environment:

```bash
docker build -t vellaveto-formal formal/
docker run --rm -v "$(pwd):/workspace" vellaveto-formal
```

The Docker image pins the major formal toolchains used by the artifact,
including Rust, Verus, Kani, TLA+, and Lean tooling.

## 10. Related Work

This artifact sits at the intersection of formal methods and runtime security
mediation.

At the methods level, it builds on well-established verification ecosystems:

- TLA+ for state-machine model checking,
- Alloy for bounded relational reasoning,
- Coq and Lean 4 for machine-checked semantics, and
- Verus and Kani for implementation-oriented verification of Rust code.

At the application level, the novelty is not a new logic, but the application
of a mixed proof stack to the runtime mediation layer of MCP-style tool calls.
The repository's proof strategy differs from papers that verify a standalone
algorithm in isolation: the target here is a security boundary whose failure
mode is privilege-bearing.

## 11. Threats to Validity

Several limitations affect the strength of the overall claim.

### 11.1 No end-to-end proof

The repository does not contain a full end-to-end mechanical proof of the
entire deployed system. Glue code, network behavior, and external dependencies
remain outside the strongest proof layer.

### 11.2 Bounded tools remain bounded

TLA+ and Kani results are exhaustive only within their configured bounds or
symbolic encodings. They are strong evidence, but they are not substitutes for
unbounded deductive proofs in every domain.

### 11.3 Abstract-model correspondence remains partial

Lean 4 and Coq proofs target abstract semantics. They strengthen the semantic
story, but do not remove the implementation-refinement problem on their own.

### 11.4 Cryptography and environment are assumed

Cryptographic primitive correctness, operating-system behavior, filesystem
semantics, and DNS or network infrastructure remain trusted assumptions rather
than proved properties.

## 12. Conclusion

This paper presents a formal verification program for a runtime security
boundary rather than for a single algorithm in isolation. The central idea is
to concentrate proof effort on the narrow waist of the system: the pure logic
that decides whether a side effect may proceed and whether the evidence
describing that decision is structurally sound.

The resulting claim is intentionally modest but meaningful. The repository does
not prove the entire system correct. It does, however, provide a layered and
reproducible proof mesh over the logic whose failure would most directly break
the security boundary: fail-closed verdict computation, delegation attenuation,
approval safety, audit integrity, and normalization kernels. By pairing those
proofs with an explicit trust boundary and an explicit refinement story, the
artifact aims to make its strongest claims both useful and reviewable.

## References

1. Leslie Lamport. "The Temporal Logic of Actions." ACM Transactions on
   Programming Languages and Systems, 1994.
2. Leslie Lamport. *Specifying Systems*. Addison-Wesley, 2002.
3. Daniel Jackson. *Software Abstractions: Logic, Language, and Analysis*.
   MIT Press, 2012.
4. David R. MacIver et al. Verus project documentation and publications.
   <https://github.com/verus-lang/verus>
5. Kani Rust Verifier project. <https://github.com/model-checking/kani>
6. Lean 4 theorem prover. <https://lean-lang.org/>
7. Coq proof assistant. <https://coq.inria.fr/>
8. Model Context Protocol specification. <https://modelcontextprotocol.io/>
9. Repository proof inventory: [README.md](README.md)
10. Trusted computing base: [../docs/TRUSTED_COMPUTING_BASE.md](../docs/TRUSTED_COMPUTING_BASE.md)
11. Formal scope and non-goals: [../docs/FORMAL_SCOPE.md](../docs/FORMAL_SCOPE.md)
12. Refinement map: [refinement/MCPPolicyEngine.md](refinement/MCPPolicyEngine.md)
13. Reproducible formal environment: [Dockerfile](Dockerfile)
