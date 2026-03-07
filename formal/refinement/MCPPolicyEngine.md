# MCP Policy Engine Refinement Map

Scope: [`formal/tla/MCPPolicyEngine.tla`](/home/paolo/.vella-workspace/sentinel/formal/tla/MCPPolicyEngine.tla) to the traced Rust evaluator in [`vellaveto-engine/src/traced.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/traced.rs) and [`vellaveto-engine/src/lib.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/src/lib.rs).

This artifact does not claim a full machine-checked forward simulation. It makes the missing refinement boundary explicit:
- an abstraction function from concrete Rust evaluation artifacts to TLA state
- per-transition simulation obligations
- executable witness tests for the highest-risk safety transitions

## Concrete Witness Boundary

The concrete state is observed through public traced evaluation APIs:
- `PolicyEngine::with_policies`
- `PolicyEngine::evaluate_action_traced`
- `PolicyEngine::evaluate_action_traced_with_context`
- `EvaluationTrace`

This uses trace output as the refinement witness instead of trying to model private Rust heap state directly.

## Abstraction Function

### Static State

| TLA object | Rust witness | Projection |
|---|---|---|
| `policies` | `PolicyEngine::with_policies(...).compiled_policies` | Sort by Rust's comparator, then project each compiled policy to `{ id, priority, type, requires_context, on_no_match_continue }` |
| `Policy.type` | `PolicyType` / traced `policy_type` string | `"Allow"`, `"Deny"`, `"Conditional"` |
| `Policy.requires_context` | `cp.context_conditions.is_empty()` | `TRUE` iff the compiled policy has at least one context condition |
| `Policy.on_no_match` | compiled conditional metadata | `TRUE` iff a Conditional policy can return `None` and continue |

### Dynamic State

| TLA variable | Rust witness | Projection |
|---|---|---|
| `pendingActions` | traced evaluation input | singleton set containing the current action before evaluation, empty after final verdict |
| `currentAction` | `Action` input plus `trace.action_summary` | `{ tool, function, has_context }` with raw parameters abstracted away |
| `verdicts` | `trace.verdict` | empty before completion, singleton map from the evaluated action to the final abstract verdict after completion |
| `engineState` | prefix of `EvaluationTrace` | `idle` before start, `matching` while consuming `PolicyMatch` entries, `applying` at the matched policy's contribution step, `done` after final verdict |
| `policyIndex` | position in `trace.matches` | 1-based index into the checked policy prefix |

### Trace Projection

Each `PolicyMatch` row is projected to one abstract transition:
- `tool_matched = false` -> `MatchPolicy` miss
- `tool_matched = true` and `verdict_contribution = Some(Allow)` -> `ApplyPolicy` allow
- `tool_matched = true` and `verdict_contribution = Some(Deny)` -> `ApplyPolicy` deny
- `tool_matched = true` and `verdict_contribution = Some(RequireApproval)` -> `ApplyConditionalApproval`
- `tool_matched = true` and `verdict_contribution = None` -> Conditional `on_no_match="continue"`

If the trace has no policy contribution and the final verdict is `"No matching policy"`, the abstract run ends in exhaustion of the policy sequence.

## Simulation Obligations

The refinement claim is split into explicit obligations.

### Initialization

`R-MCP-INIT-SORT`
- Rust `with_policies` order must refine `SortedByPriority` from the TLA model.
- Witness: compare the checked trace prefix against `PolicyEngine::sort_policies` on the same input policy set.

### Start

`R-MCP-START-EMPTY`
- Empty policy set must refine `StartEvaluation`'s fail-closed branch.
- Rust witness: `trace.matches = []`, `policies_checked = 0`, final verdict is `Deny("No policies defined")`.

`R-MCP-START-NONEMPTY`
- Non-empty policy set starts in abstract `matching` at index 1.
- Rust witness: every non-empty trace begins with the first checked policy in sorted order.

### Matching

`R-MCP-MATCH-MISS`
- A checked policy with `tool_matched = false` refines a TLA `MatchPolicy` miss.

`R-MCP-MATCH-HIT`
- A checked policy with `tool_matched = true` refines a TLA transition from `matching` to `applying`.

### Application

`R-MCP-APPLY-ALLOW`
- `verdict_contribution = Allow` refines `ApplyPolicy` allow.

`R-MCP-APPLY-DENY`
- `verdict_contribution = Deny` refines `ApplyPolicy` deny.
- This includes policy denies and fail-closed denies such as missing context.

`R-MCP-APPLY-REQUIRE-APPROVAL`
- `verdict_contribution = RequireApproval` refines `ApplyConditionalApproval`.

`R-MCP-CONTINUE`
- `tool_matched = true` with `verdict_contribution = None` refines a Conditional `on_no_match="continue"` transition back to `matching`.

`R-MCP-EXHAUSTED-NOMATCH`
- No contributing policy and final `Deny("No matching policy")` refines exhaustion of the policy sequence.

### Optimization Gap

`R-MCP-INDEX-STUTTER`
- The Rust engine may skip exact-tool policies that cannot match due to the tool index.
- This is a stuttering refinement obligation against the TLA full-scan machine:
  skipped concrete policies must satisfy `MatchesAction = FALSE` in the abstract model.
- This obligation is documented here but not yet machine-checked.

## Executable Witnesses

Executable witnesses live in [`vellaveto-engine/tests/refinement_trace.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/tests/refinement_trace.rs).

Covered obligations:
- `R-MCP-INIT-SORT`
- `R-MCP-START-EMPTY`
- `R-MCP-MATCH-MISS`
- `R-MCP-APPLY-ALLOW`
- `R-MCP-APPLY-DENY`
- `R-MCP-APPLY-REQUIRE-APPROVAL`
- `R-MCP-CONTINUE`
- `R-MCP-EXHAUSTED-NOMATCH`

Not yet covered:
- `R-MCP-INDEX-STUTTER`
- liveness / fairness obligations from TLA+
- full path, network, and IP-rule submachine refinement
- proof that abstract wildcard/exact matching soundly over-approximates all compiled matcher cases

## Current Claim

After this artifact, the project can claim:
- documented concrete-to-abstract mapping for the policy engine
- explicit simulation obligations instead of an implicit correspondence story
- executable refinement witnesses on the traced Rust evaluator

It still cannot claim:
- a machine-checked end-to-end refinement proof from TLA+ to Rust
- a verified simulation for tool-index stuttering or all submachines
