/**
 * AbacForbidOverride.als — Alloy model for ABAC forbid-override combining
 *
 * Models the ABAC combining algorithm from:
 *   vellaveto-engine/src/abac.rs:322-364
 *
 * Verifies 4 safety properties (S7-S10) about forbid-override semantics:
 *   S7:  Forbid dominance — any matching forbid produces Deny
 *   S8:  Forbid ignores priority — low-priority forbid beats high-priority permit
 *   S9:  Permit requires no forbid — Allow only when zero forbids match
 *   S10: No match -> NoMatch
 *
 * The core algorithm: scan ALL policies (not first-match); any matching forbid
 * produces Deny immediately, regardless of priority or position. This is the
 * XACML deny-overrides combining pattern.
 *
 * Correspondence:
 *   - Coq: formal/coq/Vellaveto/AbacForbidOverride.v (4 theorems)
 *   - TLA+: formal/tla/AbacForbidOverrides.tla (S7-S10, L3)
 *   - Lean 4: formal/lean/Vellaveto/AbacForbidOverride.lean (4 theorems)
 *
 * Run with Alloy Analyzer 6:
 *   java -jar org.alloytools.alloy.dist.jar AbacForbidOverride.als
 */

-- =========================================================================
-- Types
-- =========================================================================

/**
 * AbacEffect — the two possible policy effects.
 *
 * Maps to AbacEffect enum in vellaveto-engine/src/abac.rs.
 */
abstract sig AbacEffect {}
one sig Permit extends AbacEffect {}
one sig Forbid extends AbacEffect {}

/**
 * Principal — entity against which ABAC policies are evaluated.
 *
 * Maps to the requesting agent identity in EvaluationContext.
 */
sig Principal {}

/**
 * Attribute — abstract representation of entity attributes.
 */
sig Attribute {}

/**
 * AbacPolicy — a single ABAC policy entry.
 *
 * Fields:
 *   - effect: Permit or Forbid
 *   - priority: integer priority (for ordering, though forbid ignores it)
 *   - requiredAttrs: attributes that must be present for the policy to match
 *
 * Maps to the AbacPolicy struct in vellaveto-engine/src/abac.rs.
 */
sig AbacPolicy {
    effect: one AbacEffect,
    priority: one Int,
    requiredAttrs: set Attribute
}

/**
 * AbacDecision — the result of ABAC evaluation.
 */
abstract sig AbacDecision {}
one sig ADeny extends AbacDecision {}
one sig AAllow extends AbacDecision {}
one sig ANoMatch extends AbacDecision {}

/**
 * EvalContext — the evaluation context with principal and attributes.
 */
sig EvalContext {
    principal: one Principal,
    attrs: set Attribute,
    matchingPolicies: set AbacPolicy,
    result: one AbacDecision
}

-- =========================================================================
-- Facts
-- =========================================================================

/**
 * Fact: A policy matches if the principal has all required attributes.
 */
fact MatchingDefinition {
    all ctx: EvalContext, p: AbacPolicy |
        p in ctx.matchingPolicies iff p.requiredAttrs in ctx.attrs
}

/**
 * Fact: Priority is bounded for tractable model checking.
 */
fact BoundedPriority {
    all p: AbacPolicy | p.priority >= 0 and p.priority <= 5
}

/**
 * Fact: ABAC combining algorithm — forbid-override semantics.
 *
 * Models abac.rs:322-364:
 * - If ANY matching policy has effect=Forbid -> ADeny
 * - Else if ANY matching policy has effect=Permit -> AAllow
 * - Else -> ANoMatch
 *
 * This is the CRITICAL encoding: forbid dominates regardless of priority.
 */
fact AbacCombining {
    all ctx: EvalContext |
        (some p: ctx.matchingPolicies | p.effect = Forbid)
            implies ctx.result = ADeny
        else (some p: ctx.matchingPolicies | p.effect = Permit)
            implies ctx.result = AAllow
        else ctx.result = ANoMatch
}

-- =========================================================================
-- Assertions (S7-S10)
-- =========================================================================

/**
 * S7: Forbid Dominance — any matching forbid produces Deny.
 *
 * If any policy in the matching set has effect=Forbid, the result is ADeny.
 * This holds regardless of how many Permit policies also match.
 *
 * Maps to abac.rs:226-230 (immediate exit on first forbid match).
 */
assert S7_ForbidDominance {
    all ctx: EvalContext |
        (some p: ctx.matchingPolicies | p.effect = Forbid)
        implies ctx.result = ADeny
}

/**
 * S8: Forbid Ignores Priority — low-priority forbid beats high-priority permit.
 *
 * Even when a Permit policy has higher priority than a Forbid policy,
 * the Forbid still produces ADeny. Priority ordering is irrelevant for
 * the forbid-override combining algorithm.
 *
 * This is a KEY difference from the first-match engine: ABAC collects
 * ALL matching policies, and Forbid dominates regardless of position.
 */
assert S8_ForbidIgnoresPriority {
    all ctx: EvalContext, pf: AbacPolicy, pp: AbacPolicy |
        (pf in ctx.matchingPolicies and pf.effect = Forbid and
         pp in ctx.matchingPolicies and pp.effect = Permit and
         pp.priority > pf.priority)
        implies ctx.result = ADeny
}

/**
 * S9: Permit Requires No Forbid — Allow only when zero forbids match.
 *
 * If the result is AAllow, then no matching policy has effect=Forbid.
 * Contrapositive of S7.
 *
 * Maps to abac.rs:232-236.
 */
assert S9_PermitRequiresNoForbid {
    all ctx: EvalContext |
        ctx.result = AAllow implies
            no p: ctx.matchingPolicies | p.effect = Forbid
}

/**
 * S10: No Match -> NoMatch.
 *
 * If no policy matches (empty matching set), the result is ANoMatch.
 * The caller (policy engine) converts ANoMatch to Deny (fail-closed).
 *
 * Maps to abac.rs:239.
 */
assert S10_NoMatchNoMatch {
    all ctx: EvalContext |
        no ctx.matchingPolicies implies ctx.result = ANoMatch
}

-- =========================================================================
-- Check commands
-- =========================================================================

/**
 * Scope: 4 policies, 3 attributes, 2 principals, 3 contexts.
 *
 * Sufficient because:
 * - 4 policies allow mixed Permit/Forbid with varying priorities
 * - 3 attributes enable partial matching scenarios
 * - 3 contexts check different matching combinations
 * - 6 Int gives range [-32, 31] for priorities
 *
 * All checks should report 0 counterexamples.
 */
check S7_ForbidDominance for 4 AbacPolicy, 3 Attribute, 2 Principal, 3 EvalContext, 6 Int
check S8_ForbidIgnoresPriority for 4 AbacPolicy, 3 Attribute, 2 Principal, 3 EvalContext, 6 Int
check S9_PermitRequiresNoForbid for 4 AbacPolicy, 3 Attribute, 2 Principal, 3 EvalContext, 6 Int
check S10_NoMatchNoMatch for 4 AbacPolicy, 3 Attribute, 2 Principal, 3 EvalContext, 6 Int

-- =========================================================================
-- Example: show a mixed permit/forbid scenario
-- =========================================================================

/**
 * Generate an example where both Permit and Forbid policies match
 * to visualize the forbid-override behavior.
 */
pred showForbidOverride {
    some ctx: EvalContext |
        some p1: ctx.matchingPolicies | p1.effect = Permit and
        some p2: ctx.matchingPolicies | p2.effect = Forbid
}
run showForbidOverride for 4 AbacPolicy, 3 Attribute, 2 Principal, 3 EvalContext, 6 Int
