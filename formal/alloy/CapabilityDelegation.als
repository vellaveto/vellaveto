/**
 * CapabilityDelegation.als — Alloy model for capability token delegation
 *
 * Models the capability-based delegation system from:
 *   vellaveto-mcp/src/capability_token.rs
 *   vellaveto-types/src/capability.rs
 *
 * Verifies 6 safety properties (S11–S16) about monotonic attenuation,
 * delegation depth bounds, temporal monotonicity, and issuer chain integrity.
 *
 * Design decisions:
 *   - Time is abstractly modeled with a total order (no real timestamps)
 *   - Pattern matching reduced to Wildcard + Exact (see MCPCommon.tla rationale)
 *   - MAX_DELEGATION_DEPTH reduced to 4 for tractable model checking
 *     (the properties are depth-independent)
 *   - Signatures use bounded scopes (5 tokens, 4 grants, 3 principals, 3 times)
 *
 * Run with Alloy Analyzer 6:
 *   java -jar org.alloytools.alloy.dist.jar CapabilityDelegation.als
 */

-- =========================================================================
-- Abstract types
-- =========================================================================

/**
 * Pattern — models glob patterns used in grants.
 *
 * Abstracted to two cases matching MCPCommon.tla's PatternMatch:
 *   Wildcard: matches everything (pattern = "*")
 *   ExactPattern: matches only itself
 *
 * Maps to pattern_matches() at capability_token.rs:419-430
 */
abstract sig Pattern {}
one sig Wildcard extends Pattern {}
sig ExactPattern extends Pattern {}

/**
 * Principal — an entity that can hold or issue tokens.
 *
 * Maps to the issuer/holder string fields in CapabilityToken.
 */
sig Principal {}

/**
 * Path — a target path that can appear in grants.
 */
sig Path {}

/**
 * Domain — a target domain that can appear in grants.
 */
sig Domain {}

/**
 * Time — abstract time with a total order.
 *
 * Design decision: We use Alloy's ordering utility to impose a total order
 * on Time atoms. This captures temporal monotonicity (child.expiry <= parent.expiry)
 * without requiring date arithmetic.
 */
open util/ordering[Time]
sig Time {}

-- =========================================================================
-- Grant — a permission scope within a capability token
-- =========================================================================

/**
 * Grant — models CapabilityGrant from vellaveto-types/src/capability.rs.
 *
 * Each grant specifies:
 *   - toolPattern: which tools this grant covers
 *   - funcPattern: which functions this grant covers
 *   - allowedPaths: set of paths this grant permits (empty = unrestricted)
 *   - allowedDomains: set of domains this grant permits (empty = unrestricted)
 *
 * Maps to the CapabilityGrant struct fields:
 *   tool_pattern, function_pattern, allowed_paths, allowed_domains
 */
sig Grant {
    toolPattern: one Pattern,
    funcPattern: one Pattern,
    allowedPaths: set Path,
    allowedDomains: set Domain
}

-- =========================================================================
-- Token — a capability delegation token
-- =========================================================================

/**
 * Token — models CapabilityToken from vellaveto-types/src/capability.rs.
 *
 * Fields:
 *   - parent: the token this was delegated from (none for root tokens)
 *   - issuer: who created this token
 *   - holder: who can use this token
 *   - grants: set of permission grants
 *   - depth: remaining delegation depth (0 = terminal, cannot delegate further)
 *   - expiry: when this token expires
 *
 * Maps to CapabilityToken struct:
 *   parent_token_id, issuer, holder, grants, remaining_depth, expires_at
 */
sig Token {
    parent: lone Token,          -- lone = 0 or 1 (root tokens have no parent)
    issuer: one Principal,
    holder: one Principal,
    grants: some Grant,          -- some = 1 or more (non-empty, validate_structure)
    depth: one Int,
    expiry: one Time
}

-- =========================================================================
-- Constants
-- =========================================================================

/**
 * MAX_DELEGATION_DEPTH — reduced from 16 (capability.rs:21) to 4 for
 * tractable model checking. The properties (monotonic attenuation, depth
 * bounds, etc.) are independent of the specific maximum value.
 */
let MAX_DEPTH = 4

-- =========================================================================
-- Structural facts (well-formedness constraints)
-- =========================================================================

/**
 * Fact: Depth is bounded [0, MAX_DEPTH].
 *
 * Maps to:
 *   - MAX_DELEGATION_DEPTH = 16 in capability.rs:21
 *   - validate_structure() check at capability.rs:156-159
 */
fact DepthBounded {
    all t: Token | t.depth >= 0 and t.depth <= MAX_DEPTH
}

/**
 * Fact: No cycles in the delegation chain.
 *
 * The parent relation must be acyclic — a token cannot be its own ancestor.
 * This is enforced by the implementation because each delegation creates a
 * new token with a fresh token_id.
 */
fact NoCycles {
    no t: Token | t in t.^parent
}

/**
 * Fact: Root tokens have no parent.
 *
 * A root token is one issued directly (not via delegation).
 * Root tokens have depth = MAX_DEPTH and no parent.
 */
fact RootTokens {
    all t: Token | no t.parent implies t.depth = MAX_DEPTH
}

/**
 * Fact: Non-root tokens must satisfy the delegation protocol.
 *
 * For every non-root token, the validDelegation predicate holds
 * between the token and its parent. This encodes the invariants
 * enforced by attenuate_capability_token() at capability_token.rs:120-210.
 */
fact DelegationProtocol {
    all child: Token | some child.parent implies
        validDelegation[child, child.parent]
}

-- =========================================================================
-- Predicates
-- =========================================================================

/**
 * patternCovers — does the parent pattern cover the child pattern?
 *
 * Models the subset relation used in grant_is_subset():
 *   - Wildcard covers everything
 *   - An exact pattern covers only itself
 *
 * Maps to the pattern check at capability_token.rs:474-480
 */
pred patternCovers[parentPat: Pattern, childPat: Pattern] {
    parentPat = Wildcard or parentPat = childPat
}

/**
 * grantSubset — is the child grant a subset of the parent grant?
 *
 * Models grant_is_subset() at capability_token.rs:470-508.
 *
 * A child grant is a subset of a parent grant when:
 *   1. Parent's tool pattern covers child's tool pattern
 *   2. Parent's function pattern covers child's function pattern
 *   3. If parent restricts paths, child's paths are a subset
 *   4. If parent restricts domains, child's domains are a subset
 *
 * This is the core monotonic attenuation relation.
 */
pred grantSubset[child: Grant, par: Grant] {
    -- Tool pattern coverage
    patternCovers[par.toolPattern, child.toolPattern]

    -- Function pattern coverage
    patternCovers[par.funcPattern, child.funcPattern]

    -- Path subset: if parent restricts paths, child must stay within them
    (some par.allowedPaths) implies
        child.allowedPaths in par.allowedPaths

    -- Domain subset: if parent restricts domains, child must stay within them
    (some par.allowedDomains) implies
        child.allowedDomains in par.allowedDomains
}

/**
 * grantsCoveredBy — are all child grants covered by at least one parent grant?
 *
 * Models the attenuation check loop at capability_token.rs:146-158:
 *   for new_grant in &new_grants {
 *       let covered = parent.grants.iter().any(|pg| grant_is_subset(new_grant, pg));
 *       if !covered { return Err(...); }
 *   }
 */
pred grantsCoveredBy[childGrants: set Grant, parentGrants: set Grant] {
    all cg: childGrants | some pg: parentGrants | grantSubset[cg, pg]
}

/**
 * validDelegation — does the child token satisfy all delegation constraints?
 *
 * Models attenuate_capability_token() at capability_token.rs:120-210.
 *
 * Constraints:
 *   1. Parent must have remaining depth > 0 (can delegate)
 *   2. Child depth = parent depth - 1 (strictly decremented)
 *   3. Child issuer = parent holder (delegation chain integrity)
 *   4. Child expiry <= parent expiry (temporal monotonicity)
 *   5. Child grants covered by parent grants (monotonic attenuation)
 */
pred validDelegation[child: Token, par: Token] {
    -- Depth check: parent must be able to delegate (capability_token.rs:128-132)
    par.depth > 0

    -- Depth decrement: child.depth = parent.depth - 1 (capability_token.rs:166)
    child.depth = minus[par.depth, 1]

    -- Issuer chain: child.issuer = parent.holder (capability_token.rs:195)
    child.issuer = par.holder

    -- Temporal monotonicity: child.expiry <= parent.expiry (capability_token.rs:172-176)
    lte[child.expiry, par.expiry]

    -- Monotonic attenuation: child grants subset of parent grants
    -- (capability_token.rs:146-158)
    grantsCoveredBy[child.grants, par.grants]
}

-- =========================================================================
-- Assertions (safety properties S11–S16)
-- =========================================================================

/**
 * S11: Monotonic Attenuation — child grants are always a subset of parent grants.
 *
 * Maps to: grant_is_subset() at capability_token.rs:470-508
 *          and the attenuation check at capability_token.rs:146-158
 *
 * For every non-root token, every grant in the child is covered by at least
 * one grant in the parent. Permissions can only narrow, never widen.
 */
assert S11_MonotonicAttenuation {
    all child: Token | some child.parent implies
        grantsCoveredBy[child.grants, child.parent.grants]
}

/**
 * S12: Transitive Attenuation — monotonic attenuation holds across entire chains.
 *
 * Derived from S11: if child ⊆ parent and parent ⊆ grandparent, then
 * child ⊆ grandparent (by transitivity of the subset relation on patterns).
 *
 * This verifies that no sequence of delegations can escalate privileges
 * beyond what the root token originally granted.
 *
 * We check: for any token and any ancestor in its delegation chain,
 * every grant in the descendant is covered by some grant in the ancestor.
 */
assert S12_TransitiveAttenuation {
    all descendant: Token, ancestor: Token |
        ancestor in descendant.^parent implies
            grantsCoveredBy[descendant.grants, ancestor.grants]
}

/**
 * S13: Depth Budget — delegation chain length never exceeds MAX_DELEGATION_DEPTH.
 *
 * Maps to: MAX_DELEGATION_DEPTH constant at capability.rs:21
 *          and the depth check at capability_token.rs:128-132
 *
 * The depth field starts at MAX_DEPTH for root tokens and strictly decrements
 * at each delegation. Therefore the maximum chain length is MAX_DEPTH.
 */
assert S13_DepthBudget {
    all t: Token | #{t.*parent} <= add[MAX_DEPTH, 1]
}

/**
 * S14: Temporal Monotonicity — child expiry never exceeds parent expiry.
 *
 * Maps to: the expiry clamping at capability_token.rs:172-176:
 *   let clamped_expires = if requested > parent_expires { parent_expires } else { requested }
 *
 * Expiry can only stay the same or shrink through the delegation chain.
 */
assert S14_TemporalMonotonicity {
    all child: Token | some child.parent implies
        lte[child.expiry, child.parent.expiry]
}

/**
 * S15: Terminal Cannot Delegate — tokens with depth=0 have no children.
 *
 * Maps to: the depth check at capability_token.rs:128-132:
 *   if parent.remaining_depth == 0 { return Err(AttenuationViolation(...)); }
 *
 * A terminal token (depth=0) cannot be used as a parent for delegation.
 */
assert S15_TerminalCannotDelegate {
    all t: Token | t.depth = 0 implies no child: Token | child.parent = t
}

/**
 * S16: Issuer Chain Integrity — child.issuer = parent.holder throughout the chain.
 *
 * Maps to: capability_token.rs:195 where the new token's issuer is set
 * to the parent's holder.
 *
 * This ensures that only the holder of a token can delegate it, maintaining
 * the chain of custody from root to leaf.
 */
assert S16_IssuerChainIntegrity {
    all child: Token | some child.parent implies
        child.issuer = child.parent.holder
}

-- =========================================================================
-- Check commands — bounded model checking
-- =========================================================================

/**
 * Scope: 5 tokens, 4 grants, 3 principals, 3 time values.
 *
 * This scope is sufficient because:
 *   - 5 tokens can form chains of length up to 5 (> MAX_DEPTH=4)
 *   - 4 grants provide enough variety for subset checking
 *   - 3 principals cover issuer/holder chains with re-delegation
 *   - 3 time values cover before/equal/after comparisons
 *
 * All checks should report 0 counterexamples.
 */
check S11_MonotonicAttenuation for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
check S12_TransitiveAttenuation for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
check S13_DepthBudget for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
check S14_TemporalMonotonicity for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
check S15_TerminalCannotDelegate for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
check S16_IssuerChainIntegrity for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int

-- =========================================================================
-- Example: show a valid delegation chain
-- =========================================================================

/**
 * Generate an example instance with at least 3 tokens forming a chain.
 * Useful for visualization and sanity-checking the model.
 */
pred showDelegationChain {
    some disj t1, t2, t3: Token |
        t2.parent = t1 and t3.parent = t2
}
run showDelegationChain for 5 Token, 4 Grant, 3 Principal, 3 Path, 3 Domain, 3 Time, 5 Int
