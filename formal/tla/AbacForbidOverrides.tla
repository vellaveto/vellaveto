------------------------ MODULE AbacForbidOverrides ------------------------
(**************************************************************************)
(* Formal specification of Vellaveto's ABAC forbid-overrides evaluation.  *)
(*                                                                        *)
(* Models AbacEngine::evaluate from:                                      *)
(*   vellaveto-engine/src/abac.rs:190-240                                *)
(*                                                                        *)
(* The ABAC engine uses "forbid-overrides" combining semantics:           *)
(*   1. Collect all matching permit and forbid policies                   *)
(*   2. If ANY forbid matches → Deny (regardless of permits or priority)  *)
(*   3. If permits match and no forbids → Allow                           *)
(*   4. If nothing matches → NoMatch (fail-closed upstream)               *)
(*                                                                        *)
(* This specification verifies 4 safety invariants (S7–S10).              *)
(*                                                                        *)
(* Key difference from MCPPolicyEngine: ABAC does NOT use first-match-    *)
(* wins. Instead, it collects ALL matching policies and then applies the  *)
(* forbid-overrides combining algorithm. This is the standard XACML       *)
(* deny-overrides pattern.                                                *)
(**************************************************************************)
EXTENDS MCPCommon, Integers, Sequences, FiniteSets, TLC

(**************************************************************************)
(* CONSTANTS                                                              *)
(**************************************************************************)
CONSTANTS
    Principals,     \* Set of principal identifiers
    AbacPolicySet,  \* Set of all ABAC policy records
    AbacActionSet   \* Set of actions to evaluate

(**************************************************************************)
(* ABAC policy effects                                                    *)
(*                                                                        *)
(* Maps to AbacEffect enum in vellaveto-engine/src/abac.rs                *)
(**************************************************************************)
Effects == {"Permit", "Forbid"}

(**************************************************************************)
(* An ABAC policy record:                                                 *)
(*   .id         - Unique policy identifier                               *)
(*   .principal  - Principal pattern (Wildcard or specific)               *)
(*   .action     - Action tool pattern                                    *)
(*   .resource   - Resource pattern (tool function)                       *)
(*   .effect     - "Permit" or "Forbid"                                   *)
(*   .priority   - Integer priority (NOT used in forbid-overrides)        *)
(*   .conditions - BOOLEAN (simplified: TRUE = conditions met)            *)
(*                                                                        *)
(* Maps to AbacPolicy struct in vellaveto-engine/src/abac.rs              *)
(**************************************************************************)

(**************************************************************************)
(* An ABAC evaluation context:                                            *)
(*   .principal  - The principal making the request                       *)
(*   .action     - The action being requested                             *)
(*                                                                        *)
(* Maps to AbacEvalContext in vellaveto-engine/src/abac.rs                *)
(**************************************************************************)

(**************************************************************************)
(* VARIABLES                                                              *)
(**************************************************************************)
VARIABLES
    abacPolicies,       \* Set of all ABAC policies
    pendingEvals,       \* Set of (principal, action) pairs awaiting evaluation
    decisions,          \* Function: (principal, action) → decision
    evalState           \* "idle" | "collecting" | "deciding" | "done"

vars == <<abacPolicies, pendingEvals, decisions, evalState>>

(**************************************************************************)
(* Decision values                                                        *)
(*                                                                        *)
(* Maps to AbacDecision enum in vellaveto-engine/src/abac.rs              *)
(**************************************************************************)
DecisionAllow(polId) == [type |-> "Allow", policy_id |-> polId]
DecisionDeny(polId, reason) == [type |-> "Deny", policy_id |-> polId, reason |-> reason]
DecisionNoMatch == [type |-> "NoMatch", policy_id |-> "none", reason |-> "No matching policy"]

(**************************************************************************)
(* MatchesAbacPolicy: Does a policy match the given principal and action? *)
(*                                                                        *)
(* Models the four-way matching at abac.rs:196-210:                      *)
(*   1. matches_principal() — principal pattern matches eval context       *)
(*   2. matches_action() — action pattern matches action tool             *)
(*   3. matches_resource() — resource pattern matches action function      *)
(*   4. evaluate_conditions() — all conditions evaluate to true           *)
(**************************************************************************)
MatchesAbacPolicy(pol, principal, action) ==
    /\ PatternMatch(pol.principal, principal)
    /\ PatternMatch(pol.action, action.tool)
    /\ PatternMatch(pol.resource, action.function)
    /\ pol.conditions = TRUE  \* Abstracted: conditions are satisfied

(**************************************************************************)
(* CollectMatching: Compute the sets of matching forbid and permit        *)
(* policies for a given (principal, action) pair.                         *)
(*                                                                        *)
(* This models the collection loop at abac.rs:196-224.                   *)
(**************************************************************************)
MatchingForbids(principal, action) ==
    {pol \in abacPolicies :
        /\ MatchesAbacPolicy(pol, principal, action)
        /\ pol.effect = "Forbid"}

MatchingPermits(principal, action) ==
    {pol \in abacPolicies :
        /\ MatchesAbacPolicy(pol, principal, action)
        /\ pol.effect = "Permit"}

(**************************************************************************)
(* ForbidOverridesDecision: The core combining algorithm                  *)
(*                                                                        *)
(* Models abac.rs:226-239:                                               *)
(*   1. If any forbid matched → Deny                                     *)
(*   2. Else if any permit matched → Allow                               *)
(*   3. Else → NoMatch                                                    *)
(*                                                                        *)
(* Note: priority is NOT consulted in the combining step.                 *)
(* A forbid with priority=1 overrides a permit with priority=1000.        *)
(* This is the key property verified by S8.                               *)
(**************************************************************************)
ForbidOverridesDecision(principal, action) ==
    LET forbids == MatchingForbids(principal, action)
        permits == MatchingPermits(principal, action)
    IN
        IF forbids # {}
        THEN
            \* Any forbid → Deny (pick first arbitrarily for the policy_id)
            LET someForbid == CHOOSE pol \in forbids : TRUE
            IN DecisionDeny(someForbid.id,
                "ABAC forbid policy '" \o someForbid.id \o "' matched")
        ELSE IF permits # {}
        THEN
            \* Permits only (no forbid) → Allow
            LET somePermit == CHOOSE pol \in permits : TRUE
            IN DecisionAllow(somePermit.id)
        ELSE
            \* Nothing matched → NoMatch
            DecisionNoMatch

(**************************************************************************)
(* TYPE INVARIANT                                                         *)
(**************************************************************************)
TypeOK ==
    /\ evalState \in {"idle", "collecting", "deciding", "done"}
    /\ \A key \in DOMAIN decisions :
        decisions[key].type \in {"Allow", "Deny", "NoMatch"}

(**************************************************************************)
(* INITIAL STATE                                                          *)
(**************************************************************************)
Init ==
    /\ abacPolicies \in SUBSET AbacPolicySet
    /\ pendingEvals \in SUBSET (Principals \X AbacActionSet) \ {{}}
    /\ decisions = [key \in {} |-> DecisionNoMatch]
    /\ evalState = "idle"

(**************************************************************************)
(* ACTION: StartCollection                                                *)
(*                                                                        *)
(* Begin evaluating a pending (principal, action) pair.                   *)
(**************************************************************************)
StartCollection ==
    /\ evalState = "idle"
    /\ pendingEvals # {}
    /\ evalState' = "collecting"
    /\ UNCHANGED <<abacPolicies, pendingEvals, decisions>>

(**************************************************************************)
(* ACTION: Decide                                                         *)
(*                                                                        *)
(* Apply forbid-overrides combining algorithm to produce a decision.      *)
(* This models the complete evaluate() function at abac.rs:190-240.      *)
(*                                                                        *)
(* In the actual implementation, collection and decision happen in a      *)
(* single pass through the policy list. Here we separate them for         *)
(* clarity, but the result is identical.                                  *)
(**************************************************************************)
Decide ==
    /\ evalState = "collecting"
    /\ \E eval \in pendingEvals :
        LET principal == eval[1]
            action == eval[2]
            decision == ForbidOverridesDecision(principal, action)
        IN
            /\ decisions' = (eval :> decision) @@ decisions
            /\ pendingEvals' = pendingEvals \ {eval}
            /\ evalState' = "done"
            /\ UNCHANGED abacPolicies

(**************************************************************************)
(* ACTION: Reset                                                          *)
(**************************************************************************)
Reset ==
    /\ evalState = "done"
    /\ evalState' = "idle"
    /\ UNCHANGED <<abacPolicies, pendingEvals, decisions>>

(**************************************************************************)
(* NEXT STATE RELATION                                                    *)
(**************************************************************************)
Next ==
    \/ StartCollection
    \/ Decide
    \/ Reset

Fairness ==
    /\ WF_vars(StartCollection)
    /\ WF_vars(Decide)
    /\ WF_vars(Reset)

Spec == Init /\ [][Next]_vars /\ Fairness

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(**************************************************************************)
(* S7: Forbid dominance — any matching forbid produces Deny regardless    *)
(* of how many permits also match.                                        *)
(*                                                                        *)
(* Maps to abac.rs:226-230:                                              *)
(*   if let Some((id, reason)) = best_forbid {                           *)
(*       return AbacDecision::Deny { policy_id, reason };                *)
(*   }                                                                    *)
(*                                                                        *)
(* The forbid check happens BEFORE the permit check, so any forbid       *)
(* causes an immediate Deny return.                                       *)
(**************************************************************************)
InvariantS7_ForbidDominance ==
    \A eval \in DOMAIN decisions :
        LET principal == eval[1]
            action == eval[2]
            forbids == MatchingForbids(principal, action)
        IN
            forbids # {} => decisions[eval].type = "Deny"

(**************************************************************************)
(* S8: Forbid ignores priority — a low-priority forbid beats a high-     *)
(* priority permit.                                                       *)
(*                                                                        *)
(* Maps to: abac.rs test at line 1212 which verifies this property.      *)
(*                                                                        *)
(* In forbid-overrides semantics, the priority field is used only to      *)
(* select which forbid/permit to report in the decision, not to           *)
(* determine whether forbid or permit wins.                               *)
(*                                                                        *)
(* This invariant strengthens S7: it holds even when the forbid policy    *)
(* has a strictly lower priority than the permit policy.                  *)
(**************************************************************************)
InvariantS8_ForbidIgnoresPriority ==
    \A eval \in DOMAIN decisions :
        LET principal == eval[1]
            action == eval[2]
            forbids == MatchingForbids(principal, action)
            permits == MatchingPermits(principal, action)
        IN
            \* Even if there's a permit with higher priority than the forbid,
            \* the decision must still be Deny
            (/\ forbids # {}
             /\ permits # {}
             /\ \E f \in forbids, p \in permits : f.priority < p.priority)
            => decisions[eval].type = "Deny"

(**************************************************************************)
(* S9: Permit only when no forbid exists — Allow is produced only when    *)
(* at least one permit matches and NO forbid matches.                     *)
(*                                                                        *)
(* Maps to abac.rs:232-236:                                              *)
(*   if let Some(id) = best_permit {                                     *)
(*       return AbacDecision::Allow { policy_id };                       *)
(*   }                                                                    *)
(*                                                                        *)
(* This is the converse of S7: Allow requires the absence of any forbid. *)
(**************************************************************************)
InvariantS9_PermitWithoutForbid ==
    \A eval \in DOMAIN decisions :
        LET principal == eval[1]
            action == eval[2]
            forbids == MatchingForbids(principal, action)
        IN
            decisions[eval].type = "Allow" => forbids = {}

(**************************************************************************)
(* S10: No match produces NoMatch — when no policy matches at all, the   *)
(* decision is NoMatch (not Allow, not Deny).                             *)
(*                                                                        *)
(* Maps to abac.rs:239:                                                  *)
(*   AbacDecision::NoMatch                                                *)
(*                                                                        *)
(* The caller (policy engine) is responsible for handling NoMatch with    *)
(* fail-closed semantics (producing Deny). The ABAC engine itself just   *)
(* reports the absence of matching policies.                              *)
(**************************************************************************)
InvariantS10_NoMatchResult ==
    \A eval \in DOMAIN decisions :
        LET principal == eval[1]
            action == eval[2]
            forbids == MatchingForbids(principal, action)
            permits == MatchingPermits(principal, action)
        IN
            (/\ forbids = {}
             /\ permits = {})
            => decisions[eval].type = "NoMatch"

=========================================================================
