------------------------- MODULE TrustContainment -------------------------
(**************************************************************************)
(* Formal specification of trust-tier and privileged-sink containment.    *)
(*                                                                        *)
(* Models the shared semantic-containment gate introduced in:             *)
(*   vellaveto-types/src/provenance.rs                                    *)
(*   vellaveto-mcp/src/mediation.rs                                       *)
(*                                                                        *)
(* This specification turns the existing TrustTier/SinkClass enums into   *)
(* a fail-closed lattice model for privileged sink admission.             *)
(*                                                                        *)
(* Verifies 6 safety invariants:                                          *)
(*   TC1: Allowed privileged flows require lineage                        *)
(*   TC2: Upward trust flows require explicit declassification            *)
(*   TC3: Unknown/quarantined privileged flows require explicit gate      *)
(*   TC4: Trust join is the least upper bound                             *)
(*   TC5: Trust meet is the greatest lower bound                          *)
(*   TC6: Sink privilege thresholds are monotonic                         *)
(*                                                                        *)
(* And 1 liveness property:                                               *)
(*   TCL1: Pending requests are eventually decided                        *)
(**************************************************************************)
EXTENDS Integers, FiniteSets, TLC

(**************************************************************************)
(* CONSTANTS                                                              *)
(**************************************************************************)
CONSTANT RequestSet

(**************************************************************************)
(* FIXED DOMAINS                                                          *)
(**************************************************************************)
TrustTiers ==
    {
        "quarantined",
        "unknown",
        "untrusted",
        "low",
        "medium",
        "high",
        "verified"
    }

SinkClasses ==
    {
        "read_only",
        "low_risk_write",
        "filesystem_write",
        "network_egress",
        "code_execution",
        "memory_write",
        "approval_ui",
        "credential_access",
        "policy_mutation"
    }

AllRequests ==
    {
        [
            source_tier             |-> t,
            sink_class              |-> s,
            has_lineage             |-> l,
            explicitly_declassified |-> d
        ] :
            t \in TrustTiers,
            s \in SinkClasses,
            l \in BOOLEAN,
            d \in BOOLEAN
    }

(**************************************************************************)
(* VARIABLES                                                              *)
(**************************************************************************)
VARIABLES
    pending,
    decisions

vars == <<pending, decisions>>

(**************************************************************************)
(* ORDERING OPERATORS                                                     *)
(**************************************************************************)
TrustRank(tier) ==
    CASE tier = "quarantined" -> 0
      [] tier = "unknown" -> 1
      [] tier = "untrusted" -> 2
      [] tier = "low" -> 3
      [] tier = "medium" -> 4
      [] tier = "high" -> 5
      [] tier = "verified" -> 6

SinkRank(sink) ==
    CASE sink = "read_only" -> 0
      [] sink = "low_risk_write" -> 1
      [] sink = "filesystem_write" -> 2
      [] sink = "network_egress" -> 3
      [] sink = "memory_write" -> 4
      [] sink = "approval_ui" -> 5
      [] sink = "code_execution" -> 6
      [] sink = "credential_access" -> 7
      [] sink = "policy_mutation" -> 8

TrustLEQ(left, right) == TrustRank(left) <= TrustRank(right)
TrustGEQ(left, right) == TrustRank(left) >= TrustRank(right)

TierJoin(left, right) ==
    IF TrustRank(left) >= TrustRank(right) THEN left ELSE right

TierMeet(left, right) ==
    IF TrustRank(left) <= TrustRank(right) THEN left ELSE right

PrivilegedSink(sink) == sink # "read_only"

RequiredTrust(sink) ==
    CASE sink = "read_only" -> "unknown"
      [] sink = "low_risk_write" -> "low"
      [] sink = "filesystem_write" -> "medium"
      [] sink = "network_egress" -> "medium"
      [] sink = "memory_write" -> "high"
      [] sink = "approval_ui" -> "high"
      [] sink = "code_execution" -> "verified"
      [] sink = "credential_access" -> "verified"
      [] sink = "policy_mutation" -> "verified"

TrustSufficient(req) ==
    TrustGEQ(req.source_tier, RequiredTrust(req.sink_class))

CanFlow(req) ==
    IF PrivilegedSink(req.sink_class)
    THEN req.has_lineage /\ (TrustSufficient(req) \/ req.explicitly_declassified)
    ELSE TrustSufficient(req) \/ req.explicitly_declassified

Evaluate(req) ==
    IF CanFlow(req) THEN "allow" ELSE "deny"

(**************************************************************************)
(* INITIAL STATE                                                          *)
(**************************************************************************)
Init ==
    /\ RequestSet \subseteq AllRequests
    /\ pending = RequestSet
    /\ decisions = [r \in RequestSet |-> "pending"]

(**************************************************************************)
(* ACTION: DecideOne                                                      *)
(*                                                                        *)
(* Pick a pending request and resolve it according to the trust flow      *)
(* rules. This models the shared mediation-layer decision gate.           *)
(**************************************************************************)
DecideOne ==
    /\ pending # {}
    /\ \E req \in pending :
        /\ pending' = pending \ {req}
        /\ decisions' = [decisions EXCEPT ![req] = Evaluate(req)]

Next == DecideOne

Spec == Init /\ [][Next]_vars /\ WF_vars(DecideOne)

(**************************************************************************)
(* TYPE INVARIANT                                                         *)
(**************************************************************************)
TypeOK ==
    /\ RequestSet \subseteq AllRequests
    /\ pending \subseteq RequestSet
    /\ decisions \in [RequestSet -> {"pending", "allow", "deny"}]

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(**************************************************************************)
(* TC1: Allowed privileged flows require lineage.                         *)
(**************************************************************************)
InvariantTC1_AllowedPrivilegedFlowsRequireLineage ==
    \A req \in RequestSet :
        decisions[req] = "allow" /\ PrivilegedSink(req.sink_class)
            => req.has_lineage

(**************************************************************************)
(* TC2: Lower-trust flows into higher-trust sinks require declassification.*)
(**************************************************************************)
InvariantTC2_UpwardFlowsRequireDeclassification ==
    \A req \in RequestSet :
        decisions[req] = "allow" /\ ~TrustSufficient(req)
            => req.explicitly_declassified

(**************************************************************************)
(* TC3: Unknown/quarantined privileged flows require an explicit gate.    *)
(**************************************************************************)
InvariantTC3_UnknownOrQuarantinedPrivilegedFlowsNeedGate ==
    \A req \in RequestSet :
        decisions[req] = "allow"
        /\ PrivilegedSink(req.sink_class)
        /\ req.source_tier \in {"unknown", "quarantined"}
            => req.explicitly_declassified

(**************************************************************************)
(* TC4: Join is the least upper bound in the trust lattice.               *)
(**************************************************************************)
InvariantTC4_JoinLeastUpperBound ==
    \A left \in TrustTiers, right \in TrustTiers :
        /\ TrustGEQ(TierJoin(left, right), left)
        /\ TrustGEQ(TierJoin(left, right), right)
        /\ \A upper \in TrustTiers :
            (TrustGEQ(upper, left) /\ TrustGEQ(upper, right))
                => TrustLEQ(TierJoin(left, right), upper)

(**************************************************************************)
(* TC5: Meet is the greatest lower bound in the trust lattice.            *)
(**************************************************************************)
InvariantTC5_MeetGreatestLowerBound ==
    \A left \in TrustTiers, right \in TrustTiers :
        /\ TrustLEQ(TierMeet(left, right), left)
        /\ TrustLEQ(TierMeet(left, right), right)
        /\ \A lower \in TrustTiers :
            (TrustLEQ(lower, left) /\ TrustLEQ(lower, right))
                => TrustLEQ(lower, TierMeet(left, right))

(**************************************************************************)
(* TC6: More privileged sinks never require less trust.                   *)
(**************************************************************************)
InvariantTC6_SinkThresholdsAreMonotonic ==
    \A left \in SinkClasses, right \in SinkClasses :
        SinkRank(left) <= SinkRank(right)
            => TrustRank(RequiredTrust(left)) <= TrustRank(RequiredTrust(right))

(**************************************************************************)
(* LIVENESS                                                               *)
(**************************************************************************)
LivenessTCL1_PendingRequestsEventuallyDrain == <> (pending = {})

=========================================================================
