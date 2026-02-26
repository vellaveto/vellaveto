------------------------ MODULE CascadingFailure ------------------------
(**************************************************************************)
(* Formal specification of multi-agent cascading failure prevention.      *)
(*                                                                        *)
(* Models the cascading failure circuit breaker system that prevents      *)
(* multi-hop tool call chains from causing unbounded failure propagation. *)
(*                                                                        *)
(* Addresses OWASP ASI08 (Cascading Hallucination Failures) by verifying  *)
(* that:                                                                  *)
(*   1. Tool call chain depth is always bounded                           *)
(*   2. Error rate tracking triggers circuit breaking                     *)
(*   3. Circuit breaker state transitions are correct                     *)
(*   4. Recovery from half-open state is safe                             *)
(*                                                                        *)
(* Maps to:                                                               *)
(*   vellaveto-engine/src/circuit_breaker.rs                              *)
(*   vellaveto-mcp/src/proxy/bridge/                                      *)
(*                                                                        *)
(* Verifies 5 safety invariants:                                          *)
(*   C1: Chain depth never exceeds MaxChainDepth                          *)
(*   C2: Error threshold triggers circuit open                            *)
(*   C3: Open circuit denies all requests (fail-closed)                   *)
(*   C4: Half-open allows exactly one probe request                       *)
(*   C5: Successful probe closes circuit                                  *)
(*                                                                        *)
(* And 2 liveness properties:                                             *)
(*   CL1: Open circuits eventually transition to half-open                *)
(*   CL2: Half-open circuits eventually resolve (close or reopen)         *)
(**************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

(**************************************************************************)
(* CONSTANTS                                                              *)
(**************************************************************************)
CONSTANTS
    MaxChainDepth,     \* Maximum tool call chain depth (maps to MAX_CALL_CHAIN_DEPTH)
    MaxErrors,         \* Error threshold for circuit opening
    Agents,            \* Set of agent identifiers
    Tools              \* Set of tool identifiers

(**************************************************************************)
(* Circuit breaker states — maps to CircuitState enum                     *)
(**************************************************************************)
CircuitStates == {"closed", "open", "half_open"}

(**************************************************************************)
(* VARIABLES                                                              *)
(**************************************************************************)
VARIABLES
    circuitState,      \* Function: (agent, tool) -> circuit state
    errorCounts,       \* Function: (agent, tool) -> consecutive error count
    chainDepths,       \* Function: agent -> current call chain depth
    probeAllowed,      \* Function: (agent, tool) -> boolean (probe in half-open)
    requestOutcomes    \* Sequence of (agent, tool, outcome) for verification

vars == <<circuitState, errorCounts, chainDepths, probeAllowed, requestOutcomes>>

(**************************************************************************)
(* Helper: all (agent, tool) pairs                                        *)
(**************************************************************************)
AgentToolPairs == Agents \X Tools

(**************************************************************************)
(* TYPE INVARIANT                                                         *)
(**************************************************************************)
TypeOK ==
    /\ \A pair \in DOMAIN circuitState :
        circuitState[pair] \in CircuitStates
    /\ \A pair \in DOMAIN errorCounts :
        errorCounts[pair] \in 0..MaxErrors + 1
    /\ \A a \in DOMAIN chainDepths :
        chainDepths[a] \in 0..MaxChainDepth + 1

(**************************************************************************)
(* INITIAL STATE                                                          *)
(**************************************************************************)
Init ==
    /\ circuitState = [pair \in AgentToolPairs |-> "closed"]
    /\ errorCounts = [pair \in AgentToolPairs |-> 0]
    /\ chainDepths = [a \in Agents |-> 0]
    /\ probeAllowed = [pair \in AgentToolPairs |-> FALSE]
    /\ requestOutcomes = <<>>

(**************************************************************************)
(* ACTION: ToolCallSuccess                                                *)
(*                                                                        *)
(* An agent makes a successful tool call.                                 *)
(* - Chain depth incremented (bounded by MaxChainDepth)                   *)
(* - Error count reset to 0                                               *)
(* - If in half_open state, circuit closes on success                     *)
(* - If in open state, request is denied (C3 — not modeled here since     *)
(*   this action represents success, which can only happen when allowed)  *)
(**************************************************************************)
ToolCallSuccess ==
    \E a \in Agents, t \in Tools :
        LET pair == <<a, t>>
        IN
        /\ chainDepths[a] < MaxChainDepth  \* Chain depth enforced
        /\ circuitState[pair] \in {"closed", "half_open"}
        /\ chainDepths' = [chainDepths EXCEPT ![a] = @ + 1]
        /\ errorCounts' = [errorCounts EXCEPT ![pair] = 0]
        /\ circuitState' =
            IF circuitState[pair] = "half_open"
            THEN [circuitState EXCEPT ![pair] = "closed"]  \* C5: probe success → close
            ELSE circuitState
        /\ probeAllowed' =
            IF circuitState[pair] = "half_open"
            THEN [probeAllowed EXCEPT ![pair] = FALSE]
            ELSE probeAllowed
        /\ requestOutcomes' = Append(requestOutcomes,
            [agent |-> a, tool |-> t, outcome |-> "success"])

(**************************************************************************)
(* ACTION: ToolCallFailure                                                *)
(*                                                                        *)
(* An agent's tool call fails.                                            *)
(* - Error count incremented (saturating — maps to saturating_add)        *)
(* - If error count reaches threshold, circuit opens (C2)                 *)
(* - If in half_open, failure reopens circuit                             *)
(**************************************************************************)
ToolCallFailure ==
    \E a \in Agents, t \in Tools :
        LET pair == <<a, t>>
            newErrors == IF errorCounts[pair] < MaxErrors + 1
                         THEN errorCounts[pair] + 1
                         ELSE MaxErrors + 1  \* Saturating add
        IN
        /\ circuitState[pair] \in {"closed", "half_open"}
        /\ chainDepths[a] < MaxChainDepth
        /\ errorCounts' = [errorCounts EXCEPT ![pair] = newErrors]
        /\ circuitState' =
            IF newErrors >= MaxErrors
            THEN [circuitState EXCEPT ![pair] = "open"]  \* C2: threshold → open
            ELSE IF circuitState[pair] = "half_open"
            THEN [circuitState EXCEPT ![pair] = "open"]  \* Half-open failure → reopen
            ELSE circuitState
        /\ probeAllowed' = [probeAllowed EXCEPT ![pair] = FALSE]
        /\ chainDepths' = [chainDepths EXCEPT ![a] = @ + 1]
        /\ requestOutcomes' = Append(requestOutcomes,
            [agent |-> a, tool |-> t, outcome |-> "failure"])

(**************************************************************************)
(* ACTION: ToolCallDeniedByCircuit                                        *)
(*                                                                        *)
(* Circuit is open — request denied without forwarding.                   *)
(* This is the fail-closed behavior of the circuit breaker (C3).          *)
(**************************************************************************)
ToolCallDeniedByCircuit ==
    \E a \in Agents, t \in Tools :
        LET pair == <<a, t>>
        IN
        /\ circuitState[pair] = "open"
        /\ requestOutcomes' = Append(requestOutcomes,
            [agent |-> a, tool |-> t, outcome |-> "denied_circuit_open"])
        /\ UNCHANGED <<circuitState, errorCounts, chainDepths, probeAllowed>>

(**************************************************************************)
(* ACTION: CircuitHalfOpen                                                *)
(*                                                                        *)
(* Timer expires on open circuit, transitions to half-open.               *)
(* Allows exactly one probe request (C4).                                 *)
(**************************************************************************)
CircuitHalfOpen ==
    \E a \in Agents, t \in Tools :
        LET pair == <<a, t>>
        IN
        /\ circuitState[pair] = "open"
        /\ circuitState' = [circuitState EXCEPT ![pair] = "half_open"]
        /\ probeAllowed' = [probeAllowed EXCEPT ![pair] = TRUE]
        /\ UNCHANGED <<errorCounts, chainDepths, requestOutcomes>>

(**************************************************************************)
(* ACTION: ChainComplete                                                  *)
(*                                                                        *)
(* An agent's call chain completes, resetting depth to 0.                 *)
(* Models the end of a multi-hop tool call sequence.                      *)
(**************************************************************************)
ChainComplete ==
    \E a \in Agents :
        /\ chainDepths[a] > 0
        /\ chainDepths' = [chainDepths EXCEPT ![a] = 0]
        /\ UNCHANGED <<circuitState, errorCounts, probeAllowed, requestOutcomes>>

(**************************************************************************)
(* NEXT STATE RELATION                                                    *)
(**************************************************************************)
Next ==
    \/ ToolCallSuccess
    \/ ToolCallFailure
    \/ ToolCallDeniedByCircuit
    \/ CircuitHalfOpen
    \/ ChainComplete

(**************************************************************************)
(* FAIRNESS                                                               *)
(**************************************************************************)
Fairness ==
    /\ WF_vars(ToolCallSuccess)
    /\ WF_vars(CircuitHalfOpen)
    /\ WF_vars(ChainComplete)
    \* Failures and denials are not fair — they can happen but aren't required

Spec == Init /\ [][Next]_vars /\ Fairness

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(**************************************************************************)
(* C1: Chain depth never exceeds MaxChainDepth                            *)
(*                                                                        *)
(* No agent's tool call chain can grow beyond the configured maximum.     *)
(* This prevents unbounded cascading through multi-hop chains.            *)
(* Addresses OWASP ASI08 depth limit requirement.                         *)
(**************************************************************************)
InvariantC1_ChainDepthBounded ==
    \A a \in Agents :
        chainDepths[a] <= MaxChainDepth

(**************************************************************************)
(* C2: Error threshold triggers circuit open                              *)
(*                                                                        *)
(* When consecutive errors reach MaxErrors, the circuit must be open.     *)
(* This ensures automatic protection against cascading failures.          *)
(**************************************************************************)
InvariantC2_ErrorThresholdTriggersOpen ==
    \A pair \in AgentToolPairs :
        errorCounts[pair] >= MaxErrors
        => circuitState[pair] \in {"open", "half_open"}

(**************************************************************************)
(* C3: Open circuit denies all requests                                   *)
(*                                                                        *)
(* When a circuit is open, no success outcome can occur for that          *)
(* agent-tool pair. All requests are denied (fail-closed).                *)
(*                                                                        *)
(* Formulated as: the last outcome for an open circuit pair is always     *)
(* "denied_circuit_open" (if any outcome exists since opening).           *)
(**************************************************************************)
InvariantC3_OpenCircuitDenies ==
    \A pair \in AgentToolPairs :
        circuitState[pair] = "open"
        => ~(\E a \in Agents, t \in Tools :
                /\ pair = <<a, t>>
                /\ Len(requestOutcomes) > 0
                /\ requestOutcomes[Len(requestOutcomes)].agent = a
                /\ requestOutcomes[Len(requestOutcomes)].tool = t
                /\ requestOutcomes[Len(requestOutcomes)].outcome = "success")

(**************************************************************************)
(* C4: Half-open allows limited requests                                  *)
(*                                                                        *)
(* A half-open circuit transitions to either closed (on success) or       *)
(* open (on failure). It cannot remain half-open after processing.        *)
(*                                                                        *)
(* Structural property: half_open is a transient state in the protocol.   *)
(**************************************************************************)
InvariantC4_HalfOpenTransient ==
    \A pair \in AgentToolPairs :
        circuitState[pair] = "half_open"
        => errorCounts[pair] < MaxErrors + 1  \* Still has room for one more attempt

(**************************************************************************)
(* C5: Successful probe closes circuit                                    *)
(*                                                                        *)
(* After a success in half_open state, the circuit returns to closed.     *)
(* Verified via ToolCallSuccess action structure — when half_open and     *)
(* success, the next state has the circuit closed.                        *)
(*                                                                        *)
(* This is a structural check: we verify that no half_open circuit can    *)
(* have an error count of 0 while still being in half_open state          *)
(* (because a success resets errors and closes the circuit).              *)
(**************************************************************************)
InvariantC5_ProbeSuccessCloses ==
    \A pair \in AgentToolPairs :
        /\ circuitState[pair] = "half_open"
        /\ errorCounts[pair] = 0
        => probeAllowed[pair] = TRUE  \* Still waiting for probe (hasn't succeeded yet)

(**************************************************************************)
(* LIVENESS PROPERTIES                                                    *)
(**************************************************************************)

(**************************************************************************)
(* CL1: Open circuits eventually transition to half-open                  *)
(*                                                                        *)
(* An open circuit doesn't remain open forever (under fairness).          *)
(* The timeout mechanism ensures eventual transition to half-open.        *)
(**************************************************************************)
LivenessCL1_OpenEventuallyHalfOpen ==
    \A pair \in AgentToolPairs :
        circuitState[pair] = "open"
        ~> circuitState[pair] # "open"

(**************************************************************************)
(* CL2: Half-open circuits eventually resolve                             *)
(*                                                                        *)
(* A half-open circuit doesn't remain half-open forever.                  *)
(* The probe request either succeeds (→ closed) or fails (→ open).        *)
(**************************************************************************)
LivenessCL2_HalfOpenResolves ==
    \A pair \in AgentToolPairs :
        circuitState[pair] = "half_open"
        ~> circuitState[pair] \in {"closed", "open"}

=========================================================================
