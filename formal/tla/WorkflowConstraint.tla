------------------------- MODULE WorkflowConstraint -------------------------
(**************************************************************************)
(* Formal specification of Vellaveto's workflow-level policy constraints. *)
(*                                                                        *)
(* Models the WorkflowTemplate context condition from:                    *)
(*   vellaveto-engine/src/compiled.rs   (WorkflowTemplate variant)        *)
(*   vellaveto-engine/src/context_check.rs (evaluation logic)             *)
(*   vellaveto-engine/src/policy_compile.rs (Kahn's cycle detection)      *)
(*                                                                        *)
(* This specification verifies 2 safety invariants:                       *)
(*   S8 (WorkflowPredecessor): A governed tool is only allowed if it is   *)
(*       a valid successor of the most recent governed tool in history    *)
(*       (or an entry point with no prior governed tool in history).      *)
(*   S9 (AcyclicDAG): No tool can reach itself through the successor     *)
(*       relation — the workflow graph is a DAG.                          *)
(*                                                                        *)
(* Small model: 5 governed tools + 2 ungoverned, max 6 history entries.  *)
(* DAG: auth -> {read, list}, read -> {process}, list -> {process},      *)
(*      process -> {write}                                                *)
(**************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

(**************************************************************************)
(* CONSTANTS                                                              *)
(**************************************************************************)
CONSTANTS
    GovernedTools,      \* Set of tools in the DAG
    UngovernedTools,    \* Set of tools NOT in the DAG (pass through)
    EntryPoints,        \* Set of tools with no predecessors
    MaxHistoryLen       \* Maximum number of history entries to explore

AllTools == GovernedTools \union UngovernedTools

(**************************************************************************)
(* The adjacency relation: tool -> set of valid successors.               *)
(* Defined as a TLA+ function matching the test DAG:                      *)
(*   auth -> {read, list}                                                 *)
(*   read -> {process}                                                    *)
(*   list -> {process}                                                    *)
(*   process -> {write}                                                   *)
(*   write -> {} (terminal)                                               *)
(**************************************************************************)
Successors == [
    auth    |-> {"read", "list"},
    read    |-> {"process"},
    list    |-> {"process"},
    process |-> {"write"},
    write   |-> {}
]

(**************************************************************************)
(* VARIABLES                                                              *)
(**************************************************************************)
VARIABLES
    history,        \* Sequence of tools called so far
    currentTool,    \* The tool being evaluated (or "none")
    verdict         \* "pending" | "allow" | "deny"

vars == <<history, currentTool, verdict>>

(**************************************************************************)
(* Helper: Find the most recent governed tool in a sequence.              *)
(* Returns "none" if no governed tool has been called.                    *)
(**************************************************************************)
RECURSIVE LastGoverned(_, _)
LastGoverned(seq, idx) ==
    IF idx = 0 THEN "none"
    ELSE IF seq[idx] \in GovernedTools THEN seq[idx]
    ELSE LastGoverned(seq, idx - 1)

MostRecentGoverned(seq) == LastGoverned(seq, Len(seq))

(**************************************************************************)
(* Evaluate a governed tool against the workflow template.                *)
(* Returns TRUE if the tool is allowed by the DAG.                        *)
(**************************************************************************)
IsAllowedByWorkflow(tool, hist) ==
    LET prev == MostRecentGoverned(hist)
    IN  IF prev = "none"
        THEN tool \in EntryPoints
        ELSE tool \in Successors[prev]

(**************************************************************************)
(* INITIAL STATE                                                          *)
(**************************************************************************)
Init ==
    /\ history = <<>>
    /\ currentTool = "none"
    /\ verdict = "pending"

(**************************************************************************)
(* ACTIONS                                                                *)
(**************************************************************************)

\* Select a tool and evaluate it.
EvaluateTool ==
    /\ verdict = "pending"
    /\ Len(history) < MaxHistoryLen
    /\ \E tool \in AllTools :
        /\ currentTool' = tool
        /\ IF tool \in GovernedTools
           THEN IF IsAllowedByWorkflow(tool, history)
                THEN /\ verdict' = "allow"
                     /\ history' = Append(history, tool)
                ELSE /\ verdict' = "deny"
                     /\ history' = history
           ELSE \* Non-governed tool: pass through (always allow).
                /\ verdict' = "allow"
                /\ history' = Append(history, tool)

\* Reset verdict so we can evaluate the next tool.
ResetVerdict ==
    /\ verdict \in {"allow", "deny"}
    /\ verdict' = "pending"
    /\ currentTool' = "none"
    /\ UNCHANGED history

(**************************************************************************)
(* SPECIFICATION                                                          *)
(**************************************************************************)
Next == EvaluateTool \/ ResetVerdict

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(**************************************************************************)
(* TYPE INVARIANT                                                         *)
(**************************************************************************)
TypeOK ==
    /\ history \in Seq(AllTools)
    /\ Len(history) <= MaxHistoryLen
    /\ currentTool \in AllTools \union {"none"}
    /\ verdict \in {"pending", "allow", "deny"}

(**************************************************************************)
(* S8: WorkflowPredecessor                                                *)
(*                                                                        *)
(* A governed tool receives "allow" only if:                              *)
(*   (a) no previous governed tool exists and it is an entry point, OR    *)
(*   (b) it is a valid successor of the most recent governed tool.        *)
(*                                                                        *)
(* Equivalently: if verdict = "allow" and currentTool is governed,        *)
(* then IsAllowedByWorkflow must hold at the point of evaluation          *)
(* (which is the history BEFORE appending the current tool).              *)
(**************************************************************************)
InvariantS8_WorkflowPredecessor ==
    (verdict = "allow" /\ currentTool \in GovernedTools)
        => LET histBefore == SubSeq(history, 1, Len(history) - 1)
           IN  IsAllowedByWorkflow(currentTool, histBefore)

(**************************************************************************)
(* S9: AcyclicDAG                                                         *)
(*                                                                        *)
(* No tool can reach itself through the successor relation.               *)
(* We verify this structurally: for every governed tool t, t is not       *)
(* reachable from itself via the Successors function.                     *)
(**************************************************************************)
RECURSIVE ReachableFrom(_, _)
ReachableFrom(tool, visited) ==
    LET succs == Successors[tool] \ visited
    IN  succs \union UNION {ReachableFrom(s, visited \union succs) : s \in succs}

InvariantS9_AcyclicDAG ==
    \A t \in GovernedTools : t \notin ReachableFrom(t, {})

ModelInvariant ==
    /\ TypeOK
    /\ InvariantS9_AcyclicDAG

=============================================================================
