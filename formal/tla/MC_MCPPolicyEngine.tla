----------------------- MODULE MC_MCPPolicyEngine -----------------------
(**************************************************************************)
(* Model companion for MCPPolicyEngine — defines concrete constants for   *)
(* TLC model checking.                                                    *)
(*                                                                        *)
(* TLC's .cfg parser cannot handle set-of-record literals. This module    *)
(* defines PolicySet and ActionSet as TLA+ operators that are overridden  *)
(* via CONSTANT ... <- in the .cfg file.                                  *)
(**************************************************************************)
EXTENDS MCPPolicyEngine

(**************************************************************************)
(* Model values — these are declared as CONSTANTS in the .cfg and used    *)
(* here in the record definitions.                                        *)
(**************************************************************************)
CONSTANTS t1, t2, t3, f1, f2, f3, p1, p2, p3, d1, d2, d3, wildcard

(**************************************************************************)
(* const_PolicySet: 3 policies covering key scenarios                     *)
(*                                                                        *)
(* Policy 1: High-priority wildcard Deny with blocked path p1            *)
(* Policy 2: Medium-priority Allow for t1/f1 with path/domain allowlist  *)
(* Policy 3: Medium-priority Conditional for t2/* with blocked domain,   *)
(*           on_no_match="continue", requires context                     *)
(**************************************************************************)
const_PolicySet ==
    {
        [id |-> "pol1", priority |-> 10, type |-> "Deny",
         tool |-> wildcard, function |-> wildcard,
         blocked_paths |-> {p1}, allowed_paths |-> {},
         blocked_domains |-> {}, allowed_domains |-> {},
         on_no_match |-> "deny", requires_context |-> FALSE,
         require_approval |-> FALSE],
        [id |-> "pol2", priority |-> 5, type |-> "Allow",
         tool |-> t1, function |-> f1,
         blocked_paths |-> {}, allowed_paths |-> {p2, p3},
         blocked_domains |-> {}, allowed_domains |-> {d1, d2},
         on_no_match |-> "deny", requires_context |-> FALSE,
         require_approval |-> FALSE],
        [id |-> "pol3", priority |-> 3, type |-> "Conditional",
         tool |-> t2, function |-> wildcard,
         blocked_paths |-> {}, allowed_paths |-> {},
         blocked_domains |-> {d3}, allowed_domains |-> {},
         on_no_match |-> "continue", requires_context |-> TRUE,
         require_approval |-> TRUE]
    }

(**************************************************************************)
(* const_ActionSet: 2 representative actions                              *)
(*                                                                        *)
(* Action 1: t1/f1 targeting p2/d1 with context (normal allow path)      *)
(* Action 2: t2/f2 targeting p1/d3 without context (blocked + no context) *)
(**************************************************************************)
const_ActionSet ==
    {
        [tool |-> t1, function |-> f1,
         target_paths |-> {p2}, target_domains |-> {d1},
         has_context |-> TRUE],
        [tool |-> t2, function |-> f2,
         target_paths |-> {p1}, target_domains |-> {d3},
         has_context |-> FALSE]
    }

=========================================================================
