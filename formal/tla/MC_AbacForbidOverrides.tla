--------------------- MODULE MC_AbacForbidOverrides ---------------------
(**************************************************************************)
(* Model companion for AbacForbidOverrides — defines concrete constants   *)
(* for TLC model checking.                                                *)
(*                                                                        *)
(* TLC's .cfg parser cannot handle set-of-record literals. This module    *)
(* defines AbacPolicySet and AbacActionSet as operators that are          *)
(* overridden via CONSTANT ... <- in the .cfg file.                       *)
(**************************************************************************)
EXTENDS AbacForbidOverrides

(**************************************************************************)
(* Model values                                                           *)
(**************************************************************************)
CONSTANTS t1, t2, f1, f2, wildcard, alice, bob

(**************************************************************************)
(* const_AbacPolicySet: 4 policies covering key scenarios                 *)
(*                                                                        *)
(* Policy 1: High-priority Permit for alice on t1/f1                     *)
(* Policy 2: Low-priority Forbid for alice on t1/* — tests S8            *)
(*           (low-priority forbid beats high-priority permit)             *)
(* Policy 3: Permit for bob on t2/f2                                     *)
(* Policy 4: Permit for bob on t1/f1 with conditions=FALSE — tests that  *)
(*           unsatisfied conditions exclude a policy from matching (P3-2) *)
(**************************************************************************)
const_AbacPolicySet ==
    {
        [id |-> "abac1", principal |-> alice, action |-> t1, resource |-> f1,
         effect |-> "Permit", priority |-> 10, conditions |-> TRUE],
        [id |-> "abac2", principal |-> alice, action |-> t1, resource |-> wildcard,
         effect |-> "Forbid", priority |-> 1, conditions |-> TRUE],
        [id |-> "abac3", principal |-> bob, action |-> t2, resource |-> f2,
         effect |-> "Permit", priority |-> 5, conditions |-> TRUE],
        [id |-> "abac4", principal |-> bob, action |-> t1, resource |-> f1,
         effect |-> "Permit", priority |-> 8, conditions |-> FALSE]
    }

(**************************************************************************)
(* const_AbacActionSet: 2 representative actions                          *)
(**************************************************************************)
const_AbacActionSet ==
    {
        [tool |-> t1, function |-> f1,
         target_paths |-> {}, target_domains |-> {},
         has_context |-> TRUE],
        [tool |-> t2, function |-> f2,
         target_paths |-> {}, target_domains |-> {},
         has_context |-> TRUE]
    }

=========================================================================
