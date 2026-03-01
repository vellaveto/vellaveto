(** * Fail-Closed Property (S1, S5)

    Proves that when no policy matches an action, the verdict is Deny.
    Mirror of [formal/lean/Vellaveto/FailClosed.lean].

    Models [PolicyEngine::evaluate_action] from
    [vellaveto-engine/src/lib.rs:234-296], specifically lines 293-295:

    <<
    Ok(Verdict::Deny {
        reason: "No matching policy".to_string(),
    })
    >>

    Invariant statement:
    For all actions [a] and policy sets [P]:
    if no policy in [P] matches [a], then [evaluate(P, a) = Deny].
*)

Require Import Vellaveto.Types.
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Import ListNotations.

Section FailClosed.

  (** Abstract matching predicate — the concrete implementation uses
      glob/regex/exact matching, but the fail-closed proof only requires
      that matching is a pure function. *)
  Variable matchesAction : Policy -> Action -> bool.

  (** Abstract policy application. Returns [Some v] when the policy
      produces a verdict, [None] when on_no_match = "continue"
      (conditional policy whose conditions are not met). *)
  Variable applyPolicy : Policy -> Action -> option Verdict.

  (** First-match evaluation with parameterized matching.
      Base case: empty list -> Deny (fail-closed). *)
  Fixpoint evaluateFirstMatch (action : Action) (policies : list Policy)
    : Verdict :=
    match policies with
    | nil => Deny "No matching policy"
    | p :: ps =>
      if matchesAction p action then
        match applyPolicy p action with
        | Some v => v
        | None => evaluateFirstMatch action ps
        end
      else
        evaluateFirstMatch action ps
    end.

  (** ** S1: Fail-closed on empty policy set *)

  (** With an empty policy list, the verdict is always Deny. *)
  Theorem s1_empty_policies_deny :
    forall (action : Action),
      evaluateFirstMatch action nil = Deny "No matching policy".
  Proof.
    intros. reflexivity.
  Qed.

  (** ** S1: Fail-closed when no policy matches *)

  (** When no policy in the list matches the action, the verdict is Deny.
      This is the core fail-closed invariant. *)
  Theorem s1_no_match_implies_deny :
    forall (action : Action) (policies : list Policy),
      (forall p, In p policies -> matchesAction p action = false) ->
      evaluateFirstMatch action policies = Deny "No matching policy".
  Proof.
    intros action policies H_none_match.
    induction policies as [| p ps IH].
    - (* nil *)
      reflexivity.
    - (* cons p ps *)
      simpl.
      rewrite H_none_match.
      + apply IH. intros q Hq. apply H_none_match. right. exact Hq.
      + left. reflexivity.
  Qed.

  (** ** S1: Fail-closed when all matching policies return None *)

  (** When every matching policy returns [None] from [applyPolicy]
      (i.e., all are Conditional with unmet conditions), the verdict
      is still Deny. *)
  Theorem s1_all_continue_implies_deny :
    forall (action : Action) (policies : list Policy),
      (forall p, In p policies ->
         matchesAction p action = true -> applyPolicy p action = None) ->
      evaluateFirstMatch action policies = Deny "No matching policy".
  Proof.
    intros action policies H_all_none.
    induction policies as [| p ps IH].
    - (* nil *)
      reflexivity.
    - (* cons p ps *)
      simpl. destruct (matchesAction p action) eqn:Hmatch.
      + (* matches *)
        rewrite H_all_none.
        * apply IH. intros q Hq Hq_match.
          apply H_all_none.
          -- right. exact Hq.
          -- exact Hq_match.
        * left. reflexivity.
        * exact Hmatch.
      + (* does not match *)
        apply IH. intros q Hq Hq_match.
        apply H_all_none.
        * right. exact Hq.
        * exact Hq_match.
  Qed.

  (** ** S5: Allow requires a matching Allow policy *)

  (** If [evaluateFirstMatch] returns [Allow], then there exists a matching
      policy whose application produces [Allow]. Contrapositive of S1. *)
  Theorem s5_allow_requires_match :
    forall (action : Action) (policies : list Policy),
      evaluateFirstMatch action policies = Allow ->
      exists p, In p policies /\
        matchesAction p action = true /\
        applyPolicy p action = Some Allow.
  Proof.
    intros action policies H_result.
    induction policies as [| p ps IH].
    - (* nil — contradiction: evaluateFirstMatch nil = Deny *)
      simpl in H_result. discriminate.
    - (* cons p ps *)
      simpl in H_result.
      destruct (matchesAction p action) eqn:Hmatch.
      + (* p matches *)
        destruct (applyPolicy p action) eqn:Happly.
        * (* applyPolicy = Some v *)
          exists p. split.
          -- left. reflexivity.
          -- split.
             ++ exact Hmatch.
             ++ rewrite Happly. f_equal. congruence.
        * (* applyPolicy = None — recurse *)
          destruct (IH H_result) as [q [Hq_in [Hq_match Hq_apply]]].
          exists q. split.
          -- right. exact Hq_in.
          -- split; assumption.
      + (* p does not match — recurse *)
        destruct (IH H_result) as [q [Hq_in [Hq_match Hq_apply]]].
        exists q. split.
        * right. exact Hq_in.
        * split; assumption.
  Qed.

End FailClosed.
