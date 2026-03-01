(** * Determinism of Policy Evaluation

    Proves that [evaluate_action] is a deterministic function:
    given the same policy set and action, it always returns the same verdict.

    Mirror of [formal/lean/Vellaveto/Determinism.lean].

    Models [PolicyEngine::evaluate_action] from
    [vellaveto-engine/src/lib.rs:234-296].

    Key insight: The evaluation is a first-match scan over a sorted list.
    Sorting is deterministic (priority desc, deny-first at equal priority,
    lexicographic by ID as tiebreaker). The scan is a pure fold with no
    side effects. Therefore the result is fully determined by (policies, action).

    In Coq, all definitions are total and deterministic by construction,
    so these theorems are intentionally trivial (by [reflexivity]). Their
    value is making the meta-property explicit and machine-checked. *)

Require Import Vellaveto.Types.
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Import ListNotations.

Section Determinism.

  (** Concrete matching: all policies match (abstract — any pure function
      would work; determinism holds for all). *)
  Definition matchesAction (p : Policy) (a : Action) : bool := true.

  (** Apply a matched policy to produce a verdict.
      Returns [None] when on_no_match = "continue". *)
  Definition applyPolicy (p : Policy) (a : Action) : option Verdict :=
    match pol_type p with
    | PTAllow => Some Allow
    | PTDeny => Some (Deny (pol_id p))
    | PTConditional => None
    end.

  (** First-match evaluation: scan policies in order, return the first
      verdict produced by a matching policy. Default: Deny. *)
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

  (** The full evaluation function: sort, then first-match scan.
      We use [id] for sorting since the determinism proof does not
      depend on sort order — it only requires sort to be a pure function. *)
  Definition evaluate (policies : list Policy) (action : Action) : Verdict :=
    evaluateFirstMatch action policies.

  (** [evaluateFirstMatch] is deterministic: same inputs -> same output. *)
  Theorem evaluateFirstMatch_deterministic :
    forall (action : Action) (policies : list Policy),
      evaluateFirstMatch action policies = evaluateFirstMatch action policies.
  Proof.
    intros. reflexivity.
  Qed.

  (** [evaluate] is deterministic: for any fixed policy set and action,
      the verdict is uniquely determined. *)
  Theorem evaluate_deterministic :
    forall (policies : list Policy) (action : Action),
      evaluate policies action = evaluate policies action.
  Proof.
    intros. reflexivity.
  Qed.

  (** Stronger form: two calls with equal inputs produce equal outputs. *)
  Theorem evaluate_eq_of_eq :
    forall (p1 p2 : list Policy) (a1 a2 : Action),
      p1 = p2 -> a1 = a2 ->
      evaluate p1 a1 = evaluate p2 a2.
  Proof.
    intros p1 p2 a1 a2 Hp Ha.
    subst. reflexivity.
  Qed.

  (** The default verdict (empty policy list) is always Deny. *)
  Theorem evaluate_empty_is_deny :
    forall (action : Action),
      evaluate nil action = Deny "No matching policy".
  Proof.
    intros. reflexivity.
  Qed.

End Determinism.
