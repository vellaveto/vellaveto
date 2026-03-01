(** * ABAC Forbid-Override Properties (S7-S10)

    Models the ABAC combining algorithm from
    [vellaveto-engine/src/abac.rs:322-364].

    The core algorithm: scan sorted policies; the first forbid match
    wins immediately (Deny), accumulating the best permit along the way.

    4 theorems:
    - S7:  Forbid dominance — any matching forbid -> Deny
    - S8:  Forbid ignores priority — forbid at any position beats permit
    - S9:  Permit requires no forbid — Allow -> no matching forbid exists
    - S10: No match -> NoMatch
*)

Require Import Vellaveto.Types.
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Import ListNotations.

Section AbacForbidOverride.

  (** Abstract matching predicate for ABAC policies. *)
  Variable matches : AbacPolicy -> bool.

  (** Core ABAC combining algorithm: scan policies in order.
      First forbid match -> ADeny (immediate exit).
      Accumulate best permit (first-match). *)
  Fixpoint abac_eval (policies : list AbacPolicy)
      (best_permit : option string) : AbacDecision :=
    match policies with
    | nil =>
      match best_permit with
      | Some pid => AAllow pid
      | None => ANoMatch
      end
    | p :: ps =>
      if matches p then
        match abac_effect p with
        | Forbid => ADeny (abac_id p)  (* S7: immediate exit *)
        | Permit =>
          abac_eval ps
            (match best_permit with
             | Some _ => best_permit  (* keep first permit *)
             | None => Some (abac_id p)
             end)
        end
      else
        abac_eval ps best_permit
    end.

  (** ** S7: Forbid Dominance *)

  (** Helper: if the head is a matching forbid, result is ADeny. *)
  Lemma abac_eval_head_forbid :
    forall p ps bp,
      matches p = true ->
      abac_effect p = Forbid ->
      abac_eval (p :: ps) bp = ADeny (abac_id p).
  Proof.
    intros p ps bp Hmatch Heff.
    simpl. rewrite Hmatch. rewrite Heff. reflexivity.
  Qed.

  (** If a matching forbid exists anywhere in the policy list,
      [abac_eval] returns [ADeny] (for some forbid policy's ID). *)
  Theorem s7_forbid_dominance :
    forall (policies : list AbacPolicy) (bp : option string),
      (exists p, In p policies /\ matches p = true /\ abac_effect p = Forbid) ->
      exists pid, abac_eval policies bp = ADeny pid.
  Proof.
    intros policies.
    induction policies as [| q qs IH].
    - (* nil — pf In nil is absurd *)
      intros bp [pf [Hin _]]. destruct Hin.
    - (* cons q qs *)
      intros bp [pf [Hin [Hmatch Heff]]].
      simpl. destruct (matches q) eqn:Hq_match.
      + (* q matches *)
        destruct (abac_effect q) eqn:Hq_eff.
        * (* q is Permit *)
          destruct Hin as [Heq | Hin_rest].
          -- (* pf = q — but q is Permit and pf is Forbid: contradiction *)
             subst. rewrite Heff in Hq_eff. discriminate.
          -- (* pf in qs — IH works for any bp *)
             apply IH. exists pf. auto.
        * (* q is Forbid — immediate *)
          exists (abac_id q). reflexivity.
      + (* q does not match *)
        destruct Hin as [Heq | Hin_rest].
        -- (* pf = q — but matches q = false and matches pf = true *)
           subst. rewrite Hmatch in Hq_match. discriminate.
        -- apply IH. exists pf. auto.
  Qed.

  (** ** S8: Forbid Ignores Priority *)

  (** Forbid at any position beats permit at any position.
      This is a corollary of S7: if a forbid matches, the result
      is always ADeny regardless of where permits appear. *)
  Theorem s8_forbid_ignores_priority :
    forall (policies : list AbacPolicy) (bp : option string)
           (pf pp : AbacPolicy),
      In pf policies ->
      In pp policies ->
      matches pf = true ->
      abac_effect pf = Forbid ->
      matches pp = true ->
      abac_effect pp = Permit ->
      exists pid, abac_eval policies bp = ADeny pid.
  Proof.
    intros policies bp pf pp Hf_in Hp_in Hf_match Hf_eff Hp_match Hp_eff.
    apply s7_forbid_dominance.
    exists pf. auto.
  Qed.

  (** ** S9: Permit Requires No Forbid *)

  (** If [abac_eval] returns [AAllow], then no matching forbid exists
      in the policy list. Contrapositive of S7. *)
  Theorem s9_permit_requires_no_forbid :
    forall (policies : list AbacPolicy) (bp : option string) (pid : string),
      abac_eval policies bp = AAllow pid ->
      ~ (exists p, In p policies /\ matches p = true /\ abac_effect p = Forbid).
  Proof.
    intros policies bp pid Hresult Hcontra.
    destruct (s7_forbid_dominance policies bp Hcontra) as [fid Hfid].
    rewrite Hfid in Hresult. discriminate.
  Qed.

  (** ** S10: No Match -> NoMatch *)

  (** If no policy matches, [abac_eval] returns whatever [best_permit]
      dictates. Starting with [None], it returns [ANoMatch]. *)
  Theorem s10_no_match_nomatch :
    forall (policies : list AbacPolicy),
      (forall p, In p policies -> matches p = false) ->
      abac_eval policies None = ANoMatch.
  Proof.
    intros policies H_none.
    induction policies as [| q qs IH].
    - (* nil *)
      simpl. reflexivity.
    - (* cons q qs *)
      simpl. rewrite H_none.
      + apply IH. intros p Hp. apply H_none. right. exact Hp.
      + left. reflexivity.
  Qed.

End AbacForbidOverride.
