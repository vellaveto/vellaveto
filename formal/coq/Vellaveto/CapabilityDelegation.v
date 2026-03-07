(** * Capability Delegation Attenuation (S11-S16)

    Models the capability token delegation chain from
    [vellaveto-mcp/src/capability_token.rs].

    Defines delegation chain as an inductive relation and proves
    attenuation properties:
    - S11: Monotonic attenuation — child grants subset of parent grants
    - S12: Transitive attenuation — holds across entire chains
    - S13: Depth bounded — chain length <= root depth
    - S14: Temporal monotonicity — child.expires <= parent.expires
    - S15: Terminal cannot delegate — depth=0 -> no children
    - S16: Issuer chain integrity — child.issuer = parent.holder
*)

Require Import Vellaveto.Types.
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Arith.PeanoNat.
Require Import Coq.Arith.Arith.
Require Import Lia.
Import ListNotations.

(** ** Grant Subset Relation *)

(** Reduced grant subset model used by the Coq proofs.
    This is an exact-pattern preorder plus monotone depth attenuation, not the
    full runtime glob/path/domain containment check. *)
Definition grant_subset (g pg : Grant) : Prop :=
  grant_tool_pattern g = grant_tool_pattern pg /\
  grant_function_pattern g = grant_function_pattern pg /\
  grant_depth_allowed g <= grant_depth_allowed pg.

(** [grant_subset] is reflexive. *)
Lemma grant_subset_refl : forall g, grant_subset g g.
Proof.
  intro g.
  unfold grant_subset.
  repeat split; try reflexivity; lia.
Qed.

(** [grant_subset] is transitive. *)
Lemma grant_subset_trans :
  forall g1 g2 g3,
    grant_subset g1 g2 -> grant_subset g2 g3 -> grant_subset g1 g3.
Proof.
  intros g1 g2 g3 [Htool12 [Hfunc12 Hdepth12]] [Htool23 [Hfunc23 Hdepth23]].
  unfold grant_subset.
  split.
  - rewrite Htool12. exact Htool23.
  - split.
    + rewrite Hfunc12. exact Hfunc23.
    + lia.
Qed.

(** ** Attenuation *)

(** Attenuated: every child grant is covered by some parent grant. *)
Definition attenuated (child parent : CapToken) : Prop :=
  forall g, In g (ct_grants child) ->
    exists pg, In pg (ct_grants parent) /\ grant_subset g pg.

(** ** Well-Formed Delegation *)

(** Structural invariants for a single delegation step. *)
Inductive well_formed_delegation : CapToken -> CapToken -> Prop :=
  | wf_deleg : forall child parent,
      ct_parent_id child = Some (ct_id parent) ->
      ct_issuer child = ct_holder parent ->
      ct_remaining_depth parent > 0 ->
      ct_remaining_depth child = ct_remaining_depth parent - 1 ->
      ct_expires child <= ct_expires parent ->
      attenuated child parent ->
      well_formed_delegation child parent.

(** ** Ancestor Chain *)

(** An ancestor chain is a sequence of well-formed delegations. *)
Inductive ancestor_chain : CapToken -> list CapToken -> Prop :=
  | chain_root : forall t, ancestor_chain t nil
  | chain_step : forall child parent rest,
      well_formed_delegation child parent ->
      ancestor_chain parent rest ->
      ancestor_chain child (parent :: rest).

(** ** S11: Monotonic Attenuation *)

(** Well-formed delegation implies attenuation. *)
Theorem s11_monotonic_attenuation :
  forall child parent,
    well_formed_delegation child parent ->
    attenuated child parent.
Proof.
  intros child parent H.
  inversion H. assumption.
Qed.

(** ** S12: Transitive Attenuation *)

(** Attenuation is transitive across chains: if child is attenuated
    w.r.t. parent, and parent is attenuated w.r.t. grandparent,
    then child is attenuated w.r.t. grandparent. *)
Lemma attenuated_trans :
  forall t1 t2 t3,
    attenuated t1 t2 -> attenuated t2 t3 -> attenuated t1 t3.
Proof.
  unfold attenuated.
  intros t1 t2 t3 H12 H23 g Hg.
  destruct (H12 g Hg) as [pg [Hpg_in Hpg_sub]].
  destruct (H23 pg Hpg_in) as [gpg [Hgpg_in Hgpg_sub]].
  exists gpg. split.
  - exact Hgpg_in.
  - exact (grant_subset_trans g pg gpg Hpg_sub Hgpg_sub).
Qed.

(** Attenuation holds across entire ancestor chains.
    For any token [t] with ancestor chain [t :: chain], [t] is
    attenuated w.r.t. the last ancestor in the chain. *)
Theorem s12_transitive_attenuation :
  forall t chain,
    ancestor_chain t chain ->
    forall ancestor, In ancestor chain ->
    exists mid_chain,
      ancestor_chain t mid_chain /\
      (mid_chain = nil \/ exists last rest, mid_chain = last :: rest) /\
      attenuated t ancestor.
Proof.
  intros t chain Hchain.
  induction Hchain as [t' | child parent rest Hwf Hparent_chain IH].
  - (* chain_root — In ancestor nil is absurd *)
    intros ancestor Hin. destruct Hin.
  - (* chain_step *)
    intros ancestor Hin.
    destruct Hin as [Heq | Hin_rest].
    + (* ancestor = parent *)
      subst ancestor.
      exists (parent :: rest). split.
      * constructor; assumption.
      * split.
        -- right. exists parent, rest. reflexivity.
        -- apply s11_monotonic_attenuation. exact Hwf.
    + (* ancestor in rest *)
      destruct (IH ancestor Hin_rest) as [mid [Hmid_chain [_ Hatt]]].
      exists (parent :: rest). split.
      * constructor; assumption.
      * split.
        -- right. exists parent, rest. reflexivity.
        -- apply attenuated_trans with (t2 := parent).
           ++ apply s11_monotonic_attenuation. exact Hwf.
           ++ exact Hatt.
Qed.

(** ** S13: Depth Bounded *)

(** Helper: well-formed delegation strictly decreases remaining depth. *)
Lemma depth_step :
  forall child parent,
    well_formed_delegation child parent ->
    ct_remaining_depth child < ct_remaining_depth parent.
Proof.
  intros child parent Hwf.
  inversion Hwf as [c p Hpid Hiss Hdepth_pos Hdepth_eq Hexp Hatt].
  subst. lia.
Qed.

(** Any ancestor in the chain has strictly greater remaining depth
    than the leaf token. Since remaining depth is a natural number
    (non-negative), this bounds the maximum chain length to the
    root's remaining depth. *)
Theorem s13_depth_bounded :
  forall t chain ancestor,
    ancestor_chain t chain ->
    In ancestor chain ->
    ct_remaining_depth t < ct_remaining_depth ancestor.
Proof.
  intros t chain ancestor Hchain.
  induction Hchain as [t' | child parent rest Hwf Hparent_chain IH].
  - (* chain_root — In ancestor nil is absurd *)
    intros Hin. destruct Hin.
  - (* chain_step *)
    intros Hin. destruct Hin as [Heq | Hin_rest].
    + (* ancestor = parent *)
      subst. apply depth_step. exact Hwf.
    + (* ancestor in rest — transitivity through parent *)
      apply Nat.lt_trans with (m := ct_remaining_depth parent).
      * apply depth_step. exact Hwf.
      * apply IH. exact Hin_rest.
Qed.

(** ** S14: Temporal Monotonicity *)

(** Well-formed delegation implies child.expires <= parent.expires. *)
Theorem s14_temporal_monotonicity :
  forall child parent,
    well_formed_delegation child parent ->
    ct_expires child <= ct_expires parent.
Proof.
  intros child parent Hwf.
  inversion Hwf. assumption.
Qed.

(** ** S15: Terminal Cannot Delegate *)

(** If a token has depth 0, it cannot be a parent in a well-formed
    delegation (no children allowed). *)
Theorem s15_terminal_no_children :
  forall child parent,
    ct_remaining_depth parent = 0 ->
    ~ well_formed_delegation child parent.
Proof.
  intros child parent Hzero Hwf.
  inversion Hwf as [c p Hpid Hiss Hdepth_pos Hdepth_eq Hexp Hatt].
  subst. rewrite Hzero in Hdepth_pos.
  apply Nat.lt_irrefl with 0. exact Hdepth_pos.
Qed.

(** ** S16: Issuer Chain Integrity *)

(** Well-formed delegation implies child.issuer = parent.holder. *)
Theorem s16_issuer_chain_integrity :
  forall child parent,
    well_formed_delegation child parent ->
    ct_issuer child = ct_holder parent.
Proof.
  intros child parent Hwf.
  inversion Hwf. assumption.
Qed.
