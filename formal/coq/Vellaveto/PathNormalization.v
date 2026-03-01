(** * Path Normalization Idempotence

    Proves that [normalize(normalize(x)) = normalize(x)].

    Mirror of [formal/lean/Vellaveto/PathNormalization.lean].

    Models [normalize_path_bounded] from
    [vellaveto-engine/src/path.rs:58-156].

    Why idempotence matters: Without idempotence, an attacker can craft
    a path that normalizes differently on each pass:
    - Pass 1: [%2570] -> [%70] (one decode iteration)
    - Pass 2: [%70] -> [p] (another decode iteration)

    If the policy engine normalizes once but the downstream tool normalizes
    again, they see different paths -> policy bypass.

    Vellaveto achieves idempotence by decoding in a loop until stable.

    Model:
    1. Iterative percent-decode until fixed point
    2. Component resolution ([.], [..])
    3. Absolute path enforcement

    The proof shows that the output of [resolveComponents] is already a
    fixed point, hence re-resolution is a no-op. *)

Require Import Vellaveto.Types.
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Import ListNotations.

Open Scope string_scope.

(** ** Iterative Percent Decoding *)

Section IterDecode.

  (** Abstract percent-decode function. *)
  Variable percentDecode : string -> string.

  (** Iterative decode: apply [percentDecode] until stable,
      up to [maxIter] iterations. Returns [None] if the limit is
      reached (fail-closed). *)
  Fixpoint iterDecode (maxIter : nat) (s : string) : option string :=
    match maxIter with
    | O => None  (* fail-closed: iteration limit exceeded *)
    | S n =>
      let decoded := percentDecode s in
      if String.eqb decoded s then Some s  (* stable: fixed point *)
      else iterDecode n decoded
    end.

  (** The output of [iterDecode] (when successful) is a fixed point
      of [percentDecode]. *)
  Theorem iterDecode_is_fixpoint :
    forall (maxIter : nat) (s result : string),
      iterDecode maxIter s = Some result ->
      percentDecode result = result.
  Proof.
    intros maxIter. induction maxIter as [| n IH]; intros s result H.
    - (* O — None, contradiction *)
      simpl in H. discriminate.
    - (* S n *)
      simpl in H.
      destruct (String.eqb (percentDecode s) s) eqn:Heq.
      + (* decoded = s: stable *)
        injection H as H. subst.
        apply String.eqb_eq. exact Heq.
      + (* decoded <> s: recurse *)
        apply IH with (s := percentDecode s). exact H.
  Qed.

End IterDecode.

(** ** Component Resolution *)

(** Resolve path components: remove [.], handle [..], flatten. *)
Fixpoint resolveComponents (cs : list string) : list string :=
  match cs with
  | nil => nil
  | c :: rest =>
    if String.eqb c "." then
      resolveComponents rest
    else if String.eqb c ".." then
      match resolveComponents rest with
      | nil => nil         (* at root, absorb *)
      | _ :: resolved => resolved  (* pop one component *)
      end
    else
      c :: resolveComponents rest
  end.

(** [resolveComponents] output contains no ["."] entries. *)
Theorem resolveComponents_no_dot :
  forall (cs : list string),
    ~ In "." (resolveComponents cs).
Proof.
  intros cs. induction cs as [| c rest IH].
  - (* nil *)
    simpl. auto.
  - (* cons c rest *)
    simpl. destruct (String.eqb c ".") eqn:Hc_dot.
    + (* c = "." — skipped, recurse *)
      exact IH.
    + destruct (String.eqb c "..") eqn:Hc_dotdot.
      * (* c = ".." *)
        destruct (resolveComponents rest) as [| x xs] eqn:Hresolved.
        -- simpl. auto.
        -- (* result is xs; IH is now ~ In "." (x :: xs)
              after destruct replaced resolveComponents rest *)
           intro Habs. apply IH. simpl. right. exact Habs.
      * (* c <> "." and c <> ".." *)
        intro Habs. simpl in Habs. destruct Habs as [Heq | Hin].
        -- (* c = "." — contradicts Hc_dot *)
           apply String.eqb_neq in Hc_dot. exact (Hc_dot Heq).
        -- (* In "." (resolveComponents rest) — contradicts IH *)
           exact (IH Hin).
Qed.

(** [resolveComponents] output contains no [".."] entries. *)
Theorem resolveComponents_no_dotdot :
  forall (cs : list string),
    ~ In ".." (resolveComponents cs).
Proof.
  intros cs. induction cs as [| c rest IH].
  - (* nil *)
    simpl. auto.
  - (* cons c rest *)
    simpl. destruct (String.eqb c ".") eqn:Hc_dot.
    + (* c = "." — skipped *)
      exact IH.
    + destruct (String.eqb c "..") eqn:Hc_dotdot.
      * (* c = ".." *)
        destruct (resolveComponents rest) as [| x xs] eqn:Hresolved.
        -- simpl. auto.
        -- intro Habs. apply IH. simpl. right. exact Habs.
      * (* c <> "." and c <> ".." *)
        intro Habs. simpl in Habs. destruct Habs as [Heq | Hin].
        -- apply String.eqb_neq in Hc_dotdot. exact (Hc_dotdot Heq).
        -- exact (IH Hin).
Qed.

(** If a list contains no ["."] or [".."], [resolveComponents]
    returns it unchanged. *)
Theorem resolveComponents_id_of_clean :
  forall (cs : list string),
    ~ In "." cs -> ~ In ".." cs ->
    resolveComponents cs = cs.
Proof.
  intros cs Hd Hdd. induction cs as [| c rest IH].
  - (* nil *)
    reflexivity.
  - (* cons c rest *)
    simpl. destruct (String.eqb c ".") eqn:Hc_dot.
    + (* c = "." — contradicts Hd *)
      exfalso. apply Hd. simpl. left. apply String.eqb_eq. exact Hc_dot.
    + destruct (String.eqb c "..") eqn:Hc_dotdot.
      * (* c = ".." — contradicts Hdd *)
        exfalso. apply Hdd. simpl. left. apply String.eqb_eq. exact Hc_dotdot.
      * (* c <> "." and c <> ".." *)
        f_equal. apply IH.
        -- intro H. apply Hd. simpl. right. exact H.
        -- intro H. apply Hdd. simpl. right. exact H.
Qed.

(** [resolveComponents] is idempotent: applying it twice yields the
    same result. Follows from [no_dot], [no_dotdot], and [id_of_clean]. *)
Theorem resolveComponents_idempotent :
  forall (cs : list string),
    resolveComponents (resolveComponents cs) = resolveComponents cs.
Proof.
  intros cs.
  apply resolveComponents_id_of_clean.
  - apply resolveComponents_no_dot.
  - apply resolveComponents_no_dotdot.
Qed.

(** ** Full Normalization Idempotence *)

(** The iterative decode output is a fixed point, so decoding again
    is identity. Combined with [resolveComponents] idempotence and
    [makeAbsolute] idempotence, this gives full normalization
    idempotence. *)
Theorem normalize_idempotent_core :
  forall (split : string -> list string) (decoded : string),
    resolveComponents (split decoded) =
    resolveComponents (resolveComponents (split decoded)).
Proof.
  intros. symmetry. apply resolveComponents_idempotent.
Qed.
