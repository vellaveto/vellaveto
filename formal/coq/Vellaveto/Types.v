(** * Vellaveto Shared Types

    Core type definitions shared across all Coq proof files.

    Maps to:
    - [vellaveto-types/src/core.rs]: Verdict, Policy, Action
    - [vellaveto-engine/src/abac.rs]: AbacEffect, AbacPolicy, AbacDecision
    - [vellaveto-mcp/src/capability_token.rs]: Grant, CapToken
*)

Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Arith.PeanoNat.
Import ListNotations.

(** ** Policy Engine Types *)

Inductive Verdict : Type :=
  | Allow : Verdict
  | Deny : string -> Verdict
  | RequireApproval : string -> Verdict.

Inductive PolicyType : Type :=
  | PTAllow : PolicyType
  | PTDeny : PolicyType
  | PTConditional : PolicyType.

Record Policy : Type := mkPolicy {
  pol_id : string;
  pol_priority : nat;
  pol_type : PolicyType;
}.

Record Action : Type := mkAction {
  act_tool : string;
  act_function : string;
}.

(** ** ABAC Types *)

Inductive AbacEffect : Type :=
  | Permit : AbacEffect
  | Forbid : AbacEffect.

Record AbacPolicy : Type := mkAbacPolicy {
  abac_id : string;
  abac_effect : AbacEffect;
  abac_priority : nat;
}.

Inductive AbacDecision : Type :=
  | ADeny : string -> AbacDecision
  | AAllow : string -> AbacDecision
  | ANoMatch : AbacDecision.

(** ** Capability Delegation Types *)

Record Grant : Type := mkGrant {
  grant_tool_pattern : string;
  grant_function_pattern : string;
  grant_depth_allowed : nat;
}.

Record CapToken : Type := mkCapToken {
  ct_id : string;
  ct_parent_id : option string;
  ct_issuer : string;
  ct_holder : string;
  ct_grants : list Grant;
  ct_remaining_depth : nat;
  ct_expires : nat;
}.

(** ** Decidable equality *)

Scheme Equality for Verdict.
Scheme Equality for PolicyType.
Scheme Equality for AbacEffect.
Scheme Equality for AbacDecision.
