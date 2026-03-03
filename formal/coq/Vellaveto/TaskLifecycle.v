(** * Task Lifecycle Properties (T1-T3)

    Models the MCP Task primitive lifecycle state machine from
    [vellaveto-mcp/src/task_state.rs].

    The MCP 2025-11-25 Tasks primitive defines a state machine for
    long-running operations. This proof verifies:

    - T1: Terminal absorbing — completed/failed/cancelled are permanent
    - T2: Initial state — tasks begin in Working or Failed
    - T3: Valid transitions — only specified transitions are allowed

    Correspondence:
    - TLA+: formal/tla/MCPTaskLifecycle.tla (T1-T5, TL1-TL2)
*)

Require Import Coq.Lists.List.
Require Import Coq.Bool.Bool.
Import ListNotations.

(** ** Task States *)

(** Maps to TaskStatus enum in the MCP specification. *)
Inductive TaskState : Type :=
  | Working : TaskState
  | InputRequired : TaskState
  | Completed : TaskState
  | Failed : TaskState
  | Cancelled : TaskState.

(** ** Terminal predicate *)

Definition is_terminal (s : TaskState) : bool :=
  match s with
  | Completed => true
  | Failed => true
  | Cancelled => true
  | _ => false
  end.

(** ** Valid transitions *)

(** Allowed state transitions per MCP 2025-11-25 spec. *)
Definition valid_transition (from to : TaskState) : bool :=
  match from, to with
  | Working, InputRequired => true
  | Working, Completed => true
  | Working, Failed => true
  | Working, Cancelled => true
  | InputRequired, Working => true
  | InputRequired, Failed => true
  | InputRequired, Cancelled => true
  (* Terminal states: no transitions out *)
  | Completed, _ => false
  | Failed, _ => false
  | Cancelled, _ => false
  (* Invalid transitions *)
  | _, _ => false
  end.

(** ** Transition function (fail-closed) *)

Definition transition (from to : TaskState) : option TaskState :=
  if valid_transition from to then Some to else None.

(** ** T1: Terminal Absorbing *)

(** Once a task reaches a terminal state, it cannot transition to
    any other state. Terminal states are absorbing in the state machine. *)
Theorem t1_terminal_absorbing :
  forall (s : TaskState) (s' : TaskState),
    is_terminal s = true ->
    valid_transition s s' = false.
Proof.
  intros s s' Hterm.
  destruct s; simpl in Hterm; try discriminate;
  destruct s'; reflexivity.
Qed.

(** Terminal states have no valid successor. *)
Theorem t1_terminal_no_successor :
  forall (s s' : TaskState),
    is_terminal s = true ->
    transition s s' = None.
Proof.
  intros s s' Hterm.
  unfold transition.
  rewrite t1_terminal_absorbing; [reflexivity | exact Hterm].
Qed.

(** ** T2: Initial State *)

(** Tasks can only begin in Working (policy allowed) or Failed
    (policy denied). *)
Definition is_valid_initial (s : TaskState) : bool :=
  match s with
  | Working => true
  | Failed => true
  | _ => false
  end.

(** Working is a valid initial state. *)
Theorem t2_working_is_initial :
  is_valid_initial Working = true.
Proof. reflexivity. Qed.

(** Failed is a valid initial state (denied by policy). *)
Theorem t2_failed_is_initial :
  is_valid_initial Failed = true.
Proof. reflexivity. Qed.

(** Non-initial states are not valid starting points. *)
Theorem t2_only_working_or_failed :
  forall s, is_valid_initial s = true -> s = Working \/ s = Failed.
Proof.
  intros s H.
  destruct s; simpl in H; try discriminate.
  - left. reflexivity.
  - right. reflexivity.
Qed.

(** ** T3: Valid Transitions Only *)

(** Working can reach all other states. *)
Theorem t3_working_transitions :
  valid_transition Working InputRequired = true /\
  valid_transition Working Completed = true /\
  valid_transition Working Failed = true /\
  valid_transition Working Cancelled = true.
Proof.
  split; [| split; [| split]]; reflexivity.
Qed.

(** InputRequired can go back to Working or to terminal states. *)
Theorem t3_input_required_transitions :
  valid_transition InputRequired Working = true /\
  valid_transition InputRequired Failed = true /\
  valid_transition InputRequired Cancelled = true.
Proof.
  split; [| split]; reflexivity.
Qed.

(** InputRequired cannot go directly to Completed. *)
Theorem t3_input_required_no_direct_complete :
  valid_transition InputRequired Completed = false.
Proof. reflexivity. Qed.

(** ** Additional: Transition Determinism *)

(** The transition function is deterministic: same input always
    produces the same output. This is trivially true since
    [valid_transition] is a pure function, but we make it explicit. *)
Theorem transition_deterministic :
  forall s1 s2 : TaskState,
    transition s1 s2 = transition s1 s2.
Proof. reflexivity. Qed.

(** ** Additional: Terminal is Irreversible *)

(** If a state is terminal, it remains terminal under any hypothetical
    transition (which will fail, returning None). *)
Theorem terminal_irreversible :
  forall (s : TaskState),
    is_terminal s = true ->
    forall s', transition s s' = None.
Proof.
  exact t1_terminal_no_successor.
Qed.
