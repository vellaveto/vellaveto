---- MODULE MC_CapabilityDelegation ----
(**************************************************************************)
(* Model companion for CapabilityDelegation.tla                           *)
(* Provides concrete constants for TLC model checking.                    *)
(**************************************************************************)
EXTENDS CapabilityDelegation

const_Principals == {"alice", "bob", "charlie"}

const_MaxDepth == 3

const_MaxTokens == 6

const_TimeValues == {1, 2, 3, 4}

=========================================================================
