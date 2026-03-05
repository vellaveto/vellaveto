-------------------- MODULE MC_CredentialVault --------------------
(**************************************************************************)
(* Model companion for CredentialVault.tla                                *)
(*                                                                        *)
(* Provides concrete constant values for TLC model checking.              *)
(* 3 credentials × 2 sessions × 3 epochs is sufficient because:          *)
(*   - State machine properties are per-credential (pairwise)             *)
(*   - Binding uniqueness needs ≥ 2 sessions                              *)
(*   - Epoch monotonicity needs ≥ 2 distinct epochs                       *)
(*   - Capacity bound needs ≥ MaxVaultEntries credentials                 *)
(**************************************************************************)
EXTENDS CredentialVault

const_CredentialIds == {"c1", "c2", "c3"}
const_SessionIds == {"s1", "s2"}
const_MaxEpoch == 3
const_MaxVaultEntries == 3

=========================================================================
