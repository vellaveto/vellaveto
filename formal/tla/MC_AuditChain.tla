---------------------- MODULE MC_AuditChain ----------------------
(**************************************************************************)
(* Model companion for AuditChain.tla                                     *)
(*                                                                        *)
(* Provides concrete constant values for TLC model checking.              *)
(* 4 entries × 3 IDs × 4 hashes is sufficient because:                   *)
(*   - Chain linkage is pairwise (entry[n] references entry[n-1])         *)
(*   - Sequence monotonicity is pairwise                                  *)
(*   - Hash uniqueness needs |HashValues| ≥ MaxEntries                    *)
(*   - Rotation continuity needs ≥ 1 rotation                             *)
(**************************************************************************)
EXTENDS AuditChain

const_MaxEntries == 4
const_EntryIds == {"e1", "e2", "e3"}
const_HashValues == {"h1", "h2", "h3", "h4"}

=========================================================================
