--------------------- MODULE MC_MCPTaskLifecycle ---------------------
(**************************************************************************)
(* Model companion for MCPTaskLifecycle — defines concrete constants for  *)
(* TLC model checking.                                                    *)
(*                                                                        *)
(* Small bounds sufficient because:                                       *)
(*   - Terminal absorbing (T1) is a structural property                   *)
(*   - Bounded concurrency (T5) only requires MaxTasks+1 task IDs        *)
(*   - Input round bound (MaxInputRounds=2) exercises the cycle           *)
(*                                                                        *)
(* Run: java -jar tla2tools.jar -config MCPTaskLifecycle.cfg              *)
(*      MC_MCPTaskLifecycle.tla                                           *)
(**************************************************************************)
EXTENDS MCPTaskLifecycle

CONSTANTS tk1, tk2, tk3

const_TaskIds == {tk1, tk2, tk3}

=========================================================================
