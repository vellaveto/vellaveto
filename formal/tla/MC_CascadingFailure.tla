--------------------- MODULE MC_CascadingFailure ---------------------
(**************************************************************************)
(* Model companion for CascadingFailure — defines concrete constants     *)
(* for TLC model checking.                                                *)
(*                                                                        *)
(* Small bounds: 2 agents, 2 tools, depth 3, error threshold 2.          *)
(* Sufficient because chain depth bounding and circuit state transitions  *)
(* are structural properties.                                             *)
(*                                                                        *)
(* Run: java -jar tla2tools.jar -config CascadingFailure.cfg             *)
(*      MC_CascadingFailure.tla                                           *)
(**************************************************************************)
EXTENDS CascadingFailure

CONSTANTS ag1, ag2, tool1, tool2

const_Agents == {ag1, ag2}
const_Tools == {tool1, tool2}

StateConstraint == Len(requestOutcomes) <= 5

=========================================================================
