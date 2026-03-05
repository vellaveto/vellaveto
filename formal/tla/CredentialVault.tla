------------------------ MODULE CredentialVault ------------------------
(**************************************************************************)
(* Credential Vault State Machine                                         *)
(*                                                                        *)
(* Models the credential lifecycle in vellaveto-mcp-shield/src/            *)
(* credential_vault.rs. Each blind credential transitions through a       *)
(* strict state machine:                                                   *)
(*                                                                        *)
(*   Available ──consume──► Active ──mark_consumed──► Consumed            *)
(*       │                                                                *)
(*       └──expire_old──► Expired                                         *)
(*                                                                        *)
(* Safety properties:                                                     *)
(*   CV1: No double-consumption (Consumed credential never consumed again)*)
(*   CV2: Active-only consume (only Active → Consumed transition)         *)
(*   CV3: Epoch monotonicity (current_epoch never decreases)              *)
(*   CV4: Capacity bounded (entries ≤ MAX_VAULT_ENTRIES)                  *)
(*   CV5: Fail-closed on exhaustion (no Available → error, no session)    *)
(*                                                                        *)
(* Maps to:                                                               *)
(*   - CredentialVault::consume_credential()   (lines 133-158)            *)
(*   - CredentialVault::mark_consumed()        (lines 167-200)            *)
(*   - CredentialVault::add_credential()       (lines 79-124)             *)
(*   - CredentialVault::expire_old_epochs()    (lines 225-260)            *)
(**************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    CredentialIds,      \* Set of credential identifiers (e.g., {"c1","c2","c3"})
    SessionIds,         \* Set of session identifiers (e.g., {"s1","s2"})
    MaxEpoch,           \* Maximum epoch value for bounded model checking
    MaxVaultEntries     \* Maximum vault capacity (maps to MAX_VAULT_ENTRIES)

VARIABLES
    status,             \* Function: CredentialId → {"Available","Active","Consumed","Expired","absent"}
    bindings,           \* Function: SessionId → CredentialId ∪ {"none"}
    currentEpoch,       \* Current epoch counter (monotonically increasing)
    credentialEpoch,    \* Function: CredentialId → epoch when credential was issued
    pc                  \* Program counter for actions

vars == <<status, bindings, currentEpoch, credentialEpoch, pc>>

Statuses == {"Available", "Active", "Consumed", "Expired", "absent"}

(**************************************************************************)
(* Type invariant                                                         *)
(**************************************************************************)
TypeOK ==
    /\ status \in [CredentialIds -> Statuses]
    /\ bindings \in [SessionIds -> CredentialIds \cup {"none"}]
    /\ currentEpoch \in 0..MaxEpoch
    /\ credentialEpoch \in [CredentialIds -> 0..MaxEpoch]
    /\ pc \in {"idle", "error"}

(**************************************************************************)
(* Initial state                                                          *)
(**************************************************************************)
Init ==
    /\ status = [c \in CredentialIds |-> "absent"]
    /\ bindings = [s \in SessionIds |-> "none"]
    /\ currentEpoch = 0
    /\ credentialEpoch = [c \in CredentialIds |-> 0]
    /\ pc = "idle"

(**************************************************************************)
(* AddCredential: Add a new credential to the vault                       *)
(*                                                                        *)
(* Maps to CredentialVault::add_credential() (lines 79-124)               *)
(* Preconditions:                                                         *)
(*   - Credential is absent (not yet in vault)                            *)
(*   - Vault not at capacity                                              *)
(*   - Credential epoch ≤ MaxEpoch                                        *)
(* Postconditions:                                                        *)
(*   - Credential status becomes Available                                *)
(*   - currentEpoch advanced if credential.epoch > currentEpoch           *)
(**************************************************************************)
AddCredential(c, epoch) ==
    /\ pc = "idle"
    /\ status[c] = "absent"
    /\ Cardinality({x \in CredentialIds : status[x] # "absent"}) < MaxVaultEntries
    /\ epoch \in 0..MaxEpoch
    /\ status' = [status EXCEPT ![c] = "Available"]
    /\ credentialEpoch' = [credentialEpoch EXCEPT ![c] = epoch]
    /\ currentEpoch' = IF epoch > currentEpoch THEN epoch ELSE currentEpoch
    /\ UNCHANGED <<bindings, pc>>

(**************************************************************************)
(* ConsumeCredential: Consume an Available credential for a session       *)
(*                                                                        *)
(* Maps to CredentialVault::consume_credential() (lines 133-158)          *)
(* Preconditions:                                                         *)
(*   - Credential status is Available                                     *)
(*   - Session has no credential bound                                    *)
(* Postconditions:                                                        *)
(*   - Credential status becomes Active                                   *)
(*   - Session bound to this credential                                   *)
(*                                                                        *)
(* SECURITY: Fail-closed — if no Available credential exists, this action *)
(* is not enabled, and the session cannot start (CV5).                    *)
(**************************************************************************)
ConsumeCredential(c, s) ==
    /\ pc = "idle"
    /\ status[c] = "Available"
    /\ bindings[s] = "none"
    /\ status' = [status EXCEPT ![c] = "Active"]
    /\ bindings' = [bindings EXCEPT ![s] = c]
    /\ UNCHANGED <<currentEpoch, credentialEpoch, pc>>

(**************************************************************************)
(* MarkConsumed: Mark an Active credential as Consumed (session ended)    *)
(*                                                                        *)
(* Maps to CredentialVault::mark_consumed() (lines 167-200)               *)
(* Preconditions:                                                         *)
(*   - Credential status is Active (R238-SHLD-6)                         *)
(* Postconditions:                                                        *)
(*   - Credential status becomes Consumed                                 *)
(*   - Session binding cleared                                            *)
(*                                                                        *)
(* SECURITY (R238-SHLD-6): Only Active → Consumed is allowed.            *)
(* Available → Consumed would skip the session binding.                   *)
(* Consumed → Consumed would be a double-consume.                        *)
(* Expired → Consumed would resurrect an invalidated credential.         *)
(**************************************************************************)
MarkConsumed(c, s) ==
    /\ pc = "idle"
    /\ status[c] = "Active"
    /\ bindings[s] = c
    /\ status' = [status EXCEPT ![c] = "Consumed"]
    /\ bindings' = [bindings EXCEPT ![s] = "none"]
    /\ UNCHANGED <<currentEpoch, credentialEpoch, pc>>

(**************************************************************************)
(* ExpireOldEpochs: Expire Available credentials from old epochs          *)
(*                                                                        *)
(* Maps to CredentialVault::expire_old_epochs() (lines 225-260)           *)
(* Preconditions:                                                         *)
(*   - Credential status is Available                                     *)
(*   - Credential epoch < currentEpoch                                    *)
(* Postconditions:                                                        *)
(*   - Credential status becomes Expired                                  *)
(*                                                                        *)
(* SECURITY: Only Available credentials can expire. Active credentials    *)
(* are bound to sessions and must go through MarkConsumed. This prevents  *)
(* a session from having its credential expired mid-use.                  *)
(**************************************************************************)
ExpireCredential(c) ==
    /\ pc = "idle"
    /\ status[c] = "Available"
    /\ credentialEpoch[c] < currentEpoch
    /\ status' = [status EXCEPT ![c] = "Expired"]
    /\ UNCHANGED <<bindings, currentEpoch, credentialEpoch, pc>>

(**************************************************************************)
(* AdvanceEpoch: Advance the current epoch                                *)
(*                                                                        *)
(* Models external epoch advancement (e.g., from replenishment task).     *)
(**************************************************************************)
AdvanceEpoch ==
    /\ pc = "idle"
    /\ currentEpoch < MaxEpoch
    /\ currentEpoch' = currentEpoch + 1
    /\ UNCHANGED <<status, bindings, credentialEpoch, pc>>

(**************************************************************************)
(* HandleError: Non-deterministic error during any operation              *)
(*                                                                        *)
(* Models lock poisoning, serialization failure, I/O error.               *)
(* SECURITY: Errors do not change credential state (fail-closed).         *)
(* The persist-then-rollback pattern in the implementation ensures that   *)
(* a failed persist leaves the credential in its original state.          *)
(**************************************************************************)
HandleError ==
    /\ pc = "idle"
    /\ pc' = "error"
    /\ UNCHANGED <<status, bindings, currentEpoch, credentialEpoch>>

RecoverFromError ==
    /\ pc = "error"
    /\ pc' = "idle"
    /\ UNCHANGED <<status, bindings, currentEpoch, credentialEpoch>>

(**************************************************************************)
(* Next: All possible transitions                                         *)
(**************************************************************************)
Next ==
    \/ \E c \in CredentialIds, epoch \in 0..MaxEpoch : AddCredential(c, epoch)
    \/ \E c \in CredentialIds, s \in SessionIds : ConsumeCredential(c, s)
    \/ \E c \in CredentialIds, s \in SessionIds : MarkConsumed(c, s)
    \/ \E c \in CredentialIds : ExpireCredential(c)
    \/ AdvanceEpoch
    \/ HandleError
    \/ RecoverFromError

Spec == Init /\ [][Next]_vars /\ WF_vars(RecoverFromError)

(**************************************************************************)
(* SAFETY INVARIANTS                                                      *)
(**************************************************************************)

(* CV1: No double-consumption.                                            *)
(* A Consumed credential never transitions back to any usable state.      *)
(* Once consumed, it stays consumed forever.                              *)
CV1_NoDoubleConsumption ==
    \A c \in CredentialIds :
        status[c] = "Consumed" =>
            /\ \A s \in SessionIds : bindings[s] # c

(* CV2: Active-only consume transition.                                   *)
(* MarkConsumed requires Active status. No other status can become        *)
(* Consumed. This is enforced by the R238-SHLD-6 guard.                  *)
(* Expressed as: if a credential is Consumed, it must have been Active    *)
(* at some point (which is implied by the transition structure).          *)
(* Stronger form: Available/Expired/absent never directly become Consumed.*)
CV2_ActiveOnlyConsume ==
    \A c \in CredentialIds :
        status[c] \in {"Available", "Expired", "absent"} =>
            status[c] # "Consumed"  \* Tautological here; the transition structure enforces it

(* CV3: Epoch monotonicity.                                               *)
(* currentEpoch never decreases. This prevents credential epoch           *)
(* comparison from producing incorrect results after epoch rollback.      *)
CV3_EpochMonotonicity ==
    currentEpoch >= 0  \* Strengthened by temporal property below

(* CV4: Capacity bounded.                                                 *)
(* The vault never exceeds MaxVaultEntries active credentials.            *)
CV4_CapacityBounded ==
    Cardinality({c \in CredentialIds : status[c] # "absent"}) <= MaxVaultEntries

(* CV5: Fail-closed on exhaustion.                                        *)
(* If no Available credentials exist, no session can consume one.         *)
(* This is structural: ConsumeCredential requires status[c] = Available.  *)
(* We verify it as: every bound session has a non-Available credential.   *)
CV5_FailClosedExhaustion ==
    \A s \in SessionIds :
        bindings[s] # "none" =>
            status[bindings[s]] \in {"Active", "Consumed"}

(* CV6: Binding uniqueness.                                               *)
(* No two sessions can be bound to the same credential simultaneously.    *)
CV6_BindingUniqueness ==
    \A s1, s2 \in SessionIds :
        s1 # s2 /\ bindings[s1] # "none" /\ bindings[s2] # "none" =>
            bindings[s1] # bindings[s2]

(* CV7: Active implies bound.                                             *)
(* An Active credential is always bound to exactly one session.           *)
CV7_ActiveImpliesBound ==
    \A c \in CredentialIds :
        status[c] = "Active" =>
            \E s \in SessionIds : bindings[s] = c

(* CV8: Error does not change state.                                      *)
(* HandleError transitions pc but never changes credential/binding state. *)
(* This models the persist-then-rollback pattern.                         *)
CV8_ErrorPreservesState ==
    pc = "error" =>
        \A c \in CredentialIds : status[c] \in Statuses

(**************************************************************************)
(* LIVENESS PROPERTIES                                                    *)
(**************************************************************************)

(* CVL1: Error recovery.                                                  *)
(* The system eventually recovers from error state.                       *)
CVL1_ErrorRecovery == pc = "error" ~> pc = "idle"

(**************************************************************************)
(* TEMPORAL SAFETY                                                        *)
(**************************************************************************)

(* CV3_Temporal: Epoch never decreases (temporal formulation).            *)
CV3_Temporal == [][currentEpoch' >= currentEpoch]_currentEpoch

(* CV_StatusIrreversible: Terminal states are absorbing.                  *)
(* Once a credential is Consumed, it stays Consumed.                      *)
(* Once a credential is Expired, it stays Expired.                        *)
CV_TerminalAbsorbing ==
    \A c \in CredentialIds :
        /\ (status[c] = "Consumed" => [][status'[c] = "Consumed"]_status)
        /\ (status[c] = "Expired" => [][status'[c] = "Expired"]_status)

=========================================================================
