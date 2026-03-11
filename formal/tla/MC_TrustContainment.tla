---- MODULE MC_TrustContainment ----
(**************************************************************************)
(* Model companion for TrustContainment.tla                               *)
(* Provides concrete edge-case requests for TLC model checking.           *)
(**************************************************************************)
EXTENDS TrustContainment

const_RequestSet ==
    {
        [
            source_tier             |-> "verified",
            sink_class              |-> "code_execution",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "medium",
            sink_class              |-> "network_egress",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "low",
            sink_class              |-> "credential_access",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "low",
            sink_class              |-> "credential_access",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> TRUE
        ],
        [
            source_tier             |-> "unknown",
            sink_class              |-> "memory_write",
            has_lineage             |-> FALSE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "quarantined",
            sink_class              |-> "policy_mutation",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "high",
            sink_class              |-> "approval_ui",
            has_lineage             |-> TRUE,
            explicitly_declassified |-> FALSE
        ],
        [
            source_tier             |-> "untrusted",
            sink_class              |-> "read_only",
            has_lineage             |-> FALSE,
            explicitly_declassified |-> FALSE
        ]
    }

=========================================================================
