#!/usr/bin/env bash
#
# check-verus-parity.sh — Verify Verus proof targets still align with production
#
# Usage: bash formal/tools/check-verus-parity.sh
# Exit code: 0 = all checks passed, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRIFT_FOUND=0
VERUS_MANIFEST="$PROJECT_DIR/formal/verus/Cargo.toml"
VERUS_LIB="$PROJECT_DIR/formal/verus/src/lib.rs"

fail() {
    echo "  DRIFT: $1"
    DRIFT_FOUND=1
}

pass() {
    echo "  OK: $1"
}

check_file_pair() {
    local label="$1"
    local prod_file="$2"
    local verus_file="$3"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    pass "$label"
}

check_symbol_parity() {
    local label="$1"
    local prod_file="$2"
    local prod_pattern="$3"
    local verus_file="$4"
    local verus_pattern="$5"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    if ! grep -Eq "$prod_pattern" "$prod_file" 2>/dev/null; then
        fail "$label — production pattern '$prod_pattern' not found in $prod_file"
        return
    fi
    if ! grep -Eq "$verus_pattern" "$verus_file" 2>/dev/null; then
        fail "$label — verus pattern '$verus_pattern' not found in $verus_file"
        return
    fi

    pass "$label"
}

echo "=== Verus Proof Target Parity Check ==="
echo ""

PROD_CORE="$PROJECT_DIR/vellaveto-engine/src/verified_core.rs"
VERUS_CORE="$PROJECT_DIR/formal/verus/verified_core.rs"
PROD_CAPABILITY_CONTEXT="$PROJECT_DIR/vellaveto-engine/src/verified_capability_context.rs"
PROD_CONTEXT_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/context_check.rs"
VERUS_CAPABILITY_CONTEXT="$PROJECT_DIR/formal/verus/verified_capability_context.rs"
PROD_BRIDGE_PRINCIPAL="$PROJECT_DIR/vellaveto-mcp/src/verified_bridge_principal.rs"
PROD_RELAY_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/proxy/bridge/relay.rs"
VERUS_BRIDGE_PRINCIPAL="$PROJECT_DIR/formal/verus/verified_bridge_principal.rs"
PROD_CONSTRAINT="$PROJECT_DIR/vellaveto-engine/src/verified_constraint_eval.rs"
PROD_CONSTRAINT_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/constraint_eval.rs"
VERUS_CONSTRAINT="$PROJECT_DIR/formal/verus/verified_constraint_eval.rs"
PROD_DEPUTY="$PROJECT_DIR/vellaveto-engine/src/verified_deputy.rs"
PROD_DEPUTY_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/deputy.rs"
VERUS_DEPUTY="$PROJECT_DIR/formal/verus/verified_deputy.rs"
PROD_AUDIT_APPEND="$PROJECT_DIR/vellaveto-audit/src/verified_audit_append.rs"
PROD_AUDIT_CHAIN="$PROJECT_DIR/vellaveto-audit/src/verified_audit_chain.rs"
PROD_AUDIT_APPEND_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/logger.rs"
PROD_AUDIT_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/verification.rs"
PROD_AUDIT_RECOVERY_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/rotation.rs"
PROD_MERKLE="$PROJECT_DIR/vellaveto-audit/src/verified_merkle.rs"
PROD_MERKLE_FOLD="$PROJECT_DIR/vellaveto-audit/src/verified_merkle_fold.rs"
PROD_MERKLE_PATH="$PROJECT_DIR/vellaveto-audit/src/verified_merkle_path.rs"
PROD_MERKLE_WRAPPER="$PROJECT_DIR/vellaveto-audit/src/merkle.rs"
PROD_ROTATION_MANIFEST="$PROJECT_DIR/vellaveto-audit/src/verified_rotation_manifest.rs"
PROD_CAPABILITY_ATTENUATION="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_attenuation.rs"
PROD_CAPABILITY_GLOB="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_glob.rs"
PROD_CAPABILITY_GLOB_SUBSET="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_glob_subset.rs"
PROD_CAPABILITY_GRANT="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_grant.rs"
PROD_CAPABILITY_IDENTITY="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_identity.rs"
PROD_CAPABILITY_LITERAL="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_literal.rs"
PROD_CAPABILITY_PATTERN="$PROJECT_DIR/vellaveto-mcp/src/verified_capability_pattern.rs"
PROD_CAPABILITY_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/capability_token.rs"
PROD_NHI="$PROJECT_DIR/vellaveto-mcp/src/verified_nhi_delegation.rs"
PROD_NHI_GRAPH="$PROJECT_DIR/vellaveto-mcp/src/verified_nhi_graph.rs"
PROD_NHI_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/nhi.rs"
VERUS_AUDIT_CHAIN="$PROJECT_DIR/formal/verus/verified_audit_chain.rs"
VERUS_AUDIT_APPEND="$PROJECT_DIR/formal/verus/verified_audit_append.rs"
VERUS_MERKLE="$PROJECT_DIR/formal/verus/verified_merkle.rs"
VERUS_MERKLE_FOLD="$PROJECT_DIR/formal/verus/verified_merkle_fold.rs"
VERUS_MERKLE_PATH="$PROJECT_DIR/formal/verus/verified_merkle_path.rs"
VERUS_ROTATION_MANIFEST="$PROJECT_DIR/formal/verus/verified_rotation_manifest.rs"
VERUS_CAPABILITY_ATTENUATION="$PROJECT_DIR/formal/verus/verified_capability_attenuation.rs"
VERUS_CAPABILITY_GLOB="$PROJECT_DIR/formal/verus/verified_capability_glob.rs"
VERUS_CAPABILITY_GLOB_SUBSET="$PROJECT_DIR/formal/verus/verified_capability_glob_subset.rs"
VERUS_CAPABILITY_GRANT="$PROJECT_DIR/formal/verus/verified_capability_grant.rs"
VERUS_CAPABILITY_IDENTITY="$PROJECT_DIR/formal/verus/verified_capability_identity.rs"
VERUS_CAPABILITY_LITERAL="$PROJECT_DIR/formal/verus/verified_capability_literal.rs"
VERUS_CAPABILITY_PATTERN="$PROJECT_DIR/formal/verus/verified_capability_pattern.rs"
VERUS_NHI="$PROJECT_DIR/formal/verus/verified_nhi_delegation.rs"
VERUS_NHI_GRAPH="$PROJECT_DIR/formal/verus/verified_nhi_graph.rs"
PROD_ENTROPY="$PROJECT_DIR/vellaveto-engine/src/verified_entropy_gate.rs"
PROD_ENTROPY_WRAPPER="$PROJECT_DIR/vellaveto-engine/src/entropy_gate.rs"
VERUS_ENTROPY="$PROJECT_DIR/formal/verus/verified_entropy_gate.rs"
PROD_CROSS_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs"
PROD_CROSS_DLP_WRAPPER="$PROJECT_DIR/vellaveto-mcp/src/inspection/cross_call_dlp.rs"
VERUS_CROSS_DLP="$PROJECT_DIR/formal/verus/verified_cross_call_dlp.rs"
PROD_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs"
VERUS_DLP="$PROJECT_DIR/formal/verus/verified_dlp_core.rs"
PROD_PATH="$PROJECT_DIR/vellaveto-engine/src/path.rs"
VERUS_PATH="$PROJECT_DIR/formal/verus/verified_path.rs"

echo "--- Cargo Verus Entrypoint ---"
check_file_pair \
    "formal/verus/Cargo.toml ↔ formal/verus/src/lib.rs" \
    "$VERUS_MANIFEST" \
    "$VERUS_LIB"
check_symbol_parity \
    "Verus manifest pins the expected vstd crate version" \
    "$VERUS_MANIFEST" \
    'vstd[[:space:]]*=[[:space:]]*"=0\.0\.0-2026-03-01-0109"' \
    "$VERUS_LIB" \
    'verified_core\.rs'
for module in \
    verified_audit_append \
    verified_audit_chain \
    verified_merkle \
    verified_merkle_fold \
    verified_merkle_path \
    verified_rotation_manifest \
    verified_capability_attenuation \
    verified_bridge_principal \
    verified_capability_context \
    verified_capability_glob \
    verified_capability_glob_subset \
    verified_capability_grant \
    verified_capability_identity \
    verified_capability_literal \
    verified_capability_pattern \
    verified_constraint_eval \
    verified_cross_call_dlp \
    verified_core \
    verified_deputy \
    verified_entropy_gate \
    verified_nhi_delegation \
    verified_nhi_graph \
    verified_dlp_core \
    verified_path \
    verified_refinement_safety
do
    check_symbol_parity \
        "$module is wired into the cargo-verus shim" \
        "$VERUS_LIB" \
        "${module}\\.rs" \
        "$PROJECT_DIR/formal/verus/${module}.rs" \
        'verus!'
done
echo ""

echo "--- Core Verdict ---"
check_file_pair "verified_core.rs ↔ vellaveto-engine/src/verified_core.rs" "$PROD_CORE" "$VERUS_CORE"
check_symbol_parity \
    "compute_single_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict'
check_symbol_parity \
    "compute_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict'
echo ""

echo "--- Capability Context Kernel ---"
check_file_pair \
    "verified_capability_context.rs ↔ vellaveto-engine/src/verified_capability_context.rs" \
    "$PROD_CAPABILITY_CONTEXT" \
    "$VERUS_CAPABILITY_CONTEXT"
for fn in capability_holder_binding_valid capability_issuer_allowed capability_remaining_depth_sufficient; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_CONTEXT" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_CONTEXT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "require_capability_token uses verified holder-binding guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_holder_binding_valid' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_holder_binding_valid'
check_symbol_parity \
    "require_capability_token uses verified issuer-allowlist guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_issuer_allowed' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_issuer_allowed'
check_symbol_parity \
    "require_capability_token uses verified depth-threshold guard" \
    "$PROD_CONTEXT_WRAPPER" \
    'verified_capability_context::capability_remaining_depth_sufficient' \
    "$VERUS_CAPABILITY_CONTEXT" \
    'pub[[:space:]]+fn[[:space:]]+capability_remaining_depth_sufficient'
echo ""

echo "--- Bridge Principal Kernel ---"
check_file_pair \
    "verified_bridge_principal.rs ↔ vellaveto-mcp/src/verified_bridge_principal.rs" \
    "$PROD_BRIDGE_PRINCIPAL" \
    "$VERUS_BRIDGE_PRINCIPAL"
for fn in configured_claim_consistent deputy_principal_source evaluation_principal_source; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_BRIDGE_PRINCIPAL" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_BRIDGE_PRINCIPAL" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "relay uses verified configured-vs-claimed consistency guard" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::configured_claim_consistent' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+configured_claim_consistent'
check_symbol_parity \
    "relay uses verified deputy principal-source selector" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::deputy_principal_source' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+deputy_principal_source'
check_symbol_parity \
    "relay uses verified evaluation principal-source selector" \
    "$PROD_RELAY_WRAPPER" \
    'verified_bridge_principal::evaluation_principal_source' \
    "$VERUS_BRIDGE_PRINCIPAL" \
    'pub[[:space:]]+fn[[:space:]]+evaluation_principal_source'
echo ""

echo "--- Constraint Evaluation Kernel ---"
check_file_pair \
    "verified_constraint_eval.rs ↔ vellaveto-engine/src/verified_constraint_eval.rs" \
    "$PROD_CONSTRAINT" \
    "$VERUS_CONSTRAINT"
for fn in all_constraints_skipped has_forbidden_parameter conditional_verdict; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CONSTRAINT" \
        "pub[[:space:]]+(const[[:space:]]+)?fn[[:space:]]+$fn" \
        "$VERUS_CONSTRAINT" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "constraint wrapper uses verified all-skipped kernel" \
    "$PROD_CONSTRAINT_WRAPPER" \
    'verified_constraint_eval::all_constraints_skipped' \
    "$VERUS_CONSTRAINT" \
    'pub[[:space:]]+fn[[:space:]]+all_constraints_skipped'
check_symbol_parity \
    "constraint wrapper uses verified no-match kernel" \
    "$PROD_CONSTRAINT_WRAPPER" \
    'verified_constraint_eval::no_match_verdict' \
    "$VERUS_CONSTRAINT" \
    'pub[[:space:]]+fn[[:space:]]+no_match_verdict'
echo ""

echo "--- Deputy Delegation Kernel ---"
check_file_pair \
    "verified_deputy.rs ↔ vellaveto-engine/src/verified_deputy.rs" \
    "$PROD_DEPUTY" \
    "$VERUS_DEPUTY"
for fn in next_delegation_depth delegation_depth_within_limit redelegation_chain_principal_valid redelegation_tool_allowed delegated_principal_matches delegated_tool_allowed; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DEPUTY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DEPUTY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "deputy register_delegation uses verified depth increment" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::next_delegation_depth' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+next_delegation_depth'
check_symbol_parity \
    "deputy register_delegation uses verified depth-limit guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegation_depth_within_limit' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegation_depth_within_limit'
check_symbol_parity \
    "deputy register_delegation uses verified chain-principal guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::redelegation_chain_principal_valid' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+redelegation_chain_principal_valid'
check_symbol_parity \
    "deputy register_delegation uses verified child-tool scope guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::redelegation_tool_allowed' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+redelegation_tool_allowed'
check_symbol_parity \
    "deputy validate_action uses verified delegate-match guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegated_principal_matches' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_principal_matches'
check_symbol_parity \
    "deputy validate_action uses verified tool-allowance guard" \
    "$PROD_DEPUTY_WRAPPER" \
    'verified_deputy::delegated_tool_allowed' \
    "$VERUS_DEPUTY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_tool_allowed'
echo ""

echo "--- Audit Append Kernel ---"
check_file_pair \
    "verified_audit_append.rs ↔ vellaveto-audit/src/verified_audit_append.rs" \
    "$PROD_AUDIT_APPEND" \
    "$VERUS_AUDIT_APPEND"
for fn in entry_count_after_rotation assigned_sequence next_entry_count next_global_sequence next_sequence_after_recovery; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_AUDIT_APPEND" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_AUDIT_APPEND" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "audit logger uses verified rotation reset" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::entry_count_after_rotation' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+entry_count_after_rotation'
check_symbol_parity \
    "audit logger uses verified assigned sequence snapshot" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::assigned_sequence' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+assigned_sequence'
check_symbol_parity \
    "audit logger uses verified per-file counter increment" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::next_entry_count' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_entry_count'
check_symbol_parity \
    "audit logger uses verified global sequence increment" \
    "$PROD_AUDIT_APPEND_WRAPPER" \
    'verified_audit_append::next_global_sequence' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_global_sequence'
check_symbol_parity \
    "audit recovery uses verified next sequence after restart" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_audit_append::next_sequence_after_recovery' \
    "$VERUS_AUDIT_APPEND" \
    'pub[[:space:]]+fn[[:space:]]+next_sequence_after_recovery'
echo ""

echo "--- Audit Chain Kernel ---"
check_file_pair \
    "verified_audit_chain.rs ↔ vellaveto-audit/src/verified_audit_chain.rs" \
    "$PROD_AUDIT_CHAIN" \
    "$VERUS_AUDIT_CHAIN"
for fn in timestamp_guard sequence_monotonic hash_presence_valid audit_chain_step_valid next_seen_hashed_entry next_prev_sequence; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_AUDIT_CHAIN" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_AUDIT_CHAIN" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "audit verification uses verified timestamp guard" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::timestamp_guard' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+timestamp_guard'
check_symbol_parity \
    "audit verification uses verified sequence gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::sequence_monotonic' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+sequence_monotonic'
check_symbol_parity \
    "audit verification uses verified hash-presence gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::hash_presence_valid' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+hash_presence_valid'
check_symbol_parity \
    "audit verification uses verified step gate" \
    "$PROD_AUDIT_WRAPPER" \
    'verified_audit_chain::audit_chain_step_valid' \
    "$VERUS_AUDIT_CHAIN" \
    'pub[[:space:]]+fn[[:space:]]+audit_chain_step_valid'
echo ""

echo "--- Merkle Kernel ---"
check_file_pair \
    "verified_merkle.rs ↔ vellaveto-audit/src/verified_merkle.rs" \
    "$PROD_MERKLE" \
    "$VERUS_MERKLE"
for fn in append_allowed stored_leaf_count_valid proof_tree_size_valid proof_leaf_index_valid proof_sibling_count_valid sibling_hash_len_valid; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle append uses verified capacity gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::append_allowed' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+append_allowed'
check_symbol_parity \
    "merkle initialize uses verified stored-count gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::stored_leaf_count_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+stored_leaf_count_valid'
check_symbol_parity \
    "merkle proof verification uses verified sibling-count gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_sibling_count_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_sibling_count_valid'
check_symbol_parity \
    "merkle proof verification uses verified tree-size gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_tree_size_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_tree_size_valid'
check_symbol_parity \
    "merkle proof verification uses verified leaf-index gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::proof_leaf_index_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+proof_leaf_index_valid'
check_symbol_parity \
    "merkle proof verification uses verified sibling hash-length gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle::sibling_hash_len_valid' \
    "$VERUS_MERKLE" \
    'pub[[:space:]]+fn[[:space:]]+sibling_hash_len_valid'
echo ""

echo "--- Merkle Fold Kernel ---"
check_file_pair \
    "verified_merkle_fold.rs ↔ vellaveto-audit/src/verified_merkle_fold.rs" \
    "$PROD_MERKLE_FOLD" \
    "$VERUS_MERKLE_FOLD"
for fn in next_level_len next_level_hashes fold_proof_step fold_peak_into_root; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE_FOLD" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE_FOLD" \
        "pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle root uses verified peak-fold helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::fold_peak_into_root' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+fold_peak_into_root'
check_symbol_parity \
    "merkle level builder uses verified next-level helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::next_level_hashes' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+next_level_hashes'
check_symbol_parity \
    "merkle proof verification uses verified fold-step helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_fold::fold_proof_step' \
    "$VERUS_MERKLE_FOLD" \
    'pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+fold_proof_step'
echo ""

echo "--- Merkle Proof-Path Kernel ---"
check_file_pair \
    "verified_merkle_path.rs ↔ vellaveto-audit/src/verified_merkle_path.rs" \
    "$PROD_MERKLE_PATH" \
    "$VERUS_MERKLE_PATH"
for fn in proof_sibling_index proof_step_is_left proof_level_has_sibling proof_parent_index proof_step_places_sibling_left; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_MERKLE_PATH" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_MERKLE_PATH" \
        "pub([[:space:]]+open[[:space:]]+spec)?[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "merkle proof generation uses verified sibling-presence gate" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_level_has_sibling' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_level_has_sibling'
check_symbol_parity \
    "merkle proof generation uses verified sibling-index helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_sibling_index' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_sibling_index'
check_symbol_parity \
    "merkle proof generation uses verified direction helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_step_is_left' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_step_is_left'
check_symbol_parity \
    "merkle proof generation uses verified parent-index helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_parent_index' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_parent_index'
check_symbol_parity \
    "merkle proof verification uses verified concatenation-direction helper" \
    "$PROD_MERKLE_WRAPPER" \
    'verified_merkle_path::proof_step_places_sibling_left' \
    "$VERUS_MERKLE_PATH" \
    'pub[[:space:]]+fn[[:space:]]+proof_step_places_sibling_left'
echo ""

echo "--- Rotation Manifest Kernel ---"
check_file_pair \
    "verified_rotation_manifest.rs ↔ vellaveto-audit/src/verified_rotation_manifest.rs" \
    "$PROD_ROTATION_MANIFEST" \
    "$VERUS_ROTATION_MANIFEST"
for fn in rotation_start_hash_link_valid rotated_file_reference_valid missing_rotated_file_allowed; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_ROTATION_MANIFEST" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_ROTATION_MANIFEST" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "rotation verifier uses verified start-hash linkage guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::rotation_start_hash_link_valid' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+rotation_start_hash_link_valid'
check_symbol_parity \
    "rotation verifier uses verified rotated-file path guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::rotated_file_reference_valid' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+rotated_file_reference_valid'
check_symbol_parity \
    "rotation verifier uses verified prune-boundary guard" \
    "$PROD_AUDIT_RECOVERY_WRAPPER" \
    'verified_rotation_manifest::missing_rotated_file_allowed' \
    "$VERUS_ROTATION_MANIFEST" \
    'pub[[:space:]]+fn[[:space:]]+missing_rotated_file_allowed'
echo ""

echo "--- Capability Attenuation Kernel ---"
check_file_pair \
    "verified_capability_attenuation.rs ↔ vellaveto-mcp/src/verified_capability_attenuation.rs" \
    "$PROD_CAPABILITY_ATTENUATION" \
    "$VERUS_CAPABILITY_ATTENUATION"
for fn in attenuated_remaining_depth attenuated_expiry_epoch; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_ATTENUATION" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_ATTENUATION" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability attenuation uses verified depth gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_attenuation::attenuated_remaining_depth' \
    "$VERUS_CAPABILITY_ATTENUATION" \
    'pub[[:space:]]+fn[[:space:]]+attenuated_remaining_depth'
check_symbol_parity \
    "capability attenuation uses verified expiry gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_attenuation::attenuated_expiry_epoch' \
    "$VERUS_CAPABILITY_ATTENUATION" \
    'pub[[:space:]]+fn[[:space:]]+attenuated_expiry_epoch'
echo ""

echo "--- Capability Parent-Glob Kernel ---"
check_file_pair \
    "verified_capability_glob.rs ↔ vellaveto-mcp/src/verified_capability_glob.rs" \
    "$PROD_CAPABILITY_GLOB" \
    "$VERUS_CAPABILITY_GLOB"
for fn in ascii_fold_byte byte_eq_ignore_ascii_case literal_child_matches_parent_glob; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_GLOB" \
        "pub\\(crate\\)[[:space:]]+(const[[:space:]]+)?fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_GLOB" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability subset uses verified literal child glob matcher" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_glob::literal_child_matches_parent_glob' \
    "$VERUS_CAPABILITY_GLOB" \
    'pub[[:space:]]+fn[[:space:]]+literal_child_matches_parent_glob'
echo ""

echo "--- Capability Glob-Subset Kernel ---"
check_file_pair \
    "verified_capability_glob_subset.rs ↔ vellaveto-mcp/src/verified_capability_glob_subset.rs" \
    "$PROD_CAPABILITY_GLOB_SUBSET" \
    "$VERUS_CAPABILITY_GLOB_SUBSET"
for fn in glob_subset_accepting_counterexample glob_subset_fast_path representative_other_byte_needed; do
    check_symbol_parity \
        "$fn exists in the Verus subset-kernel model" \
        "$VERUS_CAPABILITY_GLOB_SUBSET" \
        "pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_GLOB_SUBSET" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability subset uses verified child-glob subset kernel" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_glob_subset::glob_pattern_subset' \
    "$VERUS_CAPABILITY_GLOB_SUBSET" \
    'pub[[:space:]]+fn[[:space:]]+glob_subset_fast_path'
echo ""

echo "--- Capability Grant Kernel ---"
check_file_pair \
    "verified_capability_grant.rs ↔ vellaveto-mcp/src/verified_capability_grant.rs" \
    "$PROD_CAPABILITY_GRANT" \
    "$VERUS_CAPABILITY_GRANT"
check_symbol_parity \
    "grant_restrictions_attenuated exists in production and Verus" \
    "$PROD_CAPABILITY_GRANT" \
    'pub\(crate\)[[:space:]]+const[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated' \
    "$VERUS_CAPABILITY_GRANT" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated'
check_symbol_parity \
    "capability grant subset uses verified restriction gate" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_grant::grant_restrictions_attenuated' \
    "$VERUS_CAPABILITY_GRANT" \
    'pub[[:space:]]+fn[[:space:]]+grant_restrictions_attenuated'
echo ""

echo "--- Capability Identity Kernel ---"
check_file_pair \
    "verified_capability_identity.rs ↔ vellaveto-mcp/src/verified_capability_identity.rs" \
    "$PROD_CAPABILITY_IDENTITY" \
    "$VERUS_CAPABILITY_IDENTITY"
for fn in delegation_holder_distinct delegated_child_issuer_valid holder_expectation_satisfied; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_IDENTITY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_IDENTITY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability attenuation uses verified holder-distinct guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::delegation_holder_distinct' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+delegation_holder_distinct'
check_symbol_parity \
    "capability attenuation uses verified issuer-link guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::delegated_child_issuer_valid' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+delegated_child_issuer_valid'
check_symbol_parity \
    "capability verification uses verified holder-expectation guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_identity::holder_expectation_satisfied' \
    "$VERUS_CAPABILITY_IDENTITY" \
    'pub[[:space:]]+fn[[:space:]]+holder_expectation_satisfied'
echo ""

echo "--- Capability Literal Kernel ---"
check_file_pair \
    "verified_capability_literal.rs ↔ vellaveto-mcp/src/verified_capability_literal.rs" \
    "$PROD_CAPABILITY_LITERAL" \
    "$VERUS_CAPABILITY_LITERAL"
for fn in literal_pattern_matches literal_child_pattern_subset; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_LITERAL" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_LITERAL" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability literal matcher uses verified literal fast path" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_literal::literal_pattern_matches' \
    "$VERUS_CAPABILITY_LITERAL" \
    'pub[[:space:]]+fn[[:space:]]+literal_pattern_matches'
check_symbol_parity \
    "capability subset uses verified literal child branch" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_literal::literal_child_pattern_subset' \
    "$VERUS_CAPABILITY_LITERAL" \
    'pub[[:space:]]+fn[[:space:]]+literal_child_pattern_subset'
echo ""

echo "--- Capability Pattern Kernel ---"
check_file_pair \
    "verified_capability_pattern.rs ↔ vellaveto-mcp/src/verified_capability_pattern.rs" \
    "$PROD_CAPABILITY_PATTERN" \
    "$VERUS_CAPABILITY_PATTERN"
for fn in has_glob_metacharacters pattern_subset_guard; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CAPABILITY_PATTERN" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CAPABILITY_PATTERN" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "capability pattern subset uses verified guard" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_pattern::pattern_subset_guard' \
    "$VERUS_CAPABILITY_PATTERN" \
    'pub[[:space:]]+fn[[:space:]]+pattern_subset_guard'
check_symbol_parity \
    "capability pattern subset uses verified metacharacter detector" \
    "$PROD_CAPABILITY_WRAPPER" \
    'verified_capability_pattern::has_glob_metacharacters' \
    "$VERUS_CAPABILITY_PATTERN" \
    'pub[[:space:]]+fn[[:space:]]+has_glob_metacharacters'
echo ""

echo "--- Entropy Alert Gate ---"
check_file_pair \
    "verified_entropy_gate.rs ↔ vellaveto-engine/src/verified_entropy_gate.rs" \
    "$PROD_ENTROPY" \
    "$VERUS_ENTROPY"
for fn in is_high_entropy_millibits should_alert_on_high_entropy_count high_severity_entropy_threshold entropy_alert_level entropy_alert_severity; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_ENTROPY" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_ENTROPY" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "entropy wrapper uses verified fixed-point comparator" \
    "$PROD_ENTROPY_WRAPPER" \
    'pub\(crate\)[[:space:]]+use[[:space:]]+crate::verified_entropy_gate::' \
    "$VERUS_ENTROPY" \
    'pub[[:space:]]+fn[[:space:]]+is_high_entropy_millibits'
echo ""

echo "--- NHI Delegation Kernel ---"
check_file_pair \
    "verified_nhi_delegation.rs ↔ vellaveto-mcp/src/verified_nhi_delegation.rs" \
    "$PROD_NHI" \
    "$VERUS_NHI"
for fn in identity_is_terminal delegation_participant_allowed delegation_link_effective_for_chain delegation_chain_depth_exceeded; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_NHI" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_NHI" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "NHI is_terminal uses verified terminal-state guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::identity_is_terminal' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+identity_is_terminal'
check_symbol_parity \
    "NHI create_delegation uses verified participant guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_participant_allowed' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_participant_allowed'
check_symbol_parity \
    "NHI resolve_delegation_chain uses verified link-effective guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_link_effective_for_chain' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_link_effective_for_chain'
check_symbol_parity \
    "NHI resolve_delegation_chain uses verified depth-exceeded guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_delegation::delegation_chain_depth_exceeded' \
    "$VERUS_NHI" \
    'pub[[:space:]]+fn[[:space:]]+delegation_chain_depth_exceeded'
echo ""

echo "--- NHI Delegation Graph Kernel ---"
check_file_pair \
    "verified_nhi_graph.rs ↔ vellaveto-mcp/src/verified_nhi_graph.rs" \
    "$PROD_NHI_GRAPH" \
    "$VERUS_NHI_GRAPH"
for fn in delegation_link_effective_for_successor delegation_edge_preserves_acyclicity; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_NHI_GRAPH" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_NHI_GRAPH" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "NHI create_delegation uses verified successor-link guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_graph::delegation_link_effective_for_successor' \
    "$VERUS_NHI_GRAPH" \
    'pub[[:space:]]+fn[[:space:]]+delegation_link_effective_for_successor'
check_symbol_parity \
    "NHI create_delegation uses verified cycle-preservation guard" \
    "$PROD_NHI_WRAPPER" \
    'verified_nhi_graph::delegation_edge_preserves_acyclicity' \
    "$VERUS_NHI_GRAPH" \
    'pub[[:space:]]+fn[[:space:]]+delegation_edge_preserves_acyclicity'
echo ""

echo "--- Cross-Call DLP Tracker Gate ---"
check_file_pair \
    "verified_cross_call_dlp.rs ↔ vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs" \
    "$PROD_CROSS_DLP" \
    "$VERUS_CROSS_DLP"
for fn in should_emit_capacity_exhausted_finding should_update_buffer; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_CROSS_DLP" \
        "pub\\(crate\\)[[:space:]]+const[[:space:]]+fn[[:space:]]+$fn|pub\\(crate\\)[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_CROSS_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
check_symbol_parity \
    "cross-call tracker uses verified capacity finding gate" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'verified_cross_call_dlp::should_emit_capacity_exhausted_finding' \
    "$VERUS_CROSS_DLP" \
    'pub[[:space:]]+fn[[:space:]]+should_emit_capacity_exhausted_finding'
check_symbol_parity \
    "cross-call tracker uses verified update gate" \
    "$PROD_CROSS_DLP_WRAPPER" \
    'verified_cross_call_dlp::should_update_buffer' \
    "$VERUS_CROSS_DLP" \
    'pub[[:space:]]+fn[[:space:]]+should_update_buffer'
echo ""

echo "--- DLP Buffer Core ---"
check_file_pair "verified_dlp_core.rs ↔ vellaveto-mcp/src/inspection/verified_dlp_core.rs" "$PROD_DLP" "$VERUS_DLP"
for fn in is_utf8_char_boundary extract_tail can_track_field update_total_bytes; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
echo ""

echo "--- Path Normalization Kernel ---"
check_file_pair "verified_path.rs ↔ vellaveto-engine/src/path.rs" "$PROD_PATH" "$VERUS_PATH"
check_symbol_parity \
    "production engine path normalization kernel exists" \
    "$PROD_PATH" \
    'pub(\(crate\))?[[:space:]]+fn[[:space:]]+normalize_decoded_path' \
    "$VERUS_PATH" \
    'pub[[:space:]]+fn[[:space:]]+normalize_path_bytes'
check_symbol_parity \
    "engine path wrapper calls the verified kernel boundary" \
    "$PROD_PATH" \
    'normalize_decoded_path\(current\.as_ref\(\)\)' \
    "$VERUS_PATH" \
    'pub[[:space:]]+fn[[:space:]]+normalize_path_bytes'
echo ""

if [ "$DRIFT_FOUND" -ne 0 ]; then
    echo "=== DRIFT DETECTED ==="
    echo "Verus proof targets have drifted from their documented production counterparts."
    exit 1
fi

echo "=== ALL CHECKS PASSED ==="
echo "Verus proof targets still align with production entrypoints."
