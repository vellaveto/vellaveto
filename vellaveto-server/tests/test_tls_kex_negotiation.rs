// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

use vellaveto_config::TlsKexPolicy;
use vellaveto_server::tls::effective_kex_groups_for_policy;

fn is_pq_or_hybrid_named_group(group: rustls::NamedGroup) -> bool {
    matches!(
        group,
        rustls::NamedGroup::MLKEM512
            | rustls::NamedGroup::MLKEM768
            | rustls::NamedGroup::MLKEM1024
            | rustls::NamedGroup::X25519MLKEM768
            | rustls::NamedGroup::secp256r1MLKEM768
    )
}

fn default_client_classical_groups() -> Vec<rustls::NamedGroup> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .iter()
        .map(|g| g.name())
        .filter(|g| !is_pq_or_hybrid_named_group(*g))
        .collect()
}

fn has_intersection(a: &[rustls::NamedGroup], b: &[rustls::NamedGroup]) -> bool {
    a.iter().any(|left| b.iter().any(|right| left == right))
}

#[test]
fn classical_only_removes_pq_and_hybrid_groups() {
    let groups = effective_kex_groups_for_policy(TlsKexPolicy::ClassicalOnly)
        .expect("classical_only groups should compute");
    assert!(
        !groups.is_empty(),
        "classical_only must keep at least one classical group"
    );
    assert!(
        groups.iter().all(|g| !is_pq_or_hybrid_named_group(*g)),
        "classical_only must exclude PQ/hybrid groups: {groups:?}"
    );
}

#[test]
fn hybrid_preferred_prioritizes_pq_when_available() {
    let groups = effective_kex_groups_for_policy(TlsKexPolicy::HybridPreferred)
        .expect("hybrid_preferred groups should compute");
    assert!(
        !groups.is_empty(),
        "hybrid_preferred must keep at least one group"
    );
    let has_pq = groups.iter().any(|g| is_pq_or_hybrid_named_group(*g));
    if has_pq {
        assert!(
            is_pq_or_hybrid_named_group(groups[0]),
            "hybrid_preferred should place PQ/hybrid first when available: {groups:?}"
        );
    }
}

#[test]
fn hybrid_required_when_supported_enforces_or_falls_back() {
    let groups = effective_kex_groups_for_policy(TlsKexPolicy::HybridRequiredWhenSupported)
        .expect("hybrid_required_when_supported groups should compute");
    assert!(
        !groups.is_empty(),
        "hybrid_required_when_supported must keep at least one group"
    );
    let has_pq = groups.iter().any(|g| is_pq_or_hybrid_named_group(*g));
    if has_pq {
        assert!(
            groups.iter().all(|g| is_pq_or_hybrid_named_group(*g)),
            "when PQ/hybrid exists, only PQ/hybrid groups should remain: {groups:?}"
        );
    }
}

#[test]
fn hybrid_required_failure_mode_for_classical_only_client() {
    let server_groups = effective_kex_groups_for_policy(TlsKexPolicy::HybridRequiredWhenSupported)
        .expect("server groups should compute");
    let client_groups = default_client_classical_groups();
    assert!(
        !client_groups.is_empty(),
        "classical-only client must retain at least one group"
    );

    let server_has_pq = server_groups
        .iter()
        .any(|g| is_pq_or_hybrid_named_group(*g));
    let overlap = has_intersection(&server_groups, &client_groups);
    if server_has_pq {
        assert!(
            !overlap,
            "classical-only client should have no shared KEX groups with hybrid-required server when PQ/hybrid is supported"
        );
    } else {
        assert!(
            overlap,
            "fallback mode should keep overlap with classical-only client when PQ/hybrid is unavailable"
        );
    }
}
