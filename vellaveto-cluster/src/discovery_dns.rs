// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! DNS-based service discovery (Phase 27.3).
//!
//! Resolves a DNS name via `tokio::net::lookup_host` and returns one
//! `ServiceEndpoint` per resolved address.  `watch()` spawns a periodic
//! refresh task that emits `DiscoveryEvent`s when the resolved set changes.

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use vellaveto_types::{DiscoveryEvent, ServiceEndpoint};

use crate::discovery::ServiceDiscovery;
use crate::ClusterError;

/// SECURITY (FIND-R44-012): Maximum number of DNS results to accept.
/// Prevents unbounded memory allocation from DNS amplification attacks.
const MAX_DNS_RESULTS: usize = 256;

/// DNS-based service discovery.
///
/// Resolves `dns_name` (e.g., `"vellaveto-headless:8080"`) and exposes each
/// resolved socket address as a `ServiceEndpoint`.  The port in `dns_name` is
/// required by `tokio::net::lookup_host`.
pub struct DnsServiceDiscovery {
    /// DNS host:port name to resolve (e.g., `"vellaveto-headless:8080"`).
    /// Must include a port for `tokio::net::lookup_host` compatibility.
    dns_name: String,
    /// Interval between periodic re-resolution attempts in the watch loop.
    refresh_interval: std::time::Duration,
    /// SECURITY (R241-CLUST-1): Use HTTPS scheme for discovered endpoints.
    /// When true, generates `https://` URLs instead of `http://`.
    use_tls: bool,
}

/// SECURITY (FIND-R44-013): Post-resolution IP validation to prevent DNS rebinding.
///
/// Rejects addresses that should never appear as cluster endpoints:
/// - Loopback (127.0.0.0/8, ::1)
/// - Unspecified (0.0.0.0, ::)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - AWS/cloud metadata (169.254.169.254)
/// - IPv4-mapped IPv6 addresses that map to private ranges (::ffff:127.x.x.x, etc.)
fn is_safe_addr(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip();
            if ip.is_loopback() {
                return false;
            }
            if ip.is_unspecified() {
                return false;
            }
            // Link-local: 169.254.0.0/16
            let octets = ip.octets();
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }
            true
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip();
            // Reject ::1
            if ip.is_loopback() {
                return false;
            }
            // Reject ::
            if ip.is_unspecified() {
                return false;
            }
            // Reject fe80::/10 (link-local)
            let segments = ip.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            // SECURITY (FIND-R163-003): Reject fc00::/7 (Unique Local Addresses).
            // ULAs are IPv6 equivalents of IPv4 private ranges (10/8, 172.16/12,
            // 192.168/16). Both fd00::/8 (private) and fc00::/8 (local) are rejected.
            if segments[0] & 0xfe00 == 0xfc00 {
                return false;
            }
            // Reject IPv4-mapped addresses (::ffff:x.x.x.x) that map to unsafe ranges
            if let Some(v4) = ip.to_ipv4_mapped() {
                if v4.is_loopback() || v4.is_unspecified() {
                    return false;
                }
                let octets = v4.octets();
                // Link-local: 169.254.0.0/16
                if octets[0] == 169 && octets[1] == 254 {
                    return false;
                }
                // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                if octets[0] == 10 {
                    return false;
                }
                if octets[0] == 172 && (octets[1] & 0xf0) == 16 {
                    return false;
                }
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }
            }
            true
        }
    }
}

impl DnsServiceDiscovery {
    /// Create a new DNS discovery for the given host:port name.
    ///
    /// `refresh_interval` controls how often the watcher re-resolves.
    ///
    /// # Errors
    ///
    /// Returns an error if `dns_name` is empty, too long, or contains
    /// control/format characters.
    pub fn new(dns_name: String, refresh_interval: std::time::Duration) -> Result<Self, String> {
        // SECURITY (FIND-R163-006): Validate dns_name at construction to prevent
        // log injection, OOM, and empty-string errors from tokio::lookup_host.
        if dns_name.is_empty() {
            return Err("dns_name must not be empty".to_string());
        }
        const MAX_DNS_NAME_LEN: usize = 255;
        if dns_name.len() > MAX_DNS_NAME_LEN {
            return Err("dns_name exceeds maximum length".to_string());
        }
        if vellaveto_types::has_dangerous_chars(&dns_name) {
            return Err("dns_name contains control or format characters".to_string());
        }
        // SECURITY (IMP-R224-001): Validate refresh_interval to prevent busy-loop DoS.
        // Zero or sub-second intervals cause the watch() loop to spin, saturating CPU
        // and flooding the DNS resolver.
        const MIN_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
        const MAX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(86_400);
        if refresh_interval < MIN_REFRESH_INTERVAL {
            return Err(format!(
                "refresh_interval {refresh_interval:?} is below minimum {MIN_REFRESH_INTERVAL:?}",
            ));
        }
        if refresh_interval > MAX_REFRESH_INTERVAL {
            return Err(format!(
                "refresh_interval {refresh_interval:?} exceeds maximum {MAX_REFRESH_INTERVAL:?}",
            ));
        }
        Ok(Self {
            dns_name,
            refresh_interval,
            use_tls: false,
        })
    }

    /// Enable HTTPS for discovered endpoints.
    ///
    /// When set, resolved addresses use `https://` instead of `http://`.
    /// Should be enabled when cluster TLS is configured.
    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }

    /// Perform a single DNS lookup and return sorted endpoints.
    async fn resolve(&self) -> Result<Vec<ServiceEndpoint>, ClusterError> {
        let addrs = tokio::net::lookup_host(&self.dns_name).await.map_err(|e| {
            ClusterError::Connection(format!("DNS lookup failed for '{}': {}", self.dns_name, e))
        })?;

        // SECURITY (FIND-R44-012): Bound DNS results to prevent unbounded memory allocation.
        let all_addrs: Vec<SocketAddr> = addrs.collect();
        let truncated = all_addrs.len() > MAX_DNS_RESULTS;
        if truncated {
            tracing::warn!(
                dns_name = %self.dns_name,
                total = all_addrs.len(),
                max = MAX_DNS_RESULTS,
                "DNS lookup returned more addresses than MAX_DNS_RESULTS; truncating"
            );
        }

        let mut endpoints: Vec<ServiceEndpoint> = all_addrs
            .into_iter()
            .take(MAX_DNS_RESULTS)
            .filter(|addr| {
                // SECURITY (FIND-R44-013): Post-resolution IP validation.
                let safe = is_safe_addr(addr);
                if !safe {
                    tracing::warn!(
                        dns_name = %self.dns_name,
                        rejected_addr = %addr,
                        "Rejected unsafe resolved address (loopback/unspecified/link-local/private)"
                    );
                }
                safe
            })
            .map(|addr| {
                let id = addr.to_string();
                // SECURITY (FIND-R44-046): Resolved addresses have been validated
                // through is_safe_addr() above, rejecting loopback, unspecified,
                // link-local, cloud metadata, and IPv4-mapped private ranges.
                // SECURITY (R241-CLUST-1): Use TLS scheme when configured.
                let scheme = if self.use_tls { "https" } else { "http" };
                ServiceEndpoint {
                    id: id.clone(),
                    url: format!("{scheme}://{addr}"),
                    labels: HashMap::new(),
                    healthy: true,
                }
            })
            .collect();

        // Sort for deterministic comparison across refreshes.
        endpoints.sort_by(|a, b| a.id.cmp(&b.id));
        endpoints.dedup_by(|a, b| a.id == b.id);
        Ok(endpoints)
    }
}

#[async_trait]
impl ServiceDiscovery for DnsServiceDiscovery {
    async fn discover(&self) -> Result<Vec<ServiceEndpoint>, ClusterError> {
        self.resolve().await
    }

    async fn watch(
        &self,
    ) -> Result<Option<tokio::sync::mpsc::Receiver<DiscoveryEvent>>, ClusterError> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let dns_name = self.dns_name.clone();
        let interval = self.refresh_interval;

        // Capture initial snapshot.
        let initial = self.resolve().await?;

        tokio::spawn(async move {
            let mut known: HashMap<String, ServiceEndpoint> =
                initial.into_iter().map(|ep| (ep.id.clone(), ep)).collect();
            let mut tick = tokio::time::interval(interval);
            // Skip the first immediate tick -- initial state already captured.
            tick.tick().await;

            // SECURITY (FIND-R44-043): Track consecutive DNS errors for logging.
            let mut consecutive_errors: u32 = 0;

            // FIND-R56-CLUSTER-003: Construct the resolver once before the loop
            // instead of recreating it on every tick.
            let resolver = match DnsServiceDiscovery::new(dns_name, interval) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Invalid DNS discovery configuration: {}", e);
                    return;
                }
            };

            loop {
                tick.tick().await;

                let current = match resolver.resolve().await {
                    Ok(eps) => {
                        // Reset error counter on success.
                        consecutive_errors = 0;
                        eps
                    }
                    Err(e) => {
                        // SECURITY (FIND-R44-043): Log DNS errors with backoff.
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        if consecutive_errors == 1 || consecutive_errors.is_multiple_of(10) {
                            tracing::warn!(
                                dns_name = %resolver.dns_name,
                                consecutive_errors = consecutive_errors,
                                error = %e,
                                "DNS watch resolution failed"
                            );
                        }
                        continue; // retry next tick
                    }
                };

                let current_map: HashMap<String, ServiceEndpoint> =
                    current.into_iter().map(|ep| (ep.id.clone(), ep)).collect();

                // Detect added endpoints.
                for (id, ep) in &current_map {
                    if !known.contains_key(id)
                        && tx.send(DiscoveryEvent::Added(ep.clone())).await.is_err()
                    {
                        return; // receiver dropped
                    }
                }

                // Detect removed endpoints.
                for id in known.keys() {
                    if !current_map.contains_key(id)
                        && tx
                            .send(DiscoveryEvent::Removed { id: id.clone() })
                            .await
                            .is_err()
                    {
                        return; // receiver dropped
                    }
                }

                known = current_map;
            }
        });

        Ok(Some(rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────
    // FIND-R44-013: is_safe_addr tests
    // ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_safe_addr_rejects_ipv4_loopback() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "127.0.0.1 should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_loopback_other() {
        let addr: SocketAddr = "127.99.99.99:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "127.x.x.x should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_unspecified() {
        let addr: SocketAddr = "0.0.0.0:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "0.0.0.0 should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_link_local() {
        let addr: SocketAddr = "169.254.0.1:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "169.254.x.x should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_aws_metadata() {
        let addr: SocketAddr = "169.254.169.254:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "AWS metadata IP should be rejected");
    }

    #[test]
    fn test_is_safe_addr_accepts_public_ipv4() {
        let addr: SocketAddr = "8.8.8.8:80".parse().unwrap();
        assert!(is_safe_addr(&addr), "8.8.8.8 should be accepted");
    }

    #[test]
    fn test_is_safe_addr_accepts_private_10_network() {
        // Private ranges are valid for cluster endpoints (within same VPC)
        let addr: SocketAddr = "10.0.1.5:80".parse().unwrap();
        assert!(is_safe_addr(&addr), "10.x.x.x should be accepted for IPv4");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv6_loopback() {
        let addr: SocketAddr = "[::1]:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "::1 should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv6_unspecified() {
        let addr: SocketAddr = "[::]:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), ":: should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv6_link_local() {
        let addr: SocketAddr = "[fe80::1]:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "fe80::x should be rejected");
    }

    #[test]
    fn test_is_safe_addr_accepts_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        assert!(is_safe_addr(&addr), "public IPv6 should be accepted");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_loopback() {
        let addr: SocketAddr = "[::ffff:127.0.0.1]:80".parse().unwrap();
        assert!(
            !is_safe_addr(&addr),
            "IPv4-mapped loopback should be rejected"
        );
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_link_local() {
        let addr: SocketAddr = "[::ffff:169.254.1.1]:80".parse().unwrap();
        assert!(
            !is_safe_addr(&addr),
            "IPv4-mapped link-local should be rejected"
        );
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_private_10() {
        let addr: SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();
        assert!(!is_safe_addr(&addr), "IPv4-mapped 10.x should be rejected");
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_private_172() {
        let addr: SocketAddr = "[::ffff:172.16.0.1]:80".parse().unwrap();
        assert!(
            !is_safe_addr(&addr),
            "IPv4-mapped 172.16.x should be rejected"
        );
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_private_192() {
        let addr: SocketAddr = "[::ffff:192.168.1.1]:80".parse().unwrap();
        assert!(
            !is_safe_addr(&addr),
            "IPv4-mapped 192.168.x should be rejected"
        );
    }

    #[test]
    fn test_is_safe_addr_rejects_ipv4_mapped_unspecified() {
        let addr: SocketAddr = "[::ffff:0.0.0.0]:80".parse().unwrap();
        assert!(
            !is_safe_addr(&addr),
            "IPv4-mapped 0.0.0.0 should be rejected"
        );
    }

    // ─────────────────────────────────────────────────────────
    // FIND-R44-012: MAX_DNS_RESULTS constant
    // ─────────────────────────────────────────────────────────

    #[test]
    fn test_max_dns_results_is_256() {
        assert_eq!(MAX_DNS_RESULTS, 256);
    }

    // ─────────────────────────────────────────────────────────
    // Existing tests (updated to account for FIND-R44-013)
    // ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_dns_discovery_localhost_filtered_by_safety() {
        // Resolve localhost -- addresses should be filtered by is_safe_addr.
        // Loopback addresses (127.x.x.x, ::1) are rejected.
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let endpoints = dd.discover().await.unwrap();
        // All loopback addresses should be filtered out.
        assert!(
            endpoints.is_empty(),
            "localhost endpoints should be filtered as unsafe (loopback)"
        );
    }

    #[tokio::test]
    async fn test_dns_discovery_invalid_host_returns_error() {
        let dd = DnsServiceDiscovery::new(
            "this-host-does-not-exist.invalid:9999".to_string(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let result = dd.discover().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ClusterError::Connection(_)));
    }

    #[tokio::test]
    async fn test_dns_discovery_endpoints_are_sorted() {
        // Use a hostname that might resolve to multiple addresses.
        // We test sorting with whatever resolves.
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let endpoints = dd.discover().await.unwrap();
        // Sorted check (even if empty after filtering, this should not fail).
        for pair in endpoints.windows(2) {
            assert!(pair[0].id <= pair[1].id);
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_multiple_calls_consistent() {
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let first = dd.discover().await.unwrap();
        let second = dd.discover().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn test_dns_discovery_watch_returns_receiver() {
        // Use a hostname that resolves -- even if endpoints are filtered,
        // the resolve step succeeds and watch returns Some.
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let rx = dd.watch().await.unwrap();
        assert!(rx.is_some(), "DNS discovery should support watching");
    }

    #[tokio::test]
    async fn test_dns_discovery_watch_invalid_host_returns_error() {
        let dd = DnsServiceDiscovery::new(
            "this-host-does-not-exist.invalid:9999".to_string(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        let result = dd.watch().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_discovery_rejects_empty_name() {
        let result = DnsServiceDiscovery::new(String::new(), std::time::Duration::from_secs(5));
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_discovery_rejects_control_chars() {
        let result = DnsServiceDiscovery::new(
            "bad\nhost:80".to_string(),
            std::time::Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_discovery_rejects_zero_refresh_interval() {
        // SECURITY (IMP-R224-001): Zero interval causes busy-loop DoS.
        let result =
            DnsServiceDiscovery::new("localhost:80".to_string(), std::time::Duration::ZERO);
        let err = result.err().expect("should fail");
        assert!(err.contains("below minimum"), "got: {err}");
    }

    #[test]
    fn test_dns_discovery_rejects_sub_second_refresh_interval() {
        let result = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_millis(500),
        );
        let err = result.err().expect("should fail");
        assert!(err.contains("below minimum"), "got: {err}");
    }

    #[test]
    fn test_dns_discovery_rejects_excessive_refresh_interval() {
        let result = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(100_000),
        );
        let err = result.err().expect("should fail");
        assert!(err.contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn test_dns_discovery_accepts_valid_refresh_interval() {
        let result = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(30),
        );
        assert!(result.is_ok());
    }
}
