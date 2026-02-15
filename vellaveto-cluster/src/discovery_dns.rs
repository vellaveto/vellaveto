//! DNS-based service discovery (Phase 27.3).
//!
//! Resolves a DNS name via `tokio::net::lookup_host` and returns one
//! `ServiceEndpoint` per resolved address.  `watch()` spawns a periodic
//! refresh task that emits `DiscoveryEvent`s when the resolved set changes.

use async_trait::async_trait;
use std::collections::HashMap;
use vellaveto_types::{DiscoveryEvent, ServiceEndpoint};

use crate::discovery::ServiceDiscovery;
use crate::ClusterError;

/// DNS-based service discovery.
///
/// Resolves `dns_name` (e.g., `"vellaveto-headless:8080"`) and exposes each
/// resolved socket address as a `ServiceEndpoint`.  The port in `dns_name` is
/// required by `tokio::net::lookup_host`.
pub struct DnsServiceDiscovery {
    dns_name: String,
    refresh_interval: std::time::Duration,
}

impl DnsServiceDiscovery {
    /// Create a new DNS discovery for the given host:port name.
    ///
    /// `refresh_interval` controls how often the watcher re-resolves.
    pub fn new(dns_name: String, refresh_interval: std::time::Duration) -> Self {
        Self {
            dns_name,
            refresh_interval,
        }
    }

    /// Perform a single DNS lookup and return sorted endpoints.
    async fn resolve(&self) -> Result<Vec<ServiceEndpoint>, ClusterError> {
        let addrs = tokio::net::lookup_host(&self.dns_name)
            .await
            .map_err(|e| ClusterError::Connection(format!("DNS lookup failed for '{}': {}", self.dns_name, e)))?;

        let mut endpoints: Vec<ServiceEndpoint> = addrs
            .map(|addr| {
                let id = addr.to_string();
                ServiceEndpoint {
                    id: id.clone(),
                    url: format!("http://{}", addr),
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
    ) -> Result<
        Option<tokio::sync::mpsc::Receiver<DiscoveryEvent>>,
        ClusterError,
    > {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let dns_name = self.dns_name.clone();
        let interval = self.refresh_interval;

        // Capture initial snapshot.
        let initial = self.resolve().await?;

        tokio::spawn(async move {
            let mut known: HashMap<String, ServiceEndpoint> = initial
                .into_iter()
                .map(|ep| (ep.id.clone(), ep))
                .collect();
            let mut tick = tokio::time::interval(interval);
            // Skip the first immediate tick — initial state already captured.
            tick.tick().await;

            loop {
                tick.tick().await;

                let resolver = DnsServiceDiscovery::new(dns_name.clone(), interval);
                let current = match resolver.resolve().await {
                    Ok(eps) => eps,
                    Err(_) => continue, // transient DNS failure — retry next tick
                };

                let current_map: HashMap<String, ServiceEndpoint> = current
                    .into_iter()
                    .map(|ep| (ep.id.clone(), ep))
                    .collect();

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

    #[tokio::test]
    async fn test_dns_discovery_localhost() {
        // Resolve localhost — should succeed on any machine with loopback.
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        );
        let endpoints = dd.discover().await.unwrap();
        assert!(!endpoints.is_empty(), "localhost should resolve to at least one address");
        for ep in &endpoints {
            assert!(ep.url.starts_with("http://"));
            assert!(ep.healthy);
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_invalid_host_returns_error() {
        let dd = DnsServiceDiscovery::new(
            "this-host-does-not-exist.invalid:9999".to_string(),
            std::time::Duration::from_secs(5),
        );
        let result = dd.discover().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ClusterError::Connection(_)));
    }

    #[tokio::test]
    async fn test_dns_discovery_endpoints_are_sorted() {
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        );
        let endpoints = dd.discover().await.unwrap();
        for pair in endpoints.windows(2) {
            assert!(pair[0].id <= pair[1].id);
        }
    }

    #[tokio::test]
    async fn test_dns_discovery_multiple_calls_consistent() {
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(5),
        );
        let first = dd.discover().await.unwrap();
        let second = dd.discover().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn test_dns_discovery_watch_returns_receiver() {
        let dd = DnsServiceDiscovery::new(
            "localhost:80".to_string(),
            std::time::Duration::from_secs(60),
        );
        let rx = dd.watch().await.unwrap();
        assert!(rx.is_some(), "DNS discovery should support watching");
    }

    #[tokio::test]
    async fn test_dns_discovery_watch_invalid_host_returns_error() {
        let dd = DnsServiceDiscovery::new(
            "this-host-does-not-exist.invalid:9999".to_string(),
            std::time::Duration::from_secs(5),
        );
        let result = dd.watch().await;
        assert!(result.is_err());
    }
}
