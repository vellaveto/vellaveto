//! Static service discovery (Phase 27.3).
//!
//! Wraps a fixed list of `ServiceEndpoint`s (e.g., from gateway backend config).
//! Does not support watching — `watch()` returns `Ok(None)`.

use async_trait::async_trait;
use vellaveto_types::ServiceEndpoint;

use crate::discovery::ServiceDiscovery;
use crate::ClusterError;

/// Static service discovery backed by a fixed endpoint list.
pub struct StaticServiceDiscovery {
    endpoints: Vec<ServiceEndpoint>,
}

impl StaticServiceDiscovery {
    /// Create a new static discovery with the given endpoints.
    pub fn new(endpoints: Vec<ServiceEndpoint>) -> Self {
        Self { endpoints }
    }
}

#[async_trait]
impl ServiceDiscovery for StaticServiceDiscovery {
    async fn discover(&self) -> Result<Vec<ServiceEndpoint>, ClusterError> {
        Ok(self.endpoints.clone())
    }

    async fn watch(
        &self,
    ) -> Result<Option<tokio::sync::mpsc::Receiver<vellaveto_types::DiscoveryEvent>>, ClusterError>
    {
        // Static discovery does not support watching
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_static_discovery_returns_endpoints() {
        let endpoints = vec![
            ServiceEndpoint {
                id: "backend-1".to_string(),
                url: "http://backend-1:3000".to_string(),
                labels: HashMap::new(),
                healthy: true,
            },
            ServiceEndpoint {
                id: "backend-2".to_string(),
                url: "http://backend-2:3000".to_string(),
                labels: HashMap::new(),
                healthy: false,
            },
        ];
        let sd = StaticServiceDiscovery::new(endpoints.clone());

        let discovered = sd.discover().await.unwrap();
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].id, "backend-1");
        assert_eq!(discovered[1].id, "backend-2");
        assert!(discovered[0].healthy);
        assert!(!discovered[1].healthy);
    }

    #[tokio::test]
    async fn test_static_discovery_empty() {
        let sd = StaticServiceDiscovery::new(vec![]);
        let discovered = sd.discover().await.unwrap();
        assert!(discovered.is_empty());
    }

    #[tokio::test]
    async fn test_static_discovery_watch_returns_none() {
        let sd = StaticServiceDiscovery::new(vec![]);
        let rx = sd.watch().await.unwrap();
        assert!(rx.is_none());
    }

    #[tokio::test]
    async fn test_static_discovery_multiple_calls_consistent() {
        let endpoints = vec![ServiceEndpoint {
            id: "single".to_string(),
            url: "http://single:3000".to_string(),
            labels: HashMap::new(),
            healthy: true,
        }];
        let sd = StaticServiceDiscovery::new(endpoints);

        let first = sd.discover().await.unwrap();
        let second = sd.discover().await.unwrap();
        assert_eq!(first, second);
    }
}
