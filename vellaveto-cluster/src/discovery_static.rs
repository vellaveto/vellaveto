//! Static service discovery (Phase 27.3).
//!
//! Wraps a fixed list of `ServiceEndpoint`s (e.g., from gateway backend config).
//! Does not support watching — `watch()` returns `Ok(None)`.

use async_trait::async_trait;
use vellaveto_types::ServiceEndpoint;

use crate::discovery::ServiceDiscovery;
use crate::ClusterError;

/// Static service discovery backed by a fixed endpoint list.
#[derive(Debug)]
pub struct StaticServiceDiscovery {
    endpoints: Vec<ServiceEndpoint>,
}

/// Maximum number of static endpoints (parity with MAX_DNS_RESULTS=256 in DNS discovery).
const MAX_STATIC_ENDPOINTS: usize = 256;

impl StaticServiceDiscovery {
    /// Create a new static discovery with the given endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint count exceeds `MAX_STATIC_ENDPOINTS` (256).
    pub fn new(endpoints: Vec<ServiceEndpoint>) -> Result<Self, ClusterError> {
        // SECURITY (FIND-R184-004): Bound endpoint list — parity with DNS discovery.
        if endpoints.len() > MAX_STATIC_ENDPOINTS {
            return Err(ClusterError::Validation(format!(
                "static endpoint list size {} exceeds maximum {}",
                endpoints.len(),
                MAX_STATIC_ENDPOINTS
            )));
        }
        // SECURITY (IMP-R224-006): Validate each endpoint at construction time.
        // Without this, endpoints with control chars in id/url or excessively
        // long labels are accepted and propagated unvalidated.
        for (i, ep) in endpoints.iter().enumerate() {
            ep.validate()
                .map_err(|e| ClusterError::Validation(format!("endpoint[{}]: {}", i, e)))?;
        }
        Ok(Self { endpoints })
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
        let sd = StaticServiceDiscovery::new(endpoints.clone()).unwrap();

        let discovered = sd.discover().await.unwrap();
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].id, "backend-1");
        assert_eq!(discovered[1].id, "backend-2");
        assert!(discovered[0].healthy);
        assert!(!discovered[1].healthy);
    }

    #[tokio::test]
    async fn test_static_discovery_empty() {
        let sd = StaticServiceDiscovery::new(vec![]).unwrap();
        let discovered = sd.discover().await.unwrap();
        assert!(discovered.is_empty());
    }

    #[tokio::test]
    async fn test_static_discovery_watch_returns_none() {
        let sd = StaticServiceDiscovery::new(vec![]).unwrap();
        let rx = sd.watch().await.unwrap();
        assert!(rx.is_none());
    }

    #[tokio::test]
    async fn test_static_discovery_exceeds_max_endpoints() {
        let endpoints: Vec<ServiceEndpoint> = (0..257)
            .map(|i| ServiceEndpoint {
                id: format!("backend-{}", i),
                url: format!("http://backend-{}:3000", i),
                labels: HashMap::new(),
                healthy: true,
            })
            .collect();
        let err = StaticServiceDiscovery::new(endpoints).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "Expected exceeds maximum error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_static_discovery_at_max_endpoints() {
        let endpoints: Vec<ServiceEndpoint> = (0..256)
            .map(|i| ServiceEndpoint {
                id: format!("backend-{}", i),
                url: format!("http://backend-{}:3000", i),
                labels: HashMap::new(),
                healthy: true,
            })
            .collect();
        let sd = StaticServiceDiscovery::new(endpoints).unwrap();
        let discovered = sd.discover().await.unwrap();
        assert_eq!(discovered.len(), 256);
    }

    #[tokio::test]
    async fn test_static_discovery_multiple_calls_consistent() {
        let endpoints = vec![ServiceEndpoint {
            id: "single".to_string(),
            url: "http://single:3000".to_string(),
            labels: HashMap::new(),
            healthy: true,
        }];
        let sd = StaticServiceDiscovery::new(endpoints).unwrap();

        let first = sd.discover().await.unwrap();
        let second = sd.discover().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn test_static_discovery_rejects_endpoint_with_control_chars() {
        // SECURITY (IMP-R224-006): Endpoint validation at construction time.
        let endpoints = vec![ServiceEndpoint {
            id: "bad\nid".to_string(),
            url: "http://backend:3000".to_string(),
            labels: HashMap::new(),
            healthy: true,
        }];
        let err = StaticServiceDiscovery::new(endpoints).unwrap_err();
        assert!(
            err.to_string().contains("control"),
            "Expected control char error, got: {}",
            err
        );
    }
}
