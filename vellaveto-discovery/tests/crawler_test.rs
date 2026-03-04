// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Tests for TopologyCrawler with mock probes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use vellaveto_discovery::crawler::*;
use vellaveto_discovery::error::DiscoveryError;
use vellaveto_discovery::topology::ServerCapabilities;

// ═══════════════════════════════════════════════════════════════════════════════
// MOCK PROBE
// ═══════════════════════════════════════════════════════════════════════════════

struct MockServer {
    tools: Vec<ToolInfo>,
    resources: Vec<ResourceInfo>,
    capabilities: ServerCapabilities,
    latency: Duration,
    fail: bool,
}

struct MockMcpProbe {
    servers: HashMap<String, MockServer>,
    call_count: Mutex<usize>,
}

impl MockMcpProbe {
    fn new() -> Self {
        Self {
            servers: HashMap::new(),
            call_count: Mutex::new(0),
        }
    }

    fn add_server(&mut self, id: &str, tools: Vec<ToolInfo>, resources: Vec<ResourceInfo>) {
        self.servers.insert(
            id.to_string(),
            MockServer {
                tools,
                resources,
                capabilities: ServerCapabilities {
                    tools: true,
                    resources: true,
                    prompts: false,
                    logging: false,
                },
                latency: Duration::ZERO,
                fail: false,
            },
        );
    }

    fn add_slow_server(&mut self, id: &str, latency: Duration) {
        self.servers.insert(
            id.to_string(),
            MockServer {
                tools: vec![ToolInfo {
                    name: "slow_tool".to_string(),
                    description: "A slow tool".to_string(),
                    input_schema: serde_json::json!({}),
                }],
                resources: vec![],
                capabilities: ServerCapabilities {
                    tools: true,
                    resources: false,
                    prompts: false,
                    logging: false,
                },
                latency,
                fail: false,
            },
        );
    }

    fn add_failing_server(&mut self, id: &str) {
        self.servers.insert(
            id.to_string(),
            MockServer {
                tools: vec![],
                resources: vec![],
                capabilities: ServerCapabilities::default(),
                latency: Duration::ZERO,
                fail: true,
            },
        );
    }
}

#[async_trait]
impl McpServerProbe for MockMcpProbe {
    async fn list_servers(&self) -> Result<Vec<ServerInfo>, DiscoveryError> {
        let mut count = self.call_count.lock().await;
        *count = count.saturating_add(1);

        Ok(self
            .servers
            .keys()
            .map(|id| ServerInfo {
                id: id.clone(),
                name: id.clone(),
                version: Some("1.0".to_string()),
            })
            .collect())
    }

    async fn list_tools(&self, server_id: &str) -> Result<Vec<ToolInfo>, DiscoveryError> {
        let server = self
            .servers
            .get(server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;

        if server.fail {
            return Err(DiscoveryError::ServerError {
                server: server_id.to_string(),
                reason: "Mock failure".to_string(),
            });
        }

        if !server.latency.is_zero() {
            tokio::time::sleep(server.latency).await;
        }

        Ok(server.tools.clone())
    }

    async fn list_resources(&self, server_id: &str) -> Result<Vec<ResourceInfo>, DiscoveryError> {
        let server = self
            .servers
            .get(server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;

        if server.fail {
            return Err(DiscoveryError::ServerError {
                server: server_id.to_string(),
                reason: "Mock failure".to_string(),
            });
        }

        Ok(server.resources.clone())
    }

    async fn server_capabilities(
        &self,
        server_id: &str,
    ) -> Result<ServerCapabilities, DiscoveryError> {
        let server = self
            .servers
            .get(server_id)
            .ok_or_else(|| DiscoveryError::ServerNotFound(server_id.to_string()))?;

        if server.fail {
            return Err(DiscoveryError::ServerError {
                server: server_id.to_string(),
                reason: "Mock failure".to_string(),
            });
        }

        Ok(server.capabilities.clone())
    }
}

fn tool(name: &str, desc: &str) -> ToolInfo {
    ToolInfo {
        name: name.to_string(),
        description: desc.to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" }
            }
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_crawl_single_server() {
    let mut probe = MockMcpProbe::new();
    probe.add_server(
        "fs",
        vec![
            tool("read_file", "Read a file"),
            tool("write_file", "Write a file"),
            tool("search", "Search files"),
        ],
        vec![],
    );

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 1);
    assert_eq!(result.tools_found, 3);
    assert!(result.servers_failed.is_empty());
    assert_eq!(result.topology.server_count(), 1);
}

#[tokio::test]
async fn test_crawl_multi_server() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("fs", vec![tool("read_file", "Read")], vec![]);
    probe.add_server("git", vec![tool("commit", "Commit")], vec![]);
    probe.add_server("web", vec![tool("fetch", "Fetch")], vec![]);

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 3);
    assert_eq!(result.tools_found, 3);
}

#[tokio::test]
async fn test_crawl_server_timeout() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("fast", vec![tool("tool1", "Fast tool")], vec![]);
    probe.add_slow_server("slow", Duration::from_secs(10));

    let config = CrawlConfig {
        server_timeout: Duration::from_millis(100),
        continue_on_error: true,
        max_concurrent: 5,
    };
    let crawler = TopologyCrawler::new(Arc::new(probe), config);
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 1);
    assert_eq!(result.servers_failed.len(), 1);
    assert!(result.servers_failed[0].0 == "slow");
}

#[tokio::test]
async fn test_crawl_server_failure_continue() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("good", vec![tool("tool1", "Good tool")], vec![]);
    probe.add_failing_server("bad");

    let config = CrawlConfig {
        continue_on_error: true,
        ..CrawlConfig::default()
    };
    let crawler = TopologyCrawler::new(Arc::new(probe), config);
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 1);
    assert_eq!(result.servers_failed.len(), 1);
}

#[tokio::test]
async fn test_crawl_server_failure_abort() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("good", vec![tool("tool1", "Good")], vec![]);
    probe.add_failing_server("bad");

    let config = CrawlConfig {
        continue_on_error: false,
        ..CrawlConfig::default()
    };
    let crawler = TopologyCrawler::new(Arc::new(probe), config);
    let result = crawler.crawl().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_crawl_empty_server() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("empty", vec![], vec![]);

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 1);
    assert_eq!(result.tools_found, 0);
    // Server node exists but no tools
    assert_eq!(result.topology.server_count(), 1);
    assert_eq!(result.topology.server_tools("empty").len(), 0);
}

#[tokio::test]
async fn test_crawl_duplicate_tool_names_across_servers() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("serverA", vec![tool("search", "Search A")], vec![]);
    probe.add_server("serverB", vec![tool("search", "Search B")], vec![]);

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.tools_found, 2);
    assert!(result.topology.find_tool("serverA::search").is_some());
    assert!(result.topology.find_tool("serverB::search").is_some());
}

#[tokio::test]
async fn test_crawl_concurrent() {
    let mut probe = MockMcpProbe::new();
    for i in 0..5 {
        probe.add_slow_server(&format!("server{i}"), Duration::from_millis(100));
    }

    let config = CrawlConfig {
        server_timeout: Duration::from_secs(5),
        continue_on_error: true,
        max_concurrent: 5,
    };
    let crawler = TopologyCrawler::new(Arc::new(probe), config);

    let start = std::time::Instant::now();
    let result = crawler.crawl().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.servers_crawled, 5);
    // All 5 should run concurrently: ~100ms, not ~500ms
    assert!(
        elapsed < Duration::from_millis(500),
        "Expected <500ms, got {elapsed:?}"
    );
}

#[tokio::test]
async fn test_crawl_max_concurrent() {
    let mut probe = MockMcpProbe::new();
    for i in 0..5 {
        probe.add_slow_server(&format!("server{i}"), Duration::from_millis(100));
    }

    let config = CrawlConfig {
        server_timeout: Duration::from_secs(5),
        continue_on_error: true,
        max_concurrent: 2, // Only 2 at a time
    };
    let crawler = TopologyCrawler::new(Arc::new(probe), config);

    let start = std::time::Instant::now();
    let result = crawler.crawl().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.servers_crawled, 5);
    // 2+2+1 batches: ~300ms minimum
    assert!(
        elapsed >= Duration::from_millis(200),
        "Expected >=200ms, got {elapsed:?}"
    );
}

#[tokio::test]
async fn test_crawl_result_metrics() {
    let mut probe = MockMcpProbe::new();
    probe.add_server(
        "fs",
        vec![tool("read", "Read"), tool("write", "Write")],
        vec![ResourceInfo {
            uri_template: "file:///{path}".to_string(),
            name: "file".to_string(),
            mime_type: Some("text/plain".to_string()),
        }],
    );

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl().await.unwrap();

    assert_eq!(result.servers_crawled, 1);
    assert_eq!(result.tools_found, 2);
    assert_eq!(result.resources_found, 1);
    assert!(result.duration.as_millis() < 5000);
}

#[tokio::test]
async fn test_crawl_single_server_targeted() {
    let mut probe = MockMcpProbe::new();
    probe.add_server("fs", vec![tool("read", "Read")], vec![]);
    probe.add_server("git", vec![tool("commit", "Commit")], vec![]);

    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl_server("fs").await.unwrap();

    assert_eq!(result.tools_found, 1);
    assert_eq!(result.server.name, "fs");
}

#[tokio::test]
async fn test_crawl_single_server_not_found() {
    let probe = MockMcpProbe::new();
    let crawler = TopologyCrawler::new(Arc::new(probe), CrawlConfig::default());
    let result = crawler.crawl_server("nonexistent").await;
    assert!(result.is_err());
}
