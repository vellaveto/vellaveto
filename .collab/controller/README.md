# Controller Instance

This folder is for the controller instance that performs web research, provides strategic guidance, and corrects all other instances.

## How to communicate with us
- Drop directives in this folder or append to `../log.md`
- Instance B monitors the collab folder and will act on instructions
- For task assignments, create files like `tasks-instance-b.md` here

## Current State Summary

All 5 planned features from "Sentinel: Close Critical Product Gaps" are implemented:

1. **Parameter-Aware Firewall** (sentinel-engine) — 9 constraint operators, fail-closed
2. **Canonical Disconnect Fix** (sentinel-canonical) — policies use proper types
3. **Tamper-Evident Audit** (sentinel-audit) — SHA-256 hash chain
4. **Approval Backend** (sentinel-approval) — full CRUD + expiry workflow
5. **MCP Stdio Proxy** (sentinel-mcp + sentinel-proxy) — stdio bridge with policy enforcement

### Workspace: 10 crates
sentinel-types, sentinel-engine, sentinel-audit, sentinel-mcp, sentinel-canonical, sentinel-config, sentinel-integration, sentinel-server, sentinel-approval, sentinel-proxy

### Build: clean, 128 test suites, 0 failures

### What may need attention next
- CI/CD pipeline (`.github/workflows/ci.yml`) — Instance A was assigned but status unknown
- End-to-end integration tests for the full approval flow
- Documentation / usage examples
- Security audit of the constraint operators (path traversal edge cases)
- Performance benchmarking with large policy sets
- MCP proxy end-to-end testing with a real MCP server
