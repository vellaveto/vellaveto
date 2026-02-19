# Tool Discovery and Usage Plan Status

Last verified: 2026-02-19

This document tracks the implementation status of the Tool Discovery and Model Projector plan
defined in `ROADMAP.md` (Phase 34 and Phase 35) and maps each exit criterion to code evidence.

## Source of Truth

- Plan and exit criteria: `ROADMAP.md` (Phase 34, Phase 35)
- Discovery API handlers: `vellaveto-server/src/routes/discovery.rs`
- Projector API handlers: `vellaveto-server/src/routes/projector.rs`
- Discovery engine: `vellaveto-mcp/src/discovery/engine.rs`
- Projector core: `vellaveto-mcp/src/projector/mod.rs`

## Phase 34: Tool Discovery Service

| Exit criterion | Status | Evidence |
|---|---|---|
| TF-IDF index ingests MCP `tools/list` responses | Complete | `vellaveto-mcp/src/discovery/engine.rs` (`ingest_tools_list`) |
| Natural-language ranked search with relevance scores | Complete | `vellaveto-mcp/src/discovery/index.rs` (`search`), `vellaveto-mcp/src/discovery/engine.rs` (`discover`) |
| Policy filtering closure excludes unauthorized tools | Complete | `vellaveto-mcp/src/discovery/engine.rs` (`discover` with `policy_filter`) |
| Token budget enforcement for schema payloads | Complete | `vellaveto-mcp/src/discovery/engine.rs` (`token_budget` handling), `vellaveto-server/src/routes/discovery.rs` (input bounds) |
| Session lifecycle discover/use/expire/re-discover | Complete | `vellaveto-http-proxy/src/session.rs` (`record_discovered_tools`, `mark_tool_used`, `is_tool_discovery_expired`, `evict_expired_discoveries`) |
| REST API with input validation | Complete | `vellaveto-server/src/routes/discovery.rs` |
| SDK methods in Python, TypeScript, and Go | Complete | `sdk/python/vellaveto/client.py`, `sdk/typescript/src/client.ts`, `sdk/go/sentinel.go` |
| Feature-gated behavior | Complete | `vellaveto-server/Cargo.toml`, `vellaveto-http-proxy/Cargo.toml`, `vellaveto-mcp/Cargo.toml` |

## Phase 35: Model Projector

| Exit criterion | Status | Evidence |
|---|---|---|
| `ModelProjection` trait with 5 built-in model implementations | Complete | `vellaveto-mcp/src/projector/mod.rs`, `vellaveto-mcp/src/projector/claude.rs`, `vellaveto-mcp/src/projector/openai.rs`, `vellaveto-mcp/src/projector/deepseek.rs`, `vellaveto-mcp/src/projector/qwen.rs`, `vellaveto-mcp/src/projector/generic.rs` |
| `ProjectorRegistry` with concurrent lookup/registration | Complete | `vellaveto-mcp/src/projector/mod.rs` |
| Schema compression strategies | Complete | `vellaveto-mcp/src/projector/compress.rs` |
| Call repair (coercion/defaults/fuzzy) | Complete | `vellaveto-mcp/src/projector/repair.rs` |
| REST API for model listing and schema projection | Complete | `vellaveto-server/src/routes/projector.rs` |
| Feature-gated behavior | Complete | `vellaveto-server/Cargo.toml`, `vellaveto-http-proxy/Cargo.toml`, `vellaveto-mcp/Cargo.toml` |

## Documentation Closure (this cycle)

- Added full API docs for discovery/projector endpoints in `docs/API.md`.
- Added discovery/projector quick usage examples in `README.md`.
- Synced SDK API tables with implemented methods:
  - `sdk/python/README.md`
  - `sdk/go/README.md`

## Verification Commands (this cycle)

```bash
cargo test -p vellaveto-server discovery -- --nocapture
cargo test -p vellaveto-server projector -- --nocapture
```

All targeted tests passed in this audit cycle.
