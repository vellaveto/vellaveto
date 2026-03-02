# Examples

Runnable examples and reference configurations for Vellaveto.

## Quick Start Examples

| Example | Language | Description |
|---------|----------|-------------|
| [langchain-agent/](langchain-agent/) | Python | LangChain agent with credential protection and exfiltration prevention (7 scenarios) |
| [demo-exfil-attack.sh](demo-exfil-attack.sh) | Bash | Simulated data exfiltration attack against a running Vellaveto instance |
| [github-action-policy-check.yml](github-action-policy-check.yml) | YAML | CI/CD workflow that validates policies on every pull request |

## Policy Configurations

| File | Description |
|------|-------------|
| [default.toml](default.toml) | Balanced default policy — credential blocking, injection detection, DLP, default allow |
| [production.toml](production.toml) | Production-hardened policy with strict network controls |
| [credential-exfil-demo.toml](credential-exfil-demo.toml) | Demo policy for the exfiltration attack script |
| [mcp-2025-11-25.toml](mcp-2025-11-25.toml) | MCP 2025-11-25 spec-compliant configuration |
| [phase2-threat-detection.toml](phase2-threat-detection.toml) | Advanced threat detection (collusion, anomaly, drift) |

## Policy Presets

Ready-to-use presets for the `vellaveto-proxy --preset <NAME>` or `--protect <LEVEL>` flags. See [presets/README.md](presets/README.md) for the full list of 17 presets across 3 protection levels.

```bash
# One-liner protection
vellaveto-proxy --protect shield -- your-mcp-server

# Specific preset
vellaveto-proxy --preset ci-agent -- your-mcp-server
```

## SDK Examples

- **Go SDK:** [sdk/go/examples/](../sdk/go/examples/) — basic client usage + HTTP middleware pattern
- **Python SDK:** See [sdk/python/README.md](../sdk/python/README.md) for LangChain, LangGraph, async, and callback handler patterns
- **TypeScript SDK:** See [sdk/typescript/README.md](../sdk/typescript/README.md) for Claude Agent SDK integration and async patterns

## Reference Files

| File | Description |
|------|-------------|
| [approvals.jsonl](approvals.jsonl) | Sample approval request format |
| [AGENTS.md](AGENTS.md) | Multi-agent orchestration patterns |

## Next Steps

- [Policy Cookbook](../docs/POLICY_COOKBOOK.md) — 8 copy-paste-ready TOML recipes
- [Quick Start Guide](../docs/QUICKSTART.md) — Full setup walkthrough
- [Threat Model](../docs/THREAT_MODEL.md) — Attack scenarios Vellaveto defends against
