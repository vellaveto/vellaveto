# Sentinel Policy Presets

Curated policy configurations for common agent deployment scenarios. Each preset is a complete, ready-to-use configuration.

## Available Presets

| Preset | Use Case | Default Posture |
|--------|----------|-----------------|
| [`dev-laptop.toml`](dev-laptop.toml) | AI coding assistants (Cursor, Claude Code, Copilot) | Allow with credential protection |
| [`ci-agent.toml`](ci-agent.toml) | CI/CD pipeline agents (GitHub Actions, GitLab CI) | Allow with strict network controls |
| [`rag-agent.toml`](rag-agent.toml) | RAG agents (vector DB, search, document retrieval) | Allow with exfiltration prevention |
| [`database-agent.toml`](database-agent.toml) | Database agents (PostgreSQL, MySQL, MongoDB) | Allow with destructive DDL gating |
| [`browser-agent.toml`](browser-agent.toml) | Browser automation (Playwright, Puppeteer) | Allow with domain blocking |

## Quick Start

```bash
# Start Sentinel with a preset
sentinel serve --config examples/presets/dev-laptop.toml --port 3000

# Or with Docker
docker run -p 3000:3000 \
  -v ./examples/presets/ci-agent.toml:/etc/sentinel/config.toml:ro \
  ghcr.io/paolovella/sentinel:latest
```

## Customizing Presets

Each preset is a starting point. Common customizations:

1. **Add your domains** to `allowed_domains` in network rules
2. **Adjust priority values** (higher = evaluated first)
3. **Change `require_approval` to `deny`** for fully automated environments
4. **Enable/disable DLP** based on data sensitivity
5. **Set `blocking = true`** on injection detection for high-security environments

See the [production example](../production.toml) for a comprehensive configuration with all features enabled.
