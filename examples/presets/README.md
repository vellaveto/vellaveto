# Vellaveto Policy Presets

Ready-to-use policy configurations. Pick a protection level to get started instantly, or choose a professional preset for your specific deployment scenario.

## Protection Levels (Easy Mode)

Three built-in protection tiers, usable without a config file via `--protect`:

```bash
vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp
vellaveto-proxy --protect fortress -- python -m mcp_server
vellaveto-proxy --protect vault -- ./my-server
```

| Level | Default | What it blocks | For whom |
|-------|---------|----------------|----------|
| [`shield`](shield.toml) | Allow | Credentials (.aws, .ssh, .env, etc.), dangerous commands (rm -rf /, curl\|sh), injection attacks, credential leaks | Anyone — just works |
| [`fortress`](fortress.toml) | Allow | Shield + exfil domains (pastebin, transfer.sh, webhook.site), AI assistant configs (.cursor, .claude), git hooks; approval for destructive ops | Developers who want more |
| [`vault`](vault.toml) | **Deny** | Everything not explicitly allowed | Maximum security |

## Professional Presets

For specific deployment scenarios. Use with `--preset <NAME>`:

### Development & CI

| Preset | Use Case | Default |
|--------|----------|---------|
| [`dev-laptop`](dev-laptop.toml) | AI coding assistants (Cursor, Claude Code, Copilot) | Allow |
| [`ci-agent`](ci-agent.toml) | CI/CD pipelines (GitHub Actions, GitLab CI) | Allow |
| [`code-review-agent`](code-review-agent.toml) | AI code review (read-only source, git history, CI configs) | **Deny** |
| [`devops-agent`](devops-agent.toml) | Infrastructure automation (Terraform, K8s, AWS) | Allow |

### Data & APIs

| Preset | Use Case | Default |
|--------|----------|---------|
| [`database-agent`](database-agent.toml) | Database agents (PostgreSQL, MySQL, MongoDB) | Allow |
| [`rag-agent`](rag-agent.toml) | RAG agents (vector DB, search, document retrieval) | Allow |
| [`api-gateway-agent`](api-gateway-agent.toml) | API integrations with domain allowlisting | Allow |
| [`data-science-agent`](data-science-agent.toml) | Notebooks, ML pipelines, data export controls | Allow |

### Customer-Facing & Industry

| Preset | Use Case | Default |
|--------|----------|---------|
| [`browser-agent`](browser-agent.toml) | Browser automation (Playwright, Puppeteer) | Allow |
| [`customer-support-agent`](customer-support-agent.toml) | CRM/ticketing with PII redaction | Allow |

### Compliance & Regulated

| Preset | Use Case | Default |
|--------|----------|---------|
| [`compliance-starter`](compliance-starter.toml) | All 12 compliance frameworks enabled (EU AI Act, NIS2, DORA, SOC 2, ...) | **Deny** |
| [`financial-agent`](financial-agent.toml) | Financial services (DORA/NIS2 controls) | **Deny** |
| [`healthcare-agent`](healthcare-agent.toml) | Healthcare (HIPAA-aligned PHI protection) | Allow |

### Security-Hardened

| Preset | Use Case | Default |
|--------|----------|---------|
| [`sandworm-hardened`](sandworm-hardened.toml) | Supply-chain worm defense (all 10 layers) | **Deny** |
| [`consumer-shield`](consumer-shield.toml) | User-side PII sanitization, encrypted audit | Allow |

## Customizing

Copy a preset to your project and edit:

```bash
# Generate a starter config from any preset
vellaveto-proxy init --preset fortress -o vellaveto.toml

# Edit it, then use your custom config
vellaveto-proxy --config vellaveto.toml -- ./my-server
```

Common customizations:

1. **Add project-specific Allow rules** (paths, domains, tools)
2. **Adjust priorities** — higher values = evaluated first
3. **Change `require_approval` to `deny`** for fully automated environments
4. **Enable/disable DLP** based on data sensitivity
5. **Add `[shadow_agent]` detection** for multi-agent setups

See the [production example](../production.toml) for a comprehensive configuration with all features enabled.
