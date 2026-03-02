# Vellaveto Policy Presets

Ready-to-use policy configurations. Pick a protection level to get started instantly, or choose a professional preset for your specific deployment scenario.

Every policy includes plain-language threat explanations — open any `.toml` file to understand exactly what it defends against and why.

## Protection Levels (Easy Mode)

Three built-in protection tiers, usable without a config file via `--protect`:

```bash
vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp
vellaveto-proxy --protect fortress -- python -m mcp_server
vellaveto-proxy --protect vault -- ./my-server
```

| Level | Policies | Default | What it defends against |
|-------|---------|---------|------------------------|
| [`shield`](shield.toml) | 8 | Allow | Credential theft, SANDWORM AI config injection, data exfiltration, git hook persistence, system file tampering, dangerous commands; approval gates for destructive git ops |
| [`fortress`](fortress.toml) | 11 | Allow | Everything in Shield + package registry hijacking, privilege escalation, memory poisoning, shadow agent detection |
| [`vault`](vault.toml) | 11 | **Deny** | Everything — nothing runs without permission. Source reads + git reads allowed; file writes require human approval |

### Shield vs Fortress vs Vault — which one?

- **Shield** if you want protection without friction. Your AI assistant works normally, but credential theft, supply chain attacks, and exfiltration are blocked.
- **Fortress** if you want deeper supply chain defense. Adds package config tampering protection (npm/pip/cargo registry hijacking), sudo approval, and memory poisoning detection.
- **Vault** if you're working with sensitive code or untrusted MCP servers. Nothing executes without your explicit approval — but source reading and safe git commands work out of the box.

## Professional Presets

For specific deployment scenarios. Use with `--preset <NAME>`:

### Development & CI

| Preset | Policies | Defends against | Default |
|--------|---------|-----------------|---------|
| [`dev-laptop`](dev-laptop.toml) | 9 | Credential theft, SANDWORM, exfiltration, git hooks, system files, package configs, dangerous commands | Allow |
| [`ci-agent`](ci-agent.toml) | 7 | Supply chain attacks, credential theft, SANDWORM, git hook persistence, exfil domains; strict network allowlist (approved registries only) | Allow |
| [`code-review-agent`](code-review-agent.toml) | — | Unauthorized writes, credential theft; read-only access to source and git history | **Deny** |
| [`devops-agent`](devops-agent.toml) | 11 | Credential theft, unauthorized secret writes, namespace/cluster deletion, unreviewed production changes, unreviewed Terraform apply | **Deny** |

### Data & APIs

| Preset | Policies | Defends against | Default |
|--------|---------|-----------------|---------|
| [`database-agent`](database-agent.toml) | 6 | SQL injection (UNION SELECT, INTO OUTFILE, xp_cmdshell), credential theft, data exfiltration, unreviewed schema changes (ALTER/CREATE require approval) | Allow |
| [`rag-agent`](rag-agent.toml) | — | RAG-specific: vector DB access controls, response scanning | Allow |
| [`api-gateway-agent`](api-gateway-agent.toml) | — | API-specific: domain allowlisting, internal network blocking | Allow |
| [`data-science-agent`](data-science-agent.toml) | — | Notebook/ML: data export restrictions, compute controls | Allow |

### Customer-Facing & Industry

| Preset | Policies | Defends against | Default |
|--------|---------|-----------------|---------|
| [`browser-agent`](browser-agent.toml) | 7 | Credential harvesting, malicious domains, URL shortener phishing (bit.ly, tinyurl), sensitive JS execution (document.cookie, localStorage, keyloggers), download path restrictions | Allow |
| [`customer-support-agent`](customer-support-agent.toml) | — | CRM/ticketing: PII redaction, unauthorized data access | Allow |

### Compliance & Regulated

| Preset | Policies | Defends against | Default |
|--------|---------|-----------------|---------|
| [`compliance-starter`](compliance-starter.toml) | — | All 12 compliance frameworks enabled (EU AI Act, NIS2, DORA, SOC 2, ...) | **Deny** |
| [`financial-agent`](financial-agent.toml) | — | Financial services: DORA/NIS2 controls, strict audit | **Deny** |
| [`healthcare-agent`](healthcare-agent.toml) | — | Healthcare: HIPAA-aligned PHI protection | Allow |

### Security-Hardened

| Preset | Policies | Defends against | Default |
|--------|---------|-----------------|---------|
| [`sandworm-hardened`](sandworm-hardened.toml) | — | Supply-chain worm defense (all 10 defensive layers) | **Deny** |
| [`consumer-shield`](consumer-shield.toml) | — | AI provider data access: PII sanitization, encrypted local audit, session unlinkability | Allow |

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
