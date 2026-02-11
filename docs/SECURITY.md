# Sentinel Security Hardening Guide

This guide covers security best practices and hardening configurations for production Sentinel deployments.

## Table of Contents

- [Security Principles](#security-principles)
- [Authentication & Authorization](#authentication--authorization)
  - [API Key Authentication](#api-key-authentication)
  - [OAuth 2.1 / JWT](#oauth-21--jwt)
  - [RBAC Configuration](#rbac-configuration)
- [Network Security](#network-security)
  - [TLS Configuration](#tls-configuration)
  - [Firewall Rules](#firewall-rules)
  - [DNS Rebinding Protection](#dns-rebinding-protection)
- [Policy Hardening](#policy-hardening)
  - [Strict Mode](#strict-mode)
  - [Credential Protection](#credential-protection)
  - [Network Allowlisting](#network-allowlisting)
  - [Command Restrictions](#command-restrictions)
- [Detection & Prevention](#detection--prevention)
  - [Injection Scanning](#injection-scanning)
  - [DLP Configuration](#dlp-configuration)
  - [Rug-Pull Detection](#rug-pull-detection)
  - [Behavioral Anomaly Detection](#behavioral-anomaly-detection)
- [Audit & Compliance](#audit--compliance)
  - [Audit Log Configuration](#audit-log-configuration)
  - [PII Redaction](#pii-redaction)
  - [Log Integrity](#log-integrity)
- [Runtime Security](#runtime-security)
  - [Container Hardening](#container-hardening)
  - [Systemd Hardening](#systemd-hardening)
  - [Resource Limits](#resource-limits)
- [Supply Chain Security](#supply-chain-security)
  - [Binary Verification](#binary-verification)
  - [MCP Server Pinning](#mcp-server-pinning)
- [Security Checklist](#security-checklist)

---

## Security Principles

Sentinel follows these security principles:

1. **Fail-Closed**: Errors, missing policies, and unresolved context produce `Deny`, never `Allow`.
2. **Defense in Depth**: Multiple layers of security controls.
3. **Least Privilege**: Minimal permissions for the Sentinel process.
4. **Observability**: All decisions logged, all failures diagnosed.
5. **Zero Trust**: Validate every request, authenticate every caller.

---

## Authentication & Authorization

### API Key Authentication

For simple deployments, use API key authentication for admin endpoints.

```bash
# Generate a secure API key
export SENTINEL_API_KEY=$(openssl rand -hex 32)

# Store securely
echo "SENTINEL_API_KEY=$SENTINEL_API_KEY" >> /etc/sentinel/env
chmod 600 /etc/sentinel/env
```

Configure in systemd:

```ini
[Service]
EnvironmentFile=/etc/sentinel/env
```

Test authentication:

```bash
# Without key - should fail
curl localhost:3000/api/policies
# Response: 401 Unauthorized

# With key - should succeed
curl -H "Authorization: Bearer $SENTINEL_API_KEY" localhost:3000/api/policies
```

### OAuth 2.1 / JWT

For enterprise deployments, use OAuth 2.1 with JWT tokens.

```toml
# config.toml

[auth]
enabled = true
provider = "oauth2"

[auth.oauth2]
issuer = "https://auth.example.com"
audience = "sentinel-api"
jwks_url = "https://auth.example.com/.well-known/jwks.json"

# Required scopes for different operations
[auth.oauth2.scopes]
evaluate = ["sentinel:evaluate"]
admin = ["sentinel:admin"]
read = ["sentinel:read"]
```

JWT token requirements:
- **Algorithm**: RS256 or ES256 (never HS256 in production)
- **Expiry**: Short-lived tokens (< 1 hour)
- **Audience**: Must match configured audience
- **Issuer**: Must match configured issuer

### RBAC Configuration

Define roles for fine-grained access control:

```toml
# config.toml

[rbac]
enabled = true

[[rbac.roles]]
name = "evaluator"
permissions = ["evaluate"]

[[rbac.roles]]
name = "operator"
permissions = ["evaluate", "read_audit", "manage_approvals"]

[[rbac.roles]]
name = "admin"
permissions = ["evaluate", "read_audit", "manage_approvals", "manage_policies", "manage_config"]

# Map JWT claims to roles
[rbac.claim_mapping]
claim = "roles"  # JWT claim containing roles
mapping = { "sentinel-evaluator" = "evaluator", "sentinel-operator" = "operator", "sentinel-admin" = "admin" }
```

---

## Network Security

### TLS Configuration

Always terminate TLS in front of Sentinel. Use a reverse proxy with strong TLS settings.

#### Nginx Configuration

```nginx
# /etc/nginx/conf.d/sentinel.conf

server {
    listen 443 ssl http2;
    server_name sentinel.example.com;

    # TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting
        limit_req zone=sentinel burst=50 nodelay;
    }
}

# Rate limit zone
limit_req_zone $binary_remote_addr zone=sentinel:10m rate=100r/s;
```

### Firewall Rules

Restrict network access to Sentinel:

```bash
# Allow only internal network to access Sentinel
sudo ufw allow from 10.0.0.0/8 to any port 3000

# Allow only specific IPs for admin endpoints
sudo iptables -A INPUT -p tcp --dport 3000 -s 10.0.0.10 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3000 -s 10.0.0.11 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3000 -j DROP
```

For Kubernetes:

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sentinel-network-policy
spec:
  podSelector:
    matchLabels:
      app: sentinel
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ai-agents
        - podSelector:
            matchLabels:
              role: ai-agent
      ports:
        - protocol: TCP
          port: 3000
```

### DNS Rebinding Protection

Prevent DNS rebinding attacks where a public domain resolves to private IPs:

```toml
# config.toml

[[policies]]
name = "DNS rebinding protection"
tool_pattern = "http_request"
function_pattern = "*"
policy_type = "Allow"
priority = 240

[policies.network_rules.ip_rules]
# Block all private IP ranges
block_private = true

# Also block carrier-grade NAT
blocked_cidrs = [
  "100.64.0.0/10",   # CGN
  "169.254.0.0/16",  # Link-local
  "192.0.0.0/24",    # IETF protocol assignments
]

# Allow specific internal services if needed
allowed_cidrs = [
  "10.0.1.100/32",   # Internal API gateway
]
```

---

## Policy Hardening

### Strict Mode

Enable strict mode to deny unknown tools by default:

```bash
# Environment variable
export SENTINEL_STRICT_MODE=true

# Or in config.toml
[sentinel]
strict_mode = true
```

In strict mode:
- Tools not matched by any policy are denied
- New tools require explicit policy before use
- Provides defense against tool injection

### Credential Protection

Block access to credential files and secrets:

```toml
# config.toml

[[policies]]
name = "Block credential file access"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "*:*:credential-block"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # SSH keys
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/root/.ssh/**", on_match = "deny", on_missing = "skip" },

  # Cloud credentials
  { param = "*", op = "glob", pattern = "/home/*/.aws/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.gcp/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.azure/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.kube/config", on_match = "deny", on_missing = "skip" },

  # Environment files
  { param = "*", op = "glob", pattern = "**/.env*", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials*", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets*", on_match = "deny", on_missing = "skip" },

  # System files
  { param = "*", op = "glob", pattern = "/etc/shadow", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/etc/passwd", on_match = "deny", on_missing = "skip" },
]
```

### Network Allowlisting

Restrict outbound network access to approved domains:

```toml
# config.toml

[[policies]]
name = "Block known exfiltration domains"
tool_pattern = "*"
function_pattern = "*"
priority = 280

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # Tunneling services
  { param = "*", op = "domain_match", pattern = "*.ngrok.io", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.ngrok-free.app", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.serveo.net", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.localtunnel.me", on_match = "deny", on_missing = "skip" },

  # Pastebins
  { param = "*", op = "domain_match", pattern = "*.pastebin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.hastebin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.ghostbin.com", on_match = "deny", on_missing = "skip" },

  # File sharing
  { param = "*", op = "domain_match", pattern = "*.transfer.sh", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.file.io", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.wetransfer.com", on_match = "deny", on_missing = "skip" },

  # Request catchers
  { param = "*", op = "domain_match", pattern = "*.requestbin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.pipedream.net", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.webhook.site", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.burpcollaborator.net", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "HTTP domain allowlist"
tool_pattern = "http_request"
function_pattern = "*"
priority = 250

[policies.policy_type.Conditional.conditions]
on_no_match = "deny"  # Deny if not in allowlist
parameter_constraints = [
  { param = "url", op = "domain_in", patterns = [
    "api.github.com",
    "*.googleapis.com",
    "api.openai.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
    "*.internal.example.com",
  ], on_match = "allow" },
]
```

### Command Restrictions

Require approval for dangerous commands:

```toml
# config.toml

[[policies]]
name = "Dangerous commands require approval"
tool_pattern = "bash"
function_pattern = "execute"
priority = 200

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # Destructive file operations
  { param = "command", op = "regex", pattern = "(?i)(rm\\s+-rf|rm\\s+-r\\s+/|shred|wipe)", on_match = "require_approval" },

  # Disk operations
  { param = "command", op = "regex", pattern = "(?i)(dd\\s+if=|mkfs|fdisk|wipefs)", on_match = "require_approval" },

  # Network exfiltration
  { param = "command", op = "regex", pattern = "(?i)(curl.*\\|.*sh|wget.*\\|.*bash|nc\\s+-e)", on_match = "deny" },
]

[[policies]]
name = "Block privilege escalation"
tool_pattern = "bash"
function_pattern = "execute"
priority = 190

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "command", op = "regex", pattern = "(?i)(^sudo\\s|\\bsu\\s+-|\\bchmod\\s+[0-7]*s|\\bchown\\s+root)", on_match = "deny" },
  { param = "command", op = "regex", pattern = "(?i)(\\busermod\\s|\\bpasswd\\s|\\bvisudo)", on_match = "deny" },
]
```

---

## Detection & Prevention

### Injection Scanning

Enable and configure injection detection:

```toml
# config.toml

[injection]
enabled = true
block_on_injection = true  # Block detected injections

# Additional patterns to detect
extra_patterns = [
  "ignore previous instructions",
  "you are now",
  "new system prompt",
  "forget everything",
  "disregard all",
  "transfer funds",
  "send cryptocurrency",
  "execute malicious",
]

# Patterns to exclude (false positives)
disabled_patterns = []

# Unicode normalization (prevents homoglyph attacks)
normalize_unicode = true
```

### DLP Configuration

Enable Data Loss Prevention scanning:

```toml
# config.toml

[dlp]
enabled = true
block_on_finding = true  # Block requests/responses with sensitive data
scan_requests = true     # Scan outgoing data
scan_responses = true    # Scan incoming data

# Default patterns: credit cards, SSNs, API keys, etc.
# Add custom patterns:
[[dlp.custom_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
severity = "medium"

[[dlp.custom_patterns]]
name = "internal_api_key"
pattern = "sk-internal-[a-zA-Z0-9]{32}"
severity = "high"

# Decode layers (catches encoded secrets)
[dlp.decoding]
enabled = true
layers = ["base64", "url", "unicode"]
max_decode_depth = 5
```

### Rug-Pull Detection

Pin tool schemas to detect unauthorized changes:

```toml
# config.toml

[manifest]
enabled = true
enforcement = "Block"  # "Warn" or "Block"
require_signature = false

# Path to store manifest
manifest_path = "/etc/sentinel/manifest.json"

# For signed manifests (optional)
# trusted_keys = ["hex-encoded-ed25519-public-key"]
```

On first run, Sentinel captures tool schemas. On subsequent runs, any schema changes trigger alerts or blocks.

### Behavioral Anomaly Detection

Detect unusual agent behavior:

```toml
# config.toml

[behavioral]
enabled = true

# EMA smoothing factor (0.0, 1.0] - lower = slower adaptation
alpha = 0.2

# Flag when current count >= threshold * baseline
threshold = 10.0

# Minimum sessions before alerting (cold start protection)
min_sessions = 5

# Memory limits
max_tools_per_agent = 500
max_agents = 10000
```

This detects anomalies like:
- Agent suddenly making 100x more file reads than normal
- Tool usage patterns changing dramatically
- Unusual tool combinations

---

## Audit & Compliance

### Audit Log Configuration

Configure comprehensive audit logging:

```toml
# config.toml

[audit]
enabled = true
path = "/var/lib/sentinel/audit.log"

# Log every decision, not just denials
log_allows = true

# Include request/response bodies (with redaction)
log_bodies = true

# Hash chain for tamper detection
hash_chain = true

# Ed25519 checkpoints
checkpoint_interval = 1000  # entries
checkpoint_signature = true
```

### PII Redaction

Configure automatic PII redaction:

```toml
# config.toml

[audit]
# Redaction levels:
# - "Off": No redaction
# - "KeysOnly": Redact values for keys like "password", "token", "secret"
# - "KeysAndPatterns": Above + pattern matching (emails, SSNs, cards)
# - "High": Aggressive redaction including partial data masking
redaction_level = "KeysAndPatterns"

# Custom PII patterns
[[audit.custom_pii_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"

[[audit.custom_pii_patterns]]
name = "customer_id"
pattern = "CUST-[A-Z]{2}\\d{8}"

# Keys to always redact (in addition to defaults)
sensitive_keys = [
  "api_key",
  "access_token",
  "refresh_token",
  "session_id",
  "credit_card",
  "ssn",
  "password",
  "secret",
]
```

### Log Integrity

Verify audit log integrity:

```bash
# Verify hash chain
sentinel audit verify --path /var/lib/sentinel/audit.log

# Verify with checkpoint signatures
sentinel audit verify --path /var/lib/sentinel/audit.log --verify-signatures

# Output:
# Verified 15,234 entries
# Hash chain: valid
# Checkpoints: 15 (all valid)
# Last verified entry: 2026-02-08T10:30:00Z
```

For compliance, export logs to SIEM:

```toml
# config.toml

[audit.export]
enabled = true

# Splunk
[audit.export.splunk]
enabled = true
hec_url = "https://splunk.example.com:8088/services/collector"
hec_token_env = "SPLUNK_HEC_TOKEN"  # Read from environment
source = "sentinel"
sourcetype = "sentinel:audit"

# Elasticsearch
[audit.export.elasticsearch]
enabled = true
url = "https://elastic.example.com:9200"
index = "sentinel-audit"
api_key_env = "ELASTIC_API_KEY"

# Webhook (generic)
[audit.export.webhook]
enabled = true
url = "https://siem.example.com/ingest"
batch_size = 100
batch_interval_secs = 30
```

---

## Runtime Security

### Container Hardening

Use the included Dockerfile which follows security best practices:

```dockerfile
# Key security features in the Dockerfile:

# 1. Multi-stage build (minimal attack surface)
FROM rust:1.82-alpine AS builder
FROM alpine:3.21

# 2. Non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
USER sentinel

# 3. Read-only filesystem (where possible)
# 4. No shell in final image (use alpine for debugging only)
```

Runtime security options:

```bash
docker run -d \
  --name sentinel \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=./seccomp.json \
  -p 3000:3000 \
  sentinel:latest
```

For Kubernetes:

```yaml
# values.yaml

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault

podSecurityContext:
  fsGroup: 1000
```

### Systemd Hardening

The provided systemd service includes comprehensive hardening:

```ini
# /etc/systemd/system/sentinel.service

[Service]
# Run as dedicated user
User=sentinel
Group=sentinel

# Filesystem isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/sentinel /var/log/sentinel

# Kernel protection
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Capability restrictions
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=

# Namespace isolation
PrivateUsers=true
RestrictNamespaces=true

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Network restrictions (if only localhost needed)
# IPAddressDeny=any
# IPAddressAllow=localhost

# Resource limits
MemoryMax=256M
CPUQuota=200%
TasksMax=100
```

### Resource Limits

Configure resource limits to prevent DoS:

```toml
# config.toml

[limits]
# Maximum request body size
max_body_size = "1MB"

# Maximum policy count
max_policies = 10000

# Maximum concurrent evaluations
max_concurrent_evaluations = 1000

# Request timeout
request_timeout_secs = 30
```

Rate limiting:

```toml
[rate_limit]
# Per-endpoint limits
evaluate_rps = 1000
evaluate_burst = 50

admin_rps = 20
admin_burst = 5

readonly_rps = 200
readonly_burst = 20

# Per-IP limits
per_ip_rps = 100
per_ip_burst = 20

# Per-principal limits (authenticated users)
per_principal_rps = 50
per_principal_burst = 10
```

---

## Supply Chain Security

### Binary Verification

Always verify binaries before deployment:

```bash
# Download binary and signature
wget https://github.com/paolovella/sentinel/releases/download/v1.0.0/sentinel-linux-amd64
wget https://github.com/paolovella/sentinel/releases/download/v1.0.0/sentinel-linux-amd64.sha256
wget https://github.com/paolovella/sentinel/releases/download/v1.0.0/sentinel-linux-amd64.sig

# Verify checksum
sha256sum -c sentinel-linux-amd64.sha256

# Verify signature (if GPG signed)
gpg --verify sentinel-linux-amd64.sig sentinel-linux-amd64
```

For container images:

```bash
# Use image digest, not tag
docker pull ghcr.io/paolovella/sentinel@sha256:abc123...

# Verify with cosign (if signed)
cosign verify ghcr.io/paolovella/sentinel:latest
```

### MCP Server Pinning

Pin allowed MCP server binaries by SHA-256 hash:

```toml
# config.toml

[supply_chain]
enabled = true
validate_paths_on_load = true

# Allowed server binaries (path -> expected SHA-256)
[supply_chain.allowed_servers]
"/usr/local/bin/mcp-filesystem" = "a1b2c3d4e5f6..."
"/usr/local/bin/mcp-github" = "f6e5d4c3b2a1..."
"/opt/mcp/custom-server" = "1234567890ab..."
```

Generate hashes:

```bash
sha256sum /usr/local/bin/mcp-*
```

---

## Verified Hardening Backlog (2026-02-11)

This section captures externally researched controls and current implementation status.

### P0
- CI supply-chain hardening pack:
  dependency review on PRs, Dependabot for Cargo/Actions, action SHA pinning,
  build provenance attestations, and SBOM publishing are implemented.
- OAuth sender-constrained token enforcement in HTTP proxy:
  DPoP proof validation is integrated into request authorization path (not only NHI subsystem),
  with explicit failure/replay audit events and dedicated proxy counters.

### P1
- `cargo-deny` dependency policy checks (advisories/bans/sources/licenses) are now wired in CI with a baseline `deny.toml`.
- OPA runtime decision enforcement wiring is active with fail-open/fail-closed controls and runtime metrics.
  Remaining: expand complex-policy integration matrix coverage as architecture split stabilizes.

Status details and rollout progress are tracked in:
- `ROADMAP.md` (active/planned tracks)
- `CHANGELOG.md` (shipped controls)

---

## Security Checklist

Use this checklist before production deployment:

### Authentication & Authorization
- [ ] API key configured for admin endpoints
- [ ] OAuth 2.1 configured (if enterprise)
- [ ] RBAC roles defined
- [ ] Service accounts use minimal permissions

### Network Security
- [ ] TLS termination configured
- [ ] TLS 1.2+ only, strong ciphers
- [ ] Security headers configured
- [ ] Firewall rules restrict access
- [ ] DNS rebinding protection enabled

### Policy Configuration
- [ ] Strict mode enabled
- [ ] Credential file access blocked
- [ ] Exfiltration domains blocked
- [ ] Dangerous commands require approval
- [ ] Default-deny for network access

### Detection & Prevention
- [ ] Injection scanning enabled and blocking
- [ ] DLP scanning enabled
- [ ] Rug-pull detection enabled
- [ ] Behavioral anomaly detection enabled

### Audit & Compliance
- [ ] Audit logging enabled
- [ ] PII redaction configured
- [ ] Hash chain integrity enabled
- [ ] SIEM export configured
- [ ] Log retention policy defined

### Runtime Security
- [ ] Running as non-root user
- [ ] Read-only filesystem where possible
- [ ] Capabilities dropped
- [ ] Resource limits configured
- [ ] Rate limiting enabled

### Supply Chain
- [ ] Binary checksums verified
- [ ] Container images signed/verified
- [ ] MCP server binaries pinned

### Operations
- [ ] Monitoring alerts configured
- [ ] Runbook documented
- [ ] Incident response plan defined
- [ ] Backup procedures tested

---

## Related Documentation

- [Deployment Guide](./DEPLOYMENT.md) - Installation and configuration
- [Operations Runbook](./OPERATIONS.md) - Monitoring and troubleshooting
- [API Reference](./API.md) - Complete API documentation
