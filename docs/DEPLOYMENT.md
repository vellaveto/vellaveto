# Sentinel Deployment Guide

This guide covers deploying Sentinel in production environments using Docker, Kubernetes (Helm), or bare metal installations.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
  - [Single Container](#single-container)
  - [Docker Compose](#docker-compose)
- [Kubernetes Deployment](#kubernetes-deployment)
  - [Using Helm](#using-helm)
  - [Custom Values](#custom-values)
  - [High Availability](#high-availability)
- [Bare Metal Deployment](#bare-metal-deployment)
  - [Building from Source](#building-from-source)
  - [Systemd Service](#systemd-service)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Policy Configuration](#policy-configuration)
- [Health Checks](#health-checks)
- [TLS/HTTPS](#tlshttps)
- [Production Checklist](#production-checklist)

---

## Prerequisites

### Hardware Requirements

| Deployment | CPU | Memory | Disk |
|------------|-----|--------|------|
| Minimum | 1 core | 64 MB | 100 MB |
| Recommended | 2 cores | 128 MB | 1 GB |
| High-traffic | 4+ cores | 256 MB | 10 GB |

Sentinel is designed for low resource usage: <5ms P99 evaluation latency and <50MB memory baseline.

### Software Requirements

- **Docker**: 20.10+ (for containerized deployment)
- **Kubernetes**: 1.25+ with Helm 3.10+ (for K8s deployment)
- **Rust**: 1.82+ (for building from source)

---

## Quick Start

The fastest way to get Sentinel running:

```bash
# Using Docker
docker run -p 3000:3000 ghcr.io/paolovella/sentinel:latest

# Test the health endpoint
curl http://localhost:3000/health
```

---

## Docker Deployment

### Single Container

#### Pull and Run

```bash
# Pull the latest image
docker pull ghcr.io/paolovella/sentinel:latest

# Run with default configuration
docker run -d \
  --name sentinel \
  -p 3000:3000 \
  ghcr.io/paolovella/sentinel:latest

# Run with custom configuration
docker run -d \
  --name sentinel \
  -p 3000:3000 \
  -v /path/to/config.toml:/etc/sentinel/config.toml:ro \
  -v /path/to/policies:/etc/sentinel/policies:ro \
  -v sentinel-data:/var/lib/sentinel \
  ghcr.io/paolovella/sentinel:latest
```

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/paolovella/sentinel.git
cd sentinel

# Build the Docker image
docker build -t sentinel:local .

# Run your local build
docker run -d \
  --name sentinel \
  -p 3000:3000 \
  sentinel:local
```

### Docker Compose

Create a `docker-compose.yml`:

```yaml
version: "3.8"

services:
  sentinel:
    image: ghcr.io/paolovella/sentinel:latest
    container_name: sentinel
    ports:
      - "3000:3000"
    volumes:
      - ./config.toml:/etc/sentinel/config.toml:ro
      - ./policies:/etc/sentinel/policies:ro
      - sentinel-data:/var/lib/sentinel
      - sentinel-logs:/var/log/sentinel
    environment:
      - RUST_LOG=info
      - SENTINEL_STRICT_MODE=true
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    # Security: run as non-root
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp

volumes:
  sentinel-data:
  sentinel-logs:
```

With Redis for clustering:

```yaml
version: "3.8"

services:
  sentinel:
    image: ghcr.io/paolovella/sentinel:latest
    ports:
      - "3000:3000"
    volumes:
      - ./config.toml:/etc/sentinel/config.toml:ro
    environment:
      - RUST_LOG=info
      - SENTINEL_CLUSTER_ENABLED=true
      - SENTINEL_REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  redis-data:
```

---

## Kubernetes Deployment

### Using Helm

```bash
# Add the Helm repository (if published)
# helm repo add sentinel https://charts.sentinel.dev
# helm repo update

# Or install from local chart
helm install sentinel ./helm/sentinel \
  --namespace sentinel \
  --create-namespace

# Check deployment status
kubectl -n sentinel get pods
kubectl -n sentinel get svc
```

### Custom Values

Create a `values-production.yaml`:

```yaml
# Production values for Sentinel

replicaCount: 3

image:
  repository: ghcr.io/paolovella/sentinel
  tag: "1.0.0"
  pullPolicy: IfNotPresent

# Resource limits
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 64Mi

# Enable autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1s"
  hosts:
    - host: sentinel.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentinel-tls
      hosts:
        - sentinel.example.com

# Sentinel configuration
sentinel:
  logLevel: info
  strictMode: true

  injection:
    enabled: true
    blocking: true

  dlp:
    enabled: true
    blocking: true

  audit:
    redactionLevel: "High"

# Enable Prometheus metrics
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s
    labels:
      release: prometheus

# Pod disruption budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# Anti-affinity for HA
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: sentinel
          topologyKey: kubernetes.io/hostname
```

Deploy with custom values:

```bash
helm upgrade --install sentinel ./helm/sentinel \
  --namespace sentinel \
  --create-namespace \
  -f values-production.yaml
```

### High Availability

For HA deployments, enable clustering with Redis:

```yaml
# values-ha.yaml

replicaCount: 3

sentinel:
  cluster:
    enabled: true
    backend: redis
    redisUrl: redis://redis-master.redis.svc.cluster.local:6379

# External Redis (use Bitnami chart or managed Redis)
redis:
  enabled: false  # Use external Redis
```

Deploy Redis first (example using Bitnami):

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install redis bitnami/redis \
  --namespace sentinel \
  --set auth.enabled=false \
  --set architecture=standalone
```

---

## Bare Metal Deployment

### Building from Source

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/paolovella/sentinel.git
cd sentinel

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls -la target/release/sentinel
ls -la target/release/sentinel-http-proxy

# Install to system
sudo cp target/release/sentinel /usr/local/bin/
sudo cp target/release/sentinel-http-proxy /usr/local/bin/

# Verify installation
sentinel --version
```

### Directory Structure

```bash
# Create directories
sudo mkdir -p /etc/sentinel
sudo mkdir -p /var/lib/sentinel
sudo mkdir -p /var/log/sentinel

# Create sentinel user
sudo useradd -r -s /sbin/nologin sentinel
sudo chown -R sentinel:sentinel /var/lib/sentinel /var/log/sentinel

# Copy configuration
sudo cp examples/production.toml /etc/sentinel/config.toml
sudo chmod 640 /etc/sentinel/config.toml
```

### Systemd Service

Create `/etc/systemd/system/sentinel.service`:

```ini
[Unit]
Description=Sentinel MCP Tool Firewall
Documentation=https://github.com/paolovella/sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
ExecStart=/usr/local/bin/sentinel serve \
    --config /etc/sentinel/config.toml \
    --bind 0.0.0.0:3000
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sentinel /var/log/sentinel
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Resource limits
MemoryMax=256M
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable sentinel

# Start the service
sudo systemctl start sentinel

# Check status
sudo systemctl status sentinel

# View logs
sudo journalctl -u sentinel -f
```

### HTTP Proxy Mode (Systemd)

Create `/etc/systemd/system/sentinel-http-proxy.service`:

```ini
[Unit]
Description=Sentinel HTTP Proxy
Documentation=https://github.com/paolovella/sentinel
After=network-online.target sentinel.service
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
ExecStart=/usr/local/bin/sentinel-http-proxy \
    --listen 0.0.0.0:3000 \
    --sentinel http://localhost:3000 \
    --upstream http://localhost:9000
Restart=on-failure
RestartSec=5

# Security hardening (same as above)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (trace, debug, info, warn, error) | `info` |
| `SENTINEL_STRICT_MODE` | Deny unknown tools by default | `false` |
| `SENTINEL_CONFIG` | Path to config file | `/etc/sentinel/config.toml` |
| `SENTINEL_BIND` | Listen address | `0.0.0.0:3000` |
| `SENTINEL_API_KEY` | API key for admin endpoints | (none) |
| `SENTINEL_CLUSTER_ENABLED` | Enable distributed clustering | `false` |
| `SENTINEL_REDIS_URL` | Redis URL for clustering | (none) |

### Policy Configuration

Policies can be defined in the config file or loaded from a directory:

```toml
# In config.toml

# Inline policy
[[policies]]
name = "Block credential access"
tool_pattern = "*"
function_pattern = "*"
priority = 300

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny" },
]

# Or load from directory
[policies]
directory = "/etc/sentinel/policies.d"
watch = true  # Hot reload on changes
```

---

## Health Checks

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness check (returns 200 if running) |
| `/ready` | GET | Readiness check (returns 200 if ready to serve) |
| `/metrics` | GET | Prometheus metrics |

### Example Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/sentinel-healthcheck.sh

set -e

SENTINEL_URL="${SENTINEL_URL:-http://localhost:3000}"

# Check health endpoint
response=$(curl -s -o /dev/null -w "%{http_code}" "${SENTINEL_URL}/health")

if [ "$response" != "200" ]; then
    echo "Health check failed: HTTP $response"
    exit 1
fi

echo "Sentinel is healthy"
exit 0
```

---

## TLS/HTTPS

Sentinel itself serves plain HTTP. For TLS termination, use a reverse proxy:

For staged post-quantum TLS policy rollout when Sentinel terminates TLS directly, see `./quantum-migration.md`.

### With Nginx

```nginx
# /etc/nginx/conf.d/sentinel.conf

upstream sentinel {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name sentinel.example.com;

    ssl_certificate /etc/ssl/certs/sentinel.crt;
    ssl_certificate_key /etc/ssl/private/sentinel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://sentinel;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
```

### With Caddy

```caddyfile
# Caddyfile

sentinel.example.com {
    reverse_proxy localhost:3000 {
        health_uri /health
        health_interval 30s
    }
}
```

---

## Production Checklist

Before going to production, verify:

### Security
- [ ] API key configured for admin endpoints (`SENTINEL_API_KEY`)
- [ ] Running as non-root user
- [ ] TLS termination configured
- [ ] Audit logging enabled with appropriate redaction
- [ ] Rate limiting configured
- [ ] `strictMode` enabled (deny unknown tools)

### Reliability
- [ ] Health checks configured in orchestrator
- [ ] Restart policy set (systemd `Restart=on-failure` or K8s `restartPolicy`)
- [ ] Resource limits defined
- [ ] Multiple replicas for HA (if using K8s)
- [ ] Redis configured for clustering (if multiple instances)

### Observability
- [ ] Logs shipping to centralized logging
- [ ] Prometheus metrics endpoint exposed
- [ ] Alerts configured for:
  - High error rate
  - Elevated latency (P99 > 10ms)
  - Policy evaluation failures
  - Approval queue depth

### Operations
- [ ] Backup strategy for audit logs
- [ ] Runbook documented for common issues
- [ ] Policy hot-reload tested
- [ ] Rollback procedure documented

### Example Pre-flight Check

```bash
#!/bin/bash
# pre-flight-check.sh

echo "=== Sentinel Pre-flight Check ==="

# Check binary
if ! command -v sentinel &> /dev/null; then
    echo "[FAIL] sentinel binary not found"
    exit 1
fi
echo "[OK] sentinel binary installed"

# Check config
if [ ! -f /etc/sentinel/config.toml ]; then
    echo "[FAIL] Config file not found"
    exit 1
fi
echo "[OK] Config file exists"

# Validate config
if ! sentinel validate --config /etc/sentinel/config.toml; then
    echo "[FAIL] Config validation failed"
    exit 1
fi
echo "[OK] Config is valid"

# Check directories
for dir in /var/lib/sentinel /var/log/sentinel; do
    if [ ! -d "$dir" ]; then
        echo "[FAIL] Directory $dir not found"
        exit 1
    fi
    if [ ! -w "$dir" ]; then
        echo "[FAIL] Directory $dir not writable"
        exit 1
    fi
done
echo "[OK] Data directories exist and are writable"

# Check API key
if [ -z "$SENTINEL_API_KEY" ]; then
    echo "[WARN] SENTINEL_API_KEY not set - admin endpoints unprotected"
else
    echo "[OK] API key configured"
fi

echo ""
echo "=== All checks passed ==="
```

---

## Next Steps

- [Operations Runbook](./OPERATIONS.md) - Monitoring, troubleshooting, maintenance
- [Security Hardening Guide](./SECURITY.md) - Advanced security configuration
- [API Reference](./API.md) - Complete API documentation
