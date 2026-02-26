# Vellaveto Reference Architecture — Enterprise Deployment

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enterprise Network                           │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │
│  │ LangChain│   │  CrewAI  │   │ Google   │   │  OpenAI  │    │
│  │  Agent   │   │   Crew   │   │   ADK    │   │  Agents  │    │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘    │
│       │              │              │              │           │
│       └──────────────┴──────┬───────┴──────────────┘           │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  Vellaveto SDK  │                          │
│                    │  (evaluate())   │                          │
│                    └────────┬────────┘                          │
│                             │ HTTP/gRPC                         │
│              ┌──────────────▼──────────────┐                    │
│              │    Load Balancer / Ingress   │                    │
│              └──────────────┬──────────────┘                    │
│                             │                                   │
│  ┌──────────────────────────▼──────────────────────────┐       │
│  │              Vellaveto Cluster (3 nodes)             │       │
│  │                                                      │       │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐    │       │
│  │  │   Node 1   │  │   Node 2   │  │   Node 3   │    │       │
│  │  │  (Leader)  │  │ (Follower) │  │ (Follower) │    │       │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │       │
│  │        │               │               │            │       │
│  │        └───────────────┼───────────────┘            │       │
│  │                        │                            │       │
│  └────────────────────────┼────────────────────────────┘       │
│                           │                                     │
│           ┌───────────────┼───────────────┐                    │
│           │               │               │                    │
│     ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐              │
│     │PostgreSQL │  │   OTEL    │  │  Identity │              │
│     │  (Audit)  │  │ Collector │  │ Provider  │              │
│     └───────────┘  └───────────┘  │(Okta/AAD) │              │
│                                    └───────────┘              │
│                                                                 │
│  ┌──────────────────────────────┐                              │
│  │     Admin Console (SPA)      │                              │
│  │  https://vellaveto.internal  │                              │
│  └──────────────────────────────┘                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Vellaveto Cluster
- **3-node minimum** for HA (leader election via Raft-style protocol)
- **Stateless evaluation** — any node can handle any request
- **Shared audit store** — PostgreSQL for durable audit trail
- **Resource requirements:** 2 CPU + 1 GB RAM per node

### 2. SDKs & Integrations
- **Python SDK** — LangChain, LangGraph, CrewAI, Google ADK, OpenAI Agents, Composio
- **Java SDK** — Enterprise Java applications (Spring Boot, Quarkus)
- **TypeScript SDK** — Node.js agents
- **Go SDK** — Go agents + Terraform provider
- **Evaluation latency:** < 5ms P99

### 3. PostgreSQL (Audit Store)
- Stores all audit entries with tamper-evident chain (SHA-256 + Merkle)
- Ed25519 signed checkpoints
- Zero-knowledge proofs (Pedersen + Groth16)
- **Sizing:** ~100 bytes/entry, ~8.6 GB/day at 1M evals/day

### 4. Identity Provider
- OIDC: Okta, Azure AD/Entra ID, Keycloak, Auth0
- SAML 2.0: Legacy enterprise IdPs
- SCIM 2.0: Auto-provisioning users from IdP

### 5. Admin Console
- React SPA served by Vellaveto server
- RBAC: Admin, Operator, Auditor, Viewer
- Real-time verdict stream, audit viewer, compliance dashboards

## Network Security

### Firewall Rules

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| AI Agents | Vellaveto LB | 3000/443 | HTTPS | Policy evaluation |
| Vellaveto | PostgreSQL | 5432 | TCP | Audit persistence |
| Vellaveto | OTEL Collector | 4317 | gRPC | Telemetry |
| Vellaveto | Identity Provider | 443 | HTTPS | OIDC/SAML auth |
| Admin Browser | Vellaveto LB | 443 | HTTPS | Admin console |
| Vellaveto nodes | Vellaveto nodes | 7946 | TCP/UDP | Cluster gossip |

### TLS Configuration
- TLS 1.2+ required for all external connections
- mTLS optional for inter-node communication
- Certificate rotation via K8s cert-manager or manual

## Multi-Tenancy

```
┌─────────────────────────────────────────┐
│            Vellaveto Cluster             │
│                                         │
│  ┌─────────────┐  ┌─────────────┐      │
│  │  Tenant A   │  │  Tenant B   │      │
│  │  (Policies) │  │  (Policies) │      │
│  │  (Audit)    │  │  (Audit)    │      │
│  │  (Quotas)   │  │  (Quotas)   │      │
│  └─────────────┘  └─────────────┘      │
│                                         │
│  Isolation: per-tenant policies,        │
│  audit, quotas, RBAC                    │
└─────────────────────────────────────────┘
```

- Each tenant has isolated policies, audit trails, and usage quotas
- Tenant ID propagated via `X-Tenant-ID` header or JWT claim
- Cross-tenant access is forbidden at the engine level

## Scaling Guidelines

| Metric | Single Node | 3-Node Cluster | 5-Node Cluster |
|--------|-------------|----------------|----------------|
| Evals/sec | 10,000 | 30,000 | 50,000 |
| Agents | 50 | 150 | 250 |
| Policies | 1,000 | 1,000 | 1,000 |
| Tenants | 10 | 50 | 100 |
| Audit retention | 30 days | 90 days | 1 year |
