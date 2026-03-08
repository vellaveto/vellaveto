# Vellaveto Demo Script — 30-Minute Enterprise Pilot

## Audience
Security architects, CISO teams, compliance officers, AI platform teams.

## Prerequisites
- Vellaveto running (Docker or K8s) — see DEPLOYMENT_GUIDE.md
- `curl` and `jq` installed
- Python 3.9+ with `vellaveto-sdk` installed

---

## Act 1: Deploy & Health Check (5 min)

```bash
# Verify the server is running
curl -s http://localhost:3000/health | jq .
# Expected: {"status":"ok","version":"5.0.0","uptime_secs":...}

# Check loaded policies
curl -s http://localhost:3000/api/policies | jq '.[].name'
```

**Talking points:**
- Sub-5ms P99 latency — doesn't slow down agent execution
- Fail-closed by design — if Vellaveto is unreachable, actions are denied
- 4 transport layers: HTTP, WebSocket, gRPC, stdio

---

## Act 2: Policy Creation (5 min)

```bash
# Create a deny-all baseline
curl -s -X POST http://localhost:3000/api/policies \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "deny-all",
    "name": "Deny All",
    "policy_type": "Deny",
    "priority": 0
  }' | jq .

# Create an allow policy for safe operations
curl -s -X POST http://localhost:3000/api/policies \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "allow-read",
    "name": "Allow Read Operations",
    "policy_type": "Allow",
    "priority": 100,
    "tool_match": {"tools": ["file_read", "web_search", "database_query"]},
    "path_rules": {"allowed_paths": ["/data/**", "/reports/**"]},
    "network_rules": {"allowed_domains": ["*.company.com", "api.openai.com"]}
  }' | jq .
```

**Talking points:**
- Policy-as-code: TOML configs, version controlled, reviewable
- Priorities: higher priority wins on conflict
- Glob patterns for paths, wildcard subdomains for network rules

---

## Act 3: Tool Call Evaluation (5 min)

```bash
# Test 1: Allowed read
curl -s -X POST http://localhost:3000/api/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "tool": "file_read",
    "function": "read",
    "parameters": {"path": "/data/report.csv"},
    "target_paths": ["/data/report.csv"]
  }' | jq .verdict
# Expected: "allow"

# Test 2: Blocked path traversal
curl -s -X POST http://localhost:3000/api/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "tool": "file_read",
    "function": "read",
    "parameters": {"path": "/etc/shadow"},
    "target_paths": ["/etc/shadow"]
  }' | jq .
# Expected: {"verdict":"deny","reason":"..."}

# Test 3: Blocked domain
curl -s -X POST http://localhost:3000/api/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "tool": "web_search",
    "function": "fetch",
    "parameters": {"url": "https://evil.com/exfil"},
    "target_domains": ["evil.com"]
  }' | jq .
# Expected: deny
```

**Talking points:**
- Every decision is logged to the tamper-evident audit trail
- Path traversal attacks (../../etc/passwd) are automatically detected
- DNS rebinding and IP rule enforcement for network security

---

## Act 4: Python SDK Demo (5 min)

```python
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler

client = VellavetoClient(url="http://localhost:3000")

# Direct evaluation
result = client.evaluate(
    tool="database_query",
    function="execute",
    parameters={"query": "SELECT * FROM users"},
    target_domains=["db.company.com"],
)
print(f"Verdict: {result.verdict}")  # allow

# LangChain integration
handler = VellavetoCallbackHandler(
    client=client,
    session_id="demo-session",
    raise_on_deny=True,
)
# Use handler as callback in any LangChain chain/agent
```

**Talking points:**
- 5 SDK languages: Python, Java, TypeScript, Go + Terraform
- Framework integrations: LangChain, LangGraph, CrewAI, Google ADK, OpenAI Agents
- Sync and async Python support

---

## Act 5: Admin Console (5 min)

Open `http://localhost:3000` in a browser.

**Walkthrough:**
1. **Dashboard** — real-time verdict stream, health status, compliance score
2. **Audit Log** — searchable, exportable (JSONL/CEF/CSV), chain verification
3. **Policies** — view, delete, reload from config
4. **Approvals** — pending human-in-the-loop approvals
5. **Compliance** — framework scores with progress bars
6. **Agents** — NHI agent inventory with suspend capability

**Talking points:**
- RBAC: Admin, Operator, Auditor, Viewer roles
- SSO integration: OIDC (Okta, Azure AD) and SAML 2.0
- Dark theme designed for SOC environments

---

## Act 6: Compliance Evidence (5 min)

```bash
# Check compliance status
curl -s http://localhost:3000/api/compliance/status | jq .

# Generate DORA evidence pack
curl -s http://localhost:3000/api/compliance/evidence-pack?framework=dora \
  -o dora-evidence.json
jq '.controls | length' dora-evidence.json
# Expected: 23 controls

# Verify audit chain integrity
curl -s http://localhost:3000/api/audit/verify | jq .
# Expected: {"valid":true,"errors":[]}

# ZK audit proof status
curl -s http://localhost:3000/api/zk/status | jq .
```

**Talking points:**
- 11 mapped frameworks: DORA, NIS2, EU AI Act, ISO 42001, SOC 2, CoSAI, Adversa, OWASP ASI, Singapore MGF, NIST AI 600-1, CSA ATF
- Evidence packs exportable for auditors
- Zero-knowledge proofs for tamper-evident audit without revealing content
- Merkle tree chain verification

---

## Closing (2 min)

**Key differentiators:**
1. **Agent interaction firewall** with 4 transport layers
2. **Deepest compliance coverage** — DORA + NIS2 (unique for EU market)
3. **Zero-knowledge audit** — Pedersen + Groth16 proofs
4. **Formal verification** — TLA+ and Alloy proofs
5. **Multi-tier open core** — MPL-2.0 core, Apache-2.0 benchmark/canary, BUSL-1.1 enterprise

**Next steps:**
- Define pilot scope (3-5 agent workloads)
- Provision sandbox environment
- Configure IdP integration (OIDC/SAML)
- Run compliance gap analysis
- Schedule weekly pilot reviews
