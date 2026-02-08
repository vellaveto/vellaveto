# Sentinel API Reference

This document provides a complete reference for the Sentinel HTTP API.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Common Response Formats](#common-response-formats)
- [Endpoints](#endpoints)
  - [Health & Metrics](#health--metrics)
  - [Policy Evaluation](#policy-evaluation)
  - [Policy Management](#policy-management)
  - [Approvals](#approvals)
  - [Audit](#audit)
  - [Tool Registry](#tool-registry)
  - [Tenants](#tenants)
- [Error Codes](#error-codes)

---

## Overview

### Base URL

```
http://localhost:3000
```

### Content Type

All endpoints accept and return JSON:

```
Content-Type: application/json
```

### Rate Limiting

Endpoints are rate-limited. When exceeded, the server returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

Default limits:
- Evaluate endpoint: 1000 req/s (burst: 50)
- Admin endpoints: 20 req/s (burst: 5)
- Read-only endpoints: 200 req/s (burst: 20)

---

## Authentication

### API Key

Include the API key in the `Authorization` header:

```http
Authorization: Bearer <api-key>
```

Example:

```bash
curl -H "Authorization: Bearer $SENTINEL_API_KEY" \
  http://localhost:3000/api/policies
```

### OAuth 2.1 / JWT

When OAuth is configured, use a Bearer JWT token:

```http
Authorization: Bearer <jwt-token>
```

Required JWT claims:
- `iss`: Must match configured issuer
- `aud`: Must match configured audience
- `exp`: Must be in the future
- Scope claims for authorization

---

## Common Response Formats

### Success Response

```json
{
  "data": { ... },
  "meta": {
    "request_id": "req-123"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Human-readable error message",
    "details": { ... }
  }
}
```

### Verdict

All verdict responses include one of:

```json
{ "verdict": { "Allow": {} } }
{ "verdict": { "Deny": { "reason": "blocked by policy: credential-block" } } }
{ "verdict": { "RequireApproval": { "reason": "dangerous command", "approval_id": "apr-123" } } }
```

---

## Endpoints

### Health & Metrics

#### GET /health

Check if the service is running.

**Authentication:** None required

**Response:**

```http
HTTP/1.1 200 OK

{
  "status": "healthy"
}
```

---

#### GET /metrics

Prometheus metrics in text exposition format.

**Authentication:** Required

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4

# HELP sentinel_evaluations_total Total number of policy evaluations
# TYPE sentinel_evaluations_total counter
sentinel_evaluations_total{verdict="allow"} 1234
sentinel_evaluations_total{verdict="deny"} 56
...
```

---

#### GET /api/metrics

Metrics in JSON format.

**Authentication:** Required

**Response:**

```json
{
  "evaluations": {
    "total": 1290,
    "by_verdict": {
      "allow": 1234,
      "deny": 56
    }
  },
  "policies_loaded": 15,
  "uptime_seconds": 3600
}
```

---

### Policy Evaluation

#### POST /api/evaluate

Evaluate an action against loaded policies.

**Authentication:** Required

**Request Body:**

```json
{
  "tool": "file_read",
  "function": "read",
  "parameters": {
    "path": "/home/user/documents/file.txt"
  },
  "context": {
    "agent_id": "agent-123",
    "session_id": "sess-456",
    "timestamp": "2026-02-08T10:00:00Z"
  }
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | Yes | Tool name (e.g., "file_read", "bash", "http_request") |
| `function` | string | No | Function within the tool (defaults to "*") |
| `parameters` | object | No | Tool parameters (e.g., path, url, command) |
| `target_paths` | string[] | No | Explicitly specified target paths |
| `target_domains` | string[] | No | Explicitly specified target domains |
| `resolved_ips` | string[] | No | Resolved IP addresses (for DNS rebinding protection) |
| `context` | object | No | Evaluation context for context-aware policies |

**Context Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Unique identifier for the agent |
| `session_id` | string | Current session identifier |
| `timestamp` | string | ISO 8601 timestamp |
| `call_count` | integer | Number of calls in this session |
| `previous_actions` | string[] | List of previous tool:function combinations |

**Response:**

```json
{
  "verdict": { "Allow": {} },
  "action": {
    "tool": "file_read",
    "function": "read",
    "parameters": "[REDACTED]"
  }
}
```

**Verdict Types:**

| Type | Description |
|------|-------------|
| `Allow` | Action is permitted |
| `Deny` | Action is blocked (includes reason) |
| `RequireApproval` | Action requires human approval |

**Example: Allowed Action**

```bash
curl -X POST http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "file_read",
    "function": "read",
    "parameters": {"path": "/tmp/safe.txt"}
  }'

# Response: 200 OK
{
  "verdict": { "Allow": {} },
  "action": { "tool": "file_read", "function": "read" }
}
```

**Example: Denied Action**

```bash
curl -X POST http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "file_read",
    "function": "read",
    "parameters": {"path": "/home/user/.ssh/id_rsa"}
  }'

# Response: 200 OK
{
  "verdict": {
    "Deny": {
      "reason": "blocked by policy: credential-block"
    }
  },
  "action": { "tool": "file_read", "function": "read" }
}
```

**Example: Requires Approval**

```bash
curl -X POST http://localhost:3000/api/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "bash",
    "function": "execute",
    "parameters": {"command": "rm -rf /tmp/build"}
  }'

# Response: 200 OK
{
  "verdict": {
    "RequireApproval": {
      "reason": "dangerous command: rm -rf",
      "approval_id": "apr-abc123"
    }
  },
  "action": { "tool": "bash", "function": "execute" },
  "approval_id": "apr-abc123"
}
```

---

### Policy Management

#### GET /api/policies

List all loaded policies.

**Authentication:** Required

**Response:**

```json
{
  "policies": [
    {
      "id": "*:*:credential-block",
      "name": "Block credential file access",
      "tool_pattern": "*",
      "function_pattern": "*",
      "priority": 300,
      "policy_type": "Conditional"
    },
    {
      "id": "http_request:*:domain-allowlist",
      "name": "HTTP domain allowlist",
      "tool_pattern": "http_request",
      "function_pattern": "*",
      "priority": 250,
      "policy_type": "Conditional"
    }
  ]
}
```

---

#### POST /api/policies

Add a new policy at runtime.

**Authentication:** Required (admin scope)

**Request Body:**

```json
{
  "id": "custom:deny-tool",
  "name": "Block custom tool",
  "tool_pattern": "dangerous_tool",
  "function_pattern": "*",
  "priority": 100,
  "policy_type": "Deny"
}
```

**Response:**

```json
{
  "message": "Policy added",
  "policy_id": "custom:deny-tool"
}
```

---

#### POST /api/policies/reload

Reload policies from configuration file.

**Authentication:** Required (admin scope)

**Response:**

```json
{
  "message": "Policies reloaded",
  "policy_count": 15
}
```

---

#### DELETE /api/policies/{id}

Remove a policy by ID.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Policy ID (URL-encoded if contains special chars) |

**Response:**

```json
{
  "message": "Policy removed",
  "policy_id": "custom:deny-tool"
}
```

---

### Approvals

#### GET /api/approvals/pending

List all pending approval requests.

**Authentication:** Required

**Response:**

```json
{
  "approvals": [
    {
      "id": "apr-abc123",
      "action": {
        "tool": "bash",
        "function": "execute"
      },
      "reason": "dangerous command: rm -rf",
      "requested_at": "2026-02-08T10:00:00Z",
      "requested_by": "agent-123"
    }
  ]
}
```

---

#### GET /api/approvals/{id}

Get details for a specific approval request.

**Authentication:** Required

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Approval request ID |

**Response:**

```json
{
  "id": "apr-abc123",
  "action": {
    "tool": "bash",
    "function": "execute",
    "parameters": {
      "command": "rm -rf /tmp/build"
    }
  },
  "reason": "dangerous command: rm -rf",
  "status": "pending",
  "requested_at": "2026-02-08T10:00:00Z",
  "requested_by": "agent-123"
}
```

---

#### POST /api/approvals/{id}/approve

Approve a pending request.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Approval request ID |

**Request Body:**

```json
{
  "approved_by": "operator@example.com",
  "comment": "Approved for cleanup task"
}
```

**Response:**

```json
{
  "message": "Approval granted",
  "id": "apr-abc123",
  "approved_by": "operator@example.com",
  "approved_at": "2026-02-08T10:05:00Z"
}
```

---

#### POST /api/approvals/{id}/deny

Deny a pending request.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Approval request ID |

**Request Body:**

```json
{
  "denied_by": "operator@example.com",
  "reason": "Not authorized for this operation"
}
```

**Response:**

```json
{
  "message": "Approval denied",
  "id": "apr-abc123",
  "denied_by": "operator@example.com",
  "denied_at": "2026-02-08T10:05:00Z"
}
```

---

### Audit

#### GET /api/audit/entries

List recent audit log entries.

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Maximum entries to return |
| `offset` | integer | 0 | Entries to skip |
| `verdict` | string | - | Filter by verdict (allow, deny) |
| `tool` | string | - | Filter by tool name |
| `start` | integer | - | Unix timestamp for start of range |
| `end` | integer | - | Unix timestamp for end of range |

**Response:**

```json
{
  "entries": [
    {
      "id": "entry-123",
      "timestamp": "2026-02-08T10:00:00Z",
      "action": {
        "tool": "file_read",
        "function": "read"
      },
      "verdict": { "Allow": {} },
      "policy_id": "default-allow",
      "hash": "abc123..."
    }
  ],
  "total": 1234,
  "offset": 0,
  "limit": 100
}
```

---

#### GET /api/audit/export

Export audit logs in various formats.

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | string | "jsonl" | Export format: jsonl, cef, syslog |
| `start` | integer | - | Unix timestamp for start of range |
| `end` | integer | - | Unix timestamp for end of range |
| `redact` | string | "low" | Redaction level: off, low, high |

**Response (JSON Lines):**

```
Content-Type: application/x-ndjson

{"id":"entry-123","timestamp":"2026-02-08T10:00:00Z",...}
{"id":"entry-124","timestamp":"2026-02-08T10:00:01Z",...}
```

**Response (CEF):**

```
Content-Type: text/plain

CEF:0|Sentinel|MCP-Firewall|1.0|100|Policy Evaluation|5|...
```

---

#### GET /api/audit/verify

Verify audit log integrity.

**Authentication:** Required

**Response:**

```json
{
  "valid": true,
  "entries_verified": 15234,
  "hash_chain": "valid",
  "checkpoints": {
    "total": 15,
    "valid": 15
  },
  "last_entry": "2026-02-08T10:30:00Z"
}
```

---

#### GET /api/audit/report

Generate an audit summary report.

**Authentication:** Required

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `start` | integer | - | Unix timestamp for start of range |
| `end` | integer | - | Unix timestamp for end of range |

**Response:**

```json
{
  "period": {
    "start": "2026-02-08T00:00:00Z",
    "end": "2026-02-08T23:59:59Z"
  },
  "summary": {
    "total_evaluations": 15234,
    "verdicts": {
      "allow": 14500,
      "deny": 700,
      "require_approval": 34
    },
    "top_denied_tools": [
      { "tool": "file_read", "count": 450 },
      { "tool": "bash", "count": 200 }
    ],
    "security_events": {
      "injections_detected": 5,
      "dlp_findings": 12,
      "anomalies": 3
    }
  }
}
```

---

#### GET /api/audit/checkpoints

List audit checkpoints.

**Authentication:** Required

**Response:**

```json
{
  "checkpoints": [
    {
      "id": 1,
      "entry_number": 1000,
      "hash": "abc123...",
      "signature": "sig...",
      "created_at": "2026-02-08T10:00:00Z"
    }
  ]
}
```

---

#### POST /api/audit/checkpoint

Create a new audit checkpoint.

**Authentication:** Required (admin scope)

**Response:**

```json
{
  "message": "Checkpoint created",
  "checkpoint": {
    "id": 16,
    "entry_number": 16000,
    "hash": "def456...",
    "signature": "sig...",
    "created_at": "2026-02-08T11:00:00Z"
  }
}
```

---

### Tool Registry

#### GET /api/registry/tools

List registered tools with trust scores.

**Authentication:** Required

**Response:**

```json
{
  "tools": [
    {
      "name": "file_read",
      "version": "1.0.0",
      "trust_score": 0.95,
      "approved": true,
      "schema_hash": "abc123...",
      "first_seen": "2026-01-01T00:00:00Z",
      "last_seen": "2026-02-08T10:00:00Z"
    }
  ]
}
```

---

#### POST /api/registry/tools/{name}/approve

Mark a tool as approved.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Tool name |

**Response:**

```json
{
  "message": "Tool approved",
  "tool": "file_read"
}
```

---

#### POST /api/registry/tools/{name}/revoke

Revoke tool approval.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Tool name |

**Response:**

```json
{
  "message": "Tool approval revoked",
  "tool": "dangerous_tool"
}
```

---

### Tenants

#### GET /api/tenants

List all tenants (multi-tenancy mode).

**Authentication:** Required (admin scope)

**Response:**

```json
{
  "tenants": [
    {
      "id": "tenant-1",
      "name": "Production",
      "created_at": "2026-01-01T00:00:00Z",
      "policy_count": 15
    }
  ]
}
```

---

#### POST /api/tenants

Create a new tenant.

**Authentication:** Required (admin scope)

**Request Body:**

```json
{
  "id": "tenant-2",
  "name": "Staging"
}
```

**Response:**

```json
{
  "message": "Tenant created",
  "tenant": {
    "id": "tenant-2",
    "name": "Staging",
    "created_at": "2026-02-08T10:00:00Z"
  }
}
```

---

#### GET /api/tenants/{id}

Get tenant details.

**Authentication:** Required

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Tenant ID |

**Response:**

```json
{
  "id": "tenant-1",
  "name": "Production",
  "created_at": "2026-01-01T00:00:00Z",
  "policies": [ ... ],
  "settings": { ... }
}
```

---

#### PUT /api/tenants/{id}

Update a tenant.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Tenant ID |

**Request Body:**

```json
{
  "name": "Production (Updated)"
}
```

**Response:**

```json
{
  "message": "Tenant updated",
  "tenant": {
    "id": "tenant-1",
    "name": "Production (Updated)"
  }
}
```

---

#### DELETE /api/tenants/{id}

Delete a tenant.

**Authentication:** Required (admin scope)

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `id` | Tenant ID |

**Response:**

```json
{
  "message": "Tenant deleted",
  "tenant_id": "tenant-2"
}
```

---

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `INVALID_REQUEST` | Malformed request body |
| 400 | `VALIDATION_ERROR` | Request validation failed |
| 401 | `UNAUTHORIZED` | Missing or invalid authentication |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Resource already exists |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |

**Error Response Example:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid tool name: must be alphanumeric",
    "details": {
      "field": "tool",
      "value": "invalid tool!",
      "constraint": "alphanumeric"
    }
  }
}
```

---

## Related Documentation

- [Deployment Guide](./DEPLOYMENT.md) - Installation and configuration
- [Operations Runbook](./OPERATIONS.md) - Monitoring and troubleshooting
- [Security Hardening](./SECURITY.md) - Security best practices
