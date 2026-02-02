# Sentinel Architecture Designs — C-9.3

**Author:** Orchestrator
**Date:** 2026-02-02
**Source:** Controller research files (policy-engine-patterns, audit-log-rotation, mcp-spec-and-landscape, rate-limiting-cors-headers)

---

## 1. Signed Audit Checkpoints (Phase 10.3)

### Problem

Sentinel's hash chain detects tampering within a single log file, but cannot detect wholesale file replacement. An attacker with file system access can replace the entire log with a valid-looking chain. External witnessing is needed.

### Design

#### 1.1 ChainCheckpoint Struct

```rust
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};

#[derive(Serialize, Deserialize, Clone)]
pub struct ChainCheckpoint {
    pub timestamp: String,           // ISO 8601
    pub entry_count: u64,            // total entries in chain at checkpoint time
    pub segment_id: u64,             // log rotation segment number
    pub chain_head_hash: String,     // SHA-256 hash of the last entry
    pub prev_checkpoint_hash: String,// hash of previous checkpoint (chain of checkpoints)
    pub signature: String,           // Ed25519 signature over all above fields
}
```

#### 1.2 Signing Key Management

- Key generated at first startup, stored at `~/.sentinel/audit-signing-key.pem`
- Public key exported to `~/.sentinel/audit-signing-key.pub` for verifiers
- Key rotation: new key signs a "key rotation" checkpoint that includes both old and new public keys
- Environment variable override: `SENTINEL_AUDIT_SIGNING_KEY` for deployments that inject secrets

#### 1.3 Checkpoint Triggers

- Every **1000 entries** OR every **5 minutes** (whichever comes first)
- On log rotation (always checkpoint before rotating)
- On graceful shutdown (final checkpoint)
- Checkpoint is written as a special entry type in the JSONL log:

```json
{"type": "checkpoint", "timestamp": "...", "entry_count": 5000, "segment_id": 0,
 "chain_head_hash": "abc...", "prev_checkpoint_hash": "def...", "signature": "ghi..."}
```

#### 1.4 Verification API

```
GET /api/audit/verify-checkpoints
```

Returns:
- Number of checkpoints found
- Each checkpoint's validity (signature correct, chain_head_hash matches chain at that point)
- Time coverage gaps (missing heartbeats between checkpoints)

Incremental verification:
```
GET /api/audit/verify-since?checkpoint=<entry_count>
```

Verifies only entries after the given checkpoint, enabling O(recent) verification.

#### 1.5 External Witnessing (Future)

```rust
pub trait ChainWitness: Send + Sync {
    async fn publish_checkpoint(&self, cp: &ChainCheckpoint) -> Result<(), WitnessError>;
    async fn verify_checkpoint(&self, cp: &ChainCheckpoint) -> Result<bool, WitnessError>;
}
```

Implementations:
- `FileWitness` — writes checkpoints to a separate file/directory (default)
- `HttpWitness` — POSTs checkpoints to an external verification service (future)
- `SyslogWitness` — sends to syslog for SIEM integration (future)

#### 1.6 Dependencies

- `ed25519-dalek = "2"` — Ed25519 signing (~50KB, no-std capable)
- `rand = "0.8"` (already in workspace) — key generation

#### 1.7 Security Considerations

- Signing key must be separate from the audit log file — attacker with log write access should not have key access
- Checkpoint verification should be runnable offline (no network needed for basic verification)
- Heartbeat entries (empty checkpoints) every 5 minutes detect log truncation gaps

---

## 2. Evaluation Trace / Explanation (Phase 10.4)

### Problem

When a tool call is denied, operators need to understand *why*. Currently the deny reason is a simple string. OPA and Cedar both provide structured decision explanations.

### Design

#### 2.1 EvaluationTrace Struct

```rust
#[derive(Serialize, Clone)]
pub struct EvaluationTrace {
    pub action: ActionSummary,
    pub policies_checked: usize,
    pub policies_matched: usize,
    pub duration_us: u64,
    pub matches: Vec<PolicyMatch>,
    pub final_verdict: String,          // "allow", "deny", "require_approval"
    pub verdict_reason: String,
}

#[derive(Serialize, Clone)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_type: String,            // "allow", "deny", "conditional"
    pub priority: i64,
    pub tool_matched: bool,
    pub function_matched: bool,
    pub constraint_results: Vec<ConstraintResult>,
    pub verdict_contribution: String,   // "matched", "skipped", "overridden"
}

#[derive(Serialize, Clone)]
pub struct ConstraintResult {
    pub param: String,
    pub operator: String,
    pub expected: String,
    pub actual: Option<String>,
    pub result: String,                 // "pass", "fail", "missing"
}

#[derive(Serialize, Clone)]
pub struct ActionSummary {
    pub tool: String,
    pub function: String,
    pub param_count: usize,
    pub target_paths: Vec<String>,
    pub target_domains: Vec<String>,
}
```

#### 2.2 API Integration

**Evaluate endpoint with trace:**
```
POST /api/evaluate?trace=true
```

Response:
```json
{
    "verdict": "deny",
    "reason": "blocked by policy 'no-aws-access'",
    "trace": {
        "policies_checked": 15,
        "policies_matched": 2,
        "duration_us": 340,
        "matches": [
            {
                "policy_id": "no-aws-access",
                "policy_type": "deny",
                "priority": 100,
                "tool_matched": true,
                "constraint_results": [
                    {"param": "path", "operator": "glob", "expected": "/home/*/.aws/**",
                     "actual": "/home/user/.aws/credentials", "result": "pass"}
                ],
                "verdict_contribution": "matched"
            }
        ]
    }
}
```

**Simulation endpoint (batch):**
```
POST /api/simulate
Body: {"actions": [...], "policies": [...optional override...]}
```

Returns traces for each action without actually executing. Useful for policy testing before deployment.

#### 2.3 Implementation in Engine

```rust
impl PolicyEngine {
    pub fn evaluate_action_traced(
        &self,
        action: &Action,
        policies: &[Policy],
    ) -> (Verdict, EvaluationTrace) {
        // Same logic as evaluate_action, but records each step
    }
}
```

The traced path has overhead (~20% more allocation) so it's opt-in. The non-traced `evaluate_action()` remains the default hot path.

#### 2.4 Audit Integration

When tracing is enabled, the trace is included in the audit entry's metadata:
```json
{"tool": "read_file", "verdict": "deny", "metadata": {"trace": {...}}}
```

This enables post-hoc analysis: "which policies were checked for this denied action?"

#### 2.5 Security Considerations

- Traces may reveal policy structure to callers. Consider: trace only for authenticated admin requests
- Simulation endpoint must be auth-protected (admin-only)
- Trace output should redact sensitive parameter values (reuse existing redaction)

---

## 3. Streamable HTTP Transport Architecture (Phase 9)

### Problem

Sentinel only supports stdio transport, limiting it to local MCP server deployments. The MCP spec (v2025-11-25) defines Streamable HTTP transport as the standard for remote servers. This is the single biggest gap for market relevance.

### Design

#### 3.1 Architecture Overview

```
┌─────────┐     HTTP POST     ┌─────────────────┐     HTTP POST     ┌────────────┐
│  Agent   │ ──────────────── │  Sentinel HTTP   │ ──────────────── │  Remote    │
│  Client  │     /mcp         │  Proxy           │     /mcp         │  MCP       │
│          │ ←─── JSON/SSE ── │                  │ ←─── JSON/SSE ── │  Server    │
└─────────┘                   └─────────────────┘                   └────────────┘
                                     │
                                     ├── Policy evaluation
                                     ├── Tool annotation extraction
                                     ├── Response inspection
                                     ├── Audit logging
                                     └── Session management
```

#### 3.2 Core Components

```rust
/// HTTP reverse proxy for MCP Streamable HTTP transport
pub struct HttpMcpProxy {
    /// Upstream MCP server URL
    upstream: Uri,
    /// Policy engine (shared with stdio proxy via Arc)
    engine: Arc<PolicyEngine>,
    /// Per-session state
    sessions: Arc<DashMap<String, SessionState>>,
    /// Audit logger
    audit: Arc<AuditLogger>,
    /// Configuration
    config: HttpProxyConfig,
}

pub struct SessionState {
    pub session_id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub protocol_version: Option<String>,
    pub known_tools: HashMap<String, ToolAnnotations>,
    pub request_count: u64,
}

pub struct HttpProxyConfig {
    pub upstream_url: String,
    pub listen_addr: SocketAddr,
    pub session_timeout: Duration,    // default 30 minutes
    pub max_sessions: usize,          // default 1000
    pub oauth: Option<OAuthConfig>,
}
```

#### 3.3 Request Flow

1. **Client POST to `/mcp`:**
   - Parse JSON-RPC body
   - Extract `Mcp-Session-Id` header (create session if missing)
   - Classify message: `initialize`, `tools/call`, `tools/list`, `resources/read`, etc.

2. **Policy evaluation:**
   - Same as stdio path: extract Action, evaluate against policies
   - On deny: return JSON-RPC error directly, don't forward

3. **Forward to upstream:**
   - Proxy request to upstream MCP server
   - Add/forward `Mcp-Session-Id` header
   - Forward OAuth bearer token if configured

4. **Response handling:**
   - If upstream returns JSON: parse, inspect, forward
   - If upstream returns SSE stream: proxy stream, inspect each event
   - Extract tool annotations from `tools/list` responses
   - Run response injection detection on tool results

5. **Return to client:**
   - Forward response with appropriate headers
   - Include `Mcp-Session-Id` header

#### 3.4 SSE Streaming

For long-running tool calls, MCP servers may return Server-Sent Events:

```rust
async fn proxy_sse_stream(
    upstream_response: Response<Body>,
    session: &SessionState,
    audit: &AuditLogger,
) -> Response<Body> {
    // Create a new SSE stream that:
    // 1. Reads each event from upstream
    // 2. Inspects for injection patterns
    // 3. Forwards to client
    // 4. Logs final result in audit
}
```

#### 3.5 OAuth 2.1 Integration

```rust
pub struct OAuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: Option<String>,         // for JWT validation
    pub required_scopes: Vec<String>,     // required OAuth scopes
    pub pass_through: bool,               // forward token to upstream
}
```

Token validation flow:
1. Extract `Authorization: Bearer <token>` from client request
2. Validate token (JWT signature, expiry, audience, scopes)
3. If `pass_through`, forward token to upstream
4. If not `pass_through`, use Sentinel's own credentials for upstream

#### 3.6 Binary / CLI Integration

```
sentinel http-proxy \
    --upstream https://remote-mcp-server.example.com/mcp \
    --listen 127.0.0.1:3001 \
    --config policy.toml \
    --oauth-issuer https://auth.example.com \
    --session-timeout 30m
```

#### 3.7 Shared Code with Stdio Proxy

The policy evaluation, tool annotation extraction, response inspection, and audit logging are shared between stdio and HTTP proxy modes:

```rust
/// Shared evaluation logic used by both stdio and HTTP proxy
pub trait McpInterceptor {
    fn evaluate_tool_call(&self, ...) -> ProxyDecision;
    fn evaluate_resource_read(&self, ...) -> ProxyDecision;
    fn extract_tool_annotations(&mut self, response: &Value);
    fn inspect_response(&self, response: &Value) -> Vec<&str>;
}
```

`ProxyBridge` already implements this for stdio. `HttpMcpProxy` would share the same implementation via the trait or by embedding a `ProxyBridge`.

#### 3.8 New Crate Structure

```
sentinel-http-proxy/        # NEW crate
├── Cargo.toml              # deps: axum, hyper, tokio, sentinel-engine, sentinel-mcp, sentinel-audit
├── src/
│   ├── main.rs             # CLI entry point
│   ├── proxy.rs            # HttpMcpProxy implementation
│   ├── session.rs          # Session management
│   ├── sse.rs              # SSE stream proxying
│   └── oauth.rs            # OAuth 2.1 token validation
```

#### 3.9 Dependencies

- `hyper = "1"` — HTTP client for upstream connections
- `reqwest = "0.12"` — higher-level HTTP client (optional, hyper may suffice)
- `dashmap = "5"` — concurrent session map
- `jsonwebtoken = "9"` — JWT validation for OAuth (if needed)
- `axum` (already in workspace) — HTTP server

#### 3.10 Security Considerations

- Session fixation: generate session IDs server-side, don't trust client-provided IDs
- Session hijacking: bind sessions to client IP or TLS certificate if possible
- Upstream TLS: always use HTTPS for upstream connections, verify certificates
- Request size limits: same body size limits as stdio (MAX_LINE_LENGTH)
- Rate limiting: reuse governor middleware from sentinel-server

---

## 4. Phase 10: Production Hardening (Improvement Plan Update)

### 10.1 Pre-Compiled Policies (C-9.2) — Assigned to Instance B
Eliminate Mutex-based regex/glob caches. Compile all patterns at load time.

### 10.2 API Security Headers (C-9.1) — DONE
Security response headers middleware added by Instance B + Controller.

### 10.3 Signed Audit Checkpoints — See Design §1 above
Ed25519 signed checkpoints every 1000 entries. External witnessing trait.

### 10.4 Evaluation Trace / Explanation — See Design §2 above
OPA-style decision logging with `?trace=true` query parameter.

### 10.5 Policy Index by Tool Name
Build HashMap index of policies by tool name for O(matching) instead of O(all) evaluation. Critical for 1000+ policy deployments.

### 10.6 Heartbeat Entries
Periodic empty entries in audit log (every 5 minutes) to detect truncation gaps.

---

*Last updated: 2026-02-02 — Architecture designs for C-9.3*
