# Policy Engine Design Patterns: Cedar, OPA, and Production Systems

**Date:** 2026-02-02
**Author:** Controller Instance (Research Agent a6bed5e)
**Sources:** Cedar Policy Language, OPA/Rego, NIST ABAC, Casbin, Oso

---

## 1. Cedar Policy Language (Amazon) — Design Patterns

### 1.1 Permit/Forbid with Deny-Override Semantics

Cedar uses an explicit two-rule-type system:
- `permit` — grants access when conditions are met
- `forbid` — denies access when conditions are met

The conflict resolution algorithm:
1. Collect all policies that match the request
2. If ANY `forbid` policy matches → **Deny** (regardless of how many permits match)
3. If at least one `permit` matches and zero `forbid` → **Allow**
4. If no policies match → **Deny** (default-deny / fail-closed)

**How Sentinel compares:** Sentinel uses a priority-based first-match system. The `sort_policies` function (sentinel-engine/src/lib.rs line 61) sorts by priority descending, then deny-first at equal priority, then by ID. A high-priority Allow can override a lower-priority Deny.

**Recommendation:** Consider adding a Cedar-style deny-override evaluation mode alongside the current priority mode:

```
// Cedar-style deny-override (pass all matching, not first-match)
1. Collect all policies matching the action
2. If any matching policy is Deny -> final verdict = Deny
3. Else if any matching policy is Allow -> final verdict = Allow
4. Else -> Deny (default)
```

This is significantly safer because a developer cannot accidentally override a security-critical deny rule with a broadly-scoped allow rule.

### 1.2 Entity-Attribute Model (Principal, Action, Resource)

Cedar structures every request as a triple:
- **Principal** — who is making the request
- **Action** — what operation is being performed
- **Resource** — what is being acted upon

**How Sentinel compares:** Sentinel's `Action` has `tool`, `function`, and `parameters`. It lacks an explicit principal concept (agent identity, user, session).

**Recommendation:** Extend the evaluation context:

```rust
pub struct EvaluationContext {
    pub action: Action,
    pub principal: Option<Principal>,  // agent identity, user, session
    pub resource: Option<Resource>,    // extracted from parameters
    pub environment: Environment,      // time, IP, request metadata
}
```

This enables policies like "Agent running as user X can read files but cannot execute commands" — critical for multi-tenant deployments.

### 1.3 Policy Validation at Compile Time

Cedar validates policies against a **schema** before loading. Malformed policies are rejected at load time, not evaluation time.

**How Sentinel compares:** Sentinel validates conditions at evaluation time. `strict_mode` adds unknown-key validation but per-request.

**Recommendation:** Pre-validate policies at load time:

```rust
pub fn validate_policy(policy: &Policy) -> Result<(), Vec<PolicyValidationError>> {
    // Check: ID pattern is valid (tool:function format)
    // Check: Conditions use known operators
    // Check: Glob patterns compile
    // Check: Regex patterns compile (and are bounded)
    // Check: No conflicting constraints
}
```

Pre-compiling regex/glob at load time into a `CompiledPolicy` struct eliminates the runtime caches and their `Mutex` contention.

### 1.4 Policy Analysis

Cedar includes a built-in policy analyzer:
- Vacuity checking: "Is this policy always-deny?"
- Equivalence checking: "Do these two sets produce the same results?"
- Reachability analysis: "Can principal X ever access resource Y?"

**Lightweight Sentinel adaptations:**
- **Conflict detection:** Flag overlapping tool patterns with different verdicts at same priority
- **Shadowing detection:** Warn when a wildcard policy makes specific policies unreachable
- **Coverage analysis:** Report tool:function combinations with no matching policy

---

## 2. OPA/Rego Patterns

### 2.1 Partial Evaluation

OPA's most powerful optimization: pre-compute parts of a policy that depend only on data (not the request). The runtime check becomes a simple set membership test.

**Recommendation:** Implement a "compiled policy" representation:

```rust
pub struct CompiledPolicy {
    pub id: String,
    pub policy_type: PolicyType,
    pub priority: i32,
    pub tool_matcher: ToolMatcher,          // Pre-compiled glob/wildcard
    pub constraints: Vec<CompiledConstraint>,
}

pub enum CompiledConstraint {
    ForbiddenParams(HashSet<String>),       // O(1) lookup
    RequiredParams(HashSet<String>),        // O(1) lookup
    GlobMatch { param: String, matcher: GlobMatcher },
    RegexMatch { param: String, regex: Regex },
    DomainAllowlist { param: String, domains: Vec<DomainPattern> },
}
```

This eliminates the Mutex-based regex/glob caches and moves all compilation to policy load time.

### 2.2 Decision Logging and Explanation

OPA produces detailed decision logs explaining *why* a decision was made — which rules matched, which data was consulted.

**Recommendation:** Add optional explanation mode:

```rust
pub struct EvaluationTrace {
    pub policies_checked: usize,
    pub first_match: Option<String>,
    pub matches: Vec<PolicyMatch>,
    pub duration: Duration,
}

pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_type: PolicyType,
    pub matched_tool: bool,
    pub matched_function: bool,
    pub constraint_results: Vec<ConstraintResult>,
}
```

### 2.3 Bundling and Hot-Reload

OPA supports signed collections of policies atomically loaded. Sentinel's `ArcSwap<Vec<Policy>>` is the right primitive.

**Enhancements:**
- Policy versioning: monotonic version number per loaded set
- Signature verification: sign the policy file, verify before loading
- Rollback: keep previous set for failed reload recovery

### 2.4 Performance: Policy Indexing

OPA indexes policies by first attribute. Sentinel evaluates linearly (O(all)).

**Recommendation:** Build a policy index:

```rust
pub struct PolicyIndex {
    exact: HashMap<(String, String), Vec<usize>>,    // tool:function
    tool_wildcard: HashMap<String, Vec<usize>>,      // tool:*
    global_wildcards: Vec<usize>,                     // *
}
```

For 1000 policies where only 5 match a given tool, this reduces evaluation from O(1000) to O(5).

---

## 3. Policy Evaluation Optimization Techniques

### 3.1 Pre-Compilation (Highest Impact)

Move all compilation to load time. Current Sentinel caches behind `Mutex`:

```rust
// Current: sentinel-engine/src/lib.rs lines 39-40
regex_cache: Mutex<HashMap<String, Regex>>,
glob_cache: Mutex<HashMap<String, GlobMatcher>>,
```

These introduce lock contention and cache-miss overhead. Production policy engines (Cedar, OPA, Casbin) all compile at load time.

### 3.2 Short-Circuit Evaluation

Additional opportunities beyond first-match:
- Quick rejection by tool name before constraint checking
- Fail-fast on deny policies with no conditions

### 3.3 Arena Allocation

For the hot path, avoid per-request heap allocations:
- Pre-allocate thread-local buffer for path normalization
- Use `SmallVec` for components (most paths have <8 components)
- Return `Cow<str>` when input is already normalized

### 3.4 Bloom Filter Pre-Screening

For large policy sets with many glob patterns, a bloom filter quickly answers "does this path definitely NOT match any blocked pattern?" — skip all glob evaluation if so.

---

## 4. RBAC/ABAC Patterns for Tool Access

### 4.1 ABAC Model

Key attributes for tool authorization:

| Attribute Category | Examples | Sentinel Status |
|---|---|---|
| **Subject (Agent)** | Agent identity, LLM model, user session, trust level | Not yet |
| **Action** | Tool name, function, operation type | `action.tool`, `action.function` |
| **Resource** | File path, URL, domain, database | Extracted from parameters |
| **Environment** | Time of day, request rate, session duration | Not yet |

### 4.2 Policy Layering

Production ABAC systems use layered policies:

1. **Platform layer** (immutable, highest priority): "Never allow access to /proc, /sys, AWS credentials"
2. **Organization layer**: "Our agents can access our API but not competitor APIs"
3. **User/session layer** (lowest priority): "This specific session can write to /tmp/workspace"

**Recommendation:** Make layers explicit:

```rust
pub enum PolicyLayer {
    Platform,      // priority 900-1000, immutable at runtime
    Organization,  // priority 500-899
    User,          // priority 100-499
    Default,       // priority 0-99
}
```

Hot-reload should only modify User and Default layers.

---

## 5. Policy Testing Patterns

### 5.1 Table-Driven Tests

Add a policy test runner loading test cases from TOML/JSON alongside policy files:

```toml
[[test_cases]]
name = "Block AWS credential access"
action = { tool = "file_system", function = "read_file", parameters = { path = "/home/user/.aws/credentials" } }
expected_verdict = "Deny"
```

### 5.2 Batch Simulation

```
POST /api/simulate
{
    "actions": [...],
    "policies": [...],           // Optional override
    "include_trace": true
}
```

Enables testing new policies against audit log replays before deployment.

### 5.3 Mutation Testing

Automatically mutate policies (flip Allow/Deny, change wildcards, modify priorities) and verify test suite catches mutations.

---

## Summary: Top 10 Actionable Recommendations

| # | Recommendation | Source | Impact | Effort |
|---|---|---|---|---|
| 1 | Pre-compile regex/glob at load time | OPA, Cedar | High (latency) | Medium |
| 2 | Add deny-override evaluation mode | Cedar | High (security) | Low |
| 3 | Build policy index by tool name | OPA | High (scalability) | Medium |
| 4 | Validate policies at load time | Cedar | High (reliability) | Medium |
| 5 | Add evaluation trace/explanation | OPA | Medium (observability) | Low |
| 6 | Add principal/subject context | ABAC, Cedar | High (multi-tenant) | Medium |
| 7 | Implement policy test runner | OPA, Cedar | Medium (DevEx) | Low |
| 8 | Add batch simulation endpoint | OPA, Cedar | Medium (safety) | Low |
| 9 | Implement policy layers | ABAC | Medium (governance) | Low |
| 10 | Expand property-based tests | Cedar formal verification | High (correctness) | Low |

---

## Reference URLs

- **Cedar Policy Language:** https://www.cedarpolicy.com/
- **Cedar Rust SDK:** https://github.com/cedar-policy/cedar
- **Cedar Design Paper:** "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization" (OOPSLA 2024)
- **OPA Documentation:** https://www.openpolicyagent.org/docs/latest/
- **OPA Performance:** https://www.openpolicyagent.org/docs/latest/policy-performance/
- **OPA Testing:** https://www.openpolicyagent.org/docs/latest/policy-testing/
- **NIST ABAC Guide:** NIST SP 800-162
- **Casbin (Rust):** https://github.com/casbin/casbin-rs
- **Oso:** https://www.osohq.com/

---

*Last updated: 2026-02-02*
