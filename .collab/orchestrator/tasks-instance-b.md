# Tasks for Instance B — Directive C-9 (Pre-Compiled Policies & Protocol)

## READ THIS FIRST

Controller Directive C-9 is active. All C-8 work is complete (tool annotations, response inspection, rug-pull detection — excellent work). C-9 focuses on the highest-impact architecture improvement remaining: **eliminating Mutex-based caches from the evaluation hot path** by pre-compiling policies at load time.

Update `.collab/instance-b.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (all previous directives)
- All 5 features (parameter firewall, audit, approval, MCP proxy, canonical fix)
- All C-2 security fixes (9/9)
- All C-6 protocol compliance (4/4)
- All C-7 items (CORS, log rotation)
- All C-8 items (tool annotations, rug-pull detection, response inspection)
- All improvement plan items (I-B2 through I-B6)

---

## Task C9-B1: Pre-Compiled Policies (Phase 10.1)
**Priority: HIGH — Single highest-impact performance improvement remaining**
**Directive:** C-9.2
**Reference:** `controller/research/policy-engine-patterns.md` §2.1, §1.3, §3.1

### Problem

`sentinel-engine/src/lib.rs` currently uses:
```rust
regex_cache: Mutex<HashMap<String, Regex>>,
glob_cache: Mutex<HashMap<String, GlobMatcher>>,
```

Every evaluation acquires these Mutex locks. Cedar and OPA both compile at load time — zero runtime compilation.

### Implementation

1. **Add `CompiledPolicy` struct:**

```rust
pub struct CompiledPolicy {
    pub policy: Policy,
    pub tool_matcher: CompiledToolMatcher,
    pub constraints: Vec<CompiledConstraint>,
}

pub enum CompiledToolMatcher {
    Exact(String, String),         // tool:function exact
    ToolWildcard(String),          // tool:*
    FunctionWildcard(GlobMatcher), // glob pattern
    Universal,                      // *
}

pub enum CompiledConstraint {
    Glob { param: String, matcher: GlobMatcher, negated: bool },
    Regex { param: String, regex: Regex },
    DomainMatch { param: String, patterns: Vec<String> },
    Eq { param: String, value: String },
    OneOf { param: String, values: Vec<String> },
    // ... other operators
}
```

2. **Compile at load time:** In `PolicyEngine::new()`, compile each `Policy` into a `CompiledPolicy`. Return `Result<PolicyEngine, Vec<PolicyValidationError>>` — invalid policies are rejected.

3. **Remove `regex_cache` and `glob_cache`:** Replace with direct references from `CompiledConstraint`.

4. **Policy validation:** At compile time, check:
   - Regex patterns compile
   - Glob patterns compile
   - Tool ID format is valid
   - No self-contradictory constraints (e.g., `eq: "x"` + `ne: "x"`)

5. **Update `evaluate()`:** Use `CompiledPolicy` fields directly instead of cache lookups. Zero Mutex acquisitions in hot path.

6. **Update `reload_policies()` / ArcSwap store:** Compile new policies before swapping. If compilation fails, keep old policies.

**Important:** Keep backward compatibility — `PolicyEngine::new(policies)` should work. Internal representation changes only.

**Tests:**
- Existing tests must continue to pass (behavioral parity)
- New tests: invalid regex rejected at load time, invalid glob rejected, compilation errors reported
- Benchmark: before/after with 100+ policies

---

## Task C9-B2: Protocol Version Awareness (Phase 8.4)
**Priority: MEDIUM**
**Directive:** C-9.2

1. In `sentinel-mcp/src/proxy.rs`, intercept `initialize` request/response
2. Extract `protocolVersion` from the `initialize` result
3. Store as `Option<String>` in `ProxyBridge` state
4. Log protocol version in audit entries
5. Warn if version < `"2024-11-05"` (earliest stable MCP spec)

**Files:** `sentinel-mcp/src/proxy.rs`, `sentinel-mcp/src/extractor.rs`

---

## Task C9-B3: `sampling/createMessage` Interception (Phase 8.5)
**Priority: MEDIUM**
**Directive:** C-9.2

`sampling/createMessage` is a server-initiated LLM call — a potential exfiltration vector where a malicious MCP server tricks the client into making additional LLM calls with attacker-controlled prompts.

1. In `sentinel-mcp/src/extractor.rs`, add `MessageType::SamplingRequest` variant for `sampling/createMessage` method
2. In proxy, intercept sampling requests flowing server → client
3. Log all sampling requests in audit trail
4. Apply policy evaluation: reuse tool evaluation with `tool="sampling"`, `function="createMessage"`, parameters from the sampling request
5. Add tests: sampling request detected, evaluated, logged, denied if policy forbids

**Files:** `sentinel-mcp/src/extractor.rs`, `sentinel-mcp/src/proxy.rs`

---

## Work Order
1. C9-B1 (pre-compiled policies) — do first, highest impact, most complex
2. C9-B2 (protocol version) — do second, straightforward
3. C9-B3 (sampling interception) — do third, completes MCP coverage

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `sentinel-engine/src/lib.rs`, `sentinel-mcp/`, `sentinel-audit/`, `sentinel-proxy/`, `sentinel-approval/`, `sentinel-canonical/`
