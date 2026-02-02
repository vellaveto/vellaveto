# CLAUDE.md — Sentinel Project Instructions

> **Project:** Sentinel — MCP Tool Firewall  
> **Goal:** Production-ready runtime enforcement layer for AI agent tool calls  
> **Philosophy:** Ship fast, fail safe, measure everything

---

## 🎯 Mission

Build a lightweight, high-performance policy engine that intercepts AI tool calls (MCP, OpenAI function calls), enforces security policies on paths/domains/actions, and maintains tamper-evident audit logs. The system must be:

- **Fast:** <10ms evaluation latency, <50MB memory baseline
- **Safe:** Fail-closed (deny on error), no panics in hot path
- **Observable:** Every decision logged, every failure diagnosed
- **Maintainable:** Clean abstractions, comprehensive tests, zero `unwrap()` in library code

---

## 📋 Before Every Session

```bash
# 1. Check current state
cd /path/to/sentinel
git status
cargo check --workspace 2>&1 | head -50

# 2. Run tests to establish baseline
cargo test --workspace --no-fail-fast 2>&1 | tee /tmp/test-baseline.log
echo "Baseline: $(grep -c 'test .* ok' /tmp/test-baseline.log) passing"

# 3. Note any warnings
cargo clippy --workspace 2>&1 | grep -E "^warning:" | head -20
```

**If tests fail at session start:** STOP. Diagnose and fix before proceeding. Do not add new code on a broken foundation.

---

## 🔒 Backup Protocol

### Before ANY Major Change

A "major change" is:
- Modifying more than 50 lines in a single file
- Changing public API signatures
- Restructuring modules
- Modifying Cargo.toml dependencies
- Altering database/file schemas

```bash
# Create timestamped backup branch
BACKUP_NAME="backup/$(date +%Y%m%d-%H%M%S)-before-<change-description>"
git stash push -m "WIP before $BACKUP_NAME" 2>/dev/null || true
git checkout -b "$BACKUP_NAME"
git checkout -  # Return to working branch

# Log the backup
echo "$(date -Iseconds) | $BACKUP_NAME | <brief description>" >> .backups.log
```

### Recovery Protocol

```bash
# If something goes wrong
git diff HEAD~1 --stat  # See what changed
git stash push -m "broken-state-$(date +%s)"
git checkout "$BACKUP_NAME"
git checkout -b "fix/recovery-$(date +%s)"
```

---

## 🏗️ Architecture Invariants

### Crate Dependency Graph (NEVER VIOLATE)

```
sentinel-types (leaf - no internal deps)
       ↑
sentinel-canonical (types only)
       ↑
sentinel-engine (types, canonical)
       ↑
sentinel-audit (types, engine)
sentinel-config (types)
sentinel-mcp (types, engine)
       ↑
sentinel-server (all above)
sentinel-integration (all above, test only)
```

**Rule:** Lower crates MUST NOT depend on higher crates. This prevents cycles and keeps compilation fast.

### Module Structure Per Crate

```
sentinel-<name>/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API only, re-exports
│   ├── types.rs        # Internal types (if needed)
│   ├── <feature>.rs    # Feature modules
│   └── error.rs        # Crate-specific errors
└── tests/
    └── integration.rs  # Integration tests
```

### Error Handling Rules

```rust
// ✅ CORRECT: Custom error type, no panics
pub fn evaluate(&self, action: &Action) -> Result<Verdict, EngineError> {
    let policy = self.find_policy(&action.tool)
        .ok_or_else(|| EngineError::NoPolicyFound(action.tool.clone()))?;
    // ...
}

// ❌ WRONG: Panics in library code
pub fn evaluate(&self, action: &Action) -> Verdict {
    let policy = self.find_policy(&action.tool).unwrap(); // NEVER
    // ...
}

// ❌ WRONG: Losing error context
pub fn evaluate(&self, action: &Action) -> Result<Verdict, Box<dyn Error>> {
    // Loses type information, harder to handle
}
```

---

## ⚡ Performance Rules

### Memory Budget

| Component | Max Memory | Notes |
|-----------|------------|-------|
| PolicyEngine | 10MB | Policies in memory |
| AuditLogger | 5MB buffer | Flush at threshold |
| PendingStore | 20MB | Max 1000 pending actions |
| MCP Proxy | 15MB | Per connection overhead |
| **Total baseline** | **<50MB** | Excluding OS/runtime |

### Latency Budget

| Operation | Max Latency | P99 Target |
|-----------|-------------|------------|
| Policy evaluation | 5ms | 2ms |
| Audit log write | 10ms | 5ms |
| MCP message parse | 1ms | 0.5ms |
| Full request cycle | 20ms | 10ms |

### Performance Checks

```bash
# Build with optimizations for benchmarking
cargo build --release --workspace

# Run benchmarks (if they exist)
cargo bench --workspace 2>&1 | tee /tmp/bench.log

# Profile hot paths
cargo flamegraph --bin sentinel -- serve --config test.toml &
# ... run load test ...
# kill %1
```

### Code Patterns for Performance

```rust
// ✅ CORRECT: Avoid allocations in hot path
fn matches_pattern(pattern: &str, input: &str) -> bool {
    // Use slices, not String
    pattern.split(':')
        .zip(input.split(':'))
        .all(|(p, i)| p == "*" || p == i)
}

// ❌ WRONG: Allocates on every call
fn matches_pattern(pattern: &str, input: &str) -> bool {
    let parts: Vec<String> = pattern.split(':').map(|s| s.to_string()).collect();
    // ...
}

// ✅ CORRECT: Pre-compile regex at startup
lazy_static! {
    static ref PATH_PATTERN: Regex = Regex::new(r"^/[\w/.-]+$").unwrap();
}

// ❌ WRONG: Compile regex on every call
fn validate_path(path: &str) -> bool {
    Regex::new(r"^/[\w/.-]+$").unwrap().is_match(path)
}
```

---

## 🧪 Testing Protocol

### Test Categories

| Type | Location | When to Run | Coverage Target |
|------|----------|-------------|-----------------|
| Unit | `src/*.rs` (#[cfg(test)]) | Every change | 90% |
| Integration | `tests/*.rs` | Every PR | 80% |
| E2E | `sentinel-integration/` | Before release | Key flows |
| Benchmark | `benches/*.rs` | Performance changes | N/A |

### Test Commands

```bash
# Quick check (unit tests only, fast)
cargo test --lib --workspace

# Full test suite
cargo test --workspace

# With coverage (requires cargo-llvm-cov)
cargo llvm-cov --workspace --html

# Specific crate
cargo test -p sentinel-engine

# Specific test
cargo test -p sentinel-engine test_wildcard_matching

# Show output for debugging
cargo test -p sentinel-engine -- --nocapture
```

### Test Naming Convention

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Pattern: test_<function>_<scenario>_<expected>
    
    #[test]
    fn test_evaluate_exact_match_allows() { }
    
    #[test]
    fn test_evaluate_wildcard_tool_matches_any() { }
    
    #[test]
    fn test_evaluate_no_policy_denies() { }
    
    #[test]
    fn test_evaluate_blocked_path_denies_even_if_tool_allowed() { }
}
```

### Property-Based Testing (for critical paths)

```rust
// In sentinel-engine/src/lib.rs
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;
    use super::*;

    proptest! {
        #[test]
        fn evaluate_is_deterministic(
            tool in "[a-z_]{1,20}",
            function in "[a-z_]{1,20}",
        ) {
            let engine = PolicyEngine::new(vec![/* fixed policies */]);
            let action = Action { tool, function, parameters: json!({}) };
            
            let v1 = engine.evaluate(&action);
            let v2 = engine.evaluate(&action);
            
            prop_assert_eq!(v1, v2);
        }
        
        #[test]
        fn blocked_path_always_denies(
            path in "/home/[a-z]+/\\.aws/.*",
        ) {
            let engine = PolicyEngine::with_policy(Policy {
                path_rules: Some(PathRules {
                    blocked: vec!["/home/*/.aws/**".into()],
                    ..Default::default()
                }),
                ..Default::default()
            });
            
            let action = Action {
                tool: "read_file".into(),
                target_paths: vec![path],
                ..Default::default()
            };
            
            let verdict = engine.evaluate(&action).unwrap();
            prop_assert!(matches!(verdict, Verdict::Deny { .. }));
        }
    }
}
```

---

## 🐛 Debugging Protocol

### When a Test Fails

```bash
# 1. Isolate the failure
cargo test -p <crate> <test_name> -- --nocapture 2>&1 | tee /tmp/failure.log

# 2. Check if it's flaky (run 5 times)
for i in {1..5}; do cargo test -p <crate> <test_name> 2>&1 | tail -1; done

# 3. Get more context
RUST_BACKTRACE=1 cargo test -p <crate> <test_name> -- --nocapture

# 4. If async, check for race conditions
RUST_BACKTRACE=full TOKIO_WORKER_THREADS=1 cargo test -p <crate> <test_name>
```

### When Something Panics

```bash
# Get full backtrace
RUST_BACKTRACE=full cargo run -- <args> 2>&1 | tee /tmp/panic.log

# Find the panic source
grep -A5 "panicked at" /tmp/panic.log

# Check for unwrap/expect calls
rg "\.unwrap\(\)" --type rust -l
rg "\.expect\(" --type rust -l
```

### When Performance Degrades

```bash
# 1. Compare with baseline
cargo bench -- --baseline main

# 2. Profile
cargo flamegraph --bin sentinel -- <workload>

# 3. Check allocations
cargo run --features dhat-heap -- <workload>

# 4. Look for obvious issues
rg "\.clone\(\)" --type rust src/ | wc -l
rg "\.to_string\(\)" --type rust src/ | wc -l
rg "Vec::new\(\)" --type rust src/ | wc -l
```

### Failure Documentation

When you encounter a failure, create a record:

```bash
# Create failure log
mkdir -p .failures
FAILURE_ID=$(date +%Y%m%d-%H%M%S)
cat > ".failures/$FAILURE_ID.md" << EOF
# Failure: $FAILURE_ID

## Symptom
<what happened>

## Reproduction
\`\`\`bash
<exact commands>
\`\`\`

## Root Cause
<analysis>

## Fix
<what you changed>

## Prevention
<how to avoid this in future>
EOF
```

---

## 📦 Implementation Priorities

### Current State (as of session start)
- ✅ Core types, engine, audit, config, server
- ✅ 1,084 passing tests
- ⚠️ MCP has no transport (handler only)
- ⚠️ Engine matches tool:function only (no path/domain)
- ⚠️ RequireApproval verdict has no backend
- ⚠️ Audit log not tamper-evident

### Priority Order

```
P0 (This Session - Do First)
├── Fix any failing tests
├── Fix strict_mode warning
└── Add CI workflow if missing

P1 (Core Security Value)
├── Path/domain extraction in Action
├── PathRules/NetworkRules in Policy
├── Engine evaluates path/domain constraints
└── Tests for blocked path scenarios

P2 (MCP Integration)
├── MCP JSON-RPC parser
├── Action extractor from MCP params
├── stdio proxy implementation
└── Integration test with mock server

P3 (Approval System)
├── PendingStore implementation
├── Approval HTTP endpoints
├── Proxy integration (queue + replay)
└── Expiration cleanup

P4 (Audit Hardening)
├── Hash chain in audit entries
├── Verify command
└── Log rotation

P5 (Polish)
├── Demo scenario
├── README update
├── Example policies
└── Performance benchmarks
```

---

## 🔧 Code Change Protocol

### Small Change (<20 lines)

```bash
# 1. Make change
# 2. Test immediately
cargo test -p <affected-crate>
# 3. Commit if passes
git add -p && git commit -m "<type>(<scope>): <description>"
```

### Medium Change (20-100 lines)

```bash
# 1. Create feature branch
git checkout -b feat/<feature-name>

# 2. Make change incrementally, testing after each step
# 3. Run full test suite
cargo test --workspace

# 4. Check for regressions
cargo clippy --workspace
cargo fmt --check

# 5. Commit with context
git add -p && git commit -m "<type>(<scope>): <description>

- <bullet point of what changed>
- <why it changed>
"
```

### Large Change (>100 lines)

```bash
# 1. Create backup (see Backup Protocol above)

# 2. Write RFC comment in code or issue
# 3. Create feature branch
git checkout -b feat/<feature-name>

# 4. Implement in stages:
#    a. Types first (compile, test)
#    b. Core logic (compile, test)  
#    c. Integration (compile, test)
#    d. API surface (compile, test)

# 5. Run full validation
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
cargo doc --workspace --no-deps

# 6. Squash or organize commits
git rebase -i main

# 7. Merge only if all checks pass
```

---

## 📝 Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `refactor`: Code restructure (no behavior change)
- `test`: Adding/fixing tests
- `docs`: Documentation only
- `chore`: Build, CI, dependencies

**Scopes:** `types`, `engine`, `audit`, `config`, `mcp`, `server`, `integration`

**Examples:**
```
feat(engine): add path constraint evaluation

- PathRules struct with allowed/blocked glob patterns
- Engine checks target_paths against rules after tool match
- Blocked paths deny even if tool is allowed

Closes #12
```

```
fix(mcp): handle malformed JSON-RPC gracefully

Previously, invalid JSON caused panic. Now returns
ParseError with context for debugging.

Fixes #34
```

---

## 🚀 Session Workflow

### Start of Session

```bash
# 1. Pull latest
git pull origin main

# 2. Check state
cargo check --workspace
cargo test --workspace 2>&1 | tail -5

# 3. Review priorities (see Priority Order above)
cat CLAUDE.md | grep -A20 "Priority Order"

# 4. Pick ONE task from highest incomplete priority
# 5. State what you're doing before starting
```

### During Session

```bash
# After every significant change:
cargo check --workspace  # Fast compile check
cargo test -p <crate>    # Targeted tests

# Every 30 minutes:
cargo test --workspace   # Full suite
git add -p && git commit # Checkpoint

# If stuck for >15 minutes:
# - Write down what's blocking
# - Check .failures/ for similar issues
# - Consider smaller step
# - Ask for help with specific question
```

### End of Session

```bash
# 1. Run full validation
cargo test --workspace
cargo clippy --workspace

# 2. Document state
cat > .session-state.md << EOF
## Session End: $(date -Iseconds)

### Completed
- <what you finished>

### In Progress  
- <what's partially done>

### Blocked
- <what's stuck and why>

### Next Steps
- <what to do next session>
EOF

# 3. Commit everything
git add -A
git commit -m "chore: session checkpoint

$(cat .session-state.md)"

# 4. Push
git push origin $(git branch --show-current)
```

---

## 🎯 Definition of Done

A feature is DONE when:

- [ ] Implementation compiles with zero warnings
- [ ] Unit tests cover happy path and error cases
- [ ] Integration test exercises full flow
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo fmt --check` passes
- [ ] Documentation updated (rustdoc + README if user-facing)
- [ ] No `unwrap()` or `expect()` in library code (only tests/main)
- [ ] Error types are meaningful and actionable
- [ ] Performance is within budget (if applicable)
- [ ] Backward compatible OR migration documented

---

## 🛡️ Security Checklist

Before any PR touching security-relevant code:

- [ ] Fail-closed: errors → deny, not allow
- [ ] No path traversal possible in PathRules
- [ ] Domain normalization handles edge cases (ports, trailing dots, case)
- [ ] Audit log cannot be silently corrupted
- [ ] Secrets never logged (parameters may contain API keys)
- [ ] Rate limiting considered for endpoints
- [ ] Input validation on all external data

---

## 📚 Quick Reference

### Useful Commands

```bash
# Find TODOs
rg "TODO|FIXME|HACK|XXX" --type rust

# Find unwraps (should be zero in lib code)
rg "\.unwrap\(\)" --type rust -g '!**/tests/*' -g '!**/main.rs'

# Check dependency tree
cargo tree -p sentinel-engine

# Find unused dependencies
cargo +nightly udeps --workspace

# Update dependencies
cargo update
cargo test --workspace  # Verify nothing broke

# Generate docs
cargo doc --workspace --no-deps --open
```

### File Locations

| What | Where |
|------|-------|
| Core types | `sentinel-types/src/lib.rs` |
| Policy evaluation | `sentinel-engine/src/lib.rs` |
| Audit logging | `sentinel-audit/src/lib.rs` |
| Config parsing | `sentinel-config/src/lib.rs` |
| MCP handling | `sentinel-mcp/src/lib.rs` |
| HTTP server | `sentinel-server/src/main.rs` |
| Integration tests | `sentinel-integration/tests/` |
| Example configs | `examples/` or project root |

### Key Types

```rust
// What an agent wants to do
Action { tool, function, parameters, target_paths, target_domains, payload_bytes }

// A security rule  
Policy { id, name, policy_type, priority, path_rules, network_rules }

// Evaluation result
Verdict::Allow { reason, matched_policy }
Verdict::Deny { reason, matched_policy }
Verdict::RequireApproval { reason, conditions, matched_policy }
```

---

## ⚠️ Common Mistakes to Avoid

1. **Adding dependencies without justification** — Every dep is attack surface and compile time

2. **Using `unwrap()` in library code** — Use `?` or `ok_or_else()`

3. **Cloning when borrowing works** — Check if `&T` suffices before `T.clone()`

4. **Large commits** — Small, focused commits are easier to review and revert

5. **Skipping tests "just this once"** — Tests catch regressions YOU will introduce

6. **Ignoring warnings** — Warnings become bugs. Fix or explicitly allow with comment

7. **Changing public API without migration path** — Semver matters

8. **Async where sync suffices** — Async adds complexity. Use only when needed

9. **Silent failures** — Every error should be observable (logged or returned)

10. **Premature optimization** — Measure first. Optimize only proven hot spots

---

## 🏁 Success Criteria

The project is "done" when:

1. **Functional:** `sentinel proxy` intercepts MCP calls, enforces path/domain policies, logs everything
2. **Secure:** Demo shows blocked credential exfiltration attack
3. **Observable:** Audit log is tamper-evident and verifiable
4. **Fast:** <20ms end-to-end latency, <50MB memory
5. **Tested:** >85% coverage, all critical paths have property tests
6. **Documented:** README gets user running in <5 minutes
7. **Polished:** Zero warnings, clean clippy, formatted code

---

*Last updated: 2026-02-02*
