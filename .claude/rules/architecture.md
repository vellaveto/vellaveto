# Architecture Rules — Sentinel (Rust)

These rules define the structural constraints all agents must follow.

## Crate Dependency Graph (NEVER VIOLATE)

```
sentinel-types          (leaf — no internal deps)
       |
sentinel-canonical      (types only)
sentinel-config         (types only)
       |
sentinel-engine         (types, ipnet)
       |
sentinel-audit          (types, engine)
sentinel-mcp            (types, engine)
sentinel-approval       (types)
       |
sentinel-cluster        (types, config, approval)
       |
sentinel-server         (all above)
sentinel-http-proxy     (all above)
sentinel-proxy          (all above, stdio mode)
sentinel-integration    (all above, test only)
```

Lower crates MUST NOT depend on higher crates.

## General Principles

1. **Fail-closed.** Errors, missing policies, and unresolved context produce `Deny`.
2. **No panics.** Zero `unwrap()` in library code — use `?` and `ok_or_else()` everywhere.
3. **Observable.** Every decision logged, every failure diagnosed.
4. **Fast.** <5ms P99 evaluation latency, <50MB memory baseline.

## File Organization

- Each crate lives in its own directory: `sentinel-<name>/`
- Source code: `sentinel-<name>/src/`
- Tests: `sentinel-<name>/tests/` (integration) or inline `#[cfg(test)]` (unit)
- Scripts and tooling: `scripts/`
- Agent definitions: `.claude/agents/`
- Rules: `.claude/rules/`
- Coordination state: `coordination/`

## Dependency Policy

- New dependencies must be justified in the commit message.
- Prefer well-maintained crates with good security records.
- Every dependency is attack surface — minimize count.
- Security vulnerabilities in dependencies are P1 findings.
- Use workspace dependencies in root `Cargo.toml`.

## Naming Conventions

- Files: `snake_case.rs` (Rust convention)
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Types/Structs/Enums: `PascalCase`
- Crates: `sentinel-<name>` (kebab-case)

## Error Handling

```rust
// CORRECT: Custom error type, no panics
pub fn evaluate(&self, action: &Action) -> Result<Verdict, EngineError> {
    let policy = self.find_policy(&action.tool)
        .ok_or_else(|| EngineError::NoPolicyFound(action.tool.clone()))?;
    // ...
}

// WRONG: Panics in library code
pub fn evaluate(&self, action: &Action) -> Verdict {
    let policy = self.find_policy(&action.tool).unwrap(); // NEVER
    // ...
}
```

- All external calls (network, file I/O) must have error handling.
- Never swallow errors silently — log and propagate.
- Use `thiserror` for error type definitions.
- Use `anyhow` only in binaries, not libraries.

## API Design

- RESTful endpoints follow standard HTTP semantics.
- All endpoints validate input with strong types.
- All endpoints return consistent JSON error format.
- Authentication required on all mutating endpoints.
- Rate limiting on all public endpoints.
- Fail-closed: invalid input → deny, not allow.

## Testing

- Test naming: `test_<function>_<scenario>_<expected>`
- All new code must have tests.
- Adversarial tests for security-critical paths.
- Property-based tests where applicable.

## Commits

```
<type>(<scope>): <subject>

<body>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`
Scopes: `types`, `engine`, `audit`, `config`, `mcp`, `server`, `proxy`, `integration`
