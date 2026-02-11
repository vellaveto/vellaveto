# Module Extraction Playbook

This playbook defines the standard process for splitting large modules into smaller ones without changing security posture or API behavior.

## Goals

- Keep refactors small, reviewable, and reversible.
- Preserve fail-closed behavior and existing API contracts.
- Maintain crate layering (`sentinel-types` lowest, runtime binaries highest).
- Keep split windows free from unrelated functional refactors.

## When To Use

Use this playbook when:

- splitting large files (for example route handlers) into dedicated modules
- moving code across files inside the same crate
- extracting shared internal helpers behind crate-local APIs

Do not use this as a license for behavior changes. If behavior must change, isolate it in a separate follow-up patch.

## Step 1: Define Scope And Invariants

Before moving code:

- Identify the owning crate and nearest `AGENTS.md` instructions.
- List the invariants that must remain unchanged:
  - endpoint auth and status code behavior
  - audit/metrics emission and labels
  - policy evaluation semantics
  - error handling mode (fail-open/fail-closed)
- Record the test files that currently cover those invariants.

## Step 2: Add Or Confirm Targeted Coverage

Add focused tests first if coverage is thin. Prefer crate-local tests over workspace-wide runs during iteration.

Examples:

- `cargo test -p sentinel-server`
- `cargo test -p sentinel-http-proxy --test proxy_integration`
- `cargo test -p sentinel-engine`

## Step 3: Extract In Small Compile-Green Slices

- Create destination modules with `pub(crate)` visibility by default.
- Move one cohesive unit at a time (types/helpers, then handlers/call sites).
- Keep old entrypoints delegating temporarily when needed to reduce risk.
- Run focused tests after each slice.

Avoid `unwrap()`/`expect()` in library code; return typed errors.

## Step 4: Enforce Contract Safety

If extraction touches shared contracts (`sentinel-types`) or cross-crate public behavior, run explicit contract checks:

- `cargo test -p sentinel-types --locked`
- `cargo test -p sentinel-engine --locked`
- `cargo test -p sentinel-config --locked`
- `cargo test -p sentinel-mcp --locked`
- `cargo test -p sentinel-server --locked`
- `cargo test -p sentinel-http-proxy --locked`
- `cargo test -p sentinel-integration --locked`

## Step 5: Run Final Gates

After focused checks pass:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets`
- `cargo test --workspace`

Also run feature-gated checks when relevant:

- `cargo test -p sentinel-mcp --features a2a`
- `cargo test -p sentinel-server --features redis-backend`

## Step 6: PR Hygiene

Each extraction PR should include:

- brief scope statement (what moved, what did not change)
- invariant checklist and linked tests
- any contract-impacting paths touched
- rollback note (which commit can be reverted cleanly)

Recommended structure:

1. mechanical move/rename
2. wiring updates
3. test updates
4. optional cleanup (no behavior change)

## Step 7: Post-Merge Monitoring

After merge:

- watch CI for flaky regressions in touched modules
- monitor runtime metrics/audit fields tied to moved paths
- quickly revert isolated extraction commit(s) if invariants regress
