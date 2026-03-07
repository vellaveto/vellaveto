# Full Codebase Sweep Runbook

This runbook executes a full codebase sweep with Codex sessions and Codex
skills, without Bottega. It uses separate git worktrees, explicit prompts, and
non-interactive merge steps so the sweep can run in parallel without mixing
state.

## Goal

Run a deep, low-overlap, multi-session sweep across the full codebase with:

- exact round and wave naming
- exact prompts to give each Codex session
- explicit skill usage per wave
- deterministic session order
- controlled fix, verify, and merge cadence

## Assumptions

- The root worktree may be dirty and should not be used for concurrent edit work.
- Each Codex session gets its own git worktree.
- Scout sessions are read-only and do not commit.
- Fix sessions write code and commit.
- Merge happens only from a dedicated integration worktree.

## Round Naming

Use one campaign round ID:

- Format: `RNNN`
- Example: `R239`

Wave IDs:

- `W0` = coordination and baseline
- `W1` = breadth scout
- `W2A` = core contracts
- `W2B` = security and data path
- `W2C` = runtime and ops
- `W3` = fix and closure

Branch naming:

- Coordinator: `sweep/R239/w0-coordinator`
- Breadth scout: `sweep/R239/w1-breadth`
- Core contracts scout: `sweep/R239/w2a-contracts`
- Security/data scout: `sweep/R239/w2b-data-path`
- Runtime/ops scout: `sweep/R239/w2c-runtime`
- Fix branches: `sweep/R239/w3-fix-<topic>`
- Integrator: `sweep/R239/integration`

Artifact naming:

- `quality/reports/R239-W1-findings.md`
- `quality/reports/R239-W2A-findings.md`
- `quality/reports/R239-W2B-findings.md`
- `quality/reports/R239-W2C-findings.md`
- `quality/reports/R239-W3-closure.md`

## Worktree Setup

Start from a clean mainline snapshot and create dedicated worktrees:

```bash
git fetch origin
git switch main
git pull --ff-only

git worktree add ../sentinel-r239-coordinator -b sweep/R239/w0-coordinator main
git worktree add ../sentinel-r239-breadth -b sweep/R239/w1-breadth main
git worktree add ../sentinel-r239-contracts -b sweep/R239/w2a-contracts main
git worktree add ../sentinel-r239-data-path -b sweep/R239/w2b-data-path main
git worktree add ../sentinel-r239-runtime -b sweep/R239/w2c-runtime main
git worktree add ../sentinel-r239-fix-a -b sweep/R239/w3-fix-a main
git worktree add ../sentinel-r239-fix-b -b sweep/R239/w3-fix-b main
git worktree add ../sentinel-r239-integration -b sweep/R239/integration main
```

## Session Order

Open Codex sessions in this order:

1. Coordinator
2. Breadth Scout
3. Core Contracts Scout
4. Security/Data Path Scout
5. Runtime/Ops Scout
6. Fixer A
7. Fixer B
8. Verifier
9. Committer / Integrator

Sessions 2 through 5 can run in parallel after the coordinator finishes.
Sessions 6 through 9 start only after the scout findings are consolidated.

## Wave Prompts

### W0 Coordinator

Worktree: `../sentinel-r239-coordinator`

Prompt:

```text
Use `plan-work`.

Round: R239
Wave: W0 coordinator

Goal:
- Establish the sweep baseline for the full repository.

Tasks:
- Read the root AGENTS.md and the nearest AGENTS.md files for the highest-risk modules.
- Inspect the current worktree state and identify existing local diffs that must remain untouched.
- Build a one-page sweep map covering:
  - workspace crates
  - non-crate surfaces (`.github/workflows`, `scripts`, `helm`, `sdk`, `security-testing`, `formal`, `fuzz`)
  - likely high-conflict areas
  - recommended ordering for the scout waves
- Do not edit code.
- Deliverable: a concise markdown brief saved to `quality/reports/R239-W0-map.md`.
```

### W1 Breadth Scout

Worktree: `../sentinel-r239-breadth`

Prompt:

```text
Use `plan-work`.

Round: R239
Wave: W1 breadth scout

Goal:
- Perform a read-only, full-repository breadth sweep and find the highest-signal issues missed by local narrow passes.

Scope:
- Entire workspace from `Cargo.toml`
- `.github/workflows/`, `scripts/`, `helm/`, `sdk/`, `security-testing/`, `formal/`, `fuzz/`

Focus:
- cross-crate invariants
- fail-closed defaults
- boundary validation
- concurrency and lock misuse
- docs/config/CI drift
- transport parity

Rules:
- Findings only, no edits.
- Prioritize bugs, security risks, regressions, and missing tests.
- Every finding must include file:line refs and a concrete reason it matters.
- Save the report to `quality/reports/R239-W1-findings.md`.
```

### W2A Core Contracts Scout

Worktree: `../sentinel-r239-contracts`

Prompt:

```text
Use `plan-work`.

Round: R239
Wave: W2A core contracts

Goal:
- Deep-scan shared contracts and fail-closed boundaries.

Scope:
- `vellaveto-types/`
- `vellaveto-config/`
- `vellaveto-engine/`
- `vellaveto-canonical/`
- `vellaveto-discovery/`
- `formal/` and `fuzz/` where they exercise the same contracts

Focus:
- deserialization boundaries
- `deny_unknown_fields` triage
- normalization drift
- config validation completeness
- numeric/string/collection bounds
- formal-vs-actual contract drift

Rules:
- Findings only, no edits.
- Save the report to `quality/reports/R239-W2A-findings.md`.
```

### W2B Security/Data Path Scout

Worktree: `../sentinel-r239-data-path`

Prompt:

```text
Use `plan-work`.

Round: R239
Wave: W2B security and data path

Goal:
- Deep-scan the MCP, audit, approval, shield, cluster, and crypto-adjacent paths.

Scope:
- `vellaveto-mcp/`
- `vellaveto-audit/`
- `vellaveto-approval/`
- `vellaveto-cluster/`
- `vellaveto-mcp-shield/`
- `vellaveto-http-proxy-shield/`
- `vellaveto-shield/`
- `vellaveto-tls/`
- `security-testing/`

Focus:
- inspection bypasses
- replay and nonce handling
- audit integrity and Merkle/checkpoint verification
- approval fail-open paths
- session isolation and stale state
- cryptographic material exposure

Rules:
- Findings only, no edits.
- Save the report to `quality/reports/R239-W2B-findings.md`.
```

### W2C Runtime/Ops Scout

Worktree: `../sentinel-r239-runtime`

Prompt:

```text
Use `plan-work` and `ci-fix` only for workflow diagnosis, not for fixes.

Round: R239
Wave: W2C runtime and ops

Goal:
- Deep-scan the runtime binaries, auth surfaces, deployment assets, and CI/release workflows.

Scope:
- `vellaveto-server/`
- `vellaveto-proxy/`
- `vellaveto-http-proxy/`
- `vellaveto-operator/`
- `vellaveto-canary/`
- `.github/workflows/`
- `helm/`
- `sdk/`
- `scripts/`

Focus:
- authn/authz parity
- tenant/RBAC/OAuth/DPoP edge cases
- workflow drift
- deploy and release correctness
- helm/operator/runtime config mismatch
- SDK/server surface mismatch

Rules:
- Findings only, no edits.
- Save the report to `quality/reports/R239-W2C-findings.md`.
```

## Findings Consolidation

After the four scout sessions finish, use one Codex session in the coordinator
worktree with this prompt:

```text
Use `plan-work`.

Round: R239
Task:
- Read `quality/reports/R239-W1-findings.md`, `R239-W2A-findings.md`, `R239-W2B-findings.md`, and `R239-W2C-findings.md`.
- Deduplicate overlapping findings.
- Bucket them into:
  - P0 immediate fix
  - P1 next fix
  - P2 backlog
  - P3 follow-up
- Produce a single prioritized task list in `quality/reports/R239-master-findings.md`.
- Do not edit code.
```

## Fix Wave Prompts

Only start fix waves after `R239-master-findings.md` exists.

### W3 Fixer A

Worktree: `../sentinel-r239-fix-a`

Prompt:

```text
Use `bug-triage`.

Round: R239
Wave: W3 fixer A

Input:
- Read `quality/reports/R239-master-findings.md`.

Goal:
- Implement the top-priority P0 or P1 item assigned to Fixer A.

Rules:
- Touch only the files needed for the selected issue.
- Add or update focused tests.
- Do not take a second issue in the same turn.
- Commit the result when done.
- At the end, report the exact tests run and any residual risk.
```

### W3 Fixer B

Worktree: `../sentinel-r239-fix-b`

Prompt:

```text
Use `bug-triage`.

Round: R239
Wave: W3 fixer B

Input:
- Read `quality/reports/R239-master-findings.md`.

Goal:
- Implement the next highest-priority non-overlapping P0 or P1 item assigned to Fixer B.

Rules:
- Avoid file overlap with Fixer A.
- Add or update focused tests.
- Do not take a second issue in the same turn.
- Commit the result when done.
- At the end, report the exact tests run and any residual risk.
```

## Verification Prompt

Use a separate Codex session in the integration worktree:

```text
Use `coding-guidelines-verify`.

Round: R239
Task:
- Review the fix branches prepared for this round.
- Check they follow the nearest AGENTS.md rules.
- Run the narrowest meaningful tests first, then widen if contracts crossed crate boundaries.
- Report violations, missing tests, or residual risks before merge.
- Do not rewrite unrelated code.
```

## Commit Prompt

If the fix branch needs commit cleanup before integration:

```text
Use `commit-work`.

Round: R239
Task:
- Review the current branch changes.
- Keep only the intended fix in the commit.
- Write a clear conventional commit message.
- Do not amend unrelated prior commits.
```

## Merge Cadence

Use the integration worktree: `../sentinel-r239-integration`

### P0 cadence

- One branch per P0 fix.
- Rebase onto `main` immediately before merge.
- Merge immediately after verification.
- Run targeted tests plus `bash scripts/run-quality-gates.sh` after each P0 merge.

Commands:

```bash
cd ../sentinel-r239-integration
git switch main
git pull --ff-only
git merge --no-ff sweep/R239/w3-fix-a -m "fix: resolve R239 P0 issue"
bash scripts/run-quality-gates.sh
```

### P1 cadence

- At most 2 approved fix branches before merge.
- If branches touch shared contracts or auth/runtime surfaces, merge one at a time.
- Rebase each fix branch on `main` before merge.

Commands:

```bash
cd ../sentinel-r239-fix-a
git fetch origin
git rebase main

cd ../sentinel-r239-integration
git switch main
git pull --ff-only
git merge --no-ff sweep/R239/w3-fix-a -m "fix: resolve R239 P1 issue A"
git merge --no-ff sweep/R239/w3-fix-b -m "fix: resolve R239 P1 issue B"
bash scripts/run-quality-gates.sh
```

### Scout cadence

- Scout branches never merge.
- If a scout found only findings, either keep the branch for traceability or delete the worktree after the report is saved.

## Closeout Prompt

After all intended fixes are merged:

```text
Use `coding-guidelines-verify`.

Round: R239
Wave: closeout

Goal:
- Verify the merged state is coherent.

Tasks:
- Re-read `quality/reports/R239-master-findings.md`.
- Confirm each P0/P1 is fixed or explicitly deferred.
- Run final validation appropriate to touched areas.
- Produce `quality/reports/R239-W3-closure.md` with:
  - fixed items
  - deferred items
  - residual risks
  - validation summary
```

## Final Gates

At campaign close, run from the integration worktree:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Add feature-gated or workflow-specific checks if the touched fixes require them.

## Stop Conditions

Pause the sweep if any of these are true:

- the integration worktree cannot stay close to `main`
- two fix branches start colliding on the same files or invariants
- final verification reveals a shared-contract regression
- a newly found P0 invalidates the current merge queue

## Completion Criteria

The sweep is complete when:

- all scout waves have written their reports
- the master findings file exists and is deduplicated
- every P0 and P1 is fixed or explicitly deferred with rationale
- the final gates are green
- `R239-W3-closure.md` records the residual risk clearly
