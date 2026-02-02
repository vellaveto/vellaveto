# Collaboration Channel

This folder is used by multiple Claude instances working on the same Sentinel project.
Each instance writes to their own status file and appends to the shared log.

## Hierarchy (Authority Order)
```
Controller (HIGHEST — web research, strategic direction, corrections)
    |
Orchestrator (code review, task assignment, direct fixes)
    |
Instance A (testing, CI)     Instance B (features, engine)
```

## Instances
- **Controller** — Web research, strategic guidance, corrections for ALL instances (including Orchestrator). Controller directives override all other task assignments.
- **Orchestrator** — Code review, task assignment, direct fixes, codebase health monitoring
- **Instance A** — Code quality, integration tests, CI workflow, benchmarks
- **Instance B** — Core feature implementation (engine, audit, approval, proxy)

## Files
- `instance-a.md` — Status/notes from Instance A
- `instance-b.md` — Status/notes from Instance B
- `log.md` — Shared append-only log for messages between instances
- `controller/` — Controller instance
  - `controller/status.md` — Controller status and research summary
  - `controller/directives.md` — Active directives for all instances (HIGHEST PRIORITY)
  - `controller/corrections.md` — Corrections issued to instances
  - `controller/research/` — Detailed research documents
- `orchestrator/` — Orchestrator instance
  - `orchestrator/status.md` — Orchestrator audit and health report
  - `orchestrator/improvement-plan.md` — Research-backed improvement plan
  - `orchestrator/tasks-instance-a.md` — Task assignments for Instance A
  - `orchestrator/tasks-instance-b.md` — Task assignments for Instance B
  - `orchestrator/issues/` — Place to report blocking issues

## Protocol
1. Write your status to your own file
2. Append messages to log.md with a timestamp and your instance name
3. Read the other instance's file and the log before starting work
4. **Check `controller/directives.md` FIRST** — Controller directives override everything
5. **Read orchestrator/tasks-instance-{a,b}.md for your assignments**
6. Claim tasks explicitly to avoid conflicts
7. If blocked, write to orchestrator/issues/ with a descriptive filename

## Conflict Resolution
- Controller > Orchestrator > Instance A/B
- If the Controller and Orchestrator disagree, the Controller wins
- If Instance A and Instance B have a file conflict, the Orchestrator resolves it

## Current Project State (2026-02-02)
- 10 workspace crates, 1,359 tests passing, zero clippy warnings
- All P1-P3 features implemented (engine, audit, approval, proxy)
- MCP stdio proxy functional with policy enforcement
- CI workflow in place
- Improvement plan at `orchestrator/improvement-plan.md`
