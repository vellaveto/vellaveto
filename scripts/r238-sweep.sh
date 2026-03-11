#!/usr/bin/env bash
#
# r238-sweep.sh — R238 Full Codebase Sweep
#
# Launches discovery agents (adversarial, gap-hunter, improvement-scout) with
# targeted prompts for a deep codebase analysis, then orchestrator to triage.
#
# Usage: unset CLAUDECODE && bash scripts/r238-sweep.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
WORKTREE_BASE="${PROJECT_DIR}/../swarm-worktrees/${PROJECT_NAME}"
SHARED_BASE="${PROJECT_DIR}/../swarm-shared/${PROJECT_NAME}"
COORD_DIR="$(cd "$SHARED_BASE/coordination" && pwd)"

AGENT_TIMEOUT=900  # 15 minutes per agent for deep sweep

# Check prerequisites
if ! command -v claude &>/dev/null; then
    echo "ERROR: 'claude' CLI not found in PATH."
    exit 1
fi

if [ -n "${CLAUDECODE:-}" ]; then
    echo "ERROR: CLAUDECODE env var is set. Run: unset CLAUDECODE && bash scripts/r238-sweep.sh"
    exit 1
fi

echo "=== R238 Full Codebase Sweep ==="
echo "Project:   $PROJECT_DIR"
echo "Timeout:   ${AGENT_TIMEOUT}s per agent"
echo ""

# Phase 1: Launch discovery agents in parallel
echo "--- Phase 1: Discovery Agents ---"

ADVERSARIAL_PROMPT="You are the Adversarial Researcher agent for R238. Read .claude/agents/adversarial.md, then AGENTS.md, README.md, and ROADMAP.md for project context.

This is round R238 — a DEEP codebase sweep after 237 prior audit rounds and 1,630+ findings fixed. Your job: find what 237 rounds missed.

FOCUS AREAS for R238 (pick 3-4 and go DEEP):

1. CROSS-CRATE INVARIANT VIOLATIONS: Check that invariants documented in AGENTS.md and README.md are actually enforced everywhere. For example: does every transport (HTTP/WS/gRPC/stdio/SSE) actually have DLP scanning? Does every deserialized struct have deny_unknown_fields? Grep systematically.

2. RACE CONDITIONS & CONCURRENCY: Search for RwLock/Mutex usage. Check for TOCTOU patterns (read then act without holding lock). Check AtomicU64 ordering (Relaxed on security counters is a bypass). Check DashMap iteration-under-mutation.

3. ERROR HANDLING GAPS: Find places where .ok(), .unwrap_or_default(), or match with _ => {} silently swallow errors in security-critical paths. An error swallowed in policy evaluation = implicit Allow.

4. CONFIGURATION BYPASS: Check if config validation in vellaveto-config/src/ actually covers all fields. Look for config fields without validate() bounds. Check for numeric fields accepting NaN/Infinity. Check for string fields without has_dangerous_chars().

5. SUPPLY CHAIN: Check Cargo.toml for outdated/vulnerable deps. Check for unused dependencies. Check feature flags for unintended capability exposure.

6. FORMAL VS ACTUAL: The formal/ directory has TLA+, Alloy, Kani, Verus, Lean, Coq proofs. Check if the code actually matches what the formal specs verify. Look for drift between formal models and implementation.

Report findings as: python3 scripts/lib/lock.py append coordination/events.jsonl '{\"event\":\"finding.created\",\"id\":\"R238-ADV-NNN\",\"severity\":\"P0|P1|P2\",\"status\":\"open\",\"category\":\"security\",\"title\":\"...\",\"description\":\"... with file:line refs\",\"recommendation\":\"...\",\"agent\":\"adversarial\"}'

CRITICAL: Read coordination/events.jsonl first to avoid duplicates. Be specific with file:line references. No false positives — every finding must be verifiable."

GAP_HUNTER_PROMPT="You are the Gap Hunter agent for R238. Read .claude/agents/gap-hunter.md, then AGENTS.md, README.md, and ROADMAP.md for project context.

This is round R238 — deep sweep after 237 rounds. Find the gaps that compound over time.

FOCUS AREAS for R238 (pick 3-4 and go DEEP):

1. TEST COVERAGE GAPS: The project claims 10,350 tests. Find crates/modules with disproportionately low coverage. Check: does vellaveto-approval have tests? Does vellaveto-cluster? Do the SDKs (sdk/python, sdk/typescript, sdk/go, sdk/java) have integration tests that actually hit a running server? Are there critical code paths with zero test coverage?

2. DOCUMENTATION DRIFT: Compare README.md, AGENTS.md, and ROADMAP.md claims against actual code. Do the counts match? Are all listed file paths still valid? Are the architecture rules (crate dependency graph) actually enforced in Cargo.toml? Is the OpenAPI spec (docs/openapi.yaml) in sync with actual server routes?

3. FAIL-CLOSED AUDIT: Systematically check every error/default path in security-critical code. grep for unwrap_or(false), unwrap_or(true), unwrap_or_default() in engine/audit/mcp crates. Each one is a potential fail-open. Check Default impls on security types — are defaults restrictive?

4. BOUNDARY VALIDATION: Check every struct that takes external input. Does it validate string lengths? Does it validate collection sizes (Vec/HashMap bounds)? Does it validate numeric ranges? Are there MAX_* constants for every bounded field?

5. TRANSPORT PARITY: README.md documents verified transport parity. Systematically verify: does the gRPC handler have the same checks as the HTTP handler? Does stdio? Does SSE? Pick 3 security features and trace them across all transports.

6. SDK PARITY: Check if all 4 SDKs (Python, TypeScript, Go, Java) expose the same API surface. Check if request/response formats match the server. Check if SDKs validate input before sending.

Report findings as: python3 scripts/lib/lock.py append coordination/events.jsonl '{\"event\":\"finding.created\",\"id\":\"R238-GAP-NNN\",\"severity\":\"P0|P1|P2\",\"status\":\"open\",\"category\":\"quality|security|reliability\",\"title\":\"...\",\"description\":\"... with file:line refs\",\"recommendation\":\"...\",\"agent\":\"gap-hunter\"}'

CRITICAL: Read coordination/events.jsonl first to avoid duplicates. Provide concrete evidence (file:line) for every finding."

IMPROVEMENT_PROMPT="You are the Improvement Scout agent for R238. Read .claude/agents/improvement-scout.md, then AGENTS.md, README.md, and ROADMAP.md for project context.

This is round R238 — deep sweep after 237 rounds. Focus on structural improvements with highest ROI.

FOCUS AREAS for R238 (pick 3-4 and go DEEP):

1. PERFORMANCE HOT PATHS: Profile the engine evaluation path. Check cache.rs for unnecessary allocations. Check if compiled policies are actually faster than interpreted. Check for unnecessary cloning in the proxy bridge. Look at String allocations in the injection scanner hot path.

2. CODE HEALTH: Find the largest files (>2000 lines) and assess if they should be split. Find duplicated logic across crates. Check for dead code (functions defined but never called). Check for overly complex functions (>200 lines).

3. DEPENDENCY AUDIT: Are all deps in Cargo.toml actually used? Are there lighter alternatives for heavy deps? Check feature flags — are we pulling in more than we need? What's the total dep tree size?

4. OPERATIONAL EXCELLENCE: What would an operator need to run this in production that's missing? Health checks, graceful shutdown, config reload, metrics endpoints, log rotation, crash recovery, backup/restore for audit data.

5. DEVELOPER EXPERIENCE: What slows down development? Compile times (check for heavy generics/proc macros), test times, unclear error messages, missing examples, confusing module structure.

6. SECURITY ARCHITECTURE: Are there structural improvements that would eliminate entire classes of bugs? For example: a type-level enforcement that secrets can't be logged, or a compile-time check that all transports have parity.

Report as: python3 scripts/lib/lock.py append coordination/events.jsonl '{\"event\":\"finding.created\",\"id\":\"R238-IMP-NNN\",\"severity\":\"P1|P2|P3\",\"status\":\"open\",\"category\":\"improvement\",\"title\":\"...\",\"description\":\"...\",\"recommendation\":\"...\",\"impact\":\"...\",\"estimated_effort_hours\":N,\"agent\":\"improvement-scout\"}'

CRITICAL: Read coordination/events.jsonl first to avoid duplicates. Every proposal must have concrete impact/effort analysis."

ORCHESTRATOR_PROMPT="You are the Orchestrator agent for R238. Read .claude/agents/orchestrator.md, then AGENTS.md, README.md, and ROADMAP.md for project context.

This is R238 — a full codebase sweep. Your job:

1. Read coordination/kanban.json (use: python3 scripts/lib/lock.py read-revision coordination/kanban.json, then cat coordination/kanban.json)
2. Read ALL of coordination/events.jsonl to see what findings the adversarial, gap-hunter, and improvement-scout agents have reported
3. Triage ALL findings into the kanban board:
   - P0: Create task immediately, mark as blocking
   - P1: Create task with high priority
   - P2: Create task with medium priority
   - P3: Create task with low priority
4. Group related findings into single tasks where appropriate
5. Assign tasks: worker-1 gets implementation tasks (research_required=false), worker-2 gets research-heavy tasks (research_required=true)
6. Write the updated kanban via: python3 scripts/lib/lock.py revision-write coordination/kanban.json <rev> '<json>'
7. Log all triage decisions as decision.made events

Focus on creating ACTIONABLE tasks. Each task must have: id, title, description (with file:line refs from the finding), priority, tags, estimated_hours. Never write code yourself."

# Tool restrictions
DISCOVERY_TOOLS="Bash,Read,Grep,Glob"
ORCH_TOOLS="Bash,Read,Grep,Glob"

PIDS=()
AGENTS=()

for agent_data in \
    "adversarial|${ADVERSARIAL_PROMPT}" \
    "gap-hunter|${GAP_HUNTER_PROMPT}" \
    "improvement-scout|${IMPROVEMENT_PROMPT}"; do

    agent="${agent_data%%|*}"
    prompt="${agent_data#*|}"
    WORKTREE="${WORKTREE_BASE}/${agent}"

    # Rotate log
    if [ -f "$WORKTREE/.swarm-agent.log" ] && [ -s "$WORKTREE/.swarm-agent.log" ]; then
        mv "$WORKTREE/.swarm-agent.log" "$WORKTREE/.swarm-agent.log.prev"
    fi

    echo "  Launching $agent (${AGENT_TIMEOUT}s timeout)..."
    (
        cd "$WORKTREE"
        export SWARM_AGENT="$agent"
        printf '%s' "$prompt" | timeout "$AGENT_TIMEOUT" claude --print \
            --add-dir "$COORD_DIR" \
            --add-dir "$PROJECT_DIR" \
            --allowedTools "$DISCOVERY_TOOLS" \
            > "$WORKTREE/.swarm-agent.log" 2>&1
    ) &
    PIDS+=($!)
    AGENTS+=("$agent")
    sleep 3
done

echo ""
echo "Discovery agents launched. Waiting for completion..."
echo ""

# Wait for discovery agents
idx=0
for pid in "${PIDS[@]}"; do
    agent="${AGENTS[$idx]}"
    exit_code=0
    wait "$pid" 2>/dev/null || exit_code=$?
    if [ "$exit_code" -eq 124 ]; then
        echo "  WARNING: $agent timed out after ${AGENT_TIMEOUT}s"
    else
        echo "  $agent finished (exit: $exit_code)"
    fi
    # Show output size
    SIZE=$(wc -c < "${WORKTREE_BASE}/${agent}/.swarm-agent.log" 2>/dev/null || echo 0)
    echo "    Output: ${SIZE} bytes"
    idx=$((idx + 1))
done

echo ""
echo "--- Phase 2: Orchestrator Triage ---"

WORKTREE="${WORKTREE_BASE}/orchestrator"
if [ -f "$WORKTREE/.swarm-agent.log" ] && [ -s "$WORKTREE/.swarm-agent.log" ]; then
    mv "$WORKTREE/.swarm-agent.log" "$WORKTREE/.swarm-agent.log.prev"
fi

echo "  Launching orchestrator (${AGENT_TIMEOUT}s timeout)..."
(
    cd "$WORKTREE"
    export SWARM_AGENT="orchestrator"
    printf '%s' "$ORCHESTRATOR_PROMPT" | timeout "$AGENT_TIMEOUT" claude --print \
        --add-dir "$COORD_DIR" \
        --add-dir "$PROJECT_DIR" \
        --allowedTools "$ORCH_TOOLS" \
        > "$WORKTREE/.swarm-agent.log" 2>&1
)
echo "  Orchestrator finished."

# Summary
echo ""
echo "=== R238 Sweep Complete ==="
EVENTS_COUNT=$(wc -l < "$COORD_DIR/events.jsonl" 2>/dev/null || echo 0)
KANBAN_REV=$(python3 "$PROJECT_DIR/scripts/lib/lock.py" read-revision "$COORD_DIR/kanban.json" 2>/dev/null || echo "?")
echo "Events: $EVENTS_COUNT | Kanban rev: $KANBAN_REV"
echo ""
echo "View findings:  cat coordination/events.jsonl | python3 -m json.tool"
echo "View kanban:    cat coordination/kanban.json | python3 -m json.tool"
echo "View agent logs: cat /home/paolo/.vella-workspace/swarm-worktrees/sentinel/<agent>/.swarm-agent.log"
