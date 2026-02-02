# Tasks for Instance B — Directive C-8 (MCP Spec Alignment)

## READ THIS FIRST

Controller Directive C-8 is active. Based on web research into MCP spec v2025-11-25, OWASP MCP Top 10, and competitive landscape. Full report at `controller/research/mcp-spec-and-landscape.md`.

Update `.collab/instance-b.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (all previous directives)
- All C-2 security fixes (9/9)
- All C-6 protocol compliance (4/4)
- All C-7 items (#32 CORS, #36 log rotation)
- Improvement plan: I-B2 (redaction), I-B3 (percent-encoding), I-B4 (recursive scanning), I-B5 (request timeout)

---

## Task C8-B1: Tool Annotation Awareness (Phase 8.1)
**Priority: HIGH — Lowest effort, highest differentiation value**
**Directive:** C-8.2

MCP tools now have annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`.

**Implementation:**
1. In `sentinel-mcp/src/proxy.rs`, intercept `tools/list` responses in the child-to-agent relay path (currently all responses pass through without inspection)
2. Parse tool definitions from the response, extract annotations
3. Store annotations per tool name in `ProxyBridge` state (e.g., `HashMap<String, ToolAnnotations>`)
4. During `evaluate_tool_call()`, make annotations available as additional context
5. Default policy suggestion: `destructiveHint=true` → RequireApproval
6. Log tool annotations in audit entries as metadata
7. Detect and warn if tool definitions change between `tools/list` calls (rug-pull detection per OWASP MCP03)

**Important per MCP spec:** "annotations MUST be considered untrusted unless from trusted servers." Annotations inform policy but should not override explicit deny rules.

**Files:** `sentinel-mcp/src/proxy.rs`, `sentinel-mcp/src/extractor.rs`, possibly new `sentinel-mcp/src/annotations.rs`
**Test:** Verify annotations extracted, stored, available during evaluation, rug-pull detection triggers on change

---

## Task C8-B2: Response Inspection (Phase 8.2)
**Priority: HIGH — OWASP MCP06 coverage**
**Directive:** C-8.3

Sentinel only inspects outgoing requests (agent → tool), not responses (tool → agent). Prompt injection via tool results is a known attack vector.

**Implementation:**
1. In the child-to-agent relay path, inspect tool result content before forwarding
2. Add configurable inspection rules:
   - Regex patterns for known prompt injection phrases ("IGNORE ALL PREVIOUS INSTRUCTIONS", "system prompt:", etc.)
   - Configurable via policy or separate config
3. On match:
   - Default mode: log warning + forward (log-only, safe default)
   - Strict mode: block response, return sanitized error to agent
4. Log suspicious responses in audit trail with `"inspection": "prompt_injection_detected"` metadata
5. Add `ResponseInspector` struct with configurable patterns

**Files:** `sentinel-mcp/src/proxy.rs`, new `sentinel-mcp/src/inspector.rs`
**Test:** Verify injection patterns detected, logging works, blocking mode works, clean responses pass through

---

## Task I-B6: Lock-Free Policy Reads (Phase 6.1)
**Priority: LOW — Only if time permits**

Replace `Arc<RwLock<Vec<Policy>>>` with `arc-swap` for lock-free reads. See previous task file for details.

---

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `sentinel-engine/`, `sentinel-audit/`, `sentinel-canonical/`, `sentinel-mcp/`, `sentinel-proxy/`, `sentinel-approval/`
4. Work C8-B1 first (tool annotations), then C8-B2 (response inspection)
