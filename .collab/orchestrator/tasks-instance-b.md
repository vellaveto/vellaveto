# Tasks for Instance B

## READ THIS FIRST
Outstanding work from the previous round plus new tasks from the improvement plan. The Controller instance (when active) may override these. Check `controller/directives.md` first.

Update `.collab/instance-b.md` after each task.

---

## COMPLETED TASKS (for reference)
- [x] ISSUE B0: Fix unwrap() -- done by orchestrator
- [x] ISSUE B1: Fix misleading test name -- done by orchestrator
- [x] Task B1: Wire approval endpoints -- DONE
- [x] Task B2: Cache compiled regex -- DONE (bounded HashMap)
- [x] Task B3: MCP Stdio Proxy -- DONE (proxy.rs + extractor.rs + framing.rs + sentinel-proxy)

---

## Task B4: Replace `glob` with `globset`
**Priority: HIGH -- Performance hot path**

The `glob` crate compiles patterns on every call. The `globset` crate (by BurntSushi) pre-compiles and uses Aho-Corasick internally.

Steps:
1. In `sentinel-engine/Cargo.toml`, replace `glob = "0.3"` with `globset = "0.4"`
2. Refactor `eval_glob_constraint()` and `eval_not_glob_constraint()`:
   ```rust
   use globset::{Glob, GlobMatcher};

   let matcher = Glob::new(pattern)
       .map_err(|e| /* ... */)?
       .compile_matcher();
   matcher.is_match(normalized_path)
   ```
3. Consider adding a glob cache similar to the regex cache
4. Run: `cargo test -p sentinel-engine`

---

## Task B5: Pre-Sort Policies at Load Time
**Priority: MEDIUM -- Eliminates O(n log n) per evaluation**

Currently `evaluate_action()` sorts policies by priority on every call. Sort once at load/reload time instead:
- In `sentinel-server/src/routes.rs`: sort after `reload_policies` and `add_policy`
- In `sentinel-proxy/src/main.rs`: sort after loading from config
- Document that `evaluate_action()` expects pre-sorted input

---

## Task B6: Intercept `resources/read` in Proxy
**Priority: MEDIUM -- Security gap**

The proxy only intercepts `tools/call`. MCP also has `resources/read` which accesses files/URIs. Extend `classify_message()` in `extractor.rs`:

```rust
MessageType::ResourceRead { id, uri }  // New variant
```

Then evaluate the URI against path/domain constraints.

---

## Task B7: Deep Parameter Inspection (JSON Path)
**Priority: MEDIUM -- Security depth**

Support dot-separated paths in constraint `param` field:
```json
{"param": "config.output.path", "op": "glob", "pattern": "/etc/**"}
```

Implement `get_param_by_path()` in the engine to walk nested JSON.

---

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. **Check `controller/directives.md` before starting new work**
4. Instance A is NOT modifying your files. Safe to proceed on all your owned crates.
