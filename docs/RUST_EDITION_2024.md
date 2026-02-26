# Rust Edition 2024 Migration Plan

> **Status:** Planning (DO NOT apply yet)
> **Current edition:** 2021
> **Target edition:** 2024
> **Minimum Rust version required:** 1.85.0
> **Current MSRV:** 1.88.0 (already satisfies the requirement)
> **Created:** 2026-02-26

---

## Overview

Rust Edition 2024 was stabilized in Rust 1.85.0 (February 20, 2025). This
document catalogs the breaking changes and what they mean for the Vellaveto
workspace. The actual migration should be done as a dedicated PR with full
CI validation, not mixed with feature work.

**Reference:** https://doc.rust-lang.org/edition-guide/rust-2024/index.html

---

## Edition 2024 Changes and Impact Assessment

### 1. `unsafe_op_in_unsafe_fn` (HIGH impact)

**What changed:** In Edition 2024, the body of an `unsafe fn` is no longer
implicitly an unsafe block. All unsafe operations inside `unsafe fn` must be
wrapped in explicit `unsafe { }` blocks.

**Vellaveto impact:** Moderate. The codebase has unsafe code in:
- `vellaveto-audit/src/zk/` (cryptographic primitives)
- `vellaveto-engine/src/lib.rs` (performance-critical hot paths, if any)
- Any FFI or raw pointer manipulation

**Migration:** `cargo fix --edition` will auto-wrap unsafe operations. Manual
review is needed to ensure the unsafe blocks are scoped as narrowly as possible
(which is the whole point of this change -- better unsafe auditing).

### 2. RPIT Lifetime Capture Rules (MEDIUM impact)

**What changed:** Return Position Impl Trait (RPIT) in Edition 2024 captures
all in-scope lifetime parameters by default, not just those mentioned in the
bounds. This means `fn foo<'a>(x: &'a str) -> impl Display` now captures `'a`
implicitly.

**Vellaveto impact:** Could affect functions returning `impl Trait` that
previously did not capture certain lifetimes. Most commonly surfaces as:
- Functions returning `impl Iterator` or `impl Future`
- Async functions with references in their signatures

**Migration:** `cargo fix --edition` adds explicit `+ use<...>` bounds where
needed to preserve the old behavior. Review each case to determine if the new
capturing behavior is actually preferable.

### 3. `if let` Temporary Scope Changes (MEDIUM impact)

**What changed:** In Edition 2024, temporaries generated in `if let` and
`while let` scrutinee expressions are dropped at the end of the `if`/`while`
block body, not at the end of the enclosing block. This prevents accidental
lock-holding across match arms.

**Vellaveto impact:** This is actually beneficial for the codebase. Patterns
like `if let Ok(guard) = lock.read()` will now drop the guard sooner. However,
code that *depends* on the temporary living longer will break.

**Areas to check:**
- `RwLock`/`Mutex` guard patterns in `vellaveto-engine`, `vellaveto-mcp`
- `if let Some(x) = map.get(key)` patterns where the map borrow must live
  through the if-body

**Migration:** `cargo fix --edition` will flag affected cases. Manual review
is essential for lock-guard patterns in security-critical code.

### 4. Tail Expression Temporary Lifetimes (MEDIUM impact)

**What changed:** Temporaries in tail expressions (the last expression in a
block, used as the block's value) now have their lifetimes extended to the
end of the enclosing block in some cases, and shortened in others, depending
on the context.

**Vellaveto impact:** Could affect functions that return references to
temporaries created in tail expressions.

**Migration:** `cargo fix --edition` handles most cases. Review flagged
instances manually.

### 5. `gen` Keyword Reservation (LOW impact)

**What changed:** `gen` is reserved as a keyword in Edition 2024, in
anticipation of generator blocks (`gen { yield value; }`).

**Vellaveto impact:** Search for any identifiers named `gen` in the codebase.
If found, they must be renamed or prefixed with `r#gen`.

**Migration:** `cargo fix --edition` renames automatically. Verify no `gen`
identifiers exist in public APIs (would be a breaking change for consumers).

### 6. Prelude Additions (LOW impact)

**What changed:** `Future` and `IntoFuture` are added to the 2024 prelude.

**Vellaveto impact:** If any module defines its own `Future` or `IntoFuture`
type/trait, it will shadow the prelude import and cause ambiguity errors.
Unlikely in this codebase since we use `tokio` and `std::future::Future`
directly.

**Migration:** `cargo fix --edition` adds disambiguation where needed.

### 7. `unsafe extern` Blocks (LOW impact)

**What changed:** Items in `extern` blocks are now unsafe to call/use by
default. The `unsafe extern` syntax makes this explicit, and individual items
can be marked `safe` if they are known-safe.

**Vellaveto impact:** Any `extern "C"` blocks need to become `unsafe extern "C"`.
Check `vellaveto-audit/src/zk/` and any other FFI code.

**Migration:** `cargo fix --edition` handles this automatically.

### 8. `static_mut_refs` Lint (LOW impact)

**What changed:** Taking references to mutable statics is now a hard error
(was previously a warning). Use `addr_of!`/`addr_of_mut!` or `UnsafeCell`
instead.

**Vellaveto impact:** Search for `static mut` declarations. These are rare in
well-structured Rust code. The codebase uses `OnceLock`, `AtomicU64`, etc.,
so this is unlikely to be an issue.

**Migration:** Replace any `&STATIC_MUT` with `addr_of!(STATIC_MUT)`.

### 9. Macro Fragment Specifier Changes (LOW impact)

**What changed:** The `expr` fragment specifier in `macro_rules!` now matches
more expression types (including `const { }` blocks and other new syntax).
The old behavior is available as `expr_2021`.

**Vellaveto impact:** Custom macros using `$e:expr` may match more inputs
than intended. Review all `macro_rules!` definitions.

**Migration:** `cargo fix --edition` rewrites `$e:expr` to `$e:expr_2021`
where the broader matching would cause ambiguity.

### 10. `never_type_fallback_flowing_into_unsafe` (LOW impact)

**What changed:** The `!` (never) type fallback behavior changes. Code where
the never type could fallback to `()` and flow into unsafe code is now denied.

**Vellaveto impact:** Unlikely to affect the codebase unless there are
patterns where `!` coerces to `()` in unsafe contexts.

**Migration:** `cargo fix --edition` flags affected patterns.

### 11. `unsafe_attr_outside_unsafe` (LOW impact)

**What changed:** Attributes like `#[no_mangle]` and `#[link_section]` now
require being placed inside `unsafe(...)` contexts.

**Vellaveto impact:** Check for `#[no_mangle]` or `#[export_name]` attributes
in binary crates and FFI code.

**Migration:** `cargo fix --edition` handles this.

### 12. `std::env::set_var` and `std::env::remove_var` Now Unsafe (MEDIUM impact)

**What changed:** `std::env::set_var` and `std::env::remove_var` are now
`unsafe` functions because they can cause undefined behavior in multi-threaded
programs (environment is process-global shared mutable state).

**Vellaveto impact:** Search for `env::set_var` and `env::remove_var` usage,
particularly in test code. Test setup/teardown that modifies environment
variables will need `unsafe` blocks.

**Migration:** Wrap calls in `unsafe { }` blocks with a safety comment
explaining why the call is sound (e.g., single-threaded test context).

---

## Migration Procedure

### Pre-migration Checklist

```bash
# 1. Verify MSRV supports Edition 2024 (need >= 1.85.0)
rustc --version   # Current MSRV: 1.88.0 -- OK

# 2. Ensure all tests pass on current edition
cargo test --workspace --no-fail-fast

# 3. Run clippy clean
cargo clippy --workspace --all-targets -- -D warnings

# 4. Search for potentially affected patterns
grep -rn 'unsafe fn' vellaveto-*/src/ --include='*.rs'
grep -rn 'static mut' vellaveto-*/src/ --include='*.rs'
grep -rn 'extern "C"' vellaveto-*/src/ --include='*.rs'
grep -rn 'env::set_var\|env::remove_var' vellaveto-*/src/ --include='*.rs'
grep -rn 'macro_rules!' vellaveto-*/src/ --include='*.rs'
grep -rn '\bgen\b' vellaveto-*/src/ --include='*.rs'
grep -rn '#\[no_mangle\]' vellaveto-*/src/ --include='*.rs'
```

### Migration Steps

```bash
# 1. Run the automated migration tool
cargo fix --edition --workspace --allow-dirty

# 2. Update all Cargo.toml files to edition = "2024"
#    (There are 18 workspace member crates + the fuzz crate)
sed -i 's/edition = "2021"/edition = "2024"/g' \
  vellaveto-*/Cargo.toml mcpsec/Cargo.toml fuzz/Cargo.toml

# 3. Build and test
cargo check --workspace
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings

# 4. Manual review of all changes made by cargo fix
git diff --stat
git diff  # Review every change

# 5. Verify no behavioral changes in security-critical paths
cargo test -p vellaveto-engine -- --nocapture
cargo test -p vellaveto-audit -- --nocapture
cargo test -p vellaveto-mcp -- --nocapture
```

### Post-migration Verification

1. Run the full integration test suite
2. Run the adversarial attack battery
3. Verify no `unwrap()` was introduced by `cargo fix`
4. Verify fail-closed behavior is preserved
5. Run `cargo deny check` to ensure no license/advisory regressions

---

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|------------|
| `unsafe_op_in_unsafe_fn` | Medium | Auto-fixable; review for narrow scoping |
| RPIT lifetime capture | Medium | Auto-fixable; review for correctness |
| `if let` rescoping | Medium | Manual review of lock-guard patterns |
| `env::set_var` unsafe | Medium | Affects test code primarily |
| Tail expression temps | Low | Auto-fixable |
| `gen` keyword | Low | Unlikely to exist in codebase |
| Prelude additions | Low | Unlikely to conflict |
| `unsafe extern` | Low | Auto-fixable |
| `static_mut_refs` | Low | Already using proper atomics |
| Macro fragment specs | Low | Auto-fixable |

---

## Timeline Recommendation

1. **Phase 1 (this PR):** Document the migration plan (this file)
2. **Phase 2 (separate PR):** Run `cargo fix --edition` on a branch, review
   all changes, fix any issues that the auto-fixer cannot handle
3. **Phase 3 (same PR as Phase 2):** Update all `Cargo.toml` to `edition = "2024"`
4. **Phase 4 (CI):** Ensure CI runs with the new edition; update MSRV if needed

**Do NOT mix the edition migration with feature work.** It should be a
standalone PR for clean bisection if issues arise.
