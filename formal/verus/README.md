# Verus Formal Verification

Deductive verification of Vellaveto's core verdict computation and DLP buffer
arithmetic using [Verus](https://github.com/verus-lang/verus).

## What Is Verified

### Core Verdict Logic (`verified_core.rs`)

Properties proven for ALL possible inputs (not bounded):

| ID | Property | Meaning |
|----|----------|---------|
| V1 | Fail-closed empty | Empty policy set -> Deny |
| V2 | Fail-closed no match | All unmatched -> Deny |
| V3 | Allow requires match | Allow -> matching non-deny, non-override policy exists |
| V4 | Rule override -> Deny | Path/network/IP override forces Deny |
| V5 | Totality | Function always terminates |
| V8 | Conditional pass-through | Unfired condition + continue -> skip to next |

Verification result: **9 verified, 0 errors** (Verus 0.2026.03.01, Z3 4.12.5).

Priority-dependent properties (V6, V7) require a sortedness precondition that
will be proven by a Kani harness (K19) in Phase 3.

### Proof Lemmas

| Lemma | What It Proves |
|-------|---------------|
| `lemma_first_match_override_is_deny` | First matched policy with rule_override -> final verdict is Deny |
| `lemma_all_unmatched_is_deny` | All unmatched entries -> final verdict is Deny |
| `lemma_skip_continues` | Consecutive Continue outcomes can be skipped (induction helper) |

## Production Code Correspondence

The production code lives at `vellaveto-engine/src/verified_core.rs`.
The Verus-annotated version lives here at `formal/verus/verified_core.rs`.

The executable logic is identical — Verus annotations (`ensures`, `requires`,
`invariant`, `decreases`, `proof fn`) are erased during normal compilation.
The production code uses `debug_assert` to validate that every verdict
decision agrees with the verified core.

## How to Verify

```bash
# Option 1: Binary release (recommended)
VERUS_VERSION="0.2026.03.01.25809cb"
curl -sSL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip"
unzip verus.zip -d verus-bin
rustup install 1.93.1-x86_64-unknown-linux-gnu
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# Option 2: From source
git clone https://github.com/verus-lang/verus
cd verus && ./tools/get-z3.sh && source ./tools/activate
cargo build --release
verus formal/verus/verified_core.rs
```

Expected output: `verification results:: 9 verified, 0 errors`

## Trust Boundary

See `docs/TRUSTED_COMPUTING_BASE.md` Section 5 for the full trust model.

Verus trusts:
- Z3 SMT solver (Microsoft Research)
- Verus verifier (translation from Rust+specs to Z3 queries)
- rustc codegen (LLVM)

Verus does NOT verify:
- The wrapper code that builds `ResolvedMatch` from policies and actions
- String operations, glob/regex matching, Unicode normalization
- HashMap, serde, I/O

Those are covered by Kani (bounded) and 10,000+ tests.
