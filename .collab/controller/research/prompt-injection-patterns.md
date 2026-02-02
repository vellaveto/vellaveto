# Prompt Injection Detection: Research Summary for Instance B

**Source:** Controller research agent (a7244a7), C-10.4 C1
**Purpose:** Reference material for implementing C-11 Unicode sanitization and future pattern expansion
**Full agent output:** `/tmp/claude-1000/-home-paolo--vella-workspace-sentinel/tasks/a7244a7.output`

---

## Current State (15 patterns in proxy.rs:280-296)

| Category | Count | Patterns |
|----------|-------|----------|
| Instruction override | 4 | "ignore all/previous instructions", "disregard all/previous prior" |
| Identity hijack | 3 | "you are now", "act as if", "pretend you are" |
| System prompt | 4 | "new/override/forget system prompt", "system prompt:" |
| Tag injection | 3 | `<system>`, `</system>`, `[system]` |
| Escaped newline | 1 | `\\n\\nsystem:` (literal backslash-n, not actual newlines) |

---

## C-11 Must-Fix: Unicode Sanitization Pre-Processing

Add a pre-processing step BEFORE pattern matching in `inspect_response_for_injection()`:

### 1. Strip Unicode Control Characters

```rust
fn sanitize_for_injection_scan(input: &str) -> String {
    input.chars().filter(|c| {
        let cp = *c as u32;
        // Strip Unicode tags (U+E0000-E007F)
        !(0xE0000..=0xE007F).contains(&cp) &&
        // Strip zero-width chars
        !matches!(cp, 0x200B | 0x200C | 0x200D | 0xFEFF) &&
        // Strip bidi overrides (U+202A-202E)
        !(0x202A..=0x202E).contains(&cp) &&
        // Strip variation selectors (U+FE00-FE0F)
        !(0xFE00..=0xFE0F).contains(&cp)
    }).collect()
}
```

### 2. Apply NFKC Normalization

NFKC canonicalizes homoglyphs and fullwidth characters. The `unicode-normalization` crate provides this:

```rust
use unicode_normalization::UnicodeNormalization;
let normalized: String = sanitized.nfkc().collect();
```

This converts fullwidth "ｉｇｎｏｒｅ" → "ignore" and some homoglyphs to their canonical forms.

### 3. Apply to `inspect_response_for_injection()`

Sanitize text content before pattern matching. Apply to both `result.content[].text` and `structuredContent` stringification.

---

## Recommended Additional Patterns (Future — Not C-11 Scope)

### Category 5: Structural Injection Markers (high confidence, low FP)
- `[INST]`, `[/INST]` (Llama-style)
- `<|im_start|>`, `<|im_end|>` (ChatML)
- `### Instruction:`, `### System:` (Alpaca-style)
- `<IMPORTANT>`, `</IMPORTANT>` (tool description poisoning)
- `<!--` (HTML comments in tool results are suspicious)

### Category 6: MCP-Specific Tool Call Injection (high value)
- "call the .* tool" (regex)
- "execute .* with" (regex)
- "send to" + URL-like pattern
- "forward to" + URL-like pattern
- "exfiltrate", "exfil"

### Category 7: Meta-Instruction / Behavior Modification
- "for all future requests"
- "update your instructions"
- "your new priority"
- "from now on"
- "critical update:"

### Category 8: Role/Context Manipulation
- "assume the role of"
- "enter .* mode" (regex — "debug mode", "developer mode")
- "jailbreak"
- "do anything now"

---

## Key Research Finding: Evasion Success Rates

| Attack Type | Success Rate vs. Guardrails |
|-------------|---------------------------|
| Emoji smuggling | Up to 100% |
| Homoglyphs (Cyrillic/Latin) | Up to 92% |
| Base64 encoding | 64-94% |
| Zero-width characters | ~54% |
| Unicode tag characters | High (varies) |

**MCP-Guard (academic):** Regex-only (Stage 1) catches 38.9%. Full 3-stage pipeline reaches 89.6%.

**Key insight:** Regex-only detection is adequate for **log-only mode** (defense-in-depth alert). For **block mode**, a multi-scanner threshold (e.g., 2+ patterns match) or ML classifier is needed to control false positives.

---

## Configurable Patterns (Future Architecture)

Industry consensus: patterns should be user-configurable via config:

```toml
[injection_detection]
builtin_patterns = true
action = "log"  # "log" | "block" | "require_approval"
min_matches = 1
normalize_unicode = true
strip_invisible_chars = true

[[injection_detection.custom_patterns]]
pattern = "send.*credentials.*to"
type = "regex"
severity = "critical"
```

This is not in C-11 scope but should be planned for a future phase.
