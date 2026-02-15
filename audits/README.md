# Audit History

Vellaveto has undergone **39 rounds of internal adversarial testing** using an
automated multi-agent protocol ([Bottega](https://github.com/paolovella/bottega)).
These are **not** third-party penetration tests conducted by an external firm.

## Methodology

Each audit round follows this procedure:

1. **Attack generation.** An automated adversarial agent generates attack payloads
   targeting known vulnerability classes (OWASP Agentic Top 10, MCP-specific
   threats, MITRE ATLAS techniques).
2. **Execution.** Payloads are submitted against a running Vellaveto instance in
   all supported deployment modes.
3. **Triage.** Findings are classified by severity:
   - **P0 (Critical):** Bypass of fail-closed semantics, Allow without matching
     policy, audit chain corruption
   - **P1 (High):** Authentication bypass, injection evasion, DLP bypass
   - **P2 (Medium):** Information leakage, rate limit bypass, edge case handling
   - **P3 (Low):** Documentation gaps, hardening opportunities, code quality
4. **Fix.** Each finding is addressed in a dedicated commit with regression tests.
5. **Verification.** The adversarial agent re-runs the original attack to confirm
   the fix. Findings that fail verification are reopened.

## Round Summary

| Round(s) | Phase | Scope | Findings | Fixed | Severity Distribution |
|----------|-------|-------|----------|-------|-----------------------|
| 1–5 | Core engine | Policy evaluation, path traversal, DNS rebinding | 42 | 42 | 3 P0, 8 P1, 19 P2, 12 P3 |
| 6–10 | DLP + injection | Multi-layer decode, NFKC normalization, semantic detection | 38 | 38 | 1 P0, 6 P1, 18 P2, 13 P3 |
| 11–15 | Transport | HTTP proxy, WebSocket, stdio, auth flows | 45 | 45 | 2 P0, 9 P1, 21 P2, 13 P3 |
| 16–20 | Advanced auth | ABAC, capability tokens, delegation, NHI | 52 | 52 | 4 P0, 11 P1, 22 P2, 15 P3 |
| 21–25 | ETDI + supply chain | Rug-pull, squatting, schema poisoning, ETDI signatures | 48 | 48 | 2 P0, 7 P1, 24 P2, 15 P3 |
| 26–30 | Compliance | EU AI Act, SOC 2, audit integrity, transparency | 35 | 35 | 1 P0, 5 P1, 17 P2, 12 P3 |
| 31–35 | Multi-modal + A2A | Audio/video inspection, A2A protocol, session guards | 42 | 42 | 2 P0, 8 P1, 19 P2, 13 P3 |
| 36–39 | Hardening | RwLock poisoning, PDF parsing, stego bounds, whitespace normalization | 28 | 28 | 0 P0, 4 P1, 14 P2, 10 P3 |

**Total: 330+ findings triaged, 330+ fixed and verified.**

The "400+ findings" count in the README badge includes findings from the
pentest harness (FIND-043–084+) documented in `security-testing/` and
additional findings from improvement rounds.

## Evidence

| Artifact | Location |
|----------|----------|
| Finding consolidation plan | `SWARM_FINDINGS_PLAN.md` |
| Per-phase changelog entries | `CHANGELOG.md` (search for "FIND-" or "audit round") |
| Pentest harness | `security-testing/` |
| Attack playbook | `ATTACK_PLAYBOOK.md` |
| Regression test suite | `vellaveto-integration/tests/security_regression.rs` |

## Clarification

The README badge reads "Security Audit: 38 rounds, 400+ findings". To be
precise:

- These are **internal automated adversarial iterations**, not external audits.
- The adversarial agent is an automated tool, not a human pentester.
- No external audit firm has been engaged (yet).
- All findings are reproducible via the regression test suite.

We use the term "audit" to describe the systematic, repeatable nature of the
testing process. If this terminology is misleading, we welcome feedback.
