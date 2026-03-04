# Vellaveto Bug Bounty Program

## Scope

### In Scope

All Vellaveto Rust crates (`vellaveto-*`), SDKs (`sdk/python`, `sdk/typescript`, `sdk/go`, `sdk/java`), and the admin console (`admin-console/`).

Priority areas:
- **Policy engine bypass** — any input that produces `Allow` when policies should `Deny`
- **Injection evasion** — Unicode, encoding, or splitting techniques that bypass detection
- **DLP bypass** — secrets exfiltrated without detection
- **Audit tampering** — modifying or deleting audit entries without detection
- **Authentication bypass** — accessing protected endpoints without valid credentials
- **Privilege escalation** — cross-tenant access or role elevation

### Out of Scope

- Documentation files and marketing content
- Third-party dependencies (report to the upstream maintainer)
- Components explicitly labeled as "pre-filter" or "heuristic"
- Denial of service via resource exhaustion (already covered by rate limiting)
- Social engineering attacks against Vellaveto team members

## Severity Tiers

| Severity | Reward | Examples |
|----------|--------|---------|
| **Critical** | $5,000 | Policy bypass producing Allow instead of Deny, authentication bypass, cross-tenant data access |
| **High** | $2,000 | Injection evasion bypassing all detection layers, DLP bypass for known secret patterns, audit log tampering |
| **Medium** | $500 | Partial injection evasion (detected but not blocked), information disclosure in error messages, SSRF via webhook URLs |
| **Low** | $100 | Missing input validation on non-security paths, verbose error messages, minor information leaks |

## Responsible Disclosure

1. Report via [HackerOne](https://hackerone.com/vellaveto) or email security@vellaveto.online
2. Include a proof of concept (PoC) with steps to reproduce
3. Do not disclose publicly until a fix is released (90-day coordinated disclosure window)
4. We will acknowledge receipt within 48 hours and provide a remediation timeline within 7 days

See [SECURITY.md](SECURITY.md) for the full vulnerability disclosure policy.

## Safe Harbor

We will not pursue legal action against researchers who:
- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission
- Report findings promptly through the designated channels
- Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue

## Platforms

- **HackerOne Community Edition** — primary reporting platform
- **Huntr** — AI/ML-focused bug bounty platform (for AI-specific findings)

## Recognition

Researchers who report valid findings will be credited in:
- The fix commit message
- The CHANGELOG.md entry
- The Vellaveto security acknowledgements page (with researcher's consent)
