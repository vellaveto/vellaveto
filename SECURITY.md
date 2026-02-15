# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| 2.x     | Security fixes only |
| < 2.0   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities via one of the following channels:

- **Email:** [paolovella1993@gmail.com](mailto:paolovella1993@gmail.com) with subject line `[SECURITY] <brief description>`
- **GitHub Security Advisory:** [Report a vulnerability](https://github.com/paolovella/vellaveto/security/advisories/new) (preferred)

### What to Include

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Affected version(s)
- Impact assessment (if known)

### Disclosure Timeline

1. **Acknowledgment:** within 3 business days of receipt
2. **Triage and severity assessment:** within 7 days
3. **Fix development and testing:** target 30 days for critical/high, 90 days for medium/low
4. **Coordinated disclosure:** we will coordinate with you on a disclosure date after a fix is available
5. **Advisory publication:** GitHub Security Advisory published at disclosure time

We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy). We will not pursue legal action against researchers who act in good faith.

## Scope

The following are in scope:

- All code in the [paolovella/vellaveto](https://github.com/paolovella/vellaveto) repository
- Published Docker images (`ghcr.io/paolovella/vellaveto`)
- Published SDKs (Python, TypeScript, Go)

The following are **out of scope:**

- Third-party MCP servers or tools behind Vellaveto
- Denial-of-service attacks against hosted instances
- Social engineering of maintainers

## Security Advisories

Published advisories will be listed at [github.com/paolovella/vellaveto/security/advisories](https://github.com/paolovella/vellaveto/security/advisories).

## Security Hardening

For production deployment hardening guidance, see [docs/SECURITY.md](docs/SECURITY.md).
