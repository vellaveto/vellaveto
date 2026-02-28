# Dependency Monitoring & Telemetry

This workspace already ships `cargo audit`, `cargo deny`, and an SBOM generator. Batch 3 builds on those safeguards by giving operators a simple composite script plus a process sheet that ties the results back to the latest CISA/OSINT threat intel.

## Why this matters
- **CISA Known Exploited Vulnerabilities (KEV)** is updated weekly; we now surface KEV hits whenever a dependency name matches an entry from the feed so defenders know when to patch immediately.
- **OSINT/supply-chain intel** (vercara+Mondoo reports) highlights typosquatted packages and malicious scripts in PyPI/npm/RubyGems. The new workflow lets you drop investigation notes in a dedicated directory and keeps them visible when the monitor runs.
- **Mondoo-inspired remediation**: the monitoring script writes human-readable JSON outputs and summaries so the team can escalate fixes, capture proof-of-remediation, and feed the info into longer-lived playbooks.

## Running the monitor
1. Run `scripts/run-dependency-monitor.sh` (or pass `scripts/run-dependency-monitor.sh /tmp/security`) from the repo root.
2. The script executes `cargo audit`, `cargo deny --all-features check`, and `cargo metadata`, writing JSON snapshots to `target/security/`.
3. If an advisory scan fails, the script exits non-zero and leaves the diagnostics under `target/security/` for triage.

### Optional integrations
- Run `scripts/fetch-cisa-kev.sh` to download the latest Known Exploited Vulnerabilities catalog into the `target/security` tree, then point `CISA_KEV_JSON` at that file so `cisa-kev-matches.json` is produced automatically.
- Drop OSINT summaries into `security/osint/` (or another directory and set `OSINT_SECURITY_DIR`). Each note should mention the source, date, summary, and planned response so the monitor can display the latest intel alongside the automated scans.

## Follow-up actions
1. Treat any `cargo audit` or `cargo deny` failure as high-priority: patch, bump, or remove the vulnerable dependency, document the fix, and rerun the monitor.
2. When the KEV feed flags a dependency, tag the CVE in your change log and schedule verification for the related runtime binary/release artifact.
3. Maintain the OSINT directory by archiving every weekly intelligence memo (source, date, remediation status). The monitoring script prints the latest files so you can correlate findings with observed packages.
4. Add the JSON outputs to your incident tickets (see `target/security/`) so Mondoo-style remediation steps (fix, verify, document) are repeatable.

## Automation hooks
- Consider adding the script to your CI/CD runbook (e.g., a GitHub Actions job or scheduled workflow) to keep the dependency posture visible and provide telemetry dashboards for the release team.
