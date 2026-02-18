# Contributing to Vellaveto

Thank you for your interest in contributing to Vellaveto.

## Contributor License Agreement (CLA)

All contributors must sign the [Individual Contributor License Agreement](CLA.md) before their first contribution can be merged. This is a one-time process.

**Why a CLA?** Vellaveto is dual-licensed (AGPL-3.0 + commercial). The CLA grants the maintainer the right to distribute your contributions under both licenses, enabling the project's sustainability model.

**How to sign:**
1. **Automatic:** When you open your first pull request, the CLA Assistant bot will prompt you to sign electronically.
2. **Manual:** Email **paolovella1993@gmail.com** with subject "CLA Signature — Vellaveto" containing your full name, GitHub username, and the statement: "I have read and agree to the Vellaveto Individual Contributor License Agreement."

## License

Vellaveto is dual-licensed under [AGPL-3.0](LICENSE) and a commercial license.
By submitting a contribution, you agree to the terms in [LICENSING.md](LICENSING.md) and [CLA.md](CLA.md).

## Getting Started

```bash
git clone https://github.com/paolovella/vellaveto.git
cd vellaveto
cargo check --workspace
cargo test --workspace
cargo clippy --workspace
```

All three must pass before submitting changes.

## Development Rules

1. **No `unwrap()` or `expect()` in library code** — use `?` and `ok_or_else()`
2. **Fail-closed** — errors produce `Deny`, not `Allow`
3. **Every change gets tests** — unit tests at minimum, integration tests for new features
4. **Zero clippy warnings** — `cargo clippy --workspace` must be clean
5. **No new dependencies without justification** — every dep is attack surface

## Commit Format

```
<type>(<scope>): <subject>

<body>
```

**Types:** `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`
**Scopes:** `types`, `engine`, `audit`, `config`, `mcp`, `server`, `proxy`, `integration`

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with tests
4. Ensure all checks pass:
   ```bash
   cargo test --workspace
   cargo clippy --workspace
   cargo fmt --check
   ```
5. Submit a pull request with a clear description

## Release Checklist

For maintainers cutting a new release:

1. **Version bump** — Update all `Cargo.toml` versions (workspace + 12 crates)
2. **Helm chart** — Update `helm/vellaveto/Chart.yaml` version + appVersion
3. **Python SDK** — Update `sdk/python/pyproject.toml` version
4. **CHANGELOG** — Move `[Unreleased]` items to new version section
5. **Commit** — `chore: release vX.Y.Z`
6. **Tag** — `git tag vX.Y.Z && git push --tags`
7. **Verify** — CI builds release binaries, Docker image, GitHub Release automatically

## Security

If you discover a security vulnerability, please report it privately.
See [SECURITY.md](docs/SECURITY.md) for details.
