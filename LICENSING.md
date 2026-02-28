# Vellaveto Licensing

## Three-Tier License Model

Vellaveto uses a three-tier license structure. Each crate specifies its own
license in its `Cargo.toml`. The tier determines what obligations apply when
you use, modify, or distribute that crate.

### Tier 1: MPL-2.0 (Mozilla Public License 2.0)

**Crates:** `vellaveto-types`, `vellaveto-engine`, `vellaveto-audit`,
`vellaveto-canonical`, `vellaveto-config`, `vellaveto-discovery`,
`vellaveto-approval`, `vellaveto-proxy`, `vellaveto-mcp-shield`,
`vellaveto-http-proxy-shield`, `vellaveto-shield`

**What this means:** You can use these crates in proprietary software. If you
modify *the MPL-licensed files themselves*, you must share those modifications
under MPL-2.0. Your own code that merely *uses* these crates remains under
your own license. MPL-2.0 is file-level copyleft — only modified files must
be shared, not your entire project.

Full text: [LICENSE-MPL-2.0](LICENSE-MPL-2.0)

### Tier 2: Apache-2.0

**Crates:** `vellaveto-canary`, `mcpsec`

**What this means:** Permissive license. You can use, modify, and distribute
these crates with minimal restrictions. You must include the license notice
and state changes, but there is no copyleft obligation.

Full text: [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)

### Tier 3: AGPL-3.0-only (GNU Affero General Public License v3.0)

**Crates:** `vellaveto-server`, `vellaveto-http-proxy`, `vellaveto-mcp`,
`vellaveto-cluster`, `vellaveto-operator`, `vellaveto-integration`

**What this means:** Strong copyleft. If you modify these crates and make them
available over a network (e.g., as a hosted service), you must make the
complete source code of your modified version available under AGPL-3.0.

Full text: [LICENSE](LICENSE)

### Combined Binary Note

The `vellaveto-shield` binary links `vellaveto-mcp` (AGPL-3.0). While the
shield-specific crates (`vellaveto-mcp-shield`, `vellaveto-canary`) are
MPL-2.0/Apache-2.0, the combined binary distributes as AGPL-3.0 due to
AGPL linking requirements. A future sprint may extract a minimal MPL-2.0
relay to remove this dependency.

## Commercial License

For organizations that cannot comply with the AGPL-3.0 or MPL-2.0 — for
example, if you want to embed Vellaveto in proprietary software or offer it
as a managed service without open-sourcing your modifications — a commercial
license is available.

Contact: **paolovella1993@gmail.com**

The commercial license removes all copyleft obligations and includes:
- Permission to use Vellaveto in proprietary products and services
- Permission to modify without source disclosure requirements
- Priority support and security advisory access

## Why This Structure?

1. **Consumer Shield is accessible.** MPL-2.0 lets individual users and small
   companies embed the shield in their own tools without AGPL obligations.
2. **Improvements flow back.** AGPL ensures that modifications to the server
   and protocol layers benefit everyone.
3. **Vendor-neutral tools are open.** Apache-2.0 for benchmark and canary
   tools encourages broad adoption and trust.
4. **The project is sustainable.** Organizations that build commercial products
   on Vellaveto contribute either code (via copyleft) or funding (via
   commercial license).

## Contributing

By submitting a contribution (pull request, patch, or other code) to this
project, you agree to license your contribution under the license of the
crate you are modifying, and you grant the project maintainers a perpetual,
worldwide, non-exclusive, royalty-free license to use, reproduce, modify,
sublicense, and distribute your contribution under any license, including
the commercial license described above.

This is necessary to maintain the multi-license model that funds development.
A formal Contributor License Agreement (CLA) will be provided via CLA
Assistant for all pull requests.

## AI Training Opt-Out

The source code, documentation, and all associated materials in this repository
are expressly reserved from use as training data for machine learning models,
including but not limited to large language models (LLMs), in accordance with
EU Directive 2019/790 (CDSM) Article 4 and EU AI Act Article 53.

Use of this repository's contents for AI/ML training requires explicit written
permission from the copyright holder.

## Third-Party Licenses

Vellaveto depends on open-source libraries, each under their own licenses.
Run `cargo license` for a complete list. All dependencies are compatible
with the respective tier licenses.

---

Copyright 2026 Paolo Vella. All rights reserved.
