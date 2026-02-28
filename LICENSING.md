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

### Tier 3: BUSL-1.1 (Business Source License 1.1)

**Crates:** `vellaveto-server`, `vellaveto-http-proxy`, `vellaveto-mcp`,
`vellaveto-cluster`, `vellaveto-operator`, `vellaveto-integration`

**Non-crate assets:** `admin-console/`, `helm/`, `terraform-provider-vellaveto/`,
`docker-compose.yml`, `Dockerfile`

**What this means:**

- You can read, audit, build, test, and modify this code freely.
- **Non-production use** is always free (development, testing, staging,
  evaluation, benchmarking, research, security auditing).
- **Production use** is free if your deployment uses ≤3 cluster nodes AND
  ≤25 monitored MCP endpoints.
- **Production use** requires a commercial license if you exceed those
  thresholds OR offer VellaVeto as a managed/hosted service.
- **Consumer Shield deployments** on end-user devices are always free,
  regardless of scale.
- After **3 years**, each version converts automatically to MPL-2.0 —
  the same license as the core engine.

**Why BSL, not AGPL?** AGPL prevents cloud provider freeloading but doesn't
generate revenue below the compliance pain threshold. BSL creates a clear
line: small teams and individuals use everything free, enterprises above the
threshold pay, and all code is fully auditable at all times. The 3-year
conversion to MPL-2.0 guarantees the code becomes fully free software on a
fixed schedule.

Full text: [LICENSE-BSL-1.1](LICENSE-BSL-1.1)

### Combined Binary Note

The `vellaveto-shield` binary links `vellaveto-mcp` (BUSL-1.1). However,
the BSL Additional Use Grant explicitly permits Consumer Shield deployments
on end-user devices without a commercial license. The shield-specific crates
(`vellaveto-mcp-shield`, `vellaveto-canary`) remain MPL-2.0/Apache-2.0.

## Commercial License

For organizations that need to exceed the BSL production thresholds or offer
VellaVeto as a managed service — a commercial license is available.

Contact: **paolovella1993@gmail.com**

The commercial license removes all usage restrictions and includes:
- Permission to use VellaVeto in proprietary products and services at any scale
- Permission to offer VellaVeto as a managed/hosted service
- Permission to modify without source disclosure requirements
- Priority support and security advisory access

## Why This Structure?

1. **Consumer Shield is accessible.** MPL-2.0 lets individual users and small
   companies embed the shield in their own tools without copyleft obligations.
2. **Small teams use everything free.** BSL with concrete thresholds (3 nodes /
   25 endpoints) means startups and small companies get the full enterprise
   stack at zero cost.
3. **Code is always auditable.** Unlike proprietary alternatives, every line of
   VellaVeto source is available for security review, modification, and
   contribution.
4. **Everything becomes free software.** The 3-year conversion to MPL-2.0
   guarantees that no version of VellaVeto is permanently restricted.
5. **Vendor-neutral tools are open.** Apache-2.0 for benchmark and canary
   tools encourages broad adoption and trust.
6. **The project is sustainable.** Organizations that deploy at scale
   contribute funding, while the code remains fully transparent.

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
