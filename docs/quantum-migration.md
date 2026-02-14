# Post-Quantum TLS Migration Runbook

This runbook defines a staged rollout and rollback process for Vellaveto TLS key exchange policy migration.

## Scope

- `vellaveto-server` TLS termination (`tls.mode = "tls"` or `"mtls"`)
- TLS key exchange policy in `TlsConfig`:
  - `classical_only`
  - `hybrid_preferred`
  - `hybrid_required_when_supported`
- Forwarded negotiated TLS metadata extraction for audit and observability:
  - `protocol`
  - `cipher`
  - `kex_group`

## Prerequisites

- `tls.mode` is enabled (`"tls"` or `"mtls"`).
- `tls.min_version = "1.3"` before enabling hybrid policies.
- Certificates and keys are valid and mounted:
  - `tls.cert_path`
  - `tls.key_path`
  - `tls.client_ca_path` for mTLS.
- Reverse proxy (if present) forwards TLS metadata headers consistently.

## Safety checks before rollout

1. Validate configuration.

```bash
cargo run -p vellaveto-server -- check --config /etc/vellaveto/policy.toml
```

2. Confirm startup logs show effective KEX policy behavior.

```bash
RUST_LOG=info cargo run -p vellaveto-server -- serve --config /etc/vellaveto/policy.toml
```

3. Confirm audit entries carry TLS metadata for evaluate requests (when proxy headers are provided).

```bash
curl -s localhost:3000/api/audit/entries | jq '.entries[-1].metadata.tls'
```

## Rollout phases

### Phase 0: Baseline (`classical_only`)

Use classical groups only while inventorying client capabilities.

```toml
[tls]
mode = "tls"
min_version = "1.3"
kex_policy = "classical_only"
```

Exit criteria:
- No handshake regressions in production traffic.
- TLS metadata appears in audit/observability for sampled requests.

### Phase 1: Compatibility-first hybrid (`hybrid_preferred`)

Prefer PQ/hybrid groups when provider support exists, with classical fallback.

```toml
[tls]
mode = "tls"
min_version = "1.3"
kex_policy = "hybrid_preferred"
```

Exit criteria:
- No material increase in handshake failures.
- Audit samples show negotiated `kex_group` values include hybrid/PQ where expected.

### Phase 2: Enforced hybrid where supported (`hybrid_required_when_supported`)

Restrict server groups to PQ/hybrid when provider exposes them.

```toml
[tls]
mode = "tls"
min_version = "1.3"
kex_policy = "hybrid_required_when_supported"
```

Important:
- If provider support is present, classical-only clients can fail handshake.
- If provider has no PQ/hybrid groups, Vellaveto falls back to classical groups and logs a warning.

Exit criteria:
- Client compatibility validated for all critical traffic paths.
- No unresolved handshake failure spikes after canary and staged rollout.

## Canary strategy

1. Roll out to a small percentage of instances (5-10%).
2. Monitor:
   - request success rate
   - handshake errors at edge proxy
   - Vellaveto logs for KEX policy warnings
3. Expand gradually (25% -> 50% -> 100%) only after each stage is stable.

## Forwarded TLS metadata header rules

Accepted aliases:

- Protocol:
  - `x-forwarded-tls-protocol`
  - `x-forwarded-tls-version`
  - `x-tls-protocol`
  - `x-tls-version`
- Cipher:
  - `x-forwarded-tls-cipher`
  - `x-tls-cipher`
- KEX group:
  - `x-forwarded-tls-kex-group`
  - `x-tls-kex-group`

Hardening behavior:
- Values are sanitized and bounded by length.
- Conflicting duplicate values for the same header are rejected.
- Conflicting alias values for the same field are treated as ambiguous and dropped.
- Invalid higher-priority alias values do not block valid lower-priority alias fallback.

## Rollback

If handshake failures or client incompatibilities exceed error budget:

1. Revert to the previous policy (`hybrid_required_when_supported` -> `hybrid_preferred` -> `classical_only`).
2. Redeploy config and verify startup logs.
3. Confirm request success rate returns to baseline.
4. Record affected clients and negotiate upgrade path before retrying stricter policy.

Rollback config (safe baseline):

```toml
[tls]
mode = "tls"
min_version = "1.3"
kex_policy = "classical_only"
```

## Change control checklist

- [ ] Config validated in CI and staging.
- [ ] Canary window and rollback owner assigned.
- [ ] Monitoring dashboard and alert thresholds reviewed.
- [ ] Audit sampling confirms `metadata.tls.{protocol,cipher,kex_group}` population.
- [ ] Rollback procedure tested in staging.
