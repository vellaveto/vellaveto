# Session Auth, Token, and Passkey Integration Plan

Status: draft for implementation  
Date: 2026-02-19  
Owner scope: `vellaveto-server`, `vellaveto-http-proxy`, SDKs, new session agent

## 1. Goal

Move Vellaveto from API-key-first auth to OAuth + sender-constrained sessions, with secure credential storage and passkey-enabled onboarding.

## 2. Current Baseline (from code)

- `vellaveto-server` requires `VELLAVETO_API_KEY` by default unless `--allow-anonymous` is set.
- `vellaveto-http-proxy` already supports OAuth 2.1 + DPoP, including hardened mode and anti-replay checks.
- SDKs (`sdk/go`, `sdk/python`, `sdk/typescript`) currently send static `Authorization: Bearer <api_key>`.
- No dedicated local session agent exists yet for token lifecycle and key storage.

## 3. Target Architecture

- Add a local **Session Agent** (`vv-agent`) responsible for:
  - OAuth login (device flow / browser loopback)
  - refresh/access token lifecycle
  - DPoP proof generation
  - secure storage backend abstraction
- Keep access tokens short-lived and memory-only.
- Keep refresh tokens in secure storage (OS keystore by default, Vault/cloud optional).
- Make OAuth hardened profile the production default for proxy/server API routes.
- Keep `VELLAVETO_API_KEY` only for bootstrap/dev compatibility during migration.

## 4. Phased Delivery Plan

## Phase 0 - Spec and contracts (high priority)

Deliverables:
- Add `docs/` spec for token taxonomy, scopes, TTLs, revocation semantics, DPoP requirements.
- Define standard scopes: `evaluate`, `readonly`, `admin`.
- Define threat model deltas for token theft/replay and local host compromise.

Acceptance:
- Written API contract for auth errors and scope mapping per endpoint.
- Security sign-off on fail-closed behavior when token/session validation fails.

## Phase 1 - Session core (MVP, high priority)

Deliverables:
- Create new crate: `vellaveto-session-agent` (binary).
- Create new crate: `vellaveto-auth` (library) for shared token/DPoP logic.
- Implement storage trait:
  - `keychain` (macOS)
  - `dpapi/credential-manager` (Windows)
  - `secret-service` (Linux)
  - file backend only for explicit dev mode
- Add local IPC endpoint (unix socket / named pipe) for token requests.

Acceptance:
- `vv-agent login` stores refresh token securely.
- `vv-agent token --dpop` returns short-lived access token + DPoP proof.
- No secret/token printed in logs or panic paths.

## Phase 2 - OAuth hardened defaults (high priority)

Deliverables:
- Extend `vellaveto-server` auth middleware to support OAuth JWT + scopes (not only API key).
- Keep API key auth as fallback feature flag: `auth.mode = oauth|api_key|hybrid`.
- Map routes to required scopes/roles and fail-closed on missing claims.
- Reuse proxy DPoP validation patterns where applicable.

Acceptance:
- Protected routes reject bearer tokens without required scope.
- Replay or missing DPoP fails in hardened mode.
- Existing API-key deployments still work in `hybrid` mode.

## Phase 3 - SDK token providers (high priority)

Deliverables:
- Add token provider abstraction to all SDKs:
  - env/static token provider (existing behavior)
  - agent provider (fetch token via local socket)
- Add optional `DPoP` header support in SDK request path.
- Add retry behavior for token refresh race/expiry (single-flight lock).

Acceptance:
- SDKs can run without embedding long-lived secrets.
- Cross-process token reuse works through local agent.

## Phase 4 - Passkey first-run UX (medium priority)

Deliverables:
- Add browser/loopback or device-flow login command to agent:
  - `vv-agent login --issuer ... --client-id ...`
- Passkey registration/authentication handled by IdP WebAuthn flow.
- Add step-up flow for admin actions (optional MFA/passkey assertion).

Acceptance:
- First-run onboarding succeeds on macOS/Windows/Linux desktop.
- Non-interactive token refresh works after enrollment.

## Phase 5 - Enterprise secret backends (medium priority)

Deliverables:
- Add backend plugins for:
  - HashiCorp Vault KV v2
  - AWS Secrets Manager
  - Azure Key Vault
  - GCP Secret Manager
- Add backend policy docs and least-privilege IAM templates.

Acceptance:
- Agent can read/write refresh token metadata through backend abstraction.
- Audit trail includes backend access events without leaking secret material.

## Phase 6 - Migration and deprecation (medium priority)

Deliverables:
- Add migration guide for API-key-first users.
- Mark `VELLAVETO_API_KEY` as bootstrap/dev in docs and CLI help.
- Add production warning when API key mode is used without OAuth.

Acceptance:
- Existing scripts continue in compatibility mode.
- New deployments default to OAuth hardened profile.

## 5. Crate-by-crate Work Map

- `vellaveto-server`:
  - add OAuth auth mode and scope enforcement in middleware/routes.
  - preserve fail-closed semantics for auth parse/validation errors.
- `vellaveto-http-proxy`:
  - keep OAuth hardened path as reference implementation.
  - optionally expose reusable auth/DPoP helpers from library boundary.
- `vellaveto-config`:
  - add auth mode config (`api_key`, `oauth`, `hybrid`) and validation rules.
- `vellaveto-types`:
  - add shared auth/session DTOs and error enums for SDK/agent parity.
- `sdk/go`, `sdk/python`, `sdk/typescript`:
  - add token provider interfaces and optional DPoP header injection.
- new `vellaveto-auth`:
  - OAuth token client, DPoP proof builder, key thumbprint utilities.
- new `vellaveto-session-agent`:
  - lifecycle daemon/CLI, secure storage adapter, IPC service.

## 6. CI and Security Gates

Add/extend CI jobs:

1. `cargo test -p vellaveto-auth`
2. `cargo test -p vellaveto-session-agent`
3. integration tests:
   - token replay rejected in hardened mode
   - missing scope rejected
   - expired token rejected
4. SDK integration tests against local agent mock.
5. secret redaction tests for logs/errors/panic paths.

## 7. Rollout Strategy

1. Ship Phase 1 and 3 behind feature flags (`session-agent`, `oauth-server-auth`).
2. Ship Phase 2 in `hybrid` default (OAuth preferred, API key fallback).
3. Flip production templates to OAuth hardened.
4. Keep API key fallback for one major release cycle, then deprecate.

## 8. Immediate Next Sprint (recommended)

1. Create `vellaveto-auth` crate with DPoP proof module and tests.
2. Add server auth mode config (`api_key|oauth|hybrid`) in `vellaveto-config`.
3. Implement server OAuth middleware for `/api/*` using route-scope map.
4. Add Go SDK token provider interface and agent stub first (then Python/TS parity).
5. Add a minimal `vv-agent` with secure storage + static issuer config (no passkey UI yet).

