// ═══════════════════════════════════════════════════════════════════════════════
// BILLING WEBHOOK ROUTES — Paddle + Stripe
// ═══════════════════════════════════════════════════════════════════════════════
//
// These endpoints receive webhook events from payment providers and update
// the license tier accordingly. Each provider uses its own signature scheme.
//
// SECURITY:
// - Webhooks bypass API key auth (they use provider-specific signatures)
// - Secrets read from env vars only (never config files)
// - Unknown/invalid payloads return 200 OK (to prevent retry storms)
// - No secrets logged — only event type and subscription ID
// - Request body size bounded by server's DefaultBodyLimit (1MB)

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::AppState;

/// Maximum webhook payload size (256 KB — well under the server's 1MB limit).
const MAX_WEBHOOK_PAYLOAD: usize = 262_144;

/// Maximum age for webhook timestamps (5 minutes).
///
/// SECURITY (P1-4): Prevents replay attacks by rejecting webhook events
/// with timestamps older than this tolerance. Both Paddle and Stripe include
/// timestamps in their signature headers.
const MAX_WEBHOOK_TIMESTAMP_AGE_SECS: u64 = 300;

/// Response returned to webhook callers.
#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    received: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// PADDLE WEBHOOK
// ═══════════════════════════════════════════════════════════════════════════════

/// Paddle webhook event payload (simplified — only fields we need).
#[derive(Debug, Deserialize)]
struct PaddleWebhookPayload {
    /// Event type (e.g., "subscription.created", "subscription.updated").
    #[serde(default)]
    event_type: String,
    /// Subscription data (nested). Kept for future event processing.
    #[serde(default)]
    #[allow(dead_code)]
    data: serde_json::Value,
}

/// `POST /api/billing/paddle/webhook`
///
/// Receives Paddle webhook events. Validates the signature using
/// `VELLAVETO_PADDLE_WEBHOOK_SECRET` env var.
///
/// Returns 200 OK for all payloads (valid or not) to prevent retry storms.
/// Invalid signatures are logged but not rejected at HTTP level.
pub async fn paddle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<WebhookResponse>) {
    // Bound check
    if body.len() > MAX_WEBHOOK_PAYLOAD {
        tracing::warn!(
            size = body.len(),
            "Paddle webhook payload exceeds size limit"
        );
        return (StatusCode::OK, Json(WebhookResponse { received: true }));
    }

    // Read webhook secret from billing config env var
    let secret_env = &state.billing_config.paddle.webhook_secret_env;

    let secret = match std::env::var(secret_env) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!("Paddle webhook secret not configured, ignoring event");
            return (StatusCode::OK, Json(WebhookResponse { received: true }));
        }
    };

    // Validate Paddle signature (ts + h1 scheme)
    let signature = headers
        .get("paddle-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_paddle_signature(signature, &body, &secret) {
        tracing::warn!("Paddle webhook signature verification failed");
        return (StatusCode::OK, Json(WebhookResponse { received: true }));
    }

    // Parse payload
    let payload: PaddleWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse Paddle webhook payload");
            return (StatusCode::OK, Json(WebhookResponse { received: true }));
        }
    };

    // Log the event (no secrets)
    tracing::info!(
        event_type = %payload.event_type,
        "Paddle webhook received"
    );

    // TODO: Process subscription events and update license tier
    // - subscription.created → generate license key, store subscription mapping
    // - subscription.updated → update tier if plan changed
    // - subscription.canceled → downgrade to Community
    // - subscription.past_due → log warning, grace period

    (StatusCode::OK, Json(WebhookResponse { received: true }))
}

/// Verify Paddle webhook signature.
///
/// Paddle uses `ts=<timestamp>;h1=<hmac_hex>` format in the `Paddle-Signature` header.
/// HMAC-SHA256 is computed over `<timestamp>:<body>` using the webhook secret.
fn verify_paddle_signature(signature_header: &str, body: &[u8], secret: &str) -> bool {
    // Parse "ts=<ts>;h1=<hmac>"
    let mut ts_value = "";
    let mut h1_value = "";

    for part in signature_header.split(';') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("ts=") {
            ts_value = ts;
        } else if let Some(h1) = part.strip_prefix("h1=") {
            h1_value = h1;
        }
    }

    if ts_value.is_empty() || h1_value.is_empty() {
        return false;
    }

    // SECURITY (P1-4): Reject stale timestamps to prevent replay attacks.
    if let Ok(ts) = ts_value.parse::<u64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        if now.abs_diff(ts) > MAX_WEBHOOK_TIMESTAMP_AGE_SECS {
            tracing::warn!(
                ts,
                now,
                "Paddle webhook timestamp too old or too far in the future"
            );
            return false;
        }
    } else {
        return false;
    }

    // Compute HMAC-SHA256 over "ts:body"
    let mut signed_payload = Vec::with_capacity(ts_value.len() + 1 + body.len());
    signed_payload.extend_from_slice(ts_value.as_bytes());
    signed_payload.push(b':');
    signed_payload.extend_from_slice(body);

    let expected = compute_hmac_sha256(secret.as_bytes(), &signed_payload);

    // Constant-time comparison
    constant_time_eq(
        expected.as_bytes(),
        h1_value.to_ascii_lowercase().as_bytes(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRIPE WEBHOOK
// ═══════════════════════════════════════════════════════════════════════════════

/// Stripe webhook event payload (simplified — only fields we need).
#[derive(Debug, Deserialize)]
struct StripeWebhookPayload {
    /// Event type (e.g., "invoice.paid", "customer.subscription.updated").
    #[serde(default, rename = "type")]
    event_type: String,
    /// Event data (nested). Kept for future event processing.
    #[serde(default)]
    #[allow(dead_code)]
    data: serde_json::Value,
}

/// `POST /api/billing/stripe/webhook`
///
/// Receives Stripe webhook events. Validates the signature using
/// `VELLAVETO_STRIPE_WEBHOOK_SECRET` env var (Stripe-Signature header).
///
/// Returns 200 OK for all payloads to prevent retry storms.
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<WebhookResponse>) {
    // Bound check
    if body.len() > MAX_WEBHOOK_PAYLOAD {
        tracing::warn!(
            size = body.len(),
            "Stripe webhook payload exceeds size limit"
        );
        return (StatusCode::OK, Json(WebhookResponse { received: true }));
    }

    // Read webhook secret from billing config env var
    let secret_env = &state.billing_config.stripe.webhook_secret_env;

    let secret = match std::env::var(secret_env) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!("Stripe webhook secret not configured, ignoring event");
            return (StatusCode::OK, Json(WebhookResponse { received: true }));
        }
    };

    // Validate Stripe signature
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_stripe_signature(signature, &body, &secret) {
        tracing::warn!("Stripe webhook signature verification failed");
        return (StatusCode::OK, Json(WebhookResponse { received: true }));
    }

    // Parse payload
    let payload: StripeWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse Stripe webhook payload");
            return (StatusCode::OK, Json(WebhookResponse { received: true }));
        }
    };

    // Log the event (no secrets)
    tracing::info!(
        event_type = %payload.event_type,
        "Stripe webhook received"
    );

    // TODO: Process invoice/subscription events and update license tier
    // - invoice.paid → generate/renew license key
    // - customer.subscription.updated → update tier
    // - customer.subscription.deleted → downgrade to Community
    // - invoice.payment_failed → log warning, send notification

    (StatusCode::OK, Json(WebhookResponse { received: true }))
}

/// Verify Stripe webhook signature (v1 scheme).
///
/// Stripe uses `t=<timestamp>,v1=<hmac_hex>` format in `Stripe-Signature` header.
/// HMAC-SHA256 is computed over `<timestamp>.<body>` using the `whsec_` signing secret.
fn verify_stripe_signature(signature_header: &str, body: &[u8], secret: &str) -> bool {
    let mut t_value = "";
    let mut v1_value = "";

    for part in signature_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            t_value = t;
        } else if let Some(v1) = part.strip_prefix("v1=") {
            v1_value = v1;
        }
    }

    if t_value.is_empty() || v1_value.is_empty() {
        return false;
    }

    // SECURITY (P1-4): Reject stale timestamps to prevent replay attacks.
    if let Ok(ts) = t_value.parse::<u64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        if now.abs_diff(ts) > MAX_WEBHOOK_TIMESTAMP_AGE_SECS {
            tracing::warn!(
                ts,
                now,
                "Stripe webhook timestamp too old or too far in the future"
            );
            return false;
        }
    } else {
        return false;
    }

    // Compute HMAC-SHA256 over "timestamp.body"
    let mut signed_payload = Vec::with_capacity(t_value.len() + 1 + body.len());
    signed_payload.extend_from_slice(t_value.as_bytes());
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(body);

    let expected = compute_hmac_sha256(secret.as_bytes(), &signed_payload);

    constant_time_eq(
        expected.as_bytes(),
        v1_value.to_ascii_lowercase().as_bytes(),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// HMAC-SHA256 (shared with licensing module — inline here to avoid cross-crate dep)
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute HMAC-SHA256 using the SHA-256 primitive directly.
fn compute_hmac_sha256(key: &[u8], message: &[u8]) -> String {
    use sha2::Digest;

    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut inner_hasher = Sha256::new();
    let mut inner_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key_pad[i] = k_prime[i] ^ IPAD;
    }
    inner_hasher.update(inner_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    let mut outer_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key_pad[i] = k_prime[i] ^ OPAD;
    }
    outer_hasher.update(outer_key_pad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    hex::encode(outer_hash)
}

/// Constant-time byte comparison.
///
/// SECURITY: Uses `std::hint::black_box` to prevent the compiler from
/// optimizing the accumulator loop into an early-exit comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// LICENSE INFO ENDPOINT
// ═══════════════════════════════════════════════════════════════════════════════

/// Response for the license info endpoint.
#[derive(Debug, Serialize)]
pub struct LicenseInfoResponse {
    pub tier: String,
    pub limits: vellaveto_config::TierLimits,
    pub reason: String,
}

/// `GET /api/billing/license`
///
/// Returns the current license tier and feature limits.
/// Requires API key authentication (handled by the auth middleware).
pub async fn license_info(State(state): State<AppState>) -> Json<LicenseInfoResponse> {
    let validation = state.billing_config.licensing_validation.clone();
    Json(LicenseInfoResponse {
        tier: validation.tier.to_string(),
        limits: validation.limits,
        reason: validation.reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_ts() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
    }

    #[test]
    fn test_verify_paddle_signature_valid() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let ts = current_ts();

        // Compute expected HMAC
        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b':');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("ts={};h1={}", ts, hmac);
        assert!(verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_paddle_signature_invalid() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let ts = current_ts();
        let header = format!("ts={};h1=deadbeef", ts);
        assert!(!verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_paddle_signature_missing_parts() {
        assert!(!verify_paddle_signature("", b"body", "secret"));
        let ts = current_ts();
        assert!(!verify_paddle_signature(
            &format!("ts={}", ts),
            b"body",
            "secret"
        ));
        assert!(!verify_paddle_signature("h1=abc", b"body", "secret"));
    }

    #[test]
    fn test_verify_paddle_signature_stale_timestamp() {
        let secret = "pdl_test_secret";
        let body = b"{\"event_type\":\"subscription.created\"}";
        let stale_ts = "1234567890"; // 2009 — way too old

        let mut signed = Vec::new();
        signed.extend_from_slice(stale_ts.as_bytes());
        signed.push(b':');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("ts={};h1={}", stale_ts, hmac);
        assert!(!verify_paddle_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_valid() {
        let secret = "whsec_test_secret";
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();

        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(secret.as_bytes(), &signed);

        let header = format!("t={},v1={}", ts, hmac);
        assert!(verify_stripe_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_invalid() {
        let secret = "whsec_test_secret";
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();
        let header = format!("t={},v1=deadbeef", ts);
        assert!(!verify_stripe_signature(&header, body, secret));
    }

    #[test]
    fn test_verify_stripe_signature_missing_parts() {
        assert!(!verify_stripe_signature("", b"body", "secret"));
        let ts = current_ts();
        assert!(!verify_stripe_signature(
            &format!("t={}", ts),
            b"body",
            "secret"
        ));
        assert!(!verify_stripe_signature("v1=abc", b"body", "secret"));
    }

    #[test]
    fn test_verify_stripe_signature_stale_timestamp() {
        let body = b"{\"type\":\"invoice.paid\"}";
        let stale_ts = "1234567890"; // 2009 — way too old

        let mut signed = Vec::new();
        signed.extend_from_slice(stale_ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(b"whsec_test_secret", &signed);

        let header = format!("t={},v1={}", stale_ts, hmac);
        assert!(!verify_stripe_signature(&header, body, "whsec_test_secret"));
    }

    #[test]
    fn test_verify_stripe_signature_wrong_secret() {
        let body = b"{\"type\":\"invoice.paid\"}";
        let ts = current_ts();

        let mut signed = Vec::new();
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let hmac = compute_hmac_sha256(b"correct_secret", &signed);

        let header = format!("t={},v1={}", ts, hmac);
        assert!(!verify_stripe_signature(&header, body, "wrong_secret"));
    }

    #[test]
    fn test_webhook_response_serialization() {
        let resp = WebhookResponse { received: true };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"received\":true"));
    }
}
