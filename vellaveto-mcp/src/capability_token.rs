//! Capability token issuance, attenuation, and verification.
//!
//! Provides Ed25519-based signing and verification of capability delegation
//! tokens. Tokens can be attenuated (narrowed) and delegated with monotonically
//! decreasing privileges.
//!
//! # Security Properties
//!
//! - Length-prefixed canonical content prevents boundary collision attacks
//! - Ed25519 signatures prevent token forgery
//! - Monotonic attenuation: delegated tokens can only narrow permissions
//! - Bounded delegation depth prevents infinite chains
//! - Constant-time key comparison via `subtle::ConstantTimeEq`

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use vellaveto_types::{
    Action, CapabilityError, CapabilityGrant, CapabilityToken, CapabilityVerification,
    MAX_DELEGATION_DEPTH, MAX_GRANTS,
};

/// Issue a new root capability token.
///
/// Creates a fresh token with the specified grants, signed by the issuer's
/// Ed25519 key. The token is valid for `ttl_secs` from now.
pub fn issue_capability_token(
    issuer: &str,
    holder: &str,
    grants: Vec<CapabilityGrant>,
    remaining_depth: u8,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<CapabilityToken, CapabilityError> {
    // Validate inputs
    if issuer.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "issuer must not be empty".to_string(),
        ));
    }
    if holder.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "holder must not be empty".to_string(),
        ));
    }
    if grants.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "grants must not be empty".to_string(),
        ));
    }
    if grants.len() > MAX_GRANTS {
        return Err(CapabilityError::SigningFailed(format!(
            "too many grants: {} (max {})",
            grants.len(),
            MAX_GRANTS
        )));
    }
    if remaining_depth > MAX_DELEGATION_DEPTH {
        return Err(CapabilityError::SigningFailed(format!(
            "remaining_depth {} exceeds max {}",
            remaining_depth, MAX_DELEGATION_DEPTH
        )));
    }

    // Parse signing key
    let signing_key = parse_signing_key(signing_key_hex)?;
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();

    let token_id = Uuid::new_v4().to_string();

    // Build canonical content and sign
    let canonical = build_canonical_content(
        &token_id,
        None,
        issuer,
        holder,
        &grants,
        remaining_depth,
        &issued_at,
    )?;
    let signature_hex = sign_content(&signing_key, &canonical)?;

    let token = CapabilityToken {
        token_id,
        parent_token_id: None,
        issuer: issuer.to_string(),
        holder: holder.to_string(),
        grants,
        remaining_depth,
        issued_at,
        expires_at,
        signature: signature_hex,
        issuer_public_key: public_key_hex,
    };

    token
        .validate_structure()
        .map_err(|e| CapabilityError::SigningFailed(format!("token validation failed: {}", e)))?;

    Ok(token)
}

// VERIFIED [S11]: Monotonic attenuation — delegated tokens can only reduce, never expand, capabilities (CapabilityDelegation.als S11)
// VERIFIED [S12]: Depth bounded — delegation depth strictly decreases on each delegation (CapabilityDelegation.als S12)
/// Attenuate (narrow) a parent capability token for delegation.
///
/// The new token must have:
/// - `remaining_depth` strictly less than the parent's (decremented)
/// - `grants` that are a subset of the parent's
/// - `expires_at` no later than the parent's
///
/// # Security: Monotonic Attenuation
///
/// This enforces that delegated tokens can only become more restrictive,
/// never more permissive. This prevents privilege escalation via delegation.
pub fn attenuate_capability_token(
    parent: &CapabilityToken,
    new_holder: &str,
    new_grants: Vec<CapabilityGrant>,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<CapabilityToken, CapabilityError> {
    // Check delegation depth
    if parent.remaining_depth == 0 {
        return Err(CapabilityError::AttenuationViolation(
            "parent token has remaining_depth 0 — cannot delegate further".to_string(),
        ));
    }

    if new_holder.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "new_holder must not be empty".to_string(),
        ));
    }

    if new_grants.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "new_grants must not be empty".to_string(),
        ));
    }

    // Verify grants are a subset of parent's grants
    for new_grant in &new_grants {
        let covered = parent
            .grants
            .iter()
            .any(|parent_grant| grant_is_subset(new_grant, parent_grant));
        if !covered {
            return Err(CapabilityError::AttenuationViolation(format!(
                "grant for tool '{}' function '{}' is not covered by parent token",
                new_grant.tool_pattern, new_grant.function_pattern
            )));
        }
    }

    let signing_key = parse_signing_key(signing_key_hex)?;
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339();
    let new_depth = parent.remaining_depth - 1;

    // Clamp expiry to parent's expiry
    let parent_expires = chrono::DateTime::parse_from_rfc3339(&parent.expires_at)
        .map_err(|e| CapabilityError::SigningFailed(format!("invalid parent expires_at: {}", e)))?;
    let requested_expires = now + chrono::Duration::seconds(ttl_secs as i64);
    let clamped_expires = if requested_expires > parent_expires {
        parent_expires.with_timezone(&chrono::Utc)
    } else {
        requested_expires
    };
    let expires_at = clamped_expires.to_rfc3339();

    let token_id = Uuid::new_v4().to_string();

    let canonical = build_canonical_content(
        &token_id,
        Some(&parent.token_id),
        &parent.holder, // Issuer of child = holder of parent
        new_holder,
        &new_grants,
        new_depth,
        &issued_at,
    )?;
    let signature_hex = sign_content(&signing_key, &canonical)?;

    let token = CapabilityToken {
        token_id,
        parent_token_id: Some(parent.token_id.clone()),
        issuer: parent.holder.clone(),
        holder: new_holder.to_string(),
        grants: new_grants,
        remaining_depth: new_depth,
        issued_at,
        expires_at,
        signature: signature_hex,
        issuer_public_key: public_key_hex,
    };

    token
        .validate_structure()
        .map_err(|e| CapabilityError::SigningFailed(format!("token validation failed: {}", e)))?;

    Ok(token)
}

/// Verify a capability token's signature and validity.
///
/// Checks:
/// 1. Ed25519 signature over canonical content
/// 2. Expiration (using `now` parameter)
/// 3. Holder matches expected_holder
/// 4. Public key matches expected key (if provided)
pub fn verify_capability_token(
    token: &CapabilityToken,
    expected_holder: Option<&str>,
    expected_public_key_hex: Option<&str>,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<CapabilityVerification, CapabilityError> {
    // Structural validation
    if let Err(e) = token.validate_structure() {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!("structural validation failed: {}", e)),
        });
    }

    // Check expiration
    let expires = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|e| CapabilityError::VerificationFailed(format!("invalid expires_at: {}", e)))?;
    if *now >= expires {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some("token has expired".to_string()),
        });
    }

    // Check holder match
    // SECURITY (FIND-R52-003): Case-insensitive comparison is intentional to accommodate
    // identity providers with inconsistent casing (e.g., "Alice" vs "alice"). Callers
    // that need case-sensitive holder matching should normalize both sides before calling.
    if let Some(expected) = expected_holder {
        if !token.holder.eq_ignore_ascii_case(expected) {
            return Ok(CapabilityVerification {
                valid: false,
                failure_reason: Some(format!(
                    "holder mismatch: expected '{}', got '{}'",
                    expected, token.holder
                )),
            });
        }
    }

    // Check public key match (constant-time)
    if let Some(expected_key) = expected_public_key_hex {
        let expected_bytes = hex::decode(expected_key)
            .map_err(|e| CapabilityError::InvalidKey(format!("invalid expected key hex: {}", e)))?;
        let actual_bytes = hex::decode(&token.issuer_public_key)
            .map_err(|e| CapabilityError::InvalidKey(format!("invalid token key hex: {}", e)))?;
        if expected_bytes.ct_eq(&actual_bytes).into() {
            // Keys match
        } else {
            return Ok(CapabilityVerification {
                valid: false,
                failure_reason: Some("public key mismatch".to_string()),
            });
        }
    }

    // Verify Ed25519 signature
    let pub_key_bytes = hex::decode(&token.issuer_public_key)
        .map_err(|e| CapabilityError::InvalidKey(format!("public key hex decode: {}", e)))?;
    if pub_key_bytes.len() != 32 {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!(
                "public key wrong length: {} (expected 32)",
                pub_key_bytes.len()
            )),
        });
    }
    let vk_arr: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CapabilityError::InvalidKey("public key conversion failed".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| CapabilityError::InvalidKey(format!("invalid public key: {}", e)))?;

    let sig_bytes = hex::decode(&token.signature)
        .map_err(|e| CapabilityError::VerificationFailed(format!("signature hex decode: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!(
                "signature wrong length: {} (expected 64)",
                sig_bytes.len()
            )),
        });
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        CapabilityError::VerificationFailed("signature conversion failed".to_string())
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    let canonical = build_canonical_content(
        &token.token_id,
        token.parent_token_id.as_deref(),
        &token.issuer,
        &token.holder,
        &token.grants,
        token.remaining_depth,
        &token.issued_at,
    )?;

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let content_hash = hasher.finalize();

    if verifying_key.verify(&content_hash, &signature).is_err() {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some("signature verification failed".to_string()),
        });
    }

    Ok(CapabilityVerification {
        valid: true,
        failure_reason: None,
    })
}

/// Check if a capability token's grants cover the given action.
///
/// Returns the index of the first matching grant, or `None` if no grant
/// covers the action.
pub fn check_grant_coverage(token: &CapabilityToken, action: &Action) -> Option<usize> {
    for (i, grant) in token.grants.iter().enumerate() {
        if grant_covers_action(grant, action) {
            return Some(i);
        }
    }
    None
}

/// Normalize a path by resolving `.` and `..` components.
///
/// SECURITY (FIND-083): Fail-closed — returns `None` if the path contains
/// null bytes or attempts to traverse above the root.
fn normalize_path_for_grant(path: &str) -> Option<String> {
    if path.contains('\0') {
        return None; // Null byte injection — fail-closed
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                if components.is_empty() {
                    return None; // Traversal above root — fail-closed
                }
                components.pop();
            }
            c => components.push(c),
        }
    }
    let normalized = if path.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    };
    Some(normalized)
}

/// Check if a grant covers the given action.
fn grant_covers_action(grant: &CapabilityGrant, action: &Action) -> bool {
    // Check tool pattern
    if !pattern_matches(&grant.tool_pattern, &action.tool) {
        return false;
    }
    // Check function pattern
    if !pattern_matches(&grant.function_pattern, &action.function) {
        return false;
    }
    // Check path constraints (if any)
    // SECURITY (FIND-083): Normalize action paths before matching to prevent
    // path traversal attacks (e.g., "/safe/../etc/passwd" matching "/safe/**").
    if !grant.allowed_paths.is_empty() && !action.target_paths.is_empty() {
        let all_covered = action.target_paths.iter().all(|path| {
            // Fail-closed: if normalization fails, deny the grant
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            grant
                .allowed_paths
                .iter()
                .any(|pattern| pattern_matches(pattern, &normalized))
        });
        if !all_covered {
            return false;
        }
    }
    // Check domain constraints (if any)
    if !grant.allowed_domains.is_empty() && !action.target_domains.is_empty() {
        let all_covered = action.target_domains.iter().all(|domain| {
            grant
                .allowed_domains
                .iter()
                .any(|pattern| pattern_matches(pattern, domain))
        });
        if !all_covered {
            return false;
        }
    }
    true
}

/// Simple glob pattern matching (supports `*` and `?`).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern.eq_ignore_ascii_case(value);
    }
    // Simple glob matching
    glob_match(pattern.as_bytes(), value.as_bytes())
}

/// Recursive glob matching for `*` and `?`.
fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    let mut pi = 0;
    let mut vi = 0;
    let mut star_pi = usize::MAX;
    let mut star_vi = 0;

    while vi < value.len() {
        if pi < pattern.len()
            && (pattern[pi] == b'?' || pattern[pi].eq_ignore_ascii_case(&value[vi]))
        {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_vi = vi;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Check if new_grant is a subset of parent_grant.
///
/// A grant is a subset if its tool/function patterns are equal to or more
/// specific than the parent's. For simplicity, exact equality or parent
/// having `*` patterns are accepted.
///
/// # Security (FIND-FV46-001, FIND-R46-004, FIND-FV46-002)
///
/// - Empty `allowed_paths`/`allowed_domains` in child when parent restricts = escalation
/// - Path patterns are normalized before comparison to prevent `/../` traversal
/// - `max_invocations` must be monotonically attenuated (child <= parent)
fn grant_is_subset(new_grant: &CapabilityGrant, parent_grant: &CapabilityGrant) -> bool {
    // Tool pattern must match under parent
    if !pattern_matches(&parent_grant.tool_pattern, &new_grant.tool_pattern)
        && parent_grant.tool_pattern != "*"
    {
        return false;
    }
    // Function pattern must match under parent
    if !pattern_matches(&parent_grant.function_pattern, &new_grant.function_pattern)
        && parent_grant.function_pattern != "*"
    {
        return false;
    }
    // SECURITY (FIND-FV46-001): If parent has path restrictions, child MUST also
    // have non-empty path restrictions. An empty child `allowed_paths` means
    // "unrestricted", which is strictly more permissive than the parent's
    // restrictions — violating monotonic attenuation.
    if !parent_grant.allowed_paths.is_empty() {
        if new_grant.allowed_paths.is_empty() {
            return false; // Child drops parent's path restrictions — escalation
        }
        for path in &new_grant.allowed_paths {
            // SECURITY (FIND-R46-004): Normalize path patterns in the child grant
            // before checking subset containment. Without normalization, a child
            // with "/safe/../../etc" passes the parent's "/safe/*" pattern match
            // but at runtime resolves to "/etc".
            let normalized = match normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false, // Fail-closed: malformed path = deny
            };
            let covered = parent_grant.allowed_paths.iter().any(|pp| {
                // Also normalize parent pattern for consistent comparison
                let parent_normalized = normalize_path_for_grant(pp).unwrap_or_default();
                if parent_normalized.is_empty() {
                    return false; // Malformed parent pattern — fail-closed
                }
                pattern_matches(&parent_normalized, &normalized)
            });
            if !covered {
                return false;
            }
        }
    }
    // SECURITY (FIND-FV46-001): Same check for domains — child must not drop
    // parent's domain restrictions.
    if !parent_grant.allowed_domains.is_empty() {
        if new_grant.allowed_domains.is_empty() {
            return false; // Child drops parent's domain restrictions — escalation
        }
        for domain in &new_grant.allowed_domains {
            let covered = parent_grant
                .allowed_domains
                .iter()
                .any(|pd| pattern_matches(pd, domain));
            if !covered {
                return false;
            }
        }
    }
    // SECURITY (FIND-FV46-002): max_invocations must be monotonically attenuated.
    // If parent limits invocations (> 0), child must also limit and not exceed.
    // A value of 0 means "unlimited" — child cannot be unlimited if parent limits.
    if parent_grant.max_invocations > 0
        && (new_grant.max_invocations == 0
            || new_grant.max_invocations > parent_grant.max_invocations)
    {
        return false;
    }
    true
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn parse_signing_key(hex_key: &str) -> Result<SigningKey, CapabilityError> {
    let key_bytes = hex::decode(hex_key)
        .map_err(|e| CapabilityError::InvalidKey(format!("hex decode failed: {}", e)))?;
    if key_bytes.len() != 32 {
        return Err(CapabilityError::InvalidKey(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CapabilityError::InvalidKey("key conversion failed".to_string()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Build length-prefixed canonical content for signing.
///
/// Format: `<field_len>:<field>` for each field, preventing boundary collision.
fn build_canonical_content(
    token_id: &str,
    parent_token_id: Option<&str>,
    issuer: &str,
    holder: &str,
    grants: &[CapabilityGrant],
    remaining_depth: u8,
    issued_at: &str,
) -> Result<String, CapabilityError> {
    let grants_json = serde_json::to_string(grants).map_err(|e| {
        CapabilityError::SigningFailed(format!("grants serialization failed: {}", e))
    })?;
    let parent_str = parent_token_id.unwrap_or("");
    Ok(format!(
        "{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}",
        token_id.len(),
        token_id,
        parent_str.len(),
        parent_str,
        issuer.len(),
        issuer,
        holder.len(),
        holder,
        grants_json.len(),
        grants_json,
        1,
        remaining_depth,
        issued_at.len(),
        issued_at,
    ))
}

fn sign_content(signing_key: &SigningKey, canonical: &str) -> Result<String, CapabilityError> {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let content_hash = hasher.finalize();
    let signature = signing_key.sign(&content_hash);
    Ok(hex::encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::CapabilityGrant;

    fn test_key_hex() -> String {
        let key = SigningKey::generate(&mut rand::thread_rng());
        hex::encode(key.to_bytes())
    }

    fn test_grants() -> Vec<CapabilityGrant> {
        vec![CapabilityGrant {
            tool_pattern: "file_system".into(),
            function_pattern: "read_file".into(),
            allowed_paths: vec!["/tmp/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }]
    }

    #[test]
    fn test_issue_and_verify_roundtrip() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();

        let key = parse_signing_key(&key_hex).unwrap();
        let pub_key_hex = hex::encode(key.verifying_key().as_bytes());
        let now = chrono::Utc::now();
        let result =
            verify_capability_token(&token, Some("holder-1"), Some(&pub_key_hex), &now).unwrap();
        assert!(
            result.valid,
            "Token should verify: {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        // Tamper with the signature
        token.signature = hex::encode([0xffu8; 64]);
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("signature"));
    }

    #[test]
    fn test_tampered_content_rejected() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        token.holder = "attacker".to_string();
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_expired_token_rejected() {
        let key_hex = test_key_hex();
        let token = issue_capability_token(
            "issuer-1",
            "holder-1",
            test_grants(),
            5,
            &key_hex,
            1, // 1 second TTL
        )
        .unwrap();
        // Set "now" far in the future
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let result = verify_capability_token(&token, None, None, &future).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("expired"));
    }

    #[test]
    fn test_holder_mismatch_rejected() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, Some("wrong-holder"), None, &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("holder mismatch"));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let wrong_key = test_key_hex();
        let wrong_key_obj = parse_signing_key(&wrong_key).unwrap();
        let wrong_pub = hex::encode(wrong_key_obj.verifying_key().as_bytes());
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, Some(&wrong_pub), &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("key mismatch"));
    }

    #[test]
    fn test_grant_coverage_exact_match() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer", "holder", test_grants(), 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            serde_json::json!({"path": "/tmp/test.txt"}),
        );
        assert!(check_grant_coverage(&token, &action).is_some());
    }

    #[test]
    fn test_grant_coverage_no_match() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer", "holder", test_grants(), 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "database".to_string(),
            "query".to_string(),
            serde_json::json!({}),
        );
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_coverage_glob_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "file_*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "file_system".to_string(),
            "write_file".to_string(),
            serde_json::json!({}),
        );
        assert!(check_grant_coverage(&token, &action).is_some());
    }

    #[test]
    fn test_attenuation_valid() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child =
            attenuate_capability_token(&parent, "agent-b", test_grants(), &child_key_hex, 1800)
                .unwrap();

        assert_eq!(child.remaining_depth, 4);
        assert_eq!(child.issuer, "agent-a");
        assert_eq!(child.holder, "agent-b");
        assert!(child.parent_token_id.is_some());
    }

    #[test]
    fn test_attenuation_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent =
            issue_capability_token("root", "agent-a", test_grants(), 5, &parent_key_hex, 3600)
                .unwrap();

        // Try to grant access to "database" which parent doesn't have
        let escalated_grants = vec![CapabilityGrant {
            tool_pattern: "database".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", escalated_grants, &child_key_hex, 1800);
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityError::AttenuationViolation(_) => {}
            other => panic!("Expected AttenuationViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_attenuation_depth_zero_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent =
            issue_capability_token("root", "agent-a", test_grants(), 0, &parent_key_hex, 3600)
                .unwrap();

        let result =
            attenuate_capability_token(&parent, "agent-b", test_grants(), &child_key_hex, 1800);
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityError::AttenuationViolation(_) => {}
            other => panic!("Expected AttenuationViolation, got: {:?}", other),
        }
    }

    #[test]
    fn test_attenuation_expiry_clamping() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            test_grants(),
            5,
            &parent_key_hex,
            60, // 60 seconds
        )
        .unwrap();

        let child = attenuate_capability_token(
            &parent,
            "agent-b",
            test_grants(),
            &child_key_hex,
            999999, // very long
        )
        .unwrap();

        // Child's expiry should be clamped to parent's
        let parent_exp = chrono::DateTime::parse_from_rfc3339(&parent.expires_at).unwrap();
        let child_exp = chrono::DateTime::parse_from_rfc3339(&child.expires_at).unwrap();
        assert!(child_exp <= parent_exp);
    }

    #[test]
    fn test_structural_validation_empty_fields() {
        let token = CapabilityToken {
            token_id: "".into(), // Empty!
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants: test_grants(),
            remaining_depth: 0,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_structural_validation_too_many_grants() {
        let mut grants = Vec::new();
        for i in 0..65 {
            grants.push(CapabilityGrant {
                tool_pattern: format!("tool_{}", i),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            });
        }
        let token = CapabilityToken {
            token_id: "tok-1".into(),
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants,
            remaining_depth: 0,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_structural_validation_depth_exceeds_max() {
        let token = CapabilityToken {
            token_id: "tok-1".into(),
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants: test_grants(),
            remaining_depth: 17, // > MAX_DELEGATION_DEPTH
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
    }

    #[test]
    fn test_empty_issuer_rejected() {
        let key_hex = test_key_hex();
        let result = issue_capability_token("", "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_holder_rejected() {
        let key_hex = test_key_hex();
        let result = issue_capability_token("issuer", "", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_grant_path_constraint_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "fs".into(),
            function_pattern: "read".into(),
            allowed_paths: vec!["/data/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action.target_paths = vec!["/data/file.txt".into()];
        assert!(check_grant_coverage(&token, &action).is_some());

        // Path outside allowed
        let mut action2 = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action2.target_paths = vec!["/etc/passwd".into()];
        assert!(check_grant_coverage(&token, &action2).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action.target_domains = vec!["api.example.com".into()];
        assert!(check_grant_coverage(&token, &action).is_some());

        let mut action2 = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action2.target_domains = vec!["evil.com".into()];
        assert!(check_grant_coverage(&token, &action2).is_none());
    }

    #[test]
    fn test_boundary_collision_different_issuer_holder() {
        // "issuerA" + "holderB" should produce different canonical content than
        // "issuer" + "AholderB" due to length prefixing
        let key_hex = test_key_hex();
        let token1 =
            issue_capability_token("issuerA", "holderB", test_grants(), 5, &key_hex, 3600).unwrap();
        let token2 =
            issue_capability_token("issuer", "AholderB", test_grants(), 5, &key_hex, 3600).unwrap();
        // Different tokens should have different signatures
        assert_ne!(token1.signature, token2.signature);
    }

    // SECURITY (FIND-FV46-001): Empty allowed_paths in child when parent restricts
    // must be rejected — empty means "unrestricted", which escalates privileges.
    #[test]
    fn test_attenuation_empty_paths_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec!["/data/*".into()],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries to drop path restrictions (empty = unrestricted)
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![], // Escalation: drops parent's path restriction
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-001: Child with empty paths when parent restricts must be rejected"
        );
    }

    // SECURITY (FIND-FV46-001): Same for domains.
    #[test]
    fn test_attenuation_empty_domains_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec!["*.example.com".into()],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![], // Escalation: drops parent's domain restriction
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-001: Child with empty domains when parent restricts must be rejected"
        );
    }

    // SECURITY (FIND-R46-004): Path traversal via unnormalized paths in child grant.
    #[test]
    fn test_attenuation_path_traversal_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec!["/safe/*".into()],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries path traversal: /safe/../../etc normalizes to above root
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec!["/safe/../../etc".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-R46-004: Path traversal in child grant paths must be rejected"
        );
    }

    // SECURITY (FIND-FV46-002): max_invocations must be monotonically attenuated.
    #[test]
    fn test_attenuation_max_invocations_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries unlimited invocations (0 = unlimited)
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0, // Unlimited — exceeds parent's 10
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-002: Child with unlimited invocations when parent limits must be rejected"
        );
    }

    #[test]
    fn test_attenuation_max_invocations_exceeds_parent_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries more invocations than parent allows
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 20, // Exceeds parent's 10
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-002: Child with more invocations than parent must be rejected"
        );
    }

    #[test]
    fn test_attenuation_max_invocations_valid_subset() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child with fewer invocations is fine
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 5, // Less than parent's 10 — valid
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "Child with fewer invocations than parent should succeed: {:?}",
            result.err()
        );
    }
}
