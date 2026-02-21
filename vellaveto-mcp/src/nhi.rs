//! Non-Human Identity (NHI) Lifecycle Management - Phase 10.
//!
//! Provides comprehensive identity lifecycle management for machine identities:
//! - Agent identity registration with multiple attestation types
//! - Behavioral baseline tracking for continuous authentication
//! - DPoP (RFC 9449) proof verification for sender-constrained tokens
//! - Delegation chain tracking with scope constraints
//! - Credential rotation management
//!
//! Reference: CyberArk NHI research, SPIFFE/SPIRE, RFC 9449.

use crate::accountability;
use crate::did_plc;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::RwLock;
use uuid::Uuid;
use vellaveto_config::NhiConfig;
use vellaveto_types::{
    AccountabilityAttestation, AttestationVerificationResult, DidPlc, NhiAgentIdentity,
    NhiAttestationType, NhiBehavioralBaseline, NhiBehavioralCheckResult, NhiBehavioralDeviation,
    NhiBehavioralRecommendation, NhiCredentialRotation, NhiDelegationChain, NhiDelegationLink,
    NhiDpopProof, NhiDpopVerificationResult, NhiIdentityStatus, NhiStats, VerificationTier,
};

/// Maximum nonces to keep for DPoP replay prevention.
const MAX_DPOP_NONCES: usize = 10000;

/// SECURITY (FIND-R73-005): Maximum TTL for delegations (1 year).
/// Prevents `ttl_secs as i64` overflow on u64 values > i64::MAX.
const MAX_DELEGATION_TTL_SECS: u64 = 365 * 24 * 3600;

/// Maximum behavioral baselines to store.
///
/// SECURITY (FIND-R71-P3-003): Without a cap, an attacker registering
/// many agent IDs could cause unbounded memory growth in the baselines map.
const MAX_BASELINES: usize = 100_000;

/// Maximum tool call patterns per baseline.
///
/// SECURITY (FIND-R71-P3-004): Without a cap, an attacker calling many
/// distinct tool names could cause unbounded growth in a single baseline's
/// tool_call_patterns HashMap.
const MAX_TOOL_CALL_PATTERNS: usize = 10_000;

/// NHI Manager for agent identity lifecycle management.
///
/// Thread-safe manager that coordinates identity registration, behavioral
/// attestation, DPoP verification, and delegation tracking.
#[derive(Debug)]
pub struct NhiManager {
    /// Configuration.
    config: NhiConfig,
    /// Registered agent identities indexed by ID.
    identities: RwLock<HashMap<String, NhiAgentIdentity>>,
    /// Behavioral baselines indexed by agent ID.
    baselines: RwLock<HashMap<String, NhiBehavioralBaseline>>,
    /// Active delegations indexed by (from_agent, to_agent).
    delegations: RwLock<HashMap<(String, String), NhiDelegationLink>>,
    /// DPoP nonces for replay prevention.
    dpop_nonces: RwLock<DpopNonceTracker>,
    /// Used JTIs for DPoP replay prevention.
    used_jtis: RwLock<VecDeque<(String, u64)>>,
    /// Credential rotation history.
    rotations: RwLock<VecDeque<NhiCredentialRotation>>,
    /// Statistics.
    stats: RwLock<NhiStats>,
    /// Revocation list.
    revocation_list: RwLock<HashSet<String>>,
}

impl NhiManager {
    /// Create a new NHI manager with the given configuration.
    pub fn new(config: NhiConfig) -> Self {
        Self {
            config,
            identities: RwLock::new(HashMap::new()),
            baselines: RwLock::new(HashMap::new()),
            delegations: RwLock::new(HashMap::new()),
            dpop_nonces: RwLock::new(DpopNonceTracker::new()),
            used_jtis: RwLock::new(VecDeque::new()),
            rotations: RwLock::new(VecDeque::with_capacity(1000)),
            stats: RwLock::new(NhiStats::default()),
            revocation_list: RwLock::new(HashSet::new()),
        }
    }

    /// Check if the manager is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the configuration.
    pub fn config(&self) -> &NhiConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════════
    // IDENTITY REGISTRATION
    // ═══════════════════════════════════════════════════

    /// Register a new agent identity.
    ///
    /// Returns the generated identity ID on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_identity(
        &self,
        name: &str,
        attestation_type: NhiAttestationType,
        spiffe_id: Option<&str>,
        public_key: Option<&str>,
        key_algorithm: Option<&str>,
        ttl_secs: Option<u64>,
        tags: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<String, NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        // SECURITY (FIND-R115-025): Validate input fields for length bounds and
        // control/format characters to prevent injection and resource exhaustion.
        Self::validate_register_identity_inputs(name, spiffe_id, &tags, &metadata)?;

        // Validate attestation type is allowed
        let atype_str = attestation_type.to_string();
        if !self
            .config
            .attestation_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&atype_str))
        {
            return Err(NhiError::AttestationTypeNotAllowed(atype_str));
        }

        // Compute TTL before acquiring the lock
        let ttl = ttl_secs.unwrap_or(self.config.credential_ttl_secs);
        if ttl > self.config.max_credential_ttl_secs {
            return Err(NhiError::TtlExceedsMax {
                requested: ttl,
                max: self.config.max_credential_ttl_secs,
            });
        }

        let now = chrono::Utc::now();
        let id = Uuid::new_v4().to_string();
        let expires_at = now + chrono::Duration::seconds(ttl as i64);

        let identity = NhiAgentIdentity {
            id: id.clone(),
            name: name.to_string(),
            attestation_type,
            status: NhiIdentityStatus::Probationary,
            spiffe_id: spiffe_id.map(|s| s.to_string()),
            public_key: public_key.map(|s| s.to_string()),
            key_algorithm: key_algorithm.map(|s| s.to_string()),
            issued_at: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            last_rotation: None,
            auth_count: 0,
            last_auth: None,
            tags,
            metadata,
            verification_tier: VerificationTier::default(),
            did_plc: None,
            attestations: Vec::new(),
        };

        // SECURITY (FIND-R126-005): Validate the constructed identity before
        // inserting. Defense-in-depth: enforces bounds/format on caller-supplied
        // name, tags, metadata even if the server route validation is bypassed.
        identity
            .validate()
            .map_err(NhiError::InputValidation)?;

        // Acquire write lock for atomic capacity check + insert
        let mut identities = self.identities.write().await;
        if identities.len() >= self.config.max_identities {
            return Err(NhiError::CapacityExceeded("identities".to_string()));
        }
        identities.insert(id.clone(), identity);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_identities = identities.len() as u64;
        stats.active_identities = identities
            .values()
            .filter(|i| {
                i.status == NhiIdentityStatus::Active || i.status == NhiIdentityStatus::Probationary
            })
            .count() as u64;

        Ok(id)
    }

    /// Get an identity by ID.
    pub async fn get_identity(&self, id: &str) -> Option<NhiAgentIdentity> {
        let identities = self.identities.read().await;
        identities.get(id).cloned()
    }

    /// List all identities (with optional status filter).
    pub async fn list_identities(
        &self,
        status_filter: Option<NhiIdentityStatus>,
    ) -> Vec<NhiAgentIdentity> {
        let identities = self.identities.read().await;
        identities
            .values()
            .filter(|i| status_filter.is_none_or(|s| i.status == s))
            .cloned()
            .collect()
    }

    /// Update identity status.
    pub async fn update_status(
        &self,
        id: &str,
        new_status: NhiIdentityStatus,
    ) -> Result<(), NhiError> {
        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(id)
            .ok_or_else(|| NhiError::IdentityNotFound(id.to_string()))?;

        // SECURITY (FIND-R43-007): Revoked and Expired are terminal states.
        // No transitions out of terminal states are allowed.
        if matches!(
            identity.status,
            NhiIdentityStatus::Revoked | NhiIdentityStatus::Expired
        ) && new_status != identity.status
        {
            return Err(NhiError::InvalidStatusTransition {
                from: identity.status,
                to: new_status,
            });
        }

        let old_status = identity.status;

        // Update revocation list BEFORE setting identity status so that
        // is_revoked() returns true before the status field is visible.
        // This closes the TOCTOU window where status == Revoked but
        // is_revoked() would return false.
        if new_status == NhiIdentityStatus::Revoked {
            let mut revoked = self.revocation_list.write().await;
            revoked.insert(id.to_string());
        }

        identity.status = new_status;

        // Update stats
        let mut stats = self.stats.write().await;
        match old_status {
            NhiIdentityStatus::Active | NhiIdentityStatus::Probationary => {
                stats.active_identities = stats.active_identities.saturating_sub(1);
            }
            NhiIdentityStatus::Suspended => {
                stats.suspended_identities = stats.suspended_identities.saturating_sub(1)
            }
            NhiIdentityStatus::Revoked => {
                stats.revoked_identities = stats.revoked_identities.saturating_sub(1)
            }
            NhiIdentityStatus::Expired => {
                stats.expired_identities = stats.expired_identities.saturating_sub(1)
            }
        }
        // SECURITY (FIND-R67-P3-002): Use saturating_add to prevent counter overflow.
        match new_status {
            NhiIdentityStatus::Active | NhiIdentityStatus::Probationary => {
                stats.active_identities = stats.active_identities.saturating_add(1)
            }
            NhiIdentityStatus::Suspended => {
                stats.suspended_identities = stats.suspended_identities.saturating_add(1)
            }
            NhiIdentityStatus::Revoked => {
                stats.revoked_identities = stats.revoked_identities.saturating_add(1)
            }
            NhiIdentityStatus::Expired => {
                stats.expired_identities = stats.expired_identities.saturating_add(1)
            }
        }

        Ok(())
    }

    /// Check if an identity is revoked.
    pub async fn is_revoked(&self, id: &str) -> bool {
        let revoked = self.revocation_list.read().await;
        revoked.contains(id)
    }

    /// SECURITY (FIND-R44-039): Check if an identity is in a terminal state
    /// (Revoked or Expired). Use this for access denial checks where both
    /// terminal states should block access.
    pub async fn is_terminal(&self, id: &str) -> bool {
        // Check the revocation list first (covers Revoked).
        let revoked = self.revocation_list.read().await;
        if revoked.contains(id) {
            return true;
        }
        drop(revoked);
        // Also check if the identity status is Expired.
        let identities = self.identities.read().await;
        identities
            .get(id)
            .map(|i| matches!(i.status, NhiIdentityStatus::Expired))
            .unwrap_or(false)
    }

    /// Activate an identity (transition from probationary to active).
    pub async fn activate_identity(&self, id: &str) -> Result<(), NhiError> {
        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(id)
            .ok_or_else(|| NhiError::IdentityNotFound(id.to_string()))?;

        if identity.status != NhiIdentityStatus::Probationary {
            return Err(NhiError::InvalidStatusTransition {
                from: identity.status,
                to: NhiIdentityStatus::Active,
            });
        }

        identity.status = NhiIdentityStatus::Active;

        // Note: We don't increment active_identities here because Probationary
        // is already counted as "active" in our stats. The transition from
        // Probationary -> Active doesn't change the active count.

        Ok(())
    }

    /// Record a successful authentication.
    pub async fn record_auth(&self, id: &str) -> Result<(), NhiError> {
        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(id)
            .ok_or_else(|| NhiError::IdentityNotFound(id.to_string()))?;

        // SECURITY (FIND-R67-P3-002): Use saturating_add to prevent counter overflow.
        identity.auth_count = identity.auth_count.saturating_add(1);
        identity.last_auth = Some(chrono::Utc::now().to_rfc3339());

        let mut stats = self.stats.write().await;
        stats.auths_last_hour = stats.auths_last_hour.saturating_add(1);

        Ok(())
    }

    // ═══════════════════════════════════════════════════
    // BEHAVIORAL ATTESTATION
    // ═══════════════════════════════════════════════════

    /// Update the behavioral baseline for an agent.
    pub async fn update_baseline(
        &self,
        agent_id: &str,
        tool_call: &str,
        request_interval_secs: Option<f64>,
        source_ip: Option<&str>,
    ) -> Result<(), NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        let now = chrono::Utc::now();
        let mut baselines = self.baselines.write().await;

        // SECURITY (FIND-R71-P3-003): Check capacity before inserting a new baseline.
        if !baselines.contains_key(agent_id) && baselines.len() >= MAX_BASELINES {
            tracing::warn!(
                target: "vellaveto::security",
                max = MAX_BASELINES,
                current = baselines.len(),
                agent_id = agent_id,
                "NhiManager baselines at capacity, skipping new baseline"
            );
            return Ok(());
        }

        let baseline =
            baselines
                .entry(agent_id.to_string())
                .or_insert_with(|| NhiBehavioralBaseline {
                    agent_id: agent_id.to_string(),
                    tool_call_patterns: HashMap::new(),
                    avg_request_interval_secs: 0.0,
                    request_interval_stddev: 0.0,
                    typical_session_duration_secs: 0.0,
                    observation_count: 0,
                    created_at: now.to_rfc3339(),
                    last_updated: now.to_rfc3339(),
                    confidence: 0.0,
                    typical_source_ips: Vec::new(),
                    active_hours: Vec::new(),
                });

        // SECURITY (FIND-R67-P3-002): Use saturating_add to prevent counter overflow.
        baseline.observation_count = baseline.observation_count.saturating_add(1);
        baseline.last_updated = now.to_rfc3339();

        // Update tool call frequency (exponential moving average)
        let alpha = 0.1; // Smoothing factor
        let current = baseline
            .tool_call_patterns
            .get(tool_call)
            .copied()
            .unwrap_or(0.0);
        let new_value = alpha + (1.0 - alpha) * current;
        // SECURITY (FIND-R71-P3-004): Only insert new patterns if under capacity.
        // Existing patterns are always updated (they don't grow the map).
        if baseline.tool_call_patterns.contains_key(tool_call)
            || baseline.tool_call_patterns.len() < MAX_TOOL_CALL_PATTERNS
        {
            baseline
                .tool_call_patterns
                .insert(tool_call.to_string(), new_value);
        } else {
            tracing::warn!(
                target: "vellaveto::security",
                max = MAX_TOOL_CALL_PATTERNS,
                agent_id = agent_id,
                "tool_call_patterns at capacity, skipping new pattern"
            );
        }

        // Update request interval if provided
        if let Some(interval) = request_interval_secs {
            if baseline.observation_count == 1 {
                baseline.avg_request_interval_secs = interval;
            } else {
                let delta = interval - baseline.avg_request_interval_secs;
                baseline.avg_request_interval_secs += delta / (baseline.observation_count as f64);
                // Welford's algorithm for online variance
                let delta2 = interval - baseline.avg_request_interval_secs;
                let variance_update = delta * delta2;
                let variance = baseline.request_interval_stddev.powi(2)
                    * ((baseline.observation_count - 1) as f64);
                baseline.request_interval_stddev =
                    ((variance + variance_update) / (baseline.observation_count as f64)).sqrt();

                // SECURITY (FIND-R68-002): Guard against NaN/Infinity from
                // Welford's algorithm (e.g., overflow from extreme intervals).
                if !baseline.avg_request_interval_secs.is_finite() {
                    baseline.avg_request_interval_secs = interval;
                }
                if !baseline.request_interval_stddev.is_finite() {
                    baseline.request_interval_stddev = 0.0;
                }
            }
        }

        // Update source IPs
        if let Some(ip) = source_ip {
            if !baseline.typical_source_ips.contains(&ip.to_string())
                && baseline.typical_source_ips.len() < 100
            {
                baseline.typical_source_ips.push(ip.to_string());
            }
        }

        // Update active hours
        let hour = now.format("%H").to_string().parse::<u8>().unwrap_or(0);
        if !baseline.active_hours.contains(&hour) {
            baseline.active_hours.push(hour);
        }

        // Update confidence based on observations
        let min_obs = self.config.min_baseline_observations;
        baseline.confidence = if baseline.observation_count >= min_obs {
            1.0
        } else {
            (baseline.observation_count as f64) / (min_obs as f64)
        };

        // Update stats
        let mut stats = self.stats.write().await;
        stats.with_baselines = baselines.len() as u64;

        Ok(())
    }

    /// Get the behavioral baseline for an agent.
    pub async fn get_baseline(&self, agent_id: &str) -> Option<NhiBehavioralBaseline> {
        let baselines = self.baselines.read().await;
        baselines.get(agent_id).cloned()
    }

    /// Check behavior against baseline.
    pub async fn check_behavior(
        &self,
        agent_id: &str,
        tool_call: &str,
        request_interval_secs: Option<f64>,
        source_ip: Option<&str>,
    ) -> NhiBehavioralCheckResult {
        let baselines = self.baselines.read().await;

        let Some(baseline) = baselines.get(agent_id) else {
            // No baseline yet - allow but note it's new
            return NhiBehavioralCheckResult {
                within_baseline: true,
                anomaly_score: 0.0,
                deviations: vec![],
                recommendation: NhiBehavioralRecommendation::AllowWithLogging,
            };
        };

        // Skip enforcement during learning period
        // SECURITY (FIND-R64-004): NaN confidence treated as < 1.0 (still learning).
        if !baseline.confidence.is_finite() || baseline.confidence < 1.0 {
            return NhiBehavioralCheckResult {
                within_baseline: true,
                anomaly_score: 0.0,
                deviations: vec![],
                recommendation: NhiBehavioralRecommendation::Allow,
            };
        }

        let mut deviations = Vec::new();
        let mut total_severity = 0.0;

        // Check tool call pattern
        if let Some(&expected_freq) = baseline.tool_call_patterns.get(tool_call) {
            // Tool is known - this is good
            // NOTE: Frequency deviation checking is deferred. The expected_freq
            // represents the historical call rate, but comparing a single call's
            // timing against a rate requires session-level call counting which
            // is tracked elsewhere (behavioral.rs EMA-based detection).
            let _ = expected_freq;
        } else {
            // Unknown tool - flag it
            deviations.push(NhiBehavioralDeviation {
                deviation_type: "unknown_tool".to_string(),
                observed: tool_call.to_string(),
                expected: format!(
                    "one of {:?}",
                    baseline.tool_call_patterns.keys().collect::<Vec<_>>()
                ),
                severity: 0.3,
            });
            total_severity += 0.3;
        }

        // Check request interval
        if let Some(interval) = request_interval_secs {
            if baseline.avg_request_interval_secs > 0.0 {
                let z_score = (interval - baseline.avg_request_interval_secs).abs()
                    / baseline.request_interval_stddev.max(0.1);
                // SECURITY (FIND-R115-024): NaN z_score (e.g., from 0.0/0.0 or
                // non-finite interval) must be treated as an anomaly (fail-closed).
                // NaN comparisons always return false, so `NaN > 3.0` would skip
                // the anomaly flag, allowing an attacker to bypass detection.
                if !z_score.is_finite() || z_score > 3.0 {
                    let severity = if z_score.is_finite() {
                        (z_score / 10.0).min(0.5)
                    } else {
                        0.5 // Max severity for non-finite z_score (fail-closed)
                    };
                    deviations.push(NhiBehavioralDeviation {
                        deviation_type: "request_interval".to_string(),
                        observed: format!("{:.2}s", interval),
                        expected: format!(
                            "{:.2}s ± {:.2}s",
                            baseline.avg_request_interval_secs, baseline.request_interval_stddev
                        ),
                        severity,
                    });
                    total_severity += severity;
                }
            }
        }

        // Check source IP
        if let Some(ip) = source_ip {
            if !baseline.typical_source_ips.is_empty()
                && !baseline.typical_source_ips.contains(&ip.to_string())
            {
                deviations.push(NhiBehavioralDeviation {
                    deviation_type: "source_ip".to_string(),
                    observed: ip.to_string(),
                    expected: format!("one of {:?}", baseline.typical_source_ips),
                    severity: 0.4,
                });
                total_severity += 0.4;
            }
        }

        // Compute anomaly score
        let anomaly_score = (total_severity / 1.2).min(1.0); // Normalize to 0-1
        let threshold = self.config.anomaly_threshold;

        let recommendation = if anomaly_score >= 0.8 && self.config.auto_revoke_on_anomaly {
            NhiBehavioralRecommendation::Revoke
        } else if anomaly_score >= 0.6 {
            NhiBehavioralRecommendation::Suspend
        } else if anomaly_score >= threshold {
            NhiBehavioralRecommendation::StepUpAuth
        } else if anomaly_score > 0.0 {
            NhiBehavioralRecommendation::AllowWithLogging
        } else {
            NhiBehavioralRecommendation::Allow
        };

        NhiBehavioralCheckResult {
            within_baseline: anomaly_score < threshold,
            anomaly_score,
            deviations,
            recommendation,
        }
    }

    // ═══════════════════════════════════════════════════
    // DPOP VERIFICATION (RFC 9449)
    // ═══════════════════════════════════════════════════

    /// Generate a new DPoP nonce.
    pub async fn generate_dpop_nonce(&self) -> String {
        let mut nonces = self.dpop_nonces.write().await;
        nonces.generate_nonce()
    }

    /// Verify a DPoP proof.
    ///
    /// Note: This is a structural verification. Actual cryptographic
    /// verification should be done using a proper JWT library.
    pub async fn verify_dpop_proof(
        &self,
        proof: &NhiDpopProof,
        expected_method: &str,
        expected_uri: &str,
        access_token_hash: Option<&str>,
    ) -> NhiDpopVerificationResult {
        if !self.config.enabled {
            return NhiDpopVerificationResult {
                valid: false,
                thumbprint: None,
                error: Some("NHI manager disabled".to_string()),
                new_nonce: None,
            };
        }

        // Check JTI for replay
        let mut used_jtis = self.used_jtis.write().await;
        let now_secs = chrono::Utc::now().timestamp() as u64;

        // Clean old JTIs
        while let Some((_, ts)) = used_jtis.front() {
            if now_secs.saturating_sub(*ts) > 3600 {
                used_jtis.pop_front();
            } else {
                break;
            }
        }

        if used_jtis.iter().any(|(jti, _)| jti == &proof.jti) {
            return NhiDpopVerificationResult {
                valid: false,
                thumbprint: None,
                error: Some("JTI already used (replay attack)".to_string()),
                new_nonce: Some(self.generate_dpop_nonce().await),
            };
        }

        // Check method
        if proof.htm.to_uppercase() != expected_method.to_uppercase() {
            return NhiDpopVerificationResult {
                valid: false,
                thumbprint: None,
                error: Some(format!(
                    "Method mismatch: expected {}, got {}",
                    expected_method, proof.htm
                )),
                new_nonce: None,
            };
        }

        // Check URI
        if proof.htu != expected_uri {
            return NhiDpopVerificationResult {
                valid: false,
                thumbprint: None,
                error: Some(format!(
                    "URI mismatch: expected {}, got {}",
                    expected_uri, proof.htu
                )),
                new_nonce: None,
            };
        }

        // Check nonce if required
        if self.config.dpop.require_nonce {
            let nonces = self.dpop_nonces.read().await;
            if let Some(ref nonce) = proof.nonce {
                if !nonces.is_valid(nonce) {
                    return NhiDpopVerificationResult {
                        valid: false,
                        thumbprint: None,
                        error: Some("Invalid or expired nonce".to_string()),
                        new_nonce: Some(self.generate_dpop_nonce().await),
                    };
                }
            } else {
                return NhiDpopVerificationResult {
                    valid: false,
                    thumbprint: None,
                    error: Some("Nonce required but not provided".to_string()),
                    new_nonce: Some(self.generate_dpop_nonce().await),
                };
            }
        }

        // Check access token hash if required
        if self.config.dpop.require_ath {
            if let Some(expected_ath) = access_token_hash {
                if proof.ath.as_deref() != Some(expected_ath) {
                    return NhiDpopVerificationResult {
                        valid: false,
                        thumbprint: None,
                        error: Some("Access token hash mismatch".to_string()),
                        new_nonce: None,
                    };
                }
            }
        }

        // Record JTI to prevent replay
        used_jtis.push_back((proof.jti.clone(), now_secs));
        if used_jtis.len() > MAX_DPOP_NONCES {
            used_jtis.pop_front();
        }

        // Update stats
        let mut stats = self.stats.write().await;
        // SECURITY (FIND-R67-P3-002): Use saturating_add to prevent counter overflow.
        stats.dpop_verifications_last_hour = stats.dpop_verifications_last_hour.saturating_add(1);

        // Note: Actual cryptographic verification (signature check, key extraction)
        // should be done by the caller using a proper JWT library.
        // This method handles the protocol-level checks.
        NhiDpopVerificationResult {
            valid: true,
            thumbprint: None, // Would be extracted from JWT header
            error: None,
            new_nonce: None,
        }
    }

    // ═══════════════════════════════════════════════════
    // DELEGATION MANAGEMENT
    // ═══════════════════════════════════════════════════

    /// Create a delegation from one agent to another.
    pub async fn create_delegation(
        &self,
        from_agent: &str,
        to_agent: &str,
        permissions: Vec<String>,
        scope_constraints: Vec<String>,
        ttl_secs: u64,
        reason: Option<String>,
    ) -> Result<NhiDelegationLink, NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        // SECURITY (FIND-R115-021): Reject self-delegation (case-insensitive).
        // Self-delegation is nonsensical and could create circular chains.
        if from_agent.eq_ignore_ascii_case(to_agent) {
            return Err(NhiError::SelfDelegation);
        }

        // Check both agents exist and are not in terminal state (read lock on identities only).
        let identities = self.identities.read().await;
        if !identities.contains_key(from_agent) {
            return Err(NhiError::IdentityNotFound(from_agent.to_string()));
        }
        if !identities.contains_key(to_agent) {
            return Err(NhiError::IdentityNotFound(to_agent.to_string()));
        }

        // SECURITY (FIND-R115-022): Reject delegation from/to terminal-state agents.
        // Revoked or Expired agents must not be able to delegate or receive delegations.
        if let Some(from_identity) = identities.get(from_agent) {
            if matches!(
                from_identity.status,
                NhiIdentityStatus::Revoked | NhiIdentityStatus::Expired
            ) {
                return Err(NhiError::TerminalStateAgent {
                    agent_id: from_agent.to_string(),
                    status: from_identity.status,
                });
            }
        }
        if let Some(to_identity) = identities.get(to_agent) {
            if matches!(
                to_identity.status,
                NhiIdentityStatus::Revoked | NhiIdentityStatus::Expired
            ) {
                return Err(NhiError::TerminalStateAgent {
                    agent_id: to_agent.to_string(),
                    status: to_identity.status,
                });
            }
        }
        drop(identities);

        // SECURITY (FIND-R73-005): Validate ttl_secs before casting to i64.
        if ttl_secs > MAX_DELEGATION_TTL_SECS {
            return Err(NhiError::TtlExceedsMax {
                requested: ttl_secs,
                max: MAX_DELEGATION_TTL_SECS,
            });
        }

        // SECURITY (FIND-R43-020): Acquire write lock on delegations first,
        // then check capacity and insert atomically to close TOCTOU window.
        let mut delegations = self.delegations.write().await;
        if delegations.len() >= self.config.max_delegations {
            return Err(NhiError::CapacityExceeded("delegations".to_string()));
        }

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);

        let link = NhiDelegationLink {
            from_agent: from_agent.to_string(),
            to_agent: to_agent.to_string(),
            permissions,
            scope_constraints,
            created_at: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            active: true,
            reason,
        };

        delegations.insert((from_agent.to_string(), to_agent.to_string()), link.clone());

        let mut stats = self.stats.write().await;
        stats.active_delegations = delegations.values().filter(|d| d.active).count() as u64;

        Ok(link)
    }

    /// Get delegation between two agents.
    pub async fn get_delegation(
        &self,
        from_agent: &str,
        to_agent: &str,
    ) -> Option<NhiDelegationLink> {
        let delegations = self.delegations.read().await;
        delegations
            .get(&(from_agent.to_string(), to_agent.to_string()))
            .cloned()
    }

    /// List delegations for an agent (as delegator or delegatee).
    pub async fn list_delegations(&self, agent_id: &str) -> Vec<NhiDelegationLink> {
        let delegations = self.delegations.read().await;
        delegations
            .values()
            .filter(|d| d.from_agent == agent_id || d.to_agent == agent_id)
            .cloned()
            .collect()
    }

    /// Revoke a delegation.
    pub async fn revoke_delegation(
        &self,
        from_agent: &str,
        to_agent: &str,
    ) -> Result<(), NhiError> {
        let mut delegations = self.delegations.write().await;
        let key = (from_agent.to_string(), to_agent.to_string());

        if let Some(link) = delegations.get_mut(&key) {
            link.active = false;
        } else {
            return Err(NhiError::DelegationNotFound {
                from: from_agent.to_string(),
                to: to_agent.to_string(),
            });
        }

        let mut stats = self.stats.write().await;
        stats.active_delegations = delegations.values().filter(|d| d.active).count() as u64;

        Ok(())
    }

    /// Resolve the full delegation chain for an agent.
    pub async fn resolve_delegation_chain(&self, agent_id: &str) -> NhiDelegationChain {
        let delegations = self.delegations.read().await;
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = agent_id.to_string();

        // Walk backwards through delegation chain
        while let Some(link) = delegations
            .values()
            .find(|d| d.to_agent == current && d.active)
        {
            if visited.contains(&link.from_agent) {
                break; // Prevent cycles
            }
            visited.insert(current.clone());
            chain.push(link.clone());
            current = link.from_agent.clone();

            if chain.len() > self.config.max_delegation_chain_depth {
                break;
            }
        }

        chain.reverse(); // Put in origin-to-terminus order

        NhiDelegationChain {
            chain,
            max_depth: self.config.max_delegation_chain_depth,
            resolved_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ═══════════════════════════════════════════════════
    // CREDENTIAL ROTATION
    // ═══════════════════════════════════════════════════

    /// Rotate credentials for an identity.
    pub async fn rotate_credentials(
        &self,
        agent_id: &str,
        new_public_key: &str,
        new_key_algorithm: Option<&str>,
        trigger: &str,
        new_ttl_secs: Option<u64>,
    ) -> Result<NhiCredentialRotation, NhiError> {
        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;

        let previous_thumbprint = identity
            .public_key
            .as_ref()
            .map(|k| Self::compute_thumbprint(k));
        let new_thumbprint = Self::compute_thumbprint(new_public_key);

        let now = chrono::Utc::now();
        let ttl = new_ttl_secs.unwrap_or(self.config.credential_ttl_secs);

        // SECURITY (FIND-R114-017): Validate that the rotation TTL does not exceed
        // max_credential_ttl_secs, matching the validation in register_identity().
        // Without this check, a rotation policy could create credentials that live
        // longer than the configured maximum.
        if ttl > self.config.max_credential_ttl_secs {
            return Err(NhiError::TtlExceedsMax {
                requested: ttl,
                max: self.config.max_credential_ttl_secs,
            });
        }

        let new_expires_at = now + chrono::Duration::seconds(ttl as i64);

        identity.public_key = Some(new_public_key.to_string());
        if let Some(alg) = new_key_algorithm {
            identity.key_algorithm = Some(alg.to_string());
        }
        identity.last_rotation = Some(now.to_rfc3339());
        identity.expires_at = new_expires_at.to_rfc3339();

        let rotation = NhiCredentialRotation {
            agent_id: agent_id.to_string(),
            previous_thumbprint,
            new_thumbprint: new_thumbprint.clone(),
            rotated_at: now.to_rfc3339(),
            trigger: trigger.to_string(),
            new_expires_at: new_expires_at.to_rfc3339(),
        };

        // SECURITY (FIND-R126-006): Validate rotation before recording.
        rotation
            .validate()
            .map_err(NhiError::InputValidation)?;

        // Record rotation
        let mut rotations = self.rotations.write().await;
        rotations.push_back(rotation.clone());
        if rotations.len() > 1000 {
            rotations.pop_front();
        }

        Ok(rotation)
    }

    /// Get identities expiring within the warning window.
    pub async fn get_expiring_identities(&self) -> Vec<NhiAgentIdentity> {
        let identities = self.identities.read().await;
        let now = chrono::Utc::now();
        let warning_window = chrono::Duration::hours(self.config.rotation_warning_hours as i64);
        let threshold = now + warning_window;

        identities
            .values()
            .filter(|i| {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&i.expires_at) {
                    let expires_utc = expires.with_timezone(&chrono::Utc);
                    expires_utc <= threshold && i.status == NhiIdentityStatus::Active
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    // ═══════════════════════════════════════════════════
    // DID:PLC & VERIFICATION TIER MANAGEMENT
    // ═══════════════════════════════════════════════════

    /// Generate a DID:PLC for an agent identity.
    ///
    /// Requires the agent to have a public key and key algorithm configured.
    /// The generated DID is stored on the identity and returned.
    pub async fn generate_agent_did(&self, agent_id: &str) -> Result<DidPlc, NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;

        let public_key = identity
            .public_key
            .as_ref()
            .ok_or_else(|| NhiError::NoPublicKey(agent_id.to_string()))?;
        let key_algorithm = identity.key_algorithm.as_deref().unwrap_or("Ed25519");

        let did = did_plc::generate_did_plc_from_key(public_key, key_algorithm)
            .map_err(|e| NhiError::DidGenerationFailed(e.to_string()))?;

        identity.did_plc = Some(did.as_str().to_string());
        Ok(did)
    }

    /// Set the verification tier for an agent.
    ///
    /// Tiers can only go up (no downgrades), except that `Unverified` can
    /// always be set (admin reset).
    pub async fn set_verification_tier(
        &self,
        agent_id: &str,
        tier: VerificationTier,
    ) -> Result<(), NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;

        // No downgrades (except to Unverified for admin reset)
        if tier != VerificationTier::Unverified && tier < identity.verification_tier {
            return Err(NhiError::TierDowngradeNotAllowed {
                current: identity.verification_tier,
                requested: tier,
            });
        }

        identity.verification_tier = tier;
        Ok(())
    }

    /// Get the verification tier for an agent.
    pub async fn get_verification_tier(
        &self,
        agent_id: &str,
    ) -> Result<VerificationTier, NhiError> {
        let identities = self.identities.read().await;
        let identity = identities
            .get(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;
        Ok(identity.verification_tier)
    }

    /// Sign an accountability attestation for an agent.
    ///
    /// The agent must have a public key configured. The attestation is stored
    /// on the identity and returned.
    pub async fn sign_accountability_attestation(
        &self,
        agent_id: &str,
        statement: &str,
        policy_hash: &str,
        signing_key_hex: &str,
        ttl_secs: u64,
    ) -> Result<AccountabilityAttestation, NhiError> {
        if !self.config.enabled {
            return Err(NhiError::Disabled);
        }

        let max_attestations = self.config.verification.max_attestations_per_identity;

        let mut identities = self.identities.write().await;
        let identity = identities
            .get_mut(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;

        // Check attestation limit
        if identity.attestations.len() >= max_attestations {
            return Err(NhiError::AttestationLimitExceeded {
                agent_id: agent_id.to_string(),
                max: max_attestations,
            });
        }

        let did = identity.did_plc.as_deref();

        let attestation = accountability::sign_attestation(
            agent_id,
            did,
            statement,
            policy_hash,
            signing_key_hex,
            ttl_secs,
        )
        .map_err(|e| NhiError::AttestationError(e.to_string()))?;

        identity.attestations.push(attestation.clone());
        Ok(attestation)
    }

    /// Verify an accountability attestation.
    pub async fn verify_accountability_attestation(
        &self,
        attestation: &AccountabilityAttestation,
    ) -> Result<AttestationVerificationResult, NhiError> {
        // Look up the agent's registered public key for comparison
        let identities = self.identities.read().await;
        let expected_key = identities
            .get(&attestation.agent_id)
            .and_then(|id| id.public_key.as_deref());

        let now = chrono::Utc::now();
        accountability::verify_attestation(attestation, expected_key, &now)
            .map_err(|e| NhiError::AttestationError(e.to_string()))
    }

    /// List all attestations for an agent.
    pub async fn list_attestations(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AccountabilityAttestation>, NhiError> {
        let identities = self.identities.read().await;
        let identity = identities
            .get(agent_id)
            .ok_or_else(|| NhiError::IdentityNotFound(agent_id.to_string()))?;
        Ok(identity.attestations.clone())
    }

    // ═══════════════════════════════════════════════════
    // STATISTICS
    // ═══════════════════════════════════════════════════

    /// Get current statistics.
    pub async fn stats(&self) -> NhiStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Reset hourly counters.
    pub async fn reset_hourly_counters(&self) {
        let mut stats = self.stats.write().await;
        stats.auths_last_hour = 0;
        stats.anomalies_last_hour = 0;
        stats.dpop_verifications_last_hour = 0;
    }

    // ═══════════════════════════════════════════════════
    // UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════

    /// Maximum length for agent name.
    const MAX_NAME_LEN: usize = 256;
    /// Maximum number of tags per identity.
    const MAX_TAGS: usize = 50;
    /// Maximum length for a single tag.
    const MAX_TAG_LEN: usize = 128;
    /// Maximum number of metadata entries.
    const MAX_METADATA_ENTRIES: usize = 50;
    /// Maximum length for a metadata key.
    const MAX_METADATA_KEY_LEN: usize = 128;
    /// Maximum length for a metadata value.
    const MAX_METADATA_VALUE_LEN: usize = 1024;
    /// Maximum length for SPIFFE ID.
    const MAX_SPIFFE_ID_LEN: usize = 512;

    /// SECURITY (FIND-R115-025): Validate register_identity inputs for length bounds
    /// and control/format characters.
    fn validate_register_identity_inputs(
        name: &str,
        spiffe_id: Option<&str>,
        tags: &[String],
        metadata: &HashMap<String, String>,
    ) -> Result<(), NhiError> {
        // Validate name
        if name.is_empty() {
            return Err(NhiError::InputValidation("name must not be empty".to_string()));
        }
        if name.len() > Self::MAX_NAME_LEN {
            return Err(NhiError::InputValidation(format!(
                "name length {} exceeds maximum {}",
                name.len(),
                Self::MAX_NAME_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(name) {
            return Err(NhiError::InputValidation(
                "name contains control or Unicode format characters".to_string(),
            ));
        }

        // Validate SPIFFE ID
        if let Some(sid) = spiffe_id {
            if sid.len() > Self::MAX_SPIFFE_ID_LEN {
                return Err(NhiError::InputValidation(format!(
                    "spiffe_id length {} exceeds maximum {}",
                    sid.len(),
                    Self::MAX_SPIFFE_ID_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(sid) {
                return Err(NhiError::InputValidation(
                    "spiffe_id contains control or Unicode format characters".to_string(),
                ));
            }
        }

        // Validate tags
        if tags.len() > Self::MAX_TAGS {
            return Err(NhiError::InputValidation(format!(
                "tags count {} exceeds maximum {}",
                tags.len(),
                Self::MAX_TAGS
            )));
        }
        for tag in tags {
            if tag.len() > Self::MAX_TAG_LEN {
                return Err(NhiError::InputValidation(format!(
                    "tag length {} exceeds maximum {}",
                    tag.len(),
                    Self::MAX_TAG_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(tag) {
                return Err(NhiError::InputValidation(
                    "tag contains control or Unicode format characters".to_string(),
                ));
            }
        }

        // Validate metadata
        if metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(NhiError::InputValidation(format!(
                "metadata count {} exceeds maximum {}",
                metadata.len(),
                Self::MAX_METADATA_ENTRIES
            )));
        }
        for (key, value) in metadata {
            if key.len() > Self::MAX_METADATA_KEY_LEN {
                return Err(NhiError::InputValidation(format!(
                    "metadata key length {} exceeds maximum {}",
                    key.len(),
                    Self::MAX_METADATA_KEY_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(key) {
                return Err(NhiError::InputValidation(
                    "metadata key contains control or Unicode format characters".to_string(),
                ));
            }
            if value.len() > Self::MAX_METADATA_VALUE_LEN {
                return Err(NhiError::InputValidation(format!(
                    "metadata value length {} exceeds maximum {}",
                    value.len(),
                    Self::MAX_METADATA_VALUE_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(value) {
                return Err(NhiError::InputValidation(
                    "metadata value contains control or Unicode format characters".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Compute a JWK thumbprint for a key.
    fn compute_thumbprint(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, result)
    }

    /// Cleanup expired identities and delegations.
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now();

        // Cleanup expired identities
        // SECURITY (FIND-R44-036): Also check Probationary identities for TTL expiration,
        // not just Active. If a Probationary identity's TTL has elapsed, transition to Expired.
        {
            let mut identities = self.identities.write().await;
            for identity in identities.values_mut() {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&identity.expires_at) {
                    if expires.with_timezone(&chrono::Utc) <= now
                        && matches!(
                            identity.status,
                            NhiIdentityStatus::Active | NhiIdentityStatus::Probationary
                        )
                    {
                        identity.status = NhiIdentityStatus::Expired;
                    }
                }
            }
        }

        // Cleanup expired delegations
        {
            let mut delegations = self.delegations.write().await;
            for delegation in delegations.values_mut() {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&delegation.expires_at) {
                    if expires.with_timezone(&chrono::Utc) <= now {
                        delegation.active = false;
                    }
                }
            }
        }

        // Update stats
        let identities = self.identities.read().await;
        let delegations = self.delegations.read().await;
        let mut stats = self.stats.write().await;
        stats.total_identities = identities.len() as u64;
        stats.active_identities = identities
            .values()
            .filter(|i| {
                i.status == NhiIdentityStatus::Active || i.status == NhiIdentityStatus::Probationary
            })
            .count() as u64;
        stats.expired_identities = identities
            .values()
            .filter(|i| i.status == NhiIdentityStatus::Expired)
            .count() as u64;
        stats.active_delegations = delegations.values().filter(|d| d.active).count() as u64;
    }
}

impl Default for NhiManager {
    fn default() -> Self {
        Self::new(NhiConfig::default())
    }
}

// ═══════════════════════════════════════════════════
// DPOP NONCE TRACKER
// ═══════════════════════════════════════════════════

/// Tracks DPoP nonces for replay prevention.
#[derive(Debug)]
struct DpopNonceTracker {
    /// Active nonces with their creation timestamp.
    nonces: HashMap<String, u64>,
    /// TTL for nonces in seconds.
    ttl_secs: u64,
}

impl DpopNonceTracker {
    fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            ttl_secs: 300, // 5 minutes default
        }
    }

    fn generate_nonce(&mut self) -> String {
        let nonce = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp() as u64;

        // Cleanup old nonces
        self.nonces
            .retain(|_, ts| now.saturating_sub(*ts) < self.ttl_secs);

        self.nonces.insert(nonce.clone(), now);
        nonce
    }

    fn is_valid(&self, nonce: &str) -> bool {
        if let Some(&created_at) = self.nonces.get(nonce) {
            let now = chrono::Utc::now().timestamp() as u64;
            now.saturating_sub(created_at) < self.ttl_secs
        } else {
            false
        }
    }
}

// ═══════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════

/// Errors from NHI operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NhiError {
    /// NHI manager is disabled.
    Disabled,
    /// Identity not found.
    IdentityNotFound(String),
    /// Attestation type not allowed.
    AttestationTypeNotAllowed(String),
    /// Requested TTL exceeds maximum.
    TtlExceedsMax { requested: u64, max: u64 },
    /// Capacity limit exceeded.
    CapacityExceeded(String),
    /// Invalid status transition.
    InvalidStatusTransition {
        from: NhiIdentityStatus,
        to: NhiIdentityStatus,
    },
    /// Delegation not found.
    DelegationNotFound { from: String, to: String },
    /// Delegation chain too deep.
    ChainTooDeep { depth: usize, max: usize },
    /// DID generation failed.
    DidGenerationFailed(String),
    /// Agent has no public key configured.
    NoPublicKey(String),
    /// Attestation signing or verification error.
    AttestationError(String),
    /// Too many attestations for this identity.
    AttestationLimitExceeded { agent_id: String, max: usize },
    /// Verification tier downgrade is not allowed.
    TierDowngradeNotAllowed {
        current: VerificationTier,
        requested: VerificationTier,
    },
    /// SECURITY (FIND-R115-021): Self-delegation is not permitted.
    SelfDelegation,
    /// SECURITY (FIND-R115-022): Agent is in a terminal state (Revoked/Expired).
    TerminalStateAgent {
        agent_id: String,
        status: NhiIdentityStatus,
    },
    /// SECURITY (FIND-R115-025): Input validation failure.
    InputValidation(String),
    /// SECURITY (FIND-R126-005): Structural validation failure from NhiAgentIdentity::validate().
    ValidationFailed(String),
}

impl std::fmt::Display for NhiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NhiError::Disabled => write!(f, "NHI manager is disabled"),
            NhiError::IdentityNotFound(id) => write!(f, "Identity not found: {}", id),
            NhiError::AttestationTypeNotAllowed(t) => {
                write!(f, "Attestation type not allowed: {}", t)
            }
            NhiError::TtlExceedsMax { requested, max } => {
                write!(f, "Requested TTL {} exceeds maximum {}", requested, max)
            }
            NhiError::CapacityExceeded(what) => write!(f, "Capacity exceeded for {}", what),
            NhiError::InvalidStatusTransition { from, to } => {
                write!(f, "Invalid status transition from {} to {}", from, to)
            }
            NhiError::DelegationNotFound { from, to } => {
                write!(f, "Delegation not found: {} -> {}", from, to)
            }
            NhiError::ChainTooDeep { depth, max } => {
                write!(
                    f,
                    "Delegation chain depth {} exceeds maximum {}",
                    depth, max
                )
            }
            NhiError::DidGenerationFailed(msg) => {
                write!(f, "DID generation failed: {}", msg)
            }
            NhiError::NoPublicKey(id) => {
                write!(f, "Agent '{}' has no public key configured", id)
            }
            NhiError::AttestationError(msg) => {
                write!(f, "Attestation error: {}", msg)
            }
            NhiError::AttestationLimitExceeded { agent_id, max } => {
                write!(
                    f,
                    "Agent '{}' exceeds attestation limit of {}",
                    agent_id, max
                )
            }
            NhiError::TierDowngradeNotAllowed { current, requested } => {
                write!(
                    f,
                    "Cannot downgrade verification tier from {} to {}",
                    current, requested
                )
            }
            NhiError::SelfDelegation => {
                write!(f, "Self-delegation is not permitted")
            }
            NhiError::TerminalStateAgent { agent_id, status } => {
                write!(
                    f,
                    "Agent '{}' is in terminal state '{}' and cannot participate in delegation",
                    agent_id, status
                )
            }
            NhiError::InputValidation(msg) => {
                write!(f, "Input validation failed: {}", msg)
            }
            NhiError::ValidationFailed(msg) => {
                write!(f, "Validation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for NhiError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> NhiConfig {
        NhiConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_register_identity() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Test Agent",
                NhiAttestationType::Jwt,
                None,
                Some("public-key"),
                Some("Ed25519"),
                None,
                vec!["production".to_string()],
                HashMap::new(),
            )
            .await
            .unwrap();

        assert!(!id.is_empty());

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.name, "Test Agent");
        assert_eq!(identity.status, NhiIdentityStatus::Probationary);
    }

    #[tokio::test]
    async fn test_identity_lifecycle() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Lifecycle Test",
                NhiAttestationType::Spiffe,
                Some("spiffe://example.org/agent"),
                None,
                None,
                Some(3600),
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Activate
        manager.activate_identity(&id).await.unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Active);

        // Record auth
        manager.record_auth(&id).await.unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.auth_count, 1);

        // Suspend
        manager
            .update_status(&id, NhiIdentityStatus::Suspended)
            .await
            .unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Suspended);

        // Revoke
        manager
            .update_status(&id, NhiIdentityStatus::Revoked)
            .await
            .unwrap();
        assert!(manager.is_revoked(&id).await);
    }

    #[tokio::test]
    async fn test_behavioral_baseline() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Behavioral Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Update baseline multiple times
        for i in 0..100 {
            manager
                .update_baseline(
                    &id,
                    "file:read",
                    Some(1.0 + (i as f64 * 0.01)),
                    Some("10.0.0.1"),
                )
                .await
                .unwrap();
        }

        let baseline = manager.get_baseline(&id).await.unwrap();
        assert_eq!(baseline.observation_count, 100);
        assert!(baseline.confidence >= 1.0);
        assert!(baseline.tool_call_patterns.contains_key("file:read"));
    }

    #[tokio::test]
    async fn test_behavioral_check() {
        let mut config = enabled_config();
        config.min_baseline_observations = 10;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Check Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Build baseline
        for _ in 0..20 {
            manager
                .update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1"))
                .await
                .unwrap();
        }

        // Check normal behavior
        let result = manager
            .check_behavior(&id, "file:read", Some(1.0), Some("10.0.0.1"))
            .await;
        assert!(result.within_baseline);
        assert_eq!(result.recommendation, NhiBehavioralRecommendation::Allow);

        // Check anomalous behavior (unknown tool)
        let result = manager
            .check_behavior(&id, "bash:execute", Some(1.0), Some("10.0.0.1"))
            .await;
        assert!(!result.within_baseline || result.anomaly_score > 0.0);
    }

    #[tokio::test]
    async fn test_delegation_chain() {
        let manager = NhiManager::new(enabled_config());

        // Register three agents
        let agent_a = manager
            .register_identity(
                "Agent A",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        let agent_b = manager
            .register_identity(
                "Agent B",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        let agent_c = manager
            .register_identity(
                "Agent C",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Create delegation chain: A -> B -> C
        manager
            .create_delegation(
                &agent_a,
                &agent_b,
                vec!["read".to_string()],
                vec![],
                3600,
                None,
            )
            .await
            .unwrap();
        manager
            .create_delegation(
                &agent_b,
                &agent_c,
                vec!["read".to_string()],
                vec![],
                3600,
                None,
            )
            .await
            .unwrap();

        // Resolve chain from C
        let chain = manager.resolve_delegation_chain(&agent_c).await;
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.origin(), Some(agent_a.as_str()));
        assert_eq!(chain.terminus(), Some(agent_c.as_str()));
    }

    #[tokio::test]
    async fn test_credential_rotation() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Rotation Test",
                NhiAttestationType::Jwt,
                None,
                Some("old-key"),
                Some("Ed25519"),
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let rotation = manager
            .rotate_credentials(&id, "new-key", Some("Ed25519"), "scheduled", None)
            .await
            .unwrap();

        assert!(rotation.previous_thumbprint.is_some());
        assert!(!rotation.new_thumbprint.is_empty());
        assert_eq!(rotation.trigger, "scheduled");

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.public_key, Some("new-key".to_string()));
        assert!(identity.last_rotation.is_some());
    }

    #[tokio::test]
    async fn test_dpop_nonce() {
        let manager = NhiManager::new(enabled_config());

        let nonce1 = manager.generate_dpop_nonce().await;
        let nonce2 = manager.generate_dpop_nonce().await;

        assert_ne!(nonce1, nonce2);

        let nonces = manager.dpop_nonces.read().await;
        assert!(nonces.is_valid(&nonce1));
        assert!(nonces.is_valid(&nonce2));
    }

    #[tokio::test]
    async fn test_disabled_manager() {
        let manager = NhiManager::new(NhiConfig::default()); // Disabled by default

        let result = manager
            .register_identity(
                "Should Fail",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(matches!(result, Err(NhiError::Disabled)));
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = NhiManager::new(enabled_config());

        manager
            .register_identity(
                "Test 1",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        manager
            .register_identity(
                "Test 2",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_identities, 2);
        assert_eq!(stats.active_identities, 2); // Probationary counts as active
    }

    #[tokio::test]
    async fn test_generate_agent_did() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "DID Test Agent",
                NhiAttestationType::Jwt,
                None,
                Some("abcdef1234567890abcdef1234567890"),
                Some("Ed25519"),
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let did = manager.generate_agent_did(&id).await.unwrap();
        assert!(did.as_str().starts_with("did:plc:"));
        assert_eq!(did.identifier().len(), 24);

        // Should be stored on the identity
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.did_plc.as_deref(), Some(did.as_str()));
    }

    #[tokio::test]
    async fn test_generate_agent_did_no_public_key() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "No Key Agent",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let result = manager.generate_agent_did(&id).await;
        assert!(matches!(result, Err(NhiError::NoPublicKey(_))));
    }

    #[tokio::test]
    async fn test_generate_agent_did_deterministic() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Deterministic DID",
                NhiAttestationType::Jwt,
                None,
                Some("deadbeef12345678"),
                Some("Ed25519"),
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let did1 = manager.generate_agent_did(&id).await.unwrap();
        let did2 = manager.generate_agent_did(&id).await.unwrap();
        assert_eq!(did1, did2, "Same key must produce same DID");
    }

    #[tokio::test]
    async fn test_set_verification_tier() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Tier Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Default tier should be Unverified
        let tier = manager.get_verification_tier(&id).await.unwrap();
        assert_eq!(tier, VerificationTier::Unverified);

        // Upgrade to EmailVerified
        manager
            .set_verification_tier(&id, VerificationTier::EmailVerified)
            .await
            .unwrap();
        let tier = manager.get_verification_tier(&id).await.unwrap();
        assert_eq!(tier, VerificationTier::EmailVerified);

        // Upgrade to DidVerified
        manager
            .set_verification_tier(&id, VerificationTier::DidVerified)
            .await
            .unwrap();
        let tier = manager.get_verification_tier(&id).await.unwrap();
        assert_eq!(tier, VerificationTier::DidVerified);
    }

    #[tokio::test]
    async fn test_set_verification_tier_no_downgrade() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "No Downgrade",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Set to DidVerified
        manager
            .set_verification_tier(&id, VerificationTier::DidVerified)
            .await
            .unwrap();

        // Try to downgrade to EmailVerified — should fail
        let result = manager
            .set_verification_tier(&id, VerificationTier::EmailVerified)
            .await;
        assert!(matches!(
            result,
            Err(NhiError::TierDowngradeNotAllowed { .. })
        ));

        // Tier should still be DidVerified
        let tier = manager.get_verification_tier(&id).await.unwrap();
        assert_eq!(tier, VerificationTier::DidVerified);
    }

    #[tokio::test]
    async fn test_sign_and_verify_attestation() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let signing_key_hex = hex::encode(signing_key.to_bytes());
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());

        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Attestation Agent",
                NhiAttestationType::Jwt,
                None,
                Some(&public_key_hex),
                Some("Ed25519"),
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let attestation = manager
            .sign_accountability_attestation(
                &id,
                "I accept the data handling policy",
                "sha256:abc123",
                &signing_key_hex,
                86400,
            )
            .await
            .unwrap();

        assert_eq!(attestation.agent_id, id);
        assert_eq!(attestation.algorithm, "Ed25519");

        // Verify
        let result = manager
            .verify_accountability_attestation(&attestation)
            .await
            .unwrap();
        assert!(result.is_valid());
        assert!(result.signature_valid);
        assert!(!result.expired);
    }

    #[tokio::test]
    async fn test_attestation_stored_on_identity() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let signing_key_hex = hex::encode(signing_key.to_bytes());

        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Storage Test",
                NhiAttestationType::Jwt,
                None,
                Some("test-key"),
                Some("Ed25519"),
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        manager
            .sign_accountability_attestation(&id, "stmt-1", "hash-1", &signing_key_hex, 86400)
            .await
            .unwrap();
        manager
            .sign_accountability_attestation(&id, "stmt-2", "hash-2", &signing_key_hex, 86400)
            .await
            .unwrap();

        let attestations = manager.list_attestations(&id).await.unwrap();
        assert_eq!(attestations.len(), 2);
        assert_eq!(attestations[0].statement, "stmt-1");
        assert_eq!(attestations[1].statement, "stmt-2");
    }

    #[tokio::test]
    async fn test_attestation_limit_enforced() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let signing_key_hex = hex::encode(signing_key.to_bytes());

        let mut config = enabled_config();
        config.verification.max_attestations_per_identity = 2;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Limit Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // First two should succeed
        manager
            .sign_accountability_attestation(&id, "s1", "h1", &signing_key_hex, 86400)
            .await
            .unwrap();
        manager
            .sign_accountability_attestation(&id, "s2", "h2", &signing_key_hex, 86400)
            .await
            .unwrap();

        // Third should fail
        let result = manager
            .sign_accountability_attestation(&id, "s3", "h3", &signing_key_hex, 86400)
            .await;
        assert!(matches!(
            result,
            Err(NhiError::AttestationLimitExceeded { .. })
        ));
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R44-036: cleanup_expired must transition Probationary identities
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-036: A Probationary identity whose TTL has elapsed must be
    /// transitioned to Expired by cleanup_expired().
    #[tokio::test]
    async fn test_cleanup_expired_transitions_probationary() {
        let mut config = enabled_config();
        config.max_credential_ttl_secs = 1; // 1 second TTL max
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Probationary Agent",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                Some(1), // 1-second TTL
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Identity starts as Probationary
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Probationary);

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Run cleanup
        manager.cleanup_expired().await;

        // Identity should now be Expired
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(
            identity.status,
            NhiIdentityStatus::Expired,
            "Probationary identity with elapsed TTL must be transitioned to Expired"
        );
    }

    /// FIND-R44-036: cleanup_expired still works for Active identities (regression).
    #[tokio::test]
    async fn test_cleanup_expired_still_transitions_active() {
        let mut config = enabled_config();
        config.max_credential_ttl_secs = 1;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Active Agent",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                Some(1),
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Activate the identity
        manager.activate_identity(&id).await.unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Active);

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        manager.cleanup_expired().await;

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(
            identity.status,
            NhiIdentityStatus::Expired,
            "Active identity with elapsed TTL must be transitioned to Expired"
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R44-039: is_terminal() covers Revoked and Expired
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-039: is_terminal returns true for Revoked identity.
    #[tokio::test]
    async fn test_is_terminal_returns_true_for_revoked() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Revoke Me",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        manager
            .update_status(&id, NhiIdentityStatus::Revoked)
            .await
            .unwrap();

        assert!(
            manager.is_terminal(&id).await,
            "Revoked identity must be terminal"
        );
        // is_revoked should also be true (backward compat)
        assert!(manager.is_revoked(&id).await);
    }

    /// FIND-R44-039: is_terminal returns true for Expired identity.
    #[tokio::test]
    async fn test_is_terminal_returns_true_for_expired() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Expire Me",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        manager
            .update_status(&id, NhiIdentityStatus::Expired)
            .await
            .unwrap();

        assert!(
            manager.is_terminal(&id).await,
            "Expired identity must be terminal"
        );
        // is_revoked returns false for Expired (it only checks revocation list)
        assert!(
            !manager.is_revoked(&id).await,
            "is_revoked should not cover Expired — use is_terminal instead"
        );
    }

    /// FIND-R44-039: is_terminal returns false for Active identity.
    #[tokio::test]
    async fn test_is_terminal_returns_false_for_active() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Active Agent",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        manager.activate_identity(&id).await.unwrap();

        assert!(
            !manager.is_terminal(&id).await,
            "Active identity must not be terminal"
        );
    }

    /// FIND-R44-039: is_terminal returns false for non-existent identity.
    #[tokio::test]
    async fn test_is_terminal_returns_false_for_nonexistent() {
        let manager = NhiManager::new(enabled_config());
        assert!(
            !manager.is_terminal("nonexistent-id").await,
            "Non-existent identity must not be terminal"
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R114-017: rotate_credentials must validate TTL against max_credential_ttl_secs
    // ═══════════════════════════════════════════════════════

    /// FIND-R114-017: rotate_credentials with explicit TTL exceeding max is rejected.
    #[tokio::test]
    async fn test_rotate_credentials_rejects_ttl_exceeding_max() {
        let mut config = enabled_config();
        config.max_credential_ttl_secs = 3600; // 1 hour max
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Rotation TTL Test",
                NhiAttestationType::Jwt,
                None,
                Some("old-key"),
                Some("Ed25519"),
                Some(1800), // 30 min, within max
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Attempt rotation with TTL exceeding max
        let result = manager
            .rotate_credentials(&id, "new-key", Some("Ed25519"), "scheduled", Some(7200))
            .await;

        assert!(
            matches!(
                result,
                Err(NhiError::TtlExceedsMax {
                    requested: 7200,
                    max: 3600
                })
            ),
            "rotate_credentials must reject TTL exceeding max_credential_ttl_secs, got: {:?}",
            result
        );

        // Verify old key is unchanged (rotation was rejected)
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(
            identity.public_key,
            Some("old-key".to_string()),
            "Rejected rotation must not modify the identity"
        );
    }

    /// FIND-R114-017: rotate_credentials with default TTL within max succeeds.
    #[tokio::test]
    async fn test_rotate_credentials_default_ttl_within_max_succeeds() {
        let mut config = enabled_config();
        config.credential_ttl_secs = 1800; // default 30 min
        config.max_credential_ttl_secs = 3600; // max 1 hour
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Default TTL Test",
                NhiAttestationType::Jwt,
                None,
                Some("old-key"),
                Some("Ed25519"),
                Some(1800),
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Rotation with None TTL should use credential_ttl_secs (1800), which is <= max (3600)
        let result = manager
            .rotate_credentials(&id, "new-key", Some("Ed25519"), "scheduled", None)
            .await;

        assert!(
            result.is_ok(),
            "rotate_credentials with default TTL within max should succeed, got: {:?}",
            result
        );
    }

    /// FIND-R114-017: rotate_credentials with explicit TTL at exactly max succeeds.
    #[tokio::test]
    async fn test_rotate_credentials_ttl_at_max_succeeds() {
        let mut config = enabled_config();
        config.max_credential_ttl_secs = 3600;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Exact Max TTL",
                NhiAttestationType::Jwt,
                None,
                Some("old-key"),
                Some("Ed25519"),
                Some(3600),
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // TTL exactly at max should succeed
        let result = manager
            .rotate_credentials(&id, "new-key", Some("Ed25519"), "scheduled", Some(3600))
            .await;

        assert!(
            result.is_ok(),
            "rotate_credentials with TTL == max should succeed, got: {:?}",
            result
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R115-021: Self-delegation rejection in create_delegation
    // ═══════════════════════════════════════════════════════

    /// FIND-R115-021: Self-delegation must be rejected (exact case).
    #[tokio::test]
    async fn test_create_delegation_rejects_self_delegation() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Self-Deleg Agent",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let result = manager
            .create_delegation(&id, &id, vec!["read".to_string()], vec![], 3600, None)
            .await;

        assert!(
            matches!(result, Err(NhiError::SelfDelegation)),
            "FIND-R115-021: Self-delegation must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-021: Self-delegation must be rejected (case-insensitive).
    #[tokio::test]
    async fn test_create_delegation_rejects_self_delegation_case_insensitive() {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "CaseTest",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // UUID IDs are lowercase, so an uppercase version tests the case path
        let upper_id = id.to_uppercase();
        let result = manager
            .create_delegation(&id, &upper_id, vec!["read".to_string()], vec![], 3600, None)
            .await;

        assert!(
            matches!(result, Err(NhiError::SelfDelegation)),
            "FIND-R115-021: Self-delegation (case-insensitive) must be rejected, got: {:?}",
            result
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R115-022: Delegation from/to terminal-state agents
    // ═══════════════════════════════════════════════════════

    /// FIND-R115-022: Delegation from a revoked agent must be rejected.
    #[tokio::test]
    async fn test_create_delegation_rejects_from_revoked_agent() {
        let manager = NhiManager::new(enabled_config());

        let from_id = manager
            .register_identity(
                "Revoked Delegator",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        let to_id = manager
            .register_identity(
                "Active Delegatee",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Revoke the delegator
        manager
            .update_status(&from_id, NhiIdentityStatus::Revoked)
            .await
            .unwrap();

        let result = manager
            .create_delegation(
                &from_id,
                &to_id,
                vec!["read".to_string()],
                vec![],
                3600,
                None,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::TerminalStateAgent { .. })),
            "FIND-R115-022: Delegation from revoked agent must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-022: Delegation to an expired agent must be rejected.
    #[tokio::test]
    async fn test_create_delegation_rejects_to_expired_agent() {
        let manager = NhiManager::new(enabled_config());

        let from_id = manager
            .register_identity(
                "Active Delegator",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        let to_id = manager
            .register_identity(
                "Expired Delegatee",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Expire the delegatee
        manager
            .update_status(&to_id, NhiIdentityStatus::Expired)
            .await
            .unwrap();

        let result = manager
            .create_delegation(
                &from_id,
                &to_id,
                vec!["read".to_string()],
                vec![],
                3600,
                None,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::TerminalStateAgent { .. })),
            "FIND-R115-022: Delegation to expired agent must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-022: Delegation between two active agents should succeed.
    #[tokio::test]
    async fn test_create_delegation_allows_active_agents() {
        let manager = NhiManager::new(enabled_config());

        let from_id = manager
            .register_identity(
                "Active A",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();
        let to_id = manager
            .register_identity(
                "Active B",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        let result = manager
            .create_delegation(
                &from_id,
                &to_id,
                vec!["read".to_string()],
                vec![],
                3600,
                None,
            )
            .await;

        assert!(
            result.is_ok(),
            "Delegation between two active agents should succeed: {:?}",
            result
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R115-024: NaN bypass in check_behavior request interval
    // ═══════════════════════════════════════════════════════

    /// FIND-R115-024: NaN z_score must be treated as an anomaly (fail-closed).
    #[tokio::test]
    async fn test_check_behavior_nan_zscore_flagged_as_anomaly() {
        let mut config = enabled_config();
        config.min_baseline_observations = 5;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "NaN Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Build baseline with identical intervals to get stddev near 0.
        for _ in 0..10 {
            manager
                .update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1"))
                .await
                .unwrap();
        }

        // Verify baseline is mature (confidence = 1.0)
        let baseline = manager.get_baseline(&id).await.unwrap();
        assert!(
            baseline.confidence >= 1.0,
            "Baseline should be mature"
        );

        // Check with NaN interval which produces NaN z_score.
        // This must be flagged as anomaly (fail-closed).
        let result = manager
            .check_behavior(&id, "file:read", Some(f64::NAN), Some("10.0.0.1"))
            .await;

        assert!(
            result.deviations.iter().any(|d| d.deviation_type == "request_interval"),
            "FIND-R115-024: NaN z_score must produce a request_interval deviation, got: {:?}",
            result.deviations
        );
    }

    /// FIND-R115-024: Infinity interval must be treated as an anomaly (fail-closed).
    #[tokio::test]
    async fn test_check_behavior_infinity_interval_flagged_as_anomaly() {
        let mut config = enabled_config();
        config.min_baseline_observations = 5;
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity(
                "Inf Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap();

        // Build baseline
        for _ in 0..10 {
            manager
                .update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1"))
                .await
                .unwrap();
        }

        // Check with Infinity interval
        let result = manager
            .check_behavior(&id, "file:read", Some(f64::INFINITY), Some("10.0.0.1"))
            .await;

        assert!(
            result.deviations.iter().any(|d| d.deviation_type == "request_interval"),
            "FIND-R115-024: Infinity interval must produce a request_interval deviation, got: {:?}",
            result.deviations
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R115-025: register_identity input validation
    // ═══════════════════════════════════════════════════════

    /// FIND-R115-025: Empty name must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_empty_name() {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .register_identity(
                "",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Empty name must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-025: Name exceeding max length must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_long_name() {
        let manager = NhiManager::new(enabled_config());
        let long_name = "a".repeat(NhiManager::MAX_NAME_LEN + 1);

        let result = manager
            .register_identity(
                &long_name,
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Long name must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("name length"));
    }

    /// FIND-R115-025: Name with control characters must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_name_control_chars() {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .register_identity(
                "agent\x00evil",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Name with control chars must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("control"));
    }

    /// FIND-R115-025: Name with Unicode format characters must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_name_unicode_format_chars() {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .register_identity(
                "agent\u{200B}hidden", // zero-width space
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Name with Unicode format chars must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-025: Too many tags must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_too_many_tags() {
        let manager = NhiManager::new(enabled_config());
        let tags: Vec<String> = (0..NhiManager::MAX_TAGS + 1)
            .map(|i| format!("tag-{}", i))
            .collect();

        let result = manager
            .register_identity(
                "Tag Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                tags,
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Too many tags must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("tags count"));
    }

    /// FIND-R115-025: Long tag must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_long_tag() {
        let manager = NhiManager::new(enabled_config());
        let long_tag = "t".repeat(NhiManager::MAX_TAG_LEN + 1);

        let result = manager
            .register_identity(
                "Tag Len Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![long_tag],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Long tag must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("tag length"));
    }

    /// FIND-R115-025: Tag with control characters must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_tag_control_chars() {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .register_identity(
                "Tag Ctrl Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec!["valid-tag".to_string(), "evil\ntag".to_string()],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Tag with control chars must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-025: Too many metadata entries must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_too_many_metadata() {
        let manager = NhiManager::new(enabled_config());
        let mut metadata = HashMap::new();
        for i in 0..NhiManager::MAX_METADATA_ENTRIES + 1 {
            metadata.insert(format!("key-{}", i), "value".to_string());
        }

        let result = manager
            .register_identity(
                "Meta Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                metadata,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Too many metadata entries must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("metadata count"));
    }

    /// FIND-R115-025: Long metadata key must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_long_metadata_key() {
        let manager = NhiManager::new(enabled_config());
        let long_key = "k".repeat(NhiManager::MAX_METADATA_KEY_LEN + 1);
        let mut metadata = HashMap::new();
        metadata.insert(long_key, "value".to_string());

        let result = manager
            .register_identity(
                "Meta Key Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                metadata,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Long metadata key must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("metadata key length"));
    }

    /// FIND-R115-025: Long metadata value must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_long_metadata_value() {
        let manager = NhiManager::new(enabled_config());
        let long_value = "v".repeat(NhiManager::MAX_METADATA_VALUE_LEN + 1);
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), long_value);

        let result = manager
            .register_identity(
                "Meta Val Test",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                metadata,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Long metadata value must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("metadata value length"));
    }

    /// FIND-R115-025: Metadata key with control characters must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_metadata_key_control_chars() {
        let manager = NhiManager::new(enabled_config());
        let mut metadata = HashMap::new();
        metadata.insert("evil\x01key".to_string(), "value".to_string());

        let result = manager
            .register_identity(
                "Meta Key Ctrl",
                NhiAttestationType::Jwt,
                None,
                None,
                None,
                None,
                vec![],
                metadata,
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Metadata key with control chars must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-025: SPIFFE ID exceeding max length must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_long_spiffe_id() {
        let manager = NhiManager::new(enabled_config());
        let long_spiffe = "s".repeat(NhiManager::MAX_SPIFFE_ID_LEN + 1);

        let result = manager
            .register_identity(
                "SPIFFE Test",
                NhiAttestationType::Spiffe,
                Some(&long_spiffe),
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "Long SPIFFE ID must be rejected, got: {:?}",
            result
        );
        assert!(result.unwrap_err().to_string().contains("spiffe_id length"));
    }

    /// FIND-R115-025: SPIFFE ID with control characters must be rejected.
    #[tokio::test]
    async fn test_register_identity_rejects_spiffe_id_control_chars() {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .register_identity(
                "SPIFFE Ctrl",
                NhiAttestationType::Spiffe,
                Some("spiffe://example.org/\x00agent"),
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await;

        assert!(
            matches!(result, Err(NhiError::InputValidation(_))),
            "SPIFFE ID with control chars must be rejected, got: {:?}",
            result
        );
    }

    /// FIND-R115-025: Valid inputs must still succeed.
    #[tokio::test]
    async fn test_register_identity_valid_inputs_succeed() {
        let manager = NhiManager::new(enabled_config());
        let mut metadata = HashMap::new();
        metadata.insert("env".to_string(), "production".to_string());

        let result = manager
            .register_identity(
                "Valid Agent",
                NhiAttestationType::Jwt,
                Some("spiffe://example.org/agent"),
                Some("public-key"),
                Some("Ed25519"),
                None,
                vec!["production".to_string(), "us-east-1".to_string()],
                metadata,
            )
            .await;

        assert!(
            result.is_ok(),
            "Valid inputs should succeed: {:?}",
            result
        );
    }
}
