//! Secure task management for MCP Tasks primitive (Phase 11).
//!
//! Implements security features for long-running MCP tasks:
//! - State encryption (ChaCha20-Poly1305)
//! - Hash chain integrity (SHA-256)
//! - Authenticated resume (HMAC-SHA256 tokens)
//! - Replay protection (nonce tracking)
//! - Checkpoint verification (Ed25519 signatures)
//!
//! # Security Properties
//!
//! - **Confidentiality**: Task state is encrypted at rest using ChaCha20-Poly1305
//! - **Integrity**: State transitions form a hash chain that detects tampering
//! - **Authentication**: Resume requests require HMAC-verified tokens
//! - **Replay Protection**: Each request must include a unique nonce
//! - **Non-repudiation**: Checkpoints are signed with Ed25519
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::task_security::SecureTaskManager;
//! use vellaveto_types::{TrackedTask, TaskStatus};
//!
//! let manager = SecureTaskManager::new(encryption_key, hmac_key)?;
//!
//! // Create a secure task
//! let task = TrackedTask { /* ... */ };
//! let secure_task = manager.create_secure_task(task, Some(state_data)).await?;
//!
//! // Resume with authentication
//! let result = manager.resume_task(&resume_request).await?;
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use vellaveto_types::{
    SecureTask, SecureTaskStats, TaskCheckpoint, TaskIntegrityResult, TaskResumeRequest,
    TaskResumeResult, TaskStateTransition, TaskStatus, TrackedTask,
};

type HmacSha256 = Hmac<Sha256>;

/// Errors from secure task operations.
#[derive(Error, Debug)]
pub enum TaskSecurityError {
    #[error("Task not found: {0}")]
    TaskNotFound(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid resume token")]
    InvalidResumeToken,
    #[error("Replay attack detected: nonce already seen")]
    ReplayDetected,
    #[error("Task integrity violation: {0}")]
    IntegrityViolation(String),
    #[error("Task in terminal state")]
    TaskTerminal,
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Checkpoint verification failed: {0}")]
    CheckpointVerificationFailed(String),
}

/// Secure task manager with encryption, integrity, and authentication.
///
/// Thread-safe via `RwLock` for concurrent access.
pub struct SecureTaskManager {
    /// Active secure tasks by task_id.
    tasks: RwLock<HashMap<String, SecureTask>>,

    /// Checkpoints by checkpoint_id.
    checkpoints: RwLock<HashMap<String, TaskCheckpoint>>,

    /// ChaCha20-Poly1305 cipher for state encryption.
    cipher: ChaCha20Poly1305,

    /// HMAC key for resume token generation/verification.
    hmac_key: [u8; 32],

    /// Ed25519 signing key for checkpoints (optional).
    signing_key: Option<SigningKey>,

    /// Statistics counters.
    resume_attempts: AtomicU64,
    resume_successes: AtomicU64,
    replay_blocked: AtomicU64,
    integrity_violations: AtomicU64,
    checkpoints_created: AtomicU64,
}

impl SecureTaskManager {
    /// Create a new secure task manager.
    ///
    /// # Arguments
    /// * `encryption_key` - 32-byte key for ChaCha20-Poly1305 encryption
    /// * `hmac_key` - 32-byte key for HMAC-SHA256 resume tokens
    pub fn new(encryption_key: [u8; 32], hmac_key: [u8; 32]) -> Result<Self, TaskSecurityError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|e| TaskSecurityError::InvalidKey(e.to_string()))?;

        Ok(Self {
            tasks: RwLock::new(HashMap::new()),
            checkpoints: RwLock::new(HashMap::new()),
            cipher,
            hmac_key,
            signing_key: None,
            resume_attempts: AtomicU64::new(0),
            resume_successes: AtomicU64::new(0),
            replay_blocked: AtomicU64::new(0),
            integrity_violations: AtomicU64::new(0),
            checkpoints_created: AtomicU64::new(0),
        })
    }

    /// Create a secure task manager with a signing key for checkpoints.
    pub fn with_signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Create a shareable reference to this manager.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Create a secure task from a tracked task.
    ///
    /// Optionally encrypts state data and generates a resume token.
    pub async fn create_secure_task(
        &self,
        task: TrackedTask,
        state_data: Option<&serde_json::Value>,
    ) -> Result<SecureTask, TaskSecurityError> {
        let mut tasks = self.tasks.write().await;

        if tasks.contains_key(&task.task_id) {
            return Err(TaskSecurityError::IntegrityViolation(format!(
                "Task '{}' already exists",
                task.task_id
            )));
        }

        let mut secure_task = SecureTask::new(task.clone());

        // Generate resume token
        secure_task.resume_token = Some(self.generate_resume_token(&task.task_id)?);

        // Encrypt state data if provided
        if let Some(data) = state_data {
            let (ciphertext, nonce) = self.encrypt_state(data)?;
            secure_task.encrypted_state = Some(ciphertext);
            secure_task.encryption_nonce = Some(nonce);
        }

        // Record initial state transition
        // SECURITY (FIND-R49-001): Bound state_chain to prevent memory exhaustion.
        if secure_task.state_chain.len() >= vellaveto_types::MAX_STATE_CHAIN {
            return Err(TaskSecurityError::IntegrityViolation(format!(
                "state_chain exceeds maximum of {} entries",
                vellaveto_types::MAX_STATE_CHAIN,
            )));
        }
        let transition = self.create_transition(&secure_task, task.status.clone(), None);
        secure_task.state_chain.push(transition);

        tasks.insert(task.task_id.clone(), secure_task.clone());
        Ok(secure_task)
    }

    /// Update a task's status with hash chain recording.
    pub async fn update_status(
        &self,
        task_id: &str,
        new_status: TaskStatus,
        triggered_by: Option<&str>,
    ) -> Result<(), TaskSecurityError> {
        let mut tasks = self.tasks.write().await;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(task_id.to_string()))?;

        if task.task.is_terminal() {
            return Err(TaskSecurityError::TaskTerminal);
        }

        // SECURITY (FIND-R49-001): Bound state_chain to prevent memory exhaustion.
        if task.state_chain.len() >= vellaveto_types::MAX_STATE_CHAIN {
            return Err(TaskSecurityError::IntegrityViolation(format!(
                "state_chain exceeds maximum of {} entries",
                vellaveto_types::MAX_STATE_CHAIN,
            )));
        }
        // Record state transition
        let transition = self.create_transition(
            task,
            new_status.clone(),
            triggered_by.map(|s| s.to_string()),
        );
        task.state_chain.push(transition);
        task.task.status = new_status;

        Ok(())
    }

    /// Update task state with encryption.
    pub async fn update_state(
        &self,
        task_id: &str,
        state_data: &serde_json::Value,
    ) -> Result<(), TaskSecurityError> {
        let mut tasks = self.tasks.write().await;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(task_id.to_string()))?;

        let (ciphertext, nonce) = self.encrypt_state(state_data)?;
        task.encrypted_state = Some(ciphertext);
        task.encryption_nonce = Some(nonce);

        Ok(())
    }

    /// Resume a task with authentication.
    ///
    /// Verifies the resume token and nonce before returning task state.
    pub async fn resume_task(
        &self,
        request: &TaskResumeRequest,
    ) -> Result<TaskResumeResult, TaskSecurityError> {
        self.resume_attempts.fetch_add(1, Ordering::Relaxed);

        let mut tasks = self.tasks.write().await;

        let task = tasks
            .get_mut(&request.task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(request.task_id.clone()))?;

        // Check replay protection
        if task.is_nonce_seen(&request.nonce) {
            self.replay_blocked.fetch_add(1, Ordering::Relaxed);
            return Err(TaskSecurityError::ReplayDetected);
        }

        // Verify resume token (compare directly, no lock needed since we have task)
        let token_valid = task.resume_token.as_deref() == Some(&request.resume_token);
        if !token_valid {
            return Ok(TaskResumeResult {
                authorized: false,
                task: None,
                decrypted_state: None,
                denial_reason: Some("Invalid resume token".to_string()),
            });
        }

        // Record nonce
        task.record_nonce(request.nonce.clone());

        // Decrypt state if available
        let decrypted_state = if let (Some(ciphertext), Some(nonce)) =
            (&task.encrypted_state, &task.encryption_nonce)
        {
            Some(self.decrypt_state(ciphertext, nonce)?)
        } else {
            None
        };

        self.resume_successes.fetch_add(1, Ordering::Relaxed);

        Ok(TaskResumeResult {
            authorized: true,
            task: Some(task.clone()),
            decrypted_state,
            denial_reason: None,
        })
    }

    /// Verify the integrity of a task's state chain.
    pub async fn verify_integrity(
        &self,
        task_id: &str,
    ) -> Result<TaskIntegrityResult, TaskSecurityError> {
        let tasks = self.tasks.read().await;

        let task = tasks
            .get(task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(task_id.to_string()))?;

        let result = self.verify_chain(&task.state_chain);

        if !result.valid {
            self.integrity_violations.fetch_add(1, Ordering::Relaxed);
        }

        Ok(result)
    }

    /// Create a signed checkpoint for a task.
    pub async fn create_checkpoint(
        &self,
        task_id: &str,
    ) -> Result<TaskCheckpoint, TaskSecurityError> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            TaskSecurityError::InvalidKey("No signing key configured".to_string())
        })?;

        let tasks = self.tasks.read().await;
        let task = tasks
            .get(task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(task_id.to_string()))?;

        let sequence = task.current_sequence();
        let state_hash = task.latest_hash().unwrap_or("").to_string();
        let created_at = chrono::Utc::now().to_rfc3339();
        let checkpoint_id = format!("cp-{}", uuid::Uuid::new_v4());

        // Create signature message
        let message = format!(
            "{}|{}|{}|{}|{}",
            checkpoint_id, task_id, sequence, state_hash, created_at
        );
        let signature = signing_key.sign(message.as_bytes());

        let checkpoint = TaskCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            task_id: task_id.to_string(),
            sequence,
            state_hash,
            created_at,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().as_bytes()),
        };

        drop(tasks);

        let mut checkpoints = self.checkpoints.write().await;
        checkpoints.insert(checkpoint_id, checkpoint.clone());
        self.checkpoints_created.fetch_add(1, Ordering::Relaxed);

        Ok(checkpoint)
    }

    /// Verify a checkpoint's signature.
    pub fn verify_checkpoint(
        &self,
        checkpoint: &TaskCheckpoint,
    ) -> Result<bool, TaskSecurityError> {
        let public_key_bytes = hex::decode(&checkpoint.public_key)
            .map_err(|e| TaskSecurityError::CheckpointVerificationFailed(e.to_string()))?;

        if public_key_bytes.len() != 32 {
            return Err(TaskSecurityError::CheckpointVerificationFailed(
                "Invalid public key length".to_string(),
            ));
        }

        let key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
            TaskSecurityError::CheckpointVerificationFailed("Invalid key format".to_string())
        })?;

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| TaskSecurityError::CheckpointVerificationFailed(e.to_string()))?;

        let signature_bytes = hex::decode(&checkpoint.signature)
            .map_err(|e| TaskSecurityError::CheckpointVerificationFailed(e.to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(TaskSecurityError::CheckpointVerificationFailed(
                "Invalid signature length".to_string(),
            ));
        }

        let sig_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            TaskSecurityError::CheckpointVerificationFailed("Invalid signature format".to_string())
        })?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let message = format!(
            "{}|{}|{}|{}|{}",
            checkpoint.checkpoint_id,
            checkpoint.task_id,
            checkpoint.sequence,
            checkpoint.state_hash,
            checkpoint.created_at
        );

        match verifying_key.verify_strict(message.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get a secure task by ID.
    pub async fn get_task(&self, task_id: &str) -> Option<SecureTask> {
        let tasks = self.tasks.read().await;
        tasks.get(task_id).cloned()
    }

    /// Get a task with decrypted state (requires authorization).
    pub async fn get_task_with_state(
        &self,
        task_id: &str,
        resume_token: &str,
    ) -> Result<(SecureTask, Option<serde_json::Value>), TaskSecurityError> {
        let tasks = self.tasks.read().await;

        let task = tasks
            .get(task_id)
            .ok_or_else(|| TaskSecurityError::TaskNotFound(task_id.to_string()))?;

        // Verify resume token
        if !self.verify_resume_token(task_id, resume_token) {
            return Err(TaskSecurityError::InvalidResumeToken);
        }

        let decrypted = if let (Some(ciphertext), Some(nonce)) =
            (&task.encrypted_state, &task.encryption_nonce)
        {
            Some(self.decrypt_state(ciphertext, nonce)?)
        } else {
            None
        };

        Ok((task.clone(), decrypted))
    }

    /// Get statistics.
    pub async fn stats(&self) -> SecureTaskStats {
        let tasks = self.tasks.read().await;

        let encrypted_count = tasks
            .values()
            .filter(|t| t.encrypted_state.is_some())
            .count();
        let total_transitions: u64 = tasks.values().map(|t| t.state_chain.len() as u64).sum();

        SecureTaskStats {
            total_tasks: tasks.len(),
            encrypted_tasks: encrypted_count,
            total_transitions,
            checkpoints_created: self.checkpoints_created.load(Ordering::Relaxed),
            resume_attempts: self.resume_attempts.load(Ordering::Relaxed),
            resume_successes: self.resume_successes.load(Ordering::Relaxed),
            replay_attacks_blocked: self.replay_blocked.load(Ordering::Relaxed),
            integrity_violations: self.integrity_violations.load(Ordering::Relaxed),
        }
    }

    /// Remove terminal tasks older than retention period.
    pub async fn cleanup_old_tasks(&self, retention_secs: u64) -> usize {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(retention_secs as i64);
        let mut tasks = self.tasks.write().await;

        let old_len = tasks.len();
        tasks.retain(|_, task| {
            if !task.task.is_terminal() {
                return true;
            }
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&task.task.created_at) {
                created > cutoff
            } else {
                true
            }
        });

        old_len - tasks.len()
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────────

    fn encrypt_state(
        &self,
        data: &serde_json::Value,
    ) -> Result<(String, String), TaskSecurityError> {
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| TaskSecurityError::EncryptionFailed(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| TaskSecurityError::EncryptionFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| TaskSecurityError::EncryptionFailed(e.to_string()))?;

        Ok((BASE64.encode(&ciphertext), BASE64.encode(nonce_bytes)))
    }

    fn decrypt_state(
        &self,
        ciphertext_b64: &str,
        nonce_b64: &str,
    ) -> Result<serde_json::Value, TaskSecurityError> {
        let ciphertext = BASE64
            .decode(ciphertext_b64)
            .map_err(|e| TaskSecurityError::DecryptionFailed(e.to_string()))?;

        let nonce_bytes = BASE64
            .decode(nonce_b64)
            .map_err(|e| TaskSecurityError::DecryptionFailed(e.to_string()))?;

        if nonce_bytes.len() != 12 {
            return Err(TaskSecurityError::DecryptionFailed(
                "Invalid nonce length".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| TaskSecurityError::DecryptionFailed(e.to_string()))?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| TaskSecurityError::DecryptionFailed(e.to_string()))
    }

    fn generate_resume_token(&self, task_id: &str) -> Result<String, TaskSecurityError> {
        // HMAC-SHA256 accepts any key length, but we propagate errors per no-panic policy.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .map_err(|e| TaskSecurityError::InvalidKey(e.to_string()))?;
        mac.update(task_id.as_bytes());
        mac.update(b"|resume|");
        // Add random component for uniqueness
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|e| TaskSecurityError::EncryptionFailed(format!("RNG failed: {}", e)))?;
        mac.update(&random);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn verify_resume_token(&self, task_id: &str, token: &str) -> bool {
        // For verification, we check that the token was generated with our key
        // by checking if it's a valid HMAC (we store the full token, so we compare directly)
        // In production, you'd store a hash of the token and compare
        let tasks = self.tasks.try_read();
        if let Ok(tasks) = tasks {
            if let Some(task) = tasks.get(task_id) {
                return task.resume_token.as_deref() == Some(token);
            }
        }
        false
    }

    fn create_transition(
        &self,
        task: &SecureTask,
        new_status: TaskStatus,
        triggered_by: Option<String>,
    ) -> TaskStateTransition {
        let sequence = task.current_sequence() + 1;
        let prev_hash = task.latest_hash().unwrap_or("").to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Compute hash: SHA-256(sequence|prev_hash|status|timestamp)
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(format!("{}", new_status).as_bytes());
        hasher.update(timestamp.as_bytes());
        if let Some(ref agent) = triggered_by {
            hasher.update(agent.as_bytes());
        }
        let hash = hex::encode(hasher.finalize());

        TaskStateTransition {
            sequence,
            prev_hash,
            new_status,
            timestamp,
            triggered_by,
            hash,
        }
    }

    fn verify_chain(&self, chain: &[TaskStateTransition]) -> TaskIntegrityResult {
        if chain.is_empty() {
            return TaskIntegrityResult {
                valid: true,
                transitions_verified: 0,
                first_broken_at: None,
                failure_reason: None,
            };
        }

        let mut prev_hash = String::new();

        for (i, transition) in chain.iter().enumerate() {
            // Verify sequence is monotonic
            if transition.sequence != (i as u64 + 1) {
                return TaskIntegrityResult {
                    valid: false,
                    transitions_verified: i as u64,
                    first_broken_at: Some(i as u64),
                    failure_reason: Some(format!(
                        "Sequence mismatch: expected {}, got {}",
                        i + 1,
                        transition.sequence
                    )),
                };
            }

            // Verify prev_hash matches
            if transition.prev_hash != prev_hash {
                return TaskIntegrityResult {
                    valid: false,
                    transitions_verified: i as u64,
                    first_broken_at: Some(i as u64),
                    failure_reason: Some("Previous hash mismatch".to_string()),
                };
            }

            // Recompute and verify hash
            let mut hasher = Sha256::new();
            hasher.update(transition.sequence.to_le_bytes());
            hasher.update(transition.prev_hash.as_bytes());
            hasher.update(format!("{}", transition.new_status).as_bytes());
            hasher.update(transition.timestamp.as_bytes());
            if let Some(ref agent) = transition.triggered_by {
                hasher.update(agent.as_bytes());
            }
            let computed_hash = hex::encode(hasher.finalize());

            if computed_hash != transition.hash {
                return TaskIntegrityResult {
                    valid: false,
                    transitions_verified: i as u64,
                    first_broken_at: Some(i as u64),
                    failure_reason: Some("Hash verification failed".to_string()),
                };
            }

            prev_hash = transition.hash.clone();
        }

        TaskIntegrityResult {
            valid: true,
            transitions_verified: chain.len() as u64,
            first_broken_at: None,
            failure_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_keys() -> ([u8; 32], [u8; 32]) {
        let mut enc_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        getrandom::getrandom(&mut enc_key).unwrap();
        getrandom::getrandom(&mut hmac_key).unwrap();
        (enc_key, hmac_key)
    }

    fn make_task(id: &str) -> TrackedTask {
        TrackedTask {
            task_id: id.to_string(),
            tool: "test_tool".to_string(),
            function: "execute".to_string(),
            status: TaskStatus::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            created_by: Some("agent-1".to_string()),
            session_id: Some("session-1".to_string()),
        }
    }

    #[tokio::test]
    async fn test_create_secure_task() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        let state = json!({"progress": 0, "data": "test"});

        let secure = manager
            .create_secure_task(task, Some(&state))
            .await
            .unwrap();

        assert!(secure.resume_token.is_some());
        assert!(secure.encrypted_state.is_some());
        assert!(secure.encryption_nonce.is_some());
        assert_eq!(secure.state_chain.len(), 1);
    }

    #[tokio::test]
    async fn test_state_encryption_decryption() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        let state = json!({"secret": "confidential", "numbers": [1, 2, 3]});

        let secure = manager
            .create_secure_task(task, Some(&state))
            .await
            .unwrap();

        // Decrypt via resume
        let resume_req = TaskResumeRequest {
            task_id: "task-1".to_string(),
            resume_token: secure.resume_token.clone().unwrap(),
            nonce: hex::encode([1u8; 16]),
            agent_id: None,
        };

        let result = manager.resume_task(&resume_req).await.unwrap();
        assert!(result.authorized);
        assert_eq!(result.decrypted_state, Some(state));
    }

    #[tokio::test]
    async fn test_resume_with_invalid_token() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        let resume_req = TaskResumeRequest {
            task_id: "task-1".to_string(),
            resume_token: "invalid-token".to_string(),
            nonce: hex::encode([1u8; 16]),
            agent_id: None,
        };

        let result = manager.resume_task(&resume_req).await.unwrap();
        assert!(!result.authorized);
        assert!(result.denial_reason.is_some());
    }

    #[tokio::test]
    async fn test_replay_protection() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        let secure = manager.create_secure_task(task, None).await.unwrap();

        let nonce = hex::encode([42u8; 16]);
        let resume_req = TaskResumeRequest {
            task_id: "task-1".to_string(),
            resume_token: secure.resume_token.clone().unwrap(),
            nonce: nonce.clone(),
            agent_id: None,
        };

        // First request succeeds
        let result = manager.resume_task(&resume_req).await.unwrap();
        assert!(result.authorized);

        // Replay with same nonce fails
        let replay_result = manager.resume_task(&resume_req).await;
        assert!(matches!(
            replay_result,
            Err(TaskSecurityError::ReplayDetected)
        ));
    }

    #[tokio::test]
    async fn test_state_transition_chain() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        // Transition through states
        manager
            .update_status("task-1", TaskStatus::Running, Some("agent-1"))
            .await
            .unwrap();
        manager
            .update_status("task-1", TaskStatus::Completed, Some("agent-1"))
            .await
            .unwrap();

        let secure = manager.get_task("task-1").await.unwrap();
        assert_eq!(secure.state_chain.len(), 3);

        // Verify chain integrity
        let result = manager.verify_integrity("task-1").await.unwrap();
        assert!(result.valid);
        assert_eq!(result.transitions_verified, 3);
    }

    #[tokio::test]
    async fn test_checkpoint_creation_and_verification() {
        let (enc_key, hmac_key) = make_keys();
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        let manager = SecureTaskManager::new(enc_key, hmac_key)
            .unwrap()
            .with_signing_key(signing_key);

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        let checkpoint = manager.create_checkpoint("task-1").await.unwrap();
        assert!(!checkpoint.checkpoint_id.is_empty());
        assert!(!checkpoint.signature.is_empty());

        // Verify checkpoint
        let valid = manager.verify_checkpoint(&checkpoint).unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_tampered_checkpoint_fails_verification() {
        let (enc_key, hmac_key) = make_keys();
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        let manager = SecureTaskManager::new(enc_key, hmac_key)
            .unwrap()
            .with_signing_key(signing_key);

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        let mut checkpoint = manager.create_checkpoint("task-1").await.unwrap();

        // Tamper with the checkpoint
        checkpoint.sequence = 999;

        let valid = manager.verify_checkpoint(&checkpoint).unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_terminal_task_cannot_transition() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        manager
            .update_status("task-1", TaskStatus::Completed, None)
            .await
            .unwrap();

        // Trying to transition from terminal state fails
        let result = manager
            .update_status("task-1", TaskStatus::Running, None)
            .await;
        assert!(matches!(result, Err(TaskSecurityError::TaskTerminal)));
    }

    #[tokio::test]
    async fn test_stats() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task1 = make_task("task-1");
        let task2 = make_task("task-2");

        manager
            .create_secure_task(task1, Some(&json!({"data": 1})))
            .await
            .unwrap();
        manager.create_secure_task(task2, None).await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_tasks, 2);
        assert_eq!(stats.encrypted_tasks, 1);
        assert_eq!(stats.total_transitions, 2); // One initial transition each
    }

    #[tokio::test]
    async fn test_integrity_violation_detection() {
        let (enc_key, hmac_key) = make_keys();
        let manager = SecureTaskManager::new(enc_key, hmac_key).unwrap();

        let task = make_task("task-1");
        manager.create_secure_task(task, None).await.unwrap();

        // Manually tamper with the hash chain
        {
            let mut tasks = manager.tasks.write().await;
            let task = tasks.get_mut("task-1").unwrap();
            if let Some(transition) = task.state_chain.first_mut() {
                transition.hash = "tampered".to_string();
            }
        }

        let result = manager.verify_integrity("task-1").await.unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(0));
    }
}
