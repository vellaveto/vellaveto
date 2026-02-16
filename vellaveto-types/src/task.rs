//! MCP 2025-11-25 compliance types and Phase 11 secure task primitives.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Status of an async MCP task for lifecycle tracking.
///
/// MCP 2025-11-25 introduces async tasks that run in the background.
/// This enum tracks the current state for policy enforcement and audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task has been accepted but not yet started.
    #[default]
    Pending,
    /// Task is currently executing.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed { reason: String },
    /// Task was cancelled by request.
    Cancelled,
    /// Task expired due to timeout.
    Expired,
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed { reason } => write!(f, "failed: {reason}"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
            TaskStatus::Expired => write!(f, "expired"),
        }
    }
}

/// A tracked async MCP task for lifecycle management.
///
/// Vellaveto tracks task state to enforce policies on:
/// - Maximum concurrent tasks per session/agent
/// - Task duration limits
/// - Cancellation authorization (self-cancel only vs. any agent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackedTask {
    /// Unique task identifier from the MCP server.
    pub task_id: String,
    /// Tool that created this task.
    pub tool: String,
    /// Function that created this task.
    pub function: String,
    /// Current task status.
    pub status: TaskStatus,
    /// ISO 8601 timestamp when the task was created.
    pub created_at: String,
    /// ISO 8601 timestamp when the task expires (if set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Agent ID that created this task (for cancellation authorization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Session ID this task belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl TrackedTask {
    /// Returns true if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed
                | TaskStatus::Failed { .. }
                | TaskStatus::Cancelled
                | TaskStatus::Expired
        )
    }

    /// Returns true if the task is active (pending or running).
    pub fn is_active(&self) -> bool {
        matches!(self.status, TaskStatus::Pending | TaskStatus::Running)
    }
}

/// A state transition in a task's hash chain for tamper detection.
///
/// Each transition records the previous hash, new state, and produces
/// a new hash, forming an append-only chain that detects tampering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStateTransition {
    /// Sequence number in the hash chain (0-indexed).
    pub sequence: u64,
    /// SHA-256 hash of the previous transition (empty string for first).
    pub prev_hash: String,
    /// The new task status after this transition.
    pub new_status: TaskStatus,
    /// ISO 8601 timestamp of this transition.
    pub timestamp: String,
    /// Agent ID that triggered this transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// `SHA-256` hash of this transition (computed from `prev_hash` + `new_status` + timestamp).
    pub hash: String,
}

/// A secure task with encryption and integrity protection.
///
/// Extends `TrackedTask` with:
/// - Encrypted state data (`ChaCha20-Poly1305`)
/// - Hash chain for tamper detection
/// - Resume token for authenticated task resumption
/// - Replay protection via nonces
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecureTask {
    /// The underlying tracked task.
    pub task: TrackedTask,
    /// Encrypted task state/result data (base64-encoded ciphertext).
    /// Only present when task has state to protect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_state: Option<String>,
    /// Nonce used for encryption (base64-encoded, 12 bytes for ChaCha20-Poly1305).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_nonce: Option<String>,
    /// Hash chain of state transitions for tamper detection.
    #[serde(default)]
    pub state_chain: Vec<TaskStateTransition>,
    /// HMAC-SHA256 resume token (hex-encoded) for authenticated resumption.
    /// Generated on task creation, verified on resume requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Nonces seen for replay protection (hex-encoded).
    /// Prevents replaying old task resume/cancel requests.
    #[serde(default)]
    pub seen_nonces: Vec<String>,
    /// Maximum number of nonces to track (FIFO eviction).
    /// Capped at `MAX_NONCES_CAP` (10,000) to prevent memory exhaustion.
    #[serde(default = "default_max_nonces", deserialize_with = "deserialize_capped_max_nonces")]
    pub max_nonces: usize,
}

/// Absolute upper bound for `max_nonces` to prevent memory exhaustion.
pub const MAX_NONCES_CAP: usize = 10_000;

fn default_max_nonces() -> usize {
    1000
}

fn deserialize_capped_max_nonces<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = usize::deserialize(deserializer)?;
    Ok(value.min(MAX_NONCES_CAP))
}

impl SecureTask {
    /// Create a new secure task from a tracked task.
    pub fn new(task: TrackedTask) -> Self {
        Self {
            task,
            encrypted_state: None,
            encryption_nonce: None,
            state_chain: Vec::new(),
            resume_token: None,
            seen_nonces: Vec::new(),
            max_nonces: default_max_nonces(),
        }
    }

    /// Check if a nonce has been seen (replay detection).
    pub fn is_nonce_seen(&self, nonce: &str) -> bool {
        self.seen_nonces.iter().any(|n| n == nonce)
    }

    /// Record a nonce as seen.
    /// Enforces `MAX_NONCES_CAP` regardless of `max_nonces` field value.
    pub fn record_nonce(&mut self, nonce: String) {
        let effective_max = self.max_nonces.min(MAX_NONCES_CAP);
        if self.seen_nonces.len() >= effective_max {
            self.seen_nonces.remove(0); // FIFO eviction
        }
        self.seen_nonces.push(nonce);
    }

    /// Get the latest hash in the state chain.
    pub fn latest_hash(&self) -> Option<&str> {
        self.state_chain.last().map(|t| t.hash.as_str())
    }

    /// Get the current sequence number.
    pub fn current_sequence(&self) -> u64 {
        self.state_chain.last().map_or(0, |t| t.sequence)
    }
}

/// A checkpoint of task state for verification.
///
/// Checkpoints are signed snapshots that can be used to verify
/// task state integrity at a specific point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskCheckpoint {
    /// Unique checkpoint identifier.
    pub checkpoint_id: String,
    /// Task ID this checkpoint belongs to.
    pub task_id: String,
    /// Sequence number in the state chain at checkpoint time.
    pub sequence: u64,
    /// Hash of the state chain at checkpoint time.
    pub state_hash: String,
    /// ISO 8601 timestamp of checkpoint creation.
    pub created_at: String,
    /// Ed25519 signature of the checkpoint (hex-encoded).
    pub signature: String,
    /// Public key used to sign (hex-encoded).
    pub public_key: String,
}

/// Request to resume a task with authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResumeRequest {
    /// Task ID to resume.
    pub task_id: String,
    /// Resume token for authentication.
    pub resume_token: String,
    /// Unique nonce for replay protection (hex-encoded).
    pub nonce: String,
    /// Agent ID requesting the resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// Result of a task resume attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResumeResult {
    /// Whether the resume was authorized.
    pub authorized: bool,
    /// The task if authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<SecureTask>,
    /// Decrypted state data if authorized and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypted_state: Option<serde_json::Value>,
    /// Reason for denial if not authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

/// Result of validating a task's state chain integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskIntegrityResult {
    /// Whether the state chain is valid.
    pub valid: bool,
    /// Number of transitions verified.
    pub transitions_verified: u64,
    /// First broken transition index if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_broken_at: Option<u64>,
    /// Reason for failure if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Statistics about secure task management.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecureTaskStats {
    /// Total secure tasks tracked.
    pub total_tasks: usize,
    /// Tasks with encrypted state.
    pub encrypted_tasks: usize,
    /// Total state transitions recorded.
    pub total_transitions: u64,
    /// Checkpoints created.
    pub checkpoints_created: u64,
    /// Resume attempts.
    pub resume_attempts: u64,
    /// Successful resumes.
    pub resume_successes: u64,
    /// Replay attacks blocked.
    pub replay_attacks_blocked: u64,
    /// Integrity violations detected.
    pub integrity_violations: u64,
}
