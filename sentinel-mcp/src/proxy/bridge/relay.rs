//! Bidirectional relay loop for `ProxyBridge`.
//!
//! Contains the `run()` method and its handler methods for each message type.
//! The relay sits between agent stdin/stdout and child MCP server,
//! evaluating every tool call, resource read, and task request against policies.

use super::ProxyBridge;
use super::ToolAnnotations;
use crate::extractor::{
    classify_message, extract_action, extract_resource_action, extract_task_action,
    make_batch_error_response, make_denial_response, make_invalid_response, MessageType,
};
use crate::framing::{read_message, write_message};
use crate::inspection::{
    scan_notification_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_injection, scan_response_for_secrets, scan_tool_descriptions,
    scan_tool_descriptions_with_scanner,
};
use crate::output_validation::ValidationResult;
use crate::proxy::types::{ProxyDecision, ProxyError};
use sentinel_config::ToolManifest;
use sentinel_types::{EvaluationContext, Verdict};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::process::{ChildStdin, ChildStdout};

/// SECURITY (R8-MCP-8): Maximum number of pending (in-flight) requests.
/// Prevents OOM if an agent sends requests faster than the server responds.
const MAX_PENDING_REQUESTS: usize = 1000;

/// Maximum action history entries for context-aware evaluation.
const MAX_ACTION_HISTORY: usize = 100;

/// Initial capacity for pending request tracking.
const INITIAL_PENDING_REQUEST_CAPACITY: usize = 256;

/// Initial capacity for tool state tracking.
const INITIAL_TOOL_STATE_CAPACITY: usize = 128;

/// Initial capacity for call count tracking.
const INITIAL_CALL_COUNTS_CAPACITY: usize = 128;

/// Bundled mutable I/O handles for the relay loop.
///
/// Groups agent-side and child-side writers to reduce handler argument counts.
struct IoWriters<'a> {
    agent: &'a mut tokio::io::Stdout,
    child: &'a mut ChildStdin,
}

/// Mutable session state for the relay loop.
///
/// Groups all per-session mutable variables that are threaded through
/// the handler methods during the bidirectional message relay.
struct RelayState {
    /// Pending request IDs for timeout detection and circuit breaker recording.
    /// Key: serialized JSON-RPC id, Value: (timestamp, tool_name).
    pending_requests: HashMap<String, (Instant, String)>,
    /// Track tools/list request IDs so we can intercept responses.
    tools_list_request_ids: HashSet<String>,
    /// Known tool annotations for rug-pull detection.
    known_tool_annotations: HashMap<String, ToolAnnotations>,
    /// Track initialize request IDs for protocol version negotiation.
    initialize_request_ids: HashSet<String>,
    /// Negotiated MCP protocol version.
    negotiated_protocol_version: Option<String>,
    /// Rug-pulled tools flagged for blocking.
    flagged_tools: HashSet<String>,
    /// Pinned tool manifest for schema verification.
    pinned_manifest: Option<ToolManifest>,
    /// Memory poisoning defense tracker.
    memory_tracker: crate::memory_tracking::MemoryTracker,
    /// Context-aware evaluation call counts.
    call_counts: HashMap<String, u64>,
    /// Context-aware evaluation action history.
    action_history: VecDeque<String>,
    /// Elicitation rate limiting counter (per session/proxy lifetime).
    elicitation_count: u32,
}

impl RelayState {
    fn new(flagged_tools: HashSet<String>) -> Self {
        Self {
            pending_requests: HashMap::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            tools_list_request_ids: HashSet::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            known_tool_annotations: HashMap::with_capacity(INITIAL_TOOL_STATE_CAPACITY),
            initialize_request_ids: HashSet::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            negotiated_protocol_version: None,
            flagged_tools,
            pinned_manifest: None,
            memory_tracker: crate::memory_tracking::MemoryTracker::new(),
            call_counts: HashMap::with_capacity(INITIAL_CALL_COUNTS_CAPACITY),
            action_history: VecDeque::with_capacity(MAX_ACTION_HISTORY),
            elicitation_count: 0,
        }
    }

    /// Build an EvaluationContext from the current session state.
    fn evaluation_context(&self) -> EvaluationContext {
        EvaluationContext {
            timestamp: None,
            agent_id: None,
            agent_identity: None,
            call_counts: self.call_counts.clone(),
            previous_actions: self.action_history.iter().cloned().collect(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
        }
    }

    /// Record a successful forward for context tracking.
    fn record_forwarded_action(&mut self, action_name: &str) {
        *self.call_counts.entry(action_name.to_string()).or_insert(0) += 1;
        if self.action_history.len() >= MAX_ACTION_HISTORY {
            self.action_history.pop_front();
        }
        self.action_history.push_back(action_name.to_string());
    }

    /// Track a pending request for timeout detection.
    fn track_pending_request(&mut self, id: &Value, tool_name: String) {
        if !id.is_null() {
            let id_key = id.to_string();
            if self.pending_requests.len() < MAX_PENDING_REQUESTS {
                self.pending_requests
                    .insert(id_key, (Instant::now(), tool_name));
            } else {
                tracing::warn!(
                    "Pending request limit reached ({}), not tracking request",
                    MAX_PENDING_REQUESTS
                );
            }
        }
    }
}

impl ProxyBridge {
    /// Run the bidirectional proxy loop.
    ///
    /// Reads messages from `agent_reader` (the agent's stdout, our stdin),
    /// evaluates tool calls, forwards allowed messages to `child_stdin`,
    /// and relays responses from `child_stdout` back to `agent_writer` (our stdout).
    ///
    /// Tracks forwarded request IDs and times them out if the child doesn't
    /// respond within `request_timeout`.
    pub async fn run(
        &self,
        agent_reader: tokio::io::Stdin,
        mut agent_writer: tokio::io::Stdout,
        mut child_stdin: ChildStdin,
        child_stdout: ChildStdout,
    ) -> Result<(), ProxyError> {
        let mut agent_reader = BufReader::new(agent_reader);
        let mut child_reader = BufReader::new(child_stdout);

        // Phase 4B: Load previously persisted flagged tools on startup.
        let mut state = RelayState::new(self.load_flagged_tools().await);
        let mut io = IoWriters {
            agent: &mut agent_writer,
            child: &mut child_stdin,
        };

        // Spawn a task to relay child → agent responses
        let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<Value>(256);

        let relay_handle = tokio::spawn(async move {
            loop {
                match read_message(&mut child_reader).await {
                    Ok(Some(msg)) => {
                        if response_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // Child closed stdout
                    Err(e) => {
                        tracing::error!("Error reading from child: {}", e);
                        break;
                    }
                }
            }
        });

        // Timer for periodic timeout sweeps
        let mut timeout_interval = tokio::time::interval(Duration::from_secs(5));
        timeout_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Main loop: read from agent, evaluate, forward or block
        loop {
            tokio::select! {
                // Message from agent
                agent_msg = read_message(&mut agent_reader) => {
                    match agent_msg {
                        Ok(Some(msg)) => {
                            self.handle_agent_message(
                                msg, &mut state, &mut io,
                            ).await?;
                        }
                        Ok(None) => {
                            tracing::info!("Agent closed connection");
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Error reading from agent: {}", e);
                            break;
                        }
                    }
                }
                // Response from child
                child_msg = response_rx.recv() => {
                    match child_msg {
                        Some(msg) => {
                            self.handle_child_response(
                                msg, &mut state, &mut io,
                            ).await?;
                        }
                        None => {
                            self.handle_child_terminated(
                                &mut state, io.agent,
                            ).await?;
                            break;
                        }
                    }
                }
                // Periodic timeout sweep
                _ = timeout_interval.tick() => {
                    self.sweep_timeouts(&mut state, io.agent).await;
                }
            }
        }

        relay_handle.abort();
        Ok(())
    }

    /// Handle a message received from the agent.
    async fn handle_agent_message(
        &self,
        msg: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        match classify_message(&msg) {
            MessageType::ToolCall {
                id,
                tool_name,
                arguments,
            } => {
                self.handle_tool_call(msg, id, tool_name, arguments, state, io)
                    .await
            }
            MessageType::ResourceRead { id, uri } => {
                self.handle_resource_read(msg, id, uri, state, io).await
            }
            MessageType::SamplingRequest { id } => {
                self.handle_sampling_request(&msg, id, io.agent).await
            }
            MessageType::ElicitationRequest { id } => {
                self.handle_elicitation_request(&msg, id, state, io.agent)
                    .await
            }
            MessageType::TaskRequest {
                id,
                task_method,
                task_id,
            } => {
                self.handle_task_request(msg, id, task_method, task_id, state, io)
                    .await
            }
            MessageType::Batch => {
                // MCP 2025-06-18: batching removed from spec.
                let response = make_batch_error_response();
                tracing::warn!("Rejected JSON-RPC batch request");
                write_message(io.agent, &response)
                    .await
                    .map_err(ProxyError::Framing)
            }
            MessageType::Invalid { id, reason } => {
                let response = make_invalid_response(&id, &reason);
                tracing::warn!("Invalid MCP request: {}", reason);
                write_message(io.agent, &response)
                    .await
                    .map_err(ProxyError::Framing)
            }
            MessageType::PassThrough => self.handle_passthrough(&msg, state, io).await,
        }
    }

    /// Handle a `tools/call` request from the agent.
    async fn handle_tool_call(
        &self,
        msg: Value,
        id: Value,
        tool_name: String,
        arguments: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // C-15 Exploit #9: Block calls to rug-pulled tools
        if state.flagged_tools.contains(&tool_name) {
            let action = extract_action(&tool_name, &arguments);
            let reason = format!(
                "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                tool_name
            );
            let verdict = Verdict::Deny {
                reason: reason.clone(),
            };
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({"source": "proxy", "tool": tool_name, "event": "rug_pull_tool_blocked"}),
                )
                .await
            {
                tracing::warn!("Failed to audit rug-pull block: {}", e);
            }
            let response = make_denial_response(&id, &reason);
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // ═══════════════════════════════════════════════════════════════════
        // Phase 3.1: Pre-evaluation security checks
        // ═══════════════════════════════════════════════════════════════════

        // Phase 3.1: Circuit breaker check (OWASP ASI08)
        if let Some(ref cb) = self.circuit_breaker {
            if let Err(reason) = cb.can_proceed(&tool_name) {
                tracing::warn!(
                    "SECURITY: Circuit breaker blocking tool '{}': {}",
                    tool_name,
                    reason
                );
                let action = extract_action(&tool_name, &arguments);
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "circuit_breaker_blocked",
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit circuit breaker block: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // Phase 3.1: Shadow agent detection
        if let Some(ref detector) = self.shadow_agent {
            let fingerprint = Self::extract_fingerprint_from_meta(&msg);
            if fingerprint.is_populated() {
                if let Some(claimed_id) = Self::extract_agent_id(&msg) {
                    if let Err(alert) = detector.detect_shadow(&claimed_id, &fingerprint) {
                        tracing::warn!(
                            "SECURITY: Shadow agent detected - claimed '{}' but fingerprint mismatch",
                            claimed_id
                        );
                        let action = extract_action(&tool_name, &arguments);
                        let reason = format!(
                            "Shadow agent detected: claimed identity '{}' does not match fingerprint",
                            claimed_id
                        );
                        let verdict = Verdict::Deny {
                            reason: reason.clone(),
                        };
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({
                                    "source": "proxy",
                                    "event": "shadow_agent_detected",
                                    "claimed_id": claimed_id,
                                    "expected_summary": alert.expected_fingerprint.summary(),
                                    "actual_summary": alert.actual_fingerprint.summary(),
                                    "severity": format!("{:?}", alert.severity),
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit shadow agent: {}", e);
                        }
                        let response = make_denial_response(&id, &reason);
                        write_message(agent_writer, &response)
                            .await
                            .map_err(ProxyError::Framing)?;
                        return Ok(());
                    }
                    // Ok(()) means no shadow detected - proceed
                }
            }
        }

        // Phase 3.1: Deputy validation (OWASP ASI02)
        if let Some(ref deputy) = self.deputy {
            let session_id = "stdio-session";
            if let Some(claimed_id) = Self::extract_agent_id(&msg) {
                if let Err(err) = deputy.validate_action(session_id, &tool_name, &claimed_id) {
                    let reason = err.to_string();
                    tracing::warn!(
                        "SECURITY: Deputy validation failed for '{}' -> '{}': {}",
                        claimed_id,
                        tool_name,
                        reason
                    );
                    let action = extract_action(&tool_name, &arguments);
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "deputy_validation_failed",
                                "session": session_id,
                                "principal": claimed_id,
                                "tool": tool_name,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit deputy validation: {}", e);
                    }
                    let response = make_denial_response(&id, &reason);
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // P2: DLP scan parameters for secret exfiltration.
        let dlp_findings = scan_parameters_for_secrets(&arguments);
        if !dlp_findings.is_empty() {
            tracing::warn!(
                "SECURITY: DLP alert for tool '{}': {:?}",
                tool_name,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let action = extract_action(&tool_name, &arguments);
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in parameters: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_secret_blocked",
                        "tool": tool_name,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit DLP finding: {}", e);
            }
            // SECURITY (R28-MCP-5): Generic error to agent — do not
            // leak which DLP patterns matched or their locations.
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // OWASP ASI06: Check for memory poisoning
        let poisoning_matches = state.memory_tracker.check_parameters(&arguments);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in tool call '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    tool_name,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_action(&tool_name, &arguments);
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                poisoning_matches.len(),
                tool_name
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "tool": tool_name,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    tool = %tool_name,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // Tool registry check
        if let Some(ref registry) = self.tool_registry {
            let trust = registry.check_trust_level(&tool_name).await;
            match trust {
                crate::tool_registry::TrustLevel::Unknown => {
                    registry.register_unknown(&tool_name).await;
                    let action = extract_action(&tool_name, &arguments);
                    let reason = format!(
                        "Tool '{}' is not in the registry — requires approval before use",
                        tool_name
                    );
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "proxy", "registry": "unknown_tool", "tool": tool_name}),
                        )
                        .await
                    {
                        tracing::error!("AUDIT FAILURE: {}", e);
                    }
                    let approval_id = if let Some(ref store) = self.approval_store {
                        store.create(action, reason.clone(), None).await.ok()
                    } else {
                        None
                    };
                    let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                    let response = make_denial_response(&id, &error_data.to_string());
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                crate::tool_registry::TrustLevel::Untrusted { score } => {
                    let action = extract_action(&tool_name, &arguments);
                    let reason = format!(
                        "Tool '{}' trust score ({:.2}) is below threshold — requires approval",
                        tool_name, score
                    );
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "proxy", "registry": "untrusted_tool", "tool": tool_name}),
                        )
                        .await
                    {
                        tracing::error!("AUDIT FAILURE: {}", e);
                    }
                    let approval_id = if let Some(ref store) = self.approval_store {
                        store.create(action, reason.clone(), None).await.ok()
                    } else {
                        None
                    };
                    let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                    let response = make_denial_response(&id, &error_data.to_string());
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                crate::tool_registry::TrustLevel::Trusted => {
                    // Trusted — proceed to engine evaluation
                }
            }
        }

        let ann = state.known_tool_annotations.get(&tool_name);
        let eval_ctx = state.evaluation_context();
        match self.evaluate_tool_call(&id, &tool_name, &arguments, ann, Some(&eval_ctx)) {
            ProxyDecision::Forward => {
                // Record tool call in registry on Allow
                if let Some(ref registry) = self.tool_registry {
                    registry.record_call(&tool_name).await;
                }
                state.record_forwarded_action(&tool_name);
                state.track_pending_request(&id, tool_name);
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            ProxyDecision::Block(mut response, verdict) => {
                let action = extract_action(&tool_name, &arguments);
                // If RequireApproval and we have an approval store,
                // create a pending approval and inject the ID into
                // the JSON-RPC error data.
                if let Verdict::RequireApproval { ref reason } = verdict {
                    if let Some(ref store) = self.approval_store {
                        match store.create(action.clone(), reason.clone(), None).await {
                            Ok(approval_id) => {
                                if let Some(data) =
                                    response.get_mut("error").and_then(|e| e.get_mut("data"))
                                {
                                    data["approval_id"] = Value::String(approval_id.clone());
                                }
                                tracing::info!(
                                    "Created pending approval {} for tool '{}'",
                                    approval_id,
                                    tool_name
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to create approval (fail-closed): {}", e);
                            }
                        }
                    }
                }
                let meta = Self::tool_call_audit_metadata(&tool_name, ann);
                if let Err(e) = self.audit.log_entry(&action, &verdict, meta).await {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a `resources/read` request from the agent.
    async fn handle_resource_read(
        &self,
        msg: Value,
        id: Value,
        uri: String,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // SECURITY: DLP scan the resource URI for embedded secrets.
        let uri_as_json = json!({"uri": uri});
        let dlp_findings = scan_parameters_for_secrets(&uri_as_json);
        if !dlp_findings.is_empty() {
            tracing::warn!(
                "SECURITY: DLP alert in resource URI '{}': {:?}",
                uri,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let action = extract_resource_action(&uri);
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in resource URI: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_resource_blocked",
                        "uri": uri,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit resource DLP: {}", e);
            }
            // SECURITY (R28-MCP-5): Generic error to agent.
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R37-MCP-1): Memory poisoning check for ResourceRead.
        let uri_params = json!({"uri": &uri});
        let poisoning_matches = state.memory_tracker.check_parameters(&uri_params);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in resource read '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    uri,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_resource_action(&uri);
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in resource read '{}'",
                poisoning_matches.len(),
                uri
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "uri": uri,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    uri = %uri,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        let eval_ctx = state.evaluation_context();
        match self.evaluate_resource_read(&id, &uri, Some(&eval_ctx)) {
            ProxyDecision::Forward => {
                // SECURITY (R38-MCP-2): Update call_counts and action_history for ResourceRead.
                state.record_forwarded_action("resources/read");
                state.track_pending_request(&id, "resources/read".to_string());
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            ProxyDecision::Block(mut response, verdict) => {
                let action = extract_resource_action(&uri);
                if let Verdict::RequireApproval { ref reason } = verdict {
                    if let Some(ref store) = self.approval_store {
                        match store.create(action.clone(), reason.clone(), None).await {
                            Ok(approval_id) => {
                                if let Some(data) =
                                    response.get_mut("error").and_then(|e| e.get_mut("data"))
                                {
                                    data["approval_id"] = Value::String(approval_id.clone());
                                }
                                tracing::info!(
                                    "Created pending approval {} for resource '{}'",
                                    approval_id,
                                    uri
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to create approval for resource: {}", e);
                            }
                        }
                    }
                }
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "proxy", "resource_uri": uri}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a `sampling/createMessage` request from the child server.
    async fn handle_sampling_request(
        &self,
        msg: &Value,
        id: Value,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let verdict = crate::elicitation::inspect_sampling(&params, &self.sampling_config);
        match verdict {
            crate::elicitation::SamplingVerdict::Allow => {
                write_message(agent_writer, msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            crate::elicitation::SamplingVerdict::Deny { reason } => {
                let response = make_denial_response(&id, &reason);
                let action = sentinel_types::Action::new(
                    "sentinel",
                    "sampling_blocked",
                    json!({"reason": &reason}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: reason.clone(),
                        },
                        json!({"source": "proxy", "event": "sampling_blocked"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                tracing::warn!("Blocked sampling/createMessage: {}", reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle an `elicitation/create` request from the child server.
    async fn handle_elicitation_request(
        &self,
        msg: &Value,
        id: Value,
        state: &mut RelayState,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let verdict = crate::elicitation::inspect_elicitation(
            &params,
            &self.elicitation_config,
            state.elicitation_count,
        );
        match verdict {
            crate::elicitation::ElicitationVerdict::Allow => {
                // SECURITY (R28-MCP-8): Saturating add prevents
                // panic from overflow-checks in release profile.
                state.elicitation_count = state.elicitation_count.saturating_add(1);
                write_message(agent_writer, msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            crate::elicitation::ElicitationVerdict::Deny { reason } => {
                let action = sentinel_types::Action::new(
                    "sentinel",
                    "elicitation_intercepted",
                    json!({"reason": &reason}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: reason.clone(),
                        },
                        json!({"source": "proxy", "event": "elicitation_intercepted"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                tracing::warn!("Blocked elicitation/create: {}", reason);
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a task request (`tasks/get`, `tasks/cancel`, etc.) from the agent.
    async fn handle_task_request(
        &self,
        msg: Value,
        id: Value,
        task_method: String,
        task_id: Option<String>,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        tracing::debug!("Task request: {} (task_id: {:?})", task_method, task_id);

        // R4-1: DLP scan task request parameters for secret exfiltration.
        let task_params = msg.get("params").cloned().unwrap_or(json!({}));
        let dlp_findings = scan_parameters_for_secrets(&task_params);
        if !dlp_findings.is_empty() {
            tracing::warn!(
                "SECURITY: DLP alert for task '{}': {:?}",
                task_method,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let dlp_action = extract_task_action(&task_method, task_id.as_deref());
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in task request: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &dlp_action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_secret_blocked_task",
                        "task_method": task_method,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit DLP finding: {}", e);
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R37-MCP-1): Memory poisoning check for TaskRequest.
        let poisoning_matches = state.memory_tracker.check_parameters(&task_params);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in task request '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    task_method,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_task_action(&task_method, task_id.as_deref());
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                poisoning_matches.len(),
                task_method
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "task_method": task_method,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    task_method = %task_method,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        let action = extract_task_action(&task_method, task_id.as_deref());
        let eval_ctx = state.evaluation_context();
        match self.evaluate_action_inner(&action, Some(&eval_ctx)) {
            Ok((Verdict::Allow, _trace)) => {
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "proxy",
                            "event": "task_request_forwarded",
                            "task_method": task_method,
                            "task_id": task_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                // SECURITY (R38-MCP-2): Update call_counts and action_history.
                state.record_forwarded_action(&task_method);
                state.track_pending_request(&id, task_method);
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Ok((verdict @ Verdict::Deny { .. }, _))
            | Ok((verdict @ Verdict::RequireApproval { .. }, _)) => {
                let reason = match &verdict {
                    Verdict::Deny { reason } => reason.clone(),
                    Verdict::RequireApproval { reason } => reason.clone(),
                    _ => unreachable!(),
                };
                let response = make_denial_response(&id, &reason);
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_denied",
                            "task_method": task_method,
                            "task_id": task_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_unknown_verdict",
                            "task_method": task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for task '{}': {}", task_method, e);
                let reason = "Policy evaluation failed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_eval_error",
                            "task_method": task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a passthrough message (not a tool call, resource read, or task request).
    async fn handle_passthrough(
        &self,
        msg: &Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // Track passthrough requests that have an id
        if let Some(id) = msg.get("id") {
            if !id.is_null() {
                // SECURITY (R33-MCP-1): Enforce MAX_PENDING_REQUESTS on PassThrough.
                if state.pending_requests.len() >= MAX_PENDING_REQUESTS {
                    let response = make_invalid_response(id, "Too many pending requests");
                    tracing::warn!("PassThrough request rejected: pending request limit reached");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                let id_key = id.to_string();
                let method = msg.get("method").and_then(|m| m.as_str());
                let method_name = method.unwrap_or("unknown").to_string();
                state
                    .pending_requests
                    .insert(id_key.clone(), (Instant::now(), method_name));
                // SECURITY (R29-MCP-1): Normalize method before tracking.
                let normalized_method = method.map(crate::extractor::normalize_method);

                // C-8.2: Track tools/list requests for annotation extraction
                if normalized_method.as_deref() == Some("tools/list") {
                    state.tools_list_request_ids.insert(id_key.clone());
                }

                // C-8.4: Track initialize requests for protocol version
                if normalized_method.as_deref() == Some("initialize") {
                    state.initialize_request_ids.insert(id_key);
                    if let Some(ver) = msg
                        .get("params")
                        .and_then(|p| p.get("protocolVersion"))
                        .and_then(|v| v.as_str())
                    {
                        tracing::info!("MCP initialize: client requested protocol version {}", ver);
                    }
                }
            }
        }
        // Non-tool-call messages pass through unmodified
        write_message(child_stdin, msg)
            .await
            .map_err(ProxyError::Framing)
    }

    /// Handle a response received from the child MCP server.
    async fn handle_child_response(
        &self,
        mut msg: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // C-8.5 / R8-MCP-1: Block ALL server-initiated requests.
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            // SECURITY (R23-MCP-3): Treat `"id": null` as a notification.
            let is_request = msg.get("id").is_some_and(|v| !v.is_null());
            if is_request {
                tracing::warn!(
                    "SECURITY: Server sent request '{}' — blocked (only notifications allowed from server)",
                    method
                );
                let action = sentinel_types::Action::new(
                    "sentinel",
                    "server_request_blocked",
                    json!({
                        "method": method,
                        "request_id": msg.get("id"),
                    }),
                );
                let verdict = Verdict::Deny {
                    reason: format!("Server-initiated request '{}' blocked by Sentinel", method),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "proxy", "event": "server_request_blocked"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit server request block: {}", e);
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32001,
                        "message": format!(
                            "{} blocked by Sentinel proxy — server-initiated requests not allowed",
                            method
                        )
                    }
                });
                write_message(child_stdin, &error_response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }

            // Notifications: forwarded through with DLP + injection scanning
            if self.response_dlp_enabled {
                let dlp_findings = scan_notification_for_secrets(&msg);
                if !dlp_findings.is_empty() {
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!("SECURITY: DLP alert in server notification: {:?}", patterns);
                    let action = sentinel_types::Action::new(
                        "sentinel",
                        "notification_dlp_secret_detected",
                        json!({
                            "findings": patterns,
                            "method": msg.get("method"),
                        }),
                    );
                    let verdict = if self.response_dlp_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "Notification blocked: secrets detected ({:?})",
                                patterns
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "notification_dlp_secret_detected",
                                "findings": patterns,
                                "blocked": self.response_dlp_blocking,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification DLP: {}", e);
                    }
                    if self.response_dlp_blocking {
                        return Ok(());
                    }
                }
            }

            // SECURITY (R21-MCP-1): Scan notification params for injection patterns.
            if !self.injection_disabled {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.injection_scanner {
                        scanner
                            .scan_notification(&msg)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        scan_notification_for_injection(&msg)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    };
                if !injection_matches.is_empty() {
                    tracing::warn!(
                        "SECURITY: Injection detected in server notification: {:?}",
                        injection_matches
                    );
                    let action = sentinel_types::Action::new(
                        "sentinel",
                        "notification_injection_detected",
                        json!({
                            "patterns": injection_matches,
                            "method": msg.get("method"),
                        }),
                    );
                    let verdict = if self.injection_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "Notification blocked: injection detected ({:?})",
                                injection_matches
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "notification_injection_detected",
                                "patterns": injection_matches,
                                "blocked": self.injection_blocking,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification injection: {}", e);
                    }
                    if self.injection_blocking {
                        return Ok(());
                    }
                }
            }

            // SECURITY (R38-MCP-1 + FIND-052): Fingerprint notification data.
            if let Some(method) = msg.get("method") {
                state.memory_tracker.extract_from_value(method);
            }
            if let Some(params) = msg.get("params") {
                state.memory_tracker.extract_from_value(params);
            }
        }

        // Remove from pending requests on response
        let mut response_tool_name: Option<String> = None;
        if let Some(id) = msg.get("id") {
            if !id.is_null() {
                let id_key = id.to_string();
                // Phase 3.1: Circuit breaker recording on response
                if let Some((_, tool_name)) = state.pending_requests.remove(&id_key) {
                    response_tool_name = Some(tool_name.clone());
                    if let Some(ref cb) = self.circuit_breaker {
                        if msg.get("error").is_some() {
                            cb.record_failure(&tool_name);
                        } else {
                            cb.record_success(&tool_name);
                        }
                    }
                }

                // C-8.2: If this is a tools/list response, extract annotations
                if state.tools_list_request_ids.remove(&id_key) {
                    self.handle_tools_list_response(&msg, state).await;
                }

                // C-8.4: If this is an initialize response, extract protocol version
                if state.initialize_request_ids.remove(&id_key) {
                    if let Some(ver) = msg
                        .get("result")
                        .and_then(|r| r.get("protocolVersion"))
                        .and_then(|v| v.as_str())
                    {
                        tracing::info!(
                            "MCP initialize: server negotiated protocol version {}",
                            ver
                        );
                        state.negotiated_protocol_version = Some(ver.to_string());
                        let action = sentinel_types::Action::new(
                            "sentinel",
                            "protocol_version",
                            json!({
                                "server_protocol_version": ver,
                                "server_name": msg.get("result")
                                    .and_then(|r| r.get("serverInfo"))
                                    .and_then(|s| s.get("name"))
                                    .and_then(|n| n.as_str()),
                                "server_version": msg.get("result")
                                    .and_then(|r| r.get("serverInfo"))
                                    .and_then(|s| s.get("version"))
                                    .and_then(|v| v.as_str()),
                                "capabilities": msg.get("result")
                                    .and_then(|r| r.get("capabilities")),
                            }),
                        );
                        let verdict = Verdict::Allow;
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({"source": "proxy", "event": "protocol_negotiation"}),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit protocol version: {}", e);
                        }
                    }
                }
            }
        }

        // C-8.3: Inspect response for prompt injection (OWASP MCP06)
        let injection_matches: Vec<String> = if self.injection_disabled {
            Vec::new()
        } else if let Some(ref scanner) = self.injection_scanner {
            scanner
                .scan_response(&msg)
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            scan_response_for_injection(&msg)
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        };
        if !injection_matches.is_empty() {
            tracing::warn!(
                "SECURITY: Potential prompt injection in tool response! \
                 Matched patterns: {:?}",
                injection_matches
            );
            let (verdict, should_block) = if self.injection_blocking {
                (
                    Verdict::Deny {
                        reason: format!(
                            "Response blocked: prompt injection detected ({})",
                            injection_matches.join(", ")
                        ),
                    },
                    true,
                )
            } else {
                (Verdict::Allow, false)
            };
            let action = sentinel_types::Action::new(
                "sentinel",
                "response_inspection",
                json!({
                    "matched_patterns": injection_matches,
                    "response_id": msg.get("id"),
                    "blocked": should_block,
                }),
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({
                        "source": "proxy",
                        "event": "prompt_injection_detected",
                        "patterns": injection_matches,
                        "protocol_version": state.negotiated_protocol_version,
                        "blocked": should_block,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit injection detection: {}", e);
            }

            if should_block {
                let blocked_response = json!({
                    "jsonrpc": "2.0",
                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32005,
                        "message": "Response blocked: prompt injection detected"
                    }
                });
                write_message(agent_writer, &blocked_response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // MCP 2025-06-18: Validate structuredContent against output schemas
        if let Some(result) = msg.get("result") {
            if let Some(structured) = result.get("structuredContent") {
                if let Some(tool_name) = response_tool_name.as_deref() {
                    match self.output_schema_registry.validate(tool_name, structured) {
                        ValidationResult::Valid => {
                            tracing::debug!("structuredContent validated for tool '{}'", tool_name);
                        }
                        ValidationResult::NoSchema => {
                            if self.output_schema_blocking {
                                tracing::warn!(
                                    "SECURITY: No output schema registered for tool '{}' \
                                     while output_schema_blocking=true; blocking response",
                                    tool_name
                                );
                                let action = sentinel_types::Action::new(
                                    "sentinel",
                                    "output_schema_violation",
                                    json!({
                                        "tool": tool_name,
                                        "violations": ["no output schema registered for tool"],
                                        "response_id": msg.get("id"),
                                    }),
                                );
                                if let Err(e) = self
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: format!(
                                                "structuredContent schema validation blocked: no schema registered for tool '{}'",
                                                tool_name
                                            ),
                                        },
                                        json!({"source": "proxy", "event": "output_schema_violation"}),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit output schema missing-schema violation: {}",
                                        e
                                    );
                                }

                                let blocked_response = json!({
                                    "jsonrpc": "2.0",
                                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                                    "error": {
                                        "code": -32005,
                                        "message": "Response blocked: no output schema registered for structuredContent validation"
                                    }
                                });
                                write_message(agent_writer, &blocked_response)
                                    .await
                                    .map_err(ProxyError::Framing)?;
                                return Ok(());
                            } else {
                                tracing::debug!(
                                    "No output schema registered for tool '{}', skipping validation",
                                    tool_name
                                );
                            }
                        }
                        ValidationResult::Invalid { violations } => {
                            tracing::warn!(
                                "SECURITY: structuredContent validation failed for tool '{}': {:?}",
                                tool_name,
                                violations
                            );
                            let action = sentinel_types::Action::new(
                                "sentinel",
                                "output_schema_violation",
                                json!({
                                    "tool": tool_name,
                                    "violations": violations,
                                    "response_id": msg.get("id"),
                                }),
                            );
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "structuredContent validation failed: {:?}",
                                            violations
                                        ),
                                    },
                                    json!({"source": "proxy", "event": "output_schema_violation"}),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit output schema violation: {}", e);
                            }

                            if self.output_schema_blocking {
                                let blocked_response = json!({
                                    "jsonrpc": "2.0",
                                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                                    "error": {
                                        "code": -32005,
                                        "message": "Response blocked: structuredContent schema validation failed"
                                    }
                                });
                                write_message(agent_writer, &blocked_response)
                                    .await
                                    .map_err(ProxyError::Framing)?;
                                return Ok(());
                            }
                        }
                    }
                } else if self.output_schema_blocking {
                    tracing::warn!(
                        "SECURITY: structuredContent present but tool context unavailable \
                         while output_schema_blocking=true; blocking response"
                    );
                    let action = sentinel_types::Action::new(
                        "sentinel",
                        "output_schema_violation",
                        json!({
                            "tool": Value::Null,
                            "violations": ["tool context unavailable for structuredContent schema validation"],
                            "response_id": msg.get("id"),
                        }),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: "structuredContent schema validation blocked: tool context unavailable".to_string(),
                            },
                            json!({"source": "proxy", "event": "output_schema_violation"}),
                        )
                        .await
                    {
                        tracing::warn!(
                            "Failed to audit output schema context violation: {}",
                            e
                        );
                    }

                    let blocked_response = json!({
                        "jsonrpc": "2.0",
                        "id": msg.get("id").cloned().unwrap_or(Value::Null),
                        "error": {
                            "code": -32005,
                            "message": "Response blocked: structuredContent schema validation unavailable (missing tool context)"
                        }
                    });
                    write_message(agent_writer, &blocked_response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                } else {
                    tracing::debug!(
                        "structuredContent present but tool context unavailable; skipping schema validation"
                    );
                }
            }
        }

        // DLP response scanning: detect secrets in tool response content
        if self.response_dlp_enabled {
            let dlp_findings = scan_response_for_secrets(&msg);
            if !dlp_findings.is_empty() {
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                tracing::warn!("SECURITY: DLP alert in tool response: {:?}", patterns);
                let action = sentinel_types::Action::new(
                    "sentinel",
                    "response_dlp_secret_detected",
                    json!({
                        "findings": patterns,
                        "response_id": msg.get("id"),
                    }),
                );
                let verdict = if self.response_dlp_blocking {
                    Verdict::Deny {
                        reason: format!("Response blocked: secrets detected ({:?})", patterns),
                    }
                } else {
                    Verdict::Allow // Log-only
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "response_dlp_secret_detected",
                            "findings": patterns,
                            "blocked": self.response_dlp_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit response DLP finding: {}", e);
                }

                if self.response_dlp_blocking {
                    let blocked_response = json!({
                        "jsonrpc": "2.0",
                        "id": msg.get("id").cloned().unwrap_or(Value::Null),
                        "error": {
                            "code": -32006,
                            "message": "Response blocked: secrets detected in tool output"
                        }
                    });
                    write_message(agent_writer, &blocked_response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // OWASP ASI06: Record response data for poisoning detection
        state.memory_tracker.record_response(&msg);

        // Phase 19: Art 50(1) transparency marking
        if self.transparency_marking {
            crate::transparency::mark_ai_mediated(&mut msg);
        }

        // Phase 19: Art 14 human oversight audit event
        if let Some(tool_name) = msg
            .get("id")
            .and_then(|id| {
                let id_str = match id {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => return None,
                };
                state
                    .pending_requests
                    .get(&id_str)
                    .map(|(_, name)| name.clone())
            })
        {
            if crate::transparency::requires_human_oversight(
                &tool_name,
                &self.human_oversight_tools,
            ) {
                let oversight_action = sentinel_types::Action::new(
                    "sentinel",
                    "human_oversight_triggered",
                    json!({"tool": tool_name}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &oversight_action,
                        &Verdict::Allow,
                        json!({
                            "source": "proxy",
                            "event": "human_oversight_triggered",
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit human oversight event: {}", e);
                }
            }
        }

        // Relay child response to agent
        write_message(agent_writer, &msg)
            .await
            .map_err(ProxyError::Framing)
    }

    /// Handle tools/list response processing.
    ///
    /// Extracts tool annotations, detects rug-pulls, scans descriptions for
    /// injection, verifies manifests, registers output schemas, and detects
    /// schema poisoning.
    async fn handle_tools_list_response(&self, msg: &Value, state: &mut RelayState) {
        // Phase 4B: Snapshot flagged tools before detection to identify new ones
        let flagged_before: HashSet<String> = state.flagged_tools.clone();

        Self::extract_tool_annotations(
            msg,
            &mut state.known_tool_annotations,
            &mut state.flagged_tools,
            &self.audit,
            &self.known_tools,
        )
        .await;

        // Phase 4B: Persist any newly flagged tools
        for name in state.flagged_tools.difference(&flagged_before) {
            let reason = "annotation_change_or_new_tool";
            self.persist_flagged_tool(name, reason).await;
        }

        // P2: Scan tool descriptions for embedded injection
        if !self.injection_disabled {
            let desc_findings = if let Some(ref scanner) = self.injection_scanner {
                scan_tool_descriptions_with_scanner(msg, scanner)
            } else {
                scan_tool_descriptions(msg)
            };
            for finding in &desc_findings {
                tracing::warn!(
                    "SECURITY: Injection detected in tool '{}' description! Patterns: {:?}",
                    finding.tool_name,
                    finding.matched_patterns
                );
                let action = sentinel_types::Action::new(
                    "sentinel",
                    "tool_description_injection",
                    json!({
                        "tool": finding.tool_name,
                        "matched_patterns": finding.matched_patterns,
                    }),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: format!(
                                "Tool '{}' description contains injection patterns: {:?}",
                                finding.tool_name, finding.matched_patterns
                            ),
                        },
                        json!({"source": "proxy", "event": "tool_description_injection"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit tool description injection: {}", e);
                }
                // SECURITY (R29-MCP-2): Flag tools with injection in descriptions.
                state.flagged_tools.insert(finding.tool_name.clone());
                self.persist_flagged_tool(&finding.tool_name, "description_injection")
                    .await;
            }
        }

        // Phase 5: Manifest verification on tools/list responses
        if let Some(ref manifest_cfg) = self.manifest_config {
            if manifest_cfg.enabled {
                match &state.pinned_manifest {
                    None => {
                        if let Some(m) = ToolManifest::from_tools_list(msg) {
                            tracing::info!("Pinned tool manifest: {} tools", m.tools.len());
                            state.pinned_manifest = Some(m);
                        }
                    }
                    Some(pinned) => {
                        if let Err(discrepancies) = manifest_cfg.verify_manifest(pinned, msg) {
                            tracing::warn!(
                                "SECURITY: Tool manifest verification FAILED: {:?}",
                                discrepancies
                            );
                            let action = sentinel_types::Action::new(
                                "sentinel",
                                "manifest_verification",
                                json!({
                                    "discrepancies": discrepancies,
                                    "pinned_tool_count": pinned.tools.len(),
                                }),
                            );
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "Manifest verification failed: {:?}",
                                            discrepancies
                                        ),
                                    },
                                    json!({"source": "proxy", "event": "manifest_verification_failed"}),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit manifest failure: {}", e);
                            }
                        }
                    }
                }
            }
        }

        // MCP 2025-06-18: Register output schemas for structuredContent validation
        self.output_schema_registry.register_from_tools_list(msg);
        tracing::debug!(
            "Output schema registry: {} schemas registered",
            self.output_schema_registry.len()
        );

        // Phase 3.1: Schema poisoning detection (OWASP ASI05)
        if let Some(ref tracker) = self.schema_lineage {
            if let Some(tools) = msg
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
            {
                for tool in tools {
                    if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                        let schema = tool.get("inputSchema").cloned().unwrap_or(json!({}));
                        match tracker.observe_schema(name, &schema) {
                            crate::schema_poisoning::ObservationResult::MajorChange {
                                similarity,
                                alert,
                            } => {
                                tracing::warn!(
                                    "SECURITY: Schema poisoning detected for tool '{}': similarity={:.2}",
                                    name, similarity
                                );
                                let action = sentinel_types::Action::new(
                                    "sentinel",
                                    "schema_poisoning_detected",
                                    json!({
                                        "tool": name,
                                        "similarity": similarity,
                                        "alert": format!("{:?}", alert),
                                    }),
                                );
                                if let Err(e) = self
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: format!(
                                                "Schema poisoning detected: tool '{}' schema changed (similarity={:.2})",
                                                name, similarity
                                            ),
                                        },
                                        json!({
                                            "source": "proxy",
                                            "event": "schema_poisoning_detected",
                                            "tool": name,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit schema poisoning: {}", e);
                                }
                                state.flagged_tools.insert(name.to_string());
                                self.persist_flagged_tool(name, "schema_poisoning").await;
                            }
                            crate::schema_poisoning::ObservationResult::MinorChange {
                                similarity,
                            } => {
                                tracing::debug!(
                                    "Schema minor change for tool '{}': similarity={:.2}",
                                    name,
                                    similarity
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Handle child process termination, flushing pending requests with errors.
    async fn handle_child_terminated(
        &self,
        state: &mut RelayState,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        if !state.pending_requests.is_empty() {
            tracing::error!(
                "Child MCP server terminated with {} pending requests",
                state.pending_requests.len()
            );
            let crash_ids: Vec<String> = state.pending_requests.keys().cloned().collect();
            let pending_count = crash_ids.len();
            for id_key in &crash_ids {
                // Phase 3.1: Circuit breaker - record crash as failure
                if let Some((_, tool_name)) = state.pending_requests.remove(id_key) {
                    if let Some(ref cb) = self.circuit_breaker {
                        cb.record_failure(&tool_name);
                    }
                }
                let id: Value = serde_json::from_str(id_key).unwrap_or(Value::Null);
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32003,
                        "message": "Child MCP server terminated unexpectedly"
                    }
                });
                if let Err(e) = write_message(agent_writer, &response).await {
                    tracing::error!("Failed to send crash response: {}", e);
                }
            }
            let action = sentinel_types::Action::new("sentinel", "child_crash", json!({}));
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "Child MCP server terminated unexpectedly".to_string(),
                    },
                    json!({"source": "proxy", "event": "child_crash", "pending_requests": pending_count}),
                )
                .await
            {
                tracing::warn!("Failed to audit child crash: {}", e);
            }
        } else {
            tracing::info!("Child process closed");
        }
        Ok(())
    }

    /// Sweep timed-out pending requests and send error responses.
    async fn sweep_timeouts(&self, state: &mut RelayState, agent_writer: &mut tokio::io::Stdout) {
        let now = Instant::now();
        let timed_out: Vec<String> = state
            .pending_requests
            .iter()
            .filter(|(_, (sent_at, _))| now.duration_since(*sent_at) > self.request_timeout)
            .map(|(id_key, _)| id_key.clone())
            .collect();

        for id_key in timed_out {
            // Phase 3.1: Circuit breaker - record timeout as failure
            if let Some((_, tool_name)) = state.pending_requests.remove(&id_key) {
                if let Some(ref cb) = self.circuit_breaker {
                    cb.record_failure(&tool_name);
                }
            }
            let id: Value = serde_json::from_str(&id_key).unwrap_or(Value::Null);
            tracing::warn!("Request timed out: id={}", id_key);
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32003,
                    "message": "Request timed out: child MCP server did not respond"
                }
            });
            if let Err(e) = write_message(agent_writer, &response).await {
                tracing::error!("Failed to send timeout response: {}", e);
            }
        }
    }
}
