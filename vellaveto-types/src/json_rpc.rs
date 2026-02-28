// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! JSON-RPC 2.0 error codes for Vellaveto.
//!
//! This module provides constants for standard JSON-RPC 2.0 error codes
//! and Vellaveto-specific application error codes in the reserved range.
//!
//! # JSON-RPC 2.0 Error Code Ranges
//!
//! - `-32700`: Parse error (invalid JSON)
//! - `-32600`: Invalid Request (not a valid JSON-RPC request)
//! - `-32601`: Method not found
//! - `-32602`: Invalid params
//! - `-32603`: Internal error
//! - `-32000` to `-32099`: Server errors (reserved for implementation-defined errors)
//!
//! Vellaveto uses the reserved range for security-specific error conditions.

// ═══════════════════════════════════════════════════════════════════════════════
// Standard JSON-RPC 2.0 Error Codes
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse error: Invalid JSON was received by the server.
pub const PARSE_ERROR: i64 = -32700;

/// Invalid Request: The JSON sent is not a valid Request object.
pub const INVALID_REQUEST: i64 = -32600;

/// Method not found: The method does not exist or is not available.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Invalid params: Invalid method parameter(s).
pub const INVALID_PARAMS: i64 = -32602;

/// Internal error: Internal JSON-RPC error.
pub const INTERNAL_ERROR: i64 = -32603;

// ═══════════════════════════════════════════════════════════════════════════════
// Vellaveto Application Error Codes (-32000 to -32099)
// ═══════════════════════════════════════════════════════════════════════════════

/// Generic server error (tool execution failure, upstream error).
pub const SERVER_ERROR: i64 = -32000;

/// Policy denial: The action was denied by security policy.
///
/// Also used for:
/// - Session ownership violations
/// - Authentication required (when no credentials provided)
pub const POLICY_DENIED: i64 = -32001;

/// Approval required: The action requires human-in-the-loop approval.
///
/// Also used for authentication failures when credentials are invalid.
pub const APPROVAL_REQUIRED: i64 = -32002;

/// Validation error: Request failed DLP or output validation checks.
pub const VALIDATION_ERROR: i64 = -32003;

/// Task not found: The specified task ID does not exist.
pub const TASK_NOT_FOUND: i64 = -32004;

/// Task operation not allowed: The requested task operation is forbidden.
pub const TASK_OPERATION_NOT_ALLOWED: i64 = -32005;

/// Message too large: The request exceeds size limits.
pub const MESSAGE_TOO_LARGE: i64 = -32006;

/// Timeout: The operation timed out.
pub const TIMEOUT: i64 = -32007;

/// Injection detected: Prompt injection or command injection detected.
pub const INJECTION_DETECTED: i64 = -32008;

/// DLP violation: Sensitive data detected in request/response.
pub const DLP_VIOLATION: i64 = -32009;

/// Batch not allowed: JSON-RPC batch requests are not permitted.
pub const BATCH_NOT_ALLOWED: i64 = -32010;

/// Circuit breaker open: Too many recent failures, requests are blocked.
pub const CIRCUIT_BREAKER_OPEN: i64 = -32011;

/// Shadow agent detected: Potential impersonation or privilege escalation.
pub const SHADOW_AGENT_DETECTED: i64 = -32012;

/// Agent card not found: The requested A2A agent card is not available.
pub const AGENT_CARD_NOT_FOUND: i64 = -32020;

/// Agent card invalid: The A2A agent card is malformed or untrusted.
pub const AGENT_CARD_INVALID: i64 = -32021;

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_i64(value: i64) -> i64 {
        // Keep this check runtime so clippy doesn't treat assertions as constants.
        std::hint::black_box(value)
    }

    #[test]
    fn test_standard_codes_in_spec_range() {
        // Standard codes are -32700, -32600 to -32603
        assert_eq!(runtime_i64(PARSE_ERROR), -32700);

        let standard_codes = [
            runtime_i64(INVALID_REQUEST),
            runtime_i64(METHOD_NOT_FOUND),
            runtime_i64(INVALID_PARAMS),
            runtime_i64(INTERNAL_ERROR),
        ];
        for code in standard_codes {
            assert!(
                (-32700..=-32600).contains(&code),
                "Standard code {} is outside -32700..=-32600",
                code
            );
        }
    }

    #[test]
    fn test_application_codes_in_reserved_range() {
        // Application codes must be -32000 to -32099
        let codes = [
            SERVER_ERROR,
            POLICY_DENIED,
            APPROVAL_REQUIRED,
            VALIDATION_ERROR,
            TASK_NOT_FOUND,
            TASK_OPERATION_NOT_ALLOWED,
            MESSAGE_TOO_LARGE,
            TIMEOUT,
            INJECTION_DETECTED,
            DLP_VIOLATION,
            BATCH_NOT_ALLOWED,
            CIRCUIT_BREAKER_OPEN,
            SHADOW_AGENT_DETECTED,
            AGENT_CARD_NOT_FOUND,
            AGENT_CARD_INVALID,
        ];

        for code in codes {
            let code = runtime_i64(code);
            assert!(
                (-32099..=-32000).contains(&code),
                "Code {} is outside reserved range -32099 to -32000",
                code
            );
        }
    }

    #[test]
    fn test_no_duplicate_codes() {
        let codes = [
            PARSE_ERROR,
            INVALID_REQUEST,
            METHOD_NOT_FOUND,
            INVALID_PARAMS,
            INTERNAL_ERROR,
            SERVER_ERROR,
            POLICY_DENIED,
            APPROVAL_REQUIRED,
            VALIDATION_ERROR,
            TASK_NOT_FOUND,
            TASK_OPERATION_NOT_ALLOWED,
            MESSAGE_TOO_LARGE,
            TIMEOUT,
            INJECTION_DETECTED,
            DLP_VIOLATION,
            BATCH_NOT_ALLOWED,
            CIRCUIT_BREAKER_OPEN,
            SHADOW_AGENT_DETECTED,
            AGENT_CARD_NOT_FOUND,
            AGENT_CARD_INVALID,
        ];

        let mut seen = std::collections::HashSet::new();
        for code in codes {
            assert!(seen.insert(code), "Duplicate error code: {}", code);
        }
    }
}
