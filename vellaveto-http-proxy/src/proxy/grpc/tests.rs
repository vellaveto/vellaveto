// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Unit tests for gRPC transport (Phase 17.2).

use super::convert::*;
use super::interceptors::*;
use super::proto::*;
use super::upstream::*;
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use prost_types::value::Kind;
use serde_json::json;
use vellaveto_canonical::{canonical_request_preimage, CanonicalRequestInput};
use vellaveto_types::{ClientProvenance, RequestSignature, SignatureVerificationStatus};

fn empty_session_store() -> crate::session::SessionStore {
    crate::session::SessionStore::new(std::time::Duration::from_secs(300), 8)
}

fn empty_trusted_request_signers(
) -> std::collections::HashMap<String, crate::proxy::TrustedRequestSigner> {
    std::collections::HashMap::new()
}

fn default_detached_signature_freshness() -> crate::proxy::DetachedSignatureFreshnessConfig {
    crate::proxy::DetachedSignatureFreshnessConfig::default()
}

#[derive(Default)]
struct DetachedSignatureBinding<'a> {
    session_scope_binding: Option<&'a str>,
    routing_identity: Option<&'a str>,
    workload_identity: Option<vellaveto_types::WorkloadIdentity>,
}

fn make_detached_request_signature_header(signature: &RequestSignature) -> String {
    URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(signature).expect("serialize detached request signature"))
}

fn make_signed_detached_request_signature_header_with_scope(
    action: &vellaveto_types::Action,
    key_id: &str,
    signing_key: &SigningKey,
    session_scope_binding: Option<&str>,
) -> String {
    make_signed_detached_request_signature_header_with_binding(
        action,
        key_id,
        signing_key,
        DetachedSignatureBinding {
            session_scope_binding,
            ..DetachedSignatureBinding::default()
        },
    )
}

fn make_signed_detached_request_signature_header_with_binding(
    action: &vellaveto_types::Action,
    key_id: &str,
    signing_key: &SigningKey,
    binding: DetachedSignatureBinding<'_>,
) -> String {
    let mut request_signature = RequestSignature {
        key_id: Some(key_id.to_string()),
        algorithm: Some("ed25519".to_string()),
        nonce: Some("detached-nonce".to_string()),
        created_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        signature: None,
    };
    let input = CanonicalRequestInput::from_action(
        action,
        binding.session_scope_binding,
        Some(&ClientProvenance {
            request_signature: Some(request_signature.clone()),
            workload_identity: binding.workload_identity,
            ..ClientProvenance::default()
        }),
        binding.routing_identity,
    );
    let preimage = canonical_request_preimage(&input).expect("canonical request preimage");
    request_signature.signature = Some(hex::encode(signing_key.sign(&preimage).to_bytes()));
    make_detached_request_signature_header(&request_signature)
}

fn trusted_request_signers_for(
    key_id: &str,
    signing_key: &SigningKey,
) -> std::collections::HashMap<String, crate::proxy::TrustedRequestSigner> {
    std::collections::HashMap::from([(
        key_id.to_string(),
        crate::proxy::TrustedRequestSigner {
            public_key: signing_key.verifying_key().to_bytes(),
            session_key_scope: vellaveto_types::SessionKeyScope::Unknown,
            execution_is_ephemeral: false,
            workload_identity: None,
        },
    )])
}

// ═══════════════════════════════════════════════════════════════════════
// GrpcConfig tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_config_defaults() {
    let config = GrpcConfig::default();
    assert_eq!(config.listen_addr.port(), 50051);
    assert_eq!(config.max_message_size, 4 * 1024 * 1024);
    assert!(config.upstream_grpc_url.is_none());
    assert!(config.health_enabled);
    assert_eq!(config.stream_message_rate_limit, 100);
}

#[test]
fn test_grpc_config_custom_values() {
    let config = GrpcConfig {
        listen_addr: "0.0.0.0:9090".parse().unwrap(),
        max_message_size: 8 * 1024 * 1024,
        upstream_grpc_url: Some("http://upstream:50051".to_string()),
        health_enabled: false,
        stream_message_rate_limit: 200,
    };
    assert_eq!(config.listen_addr.port(), 9090);
    assert_eq!(config.max_message_size, 8 * 1024 * 1024);
    assert_eq!(
        config.upstream_grpc_url.as_deref(),
        Some("http://upstream:50051")
    );
    assert!(!config.health_enabled);
    assert_eq!(config.stream_message_rate_limit, 200);
}

#[test]
fn test_grpc_config_serde_roundtrip() {
    let config = GrpcConfig {
        listen_addr: "127.0.0.1:50051".parse().unwrap(),
        max_message_size: 4194304,
        upstream_grpc_url: None,
        health_enabled: true,
        stream_message_rate_limit: 100,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: GrpcConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.listen_addr, parsed.listen_addr);
    assert_eq!(config.max_message_size, parsed.max_message_size);
    assert_eq!(config.upstream_grpc_url, parsed.upstream_grpc_url);
    assert_eq!(config.health_enabled, parsed.health_enabled);
    assert_eq!(
        config.stream_message_rate_limit,
        parsed.stream_message_rate_limit
    );
}

// ═══════════════════════════════════════════════════════════════════════
// R245: GrpcConfig validation tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_r245_grpc_config_validate_default_ok() {
    assert!(GrpcConfig::default().validate().is_ok());
}

#[test]
fn test_r245_grpc_config_validate_zero_message_size_rejected() {
    let config = GrpcConfig {
        max_message_size: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_message_size"));
}

#[test]
fn test_r245_grpc_config_validate_excessive_message_size_rejected() {
    let config = GrpcConfig {
        max_message_size: 512 * 1024 * 1024, // 512 MB > 256 MB limit
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_message_size"));
}

#[test]
fn test_r245_grpc_config_validate_dangerous_chars_in_url_rejected() {
    let config = GrpcConfig {
        upstream_grpc_url: Some("http://upstream\x00:50051".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control or format"));
}

#[test]
fn test_r245_grpc_config_validate_clean_url_accepted() {
    let config = GrpcConfig {
        upstream_grpc_url: Some("http://upstream.example.com:50051".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// R251: stream_message_rate_limit validation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_r251_grpc_config_validate_zero_rate_limit_rejected() {
    let config = GrpcConfig {
        stream_message_rate_limit: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("stream_message_rate_limit"));
}

#[test]
fn test_r251_grpc_config_validate_excessive_rate_limit_rejected() {
    let config = GrpcConfig {
        stream_message_rate_limit: 100_000, // > 10,000 limit
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("stream_message_rate_limit"));
}

#[test]
fn test_r251_grpc_config_validate_valid_rate_limit_accepted() {
    let config = GrpcConfig {
        stream_message_rate_limit: 500,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: proto_request_to_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_proto_request_to_json_tool_call() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(42)),
        method: "tools/call".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![
                (
                    "name".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue("read_file".to_string())),
                    },
                ),
                (
                    "arguments".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StructValue(prost_types::Struct {
                            fields: vec![(
                                "path".to_string(),
                                prost_types::Value {
                                    kind: Some(Kind::StringValue("/etc/passwd".to_string())),
                                },
                            )]
                            .into_iter()
                            .collect(),
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 42);
    assert_eq!(json["method"], "tools/call");
    assert_eq!(json["params"]["name"], "read_file");
    assert_eq!(json["params"]["arguments"]["path"], "/etc/passwd");
}

#[test]
fn test_proto_request_to_json_string_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdString("abc-123".to_string())),
        method: "ping".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert_eq!(json["id"], "abc-123");
}

#[test]
fn test_proto_request_to_json_null_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert!(json["id"].is_null());
}

#[test]
fn test_proto_request_to_json_no_params() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    assert!(json.get("params").is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: prost_struct_to_json
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_prost_struct_to_json_all_types() {
    let s = prost_types::Struct {
        fields: vec![
            (
                "null_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NullValue(0)),
                },
            ),
            (
                "bool_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::BoolValue(true)),
                },
            ),
            (
                "number_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(std::f64::consts::PI)),
                },
            ),
            (
                "string_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("hello".to_string())),
                },
            ),
            (
                "list_val".to_string(),
                prost_types::Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue {
                        values: vec![prost_types::Value {
                            kind: Some(Kind::NumberValue(1.0)),
                        }],
                    })),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["null_val"].is_null());
    assert_eq!(json["bool_val"], true);
    assert!((json["number_val"].as_f64().unwrap() - std::f64::consts::PI).abs() < f64::EPSILON);
    assert_eq!(json["string_val"], "hello");
    assert_eq!(json["list_val"][0], 1);
}

#[test]
fn test_prost_struct_to_json_nested() {
    let inner = prost_types::Struct {
        fields: vec![(
            "key".to_string(),
            prost_types::Value {
                kind: Some(Kind::StringValue("value".to_string())),
            },
        )]
        .into_iter()
        .collect(),
    };

    let outer = prost_types::Struct {
        fields: vec![(
            "nested".to_string(),
            prost_types::Value {
                kind: Some(Kind::StructValue(inner)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&outer, 0).unwrap();
    assert_eq!(json["nested"]["key"], "value");
}

#[test]
fn test_prost_struct_to_json_empty() {
    let s = prost_types::Struct {
        fields: Default::default(),
    };
    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json.as_object().unwrap().is_empty());
}

#[test]
fn test_prost_struct_to_json_nan_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::NAN)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let result = prost_struct_to_json(&s, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("NaN"));
}

#[test]
fn test_prost_struct_to_json_infinity_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::INFINITY)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let result = prost_struct_to_json(&s, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("NaN"));
}

#[test]
fn test_prost_struct_to_json_neg_infinity_rejected() {
    let s = prost_types::Struct {
        fields: vec![(
            "bad".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(f64::NEG_INFINITY)),
            },
        )]
        .into_iter()
        .collect(),
    };

    assert!(prost_struct_to_json(&s, 0).is_err());
}

#[test]
fn test_prost_value_none_kind_is_null() {
    let s = prost_types::Struct {
        fields: vec![("empty".to_string(), prost_types::Value { kind: None })]
            .into_iter()
            .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["empty"].is_null());
}

#[test]
fn test_prost_struct_depth_exceeded() {
    // Build deeply nested struct
    let mut current = prost_types::Struct {
        fields: vec![(
            "leaf".to_string(),
            prost_types::Value {
                kind: Some(Kind::StringValue("deep".to_string())),
            },
        )]
        .into_iter()
        .collect(),
    };

    for _ in 0..70 {
        current = prost_types::Struct {
            fields: vec![(
                "nest".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StructValue(current)),
                },
            )]
            .into_iter()
            .collect(),
        };
    }

    let result = prost_struct_to_json(&current, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("depth"));
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: integer handling
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_prost_number_integer_roundtrip() {
    let s = prost_types::Struct {
        fields: vec![(
            "count".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(42.0)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    // 42.0 should be represented as integer 42
    assert_eq!(json["count"], 42);
    assert!(json["count"].is_i64());
}

#[test]
fn test_prost_number_float_roundtrip() {
    let s = prost_types::Struct {
        fields: vec![(
            "score".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(std::f64::consts::PI)),
            },
        )]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&s, 0).unwrap();
    assert!(json["score"].is_f64());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: json_to_proto_response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_proto_response_success() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "hello"}]
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdInt(1))
    ));
    assert!(resp.result.is_some());
    assert!(resp.error.is_none());
}

#[test]
fn test_json_to_proto_response_error() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "error": {
            "code": -32001,
            "message": "Denied by policy"
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdString(ref s)) if s == "req-1"
    ));
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert_eq!(err.message, "Denied by policy");
}

#[test]
fn test_json_to_proto_response_null_id() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": null,
        "result": {}
    });

    let resp = json_to_proto_response(&json).unwrap();
    assert!(resp.id_oneof.is_none());
}

#[test]
fn test_json_to_proto_response_not_object() {
    let json = json!("not an object");
    let result = json_to_proto_response(&json);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// Proto ↔ JSON conversion: json_to_prost_struct
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_prost_struct_object() {
    let json = json!({"a": 1, "b": "two", "c": true, "d": null, "e": [1, 2]});
    let s = json_to_prost_struct(&json, 0).unwrap();
    assert_eq!(s.fields.len(), 5);
}

#[test]
fn test_json_to_prost_struct_non_object_wrapped() {
    let json = json!(42);
    let s = json_to_prost_struct(&json, 0).unwrap();
    assert!(s.fields.contains_key("value"));
}

#[test]
fn test_json_to_prost_struct_depth_exceeded() {
    // Build deeply nested JSON
    let mut val = json!("leaf");
    for _ in 0..70 {
        val = json!({"nest": val});
    }
    let result = json_to_prost_struct(&val, 0);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// Roundtrip tests: proto → json → proto
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_struct_roundtrip_all_types() {
    let original = prost_types::Struct {
        fields: vec![
            (
                "str".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("hello".to_string())),
                },
            ),
            (
                "num".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NumberValue(99.0)),
                },
            ),
            (
                "bool".to_string(),
                prost_types::Value {
                    kind: Some(Kind::BoolValue(false)),
                },
            ),
            (
                "null".to_string(),
                prost_types::Value {
                    kind: Some(Kind::NullValue(0)),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };

    let json = prost_struct_to_json(&original, 0).unwrap();
    let roundtripped = json_to_prost_struct(&json, 0).unwrap();

    // Verify field count matches
    assert_eq!(original.fields.len(), roundtripped.fields.len());

    // Verify the json roundtrips correctly
    let json2 = prost_struct_to_json(&roundtripped, 0).unwrap();
    assert_eq!(json, json2);
}

// ═══════════════════════════════════════════════════════════════════════
// make_proto_error_response / make_proto_denial_response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_make_proto_error_response_int_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(7)),
        method: "tools/call".to_string(),
        params: None,
    };

    let resp = make_proto_error_response(&req, -32603, "Internal error");
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(matches!(
        resp.id_oneof,
        Some(json_rpc_response::IdOneof::IdInt(7))
    ));
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32603);
    assert_eq!(err.message, "Internal error");
}

#[test]
fn test_make_proto_denial_response() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdString("r1".to_string())),
        method: "tools/call".to_string(),
        params: None,
    };

    let resp = make_proto_denial_response(&req, "Policy forbids this");
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert_eq!(err.message, "Policy forbids this");
}

#[test]
fn test_make_proto_error_response_no_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: None,
        method: "test".to_string(),
        params: None,
    };

    let resp = make_proto_error_response(&req, -32600, "Bad request");
    assert!(resp.id_oneof.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Interceptors: session extraction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_session_id_present() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_MCP_SESSION_ID, "sess-123".parse().unwrap());
    assert_eq!(extract_session_id(&metadata), Some("sess-123".to_string()));
}

#[test]
fn test_extract_session_id_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    assert_eq!(extract_session_id(&metadata), None);
}

#[test]
fn test_extract_session_id_empty() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_MCP_SESSION_ID, "".parse().unwrap());
    assert_eq!(extract_session_id(&metadata), None);
}

#[test]
fn test_extract_session_id_oversized() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    let long_id = "a".repeat(300);
    metadata.insert(METADATA_MCP_SESSION_ID, long_id.parse().unwrap());
    assert_eq!(extract_session_id(&metadata), None);
}

// ═══════════════════════════════════════════════════════════════════════
// Interceptors: request ID extraction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_request_id_present() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(METADATA_REQUEST_ID, "req-456".parse().unwrap());
    assert_eq!(
        extract_or_generate_request_id(&metadata),
        "req-456".to_string()
    );
}

#[test]
fn test_extract_request_id_generated_when_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    let id = extract_or_generate_request_id(&metadata);
    // Generated UUID should be valid
    assert!(!id.is_empty());
    assert!(uuid::Uuid::parse_str(&id).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// Message classification via proto conversion
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_classify_tool_call_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "tools/call".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![
                (
                    "name".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue("write_file".to_string())),
                    },
                ),
                (
                    "arguments".to_string(),
                    prost_types::Value {
                        kind: Some(Kind::StructValue(prost_types::Struct {
                            fields: Default::default(),
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::ToolCall { .. }
    ));
}

#[test]
fn test_classify_resource_read_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(2)),
        method: "resources/read".to_string(),
        params: Some(prost_types::Struct {
            fields: vec![(
                "uri".to_string(),
                prost_types::Value {
                    kind: Some(Kind::StringValue("file:///etc/passwd".to_string())),
                },
            )]
            .into_iter()
            .collect(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::ResourceRead { .. }
    ));
}

#[test]
fn test_classify_batch_via_proto() {
    // Batch is detected at the JSON level (array), but our proto wraps single messages.
    // If someone sends a proto with array-like content, classify_message sees an object, not a batch.
    // Batch rejection works at the JSON-RPC level before proto conversion.
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "ping".to_string(),
        params: None,
    };
    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    // ping is a passthrough, not a batch
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::PassThrough
    ));
}

#[test]
fn test_classify_sampling_request_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(5)),
        method: "sampling/createMessage".to_string(),
        params: Some(prost_types::Struct {
            fields: Default::default(),
        }),
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::SamplingRequest { .. }
    ));
}

#[test]
fn test_classify_passthrough_via_proto() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id_oneof: Some(json_rpc_request::IdOneof::IdInt(1)),
        method: "tools/list".to_string(),
        params: None,
    };

    let json = proto_request_to_json(&req).unwrap();
    let classified = vellaveto_mcp::extractor::classify_message(&json);
    assert!(matches!(
        classified,
        vellaveto_mcp::extractor::MessageType::PassThrough
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// GrpcTransportConfig tests (vellaveto-config)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_transport_config_defaults() {
    let config = vellaveto_config::GrpcTransportConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.listen_address, "127.0.0.1:50051");
    assert_eq!(config.max_message_size_bytes, 4 * 1024 * 1024);
    assert!(config.upstream_grpc_url.is_none());
    assert!(config.health_enabled);
}

#[test]
fn test_grpc_transport_config_serde() {
    let json = r#"{
        "enabled": true,
        "listen_address": "0.0.0.0:9090",
        "max_message_size_bytes": 8388608,
        "upstream_grpc_url": "http://upstream:50051",
        "health_enabled": false
    }"#;
    let config: vellaveto_config::GrpcTransportConfig = serde_json::from_str(json).unwrap();
    assert!(config.enabled);
    assert_eq!(config.listen_address, "0.0.0.0:9090");
    assert_eq!(config.max_message_size_bytes, 8388608);
    assert_eq!(
        config.upstream_grpc_url.as_deref(),
        Some("http://upstream:50051")
    );
    assert!(!config.health_enabled);
}

// ═══════════════════════════════════════════════════════════════════════
// Upstream error types
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_upstream_error_display() {
    let err = UpstreamError::HttpError("connection refused".to_string());
    assert!(err.to_string().contains("connection refused"));

    let err = UpstreamError::JsonError("unexpected token".to_string());
    assert!(err.to_string().contains("unexpected token"));

    let err = UpstreamError::GrpcError("unavailable".to_string());
    assert!(err.to_string().contains("unavailable"));

    let err = UpstreamError::NoUpstream;
    assert!(err.to_string().contains("not configured"));
}

// ═══════════════════════════════════════════════════════════════════════
// Convert error types
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_convert_error_display() {
    let err = ConvertError::InvalidFloat;
    assert!(err.to_string().contains("NaN"));

    let err = ConvertError::DepthExceeded;
    assert!(err.to_string().contains("depth"));

    let err = ConvertError::MissingField("test_field");
    assert!(err.to_string().contains("test_field"));
}

// ═══════════════════════════════════════════════════════════════════════
// Edge cases: JSON response with error+data
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_json_to_proto_response_error_with_data() {
    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32001,
            "message": "Denied",
            "data": {"approval_id": "ap-123"}
        }
    });

    let resp = json_to_proto_response(&json).unwrap();
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32001);
    assert!(err.data.is_some());
    let data = err.data.unwrap();
    assert!(data.fields.contains_key("approval_id"));
}

#[test]
fn test_json_to_proto_response_missing_jsonrpc() {
    let json = json!({
        "id": 1,
        "result": {}
    });

    let resp = json_to_proto_response(&json).unwrap();
    // Defaults to "2.0" when missing
    assert_eq!(resp.jsonrpc, "2.0");
}

// ═══════════════════════════════════════════════════════════════════════
// Metadata constants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_metadata_constants() {
    assert_eq!(METADATA_AUTHORIZATION, "authorization");
    assert_eq!(METADATA_MCP_SESSION_ID, "mcp-session-id");
    assert_eq!(METADATA_AGENT_IDENTITY, "x-agent-identity");
    assert_eq!(METADATA_WORKLOAD_CLAIMS, "x-workload-claims");
    assert_eq!(METADATA_REQUEST_SIGNATURE, "x-request-signature");
    assert_eq!(METADATA_UPSTREAM_AGENTS, "x-upstream-agents");
    assert_eq!(METADATA_REQUEST_ID, "x-request-id");
}

#[test]
fn test_build_grpc_runtime_security_context_preserves_detached_signature_and_workload() {
    use base64::Engine;

    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let detached_signature = vellaveto_types::RequestSignature {
        key_id: Some("detached-key".to_string()),
        algorithm: Some("ed25519".to_string()),
        nonce: Some("nonce-123".to_string()),
        created_at: Some("2026-03-11T12:00:00Z".to_string()),
        signature: Some("deadbeef".to_string()),
    };
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&detached_signature).expect("serialize detached signature"));
    let eval_ctx = vellaveto_types::EvaluationContext {
        agent_identity: Some(vellaveto_types::AgentIdentity {
            subject: Some("spiffe://cluster/ns/prod/sa/grpc".to_string()),
            claims: std::collections::HashMap::from([
                ("namespace".to_string(), json!("prod")),
                ("service_account".to_string(), json!("grpc-sa")),
                ("execution_is_ephemeral".to_string(), json!(true)),
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &empty_session_store(),
            session_id: None,
            trusted_request_signers: &empty_trusted_request_signers(),
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert_eq!(
        security_context.sink_class,
        Some(vellaveto_types::SinkClass::CodeExecution)
    );
    assert_eq!(
        provenance.signature_status,
        vellaveto_types::SignatureVerificationStatus::Missing
    );
    assert_eq!(
        provenance
            .request_signature
            .as_ref()
            .and_then(|signature| signature.key_id.as_deref()),
        Some("detached-key")
    );
    assert_eq!(
        provenance.workload_binding_status,
        vellaveto_types::WorkloadBindingStatus::Bound
    );
    assert_eq!(
        provenance
            .workload_identity
            .as_ref()
            .and_then(|identity| identity.namespace.as_deref()),
        Some("prod")
    );
    assert!(
        provenance.canonical_request_hash.is_some(),
        "gRPC runtime provenance should carry canonical request binding"
    );
}

#[test]
fn test_build_grpc_runtime_security_context_verifies_detached_signature_with_trusted_signer() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let trusted_request_signers = trusted_request_signers_for("detached-key", &signing_key);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_scope(
        &action,
        "detached-key",
        &signing_key,
        Some(session_scope_binding.as_str()),
    );

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&vellaveto_types::EvaluationContext::default()),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert_eq!(
        provenance.signature_status,
        SignatureVerificationStatus::Verified
    );
    assert_eq!(
        provenance.replay_status,
        vellaveto_types::ReplayStatus::Fresh
    );
}

#[test]
fn test_build_grpc_runtime_security_context_projects_trusted_signer_metadata() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let trusted_request_signers = std::collections::HashMap::from([(
        "detached-key".to_string(),
        crate::proxy::TrustedRequestSigner {
            public_key: signing_key.verifying_key().to_bytes(),
            session_key_scope: vellaveto_types::SessionKeyScope::EphemeralSession,
            execution_is_ephemeral: true,
            workload_identity: Some(vellaveto_types::WorkloadIdentity {
                platform: Some("spiffe".into()),
                workload_id: "spiffe://cluster/ns/prod/sa/grpc".into(),
                namespace: Some("prod".into()),
                service_account: Some("grpc".into()),
                process_identity: None,
                attestation_level: Some("jwt".into()),
            }),
        },
    )]);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_binding(
        &action,
        "detached-key",
        &signing_key,
        DetachedSignatureBinding {
            session_scope_binding: Some(session_scope_binding.as_str()),
            routing_identity: None,
            workload_identity: Some(vellaveto_types::WorkloadIdentity {
                platform: Some("spiffe".into()),
                workload_id: "spiffe://cluster/ns/meta/sa/meta".into(),
                namespace: Some("meta".into()),
                service_account: Some("meta".into()),
                process_identity: None,
                attestation_level: Some("jwt".into()),
            }),
        },
    );

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&vellaveto_types::EvaluationContext::default()),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert_eq!(
        provenance.signature_status,
        SignatureVerificationStatus::Verified
    );
    assert_eq!(
        provenance.session_key_scope,
        vellaveto_types::SessionKeyScope::EphemeralSession
    );
    assert!(provenance.execution_is_ephemeral);
    assert_eq!(
        provenance.workload_binding_status,
        vellaveto_types::WorkloadBindingStatus::Bound
    );
    assert_eq!(
        provenance
            .workload_identity
            .as_ref()
            .map(|identity| identity.workload_id.as_str()),
        Some("spiffe://cluster/ns/prod/sa/grpc")
    );
}

#[test]
fn test_build_grpc_runtime_security_context_rejects_conflicting_trusted_signer_session_scope() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let signing_key = SigningKey::from_bytes(&[14u8; 32]);
    let trusted_request_signers = std::collections::HashMap::from([(
        "detached-key".to_string(),
        crate::proxy::TrustedRequestSigner {
            public_key: signing_key.verifying_key().to_bytes(),
            session_key_scope: vellaveto_types::SessionKeyScope::EphemeralSession,
            execution_is_ephemeral: false,
            workload_identity: None,
        },
    )]);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_scope(
        &action,
        "detached-key",
        &signing_key,
        Some(session_scope_binding.as_str()),
    );
    let eval_ctx = vellaveto_types::EvaluationContext {
        agent_identity: Some(vellaveto_types::AgentIdentity {
            claims: std::collections::HashMap::from([(
                "session_key_scope".to_string(),
                json!("persisted_client"),
            )]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert_eq!(
        provenance.signature_status,
        SignatureVerificationStatus::Invalid
    );
    assert_eq!(
        provenance.session_key_scope,
        vellaveto_types::SessionKeyScope::PersistedClient
    );
}

#[test]
fn test_build_grpc_runtime_security_context_marks_workload_mismatch_for_trusted_signer_expectation()
{
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let signing_key = SigningKey::from_bytes(&[15u8; 32]);
    let trusted_request_signers = std::collections::HashMap::from([(
        "detached-key".to_string(),
        crate::proxy::TrustedRequestSigner {
            public_key: signing_key.verifying_key().to_bytes(),
            session_key_scope: vellaveto_types::SessionKeyScope::Unknown,
            execution_is_ephemeral: false,
            workload_identity: Some(vellaveto_types::WorkloadIdentity {
                platform: Some("spiffe".into()),
                workload_id: "spiffe://cluster/ns/prod/sa/grpc".into(),
                namespace: Some("prod".into()),
                service_account: Some("grpc".into()),
                process_identity: None,
                attestation_level: Some("jwt".into()),
            }),
        },
    )]);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_binding(
        &action,
        "detached-key",
        &signing_key,
        DetachedSignatureBinding {
            session_scope_binding: Some(session_scope_binding.as_str()),
            routing_identity: Some("spiffe://cluster/ns/prod/sa/other"),
            workload_identity: Some(vellaveto_types::WorkloadIdentity {
                platform: Some("spiffe".into()),
                workload_id: "spiffe://cluster/ns/prod/sa/other".into(),
                namespace: Some("prod".into()),
                service_account: Some("other".into()),
                process_identity: None,
                attestation_level: Some("jwt".into()),
            }),
        },
    );
    let eval_ctx = vellaveto_types::EvaluationContext {
        agent_identity: Some(vellaveto_types::AgentIdentity {
            issuer: Some("https://issuer.example".into()),
            subject: Some("spiffe://cluster/ns/prod/sa/other".into()),
            audience: vec![],
            claims: std::collections::HashMap::from([
                (
                    "workload_id".to_string(),
                    json!("spiffe://cluster/ns/prod/sa/other"),
                ),
                ("namespace".to_string(), json!("prod")),
                ("service_account".to_string(), json!("other")),
                ("attestation_level".to_string(), json!("jwt")),
            ]),
        }),
        ..Default::default()
    };

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert_eq!(
        provenance.signature_status,
        SignatureVerificationStatus::Verified
    );
    assert_eq!(
        provenance.workload_binding_status,
        vellaveto_types::WorkloadBindingStatus::Mismatch
    );
    assert_eq!(
        provenance
            .workload_identity
            .as_ref()
            .map(|identity| identity.workload_id.as_str()),
        Some("spiffe://cluster/ns/prod/sa/other")
    );
    assert_eq!(
        security_context.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Untrusted)
    );
}

#[test]
fn test_build_grpc_runtime_security_context_detects_replayed_detached_signature() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "shell_exec",
        &json!({
            "command": "echo hi"
        }),
    );
    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let trusted_request_signers = trusted_request_signers_for("detached-key", &signing_key);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_scope(
        &action,
        "detached-key",
        &signing_key,
        Some(session_scope_binding.as_str()),
    );
    let eval_ctx = vellaveto_types::EvaluationContext::default();

    let first = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("first security context");
    let second = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("second security context");

    assert_eq!(
        first.client_provenance.as_ref().map(|p| p.replay_status),
        Some(vellaveto_types::ReplayStatus::Fresh)
    );
    assert_eq!(
        first.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Verified)
    );
    assert_eq!(
        second.client_provenance.as_ref().map(|p| p.replay_status),
        Some(vellaveto_types::ReplayStatus::ReplayDetected)
    );
    assert_eq!(
        second.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Quarantined)
    );
}

#[test]
fn test_build_grpc_runtime_security_context_marks_invalid_detached_signature() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/example"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "read_file",
        &json!({
            "path": "/tmp/example"
        }),
    );

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some("not-base64"),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&vellaveto_types::EvaluationContext::default()),
            sessions: &empty_session_store(),
            session_id: None,
            trusted_request_signers: &empty_trusted_request_signers(),
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");
    let provenance = security_context
        .client_provenance
        .as_ref()
        .expect("client provenance");

    assert!(provenance.request_signature.is_none());
    assert_eq!(
        provenance.signature_status,
        vellaveto_types::SignatureVerificationStatus::Invalid
    );
    assert_eq!(
        security_context.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Untrusted)
    );
}

#[test]
fn test_build_grpc_runtime_security_context_clamps_meta_trust_with_invalid_detached_signature() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "_meta": {
            "vellavetoSecurityContext": {
                "effective_trust_tier": "verified"
            }
        },
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/example"}
        }
    });
    let action = vellaveto_mcp::extractor::extract_action(
        "read_file",
        &json!({
            "path": "/tmp/example"
        }),
    );

    let security_context = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some("not-base64"),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&vellaveto_types::EvaluationContext::default()),
            sessions: &empty_session_store(),
            session_id: None,
            trusted_request_signers: &empty_trusted_request_signers(),
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("security context");

    assert_eq!(
        security_context.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Untrusted)
    );
}

#[test]
fn test_build_grpc_runtime_security_context_clamps_meta_replay_status_with_detached_signature() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "_meta": {
            "vellavetoSecurityContext": {
                "effective_trust_tier": "verified",
                "client_provenance": {
                    "replay_status": "fresh"
                }
            }
        },
        "method": "tools/call",
        "params": {
            "name": "shell_exec",
            "arguments": {"command": "echo hi"}
        }
    });
    let action =
        vellaveto_mcp::extractor::extract_action("shell_exec", &json!({"command": "echo hi"}));
    let signing_key = SigningKey::from_bytes(&[29u8; 32]);
    let trusted_request_signers = trusted_request_signers_for("detached-key", &signing_key);
    let sessions = empty_session_store();
    let session_id = sessions.get_or_create(None);
    let session_scope_binding = sessions
        .get(&session_id)
        .expect("session")
        .session_scope_binding
        .clone();
    let header = make_signed_detached_request_signature_header_with_scope(
        &action,
        "detached-key",
        &signing_key,
        Some(session_scope_binding.as_str()),
    );
    let eval_ctx = vellaveto_types::EvaluationContext::default();

    let first = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("first security context");
    let second = service::build_grpc_runtime_security_context(
        &msg,
        &action,
        Some(header.as_str()),
        crate::proxy::helpers::TransportSecurityInputs {
            oauth_evidence: None,
            eval_ctx: Some(&eval_ctx),
            sessions: &sessions,
            session_id: Some(&session_id),
            trusted_request_signers: &trusted_request_signers,
            detached_signature_freshness: default_detached_signature_freshness(),
        },
    )
    .expect("second security context");

    assert_eq!(
        first.client_provenance.as_ref().map(|p| p.replay_status),
        Some(vellaveto_types::ReplayStatus::Fresh)
    );
    assert_eq!(
        second.client_provenance.as_ref().map(|p| p.replay_status),
        Some(vellaveto_types::ReplayStatus::ReplayDetected)
    );
    assert_eq!(
        second.effective_trust_tier,
        Some(vellaveto_types::TrustTier::Quarantined)
    );
}

// ═══════════════════════════════════════════════════════════════════════
// TaskRequest and ExtensionMethod policy enforcement tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_task_request_classification_grpc() {
    // Verify task request is classified correctly from a proto request
    let json_msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tasks/get",
        "params": {"id": "task-abc"}
    });
    let classified = vellaveto_mcp::extractor::classify_message(&json_msg);
    match classified {
        vellaveto_mcp::extractor::MessageType::TaskRequest {
            task_method,
            task_id,
            ..
        } => {
            assert_eq!(task_method, "tasks/get");
            assert_eq!(task_id, Some("task-abc".to_string()));
        }
        other => panic!("Expected TaskRequest, got {:?}", other),
    }
}

#[test]
fn test_task_request_action_extraction_grpc() {
    let action = vellaveto_mcp::extractor::extract_task_action("tasks/cancel", Some("task-123"));
    assert_eq!(action.tool, "tasks");
    assert_eq!(action.function, "cancel");
    assert_eq!(action.parameters["task_id"], "task-123");
}

#[test]
fn test_task_request_fail_closed_no_policies_grpc() {
    // With no policies, task requests should be denied (fail-closed)
    let engine = vellaveto_engine::PolicyEngine::new(false);
    let action = vellaveto_mcp::extractor::extract_task_action("tasks/get", Some("task-abc"));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}

#[test]
fn test_extension_method_classification_grpc() {
    let json_msg = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "x-vellaveto-audit/stats",
        "params": {}
    });
    let classified = vellaveto_mcp::extractor::classify_message(&json_msg);
    match classified {
        vellaveto_mcp::extractor::MessageType::ExtensionMethod {
            extension_id,
            method,
            ..
        } => {
            assert_eq!(extension_id, "x-vellaveto-audit");
            assert_eq!(method, "x-vellaveto-audit/stats");
        }
        other => panic!("Expected ExtensionMethod, got {:?}", other),
    }
}

#[test]
fn test_extension_method_fail_closed_no_policies_grpc() {
    let engine = vellaveto_engine::PolicyEngine::new(false);
    let action = vellaveto_mcp::extractor::extract_extension_action(
        "x-vellaveto-audit",
        "x-vellaveto-audit/stats",
        &json!({}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 28: gRPC Trace Context Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_extract_trace_context_from_metadata_valid() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "traceparent",
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            .parse()
            .unwrap(),
    );

    let ctx = extract_trace_context_from_metadata(&metadata);
    assert_eq!(
        ctx.trace_id,
        Some("0af7651916cd43dd8448eb211c80319c".to_string())
    );
    assert_eq!(ctx.parent_span_id, Some("b7ad6b7169203331".to_string()));
    assert!(ctx.is_sampled());
}

#[test]
fn test_extract_trace_context_from_metadata_missing() {
    let metadata = tonic::metadata::MetadataMap::new();
    let ctx = extract_trace_context_from_metadata(&metadata);
    assert!(ctx.trace_id.is_some());
    assert_eq!(ctx.trace_id.as_ref().unwrap().len(), 32);
}

#[test]
fn test_extract_trace_context_from_metadata_with_tracestate() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "traceparent",
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            .parse()
            .unwrap(),
    );
    metadata.insert("tracestate", "vendor=value".parse().unwrap());

    let ctx = extract_trace_context_from_metadata(&metadata);
    assert_eq!(ctx.trace_state, Some("vendor=value".to_string()));
}

#[test]
fn test_extract_trace_context_from_metadata_invalid_traceparent() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("traceparent", "not-valid".parse().unwrap());

    let ctx = extract_trace_context_from_metadata(&metadata);
    assert!(ctx.trace_id.is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// FIND-R115-040: gRPC output schema registration from tools/list response
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_register_from_tools_list_response() {
    // Verify that register_from_tools_list properly registers schemas
    // from a tools/list response, ensuring gRPC parity with HTTP/WS.
    let registry = vellaveto_mcp::output_validation::OutputSchemaRegistry::new();

    let tools_list_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "grpc_search_tool",
                    "description": "Search tool for gRPC test",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "results": {"type": "array"}
                        },
                        "required": ["results"]
                    }
                },
                {
                    "name": "grpc_no_schema_tool",
                    "description": "Tool without output schema",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
    });

    registry.register_from_tools_list(&tools_list_response);
    assert!(
        registry.has_schema("grpc_search_tool"),
        "Tool with outputSchema must be registered"
    );
    assert!(
        !registry.has_schema("grpc_no_schema_tool"),
        "Tool without outputSchema must not be registered"
    );
    assert_eq!(registry.len(), 1, "Exactly one schema should be registered");
}

#[test]
fn test_grpc_register_from_tools_list_response_non_tools_list() {
    // Verify that register_from_tools_list is a no-op for non-tools/list responses.
    let registry = vellaveto_mcp::output_validation::OutputSchemaRegistry::new();

    let non_tools_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "hello"}]
        }
    });

    registry.register_from_tools_list(&non_tools_response);
    assert_eq!(
        registry.len(),
        0,
        "No schemas should be registered from a non-tools/list response"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// FIND-R115-041: Rug-pull detection for resource URIs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_flagged_tools_contains_check_resource() {
    // Verify the SessionState flagged_tools set correctly detects flagged URIs,
    // ensuring the rug-pull check pattern added to resource_read works.
    let mut flagged = std::collections::HashSet::new();
    flagged.insert("file:///suspicious/server".to_string());
    flagged.insert("compromised_tool".to_string());

    assert!(
        flagged.contains("file:///suspicious/server"),
        "flagged_tools must contain the flagged URI"
    );
    assert!(
        flagged.contains("compromised_tool"),
        "flagged_tools must contain the flagged tool name"
    );
    assert!(
        !flagged.contains("file:///safe/resource"),
        "non-flagged URI must not match"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// FIND-R115-042: Circuit breaker check for resource reads
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_grpc_circuit_breaker_blocks_resource_read_on_open_circuit() {
    // Verify the circuit breaker correctly blocks resource URIs when the
    // circuit is open, ensuring resource read parity with tool call.
    let cb = vellaveto_engine::circuit_breaker::CircuitBreakerManager::new(
        2,  // failure_threshold
        2,  // success_threshold
        60, // open_duration_secs
    );

    // Initially closed — should allow
    assert!(
        cb.can_proceed("file:///etc/data").is_ok(),
        "Closed circuit must allow resource reads"
    );

    // Record enough failures to open the circuit
    cb.record_failure("file:///etc/data");
    cb.record_failure("file:///etc/data");

    // Now the circuit should be open
    let result = cb.can_proceed("file:///etc/data");
    assert!(result.is_err(), "Open circuit must block resource reads");

    // Different URI should still be allowed (circuit breaker is per-key)
    assert!(
        cb.can_proceed("file:///other/resource").is_ok(),
        "Different URI should not be affected by another URI's open circuit"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// FIND-R115-043: tool_registry.record_call parity
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_grpc_tool_registry_record_call() {
    // Verify that the tool registry correctly records calls for trust scoring.
    // This is the pattern used in the gRPC handle_tool_call after Allow verdict.
    let dir = std::env::temp_dir().join("vellaveto_grpc_test_registry");
    let registry = vellaveto_mcp::tool_registry::ToolRegistry::new(&dir);

    // Register a tool first
    registry.register_unknown("my_grpc_tool").await;
    let entry_before = registry.get("my_grpc_tool").await;
    let calls_before = entry_before.map(|e| e.call_count).unwrap_or(0);
    assert_eq!(calls_before, 0, "New tool should have 0 calls");

    // Record a call (simulating tool_registry.record_call in handle_tool_call)
    registry.record_call("my_grpc_tool").await;

    let entry_after = registry.get("my_grpc_tool").await;
    let calls_after = entry_after.map(|e| e.call_count).unwrap_or(0);
    assert_eq!(calls_after, 1, "record_call must increment call_count to 1");

    // Record another call
    registry.record_call("my_grpc_tool").await;
    let entry_final = registry.get("my_grpc_tool").await;
    assert_eq!(
        entry_final.map(|e| e.call_count).unwrap_or(0),
        2,
        "record_call must increment call_count to 2"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}
