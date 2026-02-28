// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that verify the exact JSON serialization format of Verdict variants.
//! Existing tests do roundtrip checks but never assert the actual JSON shape.
//! If someone changes the serde attributes, these tests catch it.

use serde_json::json;
use vellaveto_types::Verdict;

#[test]
fn verdict_allow_serializes_to_string() {
    let v = Verdict::Allow;
    let json_val = serde_json::to_value(&v).unwrap();
    // Verify it's exactly the string "Allow", not an object
    assert_eq!(json_val, json!("Allow"));
}

#[test]
fn verdict_deny_serializes_to_object_with_reason() {
    let v = Verdict::Deny {
        reason: "blocked".to_string(),
    };
    let json_val = serde_json::to_value(&v).unwrap();

    // Serde's default enum serialization: {"Deny": {"reason": "blocked"}}
    assert!(json_val.is_object(), "Deny should serialize as object");
    let deny_obj = json_val.get("Deny").expect("Should have 'Deny' key");
    assert_eq!(deny_obj.get("reason").unwrap(), "blocked");
}

#[test]
fn verdict_require_approval_serializes_to_object_with_reason() {
    let v = Verdict::RequireApproval {
        reason: "needs review".to_string(),
    };
    let json_val = serde_json::to_value(&v).unwrap();

    assert!(
        json_val.is_object(),
        "RequireApproval should serialize as object"
    );
    let approval_obj = json_val
        .get("RequireApproval")
        .expect("Should have 'RequireApproval' key");
    assert_eq!(approval_obj.get("reason").unwrap(), "needs review");
}

#[test]
fn verdict_deny_with_empty_reason() {
    let v = Verdict::Deny {
        reason: String::new(),
    };
    let json_val = serde_json::to_value(&v).unwrap();
    let deny_obj = json_val.get("Deny").unwrap();
    assert_eq!(deny_obj.get("reason").unwrap(), "");
}

#[test]
fn verdict_allow_deserializes_from_string() {
    let json_val = json!("Allow");
    let v: Verdict = serde_json::from_value(json_val).unwrap();
    assert_eq!(v, Verdict::Allow);
}

#[test]
fn verdict_deny_deserializes_from_object() {
    let json_val = json!({"Deny": {"reason": "test"}});
    let v: Verdict = serde_json::from_value(json_val).unwrap();
    assert_eq!(
        v,
        Verdict::Deny {
            reason: "test".to_string()
        }
    );
}

#[test]
fn verdict_require_approval_deserializes_from_object() {
    let json_val = json!({"RequireApproval": {"reason": "check"}});
    let v: Verdict = serde_json::from_value(json_val).unwrap();
    assert_eq!(
        v,
        Verdict::RequireApproval {
            reason: "check".to_string()
        }
    );
}

// ═══════════════════════════════════════
// INVALID VERDICT JSON
// ══════════════════════════════════════

#[test]
fn verdict_rejects_unknown_variant_string() {
    let json_val = json!("Unknown");
    let result: Result<Verdict, _> = serde_json::from_value(json_val);
    assert!(result.is_err());
}

#[test]
fn verdict_rejects_deny_without_reason() {
    let json_val = json!({"Deny": {}});
    let result: Result<Verdict, _> = serde_json::from_value(json_val);
    assert!(result.is_err());
}

#[test]
fn verdict_rejects_integer() {
    let json_val = json!(42);
    let result: Result<Verdict, _> = serde_json::from_value(json_val);
    assert!(result.is_err());
}

#[test]
fn verdict_rejects_null() {
    let json_val = json!(null);
    let result: Result<Verdict, _> = serde_json::from_value(json_val);
    assert!(result.is_err());
}

#[test]
fn verdict_rejects_array() {
    let json_val = json!(["Allow"]);
    let result: Result<Verdict, _> = serde_json::from_value(json_val);
    assert!(result.is_err());
}
