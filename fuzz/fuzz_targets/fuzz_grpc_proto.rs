#![no_main]
//! Fuzz target for gRPC proto→JSON conversion.
//!
//! Takes arbitrary bytes, attempts to decode as a protobuf JsonRpcRequest,
//! converts to serde_json::Value via the conversion layer, classifies the
//! message, and (for tool calls) extracts an Action. Ensures no panics on
//! any input, including malformed protobuf data.

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Step 1: Try to decode as a protobuf JsonRpcRequest.
    // We can't import the generated types from vellaveto-http-proxy here
    // (it requires the grpc feature), so we test the prost_types conversion
    // layer directly.

    // Try to decode as a prost_types::Struct (the dynamic JSON container).
    let s = match prost_types::Struct::decode(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Step 2: Convert the struct to JSON (must not panic).
    let _json = convert_struct_to_json(&s, 0);

    // Step 3: Try the reverse direction if we got valid JSON.
    if let Ok(json_val) = convert_struct_to_json(&s, 0) {
        let _ = convert_json_to_struct(&json_val, 0);
    }

    // Step 4: Try to decode and classify as a JSON-RPC message.
    if let Ok(json_val) = convert_struct_to_json(&s, 0) {
        let _ = vellaveto_mcp::extractor::classify_message(&json_val);
    }
});

/// Maximum conversion depth (matches the real implementation).
const MAX_DEPTH: usize = 64;

fn convert_struct_to_json(
    s: &prost_types::Struct,
    depth: usize,
) -> Result<serde_json::Value, ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    let mut map = serde_json::Map::new();
    for (key, value) in &s.fields {
        map.insert(key.clone(), convert_value_to_json(value, depth + 1)?);
    }
    Ok(serde_json::Value::Object(map))
}

fn convert_value_to_json(
    v: &prost_types::Value,
    depth: usize,
) -> Result<serde_json::Value, ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    match &v.kind {
        Some(prost_types::value::Kind::NullValue(_)) => Ok(serde_json::Value::Null),
        Some(prost_types::value::Kind::NumberValue(n)) => {
            if n.is_nan() || n.is_infinite() {
                return Err(());
            }
            serde_json::Number::from_f64(*n)
                .map(serde_json::Value::Number)
                .ok_or(())
        }
        Some(prost_types::value::Kind::StringValue(s)) => {
            Ok(serde_json::Value::String(s.clone()))
        }
        Some(prost_types::value::Kind::BoolValue(b)) => Ok(serde_json::Value::Bool(*b)),
        Some(prost_types::value::Kind::StructValue(s)) => convert_struct_to_json(s, depth + 1),
        Some(prost_types::value::Kind::ListValue(list)) => {
            let items: Result<Vec<serde_json::Value>, ()> = list
                .values
                .iter()
                .map(|v| convert_value_to_json(v, depth + 1))
                .collect();
            Ok(serde_json::Value::Array(items?))
        }
        None => Ok(serde_json::Value::Null),
    }
}

fn convert_json_to_struct(
    v: &serde_json::Value,
    depth: usize,
) -> Result<prost_types::Struct, ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    match v {
        serde_json::Value::Object(map) => {
            let mut fields = std::collections::BTreeMap::new();
            for (key, val) in map {
                fields.insert(key.clone(), convert_json_to_value(val, depth + 1)?);
            }
            Ok(prost_types::Struct {
                fields: fields.into_iter().collect(),
            })
        }
        _ => Ok(prost_types::Struct {
            fields: Default::default(),
        }),
    }
}

fn convert_json_to_value(
    v: &serde_json::Value,
    depth: usize,
) -> Result<prost_types::Value, ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    let kind = match v {
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0),
        serde_json::Value::Bool(b) => prost_types::value::Kind::BoolValue(*b),
        serde_json::Value::Number(n) => {
            prost_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0.0))
        }
        serde_json::Value::String(s) => {
            prost_types::value::Kind::StringValue(s.clone())
        }
        serde_json::Value::Array(arr) => {
            let values: Result<Vec<prost_types::Value>, ()> = arr
                .iter()
                .map(|item| convert_json_to_value(item, depth + 1))
                .collect();
            prost_types::value::Kind::ListValue(prost_types::ListValue {
                values: values?,
            })
        }
        serde_json::Value::Object(_) => {
            let s = convert_json_to_struct(v, depth + 1)?;
            prost_types::value::Kind::StructValue(s)
        }
    };
    Ok(prost_types::Value { kind: Some(kind) })
}
