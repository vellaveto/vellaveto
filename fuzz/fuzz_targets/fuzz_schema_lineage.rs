#![no_main]
use libfuzzer_sys::fuzz_target;
use sentinel_mcp::schema_poisoning::{ObservationResult, SchemaLineageTracker};
use serde_json::Value;

// Fuzz the SchemaLineageTracker operations.
// Tests that schema observation and poisoning detection
// never panic regardless of input.

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first bytes to configure the tracker
    let mutation_threshold = (data[0] as f32) / 255.0; // 0.0 to 1.0
    let min_observations = data.get(1).copied().unwrap_or(3) as u32;
    let max_schemas = data.get(2).copied().unwrap_or(100) as usize;

    let tracker =
        SchemaLineageTracker::new(mutation_threshold, min_observations, max_schemas.max(1));

    // Generate tool name from remaining data
    let tool_name = if data.len() > 3 {
        std::str::from_utf8(&data[3..])
            .unwrap_or("fuzz_tool")
            .chars()
            .take(64)
            .collect::<String>()
    } else {
        "fuzz_tool".to_string()
    };

    // Try to parse remaining data as JSON schema
    let schema: Value = if data.len() > 10 {
        serde_json::from_slice(&data[10..]).unwrap_or(Value::Object(Default::default()))
    } else {
        Value::Object(Default::default())
    };

    // Test observe_schema - should never panic
    let result = tracker.observe_schema(&tool_name, &schema);
    match result {
        ObservationResult::FirstSeen => {}
        ObservationResult::Unchanged => {}
        ObservationResult::MinorChange { similarity } => {
            assert!(similarity >= 0.0 && similarity <= 1.0);
        }
        ObservationResult::MajorChange { similarity, alert: _ } => {
            assert!(similarity >= 0.0 && similarity <= 1.0);
        }
    }

    // Test detect_poisoning - should never panic
    let _ = tracker.detect_poisoning(&tool_name, &schema);

    // Test get_trust_score - should return valid range
    let trust = tracker.get_trust_score(&tool_name);
    assert!(trust >= 0.0 && trust <= 1.0);

    // Test get_lineage
    let _ = tracker.get_lineage(&tool_name);

    // Test increment_trust
    tracker.increment_trust(&tool_name, 0.1);

    // Test reset_trust
    tracker.reset_trust(&tool_name, 0.5);

    // Test tracked_count
    let _ = tracker.tracked_count();

    // Test remove
    tracker.remove(&tool_name);

    // Verify removal
    assert!(tracker.get_lineage(&tool_name).is_none());
});
