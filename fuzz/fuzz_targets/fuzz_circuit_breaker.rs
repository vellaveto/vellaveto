#![no_main]
use libfuzzer_sys::fuzz_target;
use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
use vellaveto_types::CircuitState;

// Fuzz the CircuitBreakerManager operations.
// Tests that recording successes/failures and state transitions
// never panic regardless of input sequence.

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first bytes to configure the circuit breaker
    let failure_threshold = data[0].saturating_add(1) as u32;
    let success_threshold = data.get(1).copied().unwrap_or(3).saturating_add(1) as u32;
    let open_duration = data.get(2).copied().unwrap_or(30) as u64;

    let manager = CircuitBreakerManager::new(failure_threshold, success_threshold, open_duration);

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

    // Test can_proceed - should never panic
    let _ = manager.can_proceed(&tool_name);

    // Record some failures/successes based on data bytes
    for byte in data.iter().skip(3) {
        if byte % 2 == 0 {
            let _ = manager.record_failure(&tool_name);
        } else {
            manager.record_success(&tool_name);
        }
    }

    // Test state queries - should never panic
    let state = manager.get_state(&tool_name);
    assert!(matches!(
        state,
        CircuitState::Closed | CircuitState::Open | CircuitState::HalfOpen
    ));

    // Test stats retrieval
    let _ = manager.get_stats(&tool_name);

    // Test recovery check
    let _ = manager.is_recovering(&tool_name);

    // Test tracked tools
    let _ = manager.tracked_tools();

    // Test summary
    let _ = manager.summary();

    // Test reset (may be rejected if cooldown hasn't elapsed — that's OK)
    let _ = manager.reset(&tool_name);
});
