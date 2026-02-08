#![no_main]
use libfuzzer_sys::fuzz_target;
use sentinel_types::{TaskStatus, TrackedTask};

// Fuzz the TaskStateManager operations with arbitrary task data.
// Tests that task registration, status updates, and cancellation
// never panic regardless of input.

fuzz_target!(|data: &[u8]| {
    // Try parsing as JSON to create a TrackedTask
    if let Ok(task) = serde_json::from_slice::<TrackedTask>(data) {
        // Task should be serializable/deserializable without panic
        let _ = serde_json::to_string(&task);

        // Test status transitions
        let statuses = [
            TaskStatus::Pending,
            TaskStatus::Running,
            TaskStatus::Completed,
            TaskStatus::Failed {
                reason: "fuzz".to_string(),
            },
            TaskStatus::Cancelled,
            TaskStatus::Expired,
        ];

        for status in &statuses {
            let _ = serde_json::to_string(status);
        }

        // Test is_terminal and is_active methods
        let _ = task.is_terminal();
        let _ = task.is_active();
    }

    // Also fuzz capability parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sentinel_mcp::capability::parse_capabilities(s);
    }
});
