//! Property-based tests for sentinel-audit.
//!
//! Per Directive C-16.2: Tests critical audit invariants:
//! - Hash chain integrity: arbitrary entries → verify_chain() always succeeds
//! - Checkpoint verification: N entries + checkpoint → verify always succeeds

use proptest::prelude::*;
use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

/// Generate an arbitrary Action.
fn arb_action() -> impl Strategy<Value = Action> {
    (
        "[a-z_]{1,15}",
        "[a-z_]{1,15}",
        prop_oneof![
            Just(json!({})),
            Just(json!({"path": "/tmp/test"})),
            Just(json!({"url": "https://example.com"})),
            Just(json!({"key": "value"})),
            Just(json!({"nested": {"a": 1, "b": "two"}})),
        ],
    )
        .prop_map(|(tool, function, parameters)| Action {
            tool,
            function,
            parameters,
        })
}

/// Generate an arbitrary Verdict.
fn arb_verdict() -> impl Strategy<Value = Verdict> {
    prop_oneof![
        Just(Verdict::Allow),
        "[a-z ]{3,30}".prop_map(|reason| Verdict::Deny { reason }),
        "[a-z ]{3,30}".prop_map(|reason| Verdict::RequireApproval { reason }),
    ]
}

/// Generate an arbitrary metadata Value.
fn arb_metadata() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        Just(json!({})),
        Just(json!({"source": "test"})),
        Just(json!({"request_id": "abc-123"})),
        Just(json!({"ip": "127.0.0.1", "user": "alice"})),
    ]
}

// ═══════════════════════════════════
// PROPERTY: Hash chain integrity — arbitrary entries always verify
// ═══════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn hash_chain_always_verifies(
        entries in prop::collection::vec(
            (arb_action(), arb_verdict(), arb_metadata()),
            1..=10,
        ),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = TempDir::new().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let logger = AuditLogger::new(log_path);

            // Log all entries
            for (action, verdict, metadata) in &entries {
                logger.log_entry(action, verdict, metadata.clone()).await.unwrap();
            }

            // Verify chain
            let verification = logger.verify_chain().await.unwrap();
            prop_assert!(verification.valid,
                "Hash chain must be valid after logging {} entries. \
                 First broken at: {:?}",
                entries.len(), verification.first_broken_at);
            prop_assert_eq!(verification.entries_checked, entries.len(),
                "Must have checked all {} entries", entries.len());

            Ok(())
        })?;
    }
}

// ═══════════════════════════════════
// PROPERTY: Checkpoint verification — entries + checkpoint always verify
// ═══════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(15))]
    #[test]
    fn checkpoint_always_verifies(
        entries in prop::collection::vec(
            (arb_action(), arb_verdict(), arb_metadata()),
            1..=8,
        ),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = TempDir::new().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let signing_key = AuditLogger::generate_signing_key();
            let logger = AuditLogger::new(log_path)
                .with_signing_key(signing_key);

            // Log all entries
            for (action, verdict, metadata) in &entries {
                logger.log_entry(action, verdict, metadata.clone()).await.unwrap();
            }

            // Create checkpoint
            let checkpoint = logger.create_checkpoint().await.unwrap();
            prop_assert_eq!(checkpoint.entry_count, entries.len(),
                "Checkpoint entry_count must match logged entries");

            // Verify checkpoints
            let verification = logger.verify_checkpoints().await.unwrap();
            prop_assert!(verification.valid,
                "Checkpoint verification must succeed after {} entries. \
                 Failure reason: {:?}",
                entries.len(), verification.failure_reason);
            prop_assert_eq!(verification.checkpoints_checked, 1);

            Ok(())
        })?;
    }
}

// ═══════════════════════════════════
// PROPERTY: Hash chain links — each entry's prev_hash matches prior entry_hash
// ═══════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn hash_chain_links_are_consistent(
        entry_count in 2..=8usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = TempDir::new().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let logger = AuditLogger::new(log_path);

            let action = Action {
                tool: "test".to_string(),
                function: "run".to_string(),
                parameters: json!({}),
            };

            for _ in 0..entry_count {
                logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
            }

            let entries = logger.load_entries().await.unwrap();
            prop_assert_eq!(entries.len(), entry_count);

            // First entry has no prev_hash
            prop_assert!(entries[0].prev_hash.is_none(),
                "First entry must have no prev_hash");
            prop_assert!(entries[0].entry_hash.is_some(),
                "First entry must have an entry_hash");

            // Each subsequent entry links to the previous
            for i in 1..entries.len() {
                let prev_hash = entries[i].prev_hash.as_ref();
                let expected = entries[i - 1].entry_hash.as_ref();
                prop_assert_eq!(prev_hash, expected,
                    "Entry {} prev_hash must match entry {} entry_hash.\n\
                     prev_hash: {:?}\n\
                     expected:  {:?}", i, i - 1, prev_hash, expected);
            }

            Ok(())
        })?;
    }
}

// ═══════════════════════════════════
// PROPERTY: Multiple checkpoints — all verify together
// ═══════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn multiple_checkpoints_all_verify(
        checkpoint_count in 2..=4usize,
        entries_per_checkpoint in 1..=4usize,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = TempDir::new().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let signing_key = AuditLogger::generate_signing_key();
            let logger = AuditLogger::new(log_path)
                .with_signing_key(signing_key);

            let action = Action {
                tool: "test".to_string(),
                function: "run".to_string(),
                parameters: json!({}),
            };

            for cp_idx in 0..checkpoint_count {
                for _ in 0..entries_per_checkpoint {
                    logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
                }
                let cp = logger.create_checkpoint().await.unwrap();
                let expected_count = (cp_idx + 1) * entries_per_checkpoint;
                prop_assert_eq!(cp.entry_count, expected_count,
                    "Checkpoint {} entry_count", cp_idx);
            }

            let verification = logger.verify_checkpoints().await.unwrap();
            prop_assert!(verification.valid,
                "All {} checkpoints must verify. Failure: {:?}",
                checkpoint_count, verification.failure_reason);
            prop_assert_eq!(verification.checkpoints_checked, checkpoint_count);

            Ok(())
        })?;
    }
}
