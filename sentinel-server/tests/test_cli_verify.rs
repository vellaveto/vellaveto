//! CLI integration tests for the `sentinel verify` subcommand.

use std::process::Command;
use tempfile::TempDir;

fn sentinel_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
}

// ═══════════════════════════
// BASIC ARGUMENT HANDLING
// ═══════════════════════════

#[test]
fn verify_nonexistent_audit_file_fails() {
    let output = sentinel_bin()
        .args(["verify", "--audit", "/nonexistent/path/audit.log"])
        .output()
        .expect("failed to run sentinel");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Audit log not found"),
        "Expected 'not found' in stderr: {}",
        stderr
    );
}

#[test]
fn verify_empty_audit_log_passes() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");
    std::fs::write(&audit_path, "").unwrap();

    let output = sentinel_bin()
        .args(["verify", "--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Empty audit log should verify cleanly. stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("VERIFIED"), "Expected VERIFIED in: {}", stdout);
}

#[test]
fn verify_shows_hash_chain_and_checkpoint_results() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");
    std::fs::write(&audit_path, "").unwrap();

    let output = sentinel_bin()
        .args(["verify", "--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hash chain:"), "Expected chain result");
    assert!(stdout.contains("Checkpoints:"), "Expected checkpoint result");
}

// ═══════════════════════════
// VALID AUDIT LOG VERIFICATION
// ═══════════════════════════

#[test]
fn verify_valid_audit_log_with_entries() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");

    // Use the AuditLogger to create a properly hashed log
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let logger = sentinel_audit::AuditLogger::new_unredacted(audit_path.clone());
        logger.initialize_chain().await.unwrap();

        let action = sentinel_types::Action {
            tool: "file".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({"path": "/tmp/test.txt"}),
        };
        let verdict = sentinel_types::Verdict::Allow;
        logger
            .log_entry(&action, &verdict, serde_json::json!({}))
            .await
            .unwrap();

        let action2 = sentinel_types::Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: serde_json::json!({"command": "ls"}),
        };
        let verdict2 = sentinel_types::Verdict::Deny {
            reason: "blocked".to_string(),
        };
        logger
            .log_entry(&action2, &verdict2, serde_json::json!({}))
            .await
            .unwrap();
    });

    let output = sentinel_bin()
        .args(["verify", "--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Valid audit log should verify. stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("2 entries verified"),
        "Expected 2 entries verified in: {}",
        stdout
    );
    assert!(stdout.contains("VERIFIED"), "Expected VERIFIED in: {}", stdout);
}

// ═══════════════════════════
// TAMPERED AUDIT LOG DETECTION
// ═══════════════════════════

#[test]
fn verify_tampered_audit_log_fails() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");

    // Create a valid log first
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let logger = sentinel_audit::AuditLogger::new_unredacted(audit_path.clone());
        logger.initialize_chain().await.unwrap();

        for i in 0..3 {
            let action = sentinel_types::Action {
                tool: "file".to_string(),
                function: "read".to_string(),
                parameters: serde_json::json!({"path": format!("/tmp/test{}.txt", i)}),
            };
            let verdict = sentinel_types::Verdict::Allow {
                reason: "allowed".to_string(),
                matched_policy: "test".to_string(),
            };
            logger
                .log_entry(&action, &verdict, serde_json::json!({}))
                .await
                .unwrap();
        }
    });

    // Tamper with the second entry (change the tool name)
    let content = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 3, "Expected at least 3 entries");

    let mut tampered_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    // Replace the tool in the second entry
    tampered_lines[1] = tampered_lines[1].replace("\"file\"", "\"evil_tool\"");
    std::fs::write(&audit_path, tampered_lines.join("\n") + "\n").unwrap();

    let output = sentinel_bin()
        .args(["verify", "--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "Tampered audit log should fail verification. stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("BROKEN") || stdout.contains("FAILED"),
        "Expected BROKEN or FAILED in: {}",
        stdout
    );
}

// ═══════════════════════════
// CHECKPOINT VERIFICATION
// ═══════════════════════════

#[test]
fn verify_with_valid_checkpoints() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let signing_key = sentinel_audit::AuditLogger::generate_signing_key();
        let logger = sentinel_audit::AuditLogger::new_unredacted(audit_path.clone())
            .with_signing_key(signing_key);
        logger.initialize_chain().await.unwrap();

        let action = sentinel_types::Action {
            tool: "file".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({}),
        };
        let verdict = sentinel_types::Verdict::Allow;
        logger
            .log_entry(&action, &verdict, serde_json::json!({}))
            .await
            .unwrap();

        // Create a checkpoint
        logger.create_checkpoint().await.unwrap();
    });

    let output = sentinel_bin()
        .args(["verify", "--audit", audit_path.to_str().unwrap()])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Valid checkpoint should verify. stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 verified"),
        "Expected 1 checkpoint verified in: {}",
        stdout
    );
    assert!(stdout.contains("VERIFIED"), "Expected VERIFIED in: {}", stdout);
}

#[test]
fn verify_with_trusted_key_pinning() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let verifying_key_hex = rt.block_on(async {
        let signing_key = sentinel_audit::AuditLogger::generate_signing_key();
        let vk_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&signing_key.to_bytes())
                .verifying_key()
                .as_bytes(),
        );
        let logger = sentinel_audit::AuditLogger::new_unredacted(audit_path.clone())
            .with_signing_key(signing_key);
        logger.initialize_chain().await.unwrap();

        let action = sentinel_types::Action {
            tool: "file".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({}),
        };
        let verdict = sentinel_types::Verdict::Allow;
        logger
            .log_entry(&action, &verdict, serde_json::json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        vk_hex
    });

    // Verify with correct trusted key
    let output = sentinel_bin()
        .args([
            "verify",
            "--audit",
            audit_path.to_str().unwrap(),
            "--trusted-key",
            &verifying_key_hex,
        ])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Should pass with correct trusted key. stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("key pinned"), "Expected 'key pinned' in: {}", stdout);
    assert!(stdout.contains("VERIFIED"), "Expected VERIFIED in: {}", stdout);
}

#[test]
fn verify_with_wrong_trusted_key_fails() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let signing_key = sentinel_audit::AuditLogger::generate_signing_key();
        let logger = sentinel_audit::AuditLogger::new_unredacted(audit_path.clone())
            .with_signing_key(signing_key);
        logger.initialize_chain().await.unwrap();

        let action = sentinel_types::Action {
            tool: "file".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({}),
        };
        let verdict = sentinel_types::Verdict::Allow;
        logger
            .log_entry(&action, &verdict, serde_json::json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();
    });

    // Generate a different key to use as trusted key (won't match)
    let wrong_key = sentinel_audit::AuditLogger::generate_signing_key();
    let wrong_vk = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&wrong_key.to_bytes())
            .verifying_key()
            .as_bytes(),
    );

    let output = sentinel_bin()
        .args([
            "verify",
            "--audit",
            audit_path.to_str().unwrap(),
            "--trusted-key",
            &wrong_vk,
        ])
        .output()
        .expect("failed to run sentinel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "Should fail with wrong trusted key. stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("INVALID") || stdout.contains("FAILED"),
        "Expected INVALID or FAILED in: {}",
        stdout
    );
}

#[test]
fn verify_invalid_trusted_key_hex_fails() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");
    std::fs::write(&audit_path, "").unwrap();

    let output = sentinel_bin()
        .args([
            "verify",
            "--audit",
            audit_path.to_str().unwrap(),
            "--trusted-key",
            "not-valid-hex!",
        ])
        .output()
        .expect("failed to run sentinel");

    assert!(
        !output.status.success(),
        "Invalid hex key should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid --trusted-key hex"),
        "Expected hex error in: {}",
        stderr
    );
}

#[test]
fn verify_trusted_key_wrong_length_fails() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.log");
    std::fs::write(&audit_path, "").unwrap();

    let output = sentinel_bin()
        .args([
            "verify",
            "--audit",
            audit_path.to_str().unwrap(),
            "--trusted-key",
            "abcd1234", // Only 4 bytes, need 32
        ])
        .output()
        .expect("failed to run sentinel");

    assert!(
        !output.status.success(),
        "Wrong length key should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("32 bytes"),
        "Expected length error in: {}",
        stderr
    );
}
