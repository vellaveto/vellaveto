#![no_main]
use libfuzzer_sys::fuzz_target;
use vellaveto_mcp::semantic_detection::{SemanticConfig, SemanticScanner};

// Create scanner once (static initialization would be ideal but libfuzzer doesn't support it well)
fn get_scanner() -> SemanticScanner {
    SemanticScanner::new(SemanticConfig::default()).expect("scanner should initialize")
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Limit input size to prevent excessive memory/time usage
        if s.len() > 10_000 {
            return;
        }

        let scanner = get_scanner();

        // Test score_text - must not panic on any UTF-8 input
        let (score, matched_template) = scanner.score_text(s);

        // Score should always be in valid range
        assert!(score >= 0.0 && score <= 1.0, "Score out of range: {}", score);

        // If score is above threshold, matched_template should be Some
        if score >= scanner.threshold() {
            assert!(
                matched_template.is_some(),
                "High score {} but no matched template",
                score
            );
        }

        // Test score_detailed - must also not panic
        let detailed = scanner.score_detailed(s);
        assert!(
            detailed.score >= 0.0 && detailed.score <= 1.0,
            "Detailed score out of range"
        );

        // Test scan_response with JSON value
        let json_val = serde_json::json!({
            "content": s,
            "nested": {
                "text": s
            }
        });
        let response_score = scanner.scan_response(&json_val);
        assert!(
            response_score.score >= 0.0 && response_score.score <= 1.0,
            "Response score out of range"
        );
    }
});
