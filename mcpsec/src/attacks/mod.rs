//! Attack registry — defines all 64 test cases across 12 attack classes.

pub mod a01_injection;
pub mod a02_rug_pull;
pub mod a03_parameter;
pub mod a04_dlp;
pub mod a05_deputy;
pub mod a06_memory;
pub mod a07_squatting;
pub mod a08_audit;
pub mod a09_ssrf;
pub mod a10_dos;
pub mod a11_elicitation;
pub mod a12_covert;

/// A single attack test case.
pub struct AttackTest {
    /// Unique identifier (e.g., "A1.1").
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Attack class name.
    pub class: &'static str,
    /// The JSON payload to send to the gateway.
    pub payload: serde_json::Value,
    /// Function to check whether the gateway handled the attack correctly.
    /// Takes the response body and HTTP status code, returns true if the gateway passed.
    pub check_fn: fn(&serde_json::Value, u16) -> bool,
}

/// Check if the response verdict is Deny.
pub fn is_deny(body: &serde_json::Value, status: u16) -> bool {
    if status == 403 || status == 429 {
        return true;
    }
    // Vellaveto: {"verdict": {"Deny": {"reason": "..."}}}
    if body.get("verdict").and_then(|v| v.get("Deny")).is_some() {
        return true;
    }
    // Simple: {"verdict": "Deny"} or {"verdict": "deny"}
    if let Some(v) = body.get("verdict").and_then(|v| v.as_str()) {
        if v.eq_ignore_ascii_case("deny") {
            return true;
        }
    }
    false
}

/// Check if the response verdict is Allow.
pub fn is_allow(body: &serde_json::Value, _status: u16) -> bool {
    if let Some(v) = body.get("verdict").and_then(|v| v.as_str()) {
        return v.eq_ignore_ascii_case("allow");
    }
    body.get("verdict") == Some(&serde_json::json!("Allow"))
}

/// Check if injection was flagged in the response.
pub fn has_injection(body: &serde_json::Value, _status: u16) -> bool {
    // inspection.injection_detected
    if let Some(insp) = body.get("inspection") {
        if insp.get("injection_detected") == Some(&serde_json::json!(true)) {
            return true;
        }
        if let Some(arr) = insp.get("injection_patterns").and_then(|p| p.as_array()) {
            if !arr.is_empty() {
                return true;
            }
        }
    }
    // Also count Deny as passing for injection tests (gateway blocked it)
    is_deny(body, _status)
}

/// Check if DLP findings are present.
pub fn has_dlp(body: &serde_json::Value, _status: u16) -> bool {
    if let Some(insp) = body.get("inspection") {
        if let Some(arr) = insp.get("dlp_findings").and_then(|d| d.as_array()) {
            if !arr.is_empty() {
                return true;
            }
        }
    }
    // Deny also counts as passing for DLP (gateway blocked exfiltration)
    is_deny(body, _status)
}

/// Check that the response does NOT flag anything (false positive check).
pub fn is_clean(body: &serde_json::Value, status: u16) -> bool {
    is_allow(body, status) && !has_injection(body, status) && !has_dlp(body, status)
}

/// Return all 64 attack test cases.
pub fn all_tests() -> Vec<AttackTest> {
    let mut tests = Vec::with_capacity(64);
    tests.extend(a01_injection::tests());
    tests.extend(a02_rug_pull::tests());
    tests.extend(a03_parameter::tests());
    tests.extend(a04_dlp::tests());
    tests.extend(a05_deputy::tests());
    tests.extend(a06_memory::tests());
    tests.extend(a07_squatting::tests());
    tests.extend(a08_audit::tests());
    tests.extend(a09_ssrf::tests());
    tests.extend(a10_dos::tests());
    tests.extend(a11_elicitation::tests());
    tests.extend(a12_covert::tests());
    tests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tests_count() {
        let tests = all_tests();
        assert_eq!(tests.len(), 64, "Expected 64 test cases, got {}", tests.len());
    }

    #[test]
    fn test_unique_ids() {
        let tests = all_tests();
        let mut ids: Vec<&str> = tests.iter().map(|t| t.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), tests.len(), "All test IDs must be unique");
    }

    #[test]
    fn test_is_deny_vellaveto_format() {
        let body = serde_json::json!({"verdict": {"Deny": {"reason": "blocked"}}});
        assert!(is_deny(&body, 200));
    }

    #[test]
    fn test_is_deny_simple_format() {
        let body = serde_json::json!({"verdict": "Deny"});
        assert!(is_deny(&body, 200));
    }

    #[test]
    fn test_is_deny_http_403() {
        let body = serde_json::json!({});
        assert!(is_deny(&body, 403));
    }

    #[test]
    fn test_is_allow() {
        let body = serde_json::json!({"verdict": "Allow"});
        assert!(is_allow(&body, 200));
    }
}
