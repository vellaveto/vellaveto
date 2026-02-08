//! CIMD (Capability-Indexed Message Dispatch) for MCP 2025-11-25.
//!
//! Parses and validates MCP capability declarations from clients.
//! Capabilities allow servers to advertise features and clients to
//! negotiate which features they support.
//!
//! # Example
//!
//! ```rust
//! use sentinel_mcp::capability::{parse_capabilities, capabilities_satisfy};
//!
//! // Parse capability header
//! let caps = parse_capabilities("tools/1.0, sampling, resources").unwrap();
//! assert_eq!(caps.len(), 3);
//!
//! // Check if capabilities satisfy requirements
//! let required = vec!["tools".to_string()];
//! assert!(capabilities_satisfy(&caps, &required));
//! ```

use sentinel_types::McpCapability;

/// Parse a capability header string into a list of capabilities.
///
/// The header format is comma-separated capability names with optional versions:
/// - `tools` - capability without version
/// - `tools/1.0` - capability with version
/// - `tools(read,write)` - capability with sub-capabilities
/// - `tools/1.0(read,write)` - capability with version and sub-capabilities
///
/// # Arguments
/// * `header` - The capability header string to parse
///
/// # Returns
/// A list of parsed capabilities, or an error if parsing fails.
pub fn parse_capabilities(header: &str) -> Result<Vec<McpCapability>, String> {
    if header.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut capabilities = Vec::new();

    // Split by commas, but not within parentheses
    let parts = split_capabilities(header);

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let cap = parse_single_capability(part)?;
        capabilities.push(cap);
    }

    Ok(capabilities)
}

/// Split capability string by commas, respecting parentheses.
fn split_capabilities(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;

    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    // Don't forget the last part
    if start < s.len() {
        parts.push(&s[start..]);
    }

    parts
}

/// Parse a single capability string.
fn parse_single_capability(s: &str) -> Result<McpCapability, String> {
    let s = s.trim();

    // Check for sub-capabilities: name(sub1,sub2)
    let (name_version, subs) = if let Some(paren_start) = s.find('(') {
        let paren_end = s
            .find(')')
            .ok_or_else(|| format!("Unclosed parenthesis in capability: {}", s))?;

        let name_version = &s[..paren_start];
        let subs_str = &s[paren_start + 1..paren_end];

        let subs: Vec<String> = subs_str
            .split(',')
            .map(|sub| sub.trim().to_string())
            .filter(|sub| !sub.is_empty())
            .collect();

        (name_version, subs)
    } else {
        (s, Vec::new())
    };

    // Check for version: name/version
    let (name, version) = if let Some(slash_pos) = name_version.find('/') {
        let name = &name_version[..slash_pos];
        let version = &name_version[slash_pos + 1..];
        (name.to_string(), Some(version.to_string()))
    } else {
        (name_version.to_string(), None)
    };

    // Validate capability name
    if name.is_empty() {
        return Err("Empty capability name".to_string());
    }

    // Capability names should be alphanumeric with underscores/dashes
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(format!("Invalid capability name: {}", name));
    }

    Ok(McpCapability {
        name,
        version,
        sub_capabilities: subs,
    })
}

/// Check if a set of declared capabilities satisfies a list of required capabilities.
///
/// All required capabilities must be present in the declared list.
///
/// # Arguments
/// * `declared` - The capabilities declared by the client
/// * `required` - The capabilities required by policy
///
/// # Returns
/// `true` if all required capabilities are satisfied.
pub fn capabilities_satisfy(declared: &[McpCapability], required: &[String]) -> bool {
    for req in required {
        let found = declared.iter().any(|cap| {
            // Check if the capability name matches
            if cap.name == *req {
                return true;
            }

            // Check if it's a sub-capability match: "tools.read" matches "tools" with sub "read"
            if let Some((parent, sub)) = req.split_once('.') {
                return cap.name == parent && cap.has_sub(sub);
            }

            false
        });

        if !found {
            return false;
        }
    }

    true
}

/// Check if any blocked capability is declared.
///
/// # Arguments
/// * `declared` - The capabilities declared by the client
/// * `blocked` - The capabilities that must not be declared
///
/// # Returns
/// `Some(name)` of the first blocked capability found, or `None` if none are blocked.
pub fn find_blocked_capability<'a>(
    declared: &'a [McpCapability],
    blocked: &[String],
) -> Option<&'a str> {
    for cap in declared {
        // Check if the main capability is blocked
        if blocked.iter().any(|b| b == &cap.name) {
            return Some(&cap.name);
        }

        // Check if any sub-capability is blocked (format: "parent.sub")
        for sub in &cap.sub_capabilities {
            let full_name = format!("{}.{}", cap.name, sub);
            if blocked.iter().any(|b| b == &full_name) {
                return Some(&cap.name);
            }
        }
    }

    None
}

/// Format capabilities for a response header.
pub fn format_capabilities(capabilities: &[McpCapability]) -> String {
    capabilities
        .iter()
        .map(|cap| {
            let mut s = cap.name.clone();

            if let Some(ref version) = cap.version {
                s.push('/');
                s.push_str(version);
            }

            if !cap.sub_capabilities.is_empty() {
                s.push('(');
                s.push_str(&cap.sub_capabilities.join(","));
                s.push(')');
            }

            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_parse_simple() {
        let caps = parse_capabilities("tools").unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "tools");
        assert!(caps[0].version.is_none());
        assert!(caps[0].sub_capabilities.is_empty());
    }

    #[test]
    fn test_capability_parse_multiple() {
        let caps = parse_capabilities("tools, sampling, resources").unwrap();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0].name, "tools");
        assert_eq!(caps[1].name, "sampling");
        assert_eq!(caps[2].name, "resources");
    }

    #[test]
    fn test_capability_parse_versioned() {
        let caps = parse_capabilities("tools/1.0, sampling/2.1").unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].name, "tools");
        assert_eq!(caps[0].version, Some("1.0".to_string()));
        assert_eq!(caps[1].name, "sampling");
        assert_eq!(caps[1].version, Some("2.1".to_string()));
    }

    #[test]
    fn test_capability_parse_with_subs() {
        let caps = parse_capabilities("tools(read,write)").unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "tools");
        assert_eq!(caps[0].sub_capabilities, vec!["read", "write"]);
    }

    #[test]
    fn test_capability_parse_versioned_with_subs() {
        let caps = parse_capabilities("tools/1.0(read,write,execute)").unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "tools");
        assert_eq!(caps[0].version, Some("1.0".to_string()));
        assert_eq!(caps[0].sub_capabilities, vec!["read", "write", "execute"]);
    }

    #[test]
    fn test_capability_parse_empty() {
        let caps = parse_capabilities("").unwrap();
        assert!(caps.is_empty());

        let caps = parse_capabilities("   ").unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn test_capability_parse_invalid_name() {
        let result = parse_capabilities("tools@bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_parse_unclosed_paren() {
        let result = parse_capabilities("tools(read");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unclosed"));
    }

    #[test]
    fn test_capability_required_satisfied() {
        let declared = parse_capabilities("tools, sampling, resources").unwrap();
        let required = vec!["tools".to_string(), "sampling".to_string()];

        assert!(capabilities_satisfy(&declared, &required));
    }

    #[test]
    fn test_capability_required_not_satisfied() {
        let declared = parse_capabilities("tools").unwrap();
        let required = vec!["tools".to_string(), "sampling".to_string()];

        assert!(!capabilities_satisfy(&declared, &required));
    }

    #[test]
    fn test_capability_sub_required_satisfied() {
        let declared = parse_capabilities("tools(read,write)").unwrap();
        let required = vec!["tools.read".to_string()];

        assert!(capabilities_satisfy(&declared, &required));
    }

    #[test]
    fn test_capability_sub_required_not_satisfied() {
        let declared = parse_capabilities("tools(read)").unwrap();
        let required = vec!["tools.execute".to_string()];

        assert!(!capabilities_satisfy(&declared, &required));
    }

    #[test]
    fn test_capability_blocked_found() {
        let declared = parse_capabilities("tools, admin.dangerous").unwrap();
        let blocked = vec!["admin.dangerous".to_string()];

        let result = find_blocked_capability(&declared, &blocked);
        assert_eq!(result, Some("admin.dangerous"));
    }

    #[test]
    fn test_capability_blocked_not_found() {
        let declared = parse_capabilities("tools, resources").unwrap();
        let blocked = vec!["admin.dangerous".to_string()];

        let result = find_blocked_capability(&declared, &blocked);
        assert!(result.is_none());
    }

    #[test]
    fn test_capability_format() {
        let caps = vec![
            McpCapability {
                name: "tools".to_string(),
                version: Some("1.0".to_string()),
                sub_capabilities: vec!["read".to_string(), "write".to_string()],
            },
            McpCapability::new("sampling"),
        ];

        let formatted = format_capabilities(&caps);
        assert_eq!(formatted, "tools/1.0(read,write), sampling");
    }
}
