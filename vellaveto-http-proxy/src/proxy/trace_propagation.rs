//! Trace context propagation for distributed tracing (Phase 28).
//!
//! Provides W3C Trace Context extraction, Vellaveto span creation, and
//! upstream header injection. This module bridges the gap between incoming
//! `traceparent`/`tracestate` headers and outbound upstream requests.
//!
//! # Design
//!
//! - **Fail-open for tracing**: Missing trace context generates a new one
//!   (never breaks the request). This follows W3C guidance for intermediaries.
//! - **Zero allocation for hot path**: Uses `&str` returns where possible.
//! - **Trace overhead target**: <200ns per request (parse + span ID gen + header inject).

use axum::http::HeaderMap;
use vellaveto_audit::observability::TraceContext;

/// Extract W3C Trace Context from incoming HTTP headers.
///
/// Parses `traceparent` and `tracestate` headers. If `traceparent` is missing
/// or invalid, generates a new trace context (fail-open for observability).
pub fn extract_trace_context(headers: &HeaderMap) -> TraceContext {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok());

    let mut ctx = match traceparent {
        Some(tp) => TraceContext::parse_traceparent(tp).unwrap_or_default(),
        None => TraceContext::default(),
    };

    // Ensure we always have a trace_id
    ctx.ensure_trace_id();

    // Parse tracestate if present
    if let Some(ts) = headers.get("tracestate").and_then(|v| v.to_str().ok()) {
        if !ts.is_empty() {
            ctx = ctx.with_parsed_tracestate(ts);
        }
    }

    ctx
}

/// Create a Vellaveto processing span as a child of the incoming trace context.
///
/// Returns `(child_context, vellaveto_span_id)` where:
/// - `child_context` has a new span_id representing Vellaveto's processing
/// - `vellaveto_span_id` is the span ID for Vellaveto's own span (for audit/logging)
pub fn create_vellaveto_span(parent: &TraceContext) -> (TraceContext, String) {
    let child = parent.child();
    let span_id = child
        .parent_span_id
        .clone()
        .unwrap_or_else(TraceContext::new_span_id);
    (child, span_id)
}

/// Build `traceparent` and `tracestate` header values for upstream requests.
///
/// The returned traceparent places Vellaveto's span as the parent of the
/// upstream call. The tracestate includes `vellaveto=<verdict>` prepended
/// to any existing vendor state.
///
/// Returns `(traceparent, Option<tracestate>)`.
pub fn build_upstream_headers(
    ctx: &TraceContext,
    verdict: &str,
) -> (String, Option<String>) {
    let upstream_ctx = ctx.clone().with_vellaveto_verdict(verdict);

    let traceparent = upstream_ctx
        .to_traceparent()
        .unwrap_or_else(|| {
            // Fallback: generate a minimal valid traceparent
            let trace_id = ctx
                .trace_id
                .as_deref()
                .unwrap_or("00000000000000000000000000000000");
            let span_id = ctx
                .parent_span_id
                .as_deref()
                .unwrap_or("0000000000000000");
            format!("00-{}-{}-{:02x}", trace_id, span_id, ctx.trace_flags)
        });

    let tracestate = upstream_ctx.trace_state;

    (traceparent, tracestate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_trace_context_with_valid_traceparent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );

        let ctx = extract_trace_context(&headers);
        assert_eq!(
            ctx.trace_id,
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
        assert_eq!(ctx.parent_span_id, Some("b7ad6b7169203331".to_string()));
        assert_eq!(ctx.trace_flags, 1);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_extract_trace_context_with_tracestate() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "tracestate",
            "congo=lZWRzIHRoNhcm5hcw,rojo=00f067aa0ba902b7"
                .parse()
                .unwrap(),
        );

        let ctx = extract_trace_context(&headers);
        assert_eq!(
            ctx.trace_state,
            Some("congo=lZWRzIHRoNhcm5hcw,rojo=00f067aa0ba902b7".to_string())
        );
    }

    #[test]
    fn test_extract_trace_context_missing_generates_new() {
        let headers = HeaderMap::new();
        let ctx = extract_trace_context(&headers);

        // Should have generated a trace_id
        assert!(ctx.trace_id.is_some());
        let trace_id = ctx.trace_id.as_ref().unwrap();
        assert_eq!(trace_id.len(), 32);
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_extract_trace_context_invalid_traceparent_generates_new() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "garbage".parse().unwrap());

        let ctx = extract_trace_context(&headers);
        assert!(ctx.trace_id.is_some());
    }

    #[test]
    fn test_create_vellaveto_span_returns_child() {
        let parent = TraceContext {
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
            parent_span_id: Some("b7ad6b7169203331".to_string()),
            trace_flags: 1,
            trace_state: None,
        };

        let (child, span_id) = create_vellaveto_span(&parent);
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.trace_flags, parent.trace_flags);
        assert_ne!(child.parent_span_id, parent.parent_span_id);
        assert_eq!(span_id.len(), 16);
        assert!(span_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_upstream_headers_with_verdict() {
        let ctx = TraceContext {
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
            parent_span_id: Some("b7ad6b7169203331".to_string()),
            trace_flags: 1,
            trace_state: None,
        };

        let (traceparent, tracestate) = build_upstream_headers(&ctx, "allow");
        assert!(traceparent.starts_with("00-0af7651916cd43dd8448eb211c80319c-"));
        assert!(traceparent.ends_with("-01"));
        assert_eq!(tracestate, Some("vellaveto=allow".to_string()));
    }
}
