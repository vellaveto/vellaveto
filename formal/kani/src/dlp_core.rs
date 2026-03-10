// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! DLP buffer arithmetic — extraction from
//! `vellaveto-mcp/src/inspection/verified_dlp_core.rs`.
//!
//! Pure functions for cross-call DLP buffer management. The algorithm is
//! identical to the production code. Verified by Verus (ALL inputs) and
//! Kani (bounded inputs) independently.

/// Check if a byte is a UTF-8 character boundary.
///
/// A byte is a character boundary if it is NOT a continuation byte (10xxxxxx).
#[inline]
pub fn is_utf8_char_boundary(b: u8) -> bool {
    (b & 0xC0) != 0x80
}

/// Extract the tail of a byte slice, adjusted to a valid UTF-8 character boundary.
///
/// Returns `(start, end)` indices into `value` such that:
/// - `value[start..end]` is at most `max_size` bytes (D2)
/// - `start` is at a UTF-8 character boundary (D1)
/// - `end == value.len()`
pub fn extract_tail(value: &[u8], max_size: usize) -> (usize, usize) {
    if value.is_empty() || max_size == 0 {
        return (value.len(), value.len());
    }

    let raw_start = value.len().saturating_sub(max_size);
    let mut start = raw_start;

    while start < value.len() && !is_utf8_char_boundary(value[start]) {
        start = start.saturating_add(1);
    }

    (start, value.len())
}

/// Check if a new field can be tracked without exceeding limits.
///
/// Returns `true` only if:
/// - `current_fields < max_fields` (D4: fail-closed at capacity)
/// - `current_bytes + new_buffer_bytes <= max_total_bytes` (no overflow)
pub fn can_track_field(
    current_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> bool {
    if current_fields >= max_fields {
        return false;
    }
    match current_bytes.checked_add(new_buffer_bytes) {
        Some(total) => total <= max_total_bytes,
        None => false,
    }
}

/// Update total byte accounting after replacing a buffer.
///
/// Uses saturating arithmetic to prevent underflow (D5).
pub fn update_total_bytes(old_total: usize, old_buffer_len: usize, new_buffer_len: usize) -> usize {
    old_total
        .saturating_sub(old_buffer_len)
        .saturating_add(new_buffer_len)
}

/// Compute the overlap scan region size.
pub fn compute_overlap_region_size(prev_tail_len: usize, current_value_len: usize) -> usize {
    prev_tail_len.saturating_add(current_value_len)
}

/// Check overlap completeness: can a secret split between calls be detected?
pub fn overlap_covers_secret(
    prev_value_len: usize,
    current_value_len: usize,
    overlap_size: usize,
    secret_len: usize,
    split_point: usize,
) -> bool {
    let prev_tail_len = prev_value_len.min(overlap_size);
    let combined_len = prev_tail_len.saturating_add(current_value_len);

    if split_point == 0 || split_point >= secret_len {
        return false;
    }
    if prev_tail_len < split_point
        || current_value_len < secret_len.saturating_sub(split_point)
    {
        return false;
    }

    combined_len >= secret_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_parity_char_boundary() {
        assert!(is_utf8_char_boundary(b'A'));
        assert!(!is_utf8_char_boundary(0x80));
        assert!(is_utf8_char_boundary(0xC0));
    }

    #[test]
    fn test_production_parity_extract_tail() {
        let value = "日本語".as_bytes();
        let (start, end) = extract_tail(value, 5);
        assert!(start <= end);
        assert!(end - start <= 5);
        assert!(std::str::from_utf8(&value[start..end]).is_ok());
    }

    #[test]
    fn test_production_parity_update_total() {
        assert_eq!(update_total_bytes(100, 30, 50), 120);
        assert_eq!(update_total_bytes(10, 50, 30), 30);
    }

    #[test]
    fn test_production_parity_overlap() {
        assert!(overlap_covers_secret(100, 100, 150, 20, 10));
        assert!(!overlap_covers_secret(5, 100, 150, 20, 10));
        assert!(!overlap_covers_secret(100, 100, 32, 40, 33));
    }
}
