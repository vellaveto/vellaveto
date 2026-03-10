// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Shannon entropy verification extracted from
//! `vellaveto-engine/src/collusion.rs`.
//!
//! Pure function computing byte-level Shannon entropy, used as the
//! primary signal for steganography/exfiltration detection in the
//! collusion detector.
//!
//! # Verified Properties (K59)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K59 | Entropy is finite, non-negative, ≤ 8.0 (log2(256)), empty → 0.0 |
//!
//! # Production Correspondence
//!
//! - `compute_entropy` ↔ `vellaveto-engine/src/collusion.rs:646-673`

/// Compute Shannon entropy of a byte sequence.
///
/// Verbatim from production `CollusionDetector::compute_entropy`.
///
/// Returns a value in [0.0, 8.0] (log2(256) for uniformly random bytes).
/// Empty input returns 0.0. NaN/Infinity guarded to return 0.0.
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] = freq[byte as usize].saturating_add(1);
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    // Guard against NaN/Infinity from degenerate inputs.
    if !entropy.is_finite() {
        return 0.0;
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_returns_zero() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_single_byte_returns_zero() {
        // All same byte → zero entropy
        assert_eq!(compute_entropy(&[0x41; 100]), 0.0);
    }

    #[test]
    fn test_two_values_returns_one() {
        // Equal mix of two values → entropy = 1.0
        let data: Vec<u8> = (0..100).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        let e = compute_entropy(&data);
        assert!((e - 1.0).abs() < 0.001, "Expected ~1.0, got {e}");
    }

    #[test]
    fn test_uniform_256_values() {
        // All 256 byte values equally → entropy = 8.0
        let data: Vec<u8> = (0..=255).collect();
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.001, "Expected ~8.0, got {e}");
    }

    #[test]
    fn test_always_finite_non_negative() {
        let test_cases: Vec<Vec<u8>> =
            vec![vec![0], vec![0, 1], vec![0xFF; 1000], (0..=255).collect()];
        for data in &test_cases {
            let e = compute_entropy(data);
            assert!(
                e.is_finite(),
                "Entropy not finite for input len {}",
                data.len()
            );
            assert!(e >= 0.0, "Entropy negative for input len {}", data.len());
            assert!(e <= 8.0, "Entropy > 8.0 for input len {}", data.len());
        }
    }
}
