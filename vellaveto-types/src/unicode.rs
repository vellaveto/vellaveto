// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Unicode security utilities for identity and tool name normalization.
//!
//! This module provides functions to normalize Unicode confusables (homoglyphs)
//! to their ASCII equivalents. This is critical for security checks like:
//! - Self-approval prevention (preventing "admin" vs "аdmin" bypass)
//! - Tool squatting detection (preventing "bash" vs "bаsh" spoofing)
//!
//! # Security Background
//!
//! NFKC normalization converts compatibility characters (e.g., fullwidth Latin)
//! to their canonical forms, but does NOT convert cross-script homoglyphs like
//! Cyrillic 'а' (U+0430) to Latin 'a' (U+0061). This module provides explicit
//! mapping for common confusables used in spoofing attacks.

/// Map common Unicode confusables to their ASCII equivalents.
///
/// Covers Cyrillic (lowercase + uppercase), Greek, fullwidth Latin,
/// and other common homoglyphs used in identity spoofing and tool squatting.
///
/// # Security
///
/// This function is used by:
/// - `vellaveto-approval` for self-approval prevention
/// - `vellaveto-mcp` for tool squatting detection
///
/// Both callers should apply this normalization AFTER NFKC normalization
/// and case folding for comprehensive coverage.
///
/// # Example
///
/// ```
/// use vellaveto_types::unicode::normalize_homoglyphs;
///
/// // Cyrillic 'а' (U+0430) maps to Latin 'a'
/// assert_eq!(normalize_homoglyphs("аdmin"), "admin");
///
/// // Mixed Cyrillic/Latin spoofing detected
/// assert_eq!(normalize_homoglyphs("pаssword"), "password");
///
/// // Fullwidth Latin normalized (after NFKC would already handle this)
/// assert_eq!(normalize_homoglyphs("\u{FF42}ash"), "bash");
/// ```
pub fn normalize_homoglyphs(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // ═══════════════════════════════════════════════════════════════
            // Cyrillic lowercase confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{0430}' => 'a', // Cyrillic a -> a
            '\u{0432}' => 'b', // Cyrillic ve -> b (visually similar in some fonts)
            '\u{0435}' => 'e', // Cyrillic ie -> e
            '\u{043A}' => 'k', // Cyrillic ka -> k
            '\u{043C}' => 'm', // Cyrillic em -> m
            '\u{043D}' => 'h', // Cyrillic en -> h
            '\u{043E}' => 'o', // Cyrillic o -> o
            '\u{0440}' => 'p', // Cyrillic er -> p
            '\u{0441}' => 'c', // Cyrillic es -> c
            '\u{0442}' => 't', // Cyrillic te -> t (in upright fonts)
            '\u{0443}' => 'y', // Cyrillic u -> y
            '\u{0445}' => 'x', // Cyrillic ha -> x
            '\u{0456}' => 'i', // Cyrillic i -> i
            '\u{0458}' => 'j', // Cyrillic je -> j
            '\u{04BB}' => 'h', // Cyrillic shha -> h
            '\u{0455}' => 's', // Cyrillic dze -> s
            '\u{0454}' => 'e', // Cyrillic ukrainian ie -> e
            '\u{044A}' => 'b', // Cyrillic hard sign -> b (visual)

            // ═══════════════════════════════════════════════════════════════
            // Cyrillic uppercase confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{0410}' => 'a', // Cyrillic A -> a
            '\u{0412}' => 'b', // Cyrillic Ve -> b
            '\u{0415}' => 'e', // Cyrillic Ie -> e
            '\u{041A}' => 'k', // Cyrillic Ka -> k
            '\u{041C}' => 'm', // Cyrillic Em -> m
            '\u{041D}' => 'h', // Cyrillic En -> h
            '\u{041E}' => 'o', // Cyrillic O -> o
            '\u{0420}' => 'p', // Cyrillic Er -> p
            '\u{0421}' => 'c', // Cyrillic Es -> c
            '\u{0422}' => 't', // Cyrillic Te -> t
            '\u{0423}' => 'y', // Cyrillic U -> y
            '\u{0425}' => 'x', // Cyrillic Ha -> x
            '\u{0405}' => 's', // Cyrillic Dze -> s
            '\u{0406}' => 'i', // Cyrillic I -> i
            '\u{0408}' => 'j', // Cyrillic Je -> j

            // ═══════════════════════════════════════════════════════════════
            // Greek lowercase confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{03B1}' => 'a', // alpha -> a
            '\u{03B2}' => 'b', // R228-INJ-2: beta -> b (mirrors uppercase Beta mapping)
            '\u{03B5}' => 'e', // epsilon -> e
            '\u{03B7}' => 'h', // R228-INJ-2: eta -> h (mirrors uppercase Eta mapping)
            '\u{03B9}' => 'i', // iota -> i
            '\u{03BA}' => 'k', // kappa -> k
            '\u{03BC}' => 'm', // R228-INJ-2: mu -> m (mirrors uppercase Mu mapping)
            '\u{03BD}' => 'v', // nu -> v (visually similar)
            '\u{03BF}' => 'o', // omicron -> o
            '\u{03C1}' => 'p', // rho -> p
            '\u{03C4}' => 't', // tau -> t
            '\u{03C5}' => 'u', // upsilon -> u
            '\u{03C7}' => 'x', // chi -> x
            '\u{03C9}' => 'w', // R228-INJ-2: omega -> w (visual similarity)
            '\u{03B6}' => 'z', // R228-INJ-2: zeta -> z (mirrors uppercase Zeta mapping)

            // ═══════════════════════════════════════════════════════════════
            // Greek uppercase confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{0391}' => 'a', // Alpha -> a
            '\u{0392}' => 'b', // Beta -> b
            '\u{0395}' => 'e', // Epsilon -> e
            '\u{0397}' => 'h', // Eta -> h
            '\u{0399}' => 'i', // Iota -> i
            '\u{039A}' => 'k', // Kappa -> k
            '\u{039C}' => 'm', // Mu -> m
            '\u{039D}' => 'n', // Nu -> n
            '\u{039F}' => 'o', // Omicron -> o
            '\u{03A1}' => 'p', // Rho -> p
            '\u{03A4}' => 't', // Tau -> t
            '\u{03A7}' => 'x', // Chi -> x
            '\u{03A5}' => 'y', // Upsilon -> y
            '\u{0396}' => 'z', // Zeta -> z

            // ═══════════════════════════════════════════════════════════════
            // R229-TYP-5: Armenian confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{0561}' => 'a', // Armenian small ayb -> a
            '\u{0570}' => 'h', // Armenian small ho -> h
            '\u{0578}' => 'n', // Armenian small now -> n (visual similarity in some fonts)
            '\u{0585}' => 'o', // Armenian small oh -> o
            '\u{057D}' => 's', // Armenian small seh -> s
            '\u{0582}' => 'u', // Armenian small yiwn -> u (visual similarity)

            // ═══════════════════════════════════════════════════════════════
            // Fullwidth Latin (U+FF01..U+FF5E map to U+0021..U+007E)
            // Note: NFKC handles these, but we include for defense-in-depth
            // ═══════════════════════════════════════════════════════════════
            c @ '\u{FF21}'..='\u{FF3A}' => (c as u32 - 0xFF21 + b'a' as u32) as u8 as char,
            c @ '\u{FF41}'..='\u{FF5A}' => (c as u32 - 0xFF41 + b'a' as u32) as u8 as char,
            c @ '\u{FF10}'..='\u{FF19}' => (c as u32 - 0xFF10 + b'0' as u32) as u8 as char,
            '\u{FF3F}' => '_', // Fullwidth underscore -> _

            // ═══════════════════════════════════════════════════════════════
            // R231-TYP-8: Cyrillic Extended-B Palochka (visually identical to I/l)
            // ═══════════════════════════════════════════════════════════════
            '\u{04C0}' => 'i', // Cyrillic Palochka (uppercase) -> i
            '\u{04CF}' => 'l', // Cyrillic Small Palochka -> l

            // ═══════════════════════════════════════════════════════════════
            // R231-TYP-4: Cherokee script confusables
            // Per Unicode TR39 confusables.txt — Cherokee syllabary letters
            // that are visually identical to Latin letters in most fonts.
            // ═══════════════════════════════════════════════════════════════
            '\u{13AA}' => 'g', // Cherokee GO -> G
            '\u{13B3}' => 'w', // Cherokee LA -> W
            '\u{13CB}' => 'h', // Cherokee MI -> H (Ꮋ)
            '\u{13A1}' => 'e', // Cherokee E -> E (Ꭱ)
            '\u{13A2}' => 'r', // Cherokee I -> R (Ꭲ, visual in serif fonts)
            '\u{13DA}' => 's', // Cherokee DU -> S (Ꮪ, visual similarity)
            '\u{13E4}' => 't', // Cherokee TA -> T (Ꮤ)
            '\u{13AC}' => 'h', // Cherokee HA -> H (Ꭼ, visual in some fonts)
            '\u{13D9}' => 'v', // Cherokee DO -> V (Ꮩ)
            '\u{13CF}' => 'b', // Cherokee SI -> b (Ꮟ, reversed visual)
            '\u{13D2}' => 'p', // Cherokee TLI -> P (Ꮲ)
            '\u{13A0}' => 'd', // Cherokee A -> D (Ꭰ)

            // ═══════════════════════════════════════════════════════════════
            // Other common confusables
            // ═══════════════════════════════════════════════════════════════
            '\u{0131}' => 'i', // dotless i -> i
            '\u{1D00}' => 'a', // small capital A -> a
            '\u{0261}' => 'g', // latin small letter script g -> g
            '\u{01C0}' => 'l', // latin letter dental click -> l
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}' => '-', // various dashes -> hyphen
            '\u{2018}' | '\u{2019}' | '\u{02BC}' => '\'', // curly quotes -> apostrophe

            // Pass through all other characters unchanged
            other => other,
        })
        .collect()
}

/// Normalize an identity string for security comparison.
///
/// Applies `to_lowercase()` followed by `normalize_homoglyphs()` to produce
/// a canonical form for identity comparison. This catches:
/// - ASCII case variations ("AgentAlpha" vs "agentalpha")
/// - Cyrillic/Greek/fullwidth homoglyph spoofing ("аgent" vs "agent")
///
/// Used by self-delegation and self-approval checks to prevent bypass via
/// confusable characters.
///
/// # Note
///
/// The `vellaveto-approval` crate additionally applies NFKC normalization
/// (via `unicode-normalization` crate) before this pipeline. NFKC catches
/// rare compatibility forms (e.g., circled letters U+24B6). This function
/// does NOT include NFKC to avoid adding `unicode-normalization` as a
/// dependency of the `vellaveto-types` leaf crate. The `normalize_homoglyphs`
/// function already covers fullwidth Latin as defense-in-depth.
///
/// # Example
///
/// ```
/// use vellaveto_types::unicode::normalize_identity;
///
/// // Case-insensitive
/// assert_eq!(normalize_identity("AgentAlpha"), normalize_identity("agentalpha"));
///
/// // Cyrillic homoglyph detected
/// assert_eq!(normalize_identity("\u{0430}gent"), normalize_identity("agent"));
/// ```
pub fn normalize_identity(s: &str) -> String {
    normalize_homoglyphs(&s.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════════════════════════
    // P0 Fix: Self-Approval Homoglyph Bypass Prevention Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cyrillic_a_to_latin_a() {
        // P0: Cyrillic 'а' (U+0430) must map to Latin 'a'
        // This is the primary attack vector for self-approval bypass
        assert_eq!(normalize_homoglyphs("аdmin"), "admin");
        assert_eq!(normalize_homoglyphs("\u{0430}dmin"), "admin");
    }

    #[test]
    fn test_cyrillic_spoofed_admin() {
        // Various Cyrillic spoofing attempts for "admin"
        assert_eq!(normalize_homoglyphs("аdmin"), "admin"); // Cyrillic а
        assert_eq!(normalize_homoglyphs("admіn"), "admin"); // Cyrillic і
        assert_eq!(normalize_homoglyphs("аdmіn"), "admin"); // Both
    }

    #[test]
    fn test_cyrillic_spoofed_password() {
        // Cyrillic spoofing of "password"
        assert_eq!(normalize_homoglyphs("раssword"), "password"); // Cyrillic р
        assert_eq!(normalize_homoglyphs("pаsswоrd"), "password"); // Cyrillic а and о
    }

    #[test]
    fn test_greek_spoofed_admin() {
        // Greek alphabet spoofing
        assert_eq!(normalize_homoglyphs("αdmin"), "admin"); // Greek alpha
        assert_eq!(normalize_homoglyphs("admιn"), "admin"); // Greek iota
    }

    #[test]
    fn test_fully_spoofed_tool_name() {
        // Tool names fully composed of confusables
        // "read_file" using Cyrillic: r + е(U+0435) + а(U+0430) + d + _ + f + і(U+0456) + l + е(U+0435)
        let spoofed = "r\u{0435}\u{0430}d_f\u{0456}l\u{0435}";
        assert_eq!(normalize_homoglyphs(spoofed), "read_file");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cyrillic Lowercase Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cyrillic_lowercase_comprehensive() {
        assert_eq!(normalize_homoglyphs("\u{0430}"), "a"); // а -> a
        assert_eq!(normalize_homoglyphs("\u{0435}"), "e"); // е -> e
        assert_eq!(normalize_homoglyphs("\u{043E}"), "o"); // о -> o
        assert_eq!(normalize_homoglyphs("\u{0440}"), "p"); // р -> p
        assert_eq!(normalize_homoglyphs("\u{0441}"), "c"); // с -> c
        assert_eq!(normalize_homoglyphs("\u{0445}"), "x"); // х -> x
        assert_eq!(normalize_homoglyphs("\u{0443}"), "y"); // у -> y
        assert_eq!(normalize_homoglyphs("\u{0456}"), "i"); // і -> i
        assert_eq!(normalize_homoglyphs("\u{0458}"), "j"); // ј -> j
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cyrillic Uppercase Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cyrillic_uppercase_comprehensive() {
        assert_eq!(normalize_homoglyphs("\u{0410}"), "a"); // А -> a
        assert_eq!(normalize_homoglyphs("\u{0415}"), "e"); // Е -> e
        assert_eq!(normalize_homoglyphs("\u{041E}"), "o"); // О -> o
        assert_eq!(normalize_homoglyphs("\u{0420}"), "p"); // Р -> p
        assert_eq!(normalize_homoglyphs("\u{0421}"), "c"); // С -> c
        assert_eq!(normalize_homoglyphs("\u{0423}"), "y"); // У -> y
        assert_eq!(normalize_homoglyphs("\u{0408}"), "j"); // Ј -> j
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fullwidth Latin Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fullwidth_latin() {
        // Fullwidth "ADMIN" -> "admin"
        assert_eq!(
            normalize_homoglyphs("\u{FF21}\u{FF24}\u{FF2D}\u{FF29}\u{FF2E}"),
            "admin"
        );
        // Fullwidth lowercase "bash"
        assert_eq!(
            normalize_homoglyphs("\u{FF42}\u{FF41}\u{FF53}\u{FF48}"),
            "bash"
        );
        // Fullwidth digits
        assert_eq!(normalize_homoglyphs("\u{FF10}\u{FF11}\u{FF12}"), "012");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Greek Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_greek_confusables() {
        assert_eq!(normalize_homoglyphs("\u{03B1}"), "a"); // α -> a
        assert_eq!(normalize_homoglyphs("\u{03B5}"), "e"); // ε -> e
        assert_eq!(normalize_homoglyphs("\u{03B9}"), "i"); // ι -> i
        assert_eq!(normalize_homoglyphs("\u{03BF}"), "o"); // ο -> o
        assert_eq!(normalize_homoglyphs("\u{03C1}"), "p"); // ρ -> p
        assert_eq!(normalize_homoglyphs("\u{03C4}"), "t"); // τ -> t
        assert_eq!(normalize_homoglyphs("\u{03C7}"), "x"); // χ -> x
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Edge Cases
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_already_ascii_unchanged() {
        assert_eq!(normalize_homoglyphs("admin"), "admin");
        assert_eq!(normalize_homoglyphs("read_file"), "read_file");
        assert_eq!(normalize_homoglyphs("user@example.com"), "user@example.com");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(normalize_homoglyphs(""), "");
    }

    #[test]
    fn test_various_dashes() {
        // All dash variants should normalize to hyphen-minus
        assert_eq!(normalize_homoglyphs("foo\u{2010}bar"), "foo-bar"); // hyphen
        assert_eq!(normalize_homoglyphs("foo\u{2013}bar"), "foo-bar"); // en-dash
        assert_eq!(normalize_homoglyphs("foo\u{2014}bar"), "foo-bar"); // em-dash
    }

    #[test]
    fn test_curly_quotes() {
        assert_eq!(normalize_homoglyphs("it\u{2019}s"), "it's"); // right single quote
        assert_eq!(normalize_homoglyphs("\u{2018}test\u{2019}"), "'test'"); // curly quotes
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Security: Ensure no bypass paths
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_self_approval_bypass_prevented() {
        // Scenario: Attacker "admin" tries to self-approve using "аdmin" (Cyrillic)
        let requester = "admin";
        let attacker_approver = "аdmin"; // Cyrillic а

        let normalized_req = normalize_homoglyphs(requester);
        let normalized_app = normalize_homoglyphs(attacker_approver);

        // After normalization, they MUST be equal to prevent bypass
        assert_eq!(
            normalized_req, normalized_app,
            "Self-approval bypass: Cyrillic homoglyph must normalize to same value"
        );
    }

    #[test]
    fn test_email_style_identity_spoofing() {
        // Email-style identities with Cyrillic
        let real = "alice@example.com";
        let spoofed = "аlice@example.com"; // Cyrillic а

        assert_eq!(
            normalize_homoglyphs(real),
            normalize_homoglyphs(spoofed),
            "Email identity spoofing must be detected"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // IMP-R186-009: normalize_identity unit tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_normalize_identity_empty_string() {
        assert_eq!(normalize_identity(""), "");
    }

    #[test]
    fn test_normalize_identity_pure_ascii() {
        assert_eq!(normalize_identity("admin"), "admin");
    }

    #[test]
    fn test_normalize_identity_case_folding() {
        assert_eq!(normalize_identity("AgentAlpha"), "agentalpha");
        assert_eq!(normalize_identity("ADMIN"), "admin");
    }

    #[test]
    fn test_normalize_identity_cyrillic_with_case() {
        // Uppercase Cyrillic А (U+0410) -> lowercase via to_lowercase -> 'а' (U+0430)
        // -> homoglyph mapping -> Latin 'a'
        assert_eq!(
            normalize_identity("\u{0410}GENT"),
            normalize_identity("agent")
        );
    }

    #[test]
    fn test_normalize_identity_mixed_homoglyphs_case() {
        // Mixed Cyrillic + case
        assert_eq!(
            normalize_identity("\u{0430}dmin"),
            normalize_identity("Admin")
        );
        assert_eq!(
            normalize_identity("\u{0410}DMIN"),
            normalize_identity("admin")
        );
    }

    #[test]
    fn test_normalize_identity_reflexive() {
        // normalize_identity(normalize_identity(x)) == normalize_identity(x)
        let input = "AgentAlph\u{0430}";
        let once = normalize_identity(input);
        let twice = normalize_identity(&once);
        assert_eq!(once, twice, "normalize_identity must be idempotent");
    }
}
