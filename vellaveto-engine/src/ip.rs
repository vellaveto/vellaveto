// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! IP address utilities for DNS rebinding and SSRF protection.
//!
//! This module provides comprehensive IPv4 and IPv6 private/reserved address detection,
//! including all IPv6 transition mechanisms that can embed IPv4 addresses.
//!
//! # Security Context
//!
//! DNS rebinding attacks and SSRF vulnerabilities often exploit private IP addresses.
//! These utilities are used by the policy engine's `block_private` IP rules to prevent
//! agents from accessing internal network resources.
//!
//! # IPv6 Transition Mechanisms
//!
//! The following IPv6 transition mechanisms embed IPv4 addresses and are checked:
//! - IPv4-mapped: `::ffff:x.x.x.x`
//! - IPv4-compatible: `::x.x.x.x` (deprecated but still routable)
//! - 6to4: `2002::/16`
//! - Teredo: `2001::/32`
//! - NAT64 well-known: `64:ff9b::/96`
//! - NAT64 local-use: `64:ff9b:1::/48`

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if an IP address is private/reserved and should be blocked.
///
/// Returns `true` for:
/// - IPv4: loopback, private, link-local, broadcast, CGNAT, benchmarking, documentation, reserved
/// - IPv6: loopback, unspecified, ULA, link-local, multicast, documentation, discard
/// - IPv6 with embedded private IPv4 (mapped, compatible, 6to4, Teredo, NAT64)
///
/// Used by [`PolicyEngine::check_ip_rules`] when `block_private` is enabled.
///
/// SECURITY (R18-IPV6-1): Comprehensive IPv6 special-purpose address coverage.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()      // 127.0.0.0/8
            || v4.is_private()     // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()  // 169.254/16
            || v4.is_unspecified() // 0.0.0.0
            || v4.is_broadcast()   // 255.255.255.255
            // SECURITY (R21-ENG-3): Additional reserved ranges
            || octets[0] == 0                                        // 0.0.0.0/8 (RFC 1122)
            || (octets[0] == 100 && (octets[1] & 0xC0) == 64)       // 100.64.0.0/10 CGNAT (RFC 6598)
            || (octets[0] == 198 && (octets[1] & 0xFE) == 18)       // 198.18.0.0/15 benchmarking (RFC 2544)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 (RFC 6890)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 TEST-NET-2
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)  // 203.0.113.0/24 TEST-NET-3
            // SECURITY (R23-ENG-3): Additional IANA reserved ranges
            || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 192.88.99.0/24 deprecated 6to4 relay (RFC 7526)
            || (octets[0] & 0xF0) == 240 // 240.0.0.0/4 Reserved/Class E (RFC 1112)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
            || v6.is_unspecified() // ::
            || is_ipv6_unique_local(&v6)   // fc00::/7 (ULA)
            || is_ipv6_link_local(&v6)     // fe80::/10
            || is_ipv6_multicast(&v6)      // ff00::/8
            || is_ipv6_documentation(&v6)  // 2001:db8::/32
            || is_ipv6_discard(&v6)        // 100::/64
            // Transition mechanisms with embedded IPv4
            || is_ipv4_mapped_private(&v6)      // ::ffff:x.x.x.x
            || is_ipv4_compatible_private(&v6)   // ::x.x.x.x (R21-ENG-2)
            || is_6to4_private(&v6)              // 2002::/16
            || is_teredo_private(&v6)            // 2001::/32
            || is_nat64_private(&v6)             // 64:ff9b::/96
            || is_nat64_local_private(&v6) // 64:ff9b:1::/48 (RFC 8215)
        }
    }
}

/// fc00::/7 — Unique Local Address (RFC 4193)
fn is_ipv6_unique_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — Link-Local (RFC 4291)
fn is_ipv6_link_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// ff00::/8 — Multicast (RFC 4291)
fn is_ipv6_multicast(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xff00) == 0xff00
}

/// 2001:db8::/32 — Documentation (RFC 3849)
fn is_ipv6_documentation(v6: &Ipv6Addr) -> bool {
    v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
}

/// 100::/64 — Discard-Only (RFC 6666)
fn is_ipv6_discard(v6: &Ipv6Addr) -> bool {
    v6.segments()[0] == 0x0100
        && v6.segments()[1] == 0
        && v6.segments()[2] == 0
        && v6.segments()[3] == 0
}

/// SECURITY (R22-ENG-2): Consistent reserved-range check for embedded IPv4 addresses.
///
/// All IPv6 transition mechanisms (mapped, compatible, 6to4, Teredo, NAT64) must
/// use the same set of checks. Previously, some functions only checked loopback +
/// private + link-local, while is_ipv4_compatible_private also checked CGNAT, 0/8,
/// and benchmarking ranges — creating inconsistent bypass opportunities.
fn is_embedded_ipv4_reserved(v4: &Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()                                            // 127.0.0.0/8
        || v4.is_private()                                       // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()                                    // 169.254/16
        || v4.is_unspecified()                                   // 0.0.0.0
        || v4.is_broadcast()                                     // 255.255.255.255
        || octets[0] == 0                                        // 0.0.0.0/8 (RFC 1122)
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)       // 100.64.0.0/10 CGNAT (RFC 6598)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)       // 198.18.0.0/15 benchmarking (RFC 2544)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 (RFC 6890)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 TEST-NET-1
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 TEST-NET-2
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)  // 203.0.113.0/24 TEST-NET-3
        // SECURITY (R23-ENG-3): Additional IANA reserved ranges
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 192.88.99.0/24 deprecated 6to4 relay (RFC 7526)
        || (octets[0] & 0xF0) == 240 // 240.0.0.0/4 Reserved/Class E (RFC 1112)
}

/// ::ffff:x.x.x.x — IPv4-mapped IPv6 (check embedded IPv4)
fn is_ipv4_mapped_private(v6: &Ipv6Addr) -> bool {
    v6.to_ipv4_mapped()
        .is_some_and(|v4| is_embedded_ipv4_reserved(&v4))
}

/// SECURITY (R29-ENG-1): Extract the embedded IPv4 address from any IPv6
/// transition mechanism. Returns `Some(v4)` for mapped, compatible, 6to4,
/// Teredo, NAT64 (well-known + local-use). Returns `None` if the address
/// does not embed an IPv4 address. Used by CIDR matching to canonicalize
/// IPv6 transition addresses before comparing against IPv4 CIDRs.
pub(crate) fn extract_embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    // 1. IPv4-mapped: ::ffff:x.x.x.x
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }

    let segs = v6.segments();

    // 2. IPv4-compatible: ::x.x.x.x (deprecated but still routable on some systems)
    if segs[0] == 0
        && segs[1] == 0
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
        && !(segs[6] == 0 && segs[7] <= 1)
    {
        return Some(Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ));
    }

    // 3. 6to4: 2002::/16 — embedded IPv4 in segments 1-2
    if segs[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        ));
    }

    // 4. Teredo: 2001:0000::/32 — embedded client IPv4 in segments 6-7, XORed
    if segs[0] == 0x2001 && segs[1] == 0 {
        return Some(Ipv4Addr::new(
            ((segs[6] >> 8) ^ 0xff) as u8,
            ((segs[6] & 0xff) ^ 0xff) as u8,
            ((segs[7] >> 8) ^ 0xff) as u8,
            ((segs[7] & 0xff) ^ 0xff) as u8,
        ));
    }

    // 5. NAT64 well-known: 64:ff9b::/96 — embedded IPv4 in segments 6-7
    if segs[0] == 0x0064
        && segs[1] == 0xff9b
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        return Some(Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ));
    }

    // 6. NAT64 local-use: 64:ff9b:0001::/48 — embedded IPv4 in segments 6-7
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
        return Some(Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ));
    }

    None
}

/// SECURITY (R21-ENG-2): ::x.x.x.x — IPv4-compatible IPv6 (deprecated, RFC 4291 §2.5.5.1)
///
/// Segments 0-4 are zero, segment 5 is NOT 0xffff (that would be IPv4-mapped).
/// The embedded IPv4 is in segments 6-7. Many OS kernels route these to the
/// embedded IPv4 address, enabling DNS rebinding if not blocked.
fn is_ipv4_compatible_private(v6: &Ipv6Addr) -> bool {
    let segs = v6.segments();
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0
    {
        // Skip ::0.0.0.0 and ::0.0.0.1 (unspecified/loopback already covered)
        if segs[6] == 0 && segs[7] <= 1 {
            return false; // handled by is_loopback/is_unspecified
        }
        let octets = [
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ];
        let embedded = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        return is_embedded_ipv4_reserved(&embedded);
    }
    false
}

/// 2002::/16 — 6to4 (RFC 3056) — extract embedded IPv4 from bits 16-47
fn is_6to4_private(v6: &Ipv6Addr) -> bool {
    if v6.segments()[0] != 0x2002 {
        return false;
    }
    // Embedded IPv4 is in segments 1 and 2 (bits 16-47)
    let octets = [
        (v6.segments()[1] >> 8) as u8,
        (v6.segments()[1] & 0xff) as u8,
        (v6.segments()[2] >> 8) as u8,
        (v6.segments()[2] & 0xff) as u8,
    ];
    let embedded = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// 2001::/32 — Teredo (RFC 4380) — extract embedded IPv4 from last 32 bits (XORed)
fn is_teredo_private(v6: &Ipv6Addr) -> bool {
    if v6.segments()[0] != 0x2001 || v6.segments()[1] != 0 {
        return false;
    }
    // Teredo client IPv4 is in segments 6-7, XORed with 0xFFFF
    let octets = [
        ((v6.segments()[6] >> 8) ^ 0xff) as u8,
        ((v6.segments()[6] & 0xff) ^ 0xff) as u8,
        ((v6.segments()[7] >> 8) ^ 0xff) as u8,
        ((v6.segments()[7] & 0xff) ^ 0xff) as u8,
    ];
    let embedded = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// 64:ff9b::/96 — NAT64 well-known prefix (RFC 6052) — extract embedded IPv4 from last 32 bits
fn is_nat64_private(v6: &Ipv6Addr) -> bool {
    // Check prefix 64:ff9b::/96 (segments 0-5 must be 0x0064, 0xff9b, 0, 0, 0, 0)
    if v6.segments()[0] != 0x0064
        || v6.segments()[1] != 0xff9b
        || v6.segments()[2] != 0
        || v6.segments()[3] != 0
        || v6.segments()[4] != 0
        || v6.segments()[5] != 0
    {
        return false;
    }
    // Embedded IPv4 is in segments 6-7
    let octets = [
        (v6.segments()[6] >> 8) as u8,
        (v6.segments()[6] & 0xff) as u8,
        (v6.segments()[7] >> 8) as u8,
        (v6.segments()[7] & 0xff) as u8,
    ];
    let embedded = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// SECURITY (R25-ENG-2): 64:ff9b:1::/48 — NAT64 local-use prefix (RFC 8215)
///
/// RFC 8215 defines this range for NAT64 deployments that use locally assigned
/// prefixes. Like the well-known prefix (64:ff9b::/96), it embeds IPv4 addresses
/// in the last 32 bits. An attacker could use this to bypass private IP blocking
/// since the well-known prefix is already detected but the local-use prefix was not.
fn is_nat64_local_private(v6: &Ipv6Addr) -> bool {
    // Check prefix 64:ff9b:0001::/48
    // Segment 0 = 0x0064, Segment 1 = 0xff9b, Segment 2 = 0x0001
    if v6.segments()[0] != 0x0064 || v6.segments()[1] != 0xff9b || v6.segments()[2] != 0x0001 {
        return false;
    }
    // Embedded IPv4 is in segments 6-7 (last 32 bits)
    let octets = [
        (v6.segments()[6] >> 8) as u8,
        (v6.segments()[6] & 0xff) as u8,
        (v6.segments()[7] >> 8) as u8,
        (v6.segments()[7] & 0xff) as u8,
    ];
    let embedded = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_private_ranges() {
        // Loopback
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.255.255.255".parse().unwrap()));

        // Private ranges
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));

        // Link-local
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));

        // CGNAT
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));

        // Public IP should not be blocked
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_private_ranges() {
        // Loopback
        assert!(is_private_ip("::1".parse().unwrap()));

        // Link-local
        assert!(is_private_ip("fe80::1".parse().unwrap()));

        // ULA
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));

        // Documentation
        assert!(is_private_ip("2001:db8::1".parse().unwrap()));

        // Public IPv6 should not be blocked
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        // Private IPv4 mapped to IPv6
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));

        // Public IPv4 mapped to IPv6 should not be blocked
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_6to4_addresses() {
        // 6to4 with embedded private IPv4 (192.168.1.1 -> 2002:c0a8:0101::)
        assert!(is_private_ip("2002:c0a8:0101::1".parse().unwrap()));

        // 6to4 with embedded public IPv4 should not be blocked
        assert!(!is_private_ip("2002:0808:0808::1".parse().unwrap()));
    }

    #[test]
    fn test_teredo_addresses() {
        // Teredo with embedded private IPv4 (XOR with 0xFFFF)
        // 192.168.1.1 XOR 0xFFFF = 0x3f57fefe
        assert!(is_private_ip(
            "2001:0:4136:e378:8000:63bf:3f57:fefe".parse().unwrap()
        ));
    }

    #[test]
    fn test_nat64_addresses() {
        // NAT64 well-known prefix with embedded private IPv4
        assert!(is_private_ip("64:ff9b::192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("64:ff9b::10.0.0.1".parse().unwrap()));

        // NAT64 with public IPv4 should not be blocked
        assert!(!is_private_ip("64:ff9b::8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_nat64_local_use_prefix() {
        // NAT64 local-use prefix (64:ff9b:1::/48) with embedded private IPv4
        // 192.168.1.1 = 0xc0a80101
        assert!(is_private_ip("64:ff9b:1::c0a8:0101".parse().unwrap()));

        // NAT64 local-use with public IPv4 should not be blocked
        assert!(!is_private_ip("64:ff9b:1::0808:0808".parse().unwrap()));
    }

    #[test]
    fn test_extract_embedded_ipv4() {
        // IPv4-mapped
        let v6: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert_eq!(
            extract_embedded_ipv4(&v6),
            Some("192.168.1.1".parse().unwrap())
        );

        // 6to4
        let v6: Ipv6Addr = "2002:c0a8:0101::1".parse().unwrap();
        assert_eq!(
            extract_embedded_ipv4(&v6),
            Some("192.168.1.1".parse().unwrap())
        );

        // NAT64 well-known
        let v6: Ipv6Addr = "64:ff9b::c0a8:0101".parse().unwrap();
        assert_eq!(
            extract_embedded_ipv4(&v6),
            Some("192.168.1.1".parse().unwrap())
        );

        // No embedded IPv4
        let v6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(extract_embedded_ipv4(&v6), None);
    }
}
