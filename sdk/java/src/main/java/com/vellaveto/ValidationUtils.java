package com.vellaveto;

import java.util.regex.Pattern;

/**
 * Input validation utilities for the Vellaveto SDK.
 *
 * <p>SECURITY: Mirrors validation logic from Go/Python/TypeScript SDKs for parity.</p>
 */
final class ValidationUtils {

    static final int MAX_APPROVAL_ID_LENGTH = 256;
    static final int MAX_REASON_LENGTH = 4096;
    static final int MAX_PARAMETERS_SIZE = 512 * 1024; // 512 KB
    static final int MAX_TENANT_ID_LENGTH = 64;
    static final Pattern TENANT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    static final int MAX_DISCOVER_QUERY_LENGTH = 1024;
    static final int MAX_DISCOVER_RESULTS = 20;
    static final int MAX_ZK_PROOFS_LIMIT = 1000;
    static final int MAX_PERIOD_LENGTH = 32;
    static final Pattern PERIOD_PATTERN = Pattern.compile("^[a-zA-Z0-9\\-:]+$");
    static final int MAX_DISCOVERY_SERVER_ID_LENGTH = 256;

    private ValidationUtils() {}

    /**
     * Checks if a character is a Unicode format character used for invisible text manipulation.
     * SECURITY: Covers zero-width chars, bidi overrides, BOM, interlinear annotation anchors,
     * TAG characters, and soft hyphen. Parity with Go isUnicodeFormatChar().
     */
    static boolean isUnicodeFormatChar(int codePoint) {
        // Soft hyphen: U+00AD
        if (codePoint == 0x00AD) return true;
        // Zero-width and joining chars: U+200B-U+200F
        if (codePoint >= 0x200B && codePoint <= 0x200F) return true;
        // Line/paragraph separators + bidi embedding controls: U+2028-U+202F
        if (codePoint >= 0x2028 && codePoint <= 0x202F) return true;
        // Word joiner and invisible chars: U+2060-U+2069
        if (codePoint >= 0x2060 && codePoint <= 0x2069) return true;
        // BOM: U+FEFF
        if (codePoint == 0xFEFF) return true;
        // Interlinear annotation anchors: U+FFF9-U+FFFB
        if (codePoint >= 0xFFF9 && codePoint <= 0xFFFB) return true;
        // TAG characters: U+E0001-U+E007F
        if (codePoint >= 0xE0001 && codePoint <= 0xE007F) return true;
        return false;
    }

    /**
     * Rejects strings containing ASCII control characters or Unicode format characters.
     * SECURITY: Prevents invisible text manipulation attacks.
     *
     * @param value the string to validate
     * @param fieldName the field name for error messages
     * @throws VellavetoException if the string contains forbidden characters
     */
    static void rejectControlAndFormatChars(String value, String fieldName) throws VellavetoException {
        if (value == null) return;
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            if (cp < ' ' || (cp >= 0x7F && cp <= 0x9F)) {
                throw new VellavetoException(fieldName + " contains control characters");
            }
            if (isUnicodeFormatChar(cp)) {
                throw new VellavetoException(fieldName + " contains Unicode format characters");
            }
            i += Character.charCount(cp);
        }
    }

    /**
     * Validates an approval ID: non-empty, bounded length, no forbidden chars.
     */
    static void validateApprovalId(String id) throws VellavetoException {
        if (id == null || id.isEmpty()) {
            throw new VellavetoException("approval ID must not be empty");
        }
        if (id.length() > MAX_APPROVAL_ID_LENGTH) {
            throw new VellavetoException("approval ID exceeds max length " + MAX_APPROVAL_ID_LENGTH);
        }
        rejectControlAndFormatChars(id, "approval ID");
    }

    /**
     * Validates an optional reason string.
     */
    static void validateReason(String reason) throws VellavetoException {
        if (reason == null || reason.isEmpty()) return;
        // SECURITY: Go len() measures bytes; Java length() measures chars. Use byte length for parity.
        if (reason.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_REASON_LENGTH) {
            throw new VellavetoException("reason exceeds maximum length (4096 bytes)");
        }
        rejectControlAndFormatChars(reason, "reason");
    }

    /**
     * Validates a tenant ID: 1-64 chars, alphanumeric + hyphen + underscore.
     */
    static void validateTenantId(String tenantId) throws VellavetoException {
        if (tenantId == null || tenantId.isEmpty() || tenantId.length() > MAX_TENANT_ID_LENGTH) {
            throw new VellavetoException("tenantID must be 1-64 characters, got "
                    + (tenantId == null ? 0 : tenantId.length()));
        }
        if (!TENANT_ID_PATTERN.matcher(tenantId).matches()) {
            throw new VellavetoException("tenantID contains invalid characters");
        }
    }

    /**
     * Validates a period parameter for SOC 2 access review.
     */
    static void validatePeriod(String period) throws VellavetoException {
        if (period == null || period.isEmpty()) return;
        if (period.length() > MAX_PERIOD_LENGTH) {
            throw new VellavetoException("period exceeds max length (" + MAX_PERIOD_LENGTH + ")");
        }
        if (!PERIOD_PATTERN.matcher(period).matches()) {
            throw new VellavetoException(
                    "period contains invalid characters: only alphanumeric, dashes, and colons are allowed");
        }
    }

    /**
     * Validates a format parameter (json or html).
     */
    static void validateFormat(String format) throws VellavetoException {
        if (format == null || format.isEmpty()) return;
        if (!"json".equals(format) && !"html".equals(format)) {
            throw new VellavetoException("format must be \"json\" or \"html\", got \"" + format + "\"");
        }
    }
}
