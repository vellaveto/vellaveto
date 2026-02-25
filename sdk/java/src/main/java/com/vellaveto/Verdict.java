package com.vellaveto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Represents a policy evaluation outcome.
 *
 * <p>SECURITY: Unknown verdict strings default to DENY (fail-closed).</p>
 */
public enum Verdict {
    ALLOW("allow"),
    DENY("deny"),
    REQUIRE_APPROVAL("require_approval");

    private final String value;

    Verdict(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Parses a string to a Verdict, defaulting to DENY (fail-closed).
     * Case-insensitive matching.
     */
    @JsonCreator
    public static Verdict fromString(String s) {
        if (s == null) {
            return DENY;
        }
        String lower = s.toLowerCase();
        switch (lower) {
            case "allow":
                return ALLOW;
            case "deny":
                return DENY;
            case "require_approval":
            case "requireapproval":
                return REQUIRE_APPROVAL;
            default:
                return DENY; // fail-closed
        }
    }
}
