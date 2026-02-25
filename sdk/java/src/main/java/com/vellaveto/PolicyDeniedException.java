package com.vellaveto;

/**
 * Thrown when a policy evaluation results in Deny.
 */
public class PolicyDeniedException extends VellavetoException {

    private final String reason;
    private final String policyId;

    public PolicyDeniedException(String reason, String policyId) {
        super("policy denied: " + reason
                + (policyId != null && !policyId.isEmpty() ? " (policy: " + policyId + ")" : ""));
        this.reason = reason;
        this.policyId = policyId;
    }

    public String getReason() { return reason; }
    public String getPolicyId() { return policyId; }
}
