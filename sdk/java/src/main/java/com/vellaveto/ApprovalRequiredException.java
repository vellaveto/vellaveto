package com.vellaveto;

/**
 * Thrown when a policy evaluation requires human approval.
 */
public class ApprovalRequiredException extends VellavetoException {

    private final String reason;
    private final String approvalId;

    public ApprovalRequiredException(String reason, String approvalId) {
        super("approval required: " + reason
                + (approvalId != null && !approvalId.isEmpty() ? " (approval: " + approvalId + ")" : ""));
        this.reason = reason;
        this.approvalId = approvalId;
    }

    public String getReason() { return reason; }
    public String getApprovalId() { return approvalId; }
}
