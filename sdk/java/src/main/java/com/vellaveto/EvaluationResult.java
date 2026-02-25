package com.vellaveto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * The response from a policy evaluation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EvaluationResult {

    @JsonProperty("verdict")
    private Verdict verdict;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("policy_id")
    private String policyId;

    @JsonProperty("policy_name")
    private String policyName;

    @JsonProperty("approval_id")
    private String approvalId;

    @JsonProperty("trace")
    private Map<String, Object> trace;

    public EvaluationResult() {}

    public EvaluationResult(Verdict verdict, String reason, String policyId,
                            String policyName, String approvalId, Map<String, Object> trace) {
        this.verdict = verdict;
        this.reason = reason;
        this.policyId = policyId;
        this.policyName = policyName;
        this.approvalId = approvalId;
        this.trace = trace;
    }

    public Verdict getVerdict() { return verdict; }
    public String getReason() { return reason; }
    public String getPolicyId() { return policyId; }
    public String getPolicyName() { return policyName; }
    public String getApprovalId() { return approvalId; }
    public Map<String, Object> getTrace() { return trace; }
}
