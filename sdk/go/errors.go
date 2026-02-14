package sentinel

import "fmt"

// SentinelError represents an API-level error from the Sentinel server.
type SentinelError struct {
	Message    string
	StatusCode int
}

func (e *SentinelError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("sentinel: %s (HTTP %d)", e.Message, e.StatusCode)
	}
	return fmt.Sprintf("sentinel: %s", e.Message)
}

// PolicyDeniedError is returned when a policy evaluation results in Deny.
type PolicyDeniedError struct {
	Reason   string
	PolicyID string
}

func (e *PolicyDeniedError) Error() string {
	if e.PolicyID != "" {
		return fmt.Sprintf("sentinel: policy denied: %s (policy: %s)", e.Reason, e.PolicyID)
	}
	return fmt.Sprintf("sentinel: policy denied: %s", e.Reason)
}

// ApprovalRequiredError is returned when a policy evaluation requires human approval.
type ApprovalRequiredError struct {
	Reason     string
	ApprovalID string
}

func (e *ApprovalRequiredError) Error() string {
	if e.ApprovalID != "" {
		return fmt.Sprintf("sentinel: approval required: %s (approval: %s)", e.Reason, e.ApprovalID)
	}
	return fmt.Sprintf("sentinel: approval required: %s", e.Reason)
}
