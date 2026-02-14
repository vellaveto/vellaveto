package vellaveto

import "fmt"

// VellavetoError represents an API-level error from the Vellaveto server.
type VellavetoError struct {
	Message    string
	StatusCode int
}

func (e *VellavetoError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("vellaveto: %s (HTTP %d)", e.Message, e.StatusCode)
	}
	return fmt.Sprintf("vellaveto: %s", e.Message)
}

// PolicyDeniedError is returned when a policy evaluation results in Deny.
type PolicyDeniedError struct {
	Reason   string
	PolicyID string
}

func (e *PolicyDeniedError) Error() string {
	if e.PolicyID != "" {
		return fmt.Sprintf("vellaveto: policy denied: %s (policy: %s)", e.Reason, e.PolicyID)
	}
	return fmt.Sprintf("vellaveto: policy denied: %s", e.Reason)
}

// ApprovalRequiredError is returned when a policy evaluation requires human approval.
type ApprovalRequiredError struct {
	Reason     string
	ApprovalID string
}

func (e *ApprovalRequiredError) Error() string {
	if e.ApprovalID != "" {
		return fmt.Sprintf("vellaveto: approval required: %s (approval: %s)", e.Reason, e.ApprovalID)
	}
	return fmt.Sprintf("vellaveto: approval required: %s", e.Reason)
}
