// Package vellaveto provides a Go client for the Vellaveto MCP Tool Firewall API.
package vellaveto

// Verdict represents a policy evaluation outcome.
type Verdict string

const (
	VerdictAllow          Verdict = "allow"
	VerdictDeny           Verdict = "deny"
	VerdictRequireApproval Verdict = "require_approval"
)

// ParseVerdict converts a string to a Verdict, defaulting to VerdictDeny (fail-closed).
func ParseVerdict(s string) Verdict {
	switch s {
	case "allow", "Allow":
		return VerdictAllow
	case "deny", "Deny":
		return VerdictDeny
	case "require_approval", "RequireApproval":
		return VerdictRequireApproval
	default:
		return VerdictDeny // fail-closed
	}
}

// Action describes a tool call to be evaluated by the policy engine.
type Action struct {
	Tool          string                 `json:"tool"`
	Function      string                 `json:"function,omitempty"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
	TargetPaths   []string               `json:"target_paths,omitempty"`
	TargetDomains []string               `json:"target_domains,omitempty"`
	ResolvedIPs   []string               `json:"resolved_ips,omitempty"`
}

// EvaluationContext provides session and identity context for policy evaluation.
type EvaluationContext struct {
	SessionID string                 `json:"session_id,omitempty"`
	AgentID   string                 `json:"agent_id,omitempty"`
	TenantID  string                 `json:"tenant_id,omitempty"`
	CallChain []string               `json:"call_chain,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// EvaluateRequest is the JSON body sent to POST /api/evaluate.
type EvaluateRequest struct {
	Action  Action             `json:"action"`
	Context *EvaluationContext `json:"context,omitempty"`
	Trace   bool               `json:"trace,omitempty"`
}

// EvaluationResult is the response from a policy evaluation.
type EvaluationResult struct {
	Verdict    Verdict                `json:"verdict"`
	Reason     string                 `json:"reason,omitempty"`
	PolicyID   string                 `json:"policy_id,omitempty"`
	PolicyName string                 `json:"policy_name,omitempty"`
	ApprovalID string                 `json:"approval_id,omitempty"`
	Trace      map[string]interface{} `json:"trace,omitempty"`
}

// HealthResponse is returned by the health endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// PolicySummary describes a loaded policy.
type PolicySummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PolicyType string `json:"policy_type"`
	Priority   int    `json:"priority"`
}

// SimulateRequest is the JSON body sent to POST /api/simulator/evaluate.
type SimulateRequest struct {
	Action  Action             `json:"action"`
	Context *EvaluationContext `json:"context,omitempty"`
}

// SimulateResponse is the response from the simulator evaluate endpoint.
type SimulateResponse struct {
	Verdict         Verdict                `json:"verdict"`
	Trace           map[string]interface{} `json:"trace,omitempty"`
	PoliciesChecked int                    `json:"policies_checked"`
	DurationUs      int64                  `json:"duration_us"`
}

// BatchRequest is the JSON body sent to POST /api/simulator/batch.
type BatchRequest struct {
	Actions      []Action               `json:"actions"`
	PolicyConfig map[string]interface{} `json:"policy_config,omitempty"`
}

// BatchResult is a single result within a batch evaluation.
type BatchResult struct {
	ActionIndex int                    `json:"action_index"`
	Verdict     Verdict                `json:"verdict"`
	Trace       map[string]interface{} `json:"trace,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// BatchSummary provides aggregate statistics for a batch evaluation.
type BatchSummary struct {
	Total      int   `json:"total"`
	Allowed    int   `json:"allowed"`
	Denied     int   `json:"denied"`
	Errors     int   `json:"errors"`
	DurationUs int64 `json:"duration_us"`
}

// BatchResponse is the response from the batch evaluate endpoint.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
	Summary BatchSummary  `json:"summary"`
}

// ValidateRequest is the JSON body sent to POST /api/simulator/validate.
type ValidateRequest struct {
	Config map[string]interface{} `json:"config"`
	Strict bool                   `json:"strict,omitempty"`
}

// ValidationFinding describes a single validation issue.
type ValidationFinding struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Location   string `json:"location,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// ValidationSummary provides aggregate validation statistics.
type ValidationSummary struct {
	TotalPolicies int  `json:"total_policies"`
	Errors        int  `json:"errors"`
	Warnings      int  `json:"warnings"`
	Infos         int  `json:"infos"`
	Valid         bool `json:"valid"`
}

// ValidateResponse is the response from the config validation endpoint.
type ValidateResponse struct {
	Valid       bool                `json:"valid"`
	Findings   []ValidationFinding `json:"findings"`
	Summary    ValidationSummary   `json:"summary"`
	PolicyCount int                `json:"policy_count"`
}

// DiffRequest is the JSON body sent to POST /api/simulator/diff.
type DiffRequest struct {
	Before map[string]interface{} `json:"before"`
	After  map[string]interface{} `json:"after"`
}

// PolicyDiff describes changes to a single policy between two configs.
type PolicyDiff struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Changes []string `json:"changes"`
}

// DiffResponse is the response from the config diff endpoint.
type DiffResponse struct {
	Added     []PolicySummary `json:"added"`
	Removed   []PolicySummary `json:"removed"`
	Modified  []PolicyDiff    `json:"modified"`
	Unchanged int             `json:"unchanged"`
}

// Approval represents a pending approval request.
type Approval struct {
	ID        string `json:"id"`
	Action    Action `json:"action"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}
