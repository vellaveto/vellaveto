// Package vellaveto provides a Go client for the Vellaveto MCP Tool Firewall API.
package vellaveto

import (
	"fmt"
	"strings"
)

// Verdict represents a policy evaluation outcome.
type Verdict string

const (
	VerdictAllow          Verdict = "allow"
	VerdictDeny           Verdict = "deny"
	VerdictRequireApproval Verdict = "require_approval"
)

// ParseVerdict converts a string to a Verdict, defaulting to VerdictDeny (fail-closed).
// SECURITY (FIND-GAP-014): Uses case-insensitive comparison via strings.EqualFold
// to handle all case variants (e.g., "ALLOW", "Allow", "allow").
func ParseVerdict(s string) Verdict {
	lower := strings.ToLower(s)
	switch lower {
	case "allow":
		return VerdictAllow
	case "deny":
		return VerdictDeny
	case "require_approval", "requireapproval":
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

// maxActionToolLength is the maximum allowed length for the Tool field.
const maxActionToolLength = 256

// maxActionFunctionLength is the maximum allowed length for the Function field.
const maxActionFunctionLength = 256

// maxActionTargetEntries is the maximum number of entries in target lists.
const maxActionTargetEntries = 100

// Validate checks that the Action fields are within safe bounds.
// SECURITY (FIND-R46-GO-007): Client-side input validation prevents sending
// obviously invalid or oversized payloads to the server.
func (a *Action) Validate() error {
	if a.Tool == "" {
		return fmt.Errorf("vellaveto: action.Tool must not be empty")
	}
	if len(a.Tool) > maxActionToolLength {
		return fmt.Errorf("vellaveto: action.Tool exceeds max length %d", maxActionToolLength)
	}
	if len(a.Function) > maxActionFunctionLength {
		return fmt.Errorf("vellaveto: action.Function exceeds max length %d", maxActionFunctionLength)
	}
	if len(a.TargetPaths) > maxActionTargetEntries {
		return fmt.Errorf("vellaveto: action.TargetPaths has %d entries, max %d", len(a.TargetPaths), maxActionTargetEntries)
	}
	if len(a.TargetDomains) > maxActionTargetEntries {
		return fmt.Errorf("vellaveto: action.TargetDomains has %d entries, max %d", len(a.TargetDomains), maxActionTargetEntries)
	}
	if len(a.ResolvedIPs) > maxActionTargetEntries {
		return fmt.Errorf("vellaveto: action.ResolvedIPs has %d entries, max %d", len(a.ResolvedIPs), maxActionTargetEntries)
	}
	return nil
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
//
// The server uses #[serde(flatten)] on the action, so Action fields must be
// at the root level of the JSON body (not nested under an "action" key).
// The "trace" flag is a query parameter (?trace=true), not a body field.
type EvaluateRequest struct {
	Tool          string                 `json:"tool"`
	Function      string                 `json:"function,omitempty"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
	TargetPaths   []string               `json:"target_paths,omitempty"`
	TargetDomains []string               `json:"target_domains,omitempty"`
	ResolvedIPs   []string               `json:"resolved_ips,omitempty"`
	Context       *EvaluationContext     `json:"context,omitempty"`
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

// DiscoverRequest is the JSON body sent to POST /api/discovery/search.
type DiscoverRequest struct {
	Query       string `json:"query"`
	MaxResults  int    `json:"max_results,omitempty"`
	TokenBudget *int   `json:"token_budget,omitempty"`
}

// ToolMetadata describes a tool in the discovery index.
type ToolMetadata struct {
	ToolID      string                 `json:"tool_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	ServerID    string                 `json:"server_id"`
	InputSchema map[string]interface{} `json:"input_schema"`
	SchemaHash  string                 `json:"schema_hash"`
	Sensitivity string                 `json:"sensitivity"`
	DomainTags  []string               `json:"domain_tags"`
	TokenCost   int                    `json:"token_cost"`
}

// DiscoveredTool is a single tool in a discovery result.
type DiscoveredTool struct {
	Metadata       ToolMetadata `json:"metadata"`
	RelevanceScore float64      `json:"relevance_score"`
	TTLSecs        int          `json:"ttl_secs"`
}

// DiscoveryResult is the response from the discovery search endpoint.
type DiscoveryResult struct {
	Tools           []DiscoveredTool `json:"tools"`
	Query           string           `json:"query"`
	TotalCandidates int              `json:"total_candidates"`
	PolicyFiltered  int              `json:"policy_filtered"`
}

// DiscoveryIndexStats is the response from the discovery stats endpoint.
type DiscoveryIndexStats struct {
	TotalTools    int  `json:"total_tools"`
	MaxCapacity   int  `json:"max_capacity"`
	ConfigEnabled bool `json:"config_enabled"`
}

// DiscoveryToolsResponse is the response from the discovery tools list endpoint.
type DiscoveryToolsResponse struct {
	Tools []ToolMetadata `json:"tools"`
	Total int            `json:"total"`
}

// DiscoveryReindexResponse is the response from the reindex endpoint.
type DiscoveryReindexResponse struct {
	Status     string `json:"status"`
	TotalTools int    `json:"total_tools"`
}

// CanonicalToolSchema is a model-agnostic tool schema.
type CanonicalToolSchema struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	InputSchema  interface{} `json:"input_schema"`
	OutputSchema interface{} `json:"output_schema,omitempty"`
}

// ProjectorTransformRequest is the JSON body sent to POST /api/projector/transform.
type ProjectorTransformRequest struct {
	Schema      CanonicalToolSchema `json:"schema"`
	ModelFamily string              `json:"model_family"`
}

// ProjectorModelsResponse is the response from the projector models list endpoint.
type ProjectorModelsResponse struct {
	ModelFamilies []string `json:"model_families"`
}

// ProjectorTransformResponse is the response from the projector transform endpoint.
type ProjectorTransformResponse struct {
	ProjectedSchema interface{} `json:"projected_schema"`
	TokenEstimate   int         `json:"token_estimate"`
	ModelFamily     string      `json:"model_family"`
}

// ZkSchedulerStatus is the response from GET /api/zk-audit/status.
type ZkSchedulerStatus struct {
	Active              bool    `json:"active"`
	PendingWitnesses    int     `json:"pending_witnesses"`
	CompletedProofs     int     `json:"completed_proofs"`
	LastProvedSequence  *uint64 `json:"last_proved_sequence,omitempty"`
	LastProofAt         *string `json:"last_proof_at,omitempty"`
}

// ZkBatchProof represents a stored ZK batch proof covering a range of audit entries.
type ZkBatchProof struct {
	Proof          string   `json:"proof"`
	BatchID        string   `json:"batch_id"`
	EntryRange     [2]uint64 `json:"entry_range"`
	MerkleRoot     string   `json:"merkle_root"`
	FirstPrevHash  string   `json:"first_prev_hash"`
	FinalEntryHash string   `json:"final_entry_hash"`
	CreatedAt      string   `json:"created_at"`
	EntryCount     int      `json:"entry_count"`
}

// ZkProofsResponse is the response from GET /api/zk-audit/proofs.
type ZkProofsResponse struct {
	Proofs []ZkBatchProof `json:"proofs"`
	Total  int            `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
}

// ZkVerifyRequest is the JSON body sent to POST /api/zk-audit/verify.
type ZkVerifyRequest struct {
	BatchID string `json:"batch_id"`
}

// ZkVerifyResult is the response from POST /api/zk-audit/verify.
type ZkVerifyResult struct {
	Valid      bool      `json:"valid"`
	BatchID    string    `json:"batch_id"`
	EntryRange [2]uint64 `json:"entry_range"`
	VerifiedAt string    `json:"verified_at"`
	Error      *string   `json:"error,omitempty"`
}

// ZkCommitmentEntry represents a single Pedersen commitment for an audit entry.
type ZkCommitmentEntry struct {
	Sequence   uint64 `json:"sequence"`
	Commitment string `json:"commitment"`
	Timestamp  string `json:"timestamp"`
}

// ZkCommitmentsResponse is the response from GET /api/zk-audit/commitments.
type ZkCommitmentsResponse struct {
	Commitments []ZkCommitmentEntry `json:"commitments"`
	Total       int                 `json:"total"`
	Range       [2]uint64           `json:"range"`
}

// ── Phase 39: Federation Types ───────────────────────────────────────────────

// FederationStatusResponse is the response from GET /api/federation/status.
type FederationStatusResponse struct {
	Enabled          bool                     `json:"enabled"`
	TrustAnchorCount int                      `json:"trust_anchor_count"`
	Anchors          []FederationAnchorStatus `json:"anchors"`
}

// FederationAnchorStatus represents the status of a single federation trust anchor.
type FederationAnchorStatus struct {
	OrgID                   string `json:"org_id"`
	DisplayName             string `json:"display_name"`
	TrustLevel              string `json:"trust_level"`
	SuccessfulValidations   int    `json:"successful_validations"`
	FailedValidations       int    `json:"failed_validations"`
}

// FederationTrustAnchorsResponse is the response from GET /api/federation/trust-anchors.
type FederationTrustAnchorsResponse struct {
	Anchors []FederationTrustAnchor `json:"anchors"`
	Total   int                     `json:"total"`
}

// FederationTrustAnchor represents a federation trust anchor.
type FederationTrustAnchor struct {
	OrgID       string `json:"org_id"`
	DisplayName string `json:"display_name"`
	TrustLevel  string `json:"trust_level"`
}

// ── Phase 38: SOC 2 Type II Access Review Types ─────────────────────────────

// ReviewerAttestation represents a reviewer's attestation on an access review report.
type ReviewerAttestation struct {
	ReviewerName  string  `json:"reviewer_name"`
	ReviewerTitle string  `json:"reviewer_title"`
	ReviewedAt    *string `json:"reviewed_at,omitempty"`
	Notes         string  `json:"notes"`
	Status        string  `json:"status"`
}

// AccessReviewEntry represents a per-agent access review entry.
type AccessReviewEntry struct {
	AgentID              string   `json:"agent_id"`
	SessionIDs           []string `json:"session_ids"`
	FirstAccess          string   `json:"first_access"`
	LastAccess           string   `json:"last_access"`
	TotalEvaluations     uint64   `json:"total_evaluations"`
	AllowCount           uint64   `json:"allow_count"`
	DenyCount            uint64   `json:"deny_count"`
	RequireApprovalCount uint64   `json:"require_approval_count"`
	ToolsAccessed        []string `json:"tools_accessed"`
	FunctionsCalled      []string `json:"functions_called"`
	PermissionsGranted   int      `json:"permissions_granted"`
	PermissionsUsed      int      `json:"permissions_used"`
	UsageRatio           float64  `json:"usage_ratio"`
	UnusedPermissions    []string `json:"unused_permissions"`
	AgencyRecommendation string   `json:"agency_recommendation"`
}

// Cc6Evidence represents CC6 (Logical and Physical Access Controls) evidence.
type Cc6Evidence struct {
	CC61Evidence      string `json:"cc6_1_evidence"`
	CC62Evidence      string `json:"cc6_2_evidence"`
	CC63Evidence      string `json:"cc6_3_evidence"`
	OptimalCount      int    `json:"optimal_count"`
	ReviewGrantsCount int    `json:"review_grants_count"`
	NarrowScopeCount  int    `json:"narrow_scope_count"`
	CriticalCount     int    `json:"critical_count"`
}

// AccessReviewReport represents a SOC 2 Type II access review report.
type AccessReviewReport struct {
	GeneratedAt      string              `json:"generated_at"`
	OrganizationName string              `json:"organization_name"`
	PeriodStart      string              `json:"period_start"`
	PeriodEnd        string              `json:"period_end"`
	TotalAgents      int                 `json:"total_agents"`
	TotalEvaluations uint64              `json:"total_evaluations"`
	Entries          []AccessReviewEntry `json:"entries"`
	CC6Evidence      Cc6Evidence         `json:"cc6_evidence"`
	Attestation      ReviewerAttestation `json:"attestation"`
}
