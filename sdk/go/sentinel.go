package vellaveto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBodySize limits the maximum response body size to prevent OOM
// from malicious or misconfigured servers.
// SECURITY (FIND-R46-GO-001): Without this limit, io.ReadAll on an unbounded
// response body allows a malicious server to cause OOM.
const maxResponseBodySize = 10 * 1024 * 1024 // 10 MB

// SECURITY (FIND-R56-SDK-003): Aligned default timeout across all SDKs (Python/Go/TS = 10s).
const defaultTimeout = 10 * time.Second

// Client is the Vellaveto API client.
//
// SECURITY (FIND-R46-GO-006): Thread safety — Client is safe for concurrent use
// after construction. All fields are read-only after NewClient returns: baseURL,
// apiKey, and headers are never mutated. httpClient is shared but http.Client is
// documented as safe for concurrent use. No mutexes are needed because there is
// no mutable state post-construction.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	headers    map[string]string
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key for authentication.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithHeaders adds custom headers to every request.
func WithHeaders(h map[string]string) Option {
	return func(c *Client) {
		for k, v := range h {
			c.headers[k] = v
		}
	}
}

// NewClient creates a new Vellaveto API client.
//
// SECURITY (FIND-GAP-011): Validates that baseURL is a well-formed URL with
// http:// or https:// scheme and a non-empty host. Returns an error if invalid.
// SECURITY (FIND-R46-GO-004): Default HTTP client strips Authorization header
// on cross-domain redirects to prevent API key leakage.
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return nil, fmt.Errorf("vellaveto: baseURL must not be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("vellaveto: invalid baseURL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("vellaveto: baseURL must use http:// or https:// scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("vellaveto: baseURL must have a host")
	}

	c := &Client{
		baseURL: trimmed,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("vellaveto: stopped after 10 redirects")
				}
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					// Cross-domain redirect: strip Authorization to prevent API key leak.
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// String returns a human-readable representation of the client with the API key redacted.
// SECURITY (FIND-R56-SDK-005): Prevents API key leakage in logs and debug output.
func (c *Client) String() string {
	return fmt.Sprintf("vellaveto.Client{baseURL: %q, apiKey: ***}", c.baseURL)
}

// do executes an HTTP request and returns the response body.
func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("vellaveto: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("vellaveto: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("vellaveto: request failed: %w", err)
	}
	defer resp.Body.Close()

	// SECURITY (FIND-R46-GO-001): Limit response body size to prevent OOM DoS.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("vellaveto: read response: %w", err)
	}
	if int64(len(respBody)) > maxResponseBodySize {
		return nil, resp.StatusCode, fmt.Errorf("vellaveto: response body exceeds %d byte limit", maxResponseBodySize)
	}

	return respBody, resp.StatusCode, nil
}

// maxErrorBodyDisplay is the maximum number of bytes from a response body
// included in error messages to prevent information disclosure.
// SECURITY (FIND-R46-GO-005): Full response bodies in errors can leak
// sensitive server internals (stack traces, config, internal paths).
const maxErrorBodyDisplay = 256

// doJSON executes a request, checks status, and decodes JSON into dst.
// TODO(FIND-R51-009): Add retry logic for transient HTTP failures (429, 502, 503, 504)
func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, dst interface{}) error {
	respBody, status, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		// SECURITY (FIND-R46-GO-005): Truncate response body in error messages.
		msg := string(respBody)
		if len(msg) > maxErrorBodyDisplay {
			msg = msg[:maxErrorBodyDisplay] + "...(truncated)"
		}
		return &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", msg),
			StatusCode: status,
		}
	}
	if dst != nil {
		if err := json.Unmarshal(respBody, dst); err != nil {
			return fmt.Errorf("vellaveto: decode response: %w", err)
		}
	}
	return nil
}

// Health checks the Vellaveto server health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doJSON(ctx, http.MethodGet, "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// parseVerdict handles both string and object verdict forms from the API.
// String: {"verdict": "allow"}
// Object: {"verdict": {"Deny": {"reason": "..."}}}
func parseVerdictField(raw json.RawMessage) (Verdict, string) {
	// Try string form first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return ParseVerdict(s), ""
	}

	// Try object form: {"Allow": {}} or {"Deny": {"reason": "..."}}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for key, val := range obj {
			v := ParseVerdict(key)
			var inner struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(val, &inner)
			return v, inner.Reason
		}
	}

	return VerdictDeny, "" // fail-closed
}

// evaluateRaw is the internal raw response struct for verdict parsing.
type evaluateRaw struct {
	Verdict    json.RawMessage        `json:"verdict"`
	Reason     string                 `json:"reason,omitempty"`
	PolicyID   string                 `json:"policy_id,omitempty"`
	PolicyName string                 `json:"policy_name,omitempty"`
	ApprovalID string                 `json:"approval_id,omitempty"`
	Trace      map[string]interface{} `json:"trace,omitempty"`
}

// Evaluate sends an action to the policy engine for evaluation.
//
// The server expects Action fields flattened at the root level of the JSON body
// (not nested under an "action" key) because the Rust server uses #[serde(flatten)].
// The trace flag is passed as a query parameter (?trace=true).
func (c *Client) Evaluate(ctx context.Context, action Action, evalCtx *EvaluationContext, trace bool) (*EvaluationResult, error) {
	// SECURITY (FIND-R54-SDK-008): Validate action fields before sending to server.
	if err := action.Validate(); err != nil {
		return nil, err
	}

	reqBody := EvaluateRequest{
		Tool:          action.Tool,
		Function:      action.Function,
		Parameters:    action.Parameters,
		TargetPaths:   action.TargetPaths,
		TargetDomains: action.TargetDomains,
		ResolvedIPs:   action.ResolvedIPs,
		Context:       evalCtx,
	}

	path := "/api/evaluate"
	if trace {
		path += "?trace=true"
	}

	respBody, status, err := c.do(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		// SECURITY (FIND-R46-GO-005): Truncate response body in error messages.
		msg := string(respBody)
		if len(msg) > maxErrorBodyDisplay {
			msg = msg[:maxErrorBodyDisplay] + "...(truncated)"
		}
		return nil, &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", msg),
			StatusCode: status,
		}
	}

	var raw evaluateRaw
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("vellaveto: decode response: %w", err)
	}

	verdict, objReason := parseVerdictField(raw.Verdict)
	reason := raw.Reason
	if reason == "" {
		reason = objReason
	}

	return &EvaluationResult{
		Verdict:    verdict,
		Reason:     reason,
		PolicyID:   raw.PolicyID,
		PolicyName: raw.PolicyName,
		ApprovalID: raw.ApprovalID,
		Trace:      raw.Trace,
	}, nil
}

// EvaluateOrError is like Evaluate but returns typed errors for Deny and RequireApproval verdicts.
func (c *Client) EvaluateOrError(ctx context.Context, action Action, evalCtx *EvaluationContext) error {
	result, err := c.Evaluate(ctx, action, evalCtx, false)
	if err != nil {
		return err
	}
	switch result.Verdict {
	case VerdictAllow:
		return nil
	case VerdictDeny:
		return &PolicyDeniedError{Reason: result.Reason, PolicyID: result.PolicyID}
	case VerdictRequireApproval:
		return &ApprovalRequiredError{Reason: result.Reason, ApprovalID: result.ApprovalID}
	default:
		return &PolicyDeniedError{Reason: "unknown verdict"} // fail-closed
	}
}

// ListPolicies returns all loaded policies.
func (c *Client) ListPolicies(ctx context.Context) ([]PolicySummary, error) {
	var policies []PolicySummary
	if err := c.doJSON(ctx, http.MethodGet, "/api/policies", nil, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// ReloadPoliciesResponse is the response from a policy reload operation.
type ReloadPoliciesResponse struct {
	Count   int    `json:"count,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// ReloadPolicies triggers a policy reload on the server and returns the server response.
// SECURITY (FIND-GAP-016): Captures and returns the server response body so callers
// can verify the reload was successful and inspect the reloaded policy count.
func (c *Client) ReloadPolicies(ctx context.Context) (*ReloadPoliciesResponse, error) {
	var resp ReloadPoliciesResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/policies/reload", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Simulate evaluates an action with full trace information.
func (c *Client) Simulate(ctx context.Context, action Action, evalCtx *EvaluationContext) (*SimulateResponse, error) {
	reqBody := SimulateRequest{
		Action:  action,
		Context: evalCtx,
	}
	var resp SimulateResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/evaluate", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchEvaluate evaluates multiple actions in a single request.
func (c *Client) BatchEvaluate(ctx context.Context, actions []Action, policyConfig map[string]interface{}) (*BatchResponse, error) {
	reqBody := BatchRequest{
		Actions:      actions,
		PolicyConfig: policyConfig,
	}
	var resp BatchResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/batch", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ValidateConfig validates a policy configuration.
func (c *Client) ValidateConfig(ctx context.Context, config map[string]interface{}, strict bool) (*ValidateResponse, error) {
	reqBody := ValidateRequest{
		Config: config,
		Strict: strict,
	}
	var resp ValidateResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/validate", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiffConfigs compares two policy configurations.
func (c *Client) DiffConfigs(ctx context.Context, before, after map[string]interface{}) (*DiffResponse, error) {
	reqBody := DiffRequest{
		Before: before,
		After:  after,
	}
	var resp DiffResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/simulator/diff", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPendingApprovals returns all pending approval requests.
func (c *Client) ListPendingApprovals(ctx context.Context) ([]Approval, error) {
	var approvals []Approval
	if err := c.doJSON(ctx, http.MethodGet, "/api/approvals/pending", nil, &approvals); err != nil {
		return nil, err
	}
	return approvals, nil
}

// maxApprovalIDLength is the maximum allowed length for an approval ID.
const maxApprovalIDLength = 256

// validateApprovalID checks that an approval ID is non-empty, within length
// bounds, and contains no control or Unicode format characters.
// SECURITY (FIND-R54-SDK-003): Prevents empty/oversized/malicious approval IDs.
func validateApprovalID(id string) error {
	if id == "" {
		return fmt.Errorf("vellaveto: approval ID must not be empty")
	}
	if len(id) > maxApprovalIDLength {
		return fmt.Errorf("vellaveto: approval ID exceeds max length %d", maxApprovalIDLength)
	}
	for _, c := range id {
		if c < ' ' || (c >= 0x7F && c <= 0x9F) {
			return fmt.Errorf("vellaveto: approval ID contains control characters")
		}
	}
	return nil
}

// ApproveApproval approves a pending approval by ID.
// SECURITY (FIND-R46-GO-002): URL-encode the approval ID to prevent path injection.
// SECURITY (FIND-R54-SDK-003): Validate approval ID format before sending.
func (c *Client) ApproveApproval(ctx context.Context, id string) error {
	if err := validateApprovalID(id); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/approve", nil, nil)
}

// DenyApproval denies a pending approval by ID.
// SECURITY (FIND-R46-GO-002): URL-encode the approval ID to prevent path injection.
// SECURITY (FIND-R54-SDK-003): Validate approval ID format before sending.
func (c *Client) DenyApproval(ctx context.Context, id string) error {
	if err := validateApprovalID(id); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/deny", nil, nil)
}

// Discover searches the tool discovery index for tools matching a query.
// SECURITY (FIND-R54-SDK-017): Validates query is non-empty before sending.
func (c *Client) Discover(ctx context.Context, query string, maxResults int, tokenBudget *int) (*DiscoveryResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("vellaveto: discovery query must not be empty")
	}
	reqBody := DiscoverRequest{
		Query:       query,
		MaxResults:  maxResults,
		TokenBudget: tokenBudget,
	}
	var resp DiscoveryResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/discovery/search", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryStats returns statistics about the tool discovery index.
func (c *Client) DiscoveryStats(ctx context.Context) (*DiscoveryIndexStats, error) {
	var resp DiscoveryIndexStats
	if err := c.doJSON(ctx, http.MethodGet, "/api/discovery/index/stats", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryReindex triggers a full rebuild of the IDF weights.
func (c *Client) DiscoveryReindex(ctx context.Context) (*DiscoveryReindexResponse, error) {
	var resp DiscoveryReindexResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/discovery/reindex", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryTools lists all indexed tools, optionally filtered by server ID and sensitivity.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
func (c *Client) DiscoveryTools(ctx context.Context, serverID, sensitivity string) (*DiscoveryToolsResponse, error) {
	path := "/api/discovery/tools"
	q := url.Values{}
	if serverID != "" {
		q.Set("server_id", serverID)
	}
	if sensitivity != "" {
		q.Set("sensitivity", sensitivity)
	}
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp DiscoveryToolsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProjectorModels lists supported model families in the projector registry.
func (c *Client) ProjectorModels(ctx context.Context) (*ProjectorModelsResponse, error) {
	var resp ProjectorModelsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/projector/models", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProjectSchema projects a canonical tool schema for a given model family.
// SECURITY (FIND-R55-SDK-007): Validates modelFamily is non-empty.
func (c *Client) ProjectSchema(ctx context.Context, schema CanonicalToolSchema, modelFamily string) (*ProjectorTransformResponse, error) {
	if strings.TrimSpace(modelFamily) == "" {
		return nil, fmt.Errorf("vellaveto: modelFamily must not be empty")
	}
	reqBody := ProjectorTransformRequest{
		Schema:      schema,
		ModelFamily: modelFamily,
	}
	var resp ProjectorTransformResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/projector/transform", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkStatus returns the current ZK audit scheduler status.
func (c *Client) ZkStatus(ctx context.Context) (*ZkSchedulerStatus, error) {
	var resp ZkSchedulerStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/zk-audit/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkProofs lists stored ZK batch proofs with pagination.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
func (c *Client) ZkProofs(ctx context.Context, limit, offset int) (*ZkProofsResponse, error) {
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("offset", fmt.Sprintf("%d", offset))
	path := "/api/zk-audit/proofs?" + q.Encode()
	var resp ZkProofsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkVerify verifies a stored ZK batch proof by batch ID.
// SECURITY (FIND-R54-SDK-017): Validates batchID is non-empty before sending.
func (c *Client) ZkVerify(ctx context.Context, batchID string) (*ZkVerifyResult, error) {
	if strings.TrimSpace(batchID) == "" {
		return nil, fmt.Errorf("vellaveto: batchID must not be empty")
	}
	reqBody := ZkVerifyRequest{BatchID: batchID}
	var resp ZkVerifyResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/zk-audit/verify", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ZkCommitments lists Pedersen commitments for audit entries in a sequence range.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
func (c *Client) ZkCommitments(ctx context.Context, from, to uint64) (*ZkCommitmentsResponse, error) {
	q := url.Values{}
	q.Set("from", fmt.Sprintf("%d", from))
	q.Set("to", fmt.Sprintf("%d", to))
	path := "/api/zk-audit/commitments?" + q.Encode()
	var resp ZkCommitmentsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Soc2AccessReview generates a SOC 2 Type II access review report.
// SECURITY (FIND-R46-GO-003): Use url.Values for proper URL encoding of query parameters.
func (c *Client) Soc2AccessReview(ctx context.Context, period, format, agentID string) (*AccessReviewReport, error) {
	if len(agentID) > 128 {
		return nil, &VellavetoError{Message: "agent_id exceeds max length (128)"}
	}
	// SECURITY (FIND-R55-SDK-005): Reject control chars. Parity with FederationTrustAnchors.
	for _, ch := range agentID {
		if ch < ' ' || (ch >= 0x7F && ch <= 0x9F) {
			return nil, &VellavetoError{Message: "agent_id contains control characters"}
		}
	}
	q := url.Values{}
	if period != "" {
		q.Set("period", period)
	}
	if format != "" {
		q.Set("format", format)
	}
	if agentID != "" {
		q.Set("agent_id", agentID)
	}
	path := "/api/compliance/soc2/access-review"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp AccessReviewReport
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FederationStatus returns the federation resolver status.
func (c *Client) FederationStatus(ctx context.Context) (*FederationStatusResponse, error) {
	var resp FederationStatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/federation/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FederationTrustAnchors returns configured federation trust anchors.
// orgID is optional; pass empty string to list all.
// SECURITY: Validates orgID length (max 128) and rejects control characters.
func (c *Client) FederationTrustAnchors(ctx context.Context, orgID string) (*FederationTrustAnchorsResponse, error) {
	if len(orgID) > 128 {
		return nil, &VellavetoError{Message: "org_id exceeds max length (128)"}
	}
	// SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
	for _, c := range orgID {
		if c < ' ' || (c >= 0x7F && c <= 0x9F) {
			return nil, &VellavetoError{Message: "org_id contains control characters"}
		}
	}
	path := "/api/federation/trust-anchors"
	if orgID != "" {
		q := url.Values{}
		q.Set("org_id", orgID)
		path += "?" + q.Encode()
	}
	var resp FederationTrustAnchorsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
