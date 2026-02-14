package vellaveto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 5 * time.Second

// Client is the Vellaveto API client.
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
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultTimeout},
		headers:    make(map[string]string),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("vellaveto: read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// doJSON executes a request, checks status, and decodes JSON into dst.
func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, dst interface{}) error {
	respBody, status, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", string(respBody)),
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
func (c *Client) Evaluate(ctx context.Context, action Action, evalCtx *EvaluationContext, trace bool) (*EvaluationResult, error) {
	reqBody := EvaluateRequest{
		Action:  action,
		Context: evalCtx,
		Trace:   trace,
	}

	respBody, status, err := c.do(ctx, http.MethodPost, "/api/evaluate", reqBody)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &VellavetoError{
			Message:    fmt.Sprintf("unexpected status: %s", string(respBody)),
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

// ReloadPolicies triggers a policy reload on the server.
func (c *Client) ReloadPolicies(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/api/policies/reload", nil, nil)
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

// ApproveApproval approves a pending approval by ID.
func (c *Client) ApproveApproval(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+id+"/approve", nil, nil)
}

// DenyApproval denies a pending approval by ID.
func (c *Client) DenyApproval(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/approvals/"+id+"/deny", nil, nil)
}
