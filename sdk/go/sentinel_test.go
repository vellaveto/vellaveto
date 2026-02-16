package vellaveto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// helper: create a test server that returns the given status and JSON body.
func testServer(t *testing.T, wantMethod, wantPath string, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %s, want %s", r.Method, wantMethod)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
	}))
}

func TestHealth(t *testing.T) {
	srv := testServer(t, "GET", "/health", 200, HealthResponse{Status: "ok", Version: "3.0.0"})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
	if resp.Version != "3.0.0" {
		t.Errorf("Version = %q, want %q", resp.Version, "3.0.0")
	}
}

func TestEvaluate_Allow(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "allow",
		"policy_id": "p1",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "read_file"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictAllow)
	}
	if result.PolicyID != "p1" {
		t.Errorf("PolicyID = %q, want %q", result.PolicyID, "p1")
	}
}

func TestEvaluate_Deny(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "deny",
		"reason":    "blocked by policy",
		"policy_id": "p2",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "exec"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if result.Reason != "blocked by policy" {
		t.Errorf("Reason = %q, want %q", result.Reason, "blocked by policy")
	}
}

func TestEvaluate_ObjectVerdict(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": map[string]interface{}{
			"Deny": map[string]interface{}{
				"reason": "object-form deny",
			},
		},
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "exec"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if result.Reason != "object-form deny" {
		t.Errorf("Reason = %q, want %q", result.Reason, "object-form deny")
	}
}

func TestEvaluate_UnknownVerdict_FailClosed(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": "unknown_value",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result.Verdict != VerdictDeny {
		t.Errorf("Verdict = %q, want %q (fail-closed)", result.Verdict, VerdictDeny)
	}
}

func TestEvaluateOrError_Allow(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict": "allow",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "read"}, nil)
	if err != nil {
		t.Fatalf("EvaluateOrError() should be nil for allow, got: %v", err)
	}
}

func TestEvaluateOrError_Deny(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":   "deny",
		"reason":    "no access",
		"policy_id": "p3",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "write"}, nil)
	if err == nil {
		t.Fatal("EvaluateOrError() should return error for deny")
	}
	denied, ok := err.(*PolicyDeniedError)
	if !ok {
		t.Fatalf("error type = %T, want *PolicyDeniedError", err)
	}
	if denied.Reason != "no access" {
		t.Errorf("Reason = %q, want %q", denied.Reason, "no access")
	}
	if denied.PolicyID != "p3" {
		t.Errorf("PolicyID = %q, want %q", denied.PolicyID, "p3")
	}
}

func TestEvaluateOrError_RequireApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 200, map[string]interface{}{
		"verdict":     "require_approval",
		"reason":      "needs review",
		"approval_id": "apr-1",
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.EvaluateOrError(context.Background(), Action{Tool: "deploy"}, nil)
	if err == nil {
		t.Fatal("EvaluateOrError() should return error for require_approval")
	}
	approval, ok := err.(*ApprovalRequiredError)
	if !ok {
		t.Fatalf("error type = %T, want *ApprovalRequiredError", err)
	}
	if approval.Reason != "needs review" {
		t.Errorf("Reason = %q, want %q", approval.Reason, "needs review")
	}
	if approval.ApprovalID != "apr-1" {
		t.Errorf("ApprovalID = %q, want %q", approval.ApprovalID, "apr-1")
	}
}

func TestListPolicies(t *testing.T) {
	policies := []PolicySummary{
		{ID: "p1", Name: "allow-reads", PolicyType: "allow", Priority: 10},
		{ID: "p2", Name: "deny-exec", PolicyType: "deny", Priority: 20},
	}
	srv := testServer(t, "GET", "/api/policies", 200, policies)
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0].Name != "allow-reads" {
		t.Errorf("result[0].Name = %q, want %q", result[0].Name, "allow-reads")
	}
}

func TestReloadPolicies(t *testing.T) {
	srv := testServer(t, "POST", "/api/policies/reload", 200, map[string]string{"status": "reloaded"})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatalf("ReloadPolicies() error: %v", err)
	}
}

func TestSimulate(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/evaluate", 200, SimulateResponse{
		Verdict:         VerdictAllow,
		PoliciesChecked: 3,
		DurationUs:      42,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.Simulate(context.Background(), Action{Tool: "read_file"}, nil)
	if err != nil {
		t.Fatalf("Simulate() error: %v", err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want %q", resp.Verdict, VerdictAllow)
	}
	if resp.PoliciesChecked != 3 {
		t.Errorf("PoliciesChecked = %d, want 3", resp.PoliciesChecked)
	}
}

func TestBatchEvaluate(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/batch", 200, BatchResponse{
		Results: []BatchResult{
			{ActionIndex: 0, Verdict: VerdictAllow},
			{ActionIndex: 1, Verdict: VerdictDeny},
		},
		Summary: BatchSummary{Total: 2, Allowed: 1, Denied: 1},
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.BatchEvaluate(context.Background(), []Action{
		{Tool: "read_file"},
		{Tool: "exec"},
	}, nil)
	if err != nil {
		t.Fatalf("BatchEvaluate() error: %v", err)
	}
	if resp.Summary.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Summary.Total)
	}
	if resp.Results[1].Verdict != VerdictDeny {
		t.Errorf("Results[1].Verdict = %q, want %q", resp.Results[1].Verdict, VerdictDeny)
	}
}

func TestValidateConfig(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/validate", 200, ValidateResponse{
		Valid:       true,
		PolicyCount: 5,
		Summary:     ValidationSummary{TotalPolicies: 5, Valid: true},
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ValidateConfig(context.Background(), map[string]interface{}{"policies": []string{}}, false)
	if err != nil {
		t.Fatalf("ValidateConfig() error: %v", err)
	}
	if !resp.Valid {
		t.Error("Valid = false, want true")
	}
}

func TestDiffConfigs(t *testing.T) {
	srv := testServer(t, "POST", "/api/simulator/diff", 200, DiffResponse{
		Added:     []PolicySummary{{ID: "p3", Name: "new-policy"}},
		Removed:   []PolicySummary{},
		Modified:  []PolicyDiff{},
		Unchanged: 2,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.DiffConfigs(context.Background(), map[string]interface{}{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("DiffConfigs() error: %v", err)
	}
	if len(resp.Added) != 1 {
		t.Fatalf("Added len = %d, want 1", len(resp.Added))
	}
	if resp.Added[0].Name != "new-policy" {
		t.Errorf("Added[0].Name = %q, want %q", resp.Added[0].Name, "new-policy")
	}
}

func TestListPendingApprovals(t *testing.T) {
	approvals := []Approval{
		{ID: "apr-1", Reason: "needs review", CreatedAt: "2026-01-01T00:00:00Z"},
	}
	srv := testServer(t, "GET", "/api/approvals/pending", 200, approvals)
	defer srv.Close()

	c := NewClient(srv.URL)
	result, err := c.ListPendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListPendingApprovals() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0].ID != "apr-1" {
		t.Errorf("ID = %q, want %q", result[0].ID, "apr-1")
	}
}

func TestApproveApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/approvals/apr-1/approve", 200, map[string]string{"status": "approved"})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.ApproveApproval(context.Background(), "apr-1")
	if err != nil {
		t.Fatalf("ApproveApproval() error: %v", err)
	}
}

func TestDenyApproval(t *testing.T) {
	srv := testServer(t, "POST", "/api/approvals/apr-1/deny", 200, map[string]string{"status": "denied"})
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.DenyApproval(context.Background(), "apr-1")
	if err != nil {
		t.Fatalf("DenyApproval() error: %v", err)
	}
}

func TestAPIKey_Header(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key-123" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer test-key-123")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, WithAPIKey("test-key-123"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestNoAPIKey_NoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("Authorization header should be empty, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestCustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("X-Custom = %q, want %q", r.Header.Get("X-Custom"), "value")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, WithHeaders(map[string]string{"X-Custom": "value"}))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

func TestHTTPError(t *testing.T) {
	srv := testServer(t, "GET", "/health", 500, map[string]string{"error": "internal"})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error for 500")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

func TestUnauthorizedError(t *testing.T) {
	srv := testServer(t, "POST", "/api/evaluate", 401, map[string]string{"error": "unauthorized"})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err == nil {
		t.Fatal("Evaluate() should return error for 401")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", sentErr.StatusCode)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, WithTimeout(50*time.Millisecond))
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error on timeout")
	}
}

func TestTrailingSlashRemoved(t *testing.T) {
	srv := testServer(t, "GET", "/health", 200, HealthResponse{Status: "ok"})
	defer srv.Close()

	c := NewClient(srv.URL + "/")
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

func TestEvaluateWithContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server uses #[serde(flatten)] so fields are at root level, not nested.
		var req EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Tool != "read" {
			t.Errorf("Tool = %q, want %q", req.Tool, "read")
		}
		if req.Context == nil {
			t.Fatal("context should not be nil")
		}
		if req.Context.SessionID != "sess-1" {
			t.Errorf("SessionID = %q, want %q", req.Context.SessionID, "sess-1")
		}
		if req.Context.AgentID != "agent-1" {
			t.Errorf("AgentID = %q, want %q", req.Context.AgentID, "agent-1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "read"}, &EvaluationContext{
		SessionID: "sess-1",
		AgentID:   "agent-1",
	}, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		input string
		want  Verdict
	}{
		{"allow", VerdictAllow},
		{"Allow", VerdictAllow},
		{"deny", VerdictDeny},
		{"Deny", VerdictDeny},
		{"require_approval", VerdictRequireApproval},
		{"RequireApproval", VerdictRequireApproval},
		{"", VerdictDeny},
		{"unknown", VerdictDeny},
		{"ALLOW", VerdictDeny}, // only exact matches
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseVerdict(tt.input)
			if got != tt.want {
				t.Errorf("ParseVerdict(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	t.Run("VellavetoError with status", func(t *testing.T) {
		e := &VellavetoError{Message: "not found", StatusCode: 404}
		want := "vellaveto: not found (HTTP 404)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("VellavetoError without status", func(t *testing.T) {
		e := &VellavetoError{Message: "connection failed"}
		want := "vellaveto: connection failed"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError with policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked", PolicyID: "p1"}
		want := "vellaveto: policy denied: blocked (policy: p1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError without policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked"}
		want := "vellaveto: policy denied: blocked"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError with id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review", ApprovalID: "a1"}
		want := "vellaveto: approval required: review (approval: a1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError without id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review"}
		want := "vellaveto: approval required: review"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})
}

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 10 * time.Second}
	c := NewClient("http://localhost", WithHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("httpClient should be the custom client")
	}
}

// SECURITY (FIND-R46-GO-007): Action.Validate() tests
func TestActionValidate_EmptyTool(t *testing.T) {
	a := &Action{}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty Tool")
	}
}

func TestActionValidate_ValidAction(t *testing.T) {
	a := &Action{Tool: "read_file", Function: "read"}
	err := a.Validate()
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestActionValidate_ToolTooLong(t *testing.T) {
	longTool := make([]byte, 300)
	for i := range longTool {
		longTool[i] = 'x'
	}
	a := &Action{Tool: string(longTool)}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject oversized Tool")
	}
}

func TestActionValidate_TooManyTargetPaths(t *testing.T) {
	paths := make([]string, 101)
	for i := range paths {
		paths[i] = "/some/path"
	}
	a := &Action{Tool: "fs", TargetPaths: paths}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 TargetPaths")
	}
}

func TestActionValidate_TooManyTargetDomains(t *testing.T) {
	domains := make([]string, 101)
	for i := range domains {
		domains[i] = "example.com"
	}
	a := &Action{Tool: "http", TargetDomains: domains}
	err := a.Validate()
	if err == nil {
		t.Fatal("Validate() should reject >100 TargetDomains")
	}
}

// SECURITY (FIND-R46-GO-003): Verify query parameters are properly URL-encoded.
func TestDiscoveryTools_QueryParamEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the query parameters are properly encoded
		serverID := r.URL.Query().Get("server_id")
		sensitivity := r.URL.Query().Get("sensitivity")
		if serverID != "server&evil=1" {
			t.Errorf("server_id = %q, want %q", serverID, "server&evil=1")
		}
		if sensitivity != "high&drop=table" {
			t.Errorf("sensitivity = %q, want %q", sensitivity, "high&drop=table")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DiscoveryToolsResponse{Tools: []ToolMetadata{}, Total: 0})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	// These values contain '&' and '=' which must be URL-encoded
	_, err := c.DiscoveryTools(context.Background(), "server&evil=1", "high&drop=table")
	if err != nil {
		t.Fatalf("DiscoveryTools() error: %v", err)
	}
}

// SECURITY (FIND-R46-GO-004): Verify Authorization header is stripped on cross-domain redirect.
func TestRedirectStripsAuthOnCrossDomain(t *testing.T) {
	// Target server that checks there's no Authorization header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("Authorization header should be stripped on cross-domain redirect, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer target.Close()

	// Origin server that redirects to target
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/health", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := NewClient(origin.URL, WithAPIKey("secret-key"))
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q, want %q", resp.Status, "ok")
	}
}

// SECURITY (FIND-R46-GO-004): Verify Authorization header is preserved on same-domain redirect.
func TestRedirectPreservesAuthOnSameDomain(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// First call: redirect to /health on same server
			http.Redirect(w, r, "/health", http.StatusTemporaryRedirect)
			return
		}
		// Second call: verify auth header is still present
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-key" {
			t.Errorf("Authorization header should be preserved on same-domain redirect, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, WithAPIKey("my-key"))
	_, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error: %v", err)
	}
}

// SECURITY (FIND-R46-GO-005): Verify error messages truncate large response bodies.
func TestErrorBodyTruncation(t *testing.T) {
	// Return a very large error body
	largeBody := make([]byte, 1024)
	for i := range largeBody {
		largeBody[i] = 'X'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write(largeBody)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Health(context.Background())
	if err == nil {
		t.Fatal("Health() should return error for 500")
	}
	errMsg := err.Error()
	// The error message should be truncated, not contain the full 1024-byte body
	if len(errMsg) > 400 {
		t.Errorf("Error message should be truncated, got %d chars", len(errMsg))
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

// SECURITY (P0-2): Verify Evaluate sends flattened Action fields at root level.
func TestEvaluate_FlattenedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode into a generic map to verify field layout
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}

		// Fields must be at the root level (flattened), NOT nested under "action"
		if _, hasAction := body["action"]; hasAction {
			t.Error("body should NOT have nested 'action' key — server uses #[serde(flatten)]")
		}
		if tool, ok := body["tool"].(string); !ok || tool != "read_file" {
			t.Errorf("body[\"tool\"] = %v, want %q", body["tool"], "read_file")
		}
		if fn, ok := body["function"].(string); !ok || fn != "read" {
			t.Errorf("body[\"function\"] = %v, want %q", body["function"], "read")
		}
		params, ok := body["parameters"].(map[string]interface{})
		if !ok {
			t.Fatalf("body[\"parameters\"] type = %T, want map", body["parameters"])
		}
		if params["path"] != "/etc/hosts" {
			t.Errorf("parameters.path = %v, want %q", params["path"], "/etc/hosts")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), Action{
		Tool:     "read_file",
		Function: "read",
		Parameters: map[string]interface{}{
			"path": "/etc/hosts",
		},
	}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// Verify trace=true becomes a query parameter, not a body field.
func TestEvaluate_TraceQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// trace should be a query parameter
		if r.URL.Query().Get("trace") != "true" {
			t.Errorf("query param trace = %q, want %q", r.URL.Query().Get("trace"), "true")
		}

		// trace should NOT be in the body
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, hasTrace := body["trace"]; hasTrace {
			t.Error("body should NOT have 'trace' field — it is a query parameter")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, true)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// Verify trace=false does NOT add query parameter.
func TestEvaluate_NoTraceQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("URL should have no query params when trace=false, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"verdict": "allow"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), Action{Tool: "x"}, nil, false)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// ZK Audit tests (P1-11)
// ═══════════════════════════════════════════════════════════════════

func TestZkStatus(t *testing.T) {
	seq := uint64(42)
	at := "2026-02-16T12:00:00Z"
	srv := testServer(t, "GET", "/api/zk-audit/status", 200, ZkSchedulerStatus{
		Active:             true,
		PendingWitnesses:   5,
		CompletedProofs:    10,
		LastProvedSequence: &seq,
		LastProofAt:        &at,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkStatus(context.Background())
	if err != nil {
		t.Fatalf("ZkStatus() error: %v", err)
	}
	if !resp.Active {
		t.Error("Active = false, want true")
	}
	if resp.PendingWitnesses != 5 {
		t.Errorf("PendingWitnesses = %d, want 5", resp.PendingWitnesses)
	}
	if resp.CompletedProofs != 10 {
		t.Errorf("CompletedProofs = %d, want 10", resp.CompletedProofs)
	}
	if resp.LastProvedSequence == nil || *resp.LastProvedSequence != 42 {
		t.Errorf("LastProvedSequence = %v, want 42", resp.LastProvedSequence)
	}
	if resp.LastProofAt == nil || *resp.LastProofAt != "2026-02-16T12:00:00Z" {
		t.Errorf("LastProofAt = %v, want %q", resp.LastProofAt, "2026-02-16T12:00:00Z")
	}
}

func TestZkStatus_Inactive(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/status", 200, ZkSchedulerStatus{
		Active:           false,
		PendingWitnesses: 0,
		CompletedProofs:  0,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkStatus(context.Background())
	if err != nil {
		t.Fatalf("ZkStatus() error: %v", err)
	}
	if resp.Active {
		t.Error("Active = true, want false")
	}
	if resp.LastProvedSequence != nil {
		t.Errorf("LastProvedSequence should be nil, got %v", resp.LastProvedSequence)
	}
}

func TestZkProofs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/proofs" {
			t.Errorf("path = %s, want /api/zk-audit/proofs", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("limit = %q, want %q", r.URL.Query().Get("limit"), "10")
		}
		if r.URL.Query().Get("offset") != "5" {
			t.Errorf("offset = %q, want %q", r.URL.Query().Get("offset"), "5")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkProofsResponse{
			Proofs: []ZkBatchProof{
				{
					Proof:          "abc123",
					BatchID:        "batch-1",
					EntryRange:     [2]uint64{0, 99},
					MerkleRoot:     "deadbeef",
					FirstPrevHash:  "0000",
					FinalEntryHash: "ffff",
					CreatedAt:      "2026-02-16T12:00:00Z",
					EntryCount:     100,
				},
			},
			Total:  1,
			Offset: 5,
			Limit:  10,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkProofs(context.Background(), 10, 5)
	if err != nil {
		t.Fatalf("ZkProofs() error: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("Total = %d, want 1", resp.Total)
	}
	if len(resp.Proofs) != 1 {
		t.Fatalf("len(Proofs) = %d, want 1", len(resp.Proofs))
	}
	if resp.Proofs[0].BatchID != "batch-1" {
		t.Errorf("BatchID = %q, want %q", resp.Proofs[0].BatchID, "batch-1")
	}
	if resp.Proofs[0].EntryRange != [2]uint64{0, 99} {
		t.Errorf("EntryRange = %v, want [0, 99]", resp.Proofs[0].EntryRange)
	}
	if resp.Proofs[0].EntryCount != 100 {
		t.Errorf("EntryCount = %d, want 100", resp.Proofs[0].EntryCount)
	}
}

func TestZkVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/verify" {
			t.Errorf("path = %s, want /api/zk-audit/verify", r.URL.Path)
		}
		var req ZkVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.BatchID != "batch-1" {
			t.Errorf("BatchID = %q, want %q", req.BatchID, "batch-1")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkVerifyResult{
			Valid:      true,
			BatchID:    "batch-1",
			EntryRange: [2]uint64{0, 99},
			VerifiedAt: "2026-02-16T12:30:00Z",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkVerify(context.Background(), "batch-1")
	if err != nil {
		t.Fatalf("ZkVerify() error: %v", err)
	}
	if !resp.Valid {
		t.Error("Valid = false, want true")
	}
	if resp.BatchID != "batch-1" {
		t.Errorf("BatchID = %q, want %q", resp.BatchID, "batch-1")
	}
	if resp.EntryRange != [2]uint64{0, 99} {
		t.Errorf("EntryRange = %v, want [0, 99]", resp.EntryRange)
	}
	if resp.VerifiedAt != "2026-02-16T12:30:00Z" {
		t.Errorf("VerifiedAt = %q, want %q", resp.VerifiedAt, "2026-02-16T12:30:00Z")
	}
	if resp.Error != nil {
		t.Errorf("Error = %v, want nil", resp.Error)
	}
}

func TestZkVerify_WithError(t *testing.T) {
	errMsg := "proof invalid"
	srv := testServer(t, "POST", "/api/zk-audit/verify", 200, ZkVerifyResult{
		Valid:      false,
		BatchID:    "batch-bad",
		EntryRange: [2]uint64{0, 49},
		VerifiedAt: "2026-02-16T13:00:00Z",
		Error:      &errMsg,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkVerify(context.Background(), "batch-bad")
	if err != nil {
		t.Fatalf("ZkVerify() error: %v", err)
	}
	if resp.Valid {
		t.Error("Valid = true, want false")
	}
	if resp.Error == nil || *resp.Error != "proof invalid" {
		t.Errorf("Error = %v, want %q", resp.Error, "proof invalid")
	}
}

func TestZkCommitments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/zk-audit/commitments" {
			t.Errorf("path = %s, want /api/zk-audit/commitments", r.URL.Path)
		}
		if r.URL.Query().Get("from") != "0" {
			t.Errorf("from = %q, want %q", r.URL.Query().Get("from"), "0")
		}
		if r.URL.Query().Get("to") != "100" {
			t.Errorf("to = %q, want %q", r.URL.Query().Get("to"), "100")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ZkCommitmentsResponse{
			Commitments: []ZkCommitmentEntry{
				{Sequence: 0, Commitment: "aabb", Timestamp: "2026-02-16T12:00:00Z"},
				{Sequence: 1, Commitment: "ccdd", Timestamp: "2026-02-16T12:01:00Z"},
			},
			Total: 2,
			Range: [2]uint64{0, 100},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkCommitments(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("ZkCommitments() error: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if len(resp.Commitments) != 2 {
		t.Fatalf("len(Commitments) = %d, want 2", len(resp.Commitments))
	}
	if resp.Commitments[0].Sequence != 0 {
		t.Errorf("Commitments[0].Sequence = %d, want 0", resp.Commitments[0].Sequence)
	}
	if resp.Commitments[0].Commitment != "aabb" {
		t.Errorf("Commitments[0].Commitment = %q, want %q", resp.Commitments[0].Commitment, "aabb")
	}
	if resp.Range != [2]uint64{0, 100} {
		t.Errorf("Range = %v, want [0, 100]", resp.Range)
	}
}

func TestZkStatus_HTTPError(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/status", 500, map[string]string{"error": "internal"})
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.ZkStatus(context.Background())
	if err == nil {
		t.Fatal("ZkStatus() should return error for 500")
	}
	sentErr, ok := err.(*VellavetoError)
	if !ok {
		t.Fatalf("error type = %T, want *VellavetoError", err)
	}
	if sentErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", sentErr.StatusCode)
	}
}

func TestZkProofs_Empty(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/proofs", 200, ZkProofsResponse{
		Proofs: []ZkBatchProof{},
		Total:  0,
		Offset: 0,
		Limit:  20,
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkProofs(context.Background(), 20, 0)
	if err != nil {
		t.Fatalf("ZkProofs() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if len(resp.Proofs) != 0 {
		t.Errorf("len(Proofs) = %d, want 0", len(resp.Proofs))
	}
}

func TestZkCommitments_Empty(t *testing.T) {
	srv := testServer(t, "GET", "/api/zk-audit/commitments", 200, ZkCommitmentsResponse{
		Commitments: []ZkCommitmentEntry{},
		Total:       0,
		Range:       [2]uint64{50, 60},
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	resp, err := c.ZkCommitments(context.Background(), 50, 60)
	if err != nil {
		t.Fatalf("ZkCommitments() error: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
	if resp.Range != [2]uint64{50, 60} {
		t.Errorf("Range = %v, want [50, 60]", resp.Range)
	}
}
