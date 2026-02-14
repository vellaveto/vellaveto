package sentinel

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
	sentErr, ok := err.(*SentinelError)
	if !ok {
		t.Fatalf("error type = %T, want *SentinelError", err)
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
	sentErr, ok := err.(*SentinelError)
	if !ok {
		t.Fatalf("error type = %T, want *SentinelError", err)
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
		var req EvaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
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
	t.Run("SentinelError with status", func(t *testing.T) {
		e := &SentinelError{Message: "not found", StatusCode: 404}
		want := "sentinel: not found (HTTP 404)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("SentinelError without status", func(t *testing.T) {
		e := &SentinelError{Message: "connection failed"}
		want := "sentinel: connection failed"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError with policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked", PolicyID: "p1"}
		want := "sentinel: policy denied: blocked (policy: p1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("PolicyDeniedError without policy", func(t *testing.T) {
		e := &PolicyDeniedError{Reason: "blocked"}
		want := "sentinel: policy denied: blocked"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError with id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review", ApprovalID: "a1"}
		want := "sentinel: approval required: review (approval: a1)"
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	})

	t.Run("ApprovalRequiredError without id", func(t *testing.T) {
		e := &ApprovalRequiredError{Reason: "review"}
		want := "sentinel: approval required: review"
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
