import {
  VellavetoClient,
  VellavetoError,
  Verdict,
  Action,
  EvaluationResult,
  BatchResponse,
  ValidateResponse,
  SimulateResponse,
  ZkSchedulerStatus,
  ZkProofsResponse,
  ZkVerifyResult,
  ZkCommitmentsResponse,
} from "../src";

// Mock fetch globally
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    headers: new Headers(),
    redirected: false,
    type: "basic",
    url: "",
    clone: () => jsonResponse(body, status) as Response,
    body: null,
    bodyUsed: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob: () => Promise.resolve(new Blob()),
    formData: () => Promise.resolve(new FormData()),
    text: () => Promise.resolve(JSON.stringify(body)),
    bytes: () => Promise.resolve(new Uint8Array()),
  } as Response;
}

describe("VellavetoClient", () => {
  let client: VellavetoClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-key",
      timeout: 1000,
    });
  });

  // ── Health ──────────────────────────────────────

  test("health returns status", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    const result = await client.health();
    expect(result.status).toBe("ok");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/health",
      expect.objectContaining({ method: "GET" })
    );
  });

  // ── Evaluate ────────────────────────────────────

  test("evaluate allow response", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Allow",
        action: { tool: "fs", function: "read" },
      })
    );
    const result = await client.evaluate({ tool: "fs", function: "read" });
    expect(result.verdict).toBe(Verdict.Allow);
  });

  test("evaluate deny response", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "blocked" } },
        action: { tool: "bash", function: "exec" },
      })
    );
    const result = await client.evaluate({ tool: "bash", function: "exec" });
    expect(result.verdict).toBe(Verdict.Deny);
  });

  test("evaluate with trace", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Allow",
        action: {},
        trace: { policies_checked: 3 },
      })
    );
    const result = await client.evaluate({ tool: "fs" }, undefined, true);
    expect(result.trace).toBeDefined();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/evaluate?trace=true",
      expect.anything()
    );
  });

  // ── API Key ─────────────────────────────────────

  test("api key sent in Authorization header", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await client.health();
    const call = mockFetch.mock.calls[0];
    expect(call[1].headers["Authorization"]).toBe("Bearer test-key");
  });

  test("no api key when not configured", async () => {
    const noKeyClient = new VellavetoClient({
      baseUrl: "http://localhost:3000",
    });
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await noKeyClient.health();
    const call = mockFetch.mock.calls[0];
    expect(call[1].headers["Authorization"]).toBeUndefined();
  });

  // ── List Policies ──────────────────────────────

  test("listPolicies returns array", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse([
        { id: "p1", name: "Allow reads", policy_type: "Allow", priority: 100 },
      ])
    );
    const policies = await client.listPolicies();
    expect(policies).toHaveLength(1);
    expect(policies[0].id).toBe("p1");
  });

  // ── Simulate ───────────────────────────────────

  test("simulate returns trace", async () => {
    const mockResp: SimulateResponse = {
      verdict: Verdict.Allow,
      trace: { policies_checked: 2 } as any,
      policies_checked: 2,
      duration_us: 42,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.simulate({ tool: "fs", function: "read" });
    expect(result.policies_checked).toBe(2);
  });

  // ── Batch ──────────────────────────────────────

  test("batchEvaluate multiple actions", async () => {
    const mockResp: BatchResponse = {
      results: [
        { action_index: 0, verdict: Verdict.Allow },
        { action_index: 1, verdict: Verdict.Deny },
      ],
      summary: { total: 2, allowed: 1, denied: 1, errors: 0, duration_us: 100 },
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.batchEvaluate([
      { tool: "fs" },
      { tool: "bash" },
    ]);
    expect(result.summary.total).toBe(2);
    expect(result.results).toHaveLength(2);
  });

  // ── Validate Config ────────────────────────────

  test("validateConfig valid", async () => {
    const mockResp: ValidateResponse = {
      valid: true,
      findings: [],
      summary: {
        total_policies: 2,
        errors: 0,
        warnings: 0,
        infos: 0,
        valid: true,
      },
      policy_count: 2,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.validateConfig("[[policies]]");
    expect(result.valid).toBe(true);
    expect(result.policy_count).toBe(2);
  });

  test("validateConfig invalid", async () => {
    const mockResp: ValidateResponse = {
      valid: false,
      findings: [
        {
          severity: "error",
          category: "syntax",
          code: "E001",
          message: "Bad config",
        },
      ],
      summary: {
        total_policies: 0,
        errors: 1,
        warnings: 0,
        infos: 0,
        valid: false,
      },
      policy_count: 0,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResp));
    const result = await client.validateConfig("bad");
    expect(result.valid).toBe(false);
    expect(result.findings).toHaveLength(1);
  });

  // ── Error handling ─────────────────────────────

  test("401 throws VellavetoError", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Unauthorized" }, 401)
    );
    await expect(client.health()).rejects.toThrow(VellavetoError);
    await expect(client.health()).rejects.toThrow(); // fetch is already consumed so need separate mock
  });

  test("500 throws VellavetoError with message", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Internal error" }, 500)
    );
    try {
      await client.health();
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VellavetoError);
      expect((e as VellavetoError).statusCode).toBe(500);
    }
  });

  test("network error throws VellavetoError", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Connection refused"));
    await expect(client.health()).rejects.toThrow(VellavetoError);
  });

  // ── Trailing slash removal ─────────────────────

  test("trailing slash removed from baseUrl", async () => {
    const slashClient = new VellavetoClient({
      baseUrl: "http://localhost:3000/",
    });
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await slashClient.health();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/health",
      expect.anything()
    );
  });

  // ── FIND-R46-TS-003: baseUrl validation ──────

  test("empty baseUrl throws VellavetoError", () => {
    expect(() => new VellavetoClient({ baseUrl: "" })).toThrow(VellavetoError);
    expect(() => new VellavetoClient({ baseUrl: "   " })).toThrow(VellavetoError);
  });

  test("baseUrl without http/https throws VellavetoError", () => {
    expect(() => new VellavetoClient({ baseUrl: "ftp://example.com" })).toThrow(
      "http:// or https://"
    );
    expect(() => new VellavetoClient({ baseUrl: "ws://example.com" })).toThrow(
      "http:// or https://"
    );
  });

  test("baseUrl with credentials throws VellavetoError", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "https://user:pass@example.com" })
    ).toThrow("credentials");
  });

  test("valid https baseUrl accepted", () => {
    expect(
      () => new VellavetoClient({ baseUrl: "https://api.example.com" })
    ).not.toThrow();
  });

  // ── FIND-R46-TS-004: API key not leaked in errors ──

  test("API key not leaked in network error messages", async () => {
    const secretKey = "sk-super-secret-api-key-12345";
    const keyClient = new VellavetoClient({
      baseUrl: "http://localhost:3000",
      apiKey: secretKey,
    });
    // Simulate a network error that includes the API key in its message
    mockFetch.mockRejectedValueOnce(
      new Error(`Connection refused: Bearer ${secretKey}`)
    );
    try {
      await keyClient.health();
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VellavetoError);
      expect((e as VellavetoError).message).not.toContain(secretKey);
      expect((e as VellavetoError).message).toContain("[REDACTED]");
    }
  });

  // ── FIND-R46-TS-005: http:// warning on non-localhost ──

  test("http:// on non-localhost logs warning", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    new VellavetoClient({ baseUrl: "http://api.example.com" });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("unencrypted HTTP")
    );
    warnSpy.mockRestore();
  });

  test("http:// on localhost does not log warning", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    new VellavetoClient({ baseUrl: "http://localhost:3000" });
    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  // ── P1-10: evaluate extracts reason, policy_id, policy_name ──

  test("evaluate extracts reason from top-level field", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Deny",
        reason: "path blocked by policy",
        policy_id: "pol-123",
        policy_name: "Block sensitive paths",
      })
    );
    const result = await client.evaluate({ tool: "fs", function: "read" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBe("path blocked by policy");
    expect(result.policy_id).toBe("pol-123");
    expect(result.policy_name).toBe("Block sensitive paths");
  });

  test("evaluate extracts reason from verdict object", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "blocked by deny rule" } },
        action: { tool: "bash" },
      })
    );
    const result = await client.evaluate({ tool: "bash" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBe("blocked by deny rule");
  });

  test("evaluate top-level reason takes precedence over verdict object reason", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { Deny: { reason: "inner reason" } },
        reason: "top-level reason",
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.reason).toBe("top-level reason");
  });

  test("evaluate extracts reason from RequireApproval verdict object", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: { RequireApproval: { reason: "needs human review" } },
        approval_id: "appr-456",
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.RequireApproval);
    expect(result.reason).toBe("needs human review");
    expect(result.approval_id).toBe("appr-456");
  });

  test("evaluate returns undefined for missing optional fields", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ verdict: "Allow" })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.Allow);
    expect(result.reason).toBeUndefined();
    expect(result.policy_id).toBeUndefined();
    expect(result.policy_name).toBeUndefined();
    expect(result.approval_id).toBeUndefined();
  });

  test("evaluate ignores non-string reason/policy_id/policy_name", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        verdict: "Deny",
        reason: 42,
        policy_id: true,
        policy_name: ["not", "a", "string"],
      })
    );
    const result = await client.evaluate({ tool: "fs" });
    expect(result.verdict).toBe(Verdict.Deny);
    expect(result.reason).toBeUndefined();
    expect(result.policy_id).toBeUndefined();
    expect(result.policy_name).toBeUndefined();
  });

  // ── P1-11: ZK Audit ─────────────────────────────

  test("zkStatus returns scheduler status", async () => {
    const mockStatus: ZkSchedulerStatus = {
      active: true,
      pending_witnesses: 5,
      completed_proofs: 12,
      last_proved_sequence: 100,
      last_proof_at: "2026-02-16T10:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockStatus));
    const result = await client.zkStatus();
    expect(result.active).toBe(true);
    expect(result.pending_witnesses).toBe(5);
    expect(result.completed_proofs).toBe(12);
    expect(result.last_proved_sequence).toBe(100);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/status",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkProofs returns proof list", async () => {
    const mockProofs: ZkProofsResponse = {
      proofs: [
        {
          proof: "deadbeef",
          batch_id: "batch-001",
          entry_range: [1, 50],
          merkle_root: "aabbcc",
          first_prev_hash: "000000",
          final_entry_hash: "ffffff",
          created_at: "2026-02-16T09:00:00Z",
          entry_count: 50,
        },
      ],
      total: 1,
      offset: 0,
      limit: 20,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockProofs));
    const result = await client.zkProofs(10, 0);
    expect(result.proofs).toHaveLength(1);
    expect(result.proofs[0].batch_id).toBe("batch-001");
    expect(result.total).toBe(1);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/proofs?limit=10&offset=0",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkProofs without parameters omits query string", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ proofs: [], total: 0, offset: 0, limit: 20 })
    );
    await client.zkProofs();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/proofs",
      expect.objectContaining({ method: "GET" })
    );
  });

  test("zkVerify sends batch_id and returns result", async () => {
    const mockResult: ZkVerifyResult = {
      valid: true,
      batch_id: "batch-001",
      entry_range: [1, 50],
      verified_at: "2026-02-16T10:30:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResult));
    const result = await client.zkVerify("batch-001");
    expect(result.valid).toBe(true);
    expect(result.batch_id).toBe("batch-001");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/verify",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ batch_id: "batch-001" }),
      })
    );
  });

  test("zkVerify returns error on invalid proof", async () => {
    const mockResult: ZkVerifyResult = {
      valid: false,
      batch_id: "batch-bad",
      entry_range: [1, 10],
      verified_at: "2026-02-16T10:30:00Z",
      error: "proof verification failed",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockResult));
    const result = await client.zkVerify("batch-bad");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("proof verification failed");
  });

  test("zkCommitments returns commitments for range", async () => {
    const mockCommitments: ZkCommitmentsResponse = {
      commitments: [
        { sequence: 1, commitment: "aabb" },
        { sequence: 2, commitment: "ccdd" },
      ],
      total: 2,
      range: [1, 2],
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(mockCommitments));
    const result = await client.zkCommitments(1, 2);
    expect(result.commitments).toHaveLength(2);
    expect(result.total).toBe(2);
    expect(result.range).toEqual([1, 2]);
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:3000/api/zk-audit/commitments?from=1&to=2",
      expect.objectContaining({ method: "GET" })
    );
  });
});
