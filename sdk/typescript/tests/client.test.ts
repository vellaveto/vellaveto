import {
  VellavetoClient,
  VellavetoError,
  Verdict,
  Action,
  EvaluationResult,
  BatchResponse,
  ValidateResponse,
  SimulateResponse,
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
});
