// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, beforeEach } from "vitest";
import { configure, getBaseUrl, ApiError } from "./client";
import * as api from "./client";

// Shared mock helpers
const jsonResponse = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });

const errorResponse = (status: number, body: { error: string }) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("configure / getBaseUrl", () => {
  it("strips trailing slashes", () => {
    configure("https://example.com///", "key1");
    expect(getBaseUrl()).toBe("https://example.com");
  });

  it("sets empty string when url is empty", () => {
    configure("", "");
    expect(getBaseUrl()).toBe("");
  });
});

describe("ApiError", () => {
  it("has status, message, and details", () => {
    const err = new ApiError(403, "Forbidden", "missing scope");
    expect(err.status).toBe(403);
    expect(err.message).toBe("Forbidden");
    expect(err.details).toBe("missing scope");
    expect(err.name).toBe("ApiError");
  });

  it("works without details", () => {
    const err = new ApiError(500, "Internal");
    expect(err.details).toBeUndefined();
  });
});

describe("API methods", () => {
  beforeEach(() => {
    configure("http://localhost:3000", "test-key");
    vi.restoreAllMocks();
  });

  it("health() calls /health", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ status: "ok", version: "4.0.0", uptime_secs: 120 }),
    );
    const result = await api.health();
    expect(result.status).toBe("ok");
    expect(spy).toHaveBeenCalledOnce();
    const url = spy.mock.calls[0][0];
    expect(url).toBe("http://localhost:3000/health");
  });

  it("sends Authorization header when API key is set", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ status: "ok", version: "4.0.0", uptime_secs: 0 }),
    );
    await api.health();
    const init = spy.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer test-key");
  });

  it("throws ApiError on non-2xx", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      errorResponse(403, { error: "Forbidden" }),
    );
    try {
      await api.health();
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).status).toBe(403);
      expect((e as ApiError).message).toBe("Forbidden");
    }
  });

  it("listPolicies() calls /api/policies", async () => {
    const policies = [
      { id: "p1", name: "test", policy_type: "allow", priority: 0 },
    ];
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(policies),
    );
    const result = await api.listPolicies();
    expect(result).toEqual(policies);
    expect(spy.mock.calls[0][0]).toBe("http://localhost:3000/api/policies");
  });

  it("deletePolicy() encodes the ID", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    await api.deletePolicy("policy/with spaces");
    expect(spy.mock.calls[0][0]).toContain(
      encodeURIComponent("policy/with spaces"),
    );
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("DELETE");
  });

  it("searchAudit() builds query string from params", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([]),
    );
    await api.searchAudit({
      tool: "file_read",
      verdict: "deny",
      limit: 10,
    });
    const url = spy.mock.calls[0][0] as string;
    expect(url).toContain("tool=file_read");
    expect(url).toContain("verdict=deny");
    expect(url).toContain("limit=10");
  });

  it("exportAudit() requests correct format", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("line1\nline2", {
        status: 200,
        headers: { "content-type": "text/plain" },
      }),
    );
    const result = await api.exportAudit("jsonl");
    expect(result).toBe("line1\nline2");
    expect(spy.mock.calls[0][0]).toContain("format=jsonl");
  });

  it("approveRequest() POSTs to correct URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    await api.approveRequest("req-123");
    expect(spy.mock.calls[0][0]).toBe(
      "http://localhost:3000/api/approvals/req-123/approve",
    );
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
  });

  it("denyRequest() POSTs to correct URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    await api.denyRequest("req-456");
    expect(spy.mock.calls[0][0]).toContain("/req-456/deny");
  });

  it("listAgents() calls /api/nhi/agents", async () => {
    const agents = [
      { id: "a1", name: "bot", status: "active", created_at: "2024-01-01" },
    ];
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(agents),
    );
    const result = await api.listAgents();
    expect(result).toEqual(agents);
    expect(spy.mock.calls[0][0]).toBe(
      "http://localhost:3000/api/nhi/agents",
    );
  });

  it("suspendAgent() POSTs to correct URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    await api.suspendAgent("agent-1");
    expect(spy.mock.calls[0][0]).toContain("/agent-1/suspend");
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
  });

  it("getUsage() encodes tenant ID", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ evaluations: 100, allowed: 80, denied: 20, policies: 5, approvals: 3, audit_entries: 100 }),
    );
    await api.getUsage("tenant/special");
    expect(spy.mock.calls[0][0]).toContain(
      encodeURIComponent("tenant/special"),
    );
  });

  it("resetCircuitBreaker() POSTs to correct URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    await api.resetCircuitBreaker("risky-tool");
    expect(spy.mock.calls[0][0]).toContain(
      "/api/circuit-breaker/risky-tool/reset",
    );
  });

  it("simulateEvaluate() POSTs action body", async () => {
    const action = { tool: "file_read", function: "read", parameters: {} };
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ verdict: "Allow" }),
    );
    await api.simulateEvaluate(action);
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify(action));
  });

  it("getGraphSvg() returns SVG text", async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>';
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(svg, {
        status: 200,
        headers: { "content-type": "image/svg+xml" },
      }),
    );
    const result = await api.getGraphSvg("session-1");
    expect(result).toBe(svg);
    expect(spy.mock.calls[0][0]).toContain("/session-1/svg");
  });

  it("handles non-JSON error body gracefully", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Bad Gateway", {
        status: 502,
        statusText: "Bad Gateway",
      }),
    );
    await expect(api.health()).rejects.toThrow("Bad Gateway");
  });
});
