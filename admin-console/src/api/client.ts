// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

/**
 * Vellaveto API client — typed wrapper around fetch for all server endpoints.
 *
 * All methods throw on non-2xx responses with the server's error body.
 * The base URL and API key are configured once via `configure()`.
 */

import type {
  AgentInfo,
  ApprovalRequest,
  AuditEntry,
  AuditSearchParams,
  CircuitBreakerStatus,
  ComplianceStatus,
  DeploymentInfo,
  ErrorResponse,
  HealthResponse,
  LicenseInfo,
  Policy,
  PolicyVersion,
  QuotaStatus,
  UsageMetrics,
  UserSession,
  TenantInfo,
} from "../types/api";

let baseUrl = "";
let apiKey = "";

export function configure(url: string, key: string): void {
  baseUrl = url.replace(/\/+$/, "");
  apiKey = key;
}

export function getBaseUrl(): string {
  return baseUrl;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    ...(init?.headers as Record<string, string> | undefined),
  };

  const res = await fetch(`${baseUrl}${path}`, { ...init, headers });

  if (!res.ok) {
    let body: ErrorResponse;
    try {
      body = await res.json();
    } catch {
      body = { error: res.statusText };
    }
    throw new ApiError(res.status, body.error, body.details);
  }

  if (res.status === 204) return undefined as T;

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return res.json();
  }
  return (await res.text()) as T;
}

export class ApiError extends Error {
  status: number;
  details?: string;

  constructor(status: number, message: string, details?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

// ── Health ──────────────────────────────────────────────────────────────

export const health = (): Promise<HealthResponse> => request("/health");

// ── Session / IAM ──────────────────────────────────────────────────────

export const getSession = (): Promise<UserSession> => request("/iam/session");

export const logout = (): Promise<void> =>
  request("/iam/logout", { method: "POST" });

// ── Policies ───────────────────────────────────────────────────────────

export const listPolicies = (): Promise<Policy[]> =>
  request("/api/policies");

export const createPolicy = (policy: Partial<Policy>): Promise<Policy> =>
  request("/api/policies", {
    method: "POST",
    body: JSON.stringify(policy),
  });

export const deletePolicy = (id: string): Promise<void> =>
  request(`/api/policies/${encodeURIComponent(id)}`, { method: "DELETE" });

export const reloadPolicies = (): Promise<void> =>
  request("/api/policies/reload", { method: "POST" });

// ── Policy Lifecycle ───────────────────────────────────────────────────

export const listPolicyVersions = (id: string): Promise<PolicyVersion[]> =>
  request(`/api/policies/${encodeURIComponent(id)}/versions`);

export const promotePolicyVersion = (id: string, version: number): Promise<void> =>
  request(
    `/api/policies/${encodeURIComponent(id)}/versions/${version}/promote`,
    { method: "POST" },
  );

export const approvePolicyVersion = (id: string, version: number): Promise<void> =>
  request(
    `/api/policies/${encodeURIComponent(id)}/versions/${version}/approve`,
    { method: "POST" },
  );

// ── Audit ──────────────────────────────────────────────────────────────

export const searchAudit = (params: AuditSearchParams): Promise<AuditEntry[]> => {
  const qs = new URLSearchParams();
  if (params.start) qs.set("start", params.start);
  if (params.end) qs.set("end", params.end);
  if (params.tool) qs.set("tool", params.tool);
  if (params.verdict) qs.set("verdict", params.verdict);
  if (params.agent_id) qs.set("agent_id", params.agent_id);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  return request(`/api/audit/search?${qs.toString()}`);
};

export const exportAudit = (format: "cef" | "jsonl" | "csv"): Promise<string> =>
  request(`/api/audit/export?format=${format}`);

export const verifyAudit = (): Promise<{ valid: boolean; errors: string[] }> =>
  request("/api/audit/verify");

// ── Approvals ──────────────────────────────────────────────────────────

export const listPendingApprovals = (): Promise<ApprovalRequest[]> =>
  request("/api/approvals/pending");

export const approveRequest = (id: string): Promise<void> =>
  request(`/api/approvals/${encodeURIComponent(id)}/approve`, {
    method: "POST",
  });

export const denyRequest = (id: string): Promise<void> =>
  request(`/api/approvals/${encodeURIComponent(id)}/deny`, {
    method: "POST",
  });

// ── Compliance ─────────────────────────────────────────────────────────

export const getComplianceStatus = (): Promise<ComplianceStatus> =>
  request("/api/compliance/status");

export const getGapAnalysis = (): Promise<unknown> =>
  request("/api/compliance/gap-analysis");

// ── Agents / NHI ───────────────────────────────────────────────────────

export const listAgents = (): Promise<AgentInfo[]> =>
  request("/api/nhi/agents");

export const getAgent = (id: string): Promise<AgentInfo> =>
  request(`/api/nhi/agents/${encodeURIComponent(id)}`);

export const suspendAgent = (id: string): Promise<void> =>
  request(`/api/nhi/agents/${encodeURIComponent(id)}/suspend`, {
    method: "POST",
  });

// ── Tenants ────────────────────────────────────────────────────────────

export const listTenants = (): Promise<TenantInfo[]> =>
  request("/api/tenants");

// ── Usage / Billing ────────────────────────────────────────────────────

export const getLicense = (): Promise<LicenseInfo> =>
  request("/api/billing/license");

export const getUsage = (tenantId: string): Promise<UsageMetrics> =>
  request(`/api/billing/usage/${encodeURIComponent(tenantId)}`);

export const getQuotas = (tenantId: string): Promise<QuotaStatus> =>
  request(`/api/billing/quotas/${encodeURIComponent(tenantId)}`);

// ── Circuit Breaker ────────────────────────────────────────────────────

export const listCircuitBreakers = (): Promise<CircuitBreakerStatus[]> =>
  request("/api/circuit-breaker");

export const resetCircuitBreaker = (tool: string): Promise<void> =>
  request(`/api/circuit-breaker/${encodeURIComponent(tool)}/reset`, {
    method: "POST",
  });

// ── Graphs ─────────────────────────────────────────────────────────────

export const listGraphSessions = (): Promise<string[]> =>
  request("/api/graphs");

export const getGraphSvg = (session: string): Promise<string> =>
  request(`/api/graphs/${encodeURIComponent(session)}/svg`);

// ── Deployment ─────────────────────────────────────────────────────────

export const getDeploymentInfo = (): Promise<DeploymentInfo> =>
  request("/api/deployment/info");

// ── Shadow Agents / Governance ─────────────────────────────────────────

export const getShadowReport = (): Promise<unknown> =>
  request("/api/governance/shadow-report");

export const getUnapprovedTools = (): Promise<unknown> =>
  request("/api/governance/unapproved-tools");

// ── Simulator ──────────────────────────────────────────────────────────

export const simulateEvaluate = (action: unknown): Promise<unknown> =>
  request("/api/simulator/evaluate", {
    method: "POST",
    body: JSON.stringify(action),
  });

export const validatePolicy = (content: string): Promise<unknown> =>
  request("/api/simulator/validate", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
