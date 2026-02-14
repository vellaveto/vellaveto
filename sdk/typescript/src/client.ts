/**
 * Vellaveto HTTP client for TypeScript.
 *
 * Uses native fetch() (Node 18+). Zero runtime dependencies.
 */

import {
  Action,
  Approval,
  BatchResponse,
  DiffResponse,
  EvaluationContext,
  EvaluationResult,
  HealthResponse,
  PolicySummary,
  SimulateOptions,
  SimulateResponse,
  ValidateResponse,
  Verdict,
} from "./types";

/** Configuration for the Vellaveto client. */
export interface VellavetoClientOptions {
  /** Base URL of the Vellaveto server (e.g., "http://localhost:3000"). */
  baseUrl: string;
  /** API key for authentication. */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 5000). */
  timeout?: number;
  /** Additional headers to include in every request. */
  headers?: Record<string, string>;
}

/** Error thrown by the Vellaveto client. */
export class VellavetoError extends Error {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = "VellavetoError";
    this.statusCode = statusCode;
  }
}

/** Error thrown when a policy denies an action. */
export class PolicyDenied extends VellavetoError {
  public readonly reason: string;

  constructor(reason: string) {
    super(`Policy denied: ${reason}`);
    this.name = "PolicyDenied";
    this.reason = reason;
  }
}

/** Error thrown when an action requires approval. */
export class ApprovalRequired extends VellavetoError {
  public readonly reason: string;
  public readonly approvalId: string;

  constructor(reason: string, approvalId: string) {
    super(`Approval required: ${reason} (approval_id: ${approvalId})`);
    this.name = "ApprovalRequired";
    this.reason = reason;
    this.approvalId = approvalId;
  }
}

/**
 * Vellaveto API client.
 *
 * @example
 * ```typescript
 * const client = new VellavetoClient({ baseUrl: "http://localhost:3000", apiKey: "my-key" });
 *
 * const result = await client.evaluate({
 *   tool: "filesystem",
 *   function: "read_file",
 *   parameters: { path: "/etc/passwd" },
 * });
 *
 * if (result.verdict === Verdict.Allow) {
 *   // proceed
 * }
 * ```
 */
export class VellavetoClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeout: number;
  private readonly extraHeaders: Record<string, string>;

  constructor(options: VellavetoClientOptions) {
    // Strip trailing slash
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeout = options.timeout ?? 5000;
    this.extraHeaders = options.headers ?? {};
  }

  // ────────────────────────────────────────────────────
  // Internal helpers
  // ────────────────────────────────────────────────────

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.extraHeaders,
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers: this.buildHeaders(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        let errorMsg: string;
        try {
          const errorBody = (await response.json()) as { error?: string };
          errorMsg = errorBody.error ?? response.statusText;
        } catch {
          errorMsg = response.statusText;
        }
        throw new VellavetoError(errorMsg, response.status);
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof VellavetoError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new VellavetoError(`Request timed out after ${this.timeout}ms`);
      }
      throw new VellavetoError(
        `Network error: ${error instanceof Error ? error.message : String(error)}`
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ────────────────────────────────────────────────────
  // Core API
  // ────────────────────────────────────────────────────

  /** Check server health. */
  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/health");
  }

  /** Evaluate a single action against loaded policies. */
  async evaluate(
    action: Action,
    context?: EvaluationContext,
    trace?: boolean
  ): Promise<EvaluationResult> {
    const path = trace ? "/api/evaluate?trace=true" : "/api/evaluate";
    const body: Record<string, unknown> = {
      tool: action.tool,
      function: action.function ?? "",
      parameters: action.parameters ?? {},
    };
    if (context) {
      body.context = context;
    }
    const resp = await this.request<{
      verdict: string;
      action: unknown;
      approval_id?: string;
      trace?: Record<string, unknown>;
    }>(
      "POST",
      path,
      body
    );

    return {
      verdict: parseVerdict(resp.verdict),
      approval_id: resp.approval_id,
      trace: resp.trace,
    };
  }

  // ────────────────────────────────────────────────────
  // Policy management
  // ────────────────────────────────────────────────────

  /** List loaded policies. */
  async listPolicies(): Promise<PolicySummary[]> {
    return this.request<PolicySummary[]>("GET", "/api/policies");
  }

  /** Trigger a policy reload from the config file. */
  async reloadPolicies(): Promise<{ count: number }> {
    return this.request<{ count: number }>("POST", "/api/policies/reload");
  }

  // ────────────────────────────────────────────────────
  // Simulator (Phase 22)
  // ────────────────────────────────────────────────────

  /** Simulate a single action evaluation with full trace. */
  async simulate(
    action: Action,
    options?: SimulateOptions
  ): Promise<SimulateResponse> {
    return this.request<SimulateResponse>("POST", "/api/simulator/evaluate", {
      action,
      context: options?.context,
      policy_config: options?.policy_config,
    });
  }

  /** Batch-evaluate multiple actions. */
  async batchEvaluate(
    actions: Action[],
    policyConfig?: string
  ): Promise<BatchResponse> {
    return this.request<BatchResponse>("POST", "/api/simulator/batch", {
      actions,
      policy_config: policyConfig,
    });
  }

  /** Validate a policy configuration string. */
  async validateConfig(
    config: string,
    strict?: boolean
  ): Promise<ValidateResponse> {
    return this.request<ValidateResponse>("POST", "/api/simulator/validate", {
      config,
      strict: strict ?? false,
    });
  }

  /** Diff two policy configurations. */
  async diffConfigs(before: string, after: string): Promise<DiffResponse> {
    return this.request<DiffResponse>("POST", "/api/simulator/diff", {
      before,
      after,
    });
  }

  // ────────────────────────────────────────────────────
  // Approvals
  // ────────────────────────────────────────────────────

  /** List pending approvals. */
  async listPendingApprovals(): Promise<Approval[]> {
    return this.request<Approval[]>("GET", "/api/approvals/pending");
  }

  /** Approve a pending approval by ID. */
  async approveApproval(id: string): Promise<void> {
    await this.request<unknown>("POST", `/api/approvals/${encodeURIComponent(id)}/approve`);
  }

  /** Deny a pending approval by ID. */
  async denyApproval(id: string): Promise<void> {
    await this.request<unknown>("POST", `/api/approvals/${encodeURIComponent(id)}/deny`);
  }
}

/** Parse a verdict string into the Verdict enum. */
function parseVerdict(v: unknown): Verdict {
  if (typeof v === "string") {
    const lower = v.toLowerCase();
    if (lower === "allow") return Verdict.Allow;
    if (lower === "deny" || lower.startsWith("deny")) return Verdict.Deny;
    if (lower === "require_approval" || lower.startsWith("require"))
      return Verdict.RequireApproval;
  }
  // For object-style verdicts like { "Deny": { "reason": "..." } }
  if (typeof v === "object" && v !== null) {
    if ("Allow" in v) return Verdict.Allow;
    if ("Deny" in v) return Verdict.Deny;
    if ("RequireApproval" in v) return Verdict.RequireApproval;
  }
  return Verdict.Deny; // Fail-closed
}
