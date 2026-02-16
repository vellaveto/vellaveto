/**
 * Vellaveto HTTP client for TypeScript.
 *
 * Uses native fetch() (Node 18+). Zero runtime dependencies.
 */

import {
  Action,
  Approval,
  BatchResponse,
  CanonicalToolSchema,
  DiffResponse,
  DiscoveryIndexStats,
  DiscoveryReindexResponse,
  DiscoveryResult,
  DiscoverySearchRequest,
  DiscoveryToolsResponse,
  EvaluationContext,
  EvaluationResult,
  HealthResponse,
  PolicySummary,
  ProjectorModelsResponse,
  ProjectorTransformResponse,
  SimulateOptions,
  SimulateResponse,
  ValidateResponse,
  Verdict,
  ZkCommitmentsResponse,
  ZkProofsResponse,
  ZkSchedulerStatus,
  ZkVerifyResult,
} from "./types";

// SECURITY (FIND-R46-TS-001): Maximum response body size to prevent OOM DoS.
const MAX_RESPONSE_BODY_BYTES = 10 * 1024 * 1024; // 10 MB

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
    // SECURITY (FIND-R46-TS-003): Validate baseUrl before use.
    if (!options.baseUrl || options.baseUrl.trim().length === 0) {
      throw new VellavetoError("baseUrl must not be empty");
    }

    const trimmedUrl = options.baseUrl.trim().replace(/\/+$/, "");

    // Must start with http:// or https://
    if (
      !trimmedUrl.startsWith("http://") &&
      !trimmedUrl.startsWith("https://")
    ) {
      throw new VellavetoError(
        "baseUrl must use http:// or https:// scheme"
      );
    }

    // Reject credentials in URL (userinfo@host)
    try {
      const parsed = new URL(trimmedUrl);
      if (parsed.username || parsed.password) {
        throw new VellavetoError(
          "baseUrl must not contain credentials (userinfo)"
        );
      }
    } catch (e) {
      if (e instanceof VellavetoError) throw e;
      throw new VellavetoError(
        `baseUrl is not a valid URL: ${trimmedUrl}`
      );
    }

    // SECURITY (FIND-R46-TS-005): TLS is enforced by the runtime (Node.js/browser).
    // This SDK does not provide TLS configuration options; the underlying fetch()
    // implementation handles certificate validation. Warn on non-localhost HTTP.
    if (trimmedUrl.startsWith("http://")) {
      const host = new URL(trimmedUrl).hostname;
      if (host !== "localhost" && host !== "127.0.0.1" && host !== "::1") {
        // eslint-disable-next-line no-console
        console.warn(
          `[vellaveto] WARNING: baseUrl uses unencrypted HTTP for non-localhost host "${host}". ` +
            "API keys and policy data will be transmitted in cleartext. " +
            "Use https:// in production."
        );
      }
    }

    this.baseUrl = trimmedUrl;
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

  /**
   * SECURITY (FIND-R46-TS-004): Strip API key from error messages.
   * Network errors or fetch rejections may include the Authorization header
   * value, which would expose the API key in logs or user-facing errors.
   */
  private sanitizeErrorMessage(msg: string): string {
    if (this.apiKey && msg.includes(this.apiKey)) {
      return msg.split(this.apiKey).join("[REDACTED]");
    }
    return msg;
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

      // SECURITY (FIND-R46-TS-001): Check Content-Length header before reading body.
      const contentLength = response.headers.get("content-length");
      if (contentLength !== null) {
        const size = parseInt(contentLength, 10);
        if (!isNaN(size) && size > MAX_RESPONSE_BODY_BYTES) {
          throw new VellavetoError(
            `Response body exceeds ${MAX_RESPONSE_BODY_BYTES} byte limit (Content-Length: ${size})`,
            response.status
          );
        }
      }

      if (!response.ok) {
        let errorMsg: string;
        try {
          // SECURITY (FIND-R46-TS-001): Read body as text with size check.
          const errorText = await this.readBodyBounded(response);
          const errorBody = JSON.parse(errorText) as { error?: string };
          errorMsg = errorBody.error ?? response.statusText;
        } catch (e) {
          if (e instanceof VellavetoError) throw e;
          errorMsg = response.statusText;
        }
        // SECURITY (FIND-R46-TS-004): Sanitize server error messages.
        throw new VellavetoError(
          this.sanitizeErrorMessage(errorMsg),
          response.status
        );
      }

      // SECURITY (FIND-R46-TS-001): Read body with size limit.
      const text = await this.readBodyBounded(response);
      return JSON.parse(text) as T;
    } catch (error) {
      if (error instanceof VellavetoError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new VellavetoError(`Request timed out after ${this.timeout}ms`);
      }
      // SECURITY (FIND-R46-TS-004): Sanitize error messages to prevent API key leakage.
      // Network errors may include request details that contain the Authorization header.
      const rawMsg =
        error instanceof Error ? error.message : String(error);
      throw new VellavetoError(
        `Network error: ${this.sanitizeErrorMessage(rawMsg)}`
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * SECURITY (FIND-R46-TS-001): Read response body with bounded size.
   * Prevents OOM from malicious servers sending unbounded responses.
   */
  private async readBodyBounded(response: Response): Promise<string> {
    // If the response has a body reader, use streaming with size enforcement.
    // Otherwise fall back to text() (e.g., in test mocks).
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let totalBytes = 0;

      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          totalBytes += value.byteLength;
          if (totalBytes > MAX_RESPONSE_BODY_BYTES) {
            reader.cancel();
            throw new VellavetoError(
              `Response body exceeds ${MAX_RESPONSE_BODY_BYTES} byte limit`
            );
          }
          chunks.push(value);
        }
      } finally {
        reader.releaseLock();
      }

      const decoder = new TextDecoder();
      return chunks.map((c) => decoder.decode(c, { stream: true })).join("") +
        decoder.decode();
    }

    // Fallback for environments without ReadableStream (e.g., test mocks)
    const text = await response.text();
    if (text.length > MAX_RESPONSE_BODY_BYTES) {
      throw new VellavetoError(
        `Response body exceeds ${MAX_RESPONSE_BODY_BYTES} byte limit`
      );
    }
    return text;
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
    const resp = await this.request<unknown>("POST", path, body);

    // SECURITY (FIND-R46-TS-002): Runtime type validation on server responses.
    // Fail-closed: if the response is not a valid object or contains an unknown
    // verdict, default to Deny.
    if (typeof resp !== "object" || resp === null || Array.isArray(resp)) {
      return { verdict: Verdict.Deny, reason: "malformed server response" };
    }

    const respObj = resp as Record<string, unknown>;
    const verdict = parseVerdict(respObj.verdict);

    // Extract reason from both top-level field and verdict object.
    // Top-level "reason" takes precedence; fall back to reason inside verdict object
    // (e.g., {"Deny": {"reason": "blocked"}}).
    const topReason =
      typeof respObj.reason === "string" ? respObj.reason : undefined;
    const objReason = extractVerdictReason(respObj.verdict);
    const reason = topReason ?? objReason;

    const policyId =
      typeof respObj.policy_id === "string" ? respObj.policy_id : undefined;
    const policyName =
      typeof respObj.policy_name === "string" ? respObj.policy_name : undefined;
    const approvalId =
      typeof respObj.approval_id === "string" ? respObj.approval_id : undefined;
    const respTrace =
      typeof respObj.trace === "object" && respObj.trace !== null && !Array.isArray(respObj.trace)
        ? (respObj.trace as Record<string, unknown>)
        : undefined;

    return {
      verdict,
      reason,
      policy_id: policyId,
      policy_name: policyName,
      approval_id: approvalId,
      trace: respTrace,
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

  // ────────────────────────────────────────────────────
  // Discovery (Phase 34.4)
  // ────────────────────────────────────────────────────

  /** Search the tool discovery index for matching tools. */
  async discover(
    query: string,
    maxResults?: number,
    tokenBudget?: number
  ): Promise<DiscoveryResult> {
    const body: DiscoverySearchRequest = {
      query,
      max_results: maxResults,
      token_budget: tokenBudget,
    };
    return this.request<DiscoveryResult>("POST", "/api/discovery/search", body);
  }

  /** Get statistics about the tool discovery index. */
  async discoveryStats(): Promise<DiscoveryIndexStats> {
    return this.request<DiscoveryIndexStats>(
      "GET",
      "/api/discovery/index/stats"
    );
  }

  /** Trigger a full rebuild of the IDF weights in the discovery index. */
  async discoveryReindex(): Promise<DiscoveryReindexResponse> {
    return this.request<DiscoveryReindexResponse>(
      "POST",
      "/api/discovery/reindex"
    );
  }

  /** List all indexed tools, optionally filtered by server_id and sensitivity. */
  async discoveryTools(
    serverId?: string,
    sensitivity?: string
  ): Promise<DiscoveryToolsResponse> {
    const params = new URLSearchParams();
    if (serverId) params.set("server_id", serverId);
    if (sensitivity) params.set("sensitivity", sensitivity);
    const qs = params.toString();
    const path = qs ? `/api/discovery/tools?${qs}` : "/api/discovery/tools";
    return this.request<DiscoveryToolsResponse>("GET", path);
  }

  // ────────────────────────────────────────────────────
  // Projector (Phase 35.3)
  // ────────────────────────────────────────────────────

  /** List supported model families in the projector registry. */
  async projectorModels(): Promise<ProjectorModelsResponse> {
    return this.request<ProjectorModelsResponse>(
      "GET",
      "/api/projector/models"
    );
  }

  /** Project a canonical tool schema for a given model family. */
  async projectSchema(
    schema: CanonicalToolSchema,
    modelFamily: string
  ): Promise<ProjectorTransformResponse> {
    const body = {
      schema,
      model_family: modelFamily,
    };
    return this.request<ProjectorTransformResponse>(
      "POST",
      "/api/projector/transform",
      body
    );
  }

  // ────────────────────────────────────────────────────
  // ZK Audit (Phase 37)
  // ────────────────────────────────────────────────────

  /** Get the ZK audit scheduler status. */
  async zkStatus(): Promise<ZkSchedulerStatus> {
    return this.request<ZkSchedulerStatus>("GET", "/api/zk-audit/status");
  }

  /** List stored ZK batch proofs with optional pagination. */
  async zkProofs(limit?: number, offset?: number): Promise<ZkProofsResponse> {
    const params = new URLSearchParams();
    if (limit !== undefined) params.set("limit", String(limit));
    if (offset !== undefined) params.set("offset", String(offset));
    const qs = params.toString();
    const path = qs ? `/api/zk-audit/proofs?${qs}` : "/api/zk-audit/proofs";
    return this.request<ZkProofsResponse>("GET", path);
  }

  /** Verify a stored ZK batch proof by batch ID. */
  async zkVerify(batchId: string): Promise<ZkVerifyResult> {
    return this.request<ZkVerifyResult>("POST", "/api/zk-audit/verify", {
      batch_id: batchId,
    });
  }

  /** List Pedersen commitments for audit entries in a sequence range. */
  async zkCommitments(
    fromSeq: number,
    toSeq: number
  ): Promise<ZkCommitmentsResponse> {
    const params = new URLSearchParams();
    params.set("from", String(fromSeq));
    params.set("to", String(toSeq));
    return this.request<ZkCommitmentsResponse>(
      "GET",
      `/api/zk-audit/commitments?${params.toString()}`
    );
  }
}

/**
 * Extract the reason string from an object-style verdict.
 * E.g., {"Deny": {"reason": "blocked"}} -> "blocked"
 */
function extractVerdictReason(v: unknown): string | undefined {
  if (typeof v === "object" && v !== null && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    for (const key of ["Deny", "RequireApproval"]) {
      if (key in obj && typeof obj[key] === "object" && obj[key] !== null) {
        const inner = obj[key] as Record<string, unknown>;
        if (typeof inner.reason === "string") {
          return inner.reason;
        }
      }
    }
  }
  return undefined;
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
