/**
 * Vellaveto HTTP client for TypeScript.
 *
 * Uses native fetch() (Node 18+). Zero runtime dependencies.
 */

import {
  AccessReviewReport,
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
  FederationStatusResponse,
  FederationTrustAnchorsResponse,
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

// SECURITY (FIND-R58-CFG-013): Retry parameters for transient HTTP failures.
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 500;
const RETRYABLE_STATUS_CODES = new Set([429, 502, 503, 504]);

/** Configuration for the Vellaveto client. */
export interface VellavetoClientOptions {
  /** Base URL of the Vellaveto server (e.g., "http://localhost:3000"). */
  baseUrl: string;
  /** API key for authentication. */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 10000, aligned with Python/Go SDKs). */
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

/** Default parameter key patterns considered sensitive (case-insensitive). */
const DEFAULT_SENSITIVE_KEYS: ReadonlySet<string> = new Set([
  "password", "passwd", "pass", "secret", "token",
  "api_key", "apikey", "api_secret", "access_token", "refresh_token",
  "auth_token", "bearer", "authorization", "credential", "credentials",
  "private_key", "private_key_pem", "signing_key", "encryption_key",
  "master_key", "session_token", "session_key", "client_secret",
  "connection_string", "database_url", "db_password", "db_pass",
  "aws_secret_access_key", "aws_session_token", "gcp_credentials",
  "azure_key", "stripe_key", "sendgrid_key", "twilio_token",
  "slack_token", "github_token", "gitlab_token",
  "ssh_key", "ssh_passphrase", "cert_key", "ssl_key", "tls_key",
]);

/** Patterns that match secret-like string values. */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /sk-[a-zA-Z0-9]{20,}/,
  /ghp_[a-zA-Z0-9]{36,}/,
  /gho_[a-zA-Z0-9]{36,}/,
  /github_pat_[a-zA-Z0-9_]{20,}/,
  /xoxb-[0-9]+-[a-zA-Z0-9]+/,
  /xoxp-[0-9]+-[a-zA-Z0-9]+/,
  /glpat-[a-zA-Z0-9_-]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
  /sk_live_[a-zA-Z0-9]{20,}/,
  /sk-ant-[a-zA-Z0-9_-]{20,}/,
  /npm_[a-zA-Z0-9]{20,}/,
  /pypi-[a-zA-Z0-9_-]{20,}/,
];

/** Redaction placeholder string. */
const REDACTED_PLACEHOLDER = "[REDACTED]";

/** Redaction mode. */
export type RedactionMode = "keys_only" | "values" | "all";

/** Options for constructing a ParameterRedactor. */
export interface ParameterRedactorOptions {
  /** Redaction mode: "keys_only" (default), "values", or "all". */
  mode?: RedactionMode;
  /** Override the default sensitive key set entirely. */
  sensitiveKeys?: Set<string>;
  /** Additional keys to add to the default set. */
  extraKeys?: Set<string>;
  /** Replacement string for redacted values (default: "[REDACTED]"). */
  placeholder?: string;
}

/**
 * Client-side parameter redactor for sensitive data.
 *
 * SECURITY (FIND-GAP-013): Strips or masks sensitive parameter values before
 * they are sent to the Vellaveto server for policy evaluation. This prevents
 * secrets from transiting the network even when the server is trusted.
 *
 * Matches the Python SDK ParameterRedactor pattern.
 *
 * @example
 * ```typescript
 * const redactor = new ParameterRedactor();
 * const cleaned = redactor.redact({ path: "/tmp/x", api_key: "sk-1234567890" });
 * // => { path: "/tmp/x", api_key: "[REDACTED]" }
 * ```
 */
export class ParameterRedactor {
  public readonly mode: RedactionMode;
  public readonly placeholder: string;
  private readonly sensitiveKeys: Set<string>;

  constructor(options?: ParameterRedactorOptions) {
    const mode = options?.mode ?? "keys_only";
    if (mode !== "keys_only" && mode !== "values" && mode !== "all") {
      throw new Error(
        `Invalid redaction mode: "${mode}". Must be "keys_only", "values", or "all".`
      );
    }
    this.mode = mode;
    this.placeholder = options?.placeholder ?? REDACTED_PLACEHOLDER;

    if (options?.sensitiveKeys) {
      this.sensitiveKeys = new Set(
        [...options.sensitiveKeys].map((k) => k.toLowerCase())
      );
    } else {
      this.sensitiveKeys = new Set(DEFAULT_SENSITIVE_KEYS);
    }

    if (options?.extraKeys) {
      for (const key of options.extraKeys) {
        this.sensitiveKeys.add(key.toLowerCase());
      }
    }
  }

  /** Check if a parameter key is considered sensitive. */
  isSensitiveKey(key: string): boolean {
    const normalized = key.toLowerCase().replace(/-/g, "_");
    if (this.sensitiveKeys.has(normalized)) return true;
    // Suffix match: "x_api_key" matches "api_key"
    for (const sensitive of this.sensitiveKeys) {
      if (
        normalized.endsWith(`_${sensitive}`) ||
        normalized.endsWith(`.${sensitive}`)
      ) {
        return true;
      }
    }
    return false;
  }

  /** Check if a string value looks like a secret. */
  isSensitiveValue(value: unknown): boolean {
    if (typeof value !== "string" || value.length < 8) return false;
    return SECRET_VALUE_PATTERNS.some((p) => p.test(value));
  }

  /**
   * Redact sensitive values from a parameters object.
   *
   * Returns a new object with sensitive values replaced by the placeholder.
   */
  redact(parameters: Record<string, unknown>): Record<string, unknown> {
    if (!parameters || typeof parameters !== "object") return parameters;
    if (this.mode === "all") {
      const result: Record<string, unknown> = {};
      for (const key of Object.keys(parameters)) {
        result[key] = this.placeholder;
      }
      return result;
    }
    return this.redactObject(parameters, 0);
  }

  private redactObject(
    obj: Record<string, unknown>,
    depth: number
  ): Record<string, unknown> {
    if (depth > 10) {
      const result: Record<string, unknown> = {};
      for (const key of Object.keys(obj)) {
        result[key] = this.placeholder;
      }
      return result;
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (this.isSensitiveKey(key)) {
        result[key] = this.placeholder;
      } else if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
      ) {
        result[key] = this.redactObject(
          value as Record<string, unknown>,
          depth + 1
        );
      } else if (Array.isArray(value)) {
        result[key] = this.redactArray(value, depth + 1);
      } else if (
        this.mode === "values" &&
        typeof value === "string" &&
        this.isSensitiveValue(value)
      ) {
        result[key] = this.placeholder;
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  private redactArray(arr: unknown[], depth: number): unknown[] {
    if (depth > 10) {
      return arr.map(() => this.placeholder);
    }
    return arr.map((item) => {
      if (item !== null && typeof item === "object" && !Array.isArray(item)) {
        return this.redactObject(item as Record<string, unknown>, depth + 1);
      }
      if (Array.isArray(item)) {
        return this.redactArray(item, depth + 1);
      }
      if (
        this.mode === "values" &&
        typeof item === "string" &&
        this.isSensitiveValue(item)
      ) {
        return this.placeholder;
      }
      return item;
    });
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
    // SECURITY (FIND-R56-SDK-003): Aligned default timeout across all SDKs (Python/Go/TS = 10s).
    this.timeout = options.timeout ?? 10000;
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
    let lastError: VellavetoError | undefined;
    let backoffMs = INITIAL_BACKOFF_MS;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
        backoffMs *= 2;
      }

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
          const err = new VellavetoError(
            this.sanitizeErrorMessage(errorMsg),
            response.status
          );
          // SECURITY (FIND-R58-CFG-013): Retry on transient HTTP failures.
          if (
            response.status !== undefined &&
            RETRYABLE_STATUS_CODES.has(response.status) &&
            attempt < MAX_RETRIES
          ) {
            lastError = err;
            continue;
          }
          throw err;
        }

        // SECURITY (FIND-R46-TS-001): Read body with size limit.
        const text = await this.readBodyBounded(response);
        return JSON.parse(text) as T;
      } catch (error) {
        if (error instanceof VellavetoError) {
          // If this is a retryable error we already handled above, it was re-thrown
          // because max retries exceeded — propagate it.
          if (
            error.statusCode !== undefined &&
            RETRYABLE_STATUS_CODES.has(error.statusCode) &&
            attempt < MAX_RETRIES
          ) {
            lastError = error;
            continue;
          }
          throw error;
        }
        if (error instanceof Error && error.name === "AbortError") {
          throw new VellavetoError(
            `Request timed out after ${this.timeout}ms`
          );
        }
        // SECURITY (FIND-R46-TS-004): Sanitize error messages to prevent API key leakage.
        const rawMsg =
          error instanceof Error ? error.message : String(error);
        throw new VellavetoError(
          `Network error: ${this.sanitizeErrorMessage(rawMsg)}`
        );
      } finally {
        clearTimeout(timeoutId);
      }
    }
    // All retries exhausted — throw the last error.
    throw lastError ?? new VellavetoError("Request failed after retries");
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
    // SECURITY (FIND-R54-SDK-007): Validate action before sending.
    if (!action || typeof action !== "object") {
      throw new VellavetoError("action must be a non-null object");
    }
    if (typeof action.tool !== "string" || action.tool.trim().length === 0) {
      throw new VellavetoError("action.tool must be a non-empty string");
    }
    if (action.tool.length > 256) {
      throw new VellavetoError("action.tool exceeds max length (256)");
    }
    if (
      action.function !== undefined &&
      action.function !== null &&
      typeof action.function !== "string"
    ) {
      throw new VellavetoError("action.function must be a string if provided");
    }
    if (
      action.parameters !== undefined &&
      action.parameters !== null &&
      typeof action.parameters !== "object"
    ) {
      throw new VellavetoError("action.parameters must be an object if provided");
    }
    // SECURITY (FIND-R55-SDK-006): Bound target_paths/target_domains count. Parity with Go SDK (100).
    if (action.target_paths && action.target_paths.length > 100) {
      throw new VellavetoError(
        `action.target_paths has ${action.target_paths.length} entries, max 100`
      );
    }
    if (action.target_domains && action.target_domains.length > 100) {
      throw new VellavetoError(
        `action.target_domains has ${action.target_domains.length} entries, max 100`
      );
    }
    const path = trace ? "/api/evaluate?trace=true" : "/api/evaluate";
    const body: Record<string, unknown> = {
      tool: action.tool,
      function: action.function ?? "",
      parameters: action.parameters ?? {},
      // SECURITY (FIND-R50-003): Include target_paths and target_domains in the
      // request body, matching the Python and Go SDK behavior.
      target_paths: action.target_paths ?? [],
      target_domains: action.target_domains ?? [],
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

  /**
   * Evaluate an action and throw a typed error if the verdict is not Allow.
   *
   * SECURITY (FIND-GAP-012): Matches the Python SDK evaluate_or_raise() pattern.
   * Throws PolicyDeniedError for Deny verdicts and ApprovalRequiredError for
   * RequireApproval verdicts. Returns the EvaluationResult on Allow.
   *
   * @throws {PolicyDeniedError} if verdict is Deny
   * @throws {ApprovalRequiredError} if verdict is RequireApproval
   */
  async evaluateOrRaise(
    action: Action,
    context?: EvaluationContext,
  ): Promise<EvaluationResult> {
    const result = await this.evaluate(action, context, false);
    switch (result.verdict) {
      case Verdict.Allow:
        return result;
      case Verdict.Deny:
        throw new PolicyDenied(result.reason ?? "policy denied");
      case Verdict.RequireApproval:
        throw new ApprovalRequired(
          result.reason ?? "approval required",
          result.approval_id ?? "",
        );
      default:
        // Fail-closed: unknown verdict treated as deny
        throw new PolicyDenied(result.reason ?? "unknown verdict");
    }
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
    // SECURITY (FIND-R54-SDK-003): Validate approval ID format.
    validateApprovalId(id);
    await this.request<unknown>("POST", `/api/approvals/${encodeURIComponent(id)}/approve`);
  }

  /** Deny a pending approval by ID. */
  async denyApproval(id: string): Promise<void> {
    // SECURITY (FIND-R54-SDK-003): Validate approval ID format.
    validateApprovalId(id);
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
    // SECURITY (FIND-R54-SDK-017): Reject empty query strings.
    if (typeof query !== "string" || query.trim().length === 0) {
      throw new VellavetoError("query must be a non-empty string");
    }
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
    // SECURITY (FIND-R55-SDK-007): Validate model_family non-empty.
    if (typeof modelFamily !== "string" || modelFamily.trim().length === 0) {
      throw new VellavetoError("modelFamily must be a non-empty string");
    }
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
    // SECURITY (FIND-R54-SDK-017): Reject empty batch IDs.
    if (typeof batchId !== "string" || batchId.trim().length === 0) {
      throw new VellavetoError("batchId must be a non-empty string");
    }
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

  /** Generate a SOC 2 Type II access review report. */
  async soc2AccessReview(
    period?: string,
    format?: string,
    agentId?: string
  ): Promise<AccessReviewReport> {
    // SECURITY (P4-025): Client-side format validation to fail fast on invalid values.
    if (format !== undefined && format !== "json" && format !== "html") {
      throw new VellavetoError(
        `Invalid format "${format}": must be "json" or "html"`
      );
    }
    const params = new URLSearchParams();
    if (period) params.set("period", period);
    if (format) params.set("format", format);
    if (agentId) {
      if (agentId.length > 128) {
        throw new VellavetoError("agent_id exceeds max length (128)");
      }
      // SECURITY (FIND-R55-SDK-004): Reject control chars. Parity with federationTrustAnchors.
      if (/[\x00-\x1f\x7f-\x9f]/.test(agentId)) {
        throw new VellavetoError("agent_id contains control characters");
      }
      params.set("agent_id", agentId);
    }
    const qs = params.toString();
    const path = qs
      ? `/api/compliance/soc2/access-review?${qs}`
      : "/api/compliance/soc2/access-review";
    return this.request<AccessReviewReport>("GET", path);
  }

  // ────────────────────────────────────────────────────
  // Federation (Phase 39)
  // ────────────────────────────────────────────────────

  /** Get federation status including per-anchor cache info. */
  async federationStatus(): Promise<FederationStatusResponse> {
    return this.request<FederationStatusResponse>(
      "GET",
      "/api/federation/status"
    );
  }

  /** List federation trust anchors, optionally filtered by org ID. */
  async federationTrustAnchors(
    orgId?: string
  ): Promise<FederationTrustAnchorsResponse> {
    if (orgId !== undefined) {
      if (orgId.length > 128) {
        throw new VellavetoError("org_id exceeds max length (128)");
      }
      // SECURITY (FIND-R50-037): Catch DEL (0x7F) and C1 control chars (0x80-0x9F)
      if (/[\x00-\x1f\x7f-\x9f]/.test(orgId)) {
        throw new VellavetoError("org_id contains control characters");
      }
    }
    const params = new URLSearchParams();
    if (orgId) params.set("org_id", orgId);
    const qs = params.toString();
    const path = qs
      ? `/api/federation/trust-anchors?${qs}`
      : "/api/federation/trust-anchors";
    return this.request<FederationTrustAnchorsResponse>("GET", path);
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

/**
 * SECURITY (FIND-R54-SDK-003): Validate approval ID format.
 * Rejects empty, oversized, and control-character-containing IDs.
 */
function validateApprovalId(id: string): void {
  if (typeof id !== "string" || id.trim().length === 0) {
    throw new VellavetoError("approval ID must be a non-empty string");
  }
  if (id.length > 256) {
    throw new VellavetoError("approval ID exceeds max length (256)");
  }
  if (/[\x00-\x1f\x7f-\x9f]/.test(id)) {
    throw new VellavetoError("approval ID contains control characters");
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
