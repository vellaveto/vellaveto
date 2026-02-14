/**
 * Sentinel SDK for TypeScript.
 *
 * @example
 * ```typescript
 * import { SentinelClient, Verdict } from "@sentinel-sdk/typescript";
 *
 * const client = new SentinelClient({
 *   baseUrl: "http://localhost:3000",
 *   apiKey: "your-api-key",
 * });
 *
 * const result = await client.evaluate({
 *   tool: "filesystem",
 *   function: "read_file",
 *   parameters: { path: "/tmp/data.txt" },
 * });
 *
 * if (result.verdict === Verdict.Allow) {
 *   // proceed with tool call
 * }
 * ```
 */

export { SentinelClient, SentinelClientOptions, SentinelError, PolicyDenied, ApprovalRequired } from "./client";
export {
  Action,
  Approval,
  BatchResponse,
  BatchResult,
  BatchSummary,
  DiffResponse,
  EvaluationContext,
  EvaluationResult,
  HealthResponse,
  PolicyDiff,
  PolicySummary,
  SimulateOptions,
  SimulateResponse,
  ValidateResponse,
  ValidationFinding,
  ValidationSummary,
  Verdict,
} from "./types";
