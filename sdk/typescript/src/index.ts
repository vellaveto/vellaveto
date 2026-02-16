/**
 * Vellaveto SDK for TypeScript.
 *
 * @example
 * ```typescript
 * import { VellavetoClient, Verdict } from "@vellaveto-sdk/typescript";
 *
 * const client = new VellavetoClient({
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

export { VellavetoClient, VellavetoClientOptions, VellavetoError, PolicyDenied, ApprovalRequired } from "./client";
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
  ZkBatchProof,
  ZkCommitmentsResponse,
  ZkProofsResponse,
  ZkSchedulerStatus,
  ZkVerifyResult,
} from "./types";
