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

export { VellavetoClient, VellavetoClientOptions, VellavetoError, PolicyDenied, ApprovalRequired, ParameterRedactor } from "./client";
export {
  AccessReviewEntry,
  AccessReviewReport,
  Action,
  Approval,
  BatchResponse,
  BatchResult,
  BatchSummary,
  Cc6Evidence,
  DiffResponse,
  EvaluationContext,
  EvaluationResult,
  FederationAnchorStatus,
  FederationStatusResponse,
  FederationTrustAnchor,
  FederationTrustAnchorsResponse,
  HealthResponse,
  PolicyDiff,
  PolicySummary,
  ReviewerAttestation,
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
