/**
 * Sentinel SDK type definitions.
 *
 * Mirrors the Python SDK types for API parity.
 */

/** Policy evaluation verdict. */
export enum Verdict {
  Allow = "allow",
  Deny = "deny",
  RequireApproval = "require_approval",
}

/** An action to be evaluated by Sentinel. */
export interface Action {
  tool: string;
  function?: string;
  parameters?: Record<string, unknown>;
  target_paths?: string[];
  target_domains?: string[];
}

/** Result of a policy evaluation. */
export interface EvaluationResult {
  verdict: Verdict;
  reason?: string;
  policy_id?: string;
  approval_id?: string;
  trace?: Record<string, unknown>;
}

/** Context for evaluation (session, agent, etc.). */
export interface EvaluationContext {
  session_id?: string;
  agent_id?: string;
  tenant_id?: string;
  call_chain?: string[];
  metadata?: Record<string, unknown>;
}

/** Summary of a single policy. */
export interface PolicySummary {
  id: string;
  name: string;
  policy_type: string;
  priority: number;
}

/** Options for the simulate endpoint. */
export interface SimulateOptions {
  trace?: boolean;
  policy_config?: string;
  context?: EvaluationContext;
}

/** Response from the simulate endpoint. */
export interface SimulateResponse {
  verdict: Verdict;
  trace: Record<string, unknown>;
  policies_checked: number;
  duration_us: number;
}

/** Per-action result in a batch. */
export interface BatchResult {
  action_index: number;
  verdict: Verdict;
  trace?: Record<string, unknown>;
  error?: string;
}

/** Summary statistics for a batch. */
export interface BatchSummary {
  total: number;
  allowed: number;
  denied: number;
  errors: number;
  duration_us: number;
}

/** Response from the batch endpoint. */
export interface BatchResponse {
  results: BatchResult[];
  summary: BatchSummary;
}

/** A single validation finding. */
export interface ValidationFinding {
  severity: string;
  category: string;
  code: string;
  message: string;
  location?: string;
  suggestion?: string;
}

/** Summary of validation results. */
export interface ValidationSummary {
  total_policies: number;
  errors: number;
  warnings: number;
  infos: number;
  valid: boolean;
}

/** Response from the validate endpoint. */
export interface ValidateResponse {
  valid: boolean;
  findings: ValidationFinding[];
  summary: ValidationSummary;
  policy_count: number;
}

/** A modified policy in a diff. */
export interface PolicyDiff {
  id: string;
  name: string;
  changes: string[];
}

/** Response from the diff endpoint. */
export interface DiffResponse {
  added: PolicySummary[];
  removed: PolicySummary[];
  modified: PolicyDiff[];
  unchanged: number;
}

/** A pending approval. */
export interface Approval {
  id: string;
  action: Action;
  reason: string;
  created_at: string;
  expires_at: string;
}

/** Health check response. */
export interface HealthResponse {
  status: string;
}
