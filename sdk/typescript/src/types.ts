/**
 * Vellaveto SDK type definitions.
 *
 * Mirrors the Python SDK types for API parity.
 */

/** Policy evaluation verdict. */
export enum Verdict {
  Allow = "allow",
  Deny = "deny",
  RequireApproval = "require_approval",
}

/** An action to be evaluated by Vellaveto. */
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

/** Request body for the discovery search endpoint. */
export interface DiscoverySearchRequest {
  /** Natural language description of the desired tool. */
  query: string;
  /** Maximum number of results (default: 5, max: 20). */
  max_results?: number;
  /** Optional token budget for returned schemas. */
  token_budget?: number;
}

/** A discovered tool with its relevance score. */
export interface DiscoveredTool {
  metadata: ToolMetadata;
  relevance_score: number;
  ttl_secs: number;
}

/** Metadata about a tool in the discovery index. */
export interface ToolMetadata {
  tool_id: string;
  name: string;
  description: string;
  server_id: string;
  input_schema: Record<string, unknown>;
  schema_hash: string;
  sensitivity: string;
  domain_tags: string[];
  token_cost: number;
}

/** Result of a discovery search query. */
export interface DiscoveryResult {
  tools: DiscoveredTool[];
  query: string;
  total_candidates: number;
  policy_filtered: number;
}

/** Statistics about the discovery index. */
export interface DiscoveryIndexStats {
  total_tools: number;
  max_capacity: number;
  config_enabled: boolean;
}

/** Response from the discovery tools list endpoint. */
export interface DiscoveryToolsResponse {
  tools: ToolMetadata[];
  total: number;
}

/** Response from the discovery reindex endpoint. */
export interface DiscoveryReindexResponse {
  status: string;
  total_tools: number;
}

/** Canonical tool schema (model-agnostic). */
export interface CanonicalToolSchema {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  output_schema?: Record<string, unknown> | null;
}

/** Response from the projector models list endpoint. */
export interface ProjectorModelsResponse {
  model_families: string[];
}

/** Response from the projector transform endpoint. */
export interface ProjectorTransformResponse {
  projected_schema: Record<string, unknown>;
  token_estimate: number;
  model_family: string;
}
