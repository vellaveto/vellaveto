/** Shared API types matching the Vellaveto server's Rust serde output. */

export type Verdict = "Allow" | { Deny: { reason: string } } | { RequireApproval: { reason: string } };

export interface Action {
  tool: string;
  function: string;
  parameters: Record<string, unknown>;
  target_paths?: string[];
  target_domains?: string[];
  resolved_ips?: string[];
}

export interface AuditEntry {
  id: string;
  action: Action;
  verdict: Verdict;
  timestamp: string;
  metadata: Record<string, string>;
  entry_hash: string;
  prev_hash: string;
}

export interface AuditSearchParams {
  start?: string;
  end?: string;
  tool?: string;
  verdict?: "allow" | "deny" | "require_approval";
  agent_id?: string;
  limit?: number;
  offset?: number;
}

export interface Policy {
  id: string;
  name: string;
  policy_type: string;
  priority: number;
  path_rules?: unknown;
  network_rules?: unknown;
}

export interface PolicyVersion {
  version: number;
  status: string;
  created_at: string;
  approved_by?: string;
  content: string;
}

export interface ApprovalRequest {
  id: string;
  action: Action;
  reason: string;
  requested_by?: string;
  created_at: string;
  status: "pending" | "approved" | "denied";
}

export interface ComplianceStatus {
  frameworks: Record<string, FrameworkStatus>;
}

export interface FrameworkStatus {
  name: string;
  score: number;
  passing: number;
  failing: number;
  total: number;
}

export interface HealthResponse {
  status: string;
  version: string;
  uptime_secs: number;
}

export interface AgentInfo {
  id: string;
  name: string;
  status: string;
  created_at: string;
  last_seen?: string;
  credential_type?: string;
}

export interface TenantInfo {
  id: string;
  name: string;
  created_at: string;
  policies_count: number;
}

export interface UsageMetrics {
  evaluations: number;
  allowed: number;
  denied: number;
  policies: number;
  approvals: number;
  audit_entries: number;
}

export interface QuotaStatus {
  used: number;
  limit: number;
  remaining: number;
  tier: string;
}

export interface LicenseInfo {
  tier: string;
  limits: Record<string, number>;
}

export interface CircuitBreakerStatus {
  tool: string;
  state: "closed" | "open" | "half_open";
  failure_count: number;
  last_failure?: string;
}

export interface ExecutionGraph {
  session_id: string;
  nodes: GraphNode[];
  metadata: GraphMetadata;
}

export interface GraphNode {
  id: string;
  tool: string;
  function_name: string;
  verdict: string;
  parent_id?: string;
  timestamp: string;
}

export interface GraphMetadata {
  total_nodes: number;
  start_time?: string;
  end_time?: string;
}

export interface DeploymentInfo {
  version: string;
  cluster_id?: string;
  node_count: number;
  leader?: string;
}

export type Role = "admin" | "operator" | "auditor" | "viewer";

export interface UserSession {
  id: string;
  subject?: string;
  role: Role;
  scopes: string[];
  expires_in_secs: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface ErrorResponse {
  error: string;
  details?: string;
}
