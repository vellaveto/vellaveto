export type DeploymentTarget = "docker" | "binary" | "kubernetes" | "source";

export type PolicyPreset = "strict" | "balanced" | "permissive";

export type RedactionLevel = "off" | "low" | "high";

export type AuditExportFormat = "none" | "jsonl" | "cef" | "webhook" | "syslog";

export type SdkLanguage = "python" | "typescript" | "go" | "java" | "skip";

export type ComplianceFramework =
  | "eu_ai_act"
  | "nis2"
  | "dora"
  | "soc2"
  | "iso42001";

export interface WizardState {
  // Step 1: Welcome
  deploymentTarget: DeploymentTarget;

  // Step 2: Security
  apiKey: string;
  corsOrigins: string[];
  anonymousMode: boolean;

  // Step 3: Policies
  policyPreset: PolicyPreset;

  // Step 4: Detection
  injectionEnabled: boolean;
  injectionBlocking: boolean;
  dlpEnabled: boolean;
  dlpBlocking: boolean;
  behavioralEnabled: boolean;

  // Step 5: Audit
  redactionLevel: RedactionLevel;
  auditExportFormat: AuditExportFormat;
  auditExportTarget: string;
  checkpointInterval: number;

  // Step 6: Compliance
  complianceFrameworks: ComplianceFramework[];

  // Step 7: SDK
  sdkLanguage: SdkLanguage;
}

export interface GeneratedFile {
  path: string;
  content: string;
  description: string;
}
