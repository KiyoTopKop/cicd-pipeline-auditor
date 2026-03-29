// ============================================================
// Core Types for CI/CD Pipeline Auditor (PipeLint)
// ============================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SeverityInfo {
  label: Severity;
  score: [number, number]; // [min, max]
  color: string;
  bgColor: string;
  borderColor: string;
}

export const SEVERITY_CONFIG: Record<Severity, SeverityInfo> = {
  CRITICAL: { label: 'CRITICAL', score: [9.0, 10.0], color: '#ff4d6d', bgColor: 'rgba(255,77,109,0.12)', borderColor: 'rgba(255,77,109,0.35)' },
  HIGH:     { label: 'HIGH',     score: [7.0, 8.9],  color: '#ff8c42', bgColor: 'rgba(255,140,66,0.12)', borderColor: 'rgba(255,140,66,0.35)' },
  MEDIUM:   { label: 'MEDIUM',   score: [4.0, 6.9],  color: '#ffd166', bgColor: 'rgba(255,209,102,0.12)', borderColor: 'rgba(255,209,102,0.35)' },
  LOW:      { label: 'LOW',      score: [0.1, 3.9],  color: '#4fc3f7', bgColor: 'rgba(79,195,247,0.12)', borderColor: 'rgba(79,195,247,0.35)' },
};

export type RuleCategory = 'Supply Chain' | 'Permissions' | 'Secrets' | 'Injection' | 'Triggers' | 'Environment';

export interface RuleDefinition {
  id: string;
  category: RuleCategory;
  severity: Severity;
  shortDescription: string;
  fullDescription: string;
  cwe: string;
  remediation: {
    quickFix: string;
    bestPractice: string;
    before: string;
    after: string;
  };
  references: string[];
}

// ---- Workflow Intermediate Representation ----

export interface WorkflowPermissions {
  level: 'write-all' | 'read-all' | 'none' | 'custom' | 'absent';
  scopes: Record<string, 'read' | 'write' | 'none'>;
  raw: unknown;
  line?: number;
}

export interface WorkflowStep {
  id?: string;
  name?: string;
  uses?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
  continueOnError?: boolean;
  line?: number;
  // Parsed expressions from `run` and `with` values
  expressions: string[];
  // Raw `uses` parsed parts
  usesAction?: {
    owner: string;
    repo: string;
    ref: string;
    isSHA: boolean;
    isFork: boolean;
  };
}

export interface WorkflowJob {
  id: string;
  name?: string;
  runsOn: string | string[];
  permissions?: WorkflowPermissions;
  steps: WorkflowStep[];
  uses?: string; // reusable workflow call
  secrets?: string | Record<string, string>; // 'inherit' or explicit
  line?: number;
  container?: {
    image: string;
    options?: string;
  };
  services?: Record<string, { image: string }>;
}

export interface WorkflowTrigger {
  event: string;
  config: unknown;
}

export interface WorkflowIR {
  name?: string;
  rawYaml: string;
  permissions?: WorkflowPermissions;
  triggers: WorkflowTrigger[];
  jobs: WorkflowJob[];
  // All ${{ ... }} expressions found with their locations
  allExpressions: Array<{ expr: string; location: string; line?: number }>;
  // Line-number map for key nodes
  lineMap: Record<string, number>;
  parseError?: string;
}

// ---- Finding ----

export interface Finding {
  id: string; // unique finding ID (ruleId + lineNumber)
  ruleId: string;
  ruleDef: RuleDefinition;
  severity: Severity;
  line?: number;
  column?: number;
  snippet?: string;
  context: string; // human-readable location context
  message: string;
}

// ---- Analysis Result ----

export interface AnalysisResult {
  findings: Finding[];
  counts: Record<Severity, number>;
  riskScore: number;
  analysisTimeMs: number;
  workflowName?: string;
  parseError?: string;
}
