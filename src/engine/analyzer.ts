import { parseWorkflow } from './parser';
import { ALL_CHECKERS } from './rules/matchers';
import type { AnalysisResult, Finding, Severity } from './types';

export function analyze(yamlContent: string): AnalysisResult {
  const start = performance.now();

  if (!yamlContent.trim()) {
    return {
      findings: [],
      counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      riskScore: 0,
      analysisTimeMs: 0,
      parseError: 'No workflow content provided.',
    };
  }

  const ir = parseWorkflow(yamlContent);

  if (ir.parseError) {
    return {
      findings: [],
      counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      riskScore: 0,
      analysisTimeMs: performance.now() - start,
      parseError: ir.parseError,
    };
  }

  // Run all checkers
  const rawFindings: Finding[] = ALL_CHECKERS.flatMap(checker => {
    try {
      return checker(ir);
    } catch {
      return [];
    }
  });

  // Deduplicate (same ruleId + same line)
  const seen = new Set<string>();
  const findings = rawFindings.filter(f => {
    const key = `${f.ruleId}:${f.line ?? 'global'}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort: CRITICAL → HIGH → MEDIUM → LOW, then by line number
  const ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => {
    const sev = ORDER[a.severity] - ORDER[b.severity];
    if (sev !== 0) return sev;
    return (a.line ?? 9999) - (b.line ?? 9999);
  });

  // Count by severity
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity]++;

  // CVSS-inspired risk score (weighted average)
  const riskScore = Math.min(10, (
    counts.CRITICAL * 9.5 +
    counts.HIGH * 7.5 +
    counts.MEDIUM * 5.0 +
    counts.LOW * 2.0
  ) / Math.max(1, findings.length));

  return {
    findings,
    counts,
    riskScore: Math.round(riskScore * 10) / 10,
    analysisTimeMs: Math.round(performance.now() - start),
    workflowName: ir.name,
  };
}

// JSON output formatter
export function toJSON(result: AnalysisResult): string {
  return JSON.stringify({
    schema: 'pipelint/v1',
    summary: {
      total: result.findings.length,
      counts: result.counts,
      riskScore: result.riskScore,
      analysisTimeMs: result.analysisTimeMs,
    },
    findings: result.findings.map(f => ({
      ruleId: f.ruleId,
      severity: f.severity,
      category: f.ruleDef.category,
      shortDescription: f.ruleDef.shortDescription,
      message: f.message,
      location: { line: f.line ?? null, context: f.context },
      snippet: f.snippet,
      cwe: f.ruleDef.cwe,
      remediation: f.ruleDef.remediation,
      references: f.ruleDef.references,
    })),
  }, null, 2);
}

// SARIF 2.1 output formatter
export function toSARIF(result: AnalysisResult, workflowPath = 'workflow.yml'): string {
  const SARIF_LEVEL: Record<Severity, string> = {
    CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note',
  };
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'PipeLint',
          version: '1.0.0',
          informationUri: 'https://github.com/pipelint/pipelint',
          rules: result.findings.map(f => f.ruleDef).filter((r, i, a) => a.findIndex(x => x.id === r.id) === i).map(r => ({
            id: r.id,
            name: r.shortDescription,
            shortDescription: { text: r.shortDescription },
            fullDescription: { text: r.fullDescription },
            helpUri: r.references[0] ?? '',
            properties: { tags: [r.category, r.severity, r.cwe] },
          })),
        },
      },
      results: result.findings.map(f => ({
        ruleId: f.ruleId,
        level: SARIF_LEVEL[f.severity],
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: workflowPath },
            region: { startLine: f.line ?? 1 },
          },
        }],
      })),
    }],
  }, null, 2);
}
