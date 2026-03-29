import { parseDocument, LineCounter } from 'yaml';
import type { WorkflowIR, WorkflowPermissions, WorkflowJob, WorkflowStep, WorkflowTrigger } from './types';

// Extract all ${{ ... }} expressions from a string
function extractExpressions(str: string): string[] {
  const matches: string[] = [];
  const re = /\$\{\{(.+?)\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(str)) !== null) {
    matches.push(m[1].trim());
  }
  return matches;
}

// Parse `uses: owner/repo@ref` → structured parts
function parseUsesRef(uses: string) {
  const match = uses.match(/^([^/]+)\/([^@]+)@(.+)$/);
  if (!match) return undefined;
  const [, owner, repo, ref] = match;
  const isSHA = /^[0-9a-f]{40}$/.test(ref);
  // Detect forks: repo name containing '-' after a slash could indicate fork, but we check
  // if the repo part itself signals a fork of a canonical action. We flag if owner
  // is not the canonical owner of a well-known action.
  const isFork = false; // Enhanced detection done in rule SC-003
  return { owner, repo, ref, isSHA, isFork };
}

function parsePermissions(raw: unknown, _lc?: LineCounter): WorkflowPermissions {
  if (raw === undefined || raw === null) {
    return { level: 'absent', scopes: {}, raw };
  }
  if (typeof raw === 'string') {
    if (raw === 'write-all') return { level: 'write-all', scopes: {}, raw };
    if (raw === 'read-all') return { level: 'read-all', scopes: {}, raw };
    return { level: 'none', scopes: {}, raw };
  }
  if (typeof raw === 'object' && raw !== null) {
    const scopes: Record<string, 'read' | 'write' | 'none'> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      scopes[k] = (v as string) as 'read' | 'write' | 'none';
    }
    return { level: 'custom', scopes, raw };
  }
  return { level: 'absent', scopes: {}, raw };
}

// Gather all string values recursively for expression scanning
function collectStrings(obj: unknown, acc: string[]): void {
  if (typeof obj === 'string') { acc.push(obj); return; }
  if (Array.isArray(obj)) { obj.forEach(v => collectStrings(v, acc)); return; }
  if (typeof obj === 'object' && obj !== null) {
    Object.values(obj as Record<string, unknown>).forEach(v => collectStrings(v, acc));
  }
}

export function parseWorkflow(yamlContent: string): WorkflowIR {
  const lc = new LineCounter();

  let parsed: unknown;
  try {
    parsed = parseDocument(yamlContent, { lineCounter: lc }).toJS();
  } catch (e) {
    return {
      rawYaml: yamlContent,
      triggers: [],
      jobs: [],
      allExpressions: [],
      lineMap: {},
      parseError: String(e),
    };
  }

  if (!parsed || typeof parsed !== 'object') {
    return {
      rawYaml: yamlContent,
      triggers: [],
      jobs: [],
      allExpressions: [],
      lineMap: {},
      parseError: 'Invalid or empty workflow file',
    };
  }

  const doc = parsed as Record<string, unknown>;

  // ---- Triggers ----
  const triggers: WorkflowTrigger[] = [];
  const on = doc['on'] ?? doc['true']; // 'on' sometimes parsed as boolean true
  if (on) {
    if (typeof on === 'string') {
      triggers.push({ event: on, config: {} });
    } else if (Array.isArray(on)) {
      (on as string[]).forEach(e => triggers.push({ event: e, config: {} }));
    } else if (typeof on === 'object' && on !== null) {
      Object.entries(on as Record<string, unknown>).forEach(([event, config]) => {
        triggers.push({ event, config });
      });
    }
  }

  // ---- Permissions ----
  const permissions = parsePermissions(doc['permissions']);

  // ---- Jobs ----
  const jobsRaw = (doc['jobs'] as Record<string, unknown>) ?? {};
  const jobs: WorkflowJob[] = [];

  for (const [jobId, jobRaw] of Object.entries(jobsRaw)) {
    const job = jobRaw as Record<string, unknown>;
    const runsOn = (job['runs-on'] as string | string[]) ?? 'ubuntu-latest';
    const jobPerms = job['permissions'] !== undefined
      ? parsePermissions(job['permissions'])
      : undefined;

    // Steps
    const stepsRaw = (job['steps'] as unknown[]) ?? [];
    const steps: WorkflowStep[] = stepsRaw.map((stepRaw) => {
      const step = (stepRaw as Record<string, unknown>) ?? {};
      const uses = step['uses'] as string | undefined;
      const run = step['run'] as string | undefined;
      const env = (step['env'] as Record<string, string>) ?? {};
      const withBlock = (step['with'] as Record<string, string>) ?? {};
      const continueOnError = !!(step['continue-on-error']);

      // Collect all expressions in this step
      const allStrs: string[] = [];
      collectStrings(step, allStrs);
      const expressions = allStrs.flatMap(s => extractExpressions(s));

      const usesAction = uses ? parseUsesRef(uses) : undefined;

      return {
        id: step['id'] as string | undefined,
        name: step['name'] as string | undefined,
        uses,
        run,
        env,
        with: withBlock,
        continueOnError,
        expressions,
        usesAction,
      };
    });

    // Container / services
    const containerRaw = job['container'] as Record<string, unknown> | string | undefined;
    let container: WorkflowJob['container'] | undefined;
    if (containerRaw) {
      if (typeof containerRaw === 'string') {
        container = { image: containerRaw };
      } else {
        container = {
          image: (containerRaw['image'] as string) ?? '',
          options: containerRaw['options'] as string | undefined,
        };
      }
    }

    const servicesRaw = (job['services'] as Record<string, Record<string, string>>) ?? {};
    const services: Record<string, { image: string }> = {};
    for (const [svc, svcCfg] of Object.entries(servicesRaw)) {
      services[svc] = { image: svcCfg['image'] ?? '' };
    }

    jobs.push({
      id: jobId,
      name: job['name'] as string | undefined,
      runsOn,
      permissions: jobPerms,
      steps,
      uses: job['uses'] as string | undefined,
      secrets: job['secrets'] as string | Record<string, string> | undefined,
      container,
      services: Object.keys(services).length > 0 ? services : undefined,
    });
  }

  // ---- All Expressions ----
  const allStrings: string[] = [];
  collectStrings(doc, allStrings);
  const allExpressions = allStrings.flatMap(s =>
    extractExpressions(s).map(expr => ({ expr, location: 'workflow', line: undefined }))
  );

  return {
    name: doc['name'] as string | undefined,
    rawYaml: yamlContent,
    permissions,
    triggers,
    jobs,
    allExpressions,
    lineMap: {},
  };
}
