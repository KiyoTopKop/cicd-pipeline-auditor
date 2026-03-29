import type { WorkflowIR, Finding, RuleDefinition } from '../types';
import { SUPPLY_CHAIN_RULES } from './rules-sc-pm';
import { SECRETS_RULES } from './rules-se-ci';
import { TRIGGER_RULES, ENVIRONMENT_RULES } from './rules-tr-ee';
import { PERMISSIONS_RULES } from './rules-sc-pm';

// ── Helpers ──────────────────────────────────────────────────

let _findingCounter = 0;
function makeFinding(rule: RuleDefinition, line: number | undefined, snippet: string, context: string, message: string): Finding {
  return {
    id: `${rule.id}-${line ?? 0}-${_findingCounter++}`,
    ruleId: rule.id,
    ruleDef: rule,
    severity: rule.severity,
    line,
    snippet,
    context,
    message,
  };
}

const getRuleDef = (id: string): RuleDefinition => {
  const all = [...SUPPLY_CHAIN_RULES, ...PERMISSIONS_RULES, ...SECRETS_RULES, ...INJECTION_RULES, ...TRIGGER_RULES, ...ENVIRONMENT_RULES];
  return all.find(r => r.id === id)!;
};

// ── Import injection rules locally ───────────────────────────
import { INJECTION_RULES } from './rules-se-ci';

// ── Untrusted expression contexts ────────────────────────────
const UNTRUSTED_CONTEXTS = [
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.pull_request.head.ref',
  'github.head_ref',
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.pages',
  'github.event.commits',
  'github.event.discussion.title',
  'github.event.discussion.body',
];

const OUTBOUND_NET_CALLS = ['curl', 'wget', 'fetch(', 'requests.get', 'requests.post', 'http.get', 'http.post', 'nc ', 'ncat'];
const SECRET_PATTERN_RE = /(?:password|passwd|secret|api[_-]?key|token|auth|credential|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9+/=_\-]{8,}["']?/i;
const HARDCODED_SECRET_RE = /(?:(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|eyJhbGciOi[A-Za-z0-9._\-]{20,})/;
const MUTABLE_TAG_RE = /^[^@]+@(?:v\d[\w.-]*|main|master|latest|stable|dev|develop|HEAD)$/;

// ── SC (Supply Chain) Matchers ────────────────────────────────

function checkSC001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SC-001');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (step.uses && MUTABLE_TAG_RE.test(step.uses)) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, `Action \`${step.uses}\` uses a mutable tag. Pin to a full SHA commit hash.`));
      }
    }
  }
  return findings;
}

function checkSC002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SC-002');
  const findings: Finding[] = [];
  // Verified/Trusted publishers list for M1
  const VERIFIED_OWNERS = new Set(['actions', 'github', 'docker', 'aws-actions', 'google-github-actions', 'azure', 'microsoft', 'hashicorp', 'ncipollo', 'peaceiris', 'softprops']);
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.usesAction) continue;
      const { owner } = step.usesAction;
      if (!VERIFIED_OWNERS.has(owner.toLowerCase())) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, `Action \`${step.uses}\` is from an unverified publisher \`${owner}\`.`));
      }
    }
  }
  return findings;
}

function checkSC003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SC-003');
  const findings: Finding[] = [];
  // Known canonical action owners mapping repo → owner
  const WELL_KNOWN: Record<string, string> = {
    'checkout': 'actions', 'upload-artifact': 'actions', 'download-artifact': 'actions',
    'cache': 'actions', 'setup-node': 'actions', 'setup-python': 'actions',
    'setup-java': 'actions', 'github-script': 'actions', 'configure-aws-credentials': 'aws-actions',
    'docker/login-action': 'docker', 'docker/build-push-action': 'docker',
  };
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.usesAction) continue;
      const { owner, repo } = step.usesAction;
      const canonical = WELL_KNOWN[repo] ?? WELL_KNOWN[`${owner}/${repo}`];
      if (canonical && canonical !== owner) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, `\`${step.uses}\` appears to be a fork of \`${canonical}/${repo}\`. Use the canonical action.`));
      }
    }
  }
  return findings;
}

function checkSC004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SC-004');
  const findings: Finding[] = [];
  const SENSITIVE_KEYWORDS = /deploy|release|sign|publish|upload|prod/i;
  const isSensitiveJob = (job: any) => SENSITIVE_KEYWORDS.test(job.id) || job.steps.some((s: any) => SENSITIVE_KEYWORDS.test(s.name ?? ''));
  
  for (const job of ir.jobs) {
    if (!isSensitiveJob(job)) continue;
    for (const step of job.steps) {
      if (!step.usesAction) continue;
      // If it's not a verified owner (re-using logic from SC-002 or simplified)
      const VERIFIED_OWNERS = new Set(['actions', 'github', 'docker', 'aws-actions', 'google-github-actions', 'azure', 'microsoft', 'hashicorp']);
      if (!VERIFIED_OWNERS.has(step.usesAction.owner.toLowerCase())) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, `Unofficial action \`${step.uses}\` used in a security-sensitive job \`${job.id}\`.`));
      }
    }
  }
  return findings;
}

function checkSC005(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SC-005');
  const findings: Finding[] = [];
  // Local list of "well-known" vulnerable action versions for M1
  const VULNERABLE_ACTIONS = [
    { name: 'actions/checkout', version: 'v1', advisory: 'GHSA-v725-95jq-7q7v' },
    { name: 'actions/cache', version: 'v1', advisory: 'GHSA-v725-95jq-7q7v' },
    { name: 'tj-actions/changed-files', version: 'v35', advisory: 'GHSA-4p55-p6gx-qj9q' },
  ];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.uses) continue;
      const match = VULNERABLE_ACTIONS.find(v => step.uses!.startsWith(v.name) && step.uses!.includes(`@${v.version}`));
      if (match) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, `Action \`${step.uses}\` has a known security advisory: ${match.advisory}.`));
      }
    }
  }
  return findings;
}

// ── PM (Permissions) Matchers ─────────────────────────────────

function checkPM001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-001');
  if (!ir.permissions || ir.permissions.level === 'absent') {
    return [makeFinding(rule, undefined, '# No permissions: block', 'workflow level', 'No permissions block defined. Workflow inherits potentially broad org/repo defaults.')];
  }
  return [];
}

function checkPM002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-002');
  if (ir.permissions?.level === 'write-all') {
    return [makeFinding(rule, undefined, 'permissions: write-all', 'workflow level', '`permissions: write-all` grants every scope to every job.')];
  }
  return [];
}

function checkPM003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-003');
  const findings: Finding[] = [];
  const hasWriteCommit = ir.jobs.some(j => j.steps.some(s => s.run && /(git push|git commit|gh release create|upload-release-asset)/i.test(s.run)));
  if (!hasWriteCommit && ir.permissions?.scopes?.['contents'] === 'write') {
    findings.push(makeFinding(rule, undefined, 'permissions:\n  contents: write', 'workflow level', '`contents: write` is declared but no step performs a git push or release upload.'));
  }
  return findings;
}

function checkPM004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-004');
  const hasCloudDeploy = ir.jobs.some(j => j.steps.some(s => s.uses && /(aws-actions|google-github-actions|azure\/)/i.test(s.uses)));
  if (!hasCloudDeploy && ir.permissions?.scopes?.['id-token'] === 'write') {
    return [makeFinding(rule, undefined, 'permissions:\n  id-token: write', 'workflow level', '`id-token: write` grants OIDC federation but no cloud deploy step was found.')];
  }
  return [];
}

function checkPM005(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-005');
  const wfBroad = ir.permissions && (ir.permissions.level === 'write-all' || Object.values(ir.permissions.scopes).some(v => v === 'write'));
  if (!wfBroad) return [];
  const jobsWithoutPerms = ir.jobs.filter(j => !j.permissions);
  if (jobsWithoutPerms.length > 0) {
    return jobsWithoutPerms.map(j => makeFinding(rule, j.line, `# job: ${j.id}`, `job "${j.id}"`, `Job \`${j.id}\` does not declare its own permissions while workflow-level permissions are broad.`));
  }
  return [];
}

function checkPM006(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('PM-006');
  const hasPRTrigger = ir.triggers.some(t => t.event === 'pull_request');
  if (!hasPRTrigger) return [];
  const hasIDToken = ir.permissions?.scopes?.['id-token'] === 'write' || 
                   ir.jobs.some(j => j.permissions?.scopes?.['id-token'] === 'write');
  if (hasIDToken) {
    return [makeFinding(rule, undefined, 'on: pull_request\n# permissions: id-token: write', 'workflow permissions', '`id-token: write` present in a `pull_request` context — increase of credential theft risk via malicious PRs.')];
  }
  return [];
}

// ── SE (Secrets) Matchers ─────────────────────────────────────

function checkSE001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-001');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      const hasNetCall = OUTBOUND_NET_CALLS.some(nc => step.run!.includes(nc));
      if (!hasNetCall) continue;
      const envVals = Object.values(step.env ?? {});
      const hasSecret = envVals.some(v => v.includes('secrets.'));
      if (hasSecret) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Secret passed as env var to a run: block containing outbound network calls.'));
      }
    }
  }
  return findings;
}

function checkSE002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-002');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      if (/echo\s+["\$]?\$\{\{\s*secrets\.|print\s*\(os\.environ/i.test(step.run)) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Secret is echoed or printed to stdout — may bypass GitHub log masking.'));
      }
    }
  }
  return findings;
}

function checkSE003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-003');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      if (/--build-arg\s+\w+=\$\{\{\s*secrets\./i.test(step.run)) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Secret passed as Docker --build-arg. Secrets are captured in image layer history.'));
      }
    }
  }
  return findings;
}

function checkSE004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-004');
  const findings: Finding[] = [];
  const lines = ir.rawYaml.split('\n');
  lines.forEach((line, i) => {
    if (SECRET_PATTERN_RE.test(line) || HARDCODED_SECRET_RE.test(line)) {
      // Skip if it's using a ${{ secrets.* }} reference (that's fine)
      if (!line.includes('${{') && !line.startsWith('#')) {
        findings.push(makeFinding(rule, i + 1, line.trim().slice(0, 120), `line ${i + 1}`, 'Hardcoded credential pattern detected in YAML values. Rotate immediately.'));
      }
    }
  });
  return findings;
}

function checkSE005(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-005');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.uses?.includes('upload-artifact')) continue;
      // Check if any previous step in this job wrote a secret to a file
      const prevSteps = job.steps.slice(0, job.steps.indexOf(step));
      const secretToFile = prevSteps.some(s => s.run && s.run.includes('secrets.') && /echo|tee|write|>/.test(s.run));
      if (secretToFile) {
        findings.push(makeFinding(rule, step.line, `uses: ${step.uses}`, `job "${job.id}"`, 'Artifact upload follows a step that may have written secrets to a file.'));
      }
    }
  }
  return findings;
}

function checkSE006(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('SE-006');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    if (job.secrets === 'inherit') {
      findings.push(makeFinding(rule, job.line, `secrets: inherit`, `job "${job.id}"`, '`secrets: inherit` passes ALL parent secrets to the reusable workflow.'));
    }
  }
  return findings;
}

// ── CI (Injection) Matchers ───────────────────────────────────

function checkCI001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('CI-001');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      const untrusted = UNTRUSTED_CONTEXTS.filter(ctx => step.run!.includes(ctx));
      if (untrusted.length > 0) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 200), `job "${job.id}"`, `Untrusted event context (${untrusted[0]}) interpolated directly into shell script — command injection risk.`));
      }
    }
  }
  return findings;
}

function checkCI002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('CI-002');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.uses?.includes('github-script')) continue;
      const script = (step.with as Record<string, string>)?.['script'] ?? '';
      const untrusted = UNTRUSTED_CONTEXTS.filter(ctx => script.includes(ctx));
      if (untrusted.length > 0) {
        findings.push(makeFinding(rule, step.line, script.slice(0, 120), `job "${job.id}"`, `Untrusted input (${untrusted[0]}) passed to github-script without env var indirection.`));
      }
    }
  }
  return findings;
}

function checkCI003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('CI-003');
  const findings: Finding[] = [];
  const lines = ir.rawYaml.split('\n');
  lines.forEach((line, i) => {
    if (/\$\{\{\s*(toJSON|fromJSON)\s*\(/.test(line)) {
      const untrusted = UNTRUSTED_CONTEXTS.filter(ctx => line.includes(ctx));
      if (untrusted.length > 0) {
        findings.push(makeFinding(rule, i + 1, line.trim(), `line ${i + 1}`, `toJSON/fromJSON used with untrusted input (${untrusted[0]}).`));
      }
    }
  });
  return findings;
}

function checkCI004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('CI-004');
  const findings: Finding[] = [];
  const lines = ir.rawYaml.split('\n');
  lines.forEach((line, i) => {
    if (/\$\{\{.*(github\.event\.|github\.head_ref).*\}\}/.test(line) && !/^\s*#/.test(line)) {
      if (!/^\s*env:/.test(lines[i - 1] ?? '') && !line.includes('run:') ) {
        // Dynamic expression in non-env context
        const hasUntrusted = UNTRUSTED_CONTEXTS.some(ctx => line.includes(ctx));
        if (hasUntrusted) {
          findings.push(makeFinding(rule, i + 1, line.trim(), `line ${i + 1}`, 'Dynamic expression construction uses untrusted event context values.'));
        }
      }
    }
  });
  return findings;
}

function checkCI005(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('CI-005');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run || !step.run.includes('sudo ')) continue;
      const hasUntrusted = UNTRUSTED_CONTEXTS.some(ctx => step.run!.includes(ctx));
      if (hasUntrusted) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Unsafe `sudo` usage with direct interpolation of untrusted event context.'));
      }
    }
  }
  return findings;
}

// ── TR (Triggers) Matchers ────────────────────────────────────

function checkTR001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('TR-001');
  const hasPRT = ir.triggers.some(t => t.event === 'pull_request_target');
  if (!hasPRT) return [];
  const hasHeadCheckout = ir.jobs.some(job =>
    job.steps.some(step =>
      step.uses?.includes('checkout') &&
      step.expressions.some(e => e.includes('pull_request.head') || e.includes('head_ref') || e.includes('head.sha'))
    )
  );
  if (hasHeadCheckout) {
    return [makeFinding(rule, undefined, 'on: pull_request_target\n# + checkout of PR head', 'workflow triggers', 'CRITICAL: pull_request_target + PR head checkout allows fork code execution with base repo secrets.')];
  }
  return [];
}

function checkTR002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('TR-002');
  const wrTrigger = ir.triggers.find(t => t.event === 'workflow_run');
  if (!wrTrigger) return [];
  const config = wrTrigger.config as Record<string, unknown>;
  if (!config?.['workflows'] && !config?.['branches']) {
    return [makeFinding(rule, undefined, 'on:\n  workflow_run:\n    types: [completed]', 'workflow triggers', '`workflow_run` trigger has no `workflows:` or `branches:` filter — may fire for untrusted workflows.')];
  }
  return [];
}

function checkTR003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('TR-003');
  const wdTrigger = ir.triggers.find(t => t.event === 'workflow_dispatch');
  if (!wdTrigger) return [];
  const config = wdTrigger.config as Record<string, Record<string, unknown>> | null;
  const inputs = config?.['inputs'] ?? {};
  const stringInputs = Object.entries(inputs).filter(([, v]) => {
    const inp = v as Record<string, unknown>;
    return inp?.['type'] === 'string' || !inp?.['type'];
  });
  if (stringInputs.length === 0) return [];
  // Check if any input is used directly in run: without env var
  const inputNames = stringInputs.map(([k]) => k);
  const directUse = ir.jobs.some(job =>
    job.steps.some(s => s.run && inputNames.some(name => s.run!.includes(`inputs.${name}`) && !s.run!.startsWith('env:')))
  );
  if (directUse) {
    return [makeFinding(rule, undefined, 'on:\n  workflow_dispatch:\n    inputs: ...', 'workflow triggers', 'workflow_dispatch string inputs are passed directly to shell steps without sanitization.')];
  }
  return [];
}

function checkTR004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('TR-004');
  const pushToMain = ir.triggers.some(t => {
    if (t.event !== 'push') return false;
    const cfg = t.config as Record<string, unknown>;
    const branches = cfg?.['branches'] as string[] ?? [];
    return branches.some(b => ['main', 'master'].includes(b));
  });
  if (pushToMain) {
    return [makeFinding(rule, undefined, 'on:\n  push:\n    branches: [main]', 'workflow triggers', 'Workflow triggers on push to default branch. Ensure branch protection rules are enabled.')];
  }
  return [];
}

// ── EE (Environment) Matchers ─────────────────────────────────

function checkEE001(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-001');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    const ro = typeof job.runsOn === 'string' ? job.runsOn : job.runsOn.join(',');
    if (ro.includes('self-hosted')) {
      findings.push(makeFinding(rule, job.line, `runs-on: ${ro}`, `job "${job.id}"`, `Self-hosted runner in job \`${job.id}\` — verify network isolation and ephemeral configuration.`));
    }
  }
  return findings;
}

function checkEE002(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-002');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      if (/\b(curl|wget)\b.+\|\s*(ba?sh|sh|python|perl|ruby)/i.test(step.run)) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Script downloaded and piped directly to shell (curl|bash). No integrity verification.'));
      }
    }
  }
  return findings;
}

function checkEE003(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-003');
  const findings: Finding[] = [];
  const MUTABLE_DOCKER_RE = /^[^@]+:(latest|stable|dev|develop|\d+[\w.-]*)$/;
  for (const job of ir.jobs) {
    if (job.container?.image && MUTABLE_DOCKER_RE.test(job.container.image)) {
      findings.push(makeFinding(rule, job.line, `container:\n  image: ${job.container.image}`, `job "${job.id}"`, `Docker image \`${job.container.image}\` uses a mutable tag. Pin to an immutable digest.`));
    }
    if (job.services) {
      for (const [name, svc] of Object.entries(job.services)) {
        if (MUTABLE_DOCKER_RE.test(svc.image)) {
          findings.push(makeFinding(rule, job.line, `services:\n  ${name}:\n    image: ${svc.image}`, `job "${job.id}" service "${name}"`, `Service image \`${svc.image}\` uses a mutable tag.`));
        }
      }
    }
  }
  return findings;
}

function checkEE004(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-004');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      if (/docker\s+run\s+.*--privileged/i.test(step.run) || /\/var\/run\/docker\.sock/i.test(step.run)) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Docker --privileged flag or Docker socket mount detected. Container escape risk.'));
      }
      if (job.container?.options && (/--privileged/.test(job.container.options) || /docker\.sock/.test(job.container.options))) {
        findings.push(makeFinding(rule, job.line, `container:\n  options: ${job.container.options}`, `job "${job.id}"`, 'Container options use --privileged or mount Docker socket.'));
      }
    }
  }
  return findings;
}

function checkEE005(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-005');
  const findings: Finding[] = [];
  const SECURITY_KEYWORDS = /sign|deploy|release|secret|audit|scan|security|publish|attest/i;
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.continueOnError) continue;
      const stepName = step.name ?? step.uses ?? step.run ?? '';
      if (SECURITY_KEYWORDS.test(stepName)) {
        findings.push(makeFinding(rule, step.line, `continue-on-error: true\n# step: ${stepName.slice(0, 60)}`, `job "${job.id}"`, `\`continue-on-error: true\` on security-critical step "${stepName.slice(0, 50)}". Failures will be silently ignored.`));
      }
    }
  }
  return findings;
}

function checkEE006(ir: WorkflowIR): Finding[] {
  const rule = getRuleDef('EE-006');
  const findings: Finding[] = [];
  for (const job of ir.jobs) {
    for (const step of job.steps) {
      if (!step.run) continue;
      if (/(wget|curl).+\.(tar\.gz|zip|tgz|deb|rpm|exe|dmg)\b/.test(step.run) && !/sha256|sha512|checksum|gpg|verify/i.test(step.run)) {
        findings.push(makeFinding(rule, step.line, step.run.slice(0, 120), `job "${job.id}"`, 'Binary downloaded without checksum or signature verification.'));
      }
    }
  }
  return findings;
}

// ── Rule Registry ─────────────────────────────────────────────

export const ALL_CHECKERS: Array<(ir: WorkflowIR) => Finding[]> = [
  checkSC001, checkSC002, checkSC003, checkSC004, checkSC005,
  checkPM001, checkPM002, checkPM003, checkPM004, checkPM005, checkPM006,
  checkSE001, checkSE002, checkSE003, checkSE004, checkSE005, checkSE006,
  checkCI001, checkCI002, checkCI003, checkCI004, checkCI005,
  checkTR001, checkTR002, checkTR003, checkTR004,
  checkEE001, checkEE002, checkEE003, checkEE004, checkEE005, checkEE006,
];
