import type { RuleDefinition } from '../types';

// ====================================================
// CATEGORY 1: Supply Chain (SC-001 – SC-005)
// ====================================================

export const SUPPLY_CHAIN_RULES: RuleDefinition[] = [
  {
    id: 'SC-001',
    category: 'Supply Chain',
    severity: 'CRITICAL',
    shortDescription: 'Action referenced by mutable tag instead of SHA',
    fullDescription: 'The action uses a mutable version tag (e.g., @v3, @main, @latest). Tags can be silently re-pointed by a compromised publisher, executing arbitrary code in your pipeline.',
    cwe: 'CWE-829',
    remediation: {
      quickFix: 'Pin the action to a full 40-character commit SHA.',
      bestPractice: 'Pin to SHA and add the version tag as a comment. Verify the SHA with `gh attestation verify`.',
      before: 'uses: actions/checkout@v3',
      after: 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v3.5.3',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions', 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies'],
  },
  {
    id: 'SC-002',
    category: 'Supply Chain',
    severity: 'HIGH',
    shortDescription: 'Action from non-verified publisher without provenance',
    fullDescription: 'This action is from a publisher without a verified GitHub Marketplace listing or published SLSA provenance (level < 2). The authenticity of the action cannot be confirmed.',
    cwe: 'CWE-494',
    remediation: {
      quickFix: 'Prefer actions from verified publishers (blue checkmark in GitHub Marketplace).',
      bestPractice: 'Verify action provenance with SLSA. Fork and vendor critical actions into your own org.',
      before: 'uses: some-unknown-user/mystery-action@v1',
      after: 'uses: your-org/forked-mystery-action@<pinned-sha>  # Reviewed and vendored',
    },
    references: ['https://slsa.dev/', 'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
  },
  {
    id: 'SC-003',
    category: 'Supply Chain',
    severity: 'HIGH',
    shortDescription: 'Action pulled from a repository fork',
    fullDescription: 'The action is pulled from a fork of the canonical repository. Forks may contain modified, potentially malicious code that differs from the original.',
    cwe: 'CWE-494',
    remediation: {
      quickFix: 'Use the canonical (upstream) action repository, not a fork.',
      bestPractice: 'If you must use a fork, review all commits, pin to a specific SHA, and host it in your org.',
      before: 'uses: some-fork/actions-checkout@v3  # fork of actions/checkout',
      after: 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # official',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
  },
  {
    id: 'SC-004',
    category: 'Supply Chain',
    severity: 'MEDIUM',
    shortDescription: 'Unofficial action in security-sensitive step',
    fullDescription: 'An action with no GitHub Marketplace listing is used in a security-sensitive context (deploy, release, or signing step). Unverified actions in privileged steps are high-risk.',
    cwe: 'CWE-829',
    remediation: {
      quickFix: 'Replace with an official or verified Marketplace action for sensitive operations.',
      bestPractice: 'Audit all actions used in deploy/release jobs. Prefer first-party GitHub actions.',
      before: 'uses: random-dev/deploy-to-prod@main',
      after: 'uses: github/deploy-pages@<pinned-sha>  # official GitHub action',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
  },
  {
    id: 'SC-005',
    category: 'Supply Chain',
    severity: 'CRITICAL',
    shortDescription: 'Action version has known security advisory (GHSA)',
    fullDescription: 'The pinned version of this action has a known security advisory in the GitHub Advisory Database. This version should not be used.',
    cwe: 'CWE-1395',
    remediation: {
      quickFix: 'Update to the latest patched version of the action.',
      bestPractice: 'Enable Dependabot for GitHub Actions to automatically receive update PRs for vulnerable actions.',
      before: '# uses a version with a known GHSA advisory',
      after: '# Update to patched version and enable Dependabot:\n# .github/dependabot.yml:\n# - package-ecosystem: "github-actions"\n#   directory: "/"\n#   schedule:\n#     interval: "weekly"',
    },
    references: ['https://github.com/advisories', 'https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot'],
  },
];

// ====================================================
// CATEGORY 2: Permissions (PM-001 – PM-005)
// ====================================================

export const PERMISSIONS_RULES: RuleDefinition[] = [
  {
    id: 'PM-001',
    category: 'Permissions',
    severity: 'HIGH',
    shortDescription: 'No explicit permissions block defined',
    fullDescription: 'No `permissions:` block is defined. The workflow relies on the repository or organization default permissions, which are often `write-all`. This violates the principle of least privilege.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Add `permissions: read-all` at the workflow level as a safe default.',
      bestPractice: 'Define the minimum required permissions at the job level. Start with `permissions: {}` and add only what each job needs.',
      before: '# No permissions block defined — inherits org/repo defaults\njobs:\n  build:\n    runs-on: ubuntu-latest',
      after: 'permissions:\n  contents: read  # minimum required\njobs:\n  build:\n    runs-on: ubuntu-latest',
    },
    references: ['https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token', 'https://github.com/ossf/scorecard/blob/main/docs/checks.md#token-permissions'],
  },
  {
    id: 'PM-002',
    category: 'Permissions',
    severity: 'CRITICAL',
    shortDescription: 'permissions: write-all set at workflow level',
    fullDescription: '`permissions: write-all` grants every scope to every job in this workflow. Any compromised step gains full write access to your repository, packages, and deployments.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Replace `write-all` with explicit per-scope permissions.',
      bestPractice: 'Scope permissions at the job level and grant only what each job needs.',
      before: 'permissions: write-all',
      after: 'permissions:\n  contents: read\n  # Add only what you need:\n  # pull-requests: write\n  # packages: write',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access'],
  },
  {
    id: 'PM-003',
    category: 'Permissions',
    severity: 'MEDIUM',
    shortDescription: 'Unused contents: write scope declared',
    fullDescription: '`permissions: contents: write` is declared but no step performs a git push, file commit, or release upload. This scope is unnecessarily broad.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Downgrade to `contents: read` if no write operations are performed.',
      bestPractice: 'Audit each permission scope against actual step requirements. Remove unused scopes.',
      before: 'permissions:\n  contents: write  # not actually used',
      after: 'permissions:\n  contents: read',
    },
    references: ['https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token'],
  },
  {
    id: 'PM-004',
    category: 'Permissions',
    severity: 'HIGH',
    shortDescription: 'id-token: write present outside deploy context',
    fullDescription: '`id-token: write` grants OIDC federation capability — the ability to obtain cloud provider credentials. This should only be present in deploy workflows with explicit cloud integration.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Remove `id-token: write` if this is not a cloud deployment workflow.',
      bestPractice: 'Scope `id-token: write` to the specific job that performs cloud authentication, not the whole workflow.',
      before: 'permissions:\n  id-token: write  # OIDC — but this is just a test workflow',
      after: '# Remove if not deploying to cloud\n# If deploying, scope to the specific job:\njobs:\n  deploy:\n    permissions:\n      id-token: write\n      contents: read',
    },
    references: ['https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect'],
  },
  {
    id: 'PM-005',
    category: 'Permissions',
    severity: 'MEDIUM',
    shortDescription: 'Job-level permissions not scoped individually',
    fullDescription: 'Workflow-level permissions are broad, but individual jobs do not declare their own minimum-required permission scopes. Each job should restrict permissions to only what it needs.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Add a `permissions:` block to each job with minimum required scopes.',
      bestPractice: 'Set `permissions: {}` at workflow level and explicitly grant per-job permissions.',
      before: 'permissions:\n  contents: write\n  pull-requests: write\njobs:\n  lint:\n    # inherits write-all — only needs read!',
      after: 'permissions: {}  # deny everything by default\njobs:\n  lint:\n    permissions:\n      contents: read\n  deploy:\n    permissions:\n      contents: write\n      deployments: write',
    },
    references: ['https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs'],
  },
  {
    id: 'PM-006',
    category: 'Permissions',
    severity: 'CRITICAL',
    shortDescription: 'id-token: write present in pull_request trigger',
    fullDescription: '`id-token: write` is enabled in a workflow triggered by `pull_request`. While GitHub Actions generally restricts OIDC to base repo contexts, misconfigurations in cloud role trust policies can allow attackers to obtain cloud credentials via malicious PRs.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Use `pull_request_target` with careful manual approval or only enable `id-token: write` on `push` to protected branches.',
      bestPractice: 'Restrict OIDC role trust policies in your cloud provider (AWS/Azure/GCP) to specific branches, environments, or tags. Never trust all PRs.',
      before: 'on: pull_request\npermissions:\n  id-token: write',
      after: 'on:\n  push:\n    branches: [main]\npermissions:\n  id-token: write',
    },
    references: ['https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-role-and-trust-policy'],
  },
];
