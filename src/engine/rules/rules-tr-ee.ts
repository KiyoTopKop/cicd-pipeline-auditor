import type { RuleDefinition } from '../types';

// ====================================================
// CATEGORY 5: Triggers (TR-001 – TR-004)
// ====================================================

export const TRIGGER_RULES: RuleDefinition[] = [
  {
    id: 'TR-001',
    category: 'Triggers',
    severity: 'CRITICAL',
    shortDescription: 'pull_request_target + PR head code checkout',
    fullDescription: 'The `pull_request_target` trigger executes workflows with base repo secrets and full permissions — even from untrusted forks. When combined with a checkout of the PR head branch, this allows fork attackers to execute arbitrary code with full secret access. This is PWNABLE.',
    cwe: 'CWE-1357',
    remediation: {
      quickFix: 'Remove the checkout of PR head code, or switch to `pull_request` trigger for untrusted workflows.',
      bestPractice: 'If you need pull_request_target for labeling/commenting, never checkout or execute code from the PR head. Separate build and comment workflows.',
      before: 'on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}',
      after: '# Option 1: Use pull_request (no secrets) for code execution\non: pull_request\n# Option 2: Use pull_request_target only for safe operations (no checkout)\non: pull_request_target\njobs:\n  label:\n    steps:\n      - uses: actions/labeler@<sha>  # no code checkout',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections', 'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/'],
  },
  {
    id: 'TR-002',
    category: 'Triggers',
    severity: 'HIGH',
    shortDescription: 'workflow_run without triggering workflow validation',
    fullDescription: 'The `workflow_run` trigger does not validate the triggering workflow name or branch. This workflow may execute in response to an untrusted or unexpected workflow completion, potentially from a forked repository.',
    cwe: 'CWE-284',
    remediation: {
      quickFix: 'Add explicit `workflows:` and `branches:` filters to workflow_run.',
      bestPractice: 'Validate the triggering workflow and branch. Check `github.event.workflow_run.head_branch` in steps.',
      before: 'on:\n  workflow_run:\n    types: [completed]',
      after: 'on:\n  workflow_run:\n    workflows: ["CI Build"]  # Only trusted workflow\n    branches: [main]         # Only from protected branch\n    types: [completed]',
    },
    references: ['https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run'],
  },
  {
    id: 'TR-003',
    category: 'Triggers',
    severity: 'MEDIUM',
    shortDescription: 'workflow_dispatch inputs without sanitization',
    fullDescription: 'The workflow is triggered by `workflow_dispatch` with inputs that are passed to shell steps without validation or sanitization. Manually-triggered inputs should be treated as untrusted.',
    cwe: 'CWE-20',
    remediation: {
      quickFix: 'Validate workflow_dispatch inputs before use. Use input type constraints (choice, boolean).',
      bestPractice: 'Define inputs with `type: choice` to restrict allowed values. Validate free-text inputs with allowlists.',
      before: 'on:\n  workflow_dispatch:\n    inputs:\n      environment:\n        type: string\nrun: deploy.sh ${{ inputs.environment }}',
      after: 'on:\n  workflow_dispatch:\n    inputs:\n      environment:\n        type: choice\n        options: [staging, production]\nenv:\n  ENVIRONMENT: ${{ inputs.environment }}\nrun: deploy.sh "$ENVIRONMENT"',
    },
    references: ['https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_dispatchinputs'],
  },
  {
    id: 'TR-004',
    category: 'Triggers',
    severity: 'LOW',
    shortDescription: 'Push to default branch with no branch protection',
    fullDescription: 'This workflow triggers on push to the default branch without enforcing branch protection at the workflow level. Any committer can trigger privileged pipeline steps.',
    cwe: 'CWE-284',
    remediation: {
      quickFix: 'Enable branch protection rules for the default branch in repository Settings.',
      bestPractice: 'Require PR reviews, status checks, and signed commits on the default branch.',
      before: 'on:\n  push:\n    branches: [main]  # No branch protection = any committer triggers this',
      after: '# Enable in GitHub: Settings → Branches → Branch protection rules\n# Required: Require pull request reviews before merging\n# Required: Require status checks to pass\non:\n  push:\n    branches: [main]',
    },
    references: ['https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches'],
  },
];

// ====================================================
// CATEGORY 6: Environment (EE-001 – EE-006)
// ====================================================

export const ENVIRONMENT_RULES: RuleDefinition[] = [
  {
    id: 'EE-001',
    category: 'Environment',
    severity: 'HIGH',
    shortDescription: 'Self-hosted runner without isolation documentation',
    fullDescription: 'A self-hosted runner is used without documented network isolation or runner group restrictions. Self-hosted runners persist state between jobs (workspace, tool cache, credentials) unless explicitly configured otherwise.',
    cwe: 'CWE-1357',
    remediation: {
      quickFix: 'Add a comment documenting the isolation configuration, or switch to GitHub-hosted runners.',
      bestPractice: 'Use ephemeral self-hosted runners (--once flag). Configure network isolation and restrict runner groups to trusted repos.',
      before: "runs-on: self-hosted",
      after: "# Document isolation:\nruns-on: [self-hosted, isolated, linux]\n# Ensure runner is configured with --once for ephemeral execution\n# Restrict runner group to this repository only",
    },
    references: ['https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security'],
  },
  {
    id: 'EE-002',
    category: 'Environment',
    severity: 'CRITICAL',
    shortDescription: 'Script downloaded and executed without checksum (curl|bash)',
    fullDescription: 'The workflow downloads and executes a script from an external URL without verifying its integrity (curl | bash, wget | sh pattern). A compromised CDN or MITM attack can execute arbitrary code.',
    cwe: 'CWE-494',
    remediation: {
      quickFix: 'Download the script separately and verify its SHA256 checksum before executing.',
      bestPractice: 'Vendor scripts into your repository instead of downloading them at runtime. Use content-addressed storage.',
      before: 'run: curl -fsSL https://get.example.com/install.sh | bash',
      after: '# Download and verify:\nrun: |\n  curl -fsSL https://get.example.com/install.sh -o install.sh\n  echo "expected-sha256-hash  install.sh" | sha256sum --check\n  bash install.sh',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions', 'https://cwe.mitre.org/data/definitions/494.html'],
  },
  {
    id: 'EE-003',
    category: 'Environment',
    severity: 'HIGH',
    shortDescription: 'Docker image referenced by mutable tag',
    fullDescription: 'A Docker image is referenced by a mutable tag (:latest, :stable, or a version tag) in `container:` or `services:` block. The image content can silently change between workflow runs.',
    cwe: 'CWE-494',
    remediation: {
      quickFix: 'Pin Docker images to an immutable digest (sha256:...).',
      bestPractice: 'Use image digests for all container references. Update digests deliberately via Dependabot.',
      before: 'container:\n  image: node:20-alpine  # mutable tag',
      after: 'container:\n  image: node@sha256:abc123...  # pinned digest\n  # Tag for reference: node:20-alpine',
    },
    references: ['https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier'],
  },
  {
    id: 'EE-004',
    category: 'Environment',
    severity: 'CRITICAL',
    shortDescription: '--privileged Docker run or Docker socket mount',
    fullDescription: 'The workflow uses `docker run --privileged` or mounts the Docker socket (`/var/run/docker.sock`). Either grants the container full root access to the host and enables container escape.',
    cwe: 'CWE-250',
    remediation: {
      quickFix: 'Remove `--privileged` and Docker socket mounts. Use Docker-in-Docker (dind) with rootless mode instead.',
      bestPractice: 'Use rootless Docker or Podman. Scope container capabilities with --cap-add instead of --privileged.',
      before: 'run: docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock myimage',
      after: '# Use docker:dind service instead of socket mount:\nservices:\n  docker:\n    image: docker:dind@sha256:<digest>\n    options: --privileged  # Only if absolutely needed, document why',
    },
    references: ['https://docs.docker.com/engine/security/', 'https://cwe.mitre.org/data/definitions/250.html'],
  },
  {
    id: 'EE-005',
    category: 'Environment',
    severity: 'MEDIUM',
    shortDescription: 'continue-on-error: true on security-critical step',
    fullDescription: '`continue-on-error: true` is set on a security-critical step (code signing, deployment, secret validation, security scan). A failure in this step is silently ignored, allowing the workflow to continue in a potentially compromised state.',
    cwe: 'CWE-390',
    remediation: {
      quickFix: 'Remove `continue-on-error: true` from security-critical steps.',
      bestPractice: 'Only use `continue-on-error: true` for non-critical informational steps (e.g., optional notifications). Critical steps must fail the workflow.',
      before: 'steps:\n  - name: Security scan\n    uses: security/scanner@v1\n    continue-on-error: true  # scan failure is silently ignored!',
      after: 'steps:\n  - name: Security scan\n    uses: security/scanner@<sha>\n    # Remove continue-on-error — scan failure should block the workflow',
    },
    references: ['https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepscontinue-on-error', 'https://cwe.mitre.org/data/definitions/390.html'],
  },
  {
    id: 'EE-006',
    category: 'Environment',
    severity: 'HIGH',
    shortDescription: 'Workflow downloads and installs external binaries without verification',
    fullDescription: 'The workflow downloads and installs external binaries without signature verification or checksum validation. A compromised download source can replace the binary with malicious code.',
    cwe: 'CWE-494',
    remediation: {
      quickFix: 'Verify the SHA256 or GPG signature of downloaded binaries before installation.',
      bestPractice: 'Use official package managers (apt, brew) or GitHub Actions from verified publishers for tool installation.',
      before: 'run: |\n  wget https://example.com/tool-v1.0-linux-amd64.tar.gz\n  tar -xzf tool-v1.0-linux-amd64.tar.gz\n  sudo mv tool /usr/local/bin/',
      after: 'run: |\n  wget https://example.com/tool-v1.0-linux-amd64.tar.gz\n  wget https://example.com/tool-v1.0-linux-amd64.tar.gz.sha256\n  sha256sum --check tool-v1.0-linux-amd64.tar.gz.sha256\n  tar -xzf tool-v1.0-linux-amd64.tar.gz\n  sudo mv tool /usr/local/bin/',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions', 'https://cwe.mitre.org/data/definitions/494.html'],
  },
];
