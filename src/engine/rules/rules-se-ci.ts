import type { RuleDefinition } from '../types';

// ====================================================
// CATEGORY 3: Secrets (SE-001 – SE-006)
// ====================================================

export const SECRETS_RULES: RuleDefinition[] = [
  {
    id: 'SE-001',
    category: 'Secrets',
    severity: 'CRITICAL',
    shortDescription: 'Secret passed to run: block with outbound network call',
    fullDescription: 'A secret value (${{ secrets.* }}) is passed as an environment variable to a run: block that also contains outbound network calls (curl, wget, fetch). The secret may be exfiltrated.',
    cwe: 'CWE-312',
    remediation: {
      quickFix: 'Remove secrets from steps that make outbound network calls, or remove outbound calls from steps with secrets.',
      bestPractice: 'Never mix secrets and outbound network calls in the same step. Use dedicated secret-consuming steps with no network access.',
      before: 'env:\n  API_KEY: ${{ secrets.API_KEY }}\nrun: curl -H "Authorization: $API_KEY" https://external-api.com/data',
      after: '# Separate network calls from secret usage\n# If auth is needed, use an action designed for it:\n- uses: octokit/request-action@<sha>\n  with:\n    route: GET /repos/{owner}/{repo}',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets', 'https://cwe.mitre.org/data/definitions/312.html'],
  },
  {
    id: 'SE-002',
    category: 'Secrets',
    severity: 'HIGH',
    shortDescription: 'Secret echoed or printed to stdout',
    fullDescription: 'A secret is being echoed or printed to stdout (echo $SECRET, print(os.environ[...])). GitHub attempts to mask secrets in logs but this is not guaranteed under all conditions.',
    cwe: 'CWE-532',
    remediation: {
      quickFix: 'Remove all echo/print statements that reference secret values.',
      bestPractice: 'Never log secrets. Use `::add-mask::` for dynamic values that must be masked.',
      before: 'run: echo "Using token: ${{ secrets.API_TOKEN }}"',
      after: '# Remove secret logging entirely\n# If you need to verify a secret is set, check its length:\nrun: |\n  if [ -z "${{ secrets.API_TOKEN }}" ]; then\n    echo "ERROR: API_TOKEN not set"\n    exit 1\n  fi\n  echo "API_TOKEN is configured ($(echo "${{ secrets.API_TOKEN }}" | wc -c) chars)"',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets', 'https://cwe.mitre.org/data/definitions/532.html'],
  },
  {
    id: 'SE-003',
    category: 'Secrets',
    severity: 'HIGH',
    shortDescription: 'Secret passed as Docker --build-arg',
    fullDescription: 'A secret is passed as a Docker `--build-arg`. Build arguments are captured in the image layer history and are accessible to anyone who can pull the image.',
    cwe: 'CWE-312',
    remediation: {
      quickFix: 'Use Docker BuildKit secret mounts instead of --build-arg for secrets.',
      bestPractice: 'Use `--secret id=mysecret,src=./secret.txt` with BuildKit. Never embed secrets in image layers.',
      before: 'run: docker build --build-arg API_KEY=${{ secrets.API_KEY }} .',
      after: '# Use BuildKit secret mounts:\nrun: |\n  echo "${{ secrets.API_KEY }}" > /tmp/api_key.txt\n  DOCKER_BUILDKIT=1 docker build \\\n    --secret id=api_key,src=/tmp/api_key.txt \\\n    .\n  rm /tmp/api_key.txt',
    },
    references: ['https://docs.docker.com/build/building/secrets/', 'https://cwe.mitre.org/data/definitions/312.html'],
  },
  {
    id: 'SE-004',
    category: 'Secrets',
    severity: 'CRITICAL',
    shortDescription: 'Hardcoded secret pattern detected in YAML values',
    fullDescription: 'A string matching common secret patterns (API keys, tokens, private keys, connection strings) was detected hardcoded in the YAML file. Hardcoded secrets in source control are a critical vulnerability.',
    cwe: 'CWE-798',
    remediation: {
      quickFix: 'Immediately rotate the exposed credential. Remove it from the YAML file and all git history.',
      bestPractice: 'Use GitHub Secrets (${{ secrets.MY_SECRET }}) or a secrets manager. Run `git filter-repo` to purge history.',
      before: 'env:\n  DATABASE_URL: postgresql://admin:SuperSecret123!@db.example.com/mydb',
      after: 'env:\n  DATABASE_URL: ${{ secrets.DATABASE_URL }}\n# Add to GitHub Secrets in Settings → Secrets → Actions',
    },
    references: ['https://docs.github.com/en/actions/security-guides/encrypted-secrets', 'https://cwe.mitre.org/data/definitions/798.html'],
  },
  {
    id: 'SE-005',
    category: 'Secrets',
    severity: 'HIGH',
    shortDescription: 'GITHUB_TOKEN exposed in artifact upload step',
    fullDescription: 'GITHUB_TOKEN or another secret is exposed in a step that uploads artifacts. Artifacts may be publicly accessible depending on the repository visibility setting.',
    cwe: 'CWE-312',
    remediation: {
      quickFix: 'Remove secrets from artifact upload steps and ensure artifacts contain no credentials.',
      bestPractice: 'Audit all artifact contents before upload. Use artifact retention policies and restrict access.',
      before: 'env:\n  TOKEN: ${{ secrets.GITHUB_TOKEN }}\nrun: echo $TOKEN > report.txt\n- uses: actions/upload-artifact@v3\n  with:\n    name: report\n    path: report.txt',
      after: '# Never write secrets to files that get uploaded\n- uses: actions/upload-artifact@<sha>\n  with:\n    name: report\n    path: report.txt  # ensure this file contains no secrets',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets'],
  },
  {
    id: 'SE-006',
    category: 'Secrets',
    severity: 'MEDIUM',
    shortDescription: 'secrets: inherit in reusable workflow call',
    fullDescription: '`secrets: inherit` passes ALL secrets from the parent workflow to the called workflow without explicit mapping. This violates least-privilege and may expose secrets the sub-workflow does not need.',
    cwe: 'CWE-272',
    remediation: {
      quickFix: 'Replace `secrets: inherit` with an explicit secret mapping.',
      bestPractice: 'Only pass the specific secrets that the called workflow requires.',
      before: 'jobs:\n  call-reusable:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit',
      after: 'jobs:\n  call-reusable:\n    uses: ./.github/workflows/deploy.yml\n    secrets:\n      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n      # Only pass what deploy.yml actually needs',
    },
    references: ['https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-called-workflows'],
  },
];

// ====================================================
// CATEGORY 4: Injection (CI-001 – CI-004)
// ====================================================

export const INJECTION_RULES: RuleDefinition[] = [
  {
    id: 'CI-001',
    category: 'Injection',
    severity: 'CRITICAL',
    shortDescription: 'Untrusted event context directly in run: shell script',
    fullDescription: 'Untrusted event context values (${{ github.event.pull_request.title }}, ${{ github.head_ref }}, ${{ github.event.issue.body }}) are interpolated directly into a run: shell script. An attacker controls these values and can inject arbitrary shell commands.',
    cwe: 'CWE-78',
    remediation: {
      quickFix: 'Pass untrusted input through environment variables, never directly in shell scripts.',
      bestPractice: 'Always use environment variable indirection. Validate and sanitize inputs before use.',
      before: 'run: echo "PR title: ${{ github.event.pull_request.title }}"',
      after: 'env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: echo "PR title: $PR_TITLE"\n# Environment variables are not interpreted as shell commands',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections', 'https://cwe.mitre.org/data/definitions/78.html'],
  },
  {
    id: 'CI-002',
    category: 'Injection',
    severity: 'HIGH',
    shortDescription: 'Untrusted input to github-script without sanitization',
    fullDescription: 'Untrusted input is passed to `actions/github-script` or similar script-execution actions without sanitization via environment variable indirection. The input is evaluated in a JavaScript context.',
    cwe: 'CWE-78',
    remediation: {
      quickFix: 'Pass untrusted values through environment variables in the `env:` block.',
      bestPractice: 'Validate and escape all untrusted input. Use allowlists where possible.',
      before: "- uses: actions/github-script@v6\n  with:\n    script: |\n      const title = '${{ github.event.issue.title }}';\n      console.log(title);",
      after: "- uses: actions/github-script@<sha>\n  env:\n    ISSUE_TITLE: ${{ github.event.issue.title }}\n  with:\n    script: |\n      const title = process.env.ISSUE_TITLE;\n      console.log(title);",
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable'],
  },
  {
    id: 'CI-003',
    category: 'Injection',
    severity: 'HIGH',
    shortDescription: 'Unsafe toJSON/fromJSON with untrusted input',
    fullDescription: 'The workflow uses `${{ toJSON(...) }}` or `${{ fromJSON(...) }}` with untrusted input in an expression context. This can enable expression injection by embedding expression syntax within JSON values.',
    cwe: 'CWE-94',
    remediation: {
      quickFix: 'Avoid using toJSON/fromJSON with untrusted event context values in expressions.',
      bestPractice: 'Process JSON manipulation in a script step using environment variables for untrusted input.',
      before: 'run: echo ${{ toJSON(github.event.pull_request) }}',
      after: 'env:\n  PR_JSON: ${{ toJSON(github.event.pull_request) }}\nrun: echo "$PR_JSON"',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections'],
  },
  {
    id: 'CI-004',
    category: 'Injection',
    severity: 'MEDIUM',
    shortDescription: 'Dynamic expression construction with untrusted input',
    fullDescription: 'The workflow dynamically constructs GitHub Actions expressions using untrusted input values. This could alter control flow or exfiltrate context data if the input contains expression syntax.',
    cwe: 'CWE-94',
    remediation: {
      quickFix: 'Replace dynamic expression construction with static expressions and env var indirection.',
      bestPractice: 'Treat all user-controlled input as untrusted. Never construct expressions from user input.',
      before: '# Dynamically using untrusted values in if: conditions or with: blocks',
      after: '# Use fixed conditions with env var checks:\nif: env.VALIDATED_INPUT == \'expected-value\'',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
  },
  {
    id: 'CI-005',
    category: 'Injection',
    severity: 'HIGH',
    shortDescription: 'Unsafe sudo usage with untrusted input',
    fullDescription: '`sudo` is used in a step that also processes untrusted event context or user-controlled input. If an attacker can inject shell commands, they can execute them with root privileges, leading to full runner compromise.',
    cwe: 'CWE-250',
    remediation: {
      quickFix: 'Avoid using `sudo` in the same step as untrusted input. Separate sensitive commands into dedicated steps.',
      bestPractice: 'Minimize the use of `sudo`. If required, ensure the command being run has no way to execute arbitrary strings from the environment.',
      before: '- name: Process input\n  run: sudo ./process.sh "${{ github.event.issue.title }}"',
      after: '- name: Process input\n  env:\n    TITLE: ${{ github.event.issue.title }}\n  run: ./process.sh "$TITLE"\n- name: Root task\n  run: sudo ./finalize.sh',
    },
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections'],
  },
];
