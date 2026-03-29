<p align="center">
  <img src="https://img.shields.io/badge/🛡️-PipeLint-5b8def?style=for-the-badge&labelColor=0a0d14" alt="PipeLint" />
</p>

<h1 align="center">CI/CD Pipeline Auditor</h1>

<p align="center">
  <strong>Trivy for CI Pipelines</strong> — Static security analysis for GitHub Actions workflows.
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-→-4ade80?style=flat-square" /></a>
  <a href="#-rules"><img src="https://img.shields.io/badge/32_Rules-6_Categories-ff8c42?style=flat-square" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-5b8def?style=flat-square" /></a>
  <img src="https://img.shields.io/badge/Platform-Browser-ffd166?style=flat-square" />
</p>

<br />

<p align="center">
  Paste a workflow. See critical issues in seconds.<br/>
  <em>No sign-up. No installation. No data leaves your browser.</em>
</p>

---

## 🎯 What Is This?

**PipeLint** is a developer-first security tool that statically analyzes GitHub Actions YAML workflow definitions to detect:

- 🔗 **Supply chain vulnerabilities** — unpinned actions, mutable tags, forked repos
- 🔑 **Excessive permissions** — overly broad `GITHUB_TOKEN` scopes
- 🕳️ **Secret exfiltration risks** — leaked tokens via `curl`, `echo`, `--build-arg`
- 💉 **Command injection** — untrusted PR titles/branch names in `run:` blocks
- ⚡ **Dangerous triggers** — `pull_request_target` + head checkout exploits
- 🐳 **Runtime misconfigurations** — `--privileged` containers, `curl | bash`, mutable Docker tags

All analysis runs **100% client-side** in your browser. Your workflow YAML never leaves your machine.

---

## 🚀 Quick Start

### Option 1: Web Interface
Open `http://localhost:5173` → paste your workflow → click **Audit Workflow**.

### Option 2: CLI (Local Scan)
```bash
# Scan current directory (.github/workflows/)
npx tsx src/engine/cli.ts

# Scan a specific file
npx tsx src/engine/cli.ts .github/workflows/main.yml --fail-on high
```

### Option 3: GitHub Action (CI/CD)
Add this to your workflow to audit other workflows:
```yaml
steps:
  - uses: actions/checkout@v4
  - name: Audit Workflows
    uses: KiyoTopKop/pipelint@v1
    with:
      path: '.github/workflows'
      fail-on: 'critical'
```

---

## 🖥️ How It Works

```
┌────────────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│   YAML Input       │────▶│  Parser +    │────▶│  30 Rules    │────▶│  Findings +      │
│  (paste or file)   │     │  Workflow IR  │     │  (parallel)  │     │  Remediation     │
└────────────────────┘     └──────────────┘     └──────────────┘     └──────────────────┘
```

1. **Parse** — The YAML is parsed into a typed Workflow Intermediate Representation (IR)
2. **Analyze** — All 30 rules execute against the IR concurrently
3. **Report** — Findings are deduplicated, sorted by severity, and displayed with actionable fix guidance

**Performance target:** < 100ms for single workflow analysis.

---

## 📋 Rules

PipeLint ships with **32 rules** across **6 categories**, each mapped to CWE identifiers:

### Supply Chain (SC)

| Rule | Description | Severity |
|------|-------------|----------|
| `SC-001` | Action referenced by mutable tag instead of SHA | 🔴 CRITICAL |
| `SC-002` | Action from non-verified publisher without provenance | 🟠 HIGH |
| `SC-003` | Action pulled from a repository fork | 🟠 HIGH |
| `SC-004` | Unofficial action in security-sensitive step | 🟡 MEDIUM |
| `SC-005` | Action version has known security advisory (GHSA) | 🔴 CRITICAL |

### Permissions (PM)

| Rule | Description | Severity |
|------|-------------|----------|
| `PM-001` | No explicit `permissions` block defined | 🟠 HIGH |
| `PM-002` | `permissions: write-all` at workflow level | 🔴 CRITICAL |
| `PM-003` | Unused `contents: write` scope declared | 🟡 MEDIUM |
| `PM-004` | `id-token: write` present outside deploy context | 🟠 HIGH |
| `PM-005` | Job-level permissions not scoped individually | 🟡 MEDIUM |
| `PM-006` | `id-token: write` present in `pull_request` trigger | 🔴 CRITICAL |

### Secrets (SE)

| Rule | Description | Severity |
|------|-------------|----------|
| `SE-001` | Secret passed to `run:` block with outbound network call | 🔴 CRITICAL |
| `SE-002` | Secret echoed or printed to stdout | 🟠 HIGH |
| `SE-003` | Secret passed as Docker `--build-arg` | 🟠 HIGH |
| `SE-004` | Hardcoded secret pattern detected in YAML values | 🔴 CRITICAL |
| `SE-005` | `GITHUB_TOKEN` exposed in artifact upload step | 🟠 HIGH |
| `SE-006` | `secrets: inherit` in reusable workflow call | 🟡 MEDIUM |

### Injection (CI)

| Rule | Description | Severity |
|------|-------------|----------|
| `CI-001` | Untrusted event context directly in `run:` shell script | 🔴 CRITICAL |
| `CI-002` | Untrusted input to `github-script` without sanitization | 🟠 HIGH |
| `CI-003` | Unsafe `toJSON`/`fromJSON` with untrusted input | 🟠 HIGH |
| `CI-004` | Dynamic expression construction with untrusted input | 🟡 MEDIUM |
| `CI-005` | Unsafe `sudo` usage with direct untrusted interpolation | 🟠 HIGH |

### Triggers (TR)

| Rule | Description | Severity |
|------|-------------|----------|
| `TR-001` | `pull_request_target` + PR head code checkout | 🔴 CRITICAL |
| `TR-002` | `workflow_run` without triggering workflow validation | 🟠 HIGH |
| `TR-003` | `workflow_dispatch` inputs without sanitization | 🟡 MEDIUM |
| `TR-004` | Push to default branch with no branch protection | 🔵 LOW |

### Environment (EE)

| Rule | Description | Severity |
|------|-------------|----------|
| `EE-001` | Self-hosted runner without isolation documentation | 🟠 HIGH |
| `EE-002` | Script downloaded and executed without checksum (`curl\|bash`) | 🔴 CRITICAL |
| `EE-003` | Docker image referenced by mutable tag | 🟠 HIGH |
| `EE-004` | `--privileged` Docker run or Docker socket mount | 🔴 CRITICAL |
| `EE-005` | `continue-on-error: true` on security-critical step | 🟡 MEDIUM |
| `EE-006` | External binaries installed without signature verification | 🟠 HIGH |

---

## 📤 Output Formats

| Format | Use Case |
|--------|----------|
| **Interactive UI** | Web interface with Monaco editor, inline annotations, and expandable finding cards |
| **JSON** | Machine-readable structured output for CI/CD integration |
| **SARIF 2.1** | GitHub Code Scanning integration — upload to the Security tab |

Copy JSON or SARIF directly from the summary bar in the web interface.

---

## 🏗️ Architecture

```
src/
├── engine/                    # Core analysis engine (pure logic, no I/O)
│   ├── types.ts               # WorkflowIR, Finding, RuleDefinition types
│   ├── parser.ts              # YAML → Workflow IR builder
│   ├── analyzer.ts            # Orchestrator + JSON/SARIF formatters
│   └── rules/
│       ├── rules-sc-pm.ts     # Supply Chain + Permissions rule definitions
│       ├── rules-se-ci.ts     # Secrets + Injection rule definitions
│       ├── rules-tr-ee.ts     # Triggers + Environment rule definitions
│       └── matchers.ts        # All 30 rule matcher functions
├── components/                # React components
│   ├── Editor.tsx             # Monaco YAML editor with inline decorations
│   ├── FindingCard.tsx        # Expandable finding card with remediation diffs
│   ├── Results.tsx            # Results panel (findings list)
│   └── SummaryBar.tsx         # Severity counts, risk score, export buttons
├── data/
│   └── example-workflow.yaml  # Pre-loaded vulnerable demo workflow
├── styles/
│   └── index.css              # Dark security theme design system
├── App.tsx                    # Main application state + layout
└── main.tsx                   # Entry point
```

### Design Principles

- **Engine is pure** — The analysis engine (`src/engine/`) has zero UI dependencies. It takes a YAML string and returns structured findings. This makes it trivially embeddable in a CLI, API server, or VS Code extension.
- **Rules are data-driven** — Rule definitions (descriptions, CWEs, remediation examples) are separated from matcher logic, enabling rule updates without code changes.
- **Client-side only** — No backend, no data storage, no telemetry. Privacy by architecture.

---

## 🔒 Security & Privacy

- **No data leaves your browser.** All analysis runs client-side in JavaScript.
- **No workflow content is stored, logged, or transmitted.** Ever.
- **No authentication required.** Zero friction to insight.
- **No telemetry** in the open-source version.

---

## 🗺️ Roadmap

| Milestone | Status | Description |
|-----------|--------|-------------|
| **M0 — Foundation** | ✅ Done | Core parser + rule engine + 32 rules |
| **M1 — Web Interface** | ✅ Done | Monaco editor, paste-and-scan, JSON/SARIF export |
| **M2 — CI/CD Gate** | ✅ Done | CLI version, GitHub Action, exit code management |
| M3 — Org Scale | 🔲 Planned | `--org` scan, enrichment layer, trend tracking |
| M4 — Platform Expansion | 🔲 Planned | GitLab CI support, custom rules (OPA Rego), VS Code extension |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript |
| Editor | Monaco Editor (VS Code engine) |
| YAML Parsing | `yaml` (CST-preserving parser) |
| Build | Vite |
| Styling | Vanilla CSS (custom dark theme) |
| Typography | Inter + JetBrains Mono |

---

## 📚 Standards Alignment

Rules are mapped to industry security standards:

- **CWE** — Common Weakness Enumeration identifiers on every finding
- **OSSF Scorecard** — Aligned with Pinned-Dependencies, Token-Permissions, and Dangerous-Workflow checks
- **OWASP CI/CD Top 10** — Full mapping from risk categories to PipeLint rules
- **SLSA Framework** — Detection rules promote SLSA Level 2+ practices
- **NIST SP 800-218 (SSDF)** — Supply chain integrity rules map to PW.4, PW.7, RV.1

---

## 🤝 Contributing

Contributions are welcome! To add a new rule:

1. Add the rule definition to the appropriate `rules-*.ts` file (description, CWE, remediation example)
2. Add a matcher function in `matchers.ts`
3. Register the matcher in the `ALL_CHECKERS` array
4. Test with a positive fixture (should detect) and negative fixture (should not detect)

---

## 📄 License

[Apache 2.0](LICENSE) — Use freely in personal and commercial projects.

---

<p align="center">
  <sub>Built with 🛡️ by security engineers, for developers.</sub><br/>
  <sub>Inspired by <a href="https://trivy.dev">Trivy</a>, <a href="https://github.com/ossf/scorecard">OSSF Scorecard</a>, and the <a href="https://owasp.org/www-project-top-10-ci-cd-security-risks/">OWASP CI/CD Top 10</a>.</sub>
</p>
