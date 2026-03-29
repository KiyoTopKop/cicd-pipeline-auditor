# Contributing to PipeLint

We welcome contributions! As a security tool, we have a few specific guidelines to ensure the engine remains robust and the rules are accurate.

## 🛡️ Rule Contributions

Adding a new security rule is the most common way to contribute:

1.  **Rule Definition**: Add a new rule object to the relevant file in `src/engine/rules/rules-*.ts`.
    *   Ensure you map it to a **CWE** (Common Weakness Enumeration).
    *   Provide a clear, actionable **remediation** hint.
2.  **Matcher Logic**: Implement the detection logic in `src/engine/rules/matchers.ts`.
    *   Use the `WorkflowIR` to traverse the job and step structure.
3.  **Registration**: Add your matcher to the `ALL_CHECKERS` list at the bottom of `matchers.ts`.

## 🛠️ Local Development

```bash
# Install dependencies
npm install

# Run the web UI in dev mode
npm run dev

# Run the CLI against a test file
npm run pipelint path/to/workflow.yml
```

## 🧪 Testing

Every rule should be tested against:
- **Positive Case**: A workflow that *should* trigger the finding.
- **Negative Case**: A workflow that uses the best practice and *should not* trigger.

## 📝 Pull Request Process

1.  Fork the repository and create your branch from `main`.
2.  If you've added logic, update the `README.md` rule list if applicable.
3.  Ensure your code passes linting and builds successfully (`npm run build`).

Thank you for helping make the CI/CD ecosystem more secure!
