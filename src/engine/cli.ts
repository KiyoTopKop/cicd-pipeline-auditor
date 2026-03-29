#!/usr/bin/env node
/**
 * PipeLint CLI — Professional Security Auditor for GitHub Actions
 * (c) 2026 KiyoTopKop
 */

import fs from 'fs';
import path from 'path';
import { analyze, toSARIF } from './analyzer';
import type { AnalysisResult } from './types';

const args = process.argv.slice(2);
const packageJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
const VERSION = packageJson.version || '1.0.0';

const help = `
${'\x1b[36m'}${'\x1b[1m'}🛡️  PipeLint v${VERSION}${'\x1b[0m'} — CI/CD Pipeline Security Auditor

Usage:
  npx pipelint [path] [options]

Arguments:
  path                 Path to scan (file or directory, default: .github/workflows)

Options:
  --format <type>      Output format: text, json, sarif (default: text)
  --fail-on <level>    Exit with code 1 if issues >= level: critical, high, medium, low (default: critical)
  --output <file>      Redirect report to a file (especially useful for json/sarif)
  --version, -v        Show version number
  --help, -h           Show this help menu

Examples:
  npx pipelint .github/workflows/main.yml
  npx pipelint --fail-on high
  npx pipelint --format sarif --output report.sarif
`;

function parseArguments() {
  const options: any = {
    format: 'text',
    failOn: 'critical',
    target: '.github/workflows',
    outputFile: undefined,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      console.log(help);
      process.exit(0);
    }
    if (arg === '--version' || arg === '-v') {
      console.log(`v${VERSION}`);
      process.exit(0);
    }
    if (arg === '--format') {
      options.format = args[++i];
    } else if (arg.startsWith('--format=')) {
      options.format = arg.split('=')[1];
    } else if (arg === '--fail-on') {
      options.failOn = args[++i];
    } else if (arg.startsWith('--fail-on=')) {
      options.failOn = arg.split('=')[1];
    } else if (arg === '--output') {
      options.outputFile = args[++i];
    } else if (arg.startsWith('--output=')) {
      options.outputFile = arg.split('=')[1];
    } else if (!arg.startsWith('-')) {
      options.target = arg;
    }
  }

  // Validation
  const validFormats = ['text', 'json', 'sarif'];
  if (!validFormats.includes(options.format)) {
    console.error(`\x1b[31mError: Invalid format "${options.format}". Valid options: ${validFormats.join(', ')}\x1b[0m`);
    process.exit(1);
  }

  const validLevels = ['critical', 'high', 'medium', 'low'];
  if (!validLevels.includes(options.failOn.toLowerCase())) {
    console.error(`\x1b[31mError: Invalid fail-on level "${options.failOn}". Valid options: ${validLevels.join(', ')}\x1b[0m`);
    process.exit(1);
  }

  return options;
}

const config = parseArguments();
const target = config.target;
const format = config.format;
const failOn = config.failOn;
const outputFile = config.outputFile;

// --- Colors & Formatting ---
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  orange: '\x1b[38:5:208m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
};

const labels = {
  CRITICAL: `${colors.red}${colors.bright}CRITICAL${colors.reset}`,
  HIGH: `${colors.orange}${colors.bright}HIGH${colors.reset}`,
  MEDIUM: `${colors.yellow}MEDIUM${colors.reset}`,
  LOW: `${colors.blue}LOW${colors.reset}`,
};

const SEVERITY_LEVELS = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const failLevel = SEVERITY_LEVELS[failOn.toUpperCase() as keyof typeof SEVERITY_LEVELS] ?? 0;

function wordWrap(text: string, width: number, indent: string = ''): string {
  const words = text.split(' ');
  let line = indent;
  const lines: string[] = [];

  for (const word of words) {
    if ((line + word).length > width) {
      lines.push(line.trimEnd());
      line = indent + word + ' ';
    } else {
      line += word + ' ';
    }
  }
  lines.push(line.trimEnd());
  return lines.join('\n');
}

function getRiskColor(score: number): string {
  if (score >= 7.5) return colors.red;
  if (score >= 5.0) return colors.orange;
  if (score >= 2.5) return colors.yellow;
  return colors.green;
}

function getFilesRecursive(dir: string): string[] {
  let results: string[] = [];
  const list = fs.readdirSync(dir);
  list.forEach(file => {
    file = path.join(dir, file);
    const stat = fs.statSync(file);
    if (stat && stat.isDirectory()) {
      results = results.concat(getFilesRecursive(file));
    } else {
      if (file.endsWith('.yml') || file.endsWith('.yaml')) {
        results.push(file);
      }
    }
  });
  return results;
}

// --- Scanning ---
async function run() {
  let files: string[] = [];

  // Support for stdin
  if (target === '-' || !process.stdin.isTTY && target === '.github/workflows') {
    const pipeContent = fs.readFileSync(0, 'utf8');
    if (pipeContent.trim()) {
      const result = analyze(pipeContent);
      if (format === 'json') console.log(JSON.stringify(result, null, 2));
      else if (format === 'sarif') console.log(toSARIF(result, 'stdin'));
      else {
        console.log(`${colors.cyan}--- Stdin Scan ---${colors.reset}`);
        result.findings.forEach(f => {
            const msg = wordWrap(f.message, 80, '    ');
            console.log(`  [${labels[f.severity]}] ${colors.bright}${f.ruleId}${colors.reset}\n${msg}`);
        });
      }
      process.exit(hasFailureCondition(result) ? 1 : 0);
    }
  }

  function hasFailureCondition(res: AnalysisResult): boolean {
    return res.findings.some(f => SEVERITY_LEVELS[f.severity] <= failLevel);
  }

  try {
    const stats = fs.statSync(target);
    if (stats.isDirectory()) {
      files = getFilesRecursive(target);
    } else {
      files.push(target);
    }
  } catch (err) {
    console.error(`${colors.red}Error: Target "${target}" not found.${colors.reset}`);
    process.exit(1);
  }

  if (files.length === 0) {
    console.log(`${colors.yellow}No YAML workflows found in "${target}"${colors.reset}`);
    process.exit(0);
  }

  if (format === 'text') {
    console.log(`${colors.cyan}${colors.bright}🛡️  PipeLint v1.0 — Scanning ${files.length} workflow(s)...${colors.reset}\n`);
  }

  const allFindings: { file: string; result: AnalysisResult }[] = [];
  let hasFailure = false;

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const result = analyze(content);
    allFindings.push({ file, result });

    if (format === 'text') {
      const scoreColor = getRiskColor(result.riskScore);
      console.log(`${colors.bright}File: ${file}${colors.reset} [Risk: ${scoreColor}${result.riskScore}/10${colors.reset}]`);
      if (result.findings.length === 0) {
        console.log(`  ${colors.green}✓ No issues found.${colors.reset}`);
      } else {
        for (const finding of result.findings) {
          const loc = finding.line ? `${colors.reset}${colors.cyan} (L${finding.line})${colors.reset}` : '';
          console.log(`  [${labels[finding.severity]}] ${colors.bright}${finding.ruleId}${colors.reset}${loc}`);
          console.log(wordWrap(finding.message, 90, '    '));
          if (finding.ruleDef.remediation?.quickFix) {
              const fix = wordWrap(finding.ruleDef.remediation.quickFix, 85, '          ');
              console.log(`${colors.green}    💡 Fix: ${fix.trimStart()}${colors.reset}`);
          }
        }
      }
      console.log('');
    }

    // Check exit code condition
    for (const f of result.findings) {
      if (SEVERITY_LEVELS[f.severity] <= failLevel) {
        hasFailure = true;
      }
    }
  }

  // --- Output Handling ---
  if (format === 'json') {
    console.log(JSON.stringify(allFindings, null, 2));
  } else if (format === 'sarif') {
    // Merge all findings into a single SARIF report
    const sarif = JSON.parse(toSARIF(allFindings[0].result, allFindings[0].file));
    for (let i = 1; i < allFindings.length; i++) {
        const nextSarif = JSON.parse(toSARIF(allFindings[i].result, allFindings[i].file));
        sarif.runs[0].results.push(...nextSarif.runs[0].results);
        // Merge rules in tool driver
        nextSarif.runs[0].tool.driver.rules.forEach((rule: any) => {
            if (!sarif.runs[0].tool.driver.rules.find((r: any) => r.id === rule.id)) {
                sarif.runs[0].tool.driver.rules.push(rule);
            }
        });
    }
    const out = JSON.stringify(sarif, null, 2);
    if (outputFile) fs.writeFileSync(outputFile, out);
    else console.log(out);
  }

  if (format === 'text') {
    const totalBySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    allFindings.forEach(f => {
      totalBySeverity.CRITICAL += f.result.counts.CRITICAL;
      totalBySeverity.HIGH += f.result.counts.HIGH;
      totalBySeverity.MEDIUM += f.result.counts.MEDIUM;
      totalBySeverity.LOW += f.result.counts.LOW;
    });

    const totalIssues = Object.values(totalBySeverity).reduce((a, b) => a + b, 0);
    const avgRisk = allFindings.reduce((sum, f) => sum + f.result.riskScore, 0) / Math.max(1, files.length);
    const scoreColor = getRiskColor(avgRisk);

    console.log(`${colors.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`);
    console.log(`${colors.cyan}${colors.bright}SUMMARY REPORT${colors.reset}`);
    console.log(`${colors.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`);
    console.log(`Files Scanned: ${files.length}`);
    console.log(`Average Risk:  ${scoreColor}${avgRisk.toFixed(1)} / 10.0${colors.reset}`);
    console.log(`Total Issues:  ${totalIssues > 0 ? colors.red : colors.green}${totalIssues}${colors.reset}`);
    console.log(` Breakdown:    ${labels.CRITICAL}: ${totalBySeverity.CRITICAL} | ${labels.HIGH}: ${totalBySeverity.HIGH} | ${labels.MEDIUM}: ${totalBySeverity.MEDIUM} | ${labels.LOW}: ${totalBySeverity.LOW}`);
    
    if (hasFailure) {
      console.log(`\nStatus:        ${colors.red}${colors.bright}FAILED${colors.reset} (issues found matching threshold: ${failOn.toUpperCase()})`);
    } else {
      console.log(`\nStatus:        ${colors.green}${colors.bright}PASSED${colors.reset}`);
    }
    console.log(`${colors.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}\n`);
  }

  if (hasFailure) process.exit(1);
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
