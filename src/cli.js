#!/usr/bin/env node
import path from 'node:path';
import { formatText, scanProject, toSarif } from './scanner.js';

const args = process.argv.slice(2);
const flags = new Set(args.filter((arg) => arg.startsWith('--')));
const positional = args.filter((arg) => !arg.startsWith('--'));
const rootDir = path.resolve(positional[0] || '.');

if (flags.has('--help') || flags.has('-h')) {
  console.log(`compose-risk-guard

Usage:
  compose-risk-guard [path] [--json|--sarif] [--no-fail]

Options:
  --json     Emit JSON findings
  --sarif    Emit SARIF 2.1.0
  --no-fail  Exit 0 even when findings are present
  --help     Show help
`);
  process.exit(0);
}

const findings = scanProject(rootDir);

if (flags.has('--json')) {
  console.log(JSON.stringify(findings, null, 2));
} else if (flags.has('--sarif')) {
  console.log(JSON.stringify(toSarif(findings, rootDir), null, 2));
} else {
  console.log(formatText(findings, rootDir));
}

process.exit(findings.length > 0 && !flags.has('--no-fail') ? 1 : 0);
