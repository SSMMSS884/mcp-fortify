import chalk from 'chalk';
import Table from 'cli-table3';
import type { Finding, ScanResult, Severity } from '../types.js';

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '!!',
  high: '!',
  medium: '~',
  low: '-',
  info: 'i',
};

function severityBadge(severity: Severity): string {
  return SEVERITY_COLORS[severity](` ${SEVERITY_ICONS[severity]} ${severity.toUpperCase()} `);
}

export function formatConsole(result: ScanResult, verbose: boolean): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(chalk.bold('  MCP Fortify — MCP Configuration Security Scanner'));
  lines.push(chalk.gray(`  Scanned ${result.scannedFiles.length} files in ${result.duration.toFixed(0)}ms`));
  lines.push('');

  if (verbose) {
    lines.push(chalk.gray('  Scanned files:'));
    for (const file of result.scannedFiles) {
      lines.push(chalk.gray(`    - ${file}`));
    }
    lines.push('');
  }

  if (result.findings.length === 0) {
    lines.push(chalk.green.bold('  No security issues found!'));
    lines.push('');
    return lines.join('\n');
  }

  // Summary table
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) {
    counts[f.severity]++;
  }

  const summaryParts: string[] = [];
  if (counts.critical > 0) summaryParts.push(chalk.bgRed.white.bold(` ${counts.critical} CRITICAL `));
  if (counts.high > 0) summaryParts.push(chalk.red.bold(`${counts.high} HIGH`));
  if (counts.medium > 0) summaryParts.push(chalk.yellow.bold(`${counts.medium} MEDIUM`));
  if (counts.low > 0) summaryParts.push(chalk.blue(`${counts.low} LOW`));
  if (counts.info > 0) summaryParts.push(chalk.gray(`${counts.info} INFO`));

  lines.push(`  ${summaryParts.join('  ')}`);
  lines.push('');

  // Findings
  for (const finding of result.findings) {
    lines.push(`  ${severityBadge(finding.severity)}  ${chalk.bold(finding.title)}`);
    lines.push(chalk.gray(`  Rule: ${finding.ruleId}  |  File: ${finding.filePath}${finding.line ? `:${finding.line}` : ''}`));

    if (finding.evidence) {
      lines.push(`  ${chalk.gray('Evidence:')} ${finding.evidence}`);
    }

    lines.push(`  ${chalk.gray('Fix:')} ${finding.recommendation}`);
    lines.push('');
  }

  return lines.join('\n');
}
