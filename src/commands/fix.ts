import { chmodSync, statSync } from 'fs';
import chalk from 'chalk';
import type { Finding, ScanResult } from '../types.js';

interface FixResult {
  finding: Finding;
  fixed: boolean;
  action: string;
  error?: string;
}

function fixFilePermissions(finding: Finding): FixResult {
  try {
    const isScript = finding.filePath.endsWith('.sh');
    const targetMode = isScript ? 0o700 : 0o600;
    const targetOctal = isScript ? '700' : '600';

    chmodSync(finding.filePath, targetMode);

    // Verify
    const stat = statSync(finding.filePath);
    const actual = (stat.mode & 0o777).toString(8).padStart(3, '0');

    if (actual === targetOctal) {
      return {
        finding,
        fixed: true,
        action: `chmod ${targetOctal} "${finding.filePath}"`,
      };
    }
    return {
      finding,
      fixed: false,
      action: `chmod ${targetOctal} "${finding.filePath}"`,
      error: `Permissions still ${actual} after fix attempt`,
    };
  } catch (e) {
    return {
      finding,
      fixed: false,
      action: `chmod on "${finding.filePath}"`,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export function runFix(scanResult: ScanResult, dryRun: boolean): void {
  const fixableRules = ['file-permissions'];
  const fixable = scanResult.findings.filter((f) => fixableRules.includes(f.ruleId));
  const nonFixable = scanResult.findings.filter((f) => !fixableRules.includes(f.ruleId));

  console.log('');
  console.log(chalk.bold('  MCP Fortify — Auto-Fix'));
  console.log('');

  if (fixable.length === 0) {
    console.log(chalk.green('  No auto-fixable issues found.'));
    if (nonFixable.length > 0) {
      console.log(chalk.gray(`  ${nonFixable.length} finding(s) require manual remediation.`));
    }
    console.log('');
    return;
  }

  if (dryRun) {
    console.log(chalk.yellow('  DRY RUN — no changes will be made:'));
    console.log('');
    for (const f of fixable) {
      const isScript = f.filePath.endsWith('.sh');
      console.log(chalk.gray(`  chmod ${isScript ? '700' : '600'} "${f.filePath}"`));
    }
    console.log('');
    return;
  }

  const results: FixResult[] = [];

  for (const finding of fixable) {
    if (finding.ruleId === 'file-permissions') {
      results.push(fixFilePermissions(finding));
    }
  }

  const fixed = results.filter((r) => r.fixed);
  const failed = results.filter((r) => !r.fixed);

  for (const r of fixed) {
    console.log(chalk.green(`  + Fixed: `) + r.action);
  }

  for (const r of failed) {
    console.log(chalk.red(`  x Failed: `) + `${r.action} — ${r.error}`);
  }

  console.log('');
  console.log(
    chalk.bold(`  ${fixed.length} fixed`) +
    (failed.length > 0 ? chalk.red(`, ${failed.length} failed`) : '') +
    (nonFixable.length > 0 ? chalk.gray(`, ${nonFixable.length} require manual fix`) : ''),
  );

  if (nonFixable.length > 0) {
    console.log('');
    console.log(chalk.gray('  Manual fixes needed:'));
    for (const f of nonFixable) {
      console.log(chalk.gray(`  - [${f.severity.toUpperCase()}] ${f.title}`));
      console.log(chalk.gray(`    ${f.recommendation}`));
    }
  }

  console.log('');
}
