import type { Rule, ScanOptions, ScanResult } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { discoverTargets } from './discovery.js';
import { getAllRules, getRulesByIds } from './rules/index.js';
import { loadCustomRules } from './rules/custom-loader.js';

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const start = performance.now();

  const targets = discoverTargets(options.path);

  // Select built-in rules
  let rules: Rule[] = options.rules
    ? getRulesByIds(options.rules)
    : getAllRules();

  // Load custom rules if specified
  if (options.customRules) {
    const custom = await loadCustomRules(options.customRules);
    rules = [...rules, ...custom];
  }

  let findings = rules.flatMap((rule) => rule.run(targets));

  if (options.severity) {
    const minLevel = SEVERITY_ORDER[options.severity];
    findings = findings.filter((f) => SEVERITY_ORDER[f.severity] <= minLevel);
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const duration = performance.now() - start;

  return {
    findings,
    scannedFiles: targets.map((t) => t.path),
    duration,
    timestamp: new Date().toISOString(),
  };
}

export function getExitCode(result: ScanResult, ci: boolean): number {
  if (!ci) return 0;
  const hasHighOrCritical = result.findings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  return hasHighOrCritical ? 1 : 0;
}
