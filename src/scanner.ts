import type { ScanOptions, ScanResult, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { discoverTargets } from './discovery.js';
import { getAllRules, getRulesByIds } from './rules/index.js';

export function scan(options: ScanOptions): ScanResult {
  const start = performance.now();

  // Discover targets
  const targets = discoverTargets(options.path);

  // Select rules
  const rules = options.rules
    ? getRulesByIds(options.rules)
    : getAllRules();

  // Run all rules against all targets
  let findings = rules.flatMap((rule) => rule.run(targets));

  // Filter by severity if specified
  if (options.severity) {
    const minLevel = SEVERITY_ORDER[options.severity];
    findings = findings.filter((f) => SEVERITY_ORDER[f.severity] <= minLevel);
  }

  // Sort by severity (critical first)
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
