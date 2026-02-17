import { describe, it, expect } from 'vitest';
import { scan, getExitCode } from '../src/scanner.js';
import type { ScanResult } from '../src/types.js';

describe('scan', () => {
  it('returns a valid ScanResult', () => {
    const result = scan({ format: 'console' });
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('scannedFiles');
    expect(result).toHaveProperty('duration');
    expect(result).toHaveProperty('timestamp');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.scannedFiles)).toBe(true);
    expect(typeof result.duration).toBe('number');
  });

  it('filters by severity', () => {
    const all = scan({ format: 'console' });
    const criticalOnly = scan({ format: 'console', severity: 'critical' });
    expect(criticalOnly.findings.length).toBeLessThanOrEqual(all.findings.length);
    criticalOnly.findings.forEach((f) => expect(f.severity).toBe('critical'));
  });

  it('filters by rule IDs', () => {
    const result = scan({ format: 'console', rules: ['file-permissions'] });
    result.findings.forEach((f) => expect(f.ruleId).toBe('file-permissions'));
  });
});

describe('getExitCode', () => {
  it('returns 0 when not in CI mode', () => {
    const result: ScanResult = {
      findings: [{ ruleId: 'x', severity: 'critical', title: '', description: '', filePath: '', recommendation: '' }],
      scannedFiles: [],
      duration: 0,
      timestamp: '',
    };
    expect(getExitCode(result, false)).toBe(0);
  });

  it('returns 1 in CI mode with critical findings', () => {
    const result: ScanResult = {
      findings: [{ ruleId: 'x', severity: 'critical', title: '', description: '', filePath: '', recommendation: '' }],
      scannedFiles: [],
      duration: 0,
      timestamp: '',
    };
    expect(getExitCode(result, true)).toBe(1);
  });

  it('returns 0 in CI mode with only low findings', () => {
    const result: ScanResult = {
      findings: [{ ruleId: 'x', severity: 'low', title: '', description: '', filePath: '', recommendation: '' }],
      scannedFiles: [],
      duration: 0,
      timestamp: '',
    };
    expect(getExitCode(result, true)).toBe(0);
  });
});
