export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  line?: number;
  evidence?: string;
  recommendation: string;
}

export interface ScanTarget {
  path: string;
  type: 'claude-settings' | 'claude-desktop' | 'mcp-server-config' | 'env-file' | 'launch-script' | 'project-config';
  content?: string;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  run(targets: ScanTarget[]): Finding[];
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: string[];
  duration: number;
  timestamp: string;
}

export interface ScanOptions {
  format: 'console' | 'json';
  severity?: Severity;
  rules?: string[];
  verbose?: boolean;
  ci?: boolean;
  path?: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
