import type { Finding, ScanResult, Severity } from '../types.js';
import { getAllRules } from '../rules/index.js';

// SARIF v2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

function buildRules() {
  return getAllRules().map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.description },
    defaultConfiguration: {
      level: SEVERITY_TO_SARIF_LEVEL[rule.severity],
    },
    properties: {
      severity: rule.severity,
    },
  }));
}

function buildResult(finding: Finding) {
  const result: Record<string, unknown> = {
    ruleId: finding.ruleId,
    level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
    message: {
      text: finding.description,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.filePath,
            uriBaseId: '%SRCROOT%',
          },
          ...(finding.line
            ? {
                region: {
                  startLine: finding.line,
                },
              }
            : {}),
        },
      },
    ],
    properties: {
      severity: finding.severity,
      recommendation: finding.recommendation,
      ...(finding.evidence ? { evidence: finding.evidence } : {}),
    },
  };

  return result;
}

export function formatSarif(result: ScanResult): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-fortify',
            version: '0.3.0',
            informationUri: 'https://github.com/SSMMSS884/mcp-fortify',
            rules: buildRules(),
          },
        },
        results: result.findings.map(buildResult),
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.timestamp,
            properties: {
              duration: `${result.duration.toFixed(0)}ms`,
              scannedFiles: result.scannedFiles.length,
            },
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
