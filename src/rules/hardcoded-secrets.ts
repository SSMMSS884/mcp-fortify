import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';
import { findSecrets, redact } from '../utils/patterns.js';

export class HardcodedSecretsRule extends BaseRule {
  id = 'hardcoded-secrets';
  name = 'Hardcoded Secrets';
  severity = 'critical' as const;
  description = 'Detects API keys, tokens, and passwords hardcoded in configuration files';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    for (const target of targets) {
      if (!target.content) continue;

      const secrets = findSecrets(target.content);
      for (const { pattern, match, line } of secrets) {
        findings.push(
          this.createFinding({
            title: `${pattern.name} found in config file`,
            description: `A ${pattern.name} was found hardcoded in ${target.path}. Hardcoded secrets can be leaked through version control, backups, or unauthorized file access.`,
            filePath: target.path,
            line,
            evidence: redact(match),
            recommendation:
              'Move this secret to macOS Keychain (`secrets store KEY "value"`) or use environment variable references instead of hardcoding values.',
          }),
        );
      }
    }

    return findings;
  }
}
