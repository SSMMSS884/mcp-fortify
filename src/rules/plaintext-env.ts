import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';
import { CREDENTIAL_ASSIGNMENT_REGEX, isSafePattern, redact } from '../utils/patterns.js';

export class PlaintextEnvRule extends BaseRule {
  id = 'plaintext-env';
  name = 'Plaintext Secrets in Env Blocks';
  severity = 'critical' as const;
  description = 'Detects secrets stored in plaintext within JSON config env blocks';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    for (const target of targets) {
      if (!target.content) continue;
      if (!target.path.endsWith('.json')) continue;

      let parsed: unknown;
      try {
        parsed = JSON.parse(target.content);
      } catch {
        continue;
      }

      this.scanObject(parsed, target.path, '', findings);
    }

    return findings;
  }

  private scanObject(
    obj: unknown,
    filePath: string,
    keyPath: string,
    findings: Finding[],
  ): void {
    if (!obj || typeof obj !== 'object') return;

    const record = obj as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      const currentPath = keyPath ? `${keyPath}.${key}` : key;

      if (
        (key === 'env' || key === 'environment' || key === 'ENV') &&
        typeof value === 'object' &&
        value !== null
      ) {
        this.checkEnvBlock(value as Record<string, unknown>, filePath, currentPath, findings);
        continue;
      }

      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        this.scanObject(value, filePath, currentPath, findings);
      }
    }
  }

  private checkEnvBlock(
    env: Record<string, unknown>,
    filePath: string,
    keyPath: string,
    findings: Finding[],
  ): void {
    for (const [envKey, envValue] of Object.entries(env)) {
      if (typeof envValue !== 'string') continue;

      const line = `${envKey}=${envValue}`;
      if (isSafePattern(line)) continue;
      if (isSafePattern(envValue)) continue;

      const isCredentialKey = /API_KEY|SECRET|TOKEN|PASS|CREDENTIAL|AUTH/i.test(envKey);
      const hasRealValue = envValue.length >= 10 && !/^(YOUR_|REPLACE_|xxx|placeholder|example|changeme)/i.test(envValue);

      if (isCredentialKey && hasRealValue) {
        findings.push(
          this.createFinding({
            title: `Plaintext secret in env block: ${envKey}`,
            description: `The environment variable "${envKey}" at ${keyPath}.${envKey} contains what appears to be a real secret value stored in plaintext JSON.`,
            filePath,
            evidence: `${envKey}=${redact(envValue)}`,
            recommendation:
              'Use dynamic secret references: `$(secrets get KEY_NAME)` for macOS Keychain or `$(gh auth token)` for GitHub tokens.',
          }),
        );
        continue;
      }

      const match = line.match(CREDENTIAL_ASSIGNMENT_REGEX);
      if (match && !isSafePattern(line)) {
        findings.push(
          this.createFinding({
            title: `Possible credential in env block: ${envKey}`,
            description: `The environment variable "${envKey}" at ${keyPath}.${envKey} matches a credential pattern.`,
            filePath,
            evidence: `${envKey}=${redact(envValue)}`,
            recommendation:
              'Use dynamic secret references instead of plaintext values in config files.',
          }),
        );
      }
    }
  }
}
