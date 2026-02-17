import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';

export class MissingHooksRule extends BaseRule {
  id = 'missing-hooks';
  name = 'Missing Security Hooks';
  severity = 'medium' as const;
  description = 'Checks if Claude Code settings include PreToolUse hooks for secret blocking';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    const settingsTargets = targets.filter(
      (t) => t.type === 'claude-settings' && t.content,
    );

    if (settingsTargets.length === 0) return [];

    for (const target of settingsTargets) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(target.content!);
      } catch {
        continue;
      }

      const settings = parsed as Record<string, unknown>;
      const hooks = settings.hooks as Record<string, unknown[]> | undefined;

      if (!hooks || typeof hooks !== 'object') {
        findings.push(
          this.createFinding({
            title: 'No security hooks configured',
            description:
              'Claude Code settings.json has no hooks defined. Without PreToolUse hooks, there is no automated guardrail to prevent secrets from being written to files or executed in commands.',
            filePath: target.path,
            recommendation:
              'Add a PreToolUse hook that blocks file writes containing secrets. See: https://docs.anthropic.com/en/docs/claude-code/hooks',
          }),
        );
        continue;
      }

      const preToolUse = hooks.PreToolUse;
      if (!preToolUse || !Array.isArray(preToolUse) || preToolUse.length === 0) {
        findings.push(
          this.createFinding({
            title: 'No PreToolUse hooks configured',
            description:
              'Hooks are defined but no PreToolUse hooks exist. PreToolUse hooks run before tool execution and can block dangerous operations like writing secrets to files.',
            filePath: target.path,
            recommendation:
              'Add a PreToolUse hook that scans for secret patterns before file writes. Example: a shell script that greps for API key patterns in tool input.',
          }),
        );
        continue;
      }

      // Heuristic: check if any hook mentions secret/credential blocking
      // Claude Code hooks have two formats:
      // 1. Flat: { command: "..." }
      // 2. Nested: { matcher: "Write|Edit", hooks: [{ command: "..." }] }
      const hasSecretBlocker = preToolUse.some((hookGroup: unknown) => {
        if (typeof hookGroup !== 'object' || hookGroup === null) return false;
        const group = hookGroup as Record<string, unknown>;

        // Collect all command strings from both formats
        const commands: string[] = [];
        if (typeof group.command === 'string') {
          commands.push(group.command);
        }
        if (Array.isArray(group.hooks)) {
          for (const h of group.hooks) {
            if (typeof h === 'object' && h !== null && typeof (h as Record<string, unknown>).command === 'string') {
              commands.push((h as Record<string, unknown>).command as string);
            }
          }
        }

        return commands.some((cmd) => /secret|credential|key|token|block/i.test(cmd));
      });

      if (!hasSecretBlocker) {
        findings.push(
          this.createFinding({
            severity: 'low',
            title: 'PreToolUse hooks may not block secrets',
            description:
              'PreToolUse hooks exist but none appear to check for secret/credential patterns. This is a heuristic check — if your hooks do block secrets with a non-obvious command name, this may be a false positive.',
            filePath: target.path,
            recommendation:
              'Ensure at least one PreToolUse hook scans for API key and credential patterns in file write operations.',
          }),
        );
      }
    }

    return findings;
  }
}
