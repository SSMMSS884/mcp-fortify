import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';

const DANGEROUS_TOOLS = [
  'Bash',
  'Write',
  'Edit',
  'NotebookEdit',
];

export class ToolPermissionsRule extends BaseRule {
  id = 'tool-permissions';
  name = 'Overly Permissive Tool Access';
  severity = 'medium' as const;
  description = 'Checks if Claude Code settings grant broad tool permissions without restrictions';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    const settingsTargets = targets.filter(
      (t) => t.type === 'claude-settings' && t.content,
    );

    for (const target of settingsTargets) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(target.content!);
      } catch {
        continue;
      }

      const settings = parsed as Record<string, unknown>;

      // Check for dangerously-skip-permissions equivalent in allowedTools
      const allowed = settings.allowedTools as string[] | undefined;
      if (Array.isArray(allowed)) {
        // Check for wildcard or overly broad patterns
        for (const tool of allowed) {
          if (tool === '*' || tool === 'all') {
            findings.push(
              this.createFinding({
                severity: 'high',
                title: 'Wildcard tool permissions granted',
                description: `All tools are allowed via "${tool}" in settings. This bypasses all safety checks and allows unrestricted file system and command access.`,
                filePath: target.path,
                recommendation: 'Remove wildcard permissions and explicitly list only the tools you need.',
              }),
            );
          }
        }

        // Check for broad Bash permissions without path restrictions
        const hasBashWildcard = allowed.some(
          (t) => t === 'Bash' || t === 'Bash(*)',
        );
        if (hasBashWildcard) {
          findings.push(
            this.createFinding({
              severity: 'low',
              title: 'Unrestricted Bash access allowed',
              description: `Bash tool access is granted without command restrictions. Consider using pattern-based restrictions to limit which commands can be executed.`,
              filePath: target.path,
              evidence: 'Bash or Bash(*) in allowedTools',
              recommendation: 'Use specific Bash patterns like "Bash(npm test)" or "Bash(git *)" to restrict allowed commands.',
            }),
          );
        }
      }

      // Check permissions.allow for overly broad patterns
      const permissions = settings.permissions as Record<string, unknown> | undefined;
      if (permissions && typeof permissions === 'object') {
        const allow = permissions.allow as string[] | undefined;
        if (Array.isArray(allow)) {
          for (const pattern of allow) {
            if (pattern === '*' || pattern === '**') {
              findings.push(
                this.createFinding({
                  severity: 'high',
                  title: 'Wildcard permission pattern',
                  description: `Permission pattern "${pattern}" grants unrestricted access. All operations will be auto-approved without user confirmation.`,
                  filePath: target.path,
                  recommendation: 'Use specific permission patterns instead of wildcards.',
                }),
              );
            }
          }
        }
      }
    }

    return findings;
  }
}
