import { statSync } from 'fs';
import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';
import { getPlatform } from '../utils/platform.js';

export class FilePermissionsRule extends BaseRule {
  id = 'file-permissions';
  name = 'Insecure File Permissions';
  severity = 'high' as const;
  description = 'Detects MCP config and credential files with overly permissive file permissions';

  run(targets: ScanTarget[]): Finding[] {
    if (getPlatform() === 'win32') return [];

    const findings: Finding[] = [];

    for (const target of targets) {
      try {
        const stat = statSync(target.path);
        const mode = stat.mode & 0o777;

        const groupRead = (mode & 0o040) !== 0;
        const groupWrite = (mode & 0o020) !== 0;
        const othersRead = (mode & 0o004) !== 0;
        const othersWrite = (mode & 0o002) !== 0;

        const isWorldReadable = othersRead || othersWrite;
        const isGroupAccessible = groupRead || groupWrite;

        if (isWorldReadable || isGroupAccessible) {
          const octal = mode.toString(8).padStart(3, '0');
          const isScript = target.type === 'launch-script' || target.path.endsWith('.sh');
          const expectedPerm = isScript ? '700' : '600';

          // Scripts need execute bit for owner, so 700 is acceptable
          if (isScript && mode === 0o700) continue;

          const severity = isWorldReadable ? 'high' as const : 'medium' as const;

          findings.push(
            this.createFinding({
              severity,
              title: `Insecure permissions (${octal}) on ${isScript ? 'launch script' : 'config file'}`,
              description: `${target.path} has permissions ${octal}. ${isWorldReadable ? 'Other users on this system can read this file.' : 'Group members can access this file.'} ${isScript ? 'Launch scripts' : 'Config files'} should be restricted to owner-only access.`,
              filePath: target.path,
              evidence: `Current: ${octal}, Expected: ${expectedPerm}`,
              recommendation: `Run: chmod ${expectedPerm} "${target.path}"`,
            }),
          );
        }
      } catch {
        // skip inaccessible files
      }
    }

    return findings;
  }
}
