import { existsSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';

const SENSITIVE_PATTERNS = ['.env', 'credentials', 'secrets', 'token', '*.key', '*.pem'];

export class MissingGitignoreRule extends BaseRule {
  id = 'missing-gitignore';
  name = 'Missing .gitignore Protection';
  severity = 'medium' as const;
  description = 'Checks if MCP server directories with sensitive files have proper .gitignore coverage';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    // Group targets by directory
    const dirMap = new Map<string, ScanTarget[]>();
    for (const target of targets) {
      const dir = dirname(target.path);
      if (!dirMap.has(dir)) dirMap.set(dir, []);
      dirMap.get(dir)!.push(target);
    }

    for (const [dir, dirTargets] of dirMap) {
      // Check if this directory has sensitive files
      const hasSensitiveFiles = dirTargets.some(
        (t) => t.type === 'env-file' || t.path.endsWith('.env'),
      );

      if (!hasSensitiveFiles) continue;

      // Look for .gitignore in this dir or parent dirs (up to 3 levels)
      let gitignoreContent: string | null = null;
      let gitignorePath: string | null = null;
      let searchDir = dir;

      for (let i = 0; i < 4; i++) {
        const candidate = join(searchDir, '.gitignore');
        if (existsSync(candidate)) {
          try {
            gitignoreContent = readFileSync(candidate, 'utf-8');
            gitignorePath = candidate;
          } catch {
            // can't read
          }
          break;
        }
        const parent = dirname(searchDir);
        if (parent === searchDir) break;
        searchDir = parent;
      }

      if (!gitignoreContent) {
        findings.push(
          this.createFinding({
            title: 'No .gitignore protecting sensitive files',
            description: `Directory ${dir} contains sensitive files (.env) but no .gitignore was found in the directory tree. If this directory is ever version-controlled, secrets could be committed.`,
            filePath: dir,
            recommendation: `Create a .gitignore in ${dir} with at least: .env, *.key, *.pem`,
          }),
        );
        continue;
      }

      // Check if .env is covered
      const lines = gitignoreContent.split('\n').map((l) => l.trim());
      const coversEnv = lines.some(
        (l) => l === '.env' || l === '.env*' || l === '*.env' || l === '.env.*',
      );

      if (!coversEnv) {
        findings.push(
          this.createFinding({
            severity: 'low',
            title: '.gitignore does not cover .env files',
            description: `A .gitignore exists at ${gitignorePath} but does not include .env patterns. The .env file in ${dir} could be accidentally committed.`,
            filePath: gitignorePath!,
            recommendation: 'Add ".env" and ".env*" to your .gitignore file.',
          }),
        );
      }
    }

    return findings;
  }
}
