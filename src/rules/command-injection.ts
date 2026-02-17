import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';

// Patterns that indicate unsanitized shell execution
const DANGEROUS_PATTERNS = [
  { regex: /\$\{?\w*\}?\s*[|;&]/, name: 'Variable piped to shell command' },
  { regex: /`[^`]*\$\{?\w+\}?[^`]*`/, name: 'Variable interpolation in backtick execution' },
  { regex: /eval\s*\(/, name: 'eval() usage' },
  { regex: /child_process|execSync|exec\(|spawn\(/, name: 'Direct child process execution' },
  { regex: /os\.system\s*\(/, name: 'Python os.system()' },
  { regex: /subprocess\.(call|run|Popen)\s*\(\s*(f"|f'|[^[])/, name: 'Python subprocess with string (not list)' },
  { regex: /shell\s*[:=]\s*true/, name: 'Shell mode enabled' },
];

// Patterns in JSON configs that pass unsanitized args
const CONFIG_INJECTION_PATTERNS = [
  { regex: /"\$\{[^}]+\}"/, name: 'Unquoted variable expansion in config' },
  { regex: /;\s*(rm|curl|wget|chmod|chown)\b/, name: 'Chained dangerous command in config' },
];

export class CommandInjectionRule extends BaseRule {
  id = 'command-injection';
  name = 'Command Injection Risk';
  severity = 'critical' as const;
  description = 'Detects potential command injection vectors in MCP server configs and launch scripts';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    for (const target of targets) {
      if (!target.content) continue;

      const lines = target.content.split('\n');
      const patterns = target.type === 'launch-script' || target.path.endsWith('.py')
        ? DANGEROUS_PATTERNS
        : CONFIG_INJECTION_PATTERNS;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) continue;

        for (const pattern of patterns) {
          if (pattern.regex.test(line)) {
            findings.push(
              this.createFinding({
                title: `Potential command injection: ${pattern.name}`,
                description: `${pattern.name} detected in ${target.path}. This pattern can allow an attacker to inject arbitrary commands if input is not properly sanitized.`,
                filePath: target.path,
                line: i + 1,
                evidence: line.length > 100 ? line.slice(0, 100) + '...' : line,
                recommendation:
                  'Use parameterized commands (arrays instead of strings), avoid shell=true, and validate/sanitize all input before passing to shell commands.',
              }),
            );
            break; // one finding per line
          }
        }
      }
    }

    return findings;
  }
}
