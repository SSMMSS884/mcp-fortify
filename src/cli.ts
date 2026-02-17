import { writeFileSync } from 'fs';
import { Command } from 'commander';
import { scan, getExitCode } from './scanner.js';
import { format } from './formatters/index.js';
import type { FormatType } from './formatters/index.js';
import { runInit } from './commands/init.js';
import { runFix } from './commands/fix.js';
import type { ScanOptions, Severity } from './types.js';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_FORMATS = ['console', 'json', 'sarif', 'html'];

export function createCli(): Command {
  const program = new Command();

  program
    .name('mcp-fortify')
    .description('Security scanner for MCP (Model Context Protocol) configurations')
    .version('0.3.0');

  program
    .command('scan', { isDefault: true })
    .description('Scan MCP configurations for security issues')
    .argument('[path]', 'Custom path to scan')
    .option('-f, --format <type>', 'Output format: console, json, sarif, or html', 'console')
    .option('-o, --output <file>', 'Write output to file instead of stdout')
    .option('-s, --severity <level>', 'Minimum severity to show')
    .option('--rules <ids>', 'Comma-separated rule IDs to run')
    .option('--custom-rules <path>', 'Path to custom rules module (.js)')
    .option('--no-color', 'Disable colors')
    .option('--verbose', 'Show all scanned files', false)
    .option('--ci', 'Exit with code 1 if high+ findings', false)
    .action(async (path, opts) => {
      if (opts.severity && !VALID_SEVERITIES.includes(opts.severity)) {
        console.error(`Invalid severity: ${opts.severity}. Must be one of: ${VALID_SEVERITIES.join(', ')}`);
        process.exit(2);
      }

      if (opts.format && !VALID_FORMATS.includes(opts.format)) {
        console.error(`Invalid format: ${opts.format}. Must be one of: ${VALID_FORMATS.join(', ')}`);
        process.exit(2);
      }

      const options: ScanOptions = {
        format: opts.format as FormatType,
        severity: opts.severity as Severity | undefined,
        rules: opts.rules ? opts.rules.split(',') : undefined,
        customRules: opts.customRules,
        verbose: opts.verbose,
        ci: opts.ci,
        path,
        output: opts.output,
      };

      const result = await scan(options);
      const output = format(result, options.format, options.verbose);

      if (options.output) {
        writeFileSync(options.output, output);
        console.log(`Report written to ${options.output}`);
      } else {
        console.log(output);
      }

      const exitCode = getExitCode(result, options.ci);
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  program
    .command('init')
    .description('Generate security hooks for Claude Code (PreToolUse secret blocking)')
    .action(() => {
      runInit();
    });

  program
    .command('fix')
    .description('Auto-fix remediable security issues (file permissions)')
    .option('--dry-run', 'Show what would be fixed without making changes', false)
    .action(async (opts) => {
      const result = await scan({ format: 'console' });
      runFix(result, opts.dryRun);
    });

  return program;
}

export function run(): void {
  const program = createCli();
  program.parse();
}
