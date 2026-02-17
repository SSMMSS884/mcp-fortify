import { Command } from 'commander';
import { scan, getExitCode } from './scanner.js';
import { format } from './formatters/index.js';
import type { ScanOptions, Severity } from './types.js';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function createCli(): Command {
  const program = new Command();

  program
    .name('mcp-fortify')
    .description('Security scanner for MCP (Model Context Protocol) configurations')
    .version('0.1.0');

  program
    .command('scan', { isDefault: true })
    .description('Scan MCP configurations for security issues')
    .argument('[path]', 'Custom path to scan')
    .option('-f, --format <type>', 'Output format: console or json', 'console')
    .option('-s, --severity <level>', 'Minimum severity to show')
    .option('--rules <ids>', 'Comma-separated rule IDs to run')
    .option('--no-color', 'Disable colors')
    .option('--verbose', 'Show all scanned files', false)
    .option('--ci', 'Exit with code 1 if high+ findings', false)
    .action((path, opts) => {
      if (opts.severity && !VALID_SEVERITIES.includes(opts.severity)) {
        console.error(`Invalid severity: ${opts.severity}. Must be one of: ${VALID_SEVERITIES.join(', ')}`);
        process.exit(2);
      }

      const options: ScanOptions = {
        format: opts.format as 'console' | 'json',
        severity: opts.severity as Severity | undefined,
        rules: opts.rules ? opts.rules.split(',') : undefined,
        verbose: opts.verbose,
        ci: opts.ci,
        path,
      };

      const result = scan(options);
      const output = format(result, options.format, options.verbose);

      console.log(output);

      const exitCode = getExitCode(result, options.ci);
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  return program;
}

export function run(): void {
  const program = createCli();
  program.parse();
}
