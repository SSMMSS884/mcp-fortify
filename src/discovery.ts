import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import type { ScanTarget } from './types.js';
import { getConfigPaths } from './utils/platform.js';

const MAX_FILE_SIZE = 1_048_576; // 1MB

function safeReadFile(filePath: string): string | undefined {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) return undefined;
    return readFileSync(filePath, 'utf-8');
  } catch {
    return undefined;
  }
}

export function discoverTargets(customPath?: string): ScanTarget[] {
  const targets: ScanTarget[] = [];
  const paths = getConfigPaths();

  // 1. Claude Code settings.json
  if (existsSync(paths.claudeSettings)) {
    targets.push({
      path: paths.claudeSettings,
      type: 'claude-settings',
      content: safeReadFile(paths.claudeSettings),
    });
  }

  // 2. Claude Desktop config
  if (existsSync(paths.claudeDesktopConfig)) {
    targets.push({
      path: paths.claudeDesktopConfig,
      type: 'claude-desktop',
      content: safeReadFile(paths.claudeDesktopConfig),
    });
  }

  // 3. MCP server directories (~/.claude/mcp-servers/*)
  if (existsSync(paths.claudeMcpServers)) {
    try {
      const servers = readdirSync(paths.claudeMcpServers);
      for (const server of servers) {
        const serverDir = join(paths.claudeMcpServers, server);
        try {
          if (!statSync(serverDir).isDirectory()) continue;
        } catch {
          continue;
        }

        // Check common files in each server dir
        const serverFiles = ['config.json', '.env', 'run.sh', 'server.py', 'index.js', 'index.ts'];
        for (const file of serverFiles) {
          const filePath = join(serverDir, file);
          if (existsSync(filePath)) {
            const type = file === '.env'
              ? 'env-file' as const
              : file.endsWith('.sh')
                ? 'launch-script' as const
                : 'mcp-server-config' as const;

            targets.push({
              path: filePath,
              type,
              content: safeReadFile(filePath),
            });
          }
        }
      }
    } catch {
      // can't read mcp-servers dir
    }
  }

  // 4. Project-level .mcp.json in CWD or custom path
  const searchDir = customPath || process.cwd();
  const mcpJsonPath = join(searchDir, '.mcp.json');
  if (existsSync(mcpJsonPath)) {
    targets.push({
      path: mcpJsonPath,
      type: 'project-config',
      content: safeReadFile(mcpJsonPath),
    });
  }

  // 5. Also check for claude_desktop_config.json in custom path
  if (customPath) {
    const customConfig = join(customPath, 'claude_desktop_config.json');
    if (existsSync(customConfig)) {
      targets.push({
        path: customConfig,
        type: 'claude-desktop',
        content: safeReadFile(customConfig),
      });
    }
  }

  return targets;
}
