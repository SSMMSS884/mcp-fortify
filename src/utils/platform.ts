import { homedir, platform } from 'os';
import { join } from 'path';

export type Platform = 'darwin' | 'win32' | 'linux';

export function getPlatform(): Platform {
  const p = platform();
  if (p === 'darwin' || p === 'win32' || p === 'linux') return p;
  return 'linux'; // default fallback
}

export interface ConfigPaths {
  claudeSettings: string;
  claudeDesktopConfig: string;
  claudeMcpServers: string;
  claudeHooksDir: string;
}

export function getConfigPaths(): ConfigPaths {
  const home = homedir();
  const p = getPlatform();

  let claudeDesktopConfig: string;
  switch (p) {
    case 'darwin':
      claudeDesktopConfig = join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
      break;
    case 'win32':
      claudeDesktopConfig = join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
      break;
    default:
      claudeDesktopConfig = join(home, '.config', 'Claude', 'claude_desktop_config.json');
  }

  return {
    claudeSettings: join(home, '.claude', 'settings.json'),
    claudeDesktopConfig,
    claudeMcpServers: join(home, '.claude', 'mcp-servers'),
    claudeHooksDir: join(home, '.claude', 'hooks'),
  };
}
