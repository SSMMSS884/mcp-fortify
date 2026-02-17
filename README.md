# mcp-fortify

Security scanner for MCP (Model Context Protocol) configurations. Scans your local MCP setup for hardcoded secrets, insecure file permissions, plaintext credentials, and missing security hooks — fully offline, no API keys needed.

## Why

43% of MCP implementations have command injection vulnerabilities ([Equixly research](https://www.equixly.com)). While tools like `mcp-scan` analyze MCP server source code, **no good static scanner exists** for checking whether YOUR local MCP installation is configured securely.

`mcp-fortify` answers: **"Is MY MCP setup secure?"**

## Quick Start

```bash
npx mcp-fortify
```

Or install globally:

```bash
npm install -g mcp-fortify
mcp-fortify
```

## What It Scans

Auto-discovers and scans these files on your machine:

| File | Location |
|------|----------|
| Claude Code settings | `~/.claude/settings.json` |
| Claude Desktop config | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| MCP server configs | `~/.claude/mcp-servers/*/` (run.sh, .env, server.py, etc.) |
| Project config | `.mcp.json` in current directory |

## Security Rules

| Rule | Severity | What It Detects |
|------|----------|-----------------|
| `hardcoded-secrets` | CRITICAL | API keys, tokens, passwords in any scanned file |
| `plaintext-env` | CRITICAL | Secrets in JSON config `env` blocks |
| `file-permissions` | HIGH | Config/credential files not restricted to owner-only |
| `missing-hooks` | MEDIUM | No PreToolUse hooks for secret blocking in Claude Code |

## CLI Options

```
mcp-fortify [scan] [path] [options]

Options:
  -f, --format <type>     Output format: console | json (default: console)
  -s, --severity <level>  Minimum severity to show (critical|high|medium|low|info)
  --rules <ids>           Comma-separated rule IDs to run
  --no-color              Disable colors
  --verbose               Show all scanned files
  --ci                    Exit code 1 if high+ severity findings
  -V, --version           Show version
  -h, --help              Show help
```

## Examples

```bash
# Scan with default settings
mcp-fortify

# JSON output for CI pipelines
mcp-fortify --format json

# Only critical findings, fail CI if found
mcp-fortify --severity critical --ci

# Scan specific directory
mcp-fortify scan /path/to/project

# Run only specific rules
mcp-fortify --rules hardcoded-secrets,plaintext-env
```

## Safe Patterns (Not Flagged)

mcp-fortify recognizes secure patterns and won't flag them:

- `$(secrets get KEY_NAME)` — macOS Keychain references
- `$(gh auth token)` — GitHub CLI auth
- `${ENV_VAR}` — Shell variable expansion
- `process.env.KEY` — Node.js env references
- Placeholder values (`YOUR_KEY_HERE`, `changeme`, etc.)

## Programmatic API

```typescript
import { scan, format } from 'mcp-fortify';

const result = scan({ format: 'json' });
console.log(result.findings);
```

## License

MIT
