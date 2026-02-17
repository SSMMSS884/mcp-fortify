# mcp-fortify

Security scanner for MCP (Model Context Protocol) configurations. Scans your local MCP setup for hardcoded secrets, insecure permissions, command injection risks, and missing security hooks — fully offline, no API keys needed.

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

## Security Rules (8 rules)

| Rule | Severity | What It Detects |
|------|----------|-----------------|
| `hardcoded-secrets` | CRITICAL | API keys, tokens, passwords in any scanned file |
| `plaintext-env` | CRITICAL | Secrets in JSON config `env` blocks |
| `command-injection` | CRITICAL | Shell injection vectors in launch scripts and configs |
| `file-permissions` | HIGH | Config/credential files not restricted to owner-only |
| `transport-security` | HIGH | HTTP (not HTTPS) endpoints, 0.0.0.0 bindings |
| `missing-hooks` | MEDIUM | No PreToolUse hooks for secret blocking in Claude Code |
| `tool-permissions` | MEDIUM | Wildcard tool permissions bypassing safety checks |
| `missing-gitignore` | MEDIUM | .env files not covered by .gitignore |

## Commands

### `mcp-fortify scan` (default)

Scan MCP configurations for security issues.

```bash
mcp-fortify                              # Scan with defaults
mcp-fortify --format json                # JSON output for CI
mcp-fortify --severity critical --ci     # Fail CI on critical findings
mcp-fortify --rules hardcoded-secrets    # Run specific rules only
mcp-fortify --verbose                    # Show all scanned files
mcp-fortify scan /path/to/project        # Scan custom path
```

### `mcp-fortify init`

Generate security hooks for Claude Code. Creates a PreToolUse hook that blocks file writes containing secrets.

```bash
mcp-fortify init
```

### `mcp-fortify fix`

Auto-remediate fixable issues (file permissions).

```bash
mcp-fortify fix             # Fix issues
mcp-fortify fix --dry-run   # Preview what would be fixed
```

## CLI Options

```
mcp-fortify [command] [options]

Commands:
  scan [path]     Scan MCP configurations (default)
  init            Generate security hooks for Claude Code
  fix             Auto-fix remediable security issues

Scan Options:
  -f, --format <type>     Output format: console | json (default: console)
  -s, --severity <level>  Minimum severity to show (critical|high|medium|low|info)
  --rules <ids>           Comma-separated rule IDs to run
  --no-color              Disable colors
  --verbose               Show all scanned files
  --ci                    Exit code 1 if high+ severity findings

Fix Options:
  --dry-run               Show what would be fixed without making changes
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
