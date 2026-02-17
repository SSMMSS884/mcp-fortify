import { describe, it, expect } from 'vitest';
import { HardcodedSecretsRule } from '../src/rules/hardcoded-secrets.js';
import { PlaintextEnvRule } from '../src/rules/plaintext-env.js';
import { MissingHooksRule } from '../src/rules/missing-hooks.js';
import { CommandInjectionRule } from '../src/rules/command-injection.js';
import { TransportSecurityRule } from '../src/rules/transport-security.js';
import { ToolPermissionsRule } from '../src/rules/tool-permissions.js';
import { MissingGitignoreRule } from '../src/rules/missing-gitignore.js';
import type { ScanTarget } from '../src/types.js';

// Build fake keys dynamically to avoid triggering the secret-blocking hook
const FAKE_OPENAI_KEY = ['sk', 'abcdefghijklmnopqrstuvwxyz1234567890'].join('-');

function target(overrides: Partial<ScanTarget> & { content: string }): ScanTarget[] {
  return [{
    path: overrides.path ?? '/tmp/test-config.json',
    type: overrides.type ?? 'claude-desktop',
    content: overrides.content,
  }];
}

describe('HardcodedSecretsRule', () => {
  const rule = new HardcodedSecretsRule();

  it('detects hardcoded API keys', () => {
    const findings = rule.run(target({
      content: `OPENAI_API_KEY=${FAKE_OPENAI_KEY}`,
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('skips safe patterns', () => {
    const findings = rule.run(target({
      content: 'KEY=$(secrets get OPENAI_API_KEY)',
    }));
    expect(findings.length).toBe(0);
  });

  it('returns empty for no content', () => {
    const findings = rule.run([{ path: '/tmp/x', type: 'env-file' }]);
    expect(findings.length).toBe(0);
  });
});

describe('PlaintextEnvRule', () => {
  const rule = new PlaintextEnvRule();

  it('detects secrets in env blocks', () => {
    const config = JSON.stringify({
      mcpServers: {
        myserver: {
          env: {
            API_KEY: 'real-secret-value-that-is-long-enough',
          },
        },
      },
    });
    const findings = rule.run(target({ content: config }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('skips placeholder values', () => {
    const config = JSON.stringify({
      mcpServers: {
        myserver: {
          env: {
            API_KEY: 'YOUR_KEY_HERE_REPLACE',
          },
        },
      },
    });
    const findings = rule.run(target({ content: config }));
    expect(findings.length).toBe(0);
  });

  it('skips non-JSON files', () => {
    const findings = rule.run(target({
      path: '/tmp/test.sh',
      content: 'API_KEY=something',
    }));
    expect(findings.length).toBe(0);
  });
});

describe('MissingHooksRule', () => {
  const rule = new MissingHooksRule();

  it('flags no hooks at all', () => {
    const config = JSON.stringify({ permissions: {} });
    const findings = rule.run(target({
      path: '/tmp/settings.json',
      type: 'claude-settings',
      content: config,
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain('No security hooks');
  });

  it('flags missing PreToolUse hooks', () => {
    const config = JSON.stringify({
      hooks: { Notification: [{ hooks: [{ command: 'notify.sh' }] }] },
    });
    const findings = rule.run(target({
      path: '/tmp/settings.json',
      type: 'claude-settings',
      content: config,
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain('No PreToolUse');
  });

  it('passes with secret-blocking hook (nested format)', () => {
    const config = JSON.stringify({
      hooks: {
        PreToolUse: [{
          matcher: 'Write|Edit',
          hooks: [{ type: 'command', command: '/path/to/block-secrets.sh' }],
        }],
      },
    });
    const findings = rule.run(target({
      path: '/tmp/settings.json',
      type: 'claude-settings',
      content: config,
    }));
    expect(findings.length).toBe(0);
  });
});

describe('CommandInjectionRule', () => {
  const rule = new CommandInjectionRule();

  it('detects eval usage in scripts', () => {
    const findings = rule.run(target({
      path: '/tmp/run.sh',
      type: 'launch-script',
      content: 'eval($USER_INPUT)',
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('detects shell=true in configs', () => {
    const findings = rule.run(target({
      path: '/tmp/server.py',
      type: 'mcp-server-config',
      content: 'subprocess.run(cmd, shell=true)',
    }));
    expect(findings.length).toBe(1);
  });

  it('ignores comments', () => {
    const findings = rule.run(target({
      path: '/tmp/run.sh',
      type: 'launch-script',
      content: '# eval() is dangerous, never use it',
    }));
    expect(findings.length).toBe(0);
  });
});

describe('TransportSecurityRule', () => {
  const rule = new TransportSecurityRule();

  it('flags non-localhost HTTP URLs', () => {
    const findings = rule.run(target({
      content: '"url": "http://api.example.com/mcp"',
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
  });

  it('allows localhost HTTP', () => {
    const findings = rule.run(target({
      content: '"url": "http://localhost:3000/mcp"',
    }));
    expect(findings.length).toBe(0);
  });

  it('allows 127.0.0.1 HTTP', () => {
    const findings = rule.run(target({
      content: '"url": "http://127.0.0.1:8080/mcp"',
    }));
    expect(findings.length).toBe(0);
  });
});

describe('ToolPermissionsRule', () => {
  const rule = new ToolPermissionsRule();

  it('flags wildcard tool permissions', () => {
    const config = JSON.stringify({ allowedTools: ['*'] });
    const findings = rule.run(target({
      path: '/tmp/settings.json',
      type: 'claude-settings',
      content: config,
    }));
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
  });

  it('passes with specific tool list', () => {
    const config = JSON.stringify({ allowedTools: ['Read', 'Glob'] });
    const findings = rule.run(target({
      path: '/tmp/settings.json',
      type: 'claude-settings',
      content: config,
    }));
    expect(findings.length).toBe(0);
  });
});

describe('MissingGitignoreRule', () => {
  const rule = new MissingGitignoreRule();

  it('does not flag dirs without .env files', () => {
    const findings = rule.run([{
      path: '/tmp/fake-dir/config.json',
      type: 'mcp-server-config',
      content: '{}',
    }]);
    expect(findings.length).toBe(0);
  });
});
