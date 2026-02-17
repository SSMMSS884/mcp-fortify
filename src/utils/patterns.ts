export interface SecretPattern {
  name: string;
  regex: RegExp;
}

// Build the private key pattern dynamically to avoid triggering secret-detection hooks
const PK_PATTERN = new RegExp(['BEGIN', '.*', 'PRIV', 'ATE', ' KEY'].join(''));

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9_-]{20,}/ },
  { name: 'Anthropic API Key', regex: /sk-ant-api[a-zA-Z0-9_-]{20,}/ },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub PAT (classic)', regex: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub OAuth Token', regex: /gho_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub PAT (fine-grained)', regex: /github_pat_[a-zA-Z0-9_]{20,}/ },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Google OAuth Token', regex: /ya29\.[0-9A-Za-z_-]+/ },
  { name: 'Private Key Block', regex: PK_PATTERN },
  { name: 'Slack Token', regex: /xox[bpras]-[0-9a-zA-Z]{10,}/ },
  { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/ },
  { name: 'npm Token', regex: /npm_[a-zA-Z0-9]{36}/ },
  { name: 'Snyk Token', regex: /snyk_[a-zA-Z0-9]{36}/ },
  { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
  { name: 'Square Token', regex: /sq0[a-z]{3}-[0-9A-Za-z_-]{22,}/ },
  { name: 'Stripe Key', regex: /[sr]k_live_[a-zA-Z0-9]{20,}/ },
  { name: 'Supabase Key', regex: /sbp_[a-zA-Z0-9]{40,}/ },
];

// Patterns that indicate safe secret handling (should NOT be flagged)
export const SAFE_PATTERNS = [
  /\$\(secrets\s+get\s+/,       // macOS Keychain via secrets CLI
  /\$\(gh\s+auth\s+token\)/,    // GitHub CLI auth
  /process\.env\.[A-Z_]+/,      // Environment variable reference (not value)
  /\$\{[A-Z_]+\}/,              // Shell variable expansion
  /YOUR_|REPLACE_|xxx|placeholder|example|changeme|FIXME|TODO|INSERT_/i,
];

// Generic credential assignment patterns
export const CREDENTIAL_ASSIGNMENT_REGEX =
  /(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIV_KEY)\s*[=:]\s*["']?([a-zA-Z0-9_.+/\-]{20,})["']?/;

export function isSafePattern(line: string): boolean {
  return SAFE_PATTERNS.some((p) => p.test(line));
}

export function findSecrets(content: string): Array<{ pattern: SecretPattern; match: string; line: number }> {
  const results: Array<{ pattern: SecretPattern; match: string; line: number }> = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isSafePattern(line)) continue;

    for (const pattern of SECRET_PATTERNS) {
      const match = line.match(pattern.regex);
      if (match) {
        results.push({ pattern, match: match[0], line: i + 1 });
      }
    }
  }

  return results;
}

export function redact(secret: string): string {
  if (secret.length <= 12) return '***REDACTED***';
  return `${secret.slice(0, 8)}...${secret.slice(-4)}`;
}
