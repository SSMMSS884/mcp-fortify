import type { Rule } from '../types.js';
import { HardcodedSecretsRule } from './hardcoded-secrets.js';
import { PlaintextEnvRule } from './plaintext-env.js';
import { FilePermissionsRule } from './file-permissions.js';
import { MissingHooksRule } from './missing-hooks.js';
import { CommandInjectionRule } from './command-injection.js';
import { TransportSecurityRule } from './transport-security.js';
import { ToolPermissionsRule } from './tool-permissions.js';
import { MissingGitignoreRule } from './missing-gitignore.js';

export function getAllRules(): Rule[] {
  return [
    new HardcodedSecretsRule(),
    new PlaintextEnvRule(),
    new FilePermissionsRule(),
    new MissingHooksRule(),
    new CommandInjectionRule(),
    new TransportSecurityRule(),
    new ToolPermissionsRule(),
    new MissingGitignoreRule(),
  ];
}

export function getRulesByIds(ids: string[]): Rule[] {
  const all = getAllRules();
  return all.filter((r) => ids.includes(r.id));
}
