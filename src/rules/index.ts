import type { Rule } from '../types.js';
import { HardcodedSecretsRule } from './hardcoded-secrets.js';
import { PlaintextEnvRule } from './plaintext-env.js';
import { FilePermissionsRule } from './file-permissions.js';
import { MissingHooksRule } from './missing-hooks.js';

export function getAllRules(): Rule[] {
  return [
    new HardcodedSecretsRule(),
    new PlaintextEnvRule(),
    new FilePermissionsRule(),
    new MissingHooksRule(),
  ];
}

export function getRulesByIds(ids: string[]): Rule[] {
  const all = getAllRules();
  return all.filter((r) => ids.includes(r.id));
}
