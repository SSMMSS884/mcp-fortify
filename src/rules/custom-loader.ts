import { existsSync } from 'fs';
import { resolve } from 'path';
import type { Rule } from '../types.js';

export async function loadCustomRules(rulesPath: string): Promise<Rule[]> {
  const resolved = resolve(rulesPath);

  if (!existsSync(resolved)) {
    console.error(`Custom rules path not found: ${resolved}`);
    return [];
  }

  try {
    const mod = await import(resolved);

    // Support both default export (array) and named export (rules)
    const rules: Rule[] = [];

    if (Array.isArray(mod.default)) {
      rules.push(...mod.default);
    } else if (Array.isArray(mod.rules)) {
      rules.push(...mod.rules);
    } else if (typeof mod.default === 'object' && mod.default !== null) {
      // Single rule as default export
      if ('id' in mod.default && 'run' in mod.default) {
        rules.push(mod.default);
      }
    }

    // Validate each rule has required fields
    const valid = rules.filter((r) => {
      if (!r.id || !r.name || !r.severity || typeof r.run !== 'function') {
        console.error(`Skipping invalid custom rule: missing required fields (id, name, severity, run)`);
        return false;
      }
      return true;
    });

    return valid;
  } catch (e) {
    console.error(`Failed to load custom rules from ${resolved}: ${e instanceof Error ? e.message : e}`);
    return [];
  }
}
