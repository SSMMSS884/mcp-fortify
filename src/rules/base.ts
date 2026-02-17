import type { Finding, Rule, ScanTarget, Severity } from '../types.js';

export abstract class BaseRule implements Rule {
  abstract id: string;
  abstract name: string;
  abstract severity: Severity;
  abstract description: string;

  abstract run(targets: ScanTarget[]): Finding[];

  protected createFinding(
    partial: Omit<Finding, 'ruleId' | 'severity'> & { severity?: Severity },
  ): Finding {
    return {
      ruleId: this.id,
      severity: partial.severity ?? this.severity,
      ...partial,
    };
  }
}
