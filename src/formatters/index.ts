import type { ScanResult } from '../types.js';
import { formatConsole } from './console.js';
import { formatJson } from './json.js';
import { formatSarif } from './sarif.js';
import { formatHtml } from './html.js';

export type FormatType = 'console' | 'json' | 'sarif' | 'html';

export function format(
  result: ScanResult,
  type: FormatType,
  verbose: boolean = false,
): string {
  switch (type) {
    case 'json':
      return formatJson(result);
    case 'sarif':
      return formatSarif(result);
    case 'html':
      return formatHtml(result);
    case 'console':
    default:
      return formatConsole(result, verbose);
  }
}
