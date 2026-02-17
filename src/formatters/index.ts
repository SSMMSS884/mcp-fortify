import type { ScanResult } from '../types.js';
import { formatConsole } from './console.js';
import { formatJson } from './json.js';

export function format(
  result: ScanResult,
  type: 'console' | 'json',
  verbose: boolean = false,
): string {
  switch (type) {
    case 'json':
      return formatJson(result);
    case 'console':
    default:
      return formatConsole(result, verbose);
  }
}
