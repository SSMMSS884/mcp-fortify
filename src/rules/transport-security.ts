import { BaseRule } from './base.js';
import type { Finding, ScanTarget } from '../types.js';

export class TransportSecurityRule extends BaseRule {
  id = 'transport-security';
  name = 'Insecure Transport';
  severity = 'high' as const;
  description = 'Detects MCP servers configured with insecure transport (HTTP instead of HTTPS, exposed ports)';

  run(targets: ScanTarget[]): Finding[] {
    const findings: Finding[] = [];

    for (const target of targets) {
      if (!target.content) continue;

      const lines = target.content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for HTTP URLs (not HTTPS) in configs
        const httpMatch = line.match(/http:\/\/[^\s"',)]+/);
        if (httpMatch) {
          // Allow localhost/127.0.0.1 HTTP — that's fine
          const url = httpMatch[0];
          if (!/localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]/.test(url)) {
            findings.push(
              this.createFinding({
                title: 'Non-localhost HTTP endpoint in config',
                description: `An HTTP (not HTTPS) URL pointing to a non-localhost address was found. Data sent over HTTP can be intercepted by network attackers.`,
                filePath: target.path,
                line: i + 1,
                evidence: url,
                recommendation: 'Use HTTPS for all non-localhost MCP server connections.',
              }),
            );
          }
        }

        // Check for 0.0.0.0 binding (exposes to network)
        if (/0\.0\.0\.0/.test(line) && /bind|host|listen|address/i.test(line)) {
          findings.push(
            this.createFinding({
              severity: 'medium',
              title: 'MCP server bound to all interfaces (0.0.0.0)',
              description: `Server is configured to listen on 0.0.0.0, which exposes it to all network interfaces. MCP servers should typically only be accessible locally.`,
              filePath: target.path,
              line: i + 1,
              evidence: line.trim(),
              recommendation: 'Bind to 127.0.0.1 or localhost instead of 0.0.0.0 to restrict access to local connections only.',
            }),
          );
        }

        // Check for SSE/WebSocket without auth
        if (/sse|websocket|ws:\/\//i.test(line) && !/auth|token|key/i.test(line)) {
          // Only flag if it's a URL or transport config, not a comment
          if (line.trim().startsWith('#') || line.trim().startsWith('//')) continue;
          if (/ws:\/\/[^\s"']+|"transport"\s*:\s*"sse"/i.test(line)) {
            findings.push(
              this.createFinding({
                severity: 'medium',
                title: 'SSE/WebSocket transport without visible auth',
                description: `A network transport (SSE or WebSocket) is configured without apparent authentication. Network-based MCP transports should include authentication to prevent unauthorized access.`,
                filePath: target.path,
                line: i + 1,
                evidence: line.trim().length > 100 ? line.trim().slice(0, 100) + '...' : line.trim(),
                recommendation: 'Add authentication (API key, token, or mTLS) to network-based MCP transports.',
              }),
            );
          }
        }
      }
    }

    return findings;
  }
}
