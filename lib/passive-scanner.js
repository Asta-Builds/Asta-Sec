import { EventEmitter } from 'events';

export class PassiveScanner extends EventEmitter {
  constructor() {
    super();
    this.issues = [];
    this.maxIssues = 500;

    // Ruleset definition
    this.rules = [
      {
        id: 'SEC-001',
        name: 'Exposed Cloud / API Credentials in Response',
        severity: 'critical',
        confidence: 'certain',
        check: (item) => {
          const body = item.responseBody || '';
          if (!body) return null;

          // AWS Access Key ID
          const awsMatch = body.match(/\b(AKIA[0-9A-Z]{16})\b/);
          if (awsMatch) {
            return {
              evidence: `Matched AWS Access Key: ${awsMatch[1]}`,
              description: 'An AWS Access Key ID was detected in plaintext in the server response body.',
              remediation: 'Immediately revoke the exposed AWS credential in IAM, rotate secrets, and ensure environment variables or API keys are never rendered in client responses.'
            };
          }

          // GitHub Personal Access Token
          const ghMatch = body.match(/\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/);
          if (ghMatch) {
            return {
              evidence: `Matched GitHub Token: ${ghMatch[1].substring(0, 8)}...`,
              description: 'A GitHub Personal Access Token or OAuth token was exposed in the HTTP response.',
              remediation: 'Revoke the compromised token in GitHub settings and inspect logs for unauthorized repository access.'
            };
          }

          // Private Key Header
          if (body.includes('-----BEGIN PRIVATE KEY-----') || body.includes('-----BEGIN RSA PRIVATE KEY-----')) {
            return {
              evidence: 'Found "-----BEGIN PRIVATE KEY-----" block',
              description: 'An unencrypted cryptographic private key was detected in the HTTP response.',
              remediation: 'Remove private keys from web-accessible directories and store them in a secure KMS or secret store.'
            };
          }

          return null;
        }
      },
      {
        id: 'SEC-002',
        name: 'Insecure Cookie (Missing Flags)',
        severity: 'medium',
        confidence: 'certain',
        check: (item) => {
          const rawCookies = item.responseHeaders['set-cookie'];
          if (!rawCookies) return null;

          const cookieList = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
          const missingFlags = [];

          for (const c of cookieList) {
            const parts = c.split(';').map(p => p.trim().toLowerCase());
            const cookieName = c.split('=')[0].trim();
            const hasSecure = parts.includes('secure');
            const hasHttpOnly = parts.includes('httponly');
            const hasSameSite = parts.some(p => p.startsWith('samesite='));

            const issuesForCookie = [];
            if (!hasSecure && item.protocol === 'https') issuesForCookie.push('Secure');
            if (!hasHttpOnly) issuesForCookie.push('HttpOnly');
            if (!hasSameSite) issuesForCookie.push('SameSite');

            if (issuesForCookie.length > 0) {
              missingFlags.push(`Cookie "${cookieName}" is missing: ${issuesForCookie.join(', ')}`);
            }
          }

          if (missingFlags.length > 0) {
            return {
              evidence: missingFlags.join('; '),
              description: 'One or more session cookies were set without essential security directives (Secure, HttpOnly, SameSite). This exposes cookies to XSS theft and CSRF attacks.',
              remediation: 'Configure Set-Cookie with Secure; HttpOnly; SameSite=Lax (or Strict) on all authenticated session tokens.'
            };
          }

          return null;
        }
      },
      {
        id: 'SEC-003',
        name: 'CORS Wildcard with Credentials Enabled',
        severity: 'high',
        confidence: 'certain',
        check: (item) => {
          const origin = item.responseHeaders['access-control-allow-origin'];
          const credentials = item.responseHeaders['access-control-allow-credentials'];

          if (origin === '*' && credentials === 'true') {
            return {
              evidence: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
              description: 'The server permits any arbitrary origin to execute cross-origin authenticated requests with cookies/credentials.',
              remediation: 'Specify explicit trusted whitelist origins rather than "*" when Access-Control-Allow-Credentials is set to true.'
            };
          }
          return null;
        }
      },
      {
        id: 'SEC-004',
        name: 'Sensitive Credentials Passed in Query String (GET URL)',
        severity: 'medium',
        confidence: 'firm',
        check: (item) => {
          if (item.method !== 'GET') return null;
          const urlStr = item.url.toLowerCase();

          const sensitiveParamPatterns = [
            /(password|passwd|pwd)=[^&]+/i,
            /(apikey|api_key|access_token|secret)=[^&]+/i,
            /(auth_token|bearer)=[^&]+/i
          ];

          for (const pattern of sensitiveParamPatterns) {
            const match = item.url.match(pattern);
            if (match) {
              return {
                evidence: `Query parameter exposed: ${match[0]}`,
                description: 'Sensitive credentials or API authentication tokens were supplied in the URL query string. URLs are routinely logged in browser history, proxy server logs, and Referer headers.',
                remediation: 'Send sensitive authentication credentials in the Authorization HTTP request header or within an encrypted POST body.'
              };
            }
          }
          return null;
        }
      },
      {
        id: 'SEC-005',
        name: 'Missing Clickjacking Defense (X-Frame-Options / CSP frame-ancestors)',
        severity: 'medium',
        confidence: 'certain',
        check: (item) => {
          // Only check HTML responses
          const ct = item.contentType || '';
          if (!ct.includes('html')) return null;

          const xfo = item.responseHeaders['x-frame-options'];
          const csp = item.responseHeaders['content-security-policy'] || '';

          if (!xfo && !csp.includes('frame-ancestors')) {
            return {
              evidence: 'Neither X-Frame-Options nor CSP frame-ancestors header present',
              description: 'The web page does not declare frame embedding constraints, making it susceptible to UI Redressing (Clickjacking) attacks.',
              remediation: 'Include "X-Frame-Options: DENY" (or SAMEORIGIN), or configure Content-Security-Policy: frame-ancestors \'self\'.'
            };
          }
          return null;
        }
      },
      {
        id: 'SEC-006',
        name: 'Missing HSTS (Strict-Transport-Security)',
        severity: 'low',
        confidence: 'certain',
        check: (item) => {
          if (item.protocol !== 'https') return null;
          const hsts = item.responseHeaders['strict-transport-security'];

          if (!hsts) {
            return {
              evidence: 'Strict-Transport-Security header is absent in HTTPS response',
              description: 'The server did not return an HSTS header, allowing potential SSL-stripping man-in-the-middle attacks on initial requests.',
              remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.'
            };
          }
          return null;
        }
      },
      {
        id: 'SEC-007',
        name: 'Detailed Server Banner / Framework Version Leak',
        severity: 'info',
        confidence: 'certain',
        check: (item) => {
          const server = item.responseHeaders['server'];
          const poweredBy = item.responseHeaders['x-powered-by'];

          const leaks = [];
          if (server && /\d+\.\d+/.test(server)) {
            leaks.push(`Server: ${server}`);
          }
          if (poweredBy) {
            leaks.push(`X-Powered-By: ${poweredBy}`);
          }

          if (leaks.length > 0) {
            return {
              evidence: leaks.join(' | '),
              description: 'Detailed software and framework version numbers are exposed in HTTP response headers, assisting attackers with CVE targeting.',
              remediation: 'Disable framework signature banners (e.g., set ServerTokens Prod in Apache, expose_php = Off in PHP, or app.disable(\'x-powered-by\') in Express).'
            };
          }
          return null;
        }
      }
    ];
  }

  analyze(historyItem) {
    if (!historyItem) return;

    for (const rule of this.rules) {
      try {
        const finding = rule.check(historyItem);
        if (finding) {
          // Check for duplicate issues on same host & rule
          const isDuplicate = this.issues.some(
            existing => existing.ruleId === rule.id && existing.host === historyItem.host && existing.path === historyItem.path
          );

          if (!isDuplicate) {
            const issue = {
              id: 'iss_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
              ruleId: rule.id,
              name: rule.name,
              severity: rule.severity,
              confidence: rule.confidence,
              host: historyItem.host,
              path: historyItem.path,
              url: historyItem.url,
              method: historyItem.method,
              description: finding.description,
              remediation: finding.remediation,
              evidence: finding.evidence,
              matchedItemId: historyItem.id,
              timestamp: Date.now()
            };

            this.issues.unshift(issue);
            if (this.issues.length > this.maxIssues) {
              this.issues.pop();
            }

            this.emit('issue', issue);
          }
        }
      } catch (err) {
        console.error(`[!] Passive scanner error on rule ${rule.id}:`, err);
      }
    }
  }

  getIssues() {
    return this.issues;
  }

  clearIssues() {
    this.issues = [];
    this.emit('cleared');
  }
}
