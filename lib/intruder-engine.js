import http from 'http';
import https from 'https';
import url from 'url';
import { EventEmitter } from 'events';

export class IntruderEngine extends EventEmitter {
  constructor() {
    super();
    this.isRunning = false;
    this.shouldStop = false;
    this.results = [];

    this.presets = {
      numbers_1_25: Array.from({ length: 25 }, (_, i) => (i + 1).toString()),
      common_paths: [
        'admin', 'login', 'dashboard', 'api', 'v1', 'v2', 'test', 'backup',
        'config', 'dev', 'staging', 'portal', 'secret', '.git/HEAD', '.env',
        'robots.txt', 'sitemap.xml', 'swagger.json', 'actuator/health'
      ],
      sqli_vectors: [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "1' ORDER BY 1--",
        "' UNION SELECT null,null--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1 AND 1=1",
        "1 AND 1=2"
      ],
      xss_vectors: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        'javascript:alert(1)',
        '{{7*7}}',
        '${7*7}'
      ],
      path_traversal: [
        '../../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '%2e%2e%2fetc%2fpasswd',
        '/etc/passwd',
        'C:\\Windows\\win.ini'
      ]
    };
  }

  getPresets() {
    return this.presets;
  }

  stop() {
    this.shouldStop = true;
    this.isRunning = false;
    this.emit('stopped');
  }

  async startAttack(config) {
    if (this.isRunning) {
      throw new Error('An Intruder attack is already in progress.');
    }

    this.isRunning = true;
    this.shouldStop = false;
    this.results = [];

    const {
      templateUrl,
      method = 'GET',
      headers = {},
      bodyTemplate = '',
      payloads = [],
      concurrency = 5
    } = config;

    if (!payloads || payloads.length === 0) {
      this.isRunning = false;
      throw new Error('Payload list cannot be empty.');
    }

    this.emit('started', { total: payloads.length });

    // Baseline request to calculate baseline length
    let baselineLength = null;

    let index = 0;
    const worker = async () => {
      while (index < payloads.length && !this.shouldStop) {
        const currentIndex = index++;
        const payload = payloads[currentIndex];

        // Replace §...§ or literal marker §
        const actualUrl = this.replaceMarkers(templateUrl, payload);
        const actualBody = this.replaceMarkers(bodyTemplate, payload);
        const actualHeaders = {};
        for (const [k, v] of Object.entries(headers)) {
          actualHeaders[k] = this.replaceMarkers(v, payload);
        }

        try {
          const res = await this.sendOne(method, actualUrl, actualHeaders, actualBody);
          if (baselineLength === null) baselineLength = res.length;

          const isAnomaly = baselineLength !== null && Math.abs(res.length - baselineLength) > 50;

          const item = {
            id: currentIndex + 1,
            payload,
            status: res.status,
            statusText: res.statusText,
            length: res.length,
            durationMs: res.durationMs,
            isAnomaly,
            method,
            url: actualUrl,
            headers: actualHeaders,
            body: actualBody,
            responseHeaders: res.headers,
            responseBody: res.body
          };

          this.results.push(item);
          this.emit('result', item);
        } catch (err) {
          const item = {
            id: currentIndex + 1,
            payload,
            status: 0,
            statusText: err.message,
            length: 0,
            durationMs: 0,
            isAnomaly: false,
            method,
            url: actualUrl,
            headers: actualHeaders,
            body: actualBody,
            responseHeaders: {},
            responseBody: err.message
          };
          this.results.push(item);
          this.emit('result', item);
        }
      }
    };

    const workers = [];
    const poolSize = Math.min(concurrency, payloads.length);
    for (let i = 0; i < poolSize; i++) {
      workers.push(worker());
    }

    await Promise.all(workers);
    this.isRunning = false;
    this.emit('finished', { total: this.results.length });
    return this.results;
  }

  replaceMarkers(template, payload) {
    if (!template) return template;
    // Replace §...§ with payload
    if (template.includes('§')) {
      return template.replace(/§.*?§/g, payload);
    }
    return template;
  }

  sendOne(method, reqUrl, headers, body) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      const parsed = url.parse(reqUrl);
      const isHttps = parsed.protocol === 'https:';
      const clientLib = isHttps ? https : http;

      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.path || '/',
        method,
        headers,
        rejectUnauthorized: false,
        timeout: 6000
      };

      const req = clientLib.request(opts, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const durationMs = Date.now() - startTime;
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage || '',
            headers: res.headers,
            length: buf.length,
            durationMs,
            body: buf.toString('utf8')
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timed out'));
      });

      req.on('error', reject);

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }
}
