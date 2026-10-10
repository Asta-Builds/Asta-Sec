import http from 'http';
import https from 'https';
import tls from 'tls';
import net from 'net';
import url from 'url';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { EventEmitter } from 'events';
import { WebSocketServer, WebSocket } from 'ws';
import { CaManager } from './ca-manager.js';
import { PassiveScanner } from './passive-scanner.js';
import { IntruderEngine } from './intruder-engine.js';
import { UpstreamClient } from './upstream-client.js';
import { StorageEngine } from './storage-engine.js';
import { ScopeManager } from './scope-manager.js';
import { ReportGenerator } from './report-generator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ProxyEngine extends EventEmitter {
  constructor(options = {}) {
    super();
    this.proxyPort = options.proxyPort || 8080;
    this.dashboardPort = options.dashboardPort || 8081;
    this.host = options.host || '127.0.0.1';

    this.caManager = new CaManager(options.caDir);
    this.storage = new StorageEngine(options.storage);
    this.upstreamClient = new UpstreamClient(options.upstream);
    this.scope = new ScopeManager(options.scope);
    this.interceptOnlyInScope = options.interceptOnlyInScope !== false;
    this.scanner = new PassiveScanner();
    this.intruder = new IntruderEngine();
    this.interceptEnabled = false;

    // Forward scanner events to WebSockets
    this.scanner.on('issue', issue => {
      this.broadcastWs({ type: 'scanner_issue', data: issue });
    });
    this.scanner.on('cleared', () => {
      this.broadcastWs({ type: 'issues_cleared' });
    });

    // Forward intruder events to WebSockets
    this.intruder.on('result', res => {
      this.broadcastWs({ type: 'intruder_result', data: res });
    });
    this.intruder.on('finished', data => {
      this.broadcastWs({ type: 'intruder_complete', data });
    });
    this.intruder.on('stopped', () => {
      this.broadcastWs({ type: 'intruder_stopped' });
    });

    // In-memory collections
    this.history = [];
    this.maxHistory = 1000;
    this.pendingRequests = new Map(); // id -> { id, clientReq, clientRes, ... resolve, reject }

    this.proxyServer = null;
    this.dashboardServer = null;
    this.wss = null;
    this.wsClients = new Set();

    this.staticDashboardDir = path.resolve(__dirname, '..', 'dashboard', 'dist', 'dashboard', 'browser');
  }

  async start() {
    await this.caManager.init();

    // 1. Start Proxy Server
    await this.startProxyServer();

    // 2. Start Dashboard & API Server
    await this.startDashboardServer();

    console.log(`[+] Proxy listening on http://${this.host}:${this.proxyPort}`);
    console.log(`[+] Web Dashboard available on http://${this.host}:${this.dashboardPort}`);

    return {
      proxyPort: this.proxyPort,
      dashboardPort: this.dashboardPort,
      caCertPath: this.caManager.getCaCertPath()
    };
  }

  stop() {
    if (this.proxyServer) this.proxyServer.close();
    if (this.dashboardServer) this.dashboardServer.close();
    if (this.wss) this.wss.close();
    if (this.upstreamClient) this.upstreamClient.destroy();
    if (this.storage) this.storage.cleanupAll();
  }

  // ==========================================
  // HTTP & HTTPS (CONNECT) Proxy Implementation
  // ==========================================
  startProxyServer() {
    return new Promise((resolve, reject) => {
      this.proxyServer = http.createServer((req, res) => {
        this.handlePlainHttpRequest(req, res);
      });

      this.proxyServer.on('connect', (req, clientSocket, head) => {
        this.handleHttpsConnect(req, clientSocket, head);
      });

      this.proxyServer.on('error', reject);
      this.proxyServer.listen(this.proxyPort, this.host, () => {
        resolve();
      });
    });
  }

  // Handle plain HTTP request
  handlePlainHttpRequest(req, res) {
    // Check if downloading Root CA
    const reqUrl = url.parse(req.url);
    if (reqUrl.pathname === '/cert' || reqUrl.pathname === '/asta-ca.crt') {
      res.writeHead(200, {
        'Content-Type': 'application/x-x509-ca-cert',
        'Content-Disposition': 'attachment; filename="asta-ca.crt"'
      });
      return res.end(this.caManager.getCaCertPem());
    }

    const hostHeader = req.headers['host'] || reqUrl.hostname;
    let targetHost = hostHeader;
    let targetPort = 80;

    if (hostHeader && hostHeader.includes(':')) {
      const parts = hostHeader.split(':');
      targetHost = parts[0];
      targetPort = parseInt(parts[1], 10) || 80;
    }

    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      const bodyBuffer = Buffer.concat(chunks);
      await this.processRequestPipeline({
        protocol: 'http',
        method: req.method,
        host: targetHost,
        port: targetPort,
        path: reqUrl.path || '/',
        headers: req.headers,
        body: bodyBuffer,
        clientRes: res
      });
    });
  }

  // Handle HTTPS CONNECT tunnel with dynamic TLS termination
  handleHttpsConnect(req, clientSocket, head) {
    const parts = req.url.split(':');
    const targetHost = parts[0];
    const targetPort = parseInt(parts[1], 10) || 443;

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Dynamically retrieve/mint TLS cert for the target domain
    const secureCtx = this.caManager.getSecureContext(targetHost);
    if (!secureCtx) {
      clientSocket.destroy();
      return;
    }

    // Wrap the client TCP connection in an incoming TLS Server stream
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext: secureCtx
    });

    if (head && head.length > 0) {
      tlsSocket.unshift(head);
    }

    // Pass the decrypted TLS stream into an embedded HTTP parser
    const httpInternal = new http.Server();
    httpInternal.emit('connection', tlsSocket);

    httpInternal.on('request', (downstreamReq, downstreamRes) => {
      const chunks = [];
      downstreamReq.on('data', chunk => chunks.push(chunk));
      downstreamReq.on('end', async () => {
        const bodyBuffer = Buffer.concat(chunks);
        await this.processRequestPipeline({
          protocol: 'https',
          method: downstreamReq.method,
          host: targetHost,
          port: targetPort,
          path: downstreamReq.url,
          headers: downstreamReq.headers,
          body: bodyBuffer,
          clientRes: downstreamRes
        });
      });
    });

    tlsSocket.on('error', () => {
      tlsSocket.destroy();
    });
  }

  // ==========================================
  // Pipeline: Interception & Upstream Forward
  // ==========================================
  async processRequestPipeline(context) {
    const id = 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    const fullUrl = `${context.protocol}://${context.host}:${context.port}${context.path}`;

    let reqData = {
      id,
      timestamp: Date.now(),
      protocol: context.protocol,
      method: context.method,
      host: context.host,
      port: context.port,
      path: context.path,
      url: fullUrl,
      headers: { ...context.headers },
      body: context.body ? context.body.toString('utf8') : '',
      isBinary: false
    };

    // Clean hop-by-hop headers
    delete reqData.headers['proxy-connection'];
    delete reqData.headers['proxy-authorization'];

    const inScope = this.scope.isInScope(context.host);
    reqData.inScope = inScope;

    // Check if Interception is active (respecting scope policy)
    const shouldIntercept = this.interceptEnabled && (!this.interceptOnlyInScope || inScope);
    if (shouldIntercept) {
      try {
        const decision = await new Promise((resolve, reject) => {
          this.pendingRequests.set(id, {
            data: reqData,
            resolve,
            reject,
            timestamp: Date.now()
          });

          this.broadcastWs({
            type: 'intercept_request',
            data: reqData
          });
        });

        if (decision.action === 'drop') {
          this.pendingRequests.delete(id);
          context.clientRes.writeHead(403, { 'Content-Type': 'text/plain' });
          context.clientRes.end('ASTA-SEC: Request dropped by user intercept.');
          this.broadcastWs({ type: 'intercept_resolved', id });
          return;
        }

        if (decision.action === 'forward') {
          if (decision.headers) reqData.headers = decision.headers;
          if (decision.body !== undefined) reqData.body = decision.body;
          this.pendingRequests.delete(id);
          this.broadcastWs({ type: 'intercept_resolved', id });
        }
      } catch (err) {
        this.pendingRequests.delete(id);
        context.clientRes.destroy();
        return;
      }
    }

    // Send upstream
    await this.forwardUpstream(reqData, context.clientRes);
  }

  async forwardUpstream(reqData, clientRes) {
    const startTime = Date.now();
    try {
      const { statusCode, statusMessage, headers, stream } = await this.upstreamClient.send(reqData);

      // Immediately write headers downstream to minimize Time To First Byte (TTFB)
      try {
        clientRes.writeHead(statusCode, headers);
      } catch {}

      const respChunks = [];
      stream.on('data', chunk => {
        respChunks.push(chunk);
        // Relay chunk directly downstream
        try {
          clientRes.write(chunk);
        } catch {}
      });

      stream.on('end', () => {
        try {
          clientRes.end();
        } catch {}

        const durationMs = Date.now() - startTime;
        const respBodyBuf = Buffer.concat(respChunks);
        const contentType = headers['content-type'] || '';

        // Pass through tiered storage engine for threshold-based disk spilling
        const processed = this.storage.processBody(reqData.id, 'response', respBodyBuf, contentType);

        const historyItem = {
          id: reqData.id,
          timestamp: reqData.timestamp,
          protocol: reqData.protocol,
          method: reqData.method,
          host: reqData.host,
          port: reqData.port,
          path: reqData.path,
          url: reqData.url,
          requestHeaders: reqData.headers,
          requestBody: reqData.body,
          responseStatus: statusCode,
          responseStatusText: statusMessage,
          responseHeaders: headers,
          responseBody: processed.body,
          isResponseBase64: processed.isBase64,
          isSpilled: processed.isSpilled,
          spillPath: processed.spillPath,
          inScope: reqData.inScope !== false,
          contentType,
          durationMs,
          size: processed.size
        };

        this.addHistory(historyItem);
      });

      stream.on('error', err => {
        this.handleUpstreamError(reqData, clientRes, err, startTime);
      });

    } catch (err) {
      this.handleUpstreamError(reqData, clientRes, err, startTime);
    }
  }

  handleUpstreamError(reqData, clientRes, err, startTime) {
    const durationMs = Date.now() - startTime;
    const historyItem = {
      id: reqData.id,
      timestamp: reqData.timestamp,
      protocol: reqData.protocol,
      method: reqData.method,
      host: reqData.host,
      port: reqData.port,
      path: reqData.path,
      url: reqData.url,
      requestHeaders: reqData.headers,
      requestBody: reqData.body,
      responseStatus: 502,
      responseStatusText: 'Bad Gateway (' + (err.code || 'ERR') + ')',
      responseHeaders: {},
      responseBody: err.message,
      isResponseBase64: false,
      isSpilled: false,
      spillPath: null,
      inScope: reqData.inScope !== false,
      contentType: 'text/plain',
      durationMs,
      size: 0
    };
    this.addHistory(historyItem);

    try {
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end(`ASTA-SEC Proxy Error: ${err.message}`);
    } catch {}
  }

  addHistory(item) {
    this.history.unshift(item);
    if (this.history.length > this.maxHistory) {
      const evicted = this.history.pop();
      if (evicted) {
        this.storage.cleanup(evicted);
      }
    }
    this.broadcastWs({
      type: 'history_item',
      data: item
    });
    // Only analyze in-scope traffic for vulnerabilities
    if (item.inScope !== false) {
      this.scanner.analyze(item);
    }
  }

  // ==========================================
  // Repeater Engine (using pooled UpstreamClient)
  // ==========================================
  async executeRepeaterRequest(reqData) {
    const startTime = Date.now();
    const reqUrl = url.parse(reqData.url);
    const isHttps = reqUrl.protocol === 'https:';

    const dispatchData = {
      protocol: isHttps ? 'https' : 'http',
      host: reqUrl.hostname,
      port: reqUrl.port || (isHttps ? 443 : 80),
      path: reqUrl.path || '/',
      method: reqData.method || 'GET',
      headers: reqData.headers || {},
      body: reqData.body || ''
    };

    try {
      const { statusCode, statusMessage, headers, stream } = await this.upstreamClient.send(dispatchData);
      const chunks = [];
      for await (const chunk of stream) {
        chunks.push(chunk);
      }
      const totalBuf = Buffer.concat(chunks);
      const contentType = headers['content-type'] || '';
      const processed = this.storage.processBody('rep_' + Date.now(), 'repeater', totalBuf, contentType);

      return {
        status: statusCode,
        statusText: statusMessage,
        headers,
        body: processed.body,
        isBase64: processed.isBase64,
        isSpilled: processed.isSpilled,
        contentType,
        size: processed.size,
        durationMs: Date.now() - startTime
      };
    } catch (err) {
      return {
        status: 502,
        statusText: 'Request Failed',
        headers: {},
        body: `Error: ${err.message}`,
        isBase64: false,
        contentType: 'text/plain',
        size: 0,
        durationMs: Date.now() - startTime
      };
    }
  }

  // ==========================================
  // Dashboard & REST API Server
  // ==========================================
  startDashboardServer() {
    return new Promise((resolve, reject) => {
      this.dashboardServer = http.createServer(async (req, res) => {
        // CORS Headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (req.method === 'OPTIONS') {
          res.writeHead(204);
          return res.end();
        }

        const parsed = url.parse(req.url, true);
        const p = parsed.pathname;

        // 1. Download Root CA
        if (p === '/cert' || p === '/asta-ca.crt') {
          res.writeHead(200, {
            'Content-Type': 'application/x-x509-ca-cert',
            'Content-Disposition': 'attachment; filename="asta-ca.crt"'
          });
          return res.end(this.caManager.getCaCertPem());
        }

        // 2. API Routes
        if (p === '/api/status' && req.method === 'GET') {
          return this.jsonResponse(res, {
            proxyPort: this.proxyPort,
            dashboardPort: this.dashboardPort,
            interceptEnabled: this.interceptEnabled,
            historyCount: this.history.length,
            pendingCount: this.pendingRequests.size,
            caCertPath: this.caManager.getCaCertPath()
          });
        }

        if (p === '/api/intercept/toggle' && req.method === 'POST') {
          const body = await this.readJsonBody(req);
          if (body && typeof body.enabled === 'boolean') {
            this.interceptEnabled = body.enabled;
          } else {
            this.interceptEnabled = !this.interceptEnabled;
          }
          this.broadcastWs({ type: 'intercept_state', enabled: this.interceptEnabled });
          return this.jsonResponse(res, { interceptEnabled: this.interceptEnabled });
        }

        if (p === '/api/intercept/action' && req.method === 'POST') {
          const body = await this.readJsonBody(req);
          if (!body || !body.id) {
            return this.jsonResponse(res, { error: 'Missing request id' }, 400);
          }
          const pending = this.pendingRequests.get(body.id);
          if (pending) {
            pending.resolve({
              action: body.action || 'forward',
              headers: body.headers,
              body: body.body
            });
            return this.jsonResponse(res, { success: true });
          } else {
            return this.jsonResponse(res, { error: 'Pending request not found' }, 404);
          }
        }

        if (p === '/api/intercept/pending' && req.method === 'GET') {
          const items = Array.from(this.pendingRequests.values()).map(v => v.data);
          return this.jsonResponse(res, items);
        }

        if (p === '/api/history' && req.method === 'GET') {
          return this.jsonResponse(res, this.history);
        }

        if (p.startsWith('/api/history/') && p.endsWith('/body') && req.method === 'GET') {
          const id = p.split('/')[3];
          const item = this.history.find(h => h.id === id);
          if (item) {
            const fullBody = this.storage.getFullBody(item);
            return this.jsonResponse(res, { id, fullBody, isBase64: item.isResponseBase64 });
          }
          return this.jsonResponse(res, { error: 'Not found' }, 404);
        }

        if (p.startsWith('/api/history/') && req.method === 'GET') {
          const id = p.split('/')[3];
          const item = this.history.find(h => h.id === id);
          if (item) return this.jsonResponse(res, item);
          return this.jsonResponse(res, { error: 'Not found' }, 404);
        }

        if (p === '/api/history' && req.method === 'DELETE') {
          for (const item of this.history) {
            this.storage.cleanup(item);
          }
          this.storage.cleanupAll();
          this.history = [];
          this.broadcastWs({ type: 'history_cleared' });
          return this.jsonResponse(res, { success: true });
        }

        if (p === '/api/repeater/send' && req.method === 'POST') {
          const body = await this.readJsonBody(req);
          if (!body || !body.url) {
            return this.jsonResponse(res, { error: 'Missing URL' }, 400);
          }
          const result = await this.executeRepeaterRequest(body);
          return this.jsonResponse(res, result);
        }

        // Scanner Issues Endpoints
        if (p === '/api/issues' && req.method === 'GET') {
          return this.jsonResponse(res, this.scanner.getIssues());
        }

        if (p === '/api/issues' && req.method === 'DELETE') {
          this.scanner.clearIssues();
          return this.jsonResponse(res, { success: true });
        }

        // Intruder Fuzzing Endpoints
        if (p === '/api/intruder/presets' && req.method === 'GET') {
          return this.jsonResponse(res, this.intruder.getPresets());
        }

        if (p === '/api/intruder/start' && req.method === 'POST') {
          const body = await this.readJsonBody(req);
          if (!body || !body.templateUrl) {
            return this.jsonResponse(res, { error: 'Missing templateUrl' }, 400);
          }
          this.intruder.startAttack(body).catch(err => console.error('[Intruder Error]', err));
          return this.jsonResponse(res, { started: true });
        }

        if (p === '/api/intruder/stop' && req.method === 'POST') {
          this.intruder.stop();
          return this.jsonResponse(res, { stopped: true });
        }

        // Scope Management Endpoints
        if (p === '/api/scope' && req.method === 'GET') {
          return this.jsonResponse(res, {
            rules: this.scope.getRules(),
            interceptOnlyInScope: this.interceptOnlyInScope
          });
        }

        if (p === '/api/scope' && req.method === 'POST') {
          const body = await this.readJsonBody(req);
          if (body) {
            if (Array.isArray(body.rules)) {
              this.scope.setRules(body.rules);
            }
            if (typeof body.interceptOnlyInScope === 'boolean') {
              this.interceptOnlyInScope = body.interceptOnlyInScope;
            }
            this.broadcastWs({
              type: 'scope_updated',
              rules: this.scope.getRules(),
              interceptOnlyInScope: this.interceptOnlyInScope
            });
            return this.jsonResponse(res, {
              success: true,
              rules: this.scope.getRules(),
              interceptOnlyInScope: this.interceptOnlyInScope
            });
          }
          return this.jsonResponse(res, { error: 'Invalid payload' }, 400);
        }

        // Pentest Report Generation Endpoints (Phase 5)
        if (p === '/api/report/markdown' && req.method === 'GET') {
          const md = ReportGenerator.generateMarkdown({
            issues: this.scanner.getIssues(),
            scope: this.scope.getRules(),
            historyCount: this.history.length,
            intruderResults: this.intruder.results || []
          });
          return this.jsonResponse(res, { markdown: md });
        }

        if (p === '/api/report/export' && req.method === 'GET') {
          const md = ReportGenerator.generateMarkdown({
            issues: this.scanner.getIssues(),
            scope: this.scope.getRules(),
            historyCount: this.history.length,
            intruderResults: this.intruder.results || []
          });
          res.writeHead(200, {
            'Content-Type': 'text/markdown; charset=utf-8',
            'Content-Disposition': 'attachment; filename="asta-sec-pentest-report.md"'
          });
          return res.end(md);
        }

        // 3. Static Files (Angular UI)
        this.serveStatic(req, res, p);
      });

      // WebSocket Server
      this.wss = new WebSocketServer({ server: this.dashboardServer, path: '/ws' });
      this.wss.on('connection', ws => {
        this.wsClients.add(ws);
        ws.send(JSON.stringify({
          type: 'init',
          data: {
            interceptEnabled: this.interceptEnabled,
            history: this.history.slice(0, 50),
            pending: Array.from(this.pendingRequests.values()).map(v => v.data),
            issues: this.scanner.getIssues(),
            scope: this.scope.getRules(),
            interceptOnlyInScope: this.interceptOnlyInScope
          }
        }));

        ws.on('message', raw => {
          try {
            const msg = JSON.parse(raw);
            if (msg.action === 'set_intercept') {
              this.interceptEnabled = !!msg.enabled;
              this.broadcastWs({ type: 'intercept_state', enabled: this.interceptEnabled });
            } else if (msg.action === 'intercept_action' && msg.id) {
              const pending = this.pendingRequests.get(msg.id);
              if (pending) {
                pending.resolve({
                  action: msg.subAction || 'forward',
                  headers: msg.headers,
                  body: msg.body
                });
              }
            }
          } catch {}
        });

        ws.on('close', () => this.wsClients.delete(ws));
      });

      this.dashboardServer.on('error', reject);
      this.dashboardServer.listen(this.dashboardPort, this.host, () => {
        resolve();
      });
    });
  }

  broadcastWs(payload) {
    const msg = JSON.stringify(payload);
    for (const ws of this.wsClients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    }
  }

  jsonResponse(res, data, code = 200) {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  readJsonBody(req) {
    return new Promise(resolve => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          resolve(null);
        }
      });
    });
  }

  serveStatic(req, res, reqPath) {
    let filePath = path.join(this.staticDashboardDir, reqPath === '/' ? 'index.html' : reqPath);

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(this.staticDashboardDir, 'index.html');
    }

    if (fs.existsSync(filePath)) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        '.html': 'text/html',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon',
        '.woff2': 'font/woff2'
      };
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
      return fs.createReadStream(filePath).pipe(res);
    }

    // Fallback if Angular build is not ready yet
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <title>ASTA-SEC Proxy</title>
  <meta charset="utf-8">
  <style>body{background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:40px;line-height:1.6;}</style>
</head>
<body>
  <h2>ASTA-SEC Intercepting Proxy &amp; Web Dashboard</h2>
  <p>Proxy listening on: <strong>http://127.0.0.1:${this.proxyPort}</strong></p>
  <p>Root CA Certificate: <a href="/cert" style="color:#58a6ff;">Download asta-ca.crt</a></p>
  <p>Dashboard is compiling...</p>
</body>
</html>`);
  }
}
