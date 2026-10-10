import http from 'http';
import https from 'https';

export class UpstreamClient {
  constructor(options = {}) {
    const maxSockets = options.maxSockets || 50;
    const timeout = options.timeout || 30000;

    this.httpAgent = new http.Agent({
      keepAlive: true,
      maxSockets,
      maxFreeSockets: 10,
      timeout
    });

    this.httpsAgent = new https.Agent({
      keepAlive: true,
      maxSockets,
      maxFreeSockets: 10,
      timeout,
      rejectUnauthorized: false
    });
  }

  send(reqData, options = {}) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      const isHttps = reqData.protocol === 'https';
      const clientLib = isHttps ? https : http;
      const agent = isHttps ? this.httpsAgent : this.httpAgent;

      const upstreamOptions = {
        hostname: reqData.host,
        port: reqData.port || (isHttps ? 443 : 80),
        path: reqData.path || '/',
        method: reqData.method || 'GET',
        headers: reqData.headers || {},
        agent,
        timeout: options.timeout || 30000
      };

      const upstreamReq = clientLib.request(upstreamOptions, (upstreamRes) => {
        resolve({
          statusCode: upstreamRes.statusCode,
          statusMessage: upstreamRes.statusMessage || '',
          headers: upstreamRes.headers,
          stream: upstreamRes,
          startTime
        });
      });

      upstreamReq.on('error', (err) => {
        reject(err);
      });

      upstreamReq.on('timeout', () => {
        upstreamReq.destroy();
        reject(new Error('Gateway Timeout (Upstream server took too long to respond)'));
      });

      if (reqData.body) {
        upstreamReq.write(reqData.body);
      }
      upstreamReq.end();
    });
  }

  destroy() {
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
  }
}
