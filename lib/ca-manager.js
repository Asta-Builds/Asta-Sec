import forge from 'node-forge';
import fs from 'fs';
import path from 'path';
import os from 'os';
import tls from 'tls';
import net from 'net';

const pki = forge.pki;

export class CaManager {
  constructor(caDir = null) {
    this.caDir = caDir || path.join(os.homedir(), '.asta-sec', 'ca');
    this.certPath = path.join(this.caDir, 'asta-ca.crt');
    this.keyPath = path.join(this.caDir, 'asta-ca.key');

    this.caCert = null;
    this.caPrivateKey = null;
    this.caCertPem = '';
    this.caKeyPem = '';

    // Fast cache for leaf cert secure contexts
    this.contextCache = new Map();

    // Reusable leaf RSA key pair to avoid 100ms RSA generation on every new host
    this.leafKeyPair = null;
    this.leafKeyPem = '';
  }

  async init() {
    if (!fs.existsSync(this.caDir)) {
      fs.mkdirSync(this.caDir, { recursive: true });
    }

    if (fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)) {
      try {
        this.caCertPem = fs.readFileSync(this.certPath, 'utf8');
        this.caKeyPem = fs.readFileSync(this.keyPath, 'utf8');
        this.caCert = pki.certificateFromPem(this.caCertPem);
        this.caPrivateKey = pki.privateKeyFromPem(this.caKeyPem);
      } catch (err) {
        console.error('[!] Failed to read existing CA cert, regenerating...', err);
        this.generateCa();
      }
    } else {
      this.generateCa();
    }

    // Generate shared leaf key pair once
    const keys = pki.rsa.generateKeyPair(2048);
    this.leafKeyPair = keys;
    this.leafKeyPem = pki.privateKeyToPem(keys.privateKey);

    return this;
  }

  generateCa() {
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + Date.now().toString(16);

    const now = new Date();
    cert.validity.notBefore = new Date(now.getTime() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date(now.getTime() + 10 * 365 * 24 * 3600 * 1000); // 10 years

    const attrs = [
      { name: 'commonName', value: 'ASTA-SEC Intercepting Root CA' },
      { name: 'countryName', value: 'US' },
      { name: 'organizationName', value: 'ASTA-SEC Cybersecurity Suite' },
      { name: 'organizationalUnitName', value: 'Dynamic MITM Proxy Authority' }
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true }
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());

    this.caCert = cert;
    this.caPrivateKey = keys.privateKey;
    this.caCertPem = pki.certificateToPem(cert);
    this.caKeyPem = pki.privateKeyToPem(keys.privateKey);

    fs.writeFileSync(this.certPath, this.caCertPem, 'utf8');
    fs.writeFileSync(this.keyPath, this.caKeyPem, 'utf8');
  }

  getCaCertPem() {
    return this.caCertPem;
  }

  getCaCertPath() {
    return this.certPath;
  }

  getSecureContext(hostname) {
    const hostClean = (hostname || 'localhost').toLowerCase().split(':')[0];

    if (this.contextCache.has(hostClean)) {
      return this.contextCache.get(hostClean);
    }

    try {
      const cert = pki.createCertificate();
      cert.publicKey = this.leafKeyPair.publicKey;
      cert.serialNumber = Date.now().toString(16);

      const now = new Date();
      cert.validity.notBefore = new Date(now.getTime() - 24 * 3600 * 1000);
      cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000); // 1 year

      const attrs = [
        { name: 'commonName', value: hostClean },
        { name: 'organizationName', value: 'ASTA-SEC Intercept Dynamic Host' }
      ];

      cert.setSubject(attrs);
      cert.setIssuer(this.caCert.subject.attributes);

      const altNames = [];
      if (net.isIP(hostClean)) {
        altNames.push({ type: 7, ip: hostClean });
      } else {
        altNames.push({ type: 2, value: hostClean });
        if (!hostClean.startsWith('*.')) {
          altNames.push({ type: 2, value: `*.${hostClean}` });
        }
      }

      cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
        { name: 'subjectAltName', altNames }
      ]);

      cert.sign(this.caPrivateKey, forge.md.sha256.create());

      const certPem = pki.certificateToPem(cert);
      const secureCtx = tls.createSecureContext({
        key: this.leafKeyPem,
        cert: certPem,
        ca: [this.caCertPem]
      });

      this.contextCache.set(hostClean, secureCtx);
      return secureCtx;
    } catch (err) {
      console.error(`[!] Failed to generate dynamic TLS cert for ${hostClean}:`, err);
      return null;
    }
  }
}
