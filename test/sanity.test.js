import assert from 'node:assert/strict';
import test from 'node:test';
import { CaManager } from '../lib/ca-manager.js';
import { ProxyEngine } from '../lib/proxy-engine.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

test('CaManager: generates Root CA and dynamic secure context', async () => {
  const tmpDir = path.join(os.tmpdir(), 'asta-test-ca-' + Date.now());
  const ca = new CaManager(tmpDir);
  await ca.init();

  assert.ok(fs.existsSync(ca.getCaCertPath()), 'Root CA certificate file should exist');
  assert.ok(ca.getCaCertPem().includes('BEGIN CERTIFICATE'), 'CA PEM should contain certificate header');

  const ctx = ca.getSecureContext('example.org');
  assert.ok(ctx, 'SecureContext for example.org should be created');

  // Test caching
  const ctx2 = ca.getSecureContext('example.org');
  assert.strictEqual(ctx, ctx2, 'SecureContext should be cached');

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('ProxyEngine: instantiates with expected defaults', () => {
  const engine = new ProxyEngine({ proxyPort: 9090, dashboardPort: 9091 });
  assert.strictEqual(engine.proxyPort, 9090);
  assert.strictEqual(engine.dashboardPort, 9091);
  assert.strictEqual(engine.interceptEnabled, false);
});
