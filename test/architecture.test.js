import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { StorageEngine } from '../lib/storage-engine.js';
import { UpstreamClient } from '../lib/upstream-client.js';
import { ProxyEngine } from '../lib/proxy-engine.js';

test('StorageEngine: preserves small payloads in memory without spilling', () => {
  const storage = new StorageEngine({ spillThreshold: 1024 });
  const smallBuf = Buffer.from('{"status":"ok"}', 'utf8');
  const res = storage.processBody('item_1', 'response', smallBuf, 'application/json');

  assert.strictEqual(res.isSpilled, false);
  assert.strictEqual(res.spillPath, null);
  assert.strictEqual(res.body, '{"status":"ok"}');
  assert.strictEqual(res.size, smallBuf.length);
});

test('StorageEngine: spills large payloads over threshold to disk blob and provides preview', () => {
  const tmpBlobDir = path.join(os.tmpdir(), 'asta-test-spill-' + Date.now());
  const storage = new StorageEngine({ spillThreshold: 500, blobDir: tmpBlobDir, maxMemoryPreview: 50 });
  const largeBuf = Buffer.from('A'.repeat(2000), 'utf8');

  const res = storage.processBody('item_2', 'response', largeBuf, 'text/plain');

  assert.strictEqual(res.isSpilled, true);
  assert.ok(res.spillPath && fs.existsSync(res.spillPath), 'Spill file should exist on disk');
  assert.ok(res.body.includes('Payload exceeds 512 KB') || res.body.includes('spilled to'), 'Preview should note spilling');

  const mockItem = {
    isSpilled: true,
    spillPath: res.spillPath,
    isResponseBase64: false,
    responseBody: res.body
  };

  const retrieved = storage.getFullBody(mockItem);
  assert.strictEqual(retrieved.length, 2000);
  assert.strictEqual(retrieved, 'A'.repeat(2000));

  // Test cleanup
  storage.cleanup(mockItem);
  assert.strictEqual(fs.existsSync(res.spillPath), false, 'Spill file should be unlinked after cleanup');

  storage.cleanupAll();
  fs.rmSync(tmpBlobDir, { recursive: true, force: true });
});

test('UpstreamClient: initializes connection pooling agents with keepAlive', () => {
  const client = new UpstreamClient({ maxSockets: 25, timeout: 5000 });
  assert.strictEqual(client.httpAgent.keepAlive, true);
  assert.strictEqual(client.httpsAgent.keepAlive, true);
  assert.strictEqual(client.httpAgent.maxSockets, 25);
  assert.strictEqual(client.httpsAgent.maxSockets, 25);
  client.destroy();
});

test('ProxyEngine: integrates StorageEngine and UpstreamClient cleanly', () => {
  const engine = new ProxyEngine({ proxyPort: 9876, dashboardPort: 9877 });
  assert.ok(engine.storage instanceof StorageEngine, 'Engine should initialize StorageEngine');
  assert.ok(engine.upstreamClient instanceof UpstreamClient, 'Engine should initialize UpstreamClient');
  engine.stop();
});
