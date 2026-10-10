import assert from 'node:assert/strict';
import test from 'node:test';
import { PassiveScanner } from '../lib/passive-scanner.js';
import { IntruderEngine } from '../lib/intruder-engine.js';

test('PassiveScanner: detects exposed AWS credentials and HSTS missing', () => {
  const scanner = new PassiveScanner();
  const mockItem = {
    id: 'req_1',
    url: 'https://api.internal/keys',
    method: 'GET',
    host: 'api.internal',
    path: '/keys',
    protocol: 'https',
    responseHeaders: { 
      'content-type': 'application/json',
      'strict-transport-security': 'max-age=31536000; includeSubDomains'
    },
    responseBody: '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}'
  };

  scanner.analyze(mockItem);
  const issues = scanner.getIssues();
  const awsIssue = issues.find(i => i.ruleId === 'SEC-001');
  assert.ok(awsIssue, 'Should flag exposed AWS credentials');
  assert.strictEqual(awsIssue.severity, 'critical');
  assert.ok(awsIssue.evidence.includes('AKIAIOSFODNN7EXAMPLE'));
});

test('PassiveScanner: detects missing security flags on cookies', () => {
  const scanner = new PassiveScanner();
  const mockItem = {
    id: 'req_2',
    url: 'https://app.local/login',
    method: 'POST',
    host: 'app.local',
    path: '/login',
    protocol: 'https',
    responseHeaders: {
      'content-type': 'text/html',
      'set-cookie': 'session_id=abcdef123456'
    },
    responseBody: 'OK'
  };

  scanner.analyze(mockItem);
  const issues = scanner.getIssues();
  const cookieIssue = issues.find(i => i.ruleId === 'SEC-002');
  assert.ok(cookieIssue, 'Should flag insecure cookie');
  assert.strictEqual(cookieIssue.severity, 'medium');
  assert.ok(cookieIssue.evidence.includes('session_id'));
});

test('PassiveScanner: detects CORS wildcard with credentials', () => {
  const scanner = new PassiveScanner();
  const mockItem = {
    id: 'req_3',
    url: 'https://api.target.com/user',
    method: 'GET',
    host: 'api.target.com',
    path: '/user',
    protocol: 'https',
    responseHeaders: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true'
    },
    responseBody: '{}'
  };

  scanner.analyze(mockItem);
  const issues = scanner.getIssues();
  const corsIssue = issues.find(i => i.ruleId === 'SEC-003');
  assert.ok(corsIssue, 'Should flag CORS wildcard with credentials');
  assert.strictEqual(corsIssue.severity, 'high');
});

test('IntruderEngine: presets and template marker replacement', () => {
  const intruder = new IntruderEngine();
  const presets = intruder.getPresets();

  assert.ok(Array.isArray(presets.common_paths));
  assert.ok(Array.isArray(presets.sqli_vectors));
  assert.ok(Array.isArray(presets.xss_vectors));

  const replaced = intruder.replaceMarkers('https://example.com/api?user=§admin§&role=user', 'superadmin');
  assert.strictEqual(replaced, 'https://example.com/api?user=superadmin&role=user');
});
