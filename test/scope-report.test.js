import assert from 'node:assert/strict';
import test from 'node:test';
import { ScopeManager } from '../lib/scope-manager.js';
import { ReportGenerator } from '../lib/report-generator.js';

test('ScopeManager: default open scope and rule matching', () => {
  const scope = new ScopeManager();
  
  // Default: empty rules means all traffic is in scope
  assert.strictEqual(scope.isInScope('example.com'), true);
  assert.strictEqual(scope.isInScope('sub.test.org'), true);

  // Set explicit rules
  scope.setRules(['target.com', '*.api.target.com']);
  
  // Exact match
  assert.strictEqual(scope.isInScope('target.com'), true);
  assert.strictEqual(scope.isInScope('target.com:8443'), true);

  // Wildcard subdomains
  assert.strictEqual(scope.isInScope('v1.api.target.com'), true);
  assert.strictEqual(scope.isInScope('api.target.com'), true);

  // Out of scope
  assert.strictEqual(scope.isInScope('attacker.com'), false);
  assert.strictEqual(scope.isInScope('evil-target.com'), false);

  // Add / remove rule
  scope.addRule('internal-app.local');
  assert.strictEqual(scope.isInScope('internal-app.local'), true);
  scope.removeRule('internal-app.local');
  assert.strictEqual(scope.isInScope('internal-app.local'), false);
});

test('ReportGenerator: generates OWASP WSTG compliant Markdown report', () => {
  const mockIssues = [
    {
      ruleId: 'SEC-001',
      name: 'Exposed Hardcoded AWS Access Key',
      severity: 'critical',
      confidence: 'certain',
      url: 'https://api.target.com/config',
      host: 'api.target.com',
      method: 'GET',
      description: 'Found leaked AWS Access Key in JSON response.',
      evidence: 'AKIAIOSFODNN7EXAMPLE',
      remediation: 'Immediately revoke the key and store secrets in an HSM or KMS.'
    },
    {
      ruleId: 'SEC-004',
      name: 'Missing Content-Security-Policy (CSP)',
      severity: 'medium',
      confidence: 'certain',
      url: 'https://api.target.com/',
      host: 'api.target.com',
      method: 'GET',
      description: 'The response does not specify a Content-Security-Policy header.',
      evidence: 'Header not present',
      remediation: 'Implement a strict CSP.'
    }
  ];

  const mockIntruderResults = [
    {
      payload: "' OR '1'='1",
      status: 200,
      length: 12500,
      durationMs: 45,
      isAnomaly: true,
      url: 'https://api.target.com/login'
    }
  ];

  const markdown = ReportGenerator.generateMarkdown({
    issues: mockIssues,
    scope: ['target.com', '*.target.com'],
    historyCount: 150,
    intruderResults: mockIntruderResults,
    targetName: 'Acme Financial Portal'
  });

  // Verify structure
  assert.ok(markdown.includes('# Web Application Penetration Test Report'));
  assert.ok(markdown.includes('**Overall Risk Posture:** **CRITICAL**'));
  assert.ok(markdown.includes('Acme Financial Portal'));
  assert.ok(markdown.includes('`target.com`'));
  assert.ok(markdown.includes('`*.target.com`'));
  assert.ok(markdown.includes('[SEC-001] Exposed Hardcoded AWS Access Key'));
  assert.ok(markdown.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(markdown.includes('Immediately revoke the key'));
  assert.ok(markdown.includes('Parameter Fuzzing Anomalies (Intruder Engine)'));
  assert.ok(markdown.includes("' OR '1'='1"));
  assert.ok(markdown.includes('OWASP Web Security Testing Guide (WSTG)'));
});
