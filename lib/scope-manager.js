export class ScopeManager {
  constructor(initialRules = []) {
    this.rules = [];
    if (Array.isArray(initialRules)) {
      this.setRules(initialRules);
    }
  }

  setRules(rules) {
    this.rules = rules
      .map(r => (typeof r === 'string' ? r.trim().toLowerCase() : ''))
      .filter(r => r.length > 0);
  }

  getRules() {
    return [...this.rules];
  }

  addRule(rule) {
    if (!rule || typeof rule !== 'string') return;
    const clean = rule.trim().toLowerCase();
    if (clean && !this.rules.includes(clean)) {
      this.rules.push(clean);
    }
  }

  removeRule(rule) {
    const clean = (rule || '').trim().toLowerCase();
    this.rules = this.rules.filter(r => r !== clean);
  }

  clear() {
    this.rules = [];
  }

  isInScope(host) {
    // If no rules are defined, everything is considered in-scope by default
    if (this.rules.length === 0) {
      return true;
    }

    if (!host) return false;
    const cleanHost = host.toLowerCase().split(':')[0];

    for (const rule of this.rules) {
      if (this.matchHost(cleanHost, rule)) {
        return true;
      }
    }

    return false;
  }

  matchHost(host, rule) {
    if (rule === host) return true;

    // Wildcard rule: *.example.com or *example.com
    if (rule.startsWith('*.')) {
      const baseDomain = rule.slice(2);
      if (host === baseDomain || host.endsWith('.' + baseDomain)) {
        return true;
      }
    }

    // IP or plain host without wildcard matching subdomains
    if (host.endsWith('.' + rule)) {
      return true;
    }

    return false;
  }
}
