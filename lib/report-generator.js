export class ReportGenerator {
  static generateMarkdown(data = {}) {
    const {
      issues = [],
      scope = [],
      historyCount = 0,
      intruderResults = [],
      targetName = 'Target Application',
      assessmentDate = new Date().toISOString().split('T')[0]
    } = data;

    // Severity breakdown
    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const highCount = issues.filter(i => i.severity === 'high').length;
    const mediumCount = issues.filter(i => i.severity === 'medium').length;
    const lowCount = issues.filter(i => i.severity === 'low').length;
    const infoCount = issues.filter(i => i.severity === 'info').length;
    const totalCount = issues.length;

    // Overall Risk Level
    let overallRisk = 'LOW';
    if (criticalCount > 0) overallRisk = 'CRITICAL';
    else if (highCount > 0) overallRisk = 'HIGH';
    else if (mediumCount > 0) overallRisk = 'MEDIUM';

    let md = `# Web Application Penetration Test Report

**Target:** ${targetName}  
**Date:** ${assessmentDate}  
**Testing Methodology:** OWASP Web Security Testing Guide (WSTG v4.2) / PTES  
**Assessment Tool:** ASTA-SEC Cybersecurity Suite v2.0  
**Overall Risk Posture:** **${overallRisk}**

---

## 1. Executive Summary

An authorized web application security assessment was conducted against the designated target scope. Testing evaluated defense-in-depth controls across authentication, authorization, session management, sensitive data exposure, and configuration headers.

### Vulnerability Summary Matrix

| Severity | Finding Count | Action Required |
| :--- | :---: | :--- |
| **Critical** | ${criticalCount} | Immediate remediation required (compromise imminent) |
| **High** | ${highCount} | Remediate within 24–48 hours |
| **Medium** | ${mediumCount} | Remediate in next release sprint |
| **Low** | ${lowCount} | Remediate during maintenance |
| **Informational** | ${infoCount} | Review for security best practices |
| **Total Findings** | **${totalCount}** | |

*Total HTTP/HTTPS Transactions Audited:* **${historyCount}**  
*Intruder Fuzzing Anomalies Flagged:* **${intruderResults.filter(r => r.isAnomaly).length}**

---

## 2. Scope of Assessment

The testing was constrained to the following authorized targets:

`;

    if (scope.length === 0) {
      md += `* **Unrestricted Scope:** All proxied network endpoints actively engaged during the testing window.\n\n`;
    } else {
      md += `| In-Scope Target / Domain Pattern |\n| :--- |\n`;
      for (const s of scope) {
        md += `| \`${s}\` |\n`;
      }
      md += `\n`;
    }

    md += `---

## 3. Detailed Technical Findings

`;

    if (issues.length === 0) {
      md += `*No passive vulnerabilities or configuration flaws were detected during the assessment.*\n\n`;
    } else {
      issues.forEach((iss, idx) => {
        md += `### ${idx + 1}. [${iss.ruleId}] ${iss.name}\n\n`;
        md += `- **Severity:** **${iss.severity.toUpperCase()}**\n`;
        md += `- **Confidence:** ${iss.confidence}\n`;
        md += `- **Vulnerable Endpoint:** \`${iss.method} ${iss.url}\`\n`;
        md += `- **Host:** \`${iss.host}\`\n\n`;

        md += `#### Vulnerability Description\n${iss.description}\n\n`;

        if (iss.evidence) {
          md += `#### Observed Evidence\n\`\`\`text\n${iss.evidence}\n\`\`\`\n\n`;
        }

        md += `#### Remediation Guidance\n${iss.remediation}\n\n`;
        md += `---\n\n`;
      });
    }

    if (intruderResults.length > 0) {
      const anomalies = intruderResults.filter(r => r.isAnomaly);
      if (anomalies.length > 0) {
        md += `## 4. Parameter Fuzzing Anomalies (Intruder Engine)\n\n`;
        md += `The parameter fuzzing engine identified HTTP response variations that deviate significantly from baseline behavior:\n\n`;
        md += `| Payload | Status | Response Length | Time (ms) | Endpoint |\n`;
        md += `| :--- | :---: | :---: | :---: | :--- |\n`;
        anomalies.slice(0, 25).forEach(a => {
          md += `| \`${a.payload}\` | ${a.status} | ${a.length} B | ${a.durationMs} ms | \`${a.url}\` |\n`;
        });
        md += `\n---\n\n`;
      }
    }

    md += `## 5. Methodology & Rules of Engagement Adherence

This assessment followed the structured phases of the **OWASP Web Security Testing Guide (WSTG)**:
1. **Reconnaissance & Mapping:** Discovery of assets, subdomains, and exposed interfaces.
2. **Configuration & Deployment Management:** Verification of TLS, HSTS, CSP, and CORS policies.
3. **Identity & Authentication Testing:** Verification of session identifiers and credential handling.
4. **Input Validation & Injection Analysis:** Examination of URL parameters, query strings, and payloads.
5. **Reporting & Remediation:** Provision of reproducible evidence and actionable code/architecture fixes.

*Report generated automatically by ASTA-SEC Security Suite on ${new Date().toUTCString()}*
`;

    return md;
  }
}
