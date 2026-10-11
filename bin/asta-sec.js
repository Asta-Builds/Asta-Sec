#!/usr/bin/env node

import { select, input, confirm } from '@inquirer/prompts';
import chalk from 'chalk';
import { spawn } from 'child_process';
import dns from 'dns/promises';
import net from 'net';
import https from 'https';
import http from 'http';
import tls from 'tls';
import os from 'os';
import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { ProxyEngine } from '../lib/proxy-engine.js';
import { ReportGenerator } from '../lib/report-generator.js';
import { IntruderEngine } from '../lib/intruder-engine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

// ==========================================
// ASCII Banner
// ==========================================
function printBanner() {
  console.clear();
  console.log(chalk.cyan(`
  █████╗ ███████╗████████╗ █████╗        ███████╗███████╗ ██████╗ 
 ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗       ██╔════╝██╔════╝██╔════╝ 
 ███████║███████╗   ██║   ███████║ █████╗███████╗█████╗  ██║      
 ██╔══██║╚════██║   ██║   ██╔══██║ ╚════╝╚════██║██╔══╝  ██║      
 ██║  ██║███████║   ██║   ██║  ██║       ███████║███████╗╚██████╗ 
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝       ╚══════╝╚══════╝ ╚═════╝ 
`));
  console.log(chalk.yellow.bold('      [ ASTA-SEC // ADVANCED SECURITY & NETWORK SUITE v2.0 ]'));
  console.log(chalk.gray('   Sniffer | OWASP Web Auditor | Subdomain Recon | Nmap Scanner'));
  console.log(chalk.gray('   JWT Inspector | Pentest Reporter | Concurrency & Rate-Limit Benchmark'));
  console.log(chalk.gray(' ----------------------------------------------------------------'));
}

async function pause() {
  await input({ message: chalk.dim('Press Enter to return to main menu...') });
}

// ==========================================
// TOOL 1: Packet Sniffer
// ==========================================
async function runSnifferModule() {
  console.log(chalk.bold('\n--- [1] Live Packet Sniffer Configuration ---'));

  const ifaceChoice = await select({
    message: 'Select Interface Mode:',
    choices: [
      { name: 'Auto-detect active interface (Recommended)', value: 'auto' },
      { name: 'Specific interface index (e.g. 1, 2)', value: 'index' },
      { name: 'Interface name (e.g. eth0)', value: 'name' }
    ]
  });

  let ifaceArg = '';
  if (ifaceChoice === 'index') {
    ifaceArg = await input({ message: 'Enter interface index number (e.g. 1):', default: '1' });
  } else if (ifaceChoice === 'name') {
    ifaceArg = await input({ message: 'Enter interface name (e.g. eth0):' });
  }

  const filterPreset = await select({
    message: 'Select BPF Capture Filter Preset:',
    choices: [
      { name: 'All IP & ARP traffic (ip or arp)', value: 'ip or arp' },
      { name: 'HTTP Traffic (tcp port 80)', value: 'tcp port 80' },
      { name: 'HTTP & HTTPS (tcp port 80 or tcp port 443)', value: 'tcp port 80 or tcp port 443' },
      { name: 'DNS Traffic (udp port 53 or tcp port 53)', value: 'udp port 53 or tcp port 53' },
      { name: 'ICMP / Ping Only (icmp)', value: 'icmp' },
      { name: 'Custom BPF Filter Expression', value: 'custom' }
    ]
  });

  let filterArg = filterPreset;
  if (filterPreset === 'custom') {
    filterArg = await input({ message: 'Enter BPF Filter Expression:', default: 'ip' });
  }

  const enableHex = await confirm({
    message: 'Enable Wireshark-style Hex & ASCII payload dump?',
    default: false
  });

  const packetCount = await input({
    message: 'Packet limit (0 for continuous capture until Ctrl+C):',
    default: '0'
  });

  const savePcap = await input({
    message: 'Save traffic to PCAP file? (Enter filename or leave blank):',
    default: ''
  });

  const args = [];
  if (ifaceArg) {
    args.push('-i', ifaceArg);
  }
  if (filterArg) {
    args.push('-f', filterArg);
  }
  if (enableHex) {
    args.push('-x');
  }
  if (packetCount && packetCount !== '0') {
    args.push('-c', packetCount);
  }
  if (savePcap.trim()) {
    args.push('-w', savePcap.trim());
  }

  const isWin = process.platform === 'win32';
  const exePath = isWin
    ? path.join(projectRoot, 'asta-sec.exe')
    : path.join(projectRoot, 'asta-sec');

  console.log(chalk.green(`\n[+] Launching Sniffer: ${exePath} ${args.join(' ')}\n`));

  return new Promise((resolve) => {
    let child;
    if (isWin) {
      const batPath = path.join(projectRoot, 'asta-sec.bat');
      child = spawn('cmd.exe', ['/c', batPath, ...args], {
        stdio: 'inherit',
        cwd: projectRoot
      });
    } else {
      const isRoot = process.getuid && process.getuid() === 0;
      if (isRoot) {
        child = spawn(exePath, args, { stdio: 'inherit', cwd: projectRoot });
      } else {
        child = spawn('sudo', [exePath, ...args], { stdio: 'inherit', cwd: projectRoot });
      }
    }

    child.on('close', () => {
      resolve();
    });
  });
}

// ==========================================
// TOOL 2: Website Security & OWASP Auditor
// ==========================================
async function runWebsiteAuditor(targetDomain = null) {
  console.log(chalk.bold('\n--- [2] Website Security & OWASP Header Auditor ---'));
  let target = targetDomain;
  if (!target) {
    target = await input({
      message: 'Enter website domain or URL to audit (e.g. google.com, github.com):',
      default: 'github.com'
    });
  }

  target = target.trim().replace(/^https?:\/\//, '').split('/')[0];
  console.log(chalk.cyan(`\n[*] Auditing Security Posture of: ${chalk.bold(target)}...\n`));

  let ip = '';
  try {
    const addresses = await dns.resolve4(target);
    ip = addresses[0];
    console.log(chalk.green(`[+] Target IP Resolved : ${ip}`));
  } catch (err) {
    console.log(chalk.red(`[!] DNS Resolution Failed: ${err.message}`));
    if (!targetDomain) await pause();
    return;
  }

  console.log(chalk.bold('\n--- SSL/TLS Certificate Inspection ---'));
  try {
    await new Promise((resolve) => {
      const socket = tls.connect(443, target, { servername: target, timeout: 4000 }, () => {
        const cert = socket.getPeerCertificate();
        if (cert && cert.subject) {
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

          console.log(`  ${chalk.green('[PASS]')} Issuer         : ${cert.issuer.O || cert.issuer.CN}`);
          console.log(`  ${chalk.green('[PASS]')} Subject CN     : ${cert.subject.CN}`);
          console.log(`  ${chalk.green('[PASS]')} TLS Protocol   : ${socket.getProtocol()}`);
          console.log(`  ${chalk.green('[PASS]')} Cipher Suite   : ${socket.getCipher().name}`);
          if (daysRemaining > 30) {
            console.log(`  ${chalk.green('[PASS]')} Certificate Exp: ${validTo.toISOString().split('T')[0]} (${daysRemaining} days left)`);
          } else if (daysRemaining > 0) {
            console.log(`  ${chalk.yellow('[WARN]')} Certificate Exp: Expires soon! (${daysRemaining} days left)`);
          } else {
            console.log(`  ${chalk.red('[FAIL]')} Certificate Exp: EXPIRED!`);
          }
        }
        socket.destroy();
        resolve();
      });

      socket.on('error', (err) => {
        console.log(`  ${chalk.yellow('[WARN]')} TLS connection on port 443: ${err.message}`);
        resolve();
      });

      socket.on('timeout', () => {
        console.log(`  ${chalk.yellow('[WARN]')} TLS Handshake timed out.`);
        socket.destroy();
        resolve();
      });
    });
  } catch (err) {
    console.log(`  ${chalk.yellow('[WARN]')} TLS check error: ${err.message}`);
  }

  console.log(chalk.bold('\n--- OWASP Security Headers Assessment ---'));
  try {
    const headers = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: target,
          port: 443,
          path: '/',
          method: 'GET',
          timeout: 5000,
          headers: { 'User-Agent': 'AstaSec-Security-Suite/2.0' }
        },
        (res) => {
          resolve(res.headers);
        }
      );
      req.on('error', () => {
        http.get(`http://${target}`, (res) => resolve(res.headers)).on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('Timeout')));
      req.end();
    });

    let score = 0;
    const recommendations = [];

    if (headers['strict-transport-security']) {
      score += 25;
      console.log(`  ${chalk.green('[PASS]')} Strict-Transport-Security (HSTS): ${chalk.dim(headers['strict-transport-security'])}`);
    } else {
      console.log(`  ${chalk.red('[FAIL]')} Strict-Transport-Security (HSTS) is MISSING.`);
      recommendations.push('Add Strict-Transport-Security: max-age=31536000; includeSubDomains to enforce HTTPS and prevent SSL stripping.');
    }

    if (headers['content-security-policy']) {
      score += 25;
      console.log(`  ${chalk.green('[PASS]')} Content-Security-Policy (CSP): ${chalk.dim(headers['content-security-policy'].substring(0, 60))}...`);
    } else {
      console.log(`  ${chalk.red('[FAIL]')} Content-Security-Policy (CSP) is MISSING.`);
      recommendations.push('Deploy Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and unauthorized resource loading.');
    }

    if (headers['x-frame-options']) {
      score += 15;
      console.log(`  ${chalk.green('[PASS]')} X-Frame-Options: ${headers['x-frame-options']}`);
    } else {
      console.log(`  ${chalk.red('[FAIL]')} X-Frame-Options is MISSING.`);
      recommendations.push('Configure X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking attacks.');
    }

    if (headers['x-content-type-options']) {
      score += 15;
      console.log(`  ${chalk.green('[PASS]')} X-Content-Type-Options: ${headers['x-content-type-options']}`);
    } else {
      console.log(`  ${chalk.red('[FAIL]')} X-Content-Type-Options is MISSING.`);
      recommendations.push('Add X-Content-Type-Options: nosniff to stop MIME-sniffing exploits.');
    }

    if (headers['referrer-policy']) {
      score += 10;
      console.log(`  ${chalk.green('[PASS]')} Referrer-Policy: ${headers['referrer-policy']}`);
    } else {
      console.log(`  ${chalk.yellow('[WARN]')} Referrer-Policy is MISSING.`);
      recommendations.push('Set Referrer-Policy: strict-origin-when-cross-origin to avoid leaking sensitive URL paths in Referer headers.');
    }

    if (headers['permissions-policy']) {
      score += 10;
      console.log(`  ${chalk.green('[PASS]')} Permissions-Policy: Present`);
    } else {
      console.log(`  ${chalk.yellow('[WARN]')} Permissions-Policy is MISSING.`);
    }

    console.log(chalk.bold('\n--- Information Disclosure Inspection ---'));
    if (headers['server']) {
      console.log(`  ${chalk.yellow('[INFO]')} Server Banner Exposed: ${headers['server']}`);
      if (headers['server'].includes('/')) {
        score -= 5;
        recommendations.push('Mask detailed server version numbers in the Server header to prevent targeted exploit identification.');
      }
    }
    if (headers['x-powered-by']) {
      score -= 10;
      console.log(`  ${chalk.red('[WARN]')} X-Powered-By Header Exposed: ${headers['x-powered-by']}`);
      recommendations.push('Remove X-Powered-By to conceal backend language and framework fingerprints.');
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    let grade = 'F';
    let gradeColor = chalk.red.bold;
    if (score >= 90) { grade = 'A+'; gradeColor = chalk.green.bold; }
    else if (score >= 80) { grade = 'A'; gradeColor = chalk.green.bold; }
    else if (score >= 70) { grade = 'B'; gradeColor = chalk.cyan.bold; }
    else if (score >= 55) { grade = 'C'; gradeColor = chalk.yellow.bold; }
    else if (score >= 40) { grade = 'D'; gradeColor = chalk.yellow; }

    console.log(chalk.gray('\n----------------------------------------------------------------'));
    console.log(`  Defensive Security Score : ${gradeColor(score + '/100')}`);
    console.log(`  Overall Security Grade   : ${gradeColor('[' + grade + ']')}`);
    console.log(chalk.gray('----------------------------------------------------------------'));

    if (recommendations.length > 0) {
      console.log(chalk.bold('\nRemediation Recommendations:'));
      recommendations.forEach((r, idx) => console.log(`  ${idx + 1}. ${r}`));
    }
  } catch (err) {
    console.log(chalk.red(`[!] HTTP Audit Request Failed: ${err.message}`));
  }

  if (!targetDomain) await pause();
}

// ==========================================
// TOOL 3: Subdomain Search & Attack Surface Analyzer
// ==========================================
async function runSubdomainAnalyzer(targetDomain = null) {
  console.log(chalk.bold('\n--- [3] Subdomain Search & Attack Surface Analyzer ---'));
  let domain = targetDomain;
  if (!domain) {
    domain = await input({
      message: 'Enter target root domain (e.g. github.com, tesla.com, google.com):',
      default: 'github.com'
    });
  }
  domain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];

  console.log(chalk.cyan(`\n[*] Initiating Subdomain Reconnaissance for ${chalk.bold(domain)}...`));

  const foundSubdomains = new Map();

  // 1. Passive OSINT Enumeration via HackerTarget API
  console.log(chalk.blue(`[*] Querying Passive Certificate & Host Intelligence for ${domain}...`));
  try {
    const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'AstaSec-Recon/2.0' }
    });
    if (res.ok) {
      const text = await res.text();
      if (!text.includes('error') && !text.includes('API count')) {
        const lines = text.split('\n');
        for (const line of lines) {
          const parts = line.split(',');
          if (parts.length >= 2) {
            const sub = parts[0].trim().toLowerCase();
            const ip = parts[1].trim();
            if (sub.endsWith(domain) && !foundSubdomains.has(sub)) {
              foundSubdomains.set(sub, { ip, cname: '', httpStatus: '', server: '', source: 'Passive OSINT' });
            }
          }
        }
      }
    }
  } catch (err) {
    console.log(chalk.yellow(`[!] Passive host search: ${err.message}`));
  }

  // 2. Active Concurrent DNS Brute-Forcing of Critical Subdomains
  const wordlist = [
    'www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'portal', 'vpn',
    'app', 'auth', 'login', 'sso', 'cdn', 'cloud', 'shop', 'blog', 'support',
    'docs', 'status', 'beta', 'git', 'dashboard', 'monitor', 'grafana', 'm',
    'mobile', 'corp', 'internal', 'secure', 'remote', 'gateway', 'pay',
    'billing', 'db', 'database', 'jenkins', 'gitlab', 'k8s', 'prod', 'stage'
  ];

  console.log(chalk.blue(`[*] Running Active DNS Brute-Force against ${wordlist.length} critical targets...`));

  const probePromises = wordlist.map(async (prefix) => {
    const sub = `${prefix}.${domain}`;
    if (foundSubdomains.has(sub)) return;

    try {
      const ips = await dns.resolve4(sub);
      if (ips && ips.length > 0) {
        foundSubdomains.set(sub, { ip: ips[0], cname: '', httpStatus: '', server: '', source: 'Active DNS' });
      }
    } catch {
      try {
        const cnames = await dns.resolveCname(sub);
        if (cnames && cnames.length > 0) {
          foundSubdomains.set(sub, { ip: 'CNAME-only', cname: cnames[0], httpStatus: '', server: '', source: 'Active DNS' });
        }
      } catch {}
    }
  });

  await Promise.all(probePromises);

  const subList = Array.from(foundSubdomains.keys()).sort();
  console.log(chalk.green(`\n[+] Discovered ${chalk.bold(subList.length)} unique subdomains! Beginning live service analysis...\n`));

  console.log(chalk.bold(' SUBDOMAIN                      IP / CNAME              HTTP STATUS   SERVER'));
  console.log(chalk.gray(' ---------                      ----------              -----------   ------'));

  const takeoverPatterns = [
    { service: 'GitHub Pages', domain: 'github.io' },
    { service: 'AWS S3', domain: 's3.amazonaws.com' },
    { service: 'Heroku', domain: 'herokuapp.com' },
    { service: 'Azure WebApp', domain: 'azurewebsites.net' },
    { service: 'Fastly', domain: 'fastly.net' },
    { service: 'Cloudfront', domain: 'cloudfront.net' },
    { service: 'Shopify', domain: 'myshopify.com' }
  ];

  let liveCount = 0;
  const analysisResults = [];

  for (const sub of subList) {
    const info = foundSubdomains.get(sub);

    // Resolve CNAME if not yet known
    if (!info.cname) {
      try {
        const cnames = await dns.resolveCname(sub);
        if (cnames && cnames.length > 0) info.cname = cnames[0];
      } catch {}
    }

    // HTTP / HTTPS Web Probe
    let statusText = chalk.dim('No Web');
    let serverText = '';
    let takeoverRisk = false;

    try {
      const probeRes = await new Promise((resolve) => {
        const req = https.request({
          hostname: sub,
          port: 443,
          path: '/',
          method: 'HEAD',
          timeout: 2000,
          headers: { 'User-Agent': 'AstaSec-Recon/2.0' }
        }, (res) => {
          resolve({ code: res.statusCode, server: res.headers['server'] || '' });
        });
        req.on('error', () => {
          const reqHttp = http.request({
            hostname: sub,
            port: 80,
            path: '/',
            method: 'HEAD',
            timeout: 2000,
            headers: { 'User-Agent': 'AstaSec-Recon/2.0' }
          }, (resHttp) => {
            resolve({ code: resHttp.statusCode, server: resHttp.headers['server'] || '' });
          });
          reqHttp.on('error', () => resolve(null));
          reqHttp.on('timeout', () => reqHttp.destroy());
          reqHttp.end();
        });
        req.on('timeout', () => req.destroy());
        req.end();
      });

      if (probeRes) {
        liveCount++;
        const code = probeRes.code;
        serverText = probeRes.server ? probeRes.server.substring(0, 16) : '';
        if (code >= 200 && code < 300) statusText = chalk.green(`${code} OK`);
        else if (code >= 300 && code < 400) statusText = chalk.cyan(`${code} Redirect`);
        else if (code === 401 || code === 403) statusText = chalk.yellow(`${code} Forbidden`);
        else if (code === 404) statusText = chalk.red(`${code} Not Found`);
        else statusText = chalk.magenta(`${code}`);
      }
    } catch {}

    // Check for CNAME Takeover risk
    if (info.cname) {
      for (const p of takeoverPatterns) {
        if (info.cname.includes(p.domain)) {
          if (statusText.includes('404') || info.ip === 'CNAME-only') {
            takeoverRisk = true;
          }
        }
      }
    }

    const targetDisplay = info.cname ? `-> ${info.cname}` : info.ip;
    const subCol = sub.length > 30 ? sub.substring(0, 27) + '...' : sub;
    const targetCol = targetDisplay.length > 22 ? targetDisplay.substring(0, 19) + '...' : targetDisplay;

    console.log(
      ` ${chalk.white.bold(subCol.padEnd(31))}` +
      `${chalk.cyan(targetCol.padEnd(24))}` +
      `${statusText.padEnd(20)}` +
      `${chalk.dim(serverText)}` +
      (takeoverRisk ? ` ${chalk.bgRed.white.bold(' TAKEOVER RISK ')}` : '')
    );

    analysisResults.push({
      subdomain: sub,
      ip: info.ip,
      cname: info.cname,
      takeoverRisk
    });
  }

  console.log(chalk.gray('----------------------------------------------------------------'));
  console.log(`[*] Reconnaissance complete: ${chalk.green.bold(subList.length)} subdomains identified (${liveCount} web services active).`);

  if (!targetDomain) {
    const saveFile = await confirm({
      message: 'Export discovered subdomains to a file (subdomains.txt)?',
      default: false
    });

    if (saveFile) {
      const outData = subList.join('\n');
      await fs.writeFile(path.join(process.cwd(), 'subdomains.txt'), outData, 'utf8');
      console.log(chalk.green(`[+] Exported ${subList.length} subdomains to subdomains.txt\n`));
    }

    await pause();
  }
}

// ==========================================
// TOOL 4: Port Scanner (Nmap style)
// ==========================================
async function runPortScanner(targetHost = null) {
  console.log(chalk.bold('\n--- [4] Host & Port Connectivity Scanner (Nmap-Style) ---'));
  let host = targetHost;
  if (!host) {
    host = await input({
      message: 'Enter target host to scan (e.g. scanme.nmap.org, 127.0.0.1):',
      default: 'scanme.nmap.org'
    });
  }
  host = host.trim().replace(/^https?:\/\//, '').split('/')[0];

  let ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443];
  if (!targetHost) {
    const portSelection = await select({
      message: 'Select Port Range to Scan:',
      choices: [
        { name: 'Common Web Ports (80, 443, 8080, 8443, 3000, 5000, 8000)', value: 'web' },
        { name: 'Top 18 Critical Network Ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432...)', value: 'critical' },
        { name: 'Custom Port List', value: 'custom' }
      ]
    });

    if (portSelection === 'web') {
      ports = [80, 443, 8080, 8443, 3000, 5000, 8000];
    } else if (portSelection === 'custom') {
      const customInput = await input({
        message: 'Enter comma-separated ports (e.g. 22, 80, 443, 8080):',
        default: '22, 80, 443'
      });
      ports = customInput.split(',').map((p) => parseInt(p.trim())).filter((p) => !isNaN(p) && p > 0 && p <= 65535);
    }
  }

  console.log(chalk.cyan(`\n[*] Resolving target: ${host}...`));
  let ip = '';
  try {
    const addresses = await dns.resolve4(host);
    ip = addresses[0];
    console.log(chalk.green(`[+] Target IP : ${ip}\n`));
  } catch (err) {
    console.log(chalk.red(`[!] Host Resolution Error: ${err.message}`));
    await pause();
    return;
  }

  console.log(chalk.bold(' PORT       STATE    SERVICE         LATENCY'));
  console.log(chalk.gray(' ----       -----    -------         -------'));

  const serviceNames = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3000: 'DevServer',
    3306: 'MySQL', 3389: 'RDP', 5000: 'Flask/Dev', 5432: 'PostgreSQL',
    8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
  };

  let openCount = 0;

  for (const port of ports) {
    const result = await new Promise((resolve) => {
      const start = Date.now();
      const socket = new net.Socket();
      socket.setTimeout(600);

      socket.on('connect', () => {
        const ms = Date.now() - start;
        socket.destroy();
        resolve({ open: true, ms });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ open: false });
      });

      socket.on('error', () => {
        socket.destroy();
        resolve({ open: false });
      });

      socket.connect(port, ip);
    });

    if (result.open) {
      openCount++;
      const svc = serviceNames[port] || 'unknown';
      console.log(
        ` ${chalk.white((port + '/tcp').padEnd(10))}` +
        `${chalk.green.bold('OPEN'.padEnd(9))}` +
        `${chalk.cyan(svc.padEnd(16))}` +
        `${chalk.yellow(result.ms + ' ms')}`
      );
    }
  }

  console.log(chalk.gray('----------------------------------------------------------------'));
  console.log(`[*] Scan complete: ${chalk.bold(openCount)} open port(s) detected out of ${ports.length} scanned.\n`);

  if (!targetHost) await pause();
}

// ==========================================
// TOOL 5: DNS Lookup & Record Inspector
// ==========================================
async function runDnsResolver(targetDomain = null) {
  console.log(chalk.bold('\n--- [5] DNS Resolver & Record Inspector ---'));
  let domain = targetDomain;
  if (!domain) {
    domain = await input({
      message: 'Enter domain name to query (e.g. cloudflare.com, google.com):',
      default: 'cloudflare.com'
    });
  }
  domain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];

  console.log(chalk.cyan(`\n[*] Querying DNS records for: ${chalk.bold(domain)}...\n`));

  try {
    const aRecords = await dns.resolve4(domain);
    console.log(`  ${chalk.green.bold('[A Records]    ')} ${aRecords.join(', ')}`);
  } catch {}

  try {
    const aaaaRecords = await dns.resolve6(domain);
    console.log(`  ${chalk.cyan.bold('[AAAA Records] ')} ${aaaaRecords.join(', ')}`);
  } catch {}

  try {
    const mxRecords = await dns.resolveMx(domain);
    const mxStr = mxRecords.map((m) => `${m.exchange} (Priority: ${m.priority})`).join(' | ');
    console.log(`  ${chalk.yellow.bold('[MX Records]   ')} ${mxStr}`);
  } catch {}

  try {
    const txtRecords = await dns.resolveTxt(domain);
    console.log(`  ${chalk.magenta.bold('[TXT Records]  ')}`);
    txtRecords.forEach((t) => console.log(`     -> ${t.join(' ')}`));
  } catch {}

  try {
    const nsRecords = await dns.resolveNs(domain);
    console.log(`  ${chalk.blue.bold('[NS Records]   ')} ${nsRecords.join(', ')}`);
  } catch {}

  try {
    const cnameRecords = await dns.resolveCname(domain);
    console.log(`  ${chalk.white.bold('[CNAME]        ')} ${cnameRecords.join(', ')}`);
  } catch {}

  console.log('');
  if (!targetDomain) await pause();
}

// ==========================================
// TOOL 6: IP Geolocation & Threat Intel
// ==========================================
async function runGeoIpLookup() {
  console.log(chalk.bold('\n--- [6] IP Geolocation & WHOIS Intelligence ---'));
  let target = await input({
    message: 'Enter IP address or domain name (e.g. 1.1.1.1, github.com):',
    default: '1.1.1.1'
  });
  target = target.trim().replace(/^https?:\/\//, '').split('/')[0];

  let ip = target;
  if (!net.isIP(target)) {
    try {
      const addrs = await dns.resolve4(target);
      ip = addrs[0];
      console.log(chalk.green(`[+] Domain resolved to IP: ${ip}`));
    } catch (err) {
      console.log(chalk.red(`[!] Could not resolve domain: ${err.message}`));
      await pause();
      return;
    }
  }

  console.log(chalk.cyan(`\n[*] Fetching Geolocation & ASN intelligence for ${ip}...`));

  try {
    const data = await new Promise((resolve, reject) => {
      http.get(`http://ip-api.com/json/${ip}`, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
        });
      }).on('error', reject);
    });

    if (data.status === 'success') {
      console.log(chalk.gray('----------------------------------------------------------------'));
      console.log(`  Target IP        : ${chalk.bold(data.query)}`);
      console.log(`  Country          : ${chalk.green(data.country)} (${data.countryCode})`);
      console.log(`  Region / City    : ${data.regionName}, ${data.city} (${data.zip || 'N/A'})`);
      console.log(`  Coordinates      : Lat ${data.lat}, Lon ${data.lon}`);
      console.log(`  ISP Provider     : ${chalk.cyan(data.isp)}`);
      console.log(`  Organization     : ${chalk.yellow(data.org)}`);
      console.log(`  Autonomous System: ${chalk.magenta(data.as)}`);
      console.log(`  Timezone         : ${data.timezone}`);
      console.log(chalk.gray('----------------------------------------------------------------\n'));
    } else {
      console.log(chalk.red(`[!] API Error: ${data.message}`));
    }
  } catch (err) {
    console.log(chalk.red(`[!] Lookup Request Failed: ${err.message}`));
  }

  await pause();
}

// ==========================================
// TOOL 7: Network Interfaces
// ==========================================
async function listInterfaces() {
  console.log(chalk.bold('\n--- [7] Local Network Interfaces & Addresses ---'));
  const ifaces = os.networkInterfaces();

  for (const [name, addrs] of Object.entries(ifaces)) {
    console.log(`\n  ${chalk.cyan.bold(name)}:`);
    for (const a of addrs) {
      const familyColor = a.family === 'IPv4' ? chalk.green : chalk.blue;
      console.log(`    - ${familyColor(a.family.padEnd(5))} Address: ${chalk.bold(a.address)} | MAC: ${a.mac} | Internal: ${a.internal}`);
    }
  }

  console.log('');
  await pause();
}

// ==========================================
// TOOL 8: Intercepting HTTP/S Proxy & Web Dashboard
// ==========================================
async function runProxyModule() {
  console.log(chalk.bold('\n--- [8] Intercepting HTTP/S Proxy & Angular Web Dashboard (Burp-Style) ---'));
  console.log(chalk.cyan('[*] Initializing Dynamic CA & MITM Proxy Engine...'));

  const proxy = new ProxyEngine({
    proxyPort: 8080,
    dashboardPort: 8081
  });

  const res = await proxy.start();

  console.log(chalk.green.bold('\n[+] ASTA-SEC Intercepting Proxy & Dashboard Active!'));
  console.log(`  - ${chalk.yellow('HTTP/HTTPS Proxy Port')} : ${chalk.bold('http://127.0.0.1:' + res.proxyPort)}`);
  console.log(`  - ${chalk.cyan('Angular Web Dashboard')} : ${chalk.bold.underline('http://127.0.0.1:' + res.dashboardPort)}`);
  console.log(`  - ${chalk.magenta('Root CA Certificate')}   : ${chalk.bold(res.caCertPath)}`);
  console.log(`  - ${chalk.blue('Download Root CA')}      : ${chalk.bold.underline('http://127.0.0.1:' + res.dashboardPort + '/cert')}\n`);
  console.log(chalk.dim('Set browser proxy to 127.0.0.1:8080. Press Enter to stop the proxy...\n'));

  // Automatically attempt to open the dashboard in browser on Windows
  try {
    spawn('cmd.exe', ['/c', 'start', `http://127.0.0.1:${res.dashboardPort}`], { detached: true, stdio: 'ignore' }).unref();
  } catch {}

  await pause();
  proxy.stop();
  console.log(chalk.yellow('[*] Proxy stopped.\n'));
}

// ==========================================
// TOOL 9: JWT Token Inspector & Security Analyzer
// ==========================================
async function runJwtAnalyzer(rawToken = null) {
  console.log(chalk.bold('\n--- [9] JWT Token Inspector & Security Analyzer (Phase 3) ---'));
  let token = rawToken;
  if (!token) {
    token = await input({
      message: 'Enter raw JWT token (header.payload.signature):'
    });
  }

  token = (token || '').trim();
  if (!token) {
    console.log(chalk.red('[!] No token provided.'));
    if (!rawToken) await pause();
    return;
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    console.log(chalk.red('[!] Invalid JWT Structure: Token must contain exactly 3 dot-separated parts (header.payload.signature).'));
    if (!rawToken) await pause();
    return;
  }

  function b64UrlDecode(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return Buffer.from(b64, 'base64').toString('utf8');
  }

  let headerObj = null;
  let payloadObj = null;
  const warnings = [];

  // Parse Header
  try {
    const hdrJson = b64UrlDecode(parts[0]);
    headerObj = JSON.parse(hdrJson);
    if (headerObj.alg && headerObj.alg.toLowerCase() === 'none') {
      warnings.push('CRITICAL: "alg: none" vulnerability! Token allows unsigned execution without cryptographic verification.');
    } else if (headerObj.alg && headerObj.alg.toUpperCase() === 'HS256') {
      warnings.push('INFO: Symmetric HMAC (HS256) signature. Check for weak secrets or algorithm confusion attacks.');
    }
  } catch (e) {
    warnings.push(`Header parsing error: ${e.message}`);
  }

  // Parse Payload
  try {
    const pldJson = b64UrlDecode(parts[1]);
    payloadObj = JSON.parse(pldJson);
    if (!payloadObj.exp) {
      warnings.push('WARNING: No Expiration Claim ("exp") found. The token has unlimited lifetime.');
    }
  } catch (e) {
    warnings.push(`Payload parsing error: ${e.message}`);
  }

  console.log(chalk.magenta.bold('\n[+] HEADER:'));
  console.log(chalk.dim(JSON.stringify(headerObj, null, 2)));

  console.log(chalk.cyan.bold('\n[+] PAYLOAD (CLAIMS):'));
  console.log(chalk.white(JSON.stringify(payloadObj, null, 2)));

  console.log(chalk.blue.bold('\n[+] SIGNATURE:'));
  console.log(chalk.dim(parts[2]));

  // Expiration Analysis
  if (payloadObj && payloadObj.exp) {
    const expSec = Number(payloadObj.exp);
    const nowSec = Math.floor(Date.now() / 1000);
    const expDate = new Date(expSec * 1000);
    const isExpired = nowSec > expSec;

    console.log(chalk.bold('\n--- Expiration Status ---'));
    if (isExpired) {
      const minsAgo = Math.floor((nowSec - expSec) / 60);
      console.log(chalk.red.bold(`  [EXPIRED] Token expired ${minsAgo} minutes ago (${expDate.toUTCString()})`));
    } else {
      const minsLeft = Math.floor((expSec - nowSec) / 60);
      console.log(chalk.green.bold(`  [ACTIVE] Token is valid for ${minsLeft} more minutes (Expires: ${expDate.toUTCString()})`));
    }
  }

  if (warnings.length > 0) {
    console.log(chalk.yellow.bold('\n--- Security Findings & Advisories ---'));
    for (const w of warnings) {
      if (w.startsWith('CRITICAL')) {
        console.log(`  ${chalk.red.bold('[!] ' + w)}`);
      } else if (w.startsWith('WARNING')) {
        console.log(`  ${chalk.yellow.bold('[!] ' + w)}`);
      } else {
        console.log(`  ${chalk.cyan('[i] ' + w)}`);
      }
    }
  }

  console.log('');
  if (!rawToken) await pause();
}

// ==========================================
// TOOL 10: Penetration Test Report Generator
// ==========================================
async function runReportGenerator() {
  console.log(chalk.bold('\n--- [10] OWASP WSTG Penetration Test Report Generator (Phase 5) ---'));

  const targetName = await input({
    message: 'Enter Target Application / Company Name:',
    default: 'Target Web Application'
  });

  const scopeInput = await input({
    message: 'Enter in-scope domains (comma-separated):',
    default: 'target.com, *.target.com'
  });

  const scope = scopeInput.split(',').map(s => s.trim()).filter(Boolean);

  const outputPath = await input({
    message: 'Output Markdown filename:',
    default: 'pentest-report.md'
  });

  console.log(chalk.cyan(`\n[*] Compiling penetration testing assessment report for ${chalk.bold(targetName)}...`));

  const sampleIssues = [
    {
      ruleId: 'SEC-001',
      name: 'Exposed Cloud Access Keys',
      severity: 'critical',
      confidence: 'certain',
      url: `https://${scope[0] || 'target.com'}/config.json`,
      host: scope[0] || 'target.com',
      method: 'GET',
      description: 'Publicly readable cloud service credentials detected in web application responses.',
      evidence: 'AKIAIOSFODNN7EXAMPLE',
      remediation: 'Immediately invalidate the exposed credentials and move secrets to a secure Vault/KMS.'
    },
    {
      ruleId: 'SEC-002',
      name: 'Missing Secure Flag on Session Cookies',
      severity: 'medium',
      confidence: 'certain',
      url: `https://${scope[0] || 'target.com'}/login`,
      host: scope[0] || 'target.com',
      method: 'POST',
      description: 'Session authentication cookies transmitted without the Secure or HttpOnly attributes.',
      evidence: 'Set-Cookie: session_id=...; Path=/',
      remediation: 'Configure Set-Cookie with Secure, HttpOnly, and SameSite=Lax attributes.'
    },
    {
      ruleId: 'SEC-003',
      name: 'Permissive Cross-Origin Resource Sharing (CORS)',
      severity: 'high',
      confidence: 'firm',
      url: `https://${scope[0] || 'target.com'}/api/user`,
      host: scope[0] || 'target.com',
      method: 'GET',
      description: 'Access-Control-Allow-Origin header set to wildcard with Access-Control-Allow-Credentials: true.',
      evidence: 'Access-Control-Allow-Origin: *',
      remediation: 'Restrict allowed CORS origins to trusted domains and disallow wildcard origins when credentials are supported.'
    }
  ];

  const report = ReportGenerator.generateMarkdown({
    targetName,
    scope,
    issues: sampleIssues,
    historyCount: 184,
    intruderResults: []
  });

  await fs.writeFile(path.resolve(process.cwd(), outputPath), report, 'utf8');

  console.log(chalk.green.bold(`\n[+] Penetration Testing Report generated successfully!`));
  console.log(`  File location: ${chalk.underline(path.resolve(process.cwd(), outputPath))}`);
  console.log(chalk.gray('  Adheres to: OWASP Web Security Testing Guide (WSTG v4.2) / PTES\n'));

  await pause();
}

// ==========================================
// TOOL 11: HTTP Concurrency & Rate-Limiting Resilience Benchmark
// ==========================================
async function runRateLimitBenchmark(targetUrl = null) {
  console.log(chalk.bold('\n--- [11] HTTP Concurrency & Rate-Limiting Resilience Benchmark ---'));
  console.log(chalk.dim('Simulates concurrent traffic bursts to evaluate server capacity, latency, and HTTP 429 rate-limiting defenses.'));

  let urlStr = targetUrl;
  if (!urlStr) {
    urlStr = await input({
      message: 'Enter target HTTP/HTTPS URL to benchmark (e.g. http://127.0.0.1:8080 or https://httpbin.org/get):',
      default: 'https://httpbin.org/get'
    });
  }

  urlStr = urlStr.trim();
  if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
    urlStr = 'http://' + urlStr;
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    console.log(chalk.red(`[!] Invalid URL: ${e.message}`));
    if (!targetUrl) await pause();
    return;
  }

  let totalReqs = 50;
  let concurrency = 5;

  if (!targetUrl) {
    const totalInput = await input({
      message: 'Total requests to send:',
      default: '50'
    });
    totalReqs = parseInt(totalInput) || 50;

    const concurrencyInput = await input({
      message: 'Concurrent workers (threads):',
      default: '5'
    });
    concurrency = Math.min(parseInt(concurrencyInput) || 5, 50);
  }

  console.log(chalk.cyan(`\n[*] Initiating benchmark against ${chalk.bold(urlStr)}...`));
  console.log(`    Total Requests: ${totalReqs} | Concurrency: ${concurrency}\n`);

  const client = parsed.protocol === 'https:' ? https : http;
  const latencies = [];
  const statusCounts = {};
  let completed = 0;
  let inFlight = 0;
  let reqIndex = 0;
  const startTime = Date.now();

  await new Promise((resolve) => {
    function launchNext() {
      if (completed >= totalReqs) {
        resolve();
        return;
      }

      while (inFlight < concurrency && reqIndex < totalReqs) {
        inFlight++;
        reqIndex++;
        const reqStart = Date.now();

        const req = client.request(parsed, {
          method: 'GET',
          headers: {
            'User-Agent': 'ASTA-SEC-Benchmark/2.0',
            'Accept': '*/*'
          },
          timeout: 8000
        }, (res) => {
          res.on('data', () => {});
          res.on('end', () => {
            const duration = Date.now() - reqStart;
            latencies.push(duration);
            const code = res.statusCode || 0;
            statusCounts[code] = (statusCounts[code] || 0) + 1;
            completed++;
            inFlight--;
            launchNext();
          });
        });

        req.on('error', () => {
          const duration = Date.now() - reqStart;
          latencies.push(duration);
          statusCounts['ERROR'] = (statusCounts['ERROR'] || 0) + 1;
          completed++;
          inFlight--;
          launchNext();
        });

        req.on('timeout', () => {
          req.destroy(new Error('Timeout'));
        });

        req.end();
      }
    }

    launchNext();
  });

  const totalTimeMs = Date.now() - startTime;
  const rps = ((completed / (totalTimeMs / 1000 || 0.001))).toFixed(2);

  latencies.sort((a, b) => a - b);
  const minLatency = latencies[0] || 0;
  const maxLatency = latencies[latencies.length - 1] || 0;
  const avgLatency = latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;
  const p95Latency = latencies[Math.floor(latencies.length * 0.95)] || maxLatency;

  console.log(chalk.bold('\n--- Benchmark & Resilience Results ---'));
  console.log(`  Completed Requests: ${chalk.bold(completed)} in ${(totalTimeMs / 1000).toFixed(2)}s`);
  console.log(`  Throughput Rate   : ${chalk.green.bold(rps + ' requests/sec')}`);
  console.log(`  Latency (Min/Avg) : ${minLatency} ms / ${avgLatency} ms`);
  console.log(`  Latency (P95/Max) : ${p95Latency} ms / ${maxLatency} ms`);

  console.log(chalk.bold('\n--- HTTP Status Distribution ---'));
  for (const [code, count] of Object.entries(statusCounts)) {
    if (code === '200' || code.startsWith('2')) {
      console.log(`  ${chalk.green.bold(`[HTTP ${code}]`)} ${count} requests (${Math.round(count / completed * 100)}%)`);
    } else if (code === '429') {
      console.log(`  ${chalk.yellow.bold(`[HTTP 429 Too Many Requests]`)} ${count} requests (Defensive Rate-Limiter Triggered)`);
    } else if (code.startsWith('4')) {
      console.log(`  ${chalk.cyan.bold(`[HTTP ${code}]`)} ${count} requests`);
    } else {
      console.log(`  ${chalk.red.bold(`[${code}]`)} ${count} requests`);
    }
  }

  console.log(chalk.gray('\n----------------------------------------------------------------'));
  if (statusCounts['429']) {
    console.log(chalk.green(`[+] Rate Limiting Active: Target server correctly throttled ${statusCounts['429']} requests via HTTP 429.`));
  } else if (statusCounts['500'] || statusCounts['502'] || statusCounts['503']) {
    console.log(chalk.red(`[!] Server Instability Detected: Received 5xx error responses under concurrency.`));
  } else {
    console.log(chalk.cyan(`[*] Resilience Succeeded: Server sustained all requests without rate-limiting drops or 5xx faults.`));
  }
  console.log(chalk.gray('----------------------------------------------------------------\n'));

  if (!targetUrl) await pause();
}

// ==========================================
// TOOL 12: Parameter & Route Fuzzer (Intruder Engine)
// ==========================================
async function runIntruderFuzzer(targetUrl = null) {
  console.log(chalk.bold('\n--- [12] Parameter & Route Fuzzer (Intruder Engine) ---'));
  let urlStr = targetUrl;
  if (!urlStr) {
    urlStr = await input({
      message: 'Enter target URL with §FUZZ§ marker (e.g. https://httpbin.org/get?user=§FUZZ§):',
      default: 'https://httpbin.org/get?user=§FUZZ§'
    });
  }

  const intruder = new IntruderEngine();
  const presets = intruder.getPresets();

  const presetChoice = await select({
    message: 'Select Payload Preset to test:',
    choices: [
      { name: 'Common Admin/API Paths (common_paths)', value: 'common_paths' },
      { name: 'SQL Injection Vectors (sqli_vectors)', value: 'sqli_vectors' },
      { name: 'XSS Injection Vectors (xss_vectors)', value: 'xss_vectors' },
      { name: 'Directory & Path Traversal (path_traversal)', value: 'path_traversal' },
      { name: 'Sequential Numbers (1-25)', value: 'numbers_1_25' }
    ]
  });

  const payloads = presets[presetChoice] || ['admin', 'test'];

  console.log(chalk.cyan(`\n[*] Launching Intruder attack against: ${chalk.bold(urlStr)}...`));
  console.log(chalk.gray(`    Total Payloads: ${payloads.length}\n`));

  console.log(chalk.bold(' #   PAYLOAD                      STATUS   LENGTH    TIME    ANOMALY'));
  console.log(chalk.gray(' -   -------                      ------   ------    ----    -------'));

  const parsedBase = new URL(intruder.replaceMarkers(urlStr, 'baseline'));
  const client = parsedBase.protocol === 'https:' ? https : http;

  for (let i = 0; i < payloads.length; i++) {
    const payload = payloads[i];
    const target = intruder.replaceMarkers(urlStr, payload);
    const parsed = new URL(target);

    const start = Date.now();
    const result = await new Promise((resolve) => {
      const req = client.request(parsed, {
        method: 'GET',
        headers: { 'User-Agent': 'ASTA-SEC-Intruder/2.0' },
        timeout: 4000
      }, (res) => {
        let len = 0;
        res.on('data', chunk => len += chunk.length);
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            length: len,
            durationMs: Date.now() - start
          });
        });
      });
      req.on('error', () => resolve({ status: 0, length: 0, durationMs: Date.now() - start }));
      req.on('timeout', () => req.destroy());
      req.end();
    });

    const isAnomaly = result.status >= 500 || (result.status >= 200 && result.status < 300 && payload.includes("'"));
    const pCol = payload.length > 26 ? payload.substring(0, 23) + '...' : payload;
    const statusCol = result.status ? result.status.toString() : 'ERR';
    const statusColor = result.status >= 200 && result.status < 300 ? chalk.green : chalk.yellow;

    console.log(
      ` ${chalk.dim((i + 1).toString().padEnd(4))}` +
      `${chalk.white(pCol.padEnd(28))}` +
      `${statusColor(statusCol.padEnd(9))}` +
      `${chalk.dim((result.length + ' B').padEnd(10))}` +
      `${chalk.dim((result.durationMs + ' ms').padEnd(8))}` +
      (isAnomaly ? chalk.bgMagenta.white.bold(' ANOMALY ') : '')
    );
  }

  console.log(chalk.gray('----------------------------------------------------------------'));
  console.log(chalk.green(`[+] Intruder run complete: Tested ${payloads.length} payloads.\n`));

  if (!targetUrl) await pause();
}

// ==========================================
// Main Interactive Dashboard Loop
// ==========================================
async function main() {
  const args = process.argv.slice(2);

  // Direct CLI shortcuts
  if (args.includes('--proxy')) {
    return runProxyModule();
  }
  if (args.includes('--jwt')) {
    const token = args[args.indexOf('--jwt') + 1] || null;
    return runJwtAnalyzer(token);
  }
  if (args.includes('--report')) {
    return runReportGenerator();
  }
  if (args.includes('--benchmark') || args.includes('--stress')) {
    const url = args[args.indexOf('--benchmark') + 1] || args[args.indexOf('--stress') + 1] || null;
    return runRateLimitBenchmark(url);
  }
  if (args.includes('--intruder') && args[args.indexOf('--intruder') + 1]) {
    return runIntruderFuzzer(args[args.indexOf('--intruder') + 1]);
  }
  if (args.includes('--subdomains') && args[args.indexOf('--subdomains') + 1]) {
    return runSubdomainAnalyzer(args[args.indexOf('--subdomains') + 1]);
  }
  if (args.includes('--audit') && args[args.indexOf('--audit') + 1]) {
    return runWebsiteAuditor(args[args.indexOf('--audit') + 1]);
  }
  if (args.includes('--scan') && args[args.indexOf('--scan') + 1]) {
    return runPortScanner(args[args.indexOf('--scan') + 1]);
  }
  if (args.includes('--dns') && args[args.indexOf('--dns') + 1]) {
    return runDnsResolver(args[args.indexOf('--dns') + 1]);
  }

  while (true) {
    printBanner();

    try {
      const choice = await select({
        message: 'Select Security Tool to Launch:',
        choices: [
          {
            name: '⚡  Intercepting HTTP/S Proxy & Angular Dashboard (Burp Suite-Style)',
            value: 'proxy'
          },
          {
            name: '🔑  JWT Token Inspector & Security Analyzer (Phase 3)',
            value: 'jwt'
          },
          {
            name: '📄  Penetration Test Report Generator (OWASP WSTG / PTES - Phase 5)',
            value: 'report'
          },
          {
            name: '🚀  HTTP Concurrency & Rate-Limiting Resilience Benchmark (Stress/Resilience)',
            value: 'benchmark'
          },
          {
            name: '🎯  Parameter & Route Fuzzing Engine (Intruder)',
            value: 'intruder'
          },
          {
            name: '📡  Live Packet Sniffer & Traffic Analyzer (libpcap / Npcap Engine)',
            value: 'sniffer'
          },
          {
            name: '🛡️   Website Security & OWASP Header Auditor (Nessus-Style)',
            value: 'auditor'
          },
          {
            name: '🔎  Subdomain Search & Attack Surface Analyzer (OSINT + DNS + Web)',
            value: 'subdomains'
          },
          {
            name: '🔍  Host & Port Connectivity Scanner (Nmap-Style)',
            value: 'portscan'
          },
          {
            name: '🌐  DNS Resolver & Domain Record Inspector',
            value: 'dns'
          },
          {
            name: '🌍  IP Geolocation & Threat Intelligence (WHOIS / GeoIP)',
            value: 'geoip'
          },
          {
            name: '🔌  List & Inspect Local Network Interfaces',
            value: 'ifaces'
          },
          {
            name: '❌  Exit Asta-Sec Suite',
            value: 'exit'
          }
        ]
      });

      if (choice === 'proxy') {
        await runProxyModule();
      } else if (choice === 'jwt') {
        await runJwtAnalyzer();
      } else if (choice === 'report') {
        await runReportGenerator();
      } else if (choice === 'benchmark') {
        await runRateLimitBenchmark();
      } else if (choice === 'intruder') {
        await runIntruderFuzzer();
      } else if (choice === 'sniffer') {
        await runSnifferModule();
      } else if (choice === 'auditor') {
        await runWebsiteAuditor();
      } else if (choice === 'subdomains') {
        await runSubdomainAnalyzer();
      } else if (choice === 'portscan') {
        await runPortScanner();
      } else if (choice === 'dns') {
        await runDnsResolver();
      } else if (choice === 'geoip') {
        await runGeoIpLookup();
      } else if (choice === 'ifaces') {
        await listInterfaces();
      } else if (choice === 'exit') {
        console.log(chalk.green('\n[*] Exiting ASTA-SEC Suite. Stay secure!\n'));
        process.exit(0);
      }
    } catch (err) {
      if (err.name === 'ExitPromptError') {
        console.log(chalk.green('\n[*] Goodbye!\n'));
        process.exit(0);
      }
      console.error(err);
      break;
    }
  }
}

main();
