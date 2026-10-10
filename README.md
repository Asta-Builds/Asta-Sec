# ASTA-SEC // Advanced Security & Network Suite

```
  █████╗ ███████╗████████╗ █████╗        ███████╗███████╗ ██████╗ 
 ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗       ██╔════╝██╔════╝██╔════╝ 
 ███████║███████╗   ██║   ███████║ █████╗███████╗█████╗  ██║      
 ██╔══██║╚════██║   ██║   ██╔══██║ ╚════╝╚════██║██╔══╝  ██║      
 ██║  ██║███████║   ██║   ██║  ██║       ███████║███████╗╚██████╗ 
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝       ╚══════╝╚══════╝ ╚═════╝ 
      [ ASTA-SEC // ADVANCED SECURITY & NETWORK SUITE v2.0 ]
```

An all-in-one modern cybersecurity suite featuring an **Antigravity CLI-style Interactive Menu**, **Live Packet Sniffing** (libpcap/Npcap), **Nessus-style Website Security Auditing**, **Subdomain Search & Attack Surface Recon**, **Nmap-style TCP Port Scanning**, and **DNS Decoding**.

---

## Suite Modules

### 1. 🖥️ Interactive Menu (Antigravity-Style)
Run `asta-sec` without arguments to launch an interactive menu dashboard where you choose modules:
```text
SELECT MODULE:
  [1] Live Packet Sniffer (libpcap / Npcap Engine)
  [2] Website Security & Header Auditor (OWASP / Nessus-style)
  [3] Subdomain Search & Attack Surface Recon (DNS + Web)
  [4] Host & Port Connectivity Scanner (Nmap-style)
  [5] DNS Resolver & Domain Query Tool
  [6] List & Inspect Available Network Interfaces
  [0] Exit Asta-Sec Suite
```

### 2. 🛡️ Website Security & Header Auditor (Nessus/OWASP-Style)
Performs deep HTTP security configuration assessments against web servers:
- **HSTS (`Strict-Transport-Security`):** Verifies HTTPS enforcement, max-age, and subdomains.
- **CSP (`Content-Security-Policy`):** Audits script whitelisting and XSS defenses.
- **Clickjacking Protection (`X-Frame-Options`):** Checks `DENY` or `SAMEORIGIN` rules.
- **MIME Sniffing (`X-Content-Type-Options`):** Confirms `nosniff` header.
- **Privacy Controls:** Audits `Referrer-Policy` and `Permissions-Policy`.
- **Information Disclosure:** Flags exposed `Server` version banners and `X-Powered-By` framework leaks.
- **Defensive Security Scoring:** Computes a 0–100 score and letter grade (A+ through F) with actionable remediation steps.

### 3. 🔎 Subdomain Search & Attack Surface Recon
Discovers subdomains and identifies dangling cloud infrastructure:
- **Passive OSINT Discovery:** Queries passive threat intelligence feeds to extract recorded subdomains.
- **Active DNS Probing:** Enumerates high-value enterprise subdomain prefixes (`api`, `dev`, `auth`, `admin`, `vpn`, `staging`, `portal`, `cdn`, `cloud`, `mail`, `corp`, `sso`, etc.).
- **HTTP/HTTPS Status Inspection:** Checks connectivity and returns HTTP response codes (`200 OK`, `301/302 Redirect`, `401/403 Forbidden`).
- **CNAME Subdomain Takeover Detection:** Detects dangling DNS aliases pointing to unclaimed cloud providers (GitHub Pages, Amazon S3, Heroku, Azure, Shopify, Fastly, Pantheon).
- **Export:** Export found targets to `subdomains.txt`.

### 4. 🔍 Port & Service Scanner (Nmap-Style)
Fast, non-blocking TCP connect scanner with sub-second timeouts and latency measurements:
- Probes common critical ports: HTTP (80), HTTPS (443), SSH (22), DNS (53), FTP (21), Telnet (23), SMTP (25), SMB (445), MySQL (3306), RDP (3389), PostgreSQL (5432), and HTTP-Alt (8080, 8443).
- Outputs open port status, recognized service name, and connection RTT latency in milliseconds.

### 5. ⚡ Intercepting HTTP/S Proxy & Angular Dashboard (Burp Suite-Style)
A full-featured developer & security auditing intercepting proxy with a modern Angular web dashboard:
- **HTTP / HTTPS MITM Proxy Core:** Listens on `127.0.0.1:8080`, terminates TLS via dynamic X.509 leaf certificate generation signed by a local Root CA (`asta-ca.crt`).
- **Interactive Interception (Intercept ON/OFF):** Pause pending HTTP/HTTPS requests in real-time, inspect headers and payloads, and **Forward**, **Drop**, or **Modify** before sending upstream.
- **Live HTTP History Table:** Full searchable, filterable transaction table with split-pane inspector for raw and parsed Request/Response headers and bodies.
- **Repeater Component:** Craft custom HTTP requests, fire them upstream, and inspect live responses with millisecond latency measurement.
- **Intruder / Parameter Fuzzing Engine:** Multi-threaded parameter fuzzing with configurable concurrency, payload markers (`§...§`), built-in attack vector presets (paths, SQLi, XSS, traversal, numbers), and real-time response length anomaly detection.
- **Passive Security Scanner (Issue Tracker):** Automatically inspects all incoming/outgoing traffic in real-time for exposed cloud credentials (AWS keys, GitHub tokens, private keys), insecure cookies (missing `HttpOnly`, `Secure`, `SameSite`), wildcard CORS with credentials, sensitive query parameters in GET requests, missing Clickjacking protection, missing HSTS, and framework version disclosure.
- **Decoder Utility:** Quick transformations for URL, Base64, Hex encoding/decoding.
- **Angular Dashboard:** Runs on `http://127.0.0.1:8081` with WebSocket streaming and Lucide SVG icons (zero emojis).

---

## CLI Options

```text
Usage:
  asta-sec [OPTIONS]
  asta-sec                     (Launches Interactive Menu mode)

Modes & Actions:
  -m, --menu                   Launch Antigravity-style Interactive Menu
  --proxy                      Launch Intercepting Proxy (127.0.0.1:8080) & Angular Dashboard (8081)
  --audit <url/host>           Audit website security headers (OWASP/Nessus style)
  --subdomains <domain>        Search subdomains & attack surface (DNS + Web)
  --scan <host>                Scan host ports & services (Nmap style)
  --dns <domain>               Query and decode domain DNS records
  -l, --list                   List all network interfaces and exit

Sniffer Options:
  -i, --interface <id|name>    Interface name or numeric index from --list
  -f, --filter <bpf>           BPF capture filter (default: "ip or arp")
  -c, --count <n>              Exit capture after N packets (0 = infinite)
  -w, --write <file>           Save captured packets to a PCAP dump file
  -v, --verbose                Show detailed packet headers & fields
  -x, --hex                    Display formatted Hex & ASCII payload dump
  --no-color                   Disable ANSI color output
  -h, --help                   Display help menu
```

---

## Quick Start Examples

### Interactive Mode
```powershell
.\asta-sec.bat
```

### Audit a Website's Security Posture (Nessus/OWASP)
```powershell
.\asta-sec.exe --audit github.com
.\asta-sec.exe --audit google.com
```

### Subdomain Search & Attack Surface Recon
```powershell
.\asta-sec.exe --subdomains github.com
.\asta-sec.exe --subdomains example.com
```

### Fast Port Scan on a Host (Nmap-Style)
```powershell
.\asta-sec.exe --scan scanme.nmap.org
.\asta-sec.exe --scan 127.0.0.1
```

### DNS Domain Lookup
```powershell
.\asta-sec.exe --dns cloudflare.com
```

### Live Packet Sniffing (Elevated via Launcher)
```powershell
# Sniff on interface 1 with DNS filter and Hex dump
.\asta-sec.bat -i 1 -f "udp port 53" -x

# Sniff HTTP traffic and save to traffic.pcap
.\asta-sec.bat -i 1 -f "tcp port 80" -w traffic.pcap
```

---

---

## Node.js Interactive CLI Installation

You can now run `asta-sec` globally from **any directory in any terminal** (PowerShell, Command Prompt, Windows Terminal, Git Bash, or Linux)!

### 1. Global Installation (Already linked on this system)
```bash
npm link
```
*(Or install globally: `npm install -g .`)*

### 2. Run from anywhere!
Simply type:
```bash
asta-sec
```

This presents the Antigravity-style interactive prompt with arrow key navigation:
```text
? Select Security Tool to Launch:
❯ 📡  Live Packet Sniffer & Traffic Analyzer (libpcap / Npcap Engine)
  🛡️   Website Security & OWASP Header Auditor (Nessus-Style)
  🔎  Subdomain Search & Attack Surface Analyzer (OSINT + DNS + Web)
  🔍  Host & Port Connectivity Scanner (Nmap-Style)
  🌐  DNS Resolver & Domain Record Inspector
  🌍  IP Geolocation & Threat Intelligence (WHOIS / GeoIP)
  🔌  List & Inspect Local Network Interfaces
  ❌  Exit Asta-Sec Suite
```

---

## Direct CLI Shortcuts

```bash
# Launch Intercepting Proxy & Angular Web Dashboard:
asta-sec --proxy

# Audit a website's security headers:
asta-sec --audit github.com

# Search subdomains and attack surface:
asta-sec --subdomains github.com

# Scan ports on a host:
asta-sec --scan scanme.nmap.org

# Lookup DNS records:
asta-sec --dns cloudflare.com
```

---

## Compilation (C++ Engine)

### Windows (using bundled w64devkit)
```powershell
.\w64devkit\bin\g++.exe -O2 -std=c++17 asta-sec.cpp -I.\npcap-sdk\Include -L.\npcap-sdk\Lib\x64 -lwpcap -lws2_32 -o asta-sec.exe
```

### Linux / WSL
```bash
make
```
