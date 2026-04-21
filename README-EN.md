# 🔐 VulnHunter Pro | Professional Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node](https://img.shields.io/badge/node-18%2B-brightgreen.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

**Enterprise-Grade Vulnerability Scanner for Bug Bounty Hunters**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Enterprise](#-enterprise-features) • [API](#-api-endpoints)

</div>

---

## 🎯 Overview

**VulnHunter Pro** is a professional, comprehensive security vulnerability scanner designed for Bug Bounty hunters and penetration testers. It combines the power of 21+ specialized scanning modules with an elegant interface and advanced enterprise features.

### 🌟 Why VulnHunter Pro?

- 🎯 **Built for Bug Bounty**: Compatible with Bugcrowd, HackerOne, Intigriti
- 📖 **PortSwigger-Style Reports**: Detailed exploitation steps for each vulnerability
- 🏢 **Enterprise Ready**: Multi-tenant, RBAC, SSO, Audit Logs
- 🌐 **Bilingual Support**: Full English and Arabic interface

---

## ✨ Features

### 🔍 Scanning Engines (21+ Modules)

| Module | Description | Severity |
|--------|-------------|----------|
| **XSSScanner** | Reflected, Stored, DOM-based XSS | High |
| **DOMXSSScanner** | DOM XSS scanning with Headless Browser | High |
| **SQLiScanner** | Error-based, Boolean, Time-based SQLi | Critical |
| **CSRFScanner** | Cross-Site Request Forgery | Medium |
| **SSRFScanner** | Server-Side Request Forgery | High |
| **LFIScanner** | Local File Inclusion & Path Traversal | High |
| **RCEScanner** | Remote Code Execution | Critical |
| **XXEScanner** | XML External Entity Injection | High |
| **IDORScanner** | Insecure Direct Object Reference | High |
| **OpenRedirectScanner** | Open Redirect vulnerabilities | Medium |
| **CORSScanner** | CORS Misconfiguration | Medium |
| **ClickjackingScanner** | X-Frame-Options & CSP | Low |
| **HeaderScanner** | Security Headers Analysis | Low |
| **CookieScanner** | Cookie Security Flags | Medium |
| **SSLScanner** | SSL/TLS Certificate Analysis | Medium |
| **AuthBypassScanner** | Authentication Bypass | Critical |
| **SensitiveDataScanner** | Exposed Secrets & API Keys | High |
| **DirectoryScanner** | Directory Traversal & Bruteforce | Medium |
| **SubdomainScanner** | Subdomain Enumeration | Info |
| **PortScanner** | Common Port Scanning | Info |
| **TechStackScanner** | Technology Detection | Info |

### 🛠️ Advanced Tools

| Tool | Description |
|------|-------------|
| **HeadlessCrawler** | Smart crawler with Puppeteer for SPA discovery |
| **WAFDetector** | Detection of 30+ WAF/CDN |
| **ScreenshotCapture** | Vulnerability screenshot capture |
| **OpenAPIImporter** | Import Swagger/OpenAPI specs |
| **RobotsParser** | Parse robots.txt and sitemap.xml |
| **ScanScheduler** | Schedule automated scans |

### 📊 Report Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **Walkthrough PDF** | 📖 PortSwigger-style exploitation guide | Bug Bounty Reports |
| **PDF** | Professional PDF report | Clients |
| **HTML** | Interactive report | Presentation |
| **JSON** | Raw data | Integration |
| **Markdown** | Documentation | GitHub |
| **SARIF** | Static Analysis Results | CI/CD Integration |

---

## 🏢 Enterprise Features

### 🔐 Security & Access Control

| Feature | Description |
|---------|-------------|
| **RBAC** | 6 roles: Super Admin, Admin, Manager, Analyst, Viewer, API |
| **SSO** | SAML 2.0 and OpenID Connect |
| **MFA** | Multi-Factor Authentication |
| **Audit Logs** | 50+ event types with full tracking |

### 👥 Multi-Tenancy

| Plan | Limit | Features |
|------|-------|----------|
| **FREE** | 10 scans/month | Basic |
| **PRO** | 100 scans/month | API + Reports |
| **ENTERPRISE** | Unlimited | Everything + SSO |

### 🔗 Integrations

| Platform | Features |
|----------|----------|
| **Jira** | Automatic ticket creation |
| **GitHub** | Issues + Security Advisories |
| **Slack** | Real-time notifications |

### 🔧 Additional

| Feature | Description |
|---------|-------------|
| **Worker Manager** | Distributed scanning across multiple workers |
| **Credential Vault** | AES-256-GCM encrypted storage |
| **Plugin System** | Extensible plugin architecture |

---

## 🚀 Installation

### Requirements
- Node.js 18+
- npm or yarn
- Chrome/Chromium (for Headless Browser)

### Quick Installation

```bash
# Clone the repository
git clone <repository-url>
cd "Auto vulnerability tester"

# Install all packages
npm run install:all

# Or separately:
cd server && npm install
cd ../client && npm install
```

### Environment Setup

```bash
# Create .env file in server folder
cp server/.env.example server/.env

# Edit the variables
PORT=3001
CLIENT_URL=http://localhost:5173
JWT_SECRET=your-secret-key
ENCRYPTION_KEY=your-32-char-key
```

---

## 💻 Running

### Development Mode

```bash
# Run server and client together
npm run dev

# Or separately:
# Terminal 1 - Server
cd server && npm run dev

# Terminal 2 - Client
cd client && npm run dev
```

### Production Mode

```bash
# Build the client
cd client && npm run build

# Run the server
cd server && npm start
```

### Access
- **Frontend**: http://localhost:5173
- **API**: http://localhost:3001
- **Health Check**: http://localhost:3001/api/health

---

## 📖 Usage

### 1️⃣ Basic Scanning

1. Open the interface at `http://localhost:5173`
2. Enter the target website URL
3. Choose scan type (Quick/Standard/Deep)
4. Click **"Start Scan Now"**
5. Monitor progress in real-time

### 2️⃣ Exporting Reports

After scan completion:

| Button | Output |
|--------|--------|
| **Walkthrough** | 📖 PDF with detailed exploitation steps |
| **PDF** | Standard PDF report |
| **HTML** | Interactive HTML report |
| **JSON** | Raw data |
| **SARIF** | For CI/CD pipelines |

### 3️⃣ Ownership Verification

For full scanning, you must prove site ownership:
- **HTTP**: Add file `.well-known/vulnhunter.txt`
- **DNS**: Add TXT record

---

## 🛡️ Bug Bounty Safety System

Comprehensive system to maintain compliance with Bug Bounty program rules:

### 📋 Scope Management

| Feature | Description |
|---------|-------------|
| **In-Scope Domains** | Define allowed domains with wildcards (`*.example.com`) |
| **Out-of-Scope Paths** | Exclude specific paths (`/admin/*`, `/logout`) |
| **IP Ranges** | Define allowed IP ranges |
| **Ports & Protocols** | Restrict ports and protocols |
| **Third-Party Blacklist** | Auto-block 40+ CDN/Auth providers |

### 🚦 Safety Controls

| Feature | Description | Default |
|---------|-------------|---------|
| **Global RPS** | Max requests/second | 3 |
| **Per-Host RPS** | Requests per host | 1 |
| **Max URLs** | URLs scanned limit | 200 |
| **Max Depth** | Crawl depth | 2 |
| **Safe Mode** | GET/HEAD only, no dangerous payloads | ✅ |
| **Anti-DoS** | Auto backoff on 429/503 | ✅ |

### 🎯 Program Profiles

Ready-made templates for different platforms:

```javascript
// Use a ready template
bountySystem.loadTemplate('hackerone-standard');

// Available templates:
- bugcrowd-standard   // Very safe
- hackerone-standard  // Balanced
- intigriti-standard  // Balanced
- aggressive          // Private sites only
- minimal             // Headers check only
```

### ✅ Preflight Checks

Automatic checks before starting any scan:

1. ✅ URL validation
2. ✅ Scope verification
3. ✅ Safety settings check
4. ✅ Allowed time window verification
5. ✅ User confirmations required

### 🛑 Kill Switch

Instant emergency stop for all operations:

| Feature | Description |
|---------|-------------|
| **Activate** | Stop all scans immediately |
| **AbortController** | Cancel all pending requests |
| **Worker Stop** | Stop all workers |
| **Resume** | Resume after safety confirmation |

### 🌐 Bug Bounty API Endpoints

```
GET  /api/bounty/status        - System status
POST /api/bounty/enable        - Enable system
POST /api/bounty/disable       - Disable system
POST /api/bounty/scope/in-scope    - Set allowed domains
POST /api/bounty/scope/out-of-scope - Set blocked paths
POST /api/bounty/safety/rate-limits - Modify rate limiting
POST /api/bounty/profiles/load/:id  - Load profile
POST /api/bounty/preflight     - Execute preflight check
POST /api/bounty/kill-switch/activate   - Activate Kill Switch
POST /api/bounty/kill-switch/deactivate - Deactivate Kill Switch
```

---

## 🔧 API Endpoints

### Basic Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start new scan |
| `GET` | `/api/scan/:id` | Get scan status |
| `POST` | `/api/scan/:id/stop` | Stop scan |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scan/:id/report?format=pdf` | PDF report |
| `GET` | `/api/scan/:id/walkthrough` | 📖 Walkthrough PDF |
| `GET` | `/api/scan/:id/sarif` | SARIF export |
| `POST` | `/api/walkthrough/generate` | Generate walkthrough from JSON |

### Scheduling

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/schedules` | Get schedules |
| `POST` | `/api/schedules` | Create new schedule |
| `DELETE` | `/api/schedules/:id` | Delete schedule |

### OpenAPI

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/openapi/import` | Import OpenAPI spec |
| `POST` | `/api/openapi/discover` | Auto-discover spec |

### Enterprise

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/enterprise/auth/login` | Login |
| `GET` | `/api/enterprise/tenants` | Manage tenants |
| `GET` | `/api/enterprise/audit/logs` | Audit logs |
| `GET` | `/api/enterprise/workers/status` | Worker status |

---

## 🏗️ Architecture

```
VulnHunter Pro/
├── 📁 server/
│   ├── index.js                      # Express + Socket.IO Server
│   ├── 📁 scanner/
│   │   ├── VulnerabilityScanner.js   # Main Coordinator
│   │   └── 📁 modules/               # 21+ Scanner Modules
│   │       ├── BaseScanner.js
│   │       ├── XSSScanner.js
│   │       ├── DOMXSSScanner.js
│   │       ├── SQLiScanner.js
│   │       ├── HeadlessCrawler.js
│   │       ├── ScanScheduler.js
│   │       └── ...
│   ├── 📁 utils/
│   │   ├── ReportGenerator.js        # HTML/PDF/Walkthrough
│   │   ├── SARIFExporter.js
│   │   ├── OwnershipVerifier.js
│   │   └── Logger.js
│   ├── 📁 auth/                      # RBAC + SSO
│   ├── 📁 tenants/                   # Multi-tenancy
│   ├── 📁 workers/                   # Distributed Scanning
│   ├── 📁 integrations/              # Jira/GitHub/Slack
│   ├── 📁 audit/                     # Audit Logging
│   ├── 📁 vault/                     # Credential Storage
│   ├── 📁 bounty/                    # Bug Bounty Safety System
│   └── 📁 plugins/                   # Plugin System
├── 📁 client/
│   ├── 📁 src/
│   │   ├── App.jsx
│   │   ├── 📁 contexts/
│   │   │   └── LanguageContext.jsx   # Bilingual Support
│   │   └── 📁 components/
│   │       ├── ScanForm.jsx
│   │       ├── ScanProgress.jsx
│   │       ├── ScanSummary.jsx
│   │       ├── VulnerabilityList.jsx
│   │       ├── VulnerabilityEducation.jsx
│   │       ├── BugBountySettings.jsx
│   │       ├── EnterpriseDashboard.jsx
│   │       ├── ScheduledScans.jsx
│   │       └── OwnershipVerification.jsx
│   └── ...
├── 📁 reports/                       # Generated Reports
└── 📁 logs/                          # Application Logs
```

---

## ⚙️ Advanced Configuration

### Scan Options

```javascript
{
  depth: 3,           // Crawl depth
  maxUrls: 100,       // Maximum URLs to scan
  timeout: 30000,     // Timeout in milliseconds
  threads: 5,         // Parallel threads
  enableScreenshots: true,  // Capture screenshots
  bypassWAF: false,   // Attempt WAF bypass
  scanModules: [      // Enabled modules
    'xss', 'sqli', 'csrf', 'ssrf', 'lfi', 
    'rce', 'xxe', 'idor', 'headers', 'ssl'
  ]
}
```

### Scan Templates

| Template | Modules | Time |
|----------|---------|------|
| **Quick** | Headers, SSL, CORS | ~1 minute |
| **Standard** | 10 core modules | ~5 minutes |
| **Full** | All 21 modules | ~15 minutes |
| **Custom** | Manual selection | Variable |

---

## ⚠️ Important Warnings

> **⚖️ For Ethical and Legal Use Only!**
> 
> - ✅ Only scan websites you own
> - ✅ Use in authorized Bug Bounty programs
> - ✅ Get written permission before scanning
> - ❌ Do not scan websites without permission
> - ❌ Do not use for malicious purposes
> 
> **Developers are not responsible for any illegal use**

---

## 📚 References & Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)

---

## 🤝 Contributing

We welcome your contributions!

```bash
# 1. Fork the project
# 2. Create a new branch
git checkout -b feature/amazing-feature

# 3. Commit your changes
git commit -m 'Add amazing feature'

# 4. Push
git push origin feature/amazing-feature

# 5. Open a Pull Request
```

### Contribution Areas
- 🔍 Add new scanning modules
- 🌐 Improve translations
- 📖 Documentation and examples
- 🐛 Bug fixes

---

## 📜 License

MIT License - For ethical use only

---

<div align="center">

**Made with ❤️ for the Security Community**

⭐ If you like this project, don't forget to star it!

[🇸🇦 اقرأ بالعربية](README.md)

</div>
