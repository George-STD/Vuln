import { BaseScanner } from './BaseScanner.js';

export class SensitiveDataScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Sensitive Data Scanner';
    
    // Patterns for sensitive data
    this.patterns = {
      // API Keys
      apiKeys: [
        { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
        { name: 'AWS Secret Key', pattern: /[A-Za-z0-9\/+=]{40}/g },
        { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g },
        { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g },
        { name: 'GitHub Token (old)', pattern: /[a-f0-9]{40}/g },
        { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g },
        { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24}/g },
        { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24}/g },
        { name: 'Twilio Key', pattern: /SK[0-9a-fA-F]{32}/g },
        { name: 'Firebase Key', pattern: /[a-zA-Z0-9_-]{1,}:[a-zA-Z0-9_-]{140}/g }
      ],
      
      // Credentials
      credentials: [
        { name: 'Password in URL', pattern: /[?&]password=([^&\s]+)/gi },
        { name: 'Password Field', pattern: /password["']\s*[:=]\s*["']([^"']+)["']/gi },
        { name: 'API Key in URL', pattern: /[?&]api[_-]?key=([^&\s]+)/gi },
        { name: 'Authorization Header', pattern: /Authorization:\s*Bearer\s+[a-zA-Z0-9\-_.]+/gi },
        { name: 'Basic Auth', pattern: /Authorization:\s*Basic\s+[a-zA-Z0-9+\/=]+/gi }
      ],
      
      // Personal Information
      pii: [
        { name: 'Email Address', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
        { name: 'Credit Card', pattern: /\b(?:\d[ -]*?){13,16}\b/g },
        { name: 'SSN', pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g },
        { name: 'Phone Number', pattern: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
        { name: 'IP Address', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g }
      ],
      
      // Database/Connection Strings
      connections: [
        { name: 'MongoDB URI', pattern: /mongodb(\+srv)?:\/\/[^\s"']+/gi },
        { name: 'MySQL URI', pattern: /mysql:\/\/[^\s"']+/gi },
        { name: 'PostgreSQL URI', pattern: /postgres(ql)?:\/\/[^\s"']+/gi },
        { name: 'Redis URI', pattern: /redis:\/\/[^\s"']+/gi },
        { name: 'JDBC Connection', pattern: /jdbc:[a-z]+:\/\/[^\s"']+/gi }
      ],
      
      // Private Keys
      privateKeys: [
        { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g },
        { name: 'Private Key', pattern: /-----BEGIN PRIVATE KEY-----/g },
        { name: 'OpenSSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
        { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g }
      ],
      
      // Tokens/Sessions
      tokens: [
        { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
        { name: 'Session ID', pattern: /session[_-]?id=([a-zA-Z0-9]{16,})/gi }
      ]
    };
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls } = data;
    
    // Scan main page
    try {
      const response = await this.makeRequest(this.targetUrl);
      if (response && response.data) {
        const vulns = this.scanContent(response.data.toString(), this.targetUrl);
        vulnerabilities.push(...vulns);
      }
    } catch (error) {
      this.log(`Main page scan error: ${error.message}`, 'debug');
    }
    
    // Scan JavaScript files
    const jsVulns = await this.scanJavaScriptFiles(urls);
    vulnerabilities.push(...jsVulns);
    
    // Scan common sensitive paths
    const pathVulns = await this.scanSensitivePaths();
    vulnerabilities.push(...pathVulns);
    
    return vulnerabilities;
  }
  
  scanContent(content, url) {
    const vulnerabilities = [];
    
    // Skip if content is too short
    if (!content || content.length < 100) return vulnerabilities;
    
    // Check API keys
    for (const check of this.patterns.apiKeys) {
      const matches = content.match(check.pattern);
      if (matches && matches.length > 0) {
        // Filter out false positives
        const validMatches = matches.filter(m => !this.isFalsePositive(m, check.name));
        
        if (validMatches.length > 0) {
          vulnerabilities.push({
            type: 'Sensitive Data Exposure',
            subType: check.name,
            severity: 'critical',
            url: url,
            evidence: `Found ${check.name}: ${this.maskSecret(validMatches[0])}`,
            description: `${check.name} exposed in response. This could allow unauthorized access to services.`,
            remediation: 'Remove API keys from client-side code. Use environment variables and server-side proxies.',
            references: [
              'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
            ],
            cvss: 9.0,
            cwe: 'CWE-798'
          });
        }
      }
    }
    
    // Check credentials
    for (const check of this.patterns.credentials) {
      const matches = content.match(check.pattern);
      if (matches && matches.length > 0) {
        vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          subType: check.name,
          severity: 'critical',
          url: url,
          evidence: `Found ${check.name}: ${this.maskSecret(matches[0])}`,
          description: `Credentials exposed in response.`,
          remediation: 'Never expose credentials in client-side code or URLs.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
          ],
          cvss: 9.0,
          cwe: 'CWE-798'
        });
      }
    }
    
    // Check private keys
    for (const check of this.patterns.privateKeys) {
      if (check.pattern.test(content)) {
        vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          subType: check.name,
          severity: 'critical',
          url: url,
          evidence: `Found ${check.name}`,
          description: `Private key exposed. This is a critical security issue.`,
          remediation: 'Remove private keys from public access immediately. Rotate the compromised keys.',
          references: [
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key'
          ],
          cvss: 10.0,
          cwe: 'CWE-321'
        });
      }
    }
    
    // Check connection strings
    for (const check of this.patterns.connections) {
      const matches = content.match(check.pattern);
      if (matches && matches.length > 0) {
        vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          subType: check.name,
          severity: 'critical',
          url: url,
          evidence: `Found ${check.name}: ${this.maskSecret(matches[0])}`,
          description: `Database connection string exposed.`,
          remediation: 'Store connection strings in environment variables. Never expose in client-side code.',
          references: [],
          cvss: 9.0,
          cwe: 'CWE-200'
        });
      }
    }
    
    // Check JWT tokens (might be intended, so lower severity)
    for (const check of this.patterns.tokens) {
      const matches = content.match(check.pattern);
      if (matches && matches.length > 0) {
        vulnerabilities.push({
          type: 'Sensitive Data Exposure',
          subType: check.name,
          severity: 'low',
          url: url,
          evidence: `Found ${check.name}: ${this.maskSecret(matches[0])}`,
          description: `Token found in response. Verify if this is intended.`,
          remediation: 'Review token exposure. Ensure tokens have appropriate expiry.',
          references: [],
          cvss: 3.0,
          cwe: 'CWE-200'
        });
      }
    }
    
    return vulnerabilities;
  }
  
  async scanJavaScriptFiles(urls) {
    const vulnerabilities = [];
    
    // Find JavaScript files
    const jsUrls = urls.filter(url => /\.js(\?|$)/i.test(url));
    
    for (const jsUrl of jsUrls.slice(0, 20)) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(jsUrl);
        if (response && response.data) {
          const vulns = this.scanContent(response.data.toString(), jsUrl);
          vulnerabilities.push(...vulns);
        }
      } catch (error) {
        this.log(`JS scan error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async scanSensitivePaths() {
    const vulnerabilities = [];
    const baseUrl = new URL(this.targetUrl).origin;
    
    const sensitivePaths = [
      '/.env',
      '/config.json',
      '/secrets.json',
      '/credentials.json',
      '/.aws/credentials',
      '/.docker/config.json'
    ];
    
    for (const path of sensitivePaths) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(`${baseUrl}${path}`);
        if (response && response.status === 200 && response.data) {
          const content = response.data.toString();
          if (content.length > 10 && !content.includes('<!DOCTYPE')) {
            const vulns = this.scanContent(content, `${baseUrl}${path}`);
            vulnerabilities.push(...vulns);
          }
        }
      } catch {}
    }
    
    return vulnerabilities;
  }
  
  maskSecret(secret) {
    if (!secret || secret.length < 8) return '****';
    return secret.substring(0, 4) + '****' + secret.substring(secret.length - 4);
  }
  
  isFalsePositive(match, type) {
    // Filter out common false positives
    const falsePositives = [
      /^0+$/, // All zeros
      /^1+$/, // All ones
      /^[a-z]+$/i, // Only letters
      /example|test|demo|sample|placeholder/i
    ];
    
    for (const fp of falsePositives) {
      if (fp.test(match)) return true;
    }
    
    return false;
  }
}
