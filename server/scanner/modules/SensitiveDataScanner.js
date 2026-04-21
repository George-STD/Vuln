import { BaseScanner } from './BaseScanner.js';
import crypto from 'crypto';

export class SensitiveDataScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Sensitive Data Scanner';
    
    // Patterns for sensitive data
    this.patterns = {
      // API Keys
      apiKeys: [
        { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
        // AWS Secret Key: Require proximity to AWS context (access key, "aws", "secret")
        // The old pattern /[A-Za-z0-9\/+=]{40}/ matched ANY 40-char alphanumeric string,
        // producing massive FPs on minified JS, CSS hashes, and encoded data.
        { name: 'AWS Secret Key', pattern: /(?:aws|AKIA|secret|credential)[\s\S]{0,50}([A-Za-z0-9\/+=]{40})/gi },
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

    /**
     * Cached baseline fingerprints for catch-all detection.
     * Built once per scan, reused across all sensitive path checks.
     */
    this._baselineFingerprints = null;
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
    
    // Scan common sensitive paths (now with catch-all fingerprinting)
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
  
  /**
   * REFACTORED: scanSensitivePaths now uses Catch-All Fingerprinting.
   *
   * OLD LOGIC:
   *   - Simply checked if status === 200 and content.length > 10 and didn't contain <!DOCTYPE>.
   *   - This produced massive FPs on enterprise targets that return custom 200 OK pages for everything.
   *
   * NEW LOGIC:
   *   1. Build baseline fingerprints by probing 3 random nonexistent paths.
   *   2. For each sensitive path that returns 200 OK, compare its response against the baselines.
   *   3. If the response matches the catch-all fingerprint (by hash or length similarity), discard it.
   *   4. Additionally, check if the content actually looks like a sensitive file (not an error page).
   */
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

    // ── Build catch-all fingerprints (cached for this scan) ──
    if (!this._baselineFingerprints) {
      this._baselineFingerprints = await this.buildBaselineFingerprints(baseUrl);
    }
    
    for (const path of sensitivePaths) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(`${baseUrl}${path}`);
        if (response && response.status === 200 && response.data) {
          const content = response.data.toString();

          /**
           * CATCH-ALL CHECK:
           * Compare this response against our baseline fingerprints.
           * If it matches, this is a catch-all page pretending to serve the file.
           */
          if (this.matchesBaseline(content, response.status)) {
            this.log(`Catch-all FP discarded for sensitive path: ${path}`, 'debug');
            continue;
          }

          /**
           * CONTENT VALIDATION:
           * Even after passing the catch-all check, verify the content actually
           * looks like a sensitive file and not an HTML error page.
           * - Must have content > 10 bytes
           * - Must NOT be an HTML page (unless it's a JSON/YAML config masquerading as HTML)
           * - Must NOT contain common "not found" language
           */
          if (content.length > 10 && !this.looksLikeErrorPage(content)) {
            const vulns = this.scanContent(content, `${baseUrl}${path}`);

            // Only report if we actually found sensitive data patterns in the content
            if (vulns.length > 0) {
              vulnerabilities.push(...vulns);
            } else {
              this.log(`Path ${path} returned 200 OK but no sensitive patterns found. Discarding.`, 'debug');
            }
          }
        }
      } catch {}
    }
    
    return vulnerabilities;
  }

  /**
   * Build baseline fingerprints by requesting guaranteed-nonexistent paths.
   * These fingerprints represent what the server's "not found" response looks like.
   */
  async buildBaselineFingerprints(baseUrl) {
    const fingerprints = [];

    this.log('Building catch-all baseline fingerprints for sensitive path scanning...', 'debug');

    for (let i = 0; i < 3; i++) {
      try {
        const randomSlug = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);
        const probePath = `/vulnhunter_sensitive_fp_${randomSlug}_${Date.now()}`;
        const response = await this.makeRequest(`${baseUrl}${probePath}`);

        if (response) {
          const bodyStr = response.data ? response.data.toString() : '';
          fingerprints.push({
            status: response.status,
            length: bodyStr.length,
            contentHash: this.hashContent(bodyStr),
            normalizedHash: this.hashContent(this.normalizeContent(bodyStr))
          });
        }
      } catch (err) {
        this.log(`Baseline probe ${i + 1} failed: ${err.message}`, 'debug');
      }
    }

    if (fingerprints.length === 0) {
      return { fingerprints: [{ status: 404, length: 0, contentHash: '', normalizedHash: '' }] };
    }

    const lengths = fingerprints.map(f => f.length);
    const lengthVariance = Math.max(...lengths) - Math.min(...lengths);

    return { fingerprints, lengthVariance };
  }

  /**
   * Check if a response matches the cached baseline fingerprints.
   */
  matchesBaseline(bodyStr, status) {
    if (!this._baselineFingerprints) return false;

    const { fingerprints, lengthVariance = 0 } = this._baselineFingerprints;
    const responseHash = this.hashContent(bodyStr);
    const responseNormalizedHash = this.hashContent(this.normalizeContent(bodyStr));
    const responseLength = bodyStr.length;

    for (const fp of fingerprints) {
      // Exact content match — definitely a catch-all page
      if (responseHash === fp.contentHash && fp.contentHash !== '') return true;

      // Normalized content match — catch-all with dynamic tokens
      if (responseNormalizedHash === fp.normalizedHash && fp.normalizedHash !== '') return true;

      // Status + length similarity — within variance tolerance
      if (status === fp.status) {
        const tolerance = Math.max(200, (lengthVariance || 0) * 2);
        if (Math.abs(responseLength - fp.length) < tolerance) return true;
      }
    }

    return false;
  }

  /**
   * Simple djb2 hash for fast content comparison.
   */
  hashContent(content) {
    if (!content) return '';
    let hash = 5381;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) + hash) + content.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Normalize content by stripping dynamic tokens to enable structural comparison.
   */
  normalizeContent(content) {
    if (!content) return '';
    return content
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '')
      .replace(/\b\d{10,13}\b/g, '')
      .replace(/nonce="[^"]*"/gi, '')
      .replace(/csrf[_-]?token[^"]*"[^"]*"/gi, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Heuristic: does the content look like a "not found" error page?
   */
  looksLikeErrorPage(content) {
    if (!content || content.length < 50) return false;

    const lowerContent = content.toLowerCase();

    // If it starts with common config file patterns, it's NOT an error page
    // (e.g., .env files start with KEY=VALUE, JSON files start with {, YAML with ---)
    if (content.trim().startsWith('{') || content.trim().startsWith('---') || /^[A-Z_]+=/.test(content.trim())) {
      return false;
    }

    const errorIndicators = [
      'page not found', '404 not found', 'not found', 'does not exist',
      'could not be found', 'no longer available', 'error 404',
      'we couldn\'t find', 'nothing here', 'page doesn\'t exist',
      '<!doctype html', '<html'
    ];

    let matchCount = 0;
    for (const indicator of errorIndicators) {
      if (lowerContent.includes(indicator)) matchCount++;
    }

    // HTML page with error language = almost certainly a custom 404
    if (matchCount >= 2) return true;
    if (matchCount === 1 && content.length < 5000) return true;

    return false;
  }
  
  maskSecret(secret) {
    if (!secret || secret.length < 8) return '****';
    return secret.substring(0, 4) + '****' + secret.substring(secret.length - 4);
  }
  
  isFalsePositive(match, type) {
    // ── Basic pattern-based FP filters ──
    const falsePositives = [
      /^0+$/, // All zeros
      /^1+$/, // All ones
      /^[a-z]+$/i, // Only letters (no digits = not a key)
      /example|test|demo|sample|placeholder|undefined|null|true|false/i, // Common placeholder values
      /^[0-9]+$/, // Pure numeric strings (not API keys)
    ];
    
    for (const fp of falsePositives) {
      if (fp.test(match)) return true;
    }

    /**
     * CONTEXT-AWARE FP FILTERING:
     * Many high-entropy strings in web pages are NOT secrets:
     * - CSS content hashes (e.g., webpack chunk IDs)
     * - Base64-encoded image data URIs
     * - JavaScript minification artifacts
     * - Integrity hashes (SRI)
     * - Google/Facebook tracking parameters
     */

    // Reject matches that are purely hex (likely a hash, not a key)
    if (type === 'AWS Secret Key' && /^[a-f0-9]+$/i.test(match)) return true;

    // Reject matches found inside HTML tags (likely attribute values, not leaked keys)
    if (type === 'GitHub Token (old)' && /^[a-f0-9]{40}$/.test(match)) {
      // 40-char hex strings are almost always SHA1 hashes (git commits, SRI, etc.)
      return true;
    }

    // Reject very common base64 padding patterns (not real keys)
    if (/={3,}$/.test(match)) return true;

    return false;
  }
}
