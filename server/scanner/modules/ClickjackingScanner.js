import { BaseScanner } from './BaseScanner.js';

export class ClickjackingScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Clickjacking Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls } = data;
    
    // Test main page and important pages
    const pagesToTest = [
      this.targetUrl,
      ...urls.filter(u => this.isImportantPage(u)).slice(0, 10)
    ];
    
    for (const url of pagesToTest) {
      if (this.stopped) break;
      
      const vulns = await this.testClickjacking(url);
      vulnerabilities.push(...vulns);
    }
    
    return vulnerabilities;
  }
  
  isImportantPage(url) {
    const importantPatterns = [
      /login/i,
      /register/i,
      /signup/i,
      /account/i,
      /profile/i,
      /settings/i,
      /admin/i,
      /dashboard/i,
      /payment/i,
      /checkout/i,
      /transfer/i,
      /password/i,
      /delete/i,
      /remove/i
    ];
    return importantPatterns.some(p => p.test(url));
  }
  
  async testClickjacking(url) {
    const vulnerabilities = [];
    
    try {
      const response = await this.makeRequest(url);
      if (!response) return vulnerabilities;
      
      const headers = response.headers;
      const html = response.data?.toString() || '';
      
      // Check X-Frame-Options header
      const xfo = headers['x-frame-options'];
      const xfoResult = this.analyzeXFrameOptions(xfo);
      
      // Check Content-Security-Policy frame-ancestors
      const csp = headers['content-security-policy'];
      const cspResult = this.analyzeCSPFrameAncestors(csp);
      
      // Check for JavaScript frame-busting code
      const hasFrameBusting = this.detectFrameBusting(html);
      
      // Determine vulnerability level
      if (!xfo && !cspResult.hasFrameAncestors && !hasFrameBusting) {
        // No protection at all
        vulnerabilities.push({
          type: 'Clickjacking',
          subType: 'No Frame Protection',
          severity: 'medium',
          url: url,
          evidence: 'Missing X-Frame-Options and CSP frame-ancestors',
          description: 'Page can be embedded in iframes on any domain, enabling clickjacking attacks.',
          remediation: `Add X-Frame-Options: DENY or SAMEORIGIN header. Better yet, use CSP frame-ancestors directive.`,
          references: [
            'https://owasp.org/www-community/attacks/Clickjacking',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
            'https://portswigger.net/web-security/clickjacking'
          ],
          cvss: 4.3,
          cwe: 'CWE-1021'
        });
      } else if (xfoResult.vulnerable) {
        vulnerabilities.push({
          type: 'Clickjacking',
          subType: 'Weak X-Frame-Options',
          severity: xfoResult.severity,
          url: url,
          evidence: `X-Frame-Options: ${xfo}`,
          description: xfoResult.description,
          remediation: xfoResult.remediation,
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
          ],
          cvss: xfoResult.cvss,
          cwe: 'CWE-1021'
        });
      }
      
      if (cspResult.vulnerable) {
        vulnerabilities.push({
          type: 'Clickjacking',
          subType: 'Weak CSP Frame-Ancestors',
          severity: cspResult.severity,
          url: url,
          evidence: `CSP: ${csp?.substring(0, 200)}`,
          description: cspResult.description,
          remediation: cspResult.remediation,
          references: [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'
          ],
          cvss: cspResult.cvss,
          cwe: 'CWE-1021'
        });
      }
      
      // Warn about JavaScript-only protection
      if (hasFrameBusting && !xfo && !cspResult.hasFrameAncestors) {
        vulnerabilities.push({
          type: 'Clickjacking',
          subType: 'JavaScript-Only Frame Busting',
          severity: 'low',
          url: url,
          evidence: 'Only JavaScript-based frame busting detected',
          description: 'Page relies solely on JavaScript for clickjacking protection. Can be bypassed with sandbox attribute.',
          remediation: 'Use X-Frame-Options or CSP frame-ancestors header in addition to JavaScript.',
          references: [
            'https://portswigger.net/web-security/clickjacking/preventing'
          ],
          cvss: 3.1,
          cwe: 'CWE-1021'
        });
      }
      
      // Check for double-click vulnerability on forms
      if (html.includes('<form')) {
        const doubleClickVuln = this.checkDoubleClickVulnerability(html, url);
        if (doubleClickVuln) {
          vulnerabilities.push(doubleClickVuln);
        }
      }
      
    } catch (error) {
      this.log(`Clickjacking test error for ${url}: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  analyzeXFrameOptions(xfo) {
    if (!xfo) {
      return { vulnerable: false, hasXFO: false };
    }
    
    const value = xfo.toLowerCase().trim();
    
    // DENY - most secure
    if (value === 'deny') {
      return { vulnerable: false, hasXFO: true };
    }
    
    // SAMEORIGIN - acceptable
    if (value === 'sameorigin') {
      return { vulnerable: false, hasXFO: true };
    }
    
    // ALLOW-FROM - deprecated and not widely supported
    if (value.startsWith('allow-from')) {
      return {
        vulnerable: true,
        hasXFO: true,
        severity: 'low',
        description: 'X-Frame-Options ALLOW-FROM is deprecated and not supported by modern browsers.',
        remediation: 'Use CSP frame-ancestors directive instead of ALLOW-FROM.',
        cvss: 3.1
      };
    }
    
    // Invalid value
    return {
      vulnerable: true,
      hasXFO: true,
      severity: 'medium',
      description: `Invalid X-Frame-Options value: ${xfo}. Header will be ignored.`,
      remediation: 'Use valid values: DENY or SAMEORIGIN.',
      cvss: 4.3
    };
  }
  
  analyzeCSPFrameAncestors(csp) {
    if (!csp) {
      return { vulnerable: false, hasFrameAncestors: false };
    }
    
    // Extract frame-ancestors directive
    const frameAncestorsMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
    
    if (!frameAncestorsMatch) {
      return { vulnerable: false, hasFrameAncestors: false };
    }
    
    const value = frameAncestorsMatch[1].trim().toLowerCase();
    
    // 'none' - most secure
    if (value === "'none'") {
      return { vulnerable: false, hasFrameAncestors: true };
    }
    
    // 'self' - acceptable
    if (value === "'self'") {
      return { vulnerable: false, hasFrameAncestors: true };
    }
    
    // Check for wildcards
    if (value.includes('*')) {
      return {
        vulnerable: true,
        hasFrameAncestors: true,
        severity: 'medium',
        description: `frame-ancestors contains wildcard (*), allowing framing from multiple domains.`,
        remediation: "Use specific domains or 'self' instead of wildcards.",
        cvss: 4.3
      };
    }
    
    // Check for http:// sources
    if (value.includes('http:')) {
      return {
        vulnerable: true,
        hasFrameAncestors: true,
        severity: 'low',
        description: 'frame-ancestors allows HTTP sources, which could be spoofed.',
        remediation: 'Use only HTTPS sources in frame-ancestors.',
        cvss: 3.1
      };
    }
    
    // Multiple domains - acceptable but worth noting
    const domains = value.split(/\s+/).filter(d => d && !d.startsWith("'"));
    if (domains.length > 5) {
      return {
        vulnerable: true,
        hasFrameAncestors: true,
        severity: 'info',
        description: `frame-ancestors allows ${domains.length} domains, increasing attack surface.`,
        remediation: 'Minimize the number of allowed framing domains.',
        cvss: 2.0
      };
    }
    
    return { vulnerable: false, hasFrameAncestors: true };
  }
  
  detectFrameBusting(html) {
    const frameBustingPatterns = [
      /if\s*\(\s*(?:top|parent|self)\s*[!=]==?\s*(?:window|self)\s*\)/i,
      /if\s*\(\s*(?:window|self)\s*[!=]==?\s*(?:top|parent)\s*\)/i,
      /top\.location\s*[!=]=\s*(?:self|window)\.location/i,
      /if\s*\(\s*window\.frameElement\s*\)/i,
      /top\.location\.href\s*=\s*(?:self|window)\.location\.href/i,
      /parent\.frames\.length\s*>\s*0/i,
      /if\s*\(\s*!?\s*window\.top\s*\)/i,
      /window\.top\.location\s*!==\s*window\.location/i
    ];
    
    return frameBustingPatterns.some(p => p.test(html));
  }
  
  checkDoubleClickVulnerability(html, url) {
    // Check for forms with important actions that might be vulnerable to double-click
    const dangerousForms = [
      /action=["'][^"']*(?:delete|remove|transfer|payment)/i,
      /name=["'](?:delete|remove|action)["']/i,
      /<button[^>]*(?:type=["']submit["'])?[^>]*>.*?(?:delete|remove|transfer|pay)/i
    ];
    
    const hasDangerousForm = dangerousForms.some(p => p.test(html));
    
    if (hasDangerousForm) {
      // Check if there's protection against rapid submissions
      const hasDoubleClickProtection = 
        /onclick=["'][^"']*this\.disabled\s*=\s*true/i.test(html) ||
        /data-(?:loading|submitting|submitted)/i.test(html) ||
        /preventDoubleSubmit/i.test(html);
      
      if (!hasDoubleClickProtection) {
        return {
          type: 'Clickjacking',
          subType: 'Double-Click Vulnerability',
          severity: 'info',
          url: url,
          evidence: 'Dangerous forms without double-click protection',
          description: 'Forms with sensitive actions may be vulnerable to double-click attacks.',
          remediation: 'Disable submit buttons after click, use CSRF tokens, and add confirmation dialogs.',
          references: [
            'https://portswigger.net/research/click-bandits-a-study-of-click-based-ui-manipulation'
          ],
          cvss: 2.0,
          cwe: 'CWE-1021'
        };
      }
    }
    
    return null;
  }
}
