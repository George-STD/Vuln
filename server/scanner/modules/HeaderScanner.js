import { BaseScanner } from './BaseScanner.js';

export class HeaderScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Security Headers Scanner';
    
    // Required security headers
    this.requiredHeaders = {
      'strict-transport-security': {
        severity: 'high',
        description: 'HTTP Strict Transport Security (HSTS) not set',
        recommendation: 'Set Strict-Transport-Security header with max-age of at least 31536000 (1 year)',
        cwe: 'CWE-319'
      },
      'x-content-type-options': {
        severity: 'medium',
        description: 'X-Content-Type-Options header not set',
        recommendation: 'Set X-Content-Type-Options: nosniff',
        cwe: 'CWE-16'
      },
      'x-frame-options': {
        severity: 'medium',
        description: 'X-Frame-Options header not set',
        recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN',
        cwe: 'CWE-1021'
      },
      'content-security-policy': {
        severity: 'medium',
        description: 'Content-Security-Policy header not set',
        recommendation: 'Implement a strict Content Security Policy',
        cwe: 'CWE-16'
      },
      'x-xss-protection': {
        severity: 'low',
        description: 'X-XSS-Protection header not set (legacy but still useful)',
        recommendation: 'Set X-XSS-Protection: 1; mode=block',
        cwe: 'CWE-79'
      },
      'referrer-policy': {
        severity: 'low',
        description: 'Referrer-Policy header not set',
        recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin',
        cwe: 'CWE-200'
      },
      'permissions-policy': {
        severity: 'low',
        description: 'Permissions-Policy header not set',
        recommendation: 'Define a Permissions-Policy to control browser features',
        cwe: 'CWE-16'
      }
    };
    
    // Dangerous headers that should not be present
    this.dangerousHeaders = {
      'server': {
        severity: 'info',
        description: 'Server header exposes server technology',
        recommendation: 'Remove or obscure the Server header'
      },
      'x-powered-by': {
        severity: 'info',
        description: 'X-Powered-By header exposes framework information',
        recommendation: 'Remove the X-Powered-By header'
      },
      'x-aspnet-version': {
        severity: 'low',
        description: 'X-AspNet-Version header exposes ASP.NET version',
        recommendation: 'Remove the X-AspNet-Version header'
      },
      'x-aspnetmvc-version': {
        severity: 'low',
        description: 'X-AspNetMvc-Version header exposes MVC version',
        recommendation: 'Remove the X-AspNetMvc-Version header'
      }
    };
  }
  
  async scan(data) {
    const vulnerabilities = [];
    
    try {
      const response = await this.makeRequest(this.targetUrl);
      if (!response) return vulnerabilities;
      
      const headers = response.headers;
      const url = this.targetUrl;
      const isHTTPS = url.startsWith('https://');
      
      // Check for missing security headers
      for (const [header, config] of Object.entries(this.requiredHeaders)) {
        // Skip HSTS check for HTTP sites
        if (header === 'strict-transport-security' && !isHTTPS) continue;
        
        if (!headers[header]) {
          vulnerabilities.push({
            type: 'Missing Security Header',
            subType: header.toUpperCase(),
            severity: config.severity,
            url: url,
            evidence: `Header "${header}" not found in response`,
            description: config.description,
            remediation: config.recommendation,
            references: [
              'https://owasp.org/www-project-secure-headers/',
              'https://securityheaders.com/'
            ],
            cvss: this.severityToCVSS(config.severity),
            cwe: config.cwe
          });
        } else {
          // Check header values for weaknesses
          const weakness = this.analyzeHeaderValue(header, headers[header]);
          if (weakness) {
            vulnerabilities.push({
              type: 'Weak Security Header',
              subType: header.toUpperCase(),
              severity: weakness.severity,
              url: url,
              evidence: `${header}: ${headers[header]}`,
              description: weakness.description,
              remediation: weakness.recommendation,
              references: [
                'https://owasp.org/www-project-secure-headers/'
              ],
              cvss: this.severityToCVSS(weakness.severity),
              cwe: config.cwe
            });
          }
        }
      }
      
      // Check for dangerous/information disclosure headers
      for (const [header, config] of Object.entries(this.dangerousHeaders)) {
        if (headers[header]) {
          vulnerabilities.push({
            type: 'Information Disclosure',
            subType: 'Server Banner',
            severity: config.severity,
            url: url,
            evidence: `${header}: ${headers[header]}`,
            description: config.description,
            remediation: config.recommendation,
            references: [
              'https://owasp.org/www-project-secure-headers/'
            ],
            cvss: 2.0,
            cwe: 'CWE-200'
          });
        }
      }
      
      // Analyze Content-Security-Policy if present
      if (headers['content-security-policy']) {
        const cspVulns = this.analyzeCSP(headers['content-security-policy'], url);
        vulnerabilities.push(...cspVulns);
      }
      
      // Check for HTTPS enforcement
      if (!isHTTPS) {
        vulnerabilities.push({
          type: 'Insecure Transport',
          subType: 'No HTTPS',
          severity: 'high',
          url: url,
          evidence: 'Site accessible over HTTP',
          description: 'The application is served over unencrypted HTTP',
          remediation: 'Enable HTTPS and redirect all HTTP traffic to HTTPS',
          references: [
            'https://letsencrypt.org/',
            'https://www.ssllabs.com/ssltest/'
          ],
          cvss: 7.5,
          cwe: 'CWE-319'
        });
      }
      
    } catch (error) {
      this.log(`Header scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  analyzeHeaderValue(header, value) {
    const valueLower = value.toLowerCase();
    
    switch (header) {
      case 'strict-transport-security':
        // Check for weak HSTS
        const maxAgeMatch = valueLower.match(/max-age\s*=\s*(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1]);
          if (maxAge < 31536000) {
            return {
              severity: 'medium',
              description: `HSTS max-age is too short (${maxAge} seconds). Should be at least 31536000 (1 year).`,
              recommendation: 'Increase HSTS max-age to at least 31536000 seconds'
            };
          }
        }
        if (!valueLower.includes('includesubdomains')) {
          return {
            severity: 'low',
            description: 'HSTS does not include subdomains',
            recommendation: 'Add includeSubDomains directive to HSTS'
          };
        }
        break;
        
      case 'x-frame-options':
        if (valueLower === 'allowall' || valueLower.includes('allow-from')) {
          return {
            severity: 'medium',
            description: 'X-Frame-Options allows framing which could enable clickjacking',
            recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN'
          };
        }
        break;
        
      case 'x-content-type-options':
        if (valueLower !== 'nosniff') {
          return {
            severity: 'low',
            description: 'X-Content-Type-Options has incorrect value',
            recommendation: 'Set X-Content-Type-Options: nosniff'
          };
        }
        break;
    }
    
    return null;
  }
  
  analyzeCSP(csp, url) {
    const vulnerabilities = [];
    const cspLower = csp.toLowerCase();
    
    // Check for unsafe directives
    const unsafePatterns = [
      {
        pattern: /unsafe-inline/i,
        severity: 'medium',
        description: "CSP uses 'unsafe-inline' which allows inline scripts/styles",
        recommendation: "Remove 'unsafe-inline' and use nonces or hashes"
      },
      {
        pattern: /unsafe-eval/i,
        severity: 'medium',
        description: "CSP uses 'unsafe-eval' which allows eval() and similar functions",
        recommendation: "Remove 'unsafe-eval' directive"
      },
      {
        pattern: /\*/i,
        severity: 'low',
        description: 'CSP uses wildcard (*) which weakens the policy',
        recommendation: 'Replace wildcards with specific trusted domains'
      },
      {
        pattern: /data:/i,
        severity: 'low',
        description: 'CSP allows data: URIs which can be used for XSS',
        recommendation: 'Remove data: from script-src and object-src'
      }
    ];
    
    for (const check of unsafePatterns) {
      if (check.pattern.test(cspLower)) {
        vulnerabilities.push({
          type: 'Weak CSP',
          subType: 'Content Security Policy',
          severity: check.severity,
          url: url,
          evidence: `CSP contains: ${csp.substring(0, 100)}...`,
          description: check.description,
          remediation: check.recommendation,
          references: [
            'https://content-security-policy.com/',
            'https://csp-evaluator.withgoogle.com/'
          ],
          cvss: this.severityToCVSS(check.severity),
          cwe: 'CWE-16'
        });
      }
    }
    
    // Check for missing default-src
    if (!cspLower.includes('default-src')) {
      vulnerabilities.push({
        type: 'Weak CSP',
        subType: 'Missing default-src',
        severity: 'medium',
        url: url,
        evidence: 'CSP missing default-src directive',
        description: 'CSP should have a default-src as fallback',
        remediation: "Add default-src 'self' or more restrictive value",
        references: [
          'https://content-security-policy.com/'
        ],
        cvss: 4.0,
        cwe: 'CWE-16'
      });
    }
    
    return vulnerabilities;
  }
  
  severityToCVSS(severity) {
    const mapping = {
      critical: 9.0,
      high: 7.0,
      medium: 5.0,
      low: 3.0,
      info: 1.0
    };
    return mapping[severity] || 0;
  }
}
