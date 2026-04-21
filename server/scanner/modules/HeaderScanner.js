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

    /**
     * Status codes on which we should evaluate security headers.
     * Headers on redirect responses (301, 302, 307, 308) or error responses (404, 500)
     * are irrelevant because:
     *   1. Redirect responses are never rendered by the browser — the browser follows
     *      the Location header and evaluates headers on the FINAL response only.
     *   2. 404/500 error pages are often served by a different handler (e.g., CDN, 
     *      reverse proxy) that may not set the same headers as the application.
     *   3. Reporting missing HSTS on a 301 redirect is a false positive — HSTS is
     *      evaluated on the final 200 response (or 403/401 for auth-protected pages).
     */
    this.evaluableStatusCodes = new Set([200, 201, 401, 403]);
  }
  
  /**
   * REFACTORED: scan() now follows redirects manually and evaluates headers
   * only on the final response in the redirect chain.
   *
   * OLD LOGIC:
   *   - Made a single request and evaluated headers on whatever response came back.
   *   - If the target had a redirect chain (e.g., http → https → www → final),
   *     it would evaluate headers on the first redirect response.
   *   - This caused FPs: "HSTS missing" when the 301 didn't have it but the
   *     final 200 did.
   *
   * NEW LOGIC:
   *   1. Follow the redirect chain manually (maxRedirects: 0) to capture each hop.
   *   2. Record all intermediate responses for analysis.
   *   3. Evaluate security headers ONLY on the final response.
   *   4. Only evaluate headers on responses with evaluable status codes (200, 201, 401, 403).
   *   5. Check for HSTS preload list membership to avoid FPs on preloaded domains.
   */
  async scan(data) {
    const vulnerabilities = [];
    
    try {
      // ── Follow redirect chain manually ──
      const { finalResponse, redirectChain } = await this.followRedirects(this.targetUrl);
      
      if (!finalResponse) {
        this.log('Could not reach target after following redirects', 'debug');
        return vulnerabilities;
      }

      const finalStatus = finalResponse.status;
      const headers = finalResponse.headers;
      const finalUrl = finalResponse.request?.res?.responseUrl || this.targetUrl;
      const isHTTPS = finalUrl.startsWith('https://') || this.targetUrl.startsWith('https://');

      this.log(`Redirect chain: ${redirectChain.length} hops → Final status: ${finalStatus}`, 'debug');

      /**
       * SMART STATUS CODE FILTERING:
       * Only evaluate security headers on meaningful final responses.
       * Redirect responses (3xx), Not Found (404), and Server Errors (5xx) are
       * excluded because they're often served by infrastructure (CDN, load balancer)
       * rather than the application itself.
       */
      if (!this.evaluableStatusCodes.has(finalStatus)) {
        this.log(`Final response status ${finalStatus} is not evaluable for security headers. Skipping header analysis.`, 'info');
        
        // Still check for information disclosure headers even on non-evaluable responses
        for (const [header, config] of Object.entries(this.dangerousHeaders)) {
          if (headers[header]) {
            vulnerabilities.push({
              type: 'Information Disclosure',
              subType: 'Server Banner',
              severity: config.severity,
              url: finalUrl,
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

        return vulnerabilities;
      }
      
      // ── Evaluate security headers on the final response ──
      for (const [header, config] of Object.entries(this.requiredHeaders)) {
        // Skip HSTS check for HTTP-only sites
        if (header === 'strict-transport-security' && !isHTTPS) continue;
        
        /**
         * HSTS PRELOAD CHECK:
         * If the domain is on the HSTS preload list (hardcoded in browsers),
         * the browser enforces HSTS regardless of the header. Reporting
         * "HSTS missing" for google.com, github.com, etc. is a false positive.
         * We check against a list of known preloaded domains.
         */
        if (header === 'strict-transport-security' && !headers[header]) {
          const domain = this.extractDomain(finalUrl);
          if (domain && this.isLikelyPreloaded(domain)) {
            this.log(`HSTS header missing but domain "${domain}" is likely on the HSTS preload list. Skipping.`, 'info');
            continue;
          }
        }

        if (!headers[header]) {
          vulnerabilities.push({
            type: 'Missing Security Header',
            subType: header.toUpperCase(),
            severity: config.severity,
            url: finalUrl,
            evidence: `Header "${header}" not found in final response (status: ${finalStatus})`,
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
              url: finalUrl,
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
            url: finalUrl,
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
        const cspVulns = this.analyzeCSP(headers['content-security-policy'], finalUrl);
        vulnerabilities.push(...cspVulns);
      }
      
      /**
       * HTTPS ENFORCEMENT CHECK:
       * Check if HTTP → HTTPS redirect exists. We check the redirect chain
       * rather than just the target URL protocol. If the user provided an HTTP URL
       * and the server redirected to HTTPS, that's good — no issue to report.
       */
      if (!isHTTPS) {
        // Check if the redirect chain included an upgrade to HTTPS
        const upgradedToHTTPS = redirectChain.some(r => 
          r.location && r.location.startsWith('https://')
        );

        if (!upgradedToHTTPS) {
          vulnerabilities.push({
            type: 'Insecure Transport',
            subType: 'No HTTPS',
            severity: 'high',
            url: this.targetUrl,
            evidence: 'Site accessible over HTTP without redirect to HTTPS',
            description: 'The application is served over unencrypted HTTP and does not redirect to HTTPS',
            remediation: 'Enable HTTPS and redirect all HTTP traffic to HTTPS',
            references: [
              'https://letsencrypt.org/',
              'https://www.ssllabs.com/ssltest/'
            ],
            cvss: 7.5,
            cwe: 'CWE-319'
          });
        }
      }
      
    } catch (error) {
      this.log(`Header scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }

  /**
   * Follow redirect chain manually, capturing each hop.
   * This allows us to evaluate headers on the FINAL response only.
   * 
   * @param {string} url - Starting URL
   * @param {number} maxHops - Maximum redirects to follow (prevent infinite loops)
   * @returns {Promise<{finalResponse: Object, redirectChain: Array}>}
   */
  async followRedirects(url, maxHops = 10) {
    const redirectChain = [];
    let currentUrl = url;
    let finalResponse = null;

    for (let hop = 0; hop < maxHops; hop++) {
      try {
        // Request with maxRedirects: 0 to capture each individual response
        const response = await this.makeRequest(currentUrl, {
          maxRedirects: 0
        });

        if (!response) {
          this.log(`Redirect chain broken at hop ${hop + 1}: no response`, 'debug');
          break;
        }

        const status = response.status;

        // Check if this is a redirect response
        if ([301, 302, 303, 307, 308].includes(status) && response.headers['location']) {
          const location = response.headers['location'];
          
          // Resolve relative redirect URLs
          let nextUrl;
          try {
            nextUrl = new URL(location, currentUrl).href;
          } catch {
            nextUrl = location;
          }

          redirectChain.push({
            hop: hop + 1,
            from: currentUrl,
            to: nextUrl,
            status: status,
            location: nextUrl,
            headers: response.headers
          });

          this.log(`Redirect hop ${hop + 1}: ${status} ${currentUrl} → ${nextUrl}`, 'debug');
          currentUrl = nextUrl;
          continue;
        }

        // Not a redirect — this is the final response
        finalResponse = response;
        break;

      } catch (error) {
        this.log(`Redirect chain error at hop ${hop + 1}: ${error.message}`, 'debug');
        break;
      }
    }

    // If we exhausted all hops without a final response, try one last time with auto-redirect
    if (!finalResponse) {
      try {
        finalResponse = await this.makeRequest(this.targetUrl);
      } catch (error) {
        this.log(`Fallback request failed: ${error.message}`, 'debug');
      }
    }

    return { finalResponse, redirectChain };
  }

  /**
   * Check if a domain is likely on the HSTS preload list.
   * 
   * The HSTS preload list is maintained by Chromium and includes domains that
   * have opted into browser-enforced HSTS. If a domain is preloaded, the browser
   * ALWAYS uses HTTPS regardless of the header, so reporting "HSTS missing" is wrong.
   *
   * This is a heuristic check against well-known preloaded TLDs and major domains.
   * For a comprehensive check, you'd query hstspreload.org API, but we avoid
   * external network calls during scans for performance and reliability.
   */
  isLikelyPreloaded(domain) {
    // Top-level domains that are entirely preloaded
    const preloadedTLDs = [
      '.dev', '.app', '.page', '.new', '.day', '.chrome',
      '.android', '.foo', '.how', '.soy', '.meme', '.mov',
      '.zip', '.phd', '.prof', '.nexus', '.google'
    ];

    // Well-known major domains on the preload list
    const preloadedDomains = [
      'google.com', 'www.google.com',
      'youtube.com', 'www.youtube.com',
      'facebook.com', 'www.facebook.com',
      'twitter.com', 'www.twitter.com',
      'x.com', 'www.x.com',
      'github.com', 'www.github.com',
      'microsoft.com', 'www.microsoft.com',
      'paypal.com', 'www.paypal.com',
      'dropbox.com', 'www.dropbox.com',
      'mozilla.org', 'www.mozilla.org',
      'cloudflare.com', 'www.cloudflare.com',
      'lastpass.com', 'www.lastpass.com',
      'stripe.com', 'www.stripe.com',
      'blockchain.info', 'www.blockchain.info',
      'mega.nz', 'www.mega.nz'
    ];

    const domainLower = domain.toLowerCase();

    // Check preloaded TLDs
    for (const tld of preloadedTLDs) {
      if (domainLower.endsWith(tld)) return true;
    }

    // Check preloaded domains (exact match or subdomain)
    for (const pd of preloadedDomains) {
      if (domainLower === pd || domainLower.endsWith('.' + pd)) return true;
    }

    return false;
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
