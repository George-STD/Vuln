import { BaseScanner } from './BaseScanner.js';

export class CORSScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'CORS Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, endpoints } = data;
    
    // Test main URL
    const mainVulns = await this.testCORS(this.targetUrl);
    vulnerabilities.push(...mainVulns);
    
    // Test API endpoints
    for (const endpoint of endpoints.slice(0, 10)) {
      if (this.stopped) break;
      
      const vulns = await this.testCORS(endpoint);
      vulnerabilities.push(...vulns);
    }
    
    return vulnerabilities;
  }
  
  async testCORS(url) {
    const vulnerabilities = [];
    
    // Test with various Origin values
    const testOrigins = [
      'https://evil.com',
      'https://attacker.com',
      `https://${this.extractDomain(url)}.evil.com`,
      'null',
      `https://sub.${this.extractDomain(url)}`,
      `https://${this.extractDomain(url)}evil.com`
    ];
    
    for (const origin of testOrigins) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(url, {
          headers: {
            'Origin': origin
          }
        });
        
        if (!response) continue;
        
        const corsHeaders = {
          allowOrigin: response.headers['access-control-allow-origin'],
          allowCredentials: response.headers['access-control-allow-credentials'],
          allowMethods: response.headers['access-control-allow-methods'],
          allowHeaders: response.headers['access-control-allow-headers']
        };
        
        // Check for vulnerable CORS configurations
        const vulnerability = this.analyzeCORS(corsHeaders, origin, url);
        
        if (vulnerability) {
          vulnerabilities.push(vulnerability);
          break; // One vulnerability per URL is enough
        }
      } catch (error) {
        this.log(`CORS test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  analyzeCORS(corsHeaders, testOrigin, url) {
    const { allowOrigin, allowCredentials } = corsHeaders;
    
    if (!allowOrigin) return null;
    
    // Critical: Reflects arbitrary origin with credentials
    if (allowOrigin === testOrigin && 
        allowCredentials && 
        allowCredentials.toLowerCase() === 'true') {
      return {
        type: 'CORS Misconfiguration',
        subType: 'Arbitrary Origin with Credentials',
        severity: 'critical',
        url: url,
        evidence: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCredentials}`,
        description: 'CORS policy reflects arbitrary origins with credentials enabled. This allows any website to make authenticated requests to the application.',
        remediation: 'Implement a strict allowlist of trusted origins. Never reflect arbitrary Origin headers when credentials are enabled.',
        references: [
          'https://portswigger.net/web-security/cors',
          'https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties'
        ],
        cvss: 8.8,
        cwe: 'CWE-346'
      };
    }
    
    // High: Wildcard with credentials (browser blocks but shows misconfiguration)
    if (allowOrigin === '*' && allowCredentials && allowCredentials.toLowerCase() === 'true') {
      return {
        type: 'CORS Misconfiguration',
        subType: 'Wildcard with Credentials Attempt',
        severity: 'medium',
        url: url,
        evidence: `Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: ${allowCredentials}`,
        description: 'CORS policy attempts to use wildcard with credentials (browsers block this, but indicates misconfiguration intent).',
        remediation: 'Specify exact trusted origins instead of using wildcard.',
        references: [
          'https://portswigger.net/web-security/cors'
        ],
        cvss: 5.0,
        cwe: 'CWE-346'
      };
    }
    
    // Medium: Reflects origin without credentials
    if (allowOrigin === testOrigin && testOrigin.includes('evil')) {
      return {
        type: 'CORS Misconfiguration',
        subType: 'Origin Reflection',
        severity: 'medium',
        url: url,
        evidence: `Access-Control-Allow-Origin: ${allowOrigin}`,
        description: 'CORS policy reflects the Origin header. Without credentials, impact is limited but still a concern for sensitive data.',
        remediation: 'Use a strict allowlist of trusted origins.',
        references: [
          'https://portswigger.net/web-security/cors'
        ],
        cvss: 5.3,
        cwe: 'CWE-346'
      };
    }
    
    // Medium: Null origin allowed with credentials
    if (allowOrigin === 'null' && allowCredentials && allowCredentials.toLowerCase() === 'true') {
      return {
        type: 'CORS Misconfiguration',
        subType: 'Null Origin Allowed',
        severity: 'high',
        url: url,
        evidence: `Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true`,
        description: 'CORS policy allows null origin with credentials. Attackers can use sandboxed iframes to exploit this.',
        remediation: 'Never allow null origin, especially with credentials.',
        references: [
          'https://portswigger.net/web-security/cors/access-control-allow-origin'
        ],
        cvss: 7.5,
        cwe: 'CWE-346'
      };
    }
    
    // Low: Wildcard origin (may be intentional for public APIs)
    if (allowOrigin === '*') {
      return {
        type: 'CORS Misconfiguration',
        subType: 'Wildcard Origin',
        severity: 'info',
        url: url,
        evidence: `Access-Control-Allow-Origin: *`,
        description: 'CORS policy uses wildcard. This is acceptable for truly public resources but should be verified.',
        remediation: 'Ensure wildcard CORS is intentional and no sensitive data is exposed.',
        references: [
          'https://portswigger.net/web-security/cors'
        ],
        cvss: 2.0,
        cwe: 'CWE-346'
      };
    }
    
    // Check for subdomain matching vulnerabilities
    if (testOrigin.includes(this.extractDomain(url)) && allowOrigin === testOrigin) {
      // Check if it's accepting evil subdomains
      if (testOrigin.includes('evil') || testOrigin.includes('attacker')) {
        return {
          type: 'CORS Misconfiguration',
          subType: 'Subdomain Bypass',
          severity: 'high',
          url: url,
          evidence: `Origin ${testOrigin} was accepted`,
          description: 'CORS policy has weak subdomain validation, allowing attacker-controlled subdomains.',
          remediation: 'Use exact origin matching or a strict prefix check.',
          references: [
            'https://portswigger.net/web-security/cors'
          ],
          cvss: 6.5,
          cwe: 'CWE-346'
        };
      }
    }
    
    return null;
  }
}
