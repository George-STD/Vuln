import { BaseScanner } from './BaseScanner.js';

export class OpenRedirectScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Open Redirect Scanner';
    
    // Redirect parameter names
    this.redirectParams = [
      'url', 'redirect', 'redirect_uri', 'redirect_url', 'redirectUrl',
      'return', 'returnUrl', 'return_url', 'returnTo', 'return_to',
      'next', 'nextUrl', 'next_url', 'destination', 'dest', 'target',
      'redir', 'rurl', 'go', 'goto', 'link', 'forward', 'continue',
      'callback', 'callback_url', 'path', 'out', 'view', 'site',
      'to', 'image_url', 'checkout_url', 'ref', 'reference', 'page'
    ];
    
    // Open redirect payloads
    this.payloads = [
      // Basic external redirects
      'https://evil.com',
      'http://evil.com',
      '//evil.com',
      
      // Protocol-relative URL
      '//evil.com/%2f..',
      
      // Bypass techniques
      'https://evil.com//',
      'https://evil.com/\t',
      'https://evil.com?',
      'https://evil.com#',
      
      // URL encoding bypass
      'https%3A%2F%2Fevil.com',
      '%2F%2Fevil.com',
      '//evil%E3%80%82com',
      
      // Backslash confusion
      'https://evil.com\\@target.com',
      '//evil.com\\@target.com',
      '\\/\\/evil.com',
      '/\\/evil.com',
      
      // At-sign confusion
      'https://target.com@evil.com',
      '//target.com@evil.com/',
      
      // Parameter pollution
      'https://target.com?url=https://evil.com',
      
      // JavaScript pseudo-protocol
      'javascript:alert(document.domain)',
      'javascript://evil.com/%0aalert(1)',
      'java\tscript:alert(1)',
      
      // Data URI
      'data:text/html,<script>alert(1)</script>',
      
      // Null byte
      '//evil.com%00.target.com',
      '//evil.com%0d%0a.target.com',
      
      // Path confusion
      '/\\evil.com',
      '/%5cevil.com',
      '/evil.com',
      '////evil.com',
      
      // Unicode normalization bypass
      '//ⓔⓥⓘⓛ.ⓒⓞⓜ',
      
      // CRLF injection for header injection
      '%0d%0aLocation: https://evil.com',
      
      // IP address variations
      '//0x7f000001',
      '//2130706433',
      '//127.1'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms } = data;
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          if (this.isRedirectParam(key) || this.looksLikeUrl(value)) {
            const vulns = await this.testParameter(url, key, value);
            vulnerabilities.push(...vulns);
          }
        }
      } catch (error) {
        this.log(`Open redirect URL parse error: ${error.message}`, 'debug');
      }
    }
    
    // Test forms
    for (const form of forms) {
      if (this.stopped) break;
      
      for (const input of form.inputs) {
        if (!input.name) continue;
        
        if (this.isRedirectParam(input.name)) {
          const vulns = await this.testFormInput(form, input);
          vulnerabilities.push(...vulns);
        }
      }
    }
    
    return vulnerabilities;
  }
  
  isRedirectParam(param) {
    const paramLower = param.toLowerCase();
    return this.redirectParams.some(rp => paramLower.includes(rp.toLowerCase()));
  }
  
  looksLikeUrl(value) {
    if (!value) return false;
    return /^https?:\/\//i.test(value) || 
           /^\/\//i.test(value) ||
           /^\/[a-z]/i.test(value);
  }
  
  async testParameter(baseUrl, paramName, originalValue) {
    const vulnerabilities = [];
    const testPayloads = this.getTestPayloads();
    
    for (const payload of testPayloads) {
      if (this.stopped) break;
      
      try {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(paramName, payload);
        
        const response = await this.makeRequest(testUrl.href, {
          maxRedirects: 0
        });
        
        if (!response) continue;
        
        const redirectIndicators = this.detectOpenRedirect(response, payload);
        
        if (redirectIndicators.detected) {
          vulnerabilities.push({
            type: 'Open Redirect',
            subType: redirectIndicators.type,
            severity: redirectIndicators.severity,
            url: baseUrl,
            parameter: paramName,
            payload: payload,
            evidence: redirectIndicators.evidence,
            description: `Open Redirect vulnerability in parameter "${paramName}". ${redirectIndicators.description}`,
            remediation: 'Validate redirect URLs against an allowlist of permitted domains. Use relative URLs only. Avoid using user-supplied URLs for redirects.',
            references: [
              'https://portswigger.net/kb/issues/00500100_open-redirection-reflected',
              'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
            ],
            cvss: redirectIndicators.severity === 'high' ? 6.1 : 4.0,
            cwe: 'CWE-601'
          });
          
          break;
        }
      } catch (error) {
        this.log(`Open redirect test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async testFormInput(form, input) {
    const vulnerabilities = [];
    const testPayloads = this.getTestPayloads();
    
    for (const payload of testPayloads) {
      if (this.stopped) break;
      
      const formData = {};
      form.inputs.forEach(inp => {
        formData[inp.name] = inp.name === input.name ? payload : inp.value || 'test';
      });
      
      try {
        const response = await this.makeRequest(form.action, {
          method: form.method,
          data: form.method === 'POST' ? formData : undefined,
          params: form.method === 'GET' ? formData : undefined,
          maxRedirects: 0
        });
        
        if (!response) continue;
        
        const redirectIndicators = this.detectOpenRedirect(response, payload);
        
        if (redirectIndicators.detected) {
          vulnerabilities.push({
            type: 'Open Redirect',
            subType: redirectIndicators.type,
            severity: 'medium',
            url: form.action,
            method: form.method,
            parameter: input.name,
            payload: payload,
            evidence: redirectIndicators.evidence,
            description: `Open redirect in form field "${input.name}"`,
            remediation: 'Validate redirect destinations.',
            references: [
              'https://portswigger.net/kb/issues/00500100_open-redirection-reflected'
            ],
            cvss: 4.0,
            cwe: 'CWE-601'
          });
          break;
        }
      } catch (error) {
        this.log(`Open redirect form test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  detectOpenRedirect(response, payload) {
    const result = {
      detected: false,
      type: '',
      severity: 'medium',
      evidence: '',
      description: ''
    };
    
    const status = response.status;
    const locationHeader = response.headers['location'] || '';
    const body = response.data?.toString() || '';
    
    // Check for redirect response with external URL
    if (status >= 300 && status < 400) {
      if (this.isExternalRedirect(locationHeader, payload)) {
        result.detected = true;
        result.type = 'Header-based Redirect';
        result.severity = 'high';
        result.evidence = `Location header: ${locationHeader}`;
        result.description = 'Server redirects to external URL via Location header.';
        return result;
      }
    }
    
    // Check for meta refresh redirect
    const metaRefreshPattern = /<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/i;
    const metaMatch = body.match(metaRefreshPattern);
    if (metaMatch && this.isExternalRedirect(metaMatch[1], payload)) {
      result.detected = true;
      result.type = 'Meta Refresh Redirect';
      result.severity = 'medium';
      result.evidence = `Meta refresh URL: ${metaMatch[1]}`;
      result.description = 'Page uses meta refresh to redirect to external URL.';
      return result;
    }
    
    // Check for JavaScript redirect
    const jsRedirectPatterns = [
      /window\.location\s*=\s*["']([^"']+)["']/i,
      /window\.location\.href\s*=\s*["']([^"']+)["']/i,
      /location\.replace\s*\(\s*["']([^"']+)["']/i,
      /window\.open\s*\(\s*["']([^"']+)["']/i
    ];
    
    for (const pattern of jsRedirectPatterns) {
      const jsMatch = body.match(pattern);
      if (jsMatch && this.isExternalRedirect(jsMatch[1], payload)) {
        result.detected = true;
        result.type = 'JavaScript Redirect';
        result.severity = 'medium';
        result.evidence = `JavaScript redirect: ${jsMatch[1]}`;
        result.description = 'Page uses JavaScript to redirect to external URL.';
        return result;
      }
    }
    
    // Check if payload appears in response (DOM-based potential)
    if (payload.includes('evil.com') && body.includes('evil.com')) {
      result.detected = true;
      result.type = 'Potential DOM-based Redirect';
      result.severity = 'low';
      result.evidence = 'External URL reflected in response';
      result.description = 'External URL appears in response, potential client-side redirect.';
      return result;
    }
    
    return result;
  }
  
  isExternalRedirect(url, payload) {
    if (!url) return false;
    
    const urlLower = url.toLowerCase();
    
    // Check if redirect is to an external domain
    if (urlLower.includes('evil.com') || 
        urlLower.includes('0x7f') ||
        urlLower.includes('2130706433')) {
      return true;
    }
    
    // Check if URL matches payload structure
    if (payload.includes('evil.com') && urlLower.includes('evil')) {
      return true;
    }
    
    // Check for protocol-relative URLs to external domains
    if (urlLower.startsWith('//') && !urlLower.includes(this.extractDomain(this.targetUrl))) {
      return true;
    }
    
    return false;
  }
  
  getTestPayloads() {
    return [
      'https://evil.com',
      '//evil.com',
      'https://evil.com//',
      '//evil.com/%2f..',
      'https://target.com@evil.com'
    ];
  }
}
