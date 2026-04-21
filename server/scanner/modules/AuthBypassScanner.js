import { BaseScanner } from './BaseScanner.js';

export class AuthBypassScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Authentication Bypass Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, endpoints } = data;
    
    // Find login forms
    const loginForms = forms.filter(f => this.isLoginForm(f));
    
    // Test default credentials
    for (const form of loginForms) {
      if (this.stopped) break;
      const vulns = await this.testDefaultCredentials(form);
      vulnerabilities.push(...vulns);
    }
    
    // Test for authentication bypass via HTTP method manipulation
    const methodVulns = await this.testMethodBypass(urls);
    vulnerabilities.push(...methodVulns);
    
    // Test for path traversal bypass
    const pathVulns = await this.testPathBypass(urls);
    vulnerabilities.push(...pathVulns);
    
    // Test for JWT weaknesses
    const jwtVulns = await this.testJWTWeaknesses();
    vulnerabilities.push(...jwtVulns);
    
    return vulnerabilities;
  }
  
  isLoginForm(form) {
    const actionLower = (form.action || '').toLowerCase();
    const inputs = form.inputs.map(i => (i.name || '').toLowerCase());
    
    // Check action URL
    if (/login|signin|auth|session|authenticate/i.test(actionLower)) {
      return true;
    }
    
    // Check for password field
    if (inputs.some(i => i.includes('password') || i.includes('passwd'))) {
      return true;
    }
    
    return false;
  }
  
  async testDefaultCredentials(form) {
    const vulnerabilities = [];
    
    const defaultCreds = [
      { username: 'admin', password: 'admin' },
      { username: 'admin', password: 'password' },
      { username: 'admin', password: '123456' },
      { username: 'admin', password: 'admin123' },
      { username: 'root', password: 'root' },
      { username: 'root', password: 'password' },
      { username: 'user', password: 'user' },
      { username: 'test', password: 'test' },
      { username: 'guest', password: 'guest' },
      { username: 'administrator', password: 'administrator' }
    ];
    
    // Find username and password fields
    let usernameField = null;
    let passwordField = null;
    
    for (const input of form.inputs) {
      const name = (input.name || '').toLowerCase();
      const type = (input.type || '').toLowerCase();
      
      if (type === 'password' || name.includes('password') || name.includes('passwd')) {
        passwordField = input.name;
      } else if (name.includes('user') || name.includes('email') || name.includes('login')) {
        usernameField = input.name;
      }
    }
    
    if (!usernameField || !passwordField) return vulnerabilities;
    
    // Get baseline for failed login
    const baselineData = {};
    form.inputs.forEach(inp => {
      baselineData[inp.name] = inp.value || '';
    });
    baselineData[usernameField] = 'invaliduser' + Math.random();
    baselineData[passwordField] = 'invalidpass' + Math.random();
    
    let baselineResponse;
    try {
      baselineResponse = await this.makeRequest(form.action, {
        method: form.method,
        data: form.method === 'POST' ? baselineData : undefined,
        params: form.method === 'GET' ? baselineData : undefined
      });
    } catch {
      return vulnerabilities;
    }
    
    // Test default credentials
    for (const cred of defaultCreds) {
      if (this.stopped) break;
      
      const formData = { ...baselineData };
      formData[usernameField] = cred.username;
      formData[passwordField] = cred.password;
      
      try {
        const response = await this.makeRequest(form.action, {
          method: form.method,
          data: form.method === 'POST' ? formData : undefined,
          params: form.method === 'GET' ? formData : undefined
        });
        
        if (!response) continue;
        
        // Check for successful login indicators
        if (this.isSuccessfulLogin(response, baselineResponse)) {
          vulnerabilities.push({
            type: 'Authentication Bypass',
            subType: 'Default Credentials',
            severity: 'critical',
            url: form.action,
            method: form.method,
            evidence: `Successful login with ${cred.username}:${cred.password}`,
            description: `Default credentials work: ${cred.username}/${cred.password}`,
            remediation: 'Change default credentials immediately. Implement account lockout policies.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials'
            ],
            cvss: 9.8,
            cwe: 'CWE-798'
          });
          
          break; // Found working credentials
        }
      } catch (error) {
        this.log(`Default creds test error: ${error.message}`, 'debug');
      }
      
      // Add delay to avoid rate limiting
      await this.delay(500);
    }
    
    return vulnerabilities;
  }
  
  isSuccessfulLogin(response, baselineResponse) {
    if (!response || !baselineResponse) return false;
    
    // Check for redirect to different page
    if (response.status === 302 || response.status === 301) {
      const location = response.headers['location'] || '';
      if (!location.includes('login') && !location.includes('error')) {
        return true;
      }
    }
    
    // Check for session cookie being set
    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
      const cookies = Array.isArray(setCookie) ? setCookie.join(' ') : setCookie;
      if (/session|auth|token|logged/i.test(cookies)) {
        return true;
      }
    }
    
    // Check response body for success indicators
    const body = response.data?.toString() || '';
    const baseBody = baselineResponse.data?.toString() || '';
    
    const successIndicators = [
      /welcome/i,
      /dashboard/i,
      /logout/i,
      /sign out/i,
      /my account/i,
      /profile/i
    ];
    
    const failureIndicators = [
      /invalid/i,
      /incorrect/i,
      /error/i,
      /failed/i,
      /wrong/i
    ];
    
    // Check if success indicators present in response but not baseline
    for (const indicator of successIndicators) {
      if (indicator.test(body) && !indicator.test(baseBody)) {
        return true;
      }
    }
    
    // Check if failure indicators NOT present
    const hasFailure = failureIndicators.some(i => i.test(body));
    if (!hasFailure && response.status === 200 && Math.abs(body.length - baseBody.length) > 500) {
      return true;
    }
    
    return false;
  }
  
  async testMethodBypass(urls) {
    const vulnerabilities = [];
    
    // Find admin/protected URLs
    const protectedUrls = urls.filter(url => 
      /admin|dashboard|manage|settings|config|control/i.test(url)
    );
    
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    
    for (const url of protectedUrls.slice(0, 5)) {
      if (this.stopped) break;
      
      // Get baseline with GET
      let baselineStatus;
      try {
        const baseline = await this.makeRequest(url);
        baselineStatus = baseline?.status;
        
        // If accessible, not a protected resource
        if (baselineStatus === 200) continue;
      } catch {
        continue;
      }
      
      // Try other methods
      for (const method of methods) {
        if (method === 'GET') continue;
        
        try {
          const response = await this.makeRequest(url, { method });
          
          if (response && response.status === 200 && baselineStatus !== 200) {
            vulnerabilities.push({
              type: 'Authentication Bypass',
              subType: 'HTTP Method Bypass',
              severity: 'high',
              url: url,
              method: method,
              evidence: `${method} request returned 200 while GET returned ${baselineStatus}`,
              description: `Protected resource accessible via ${method} method.`,
              remediation: 'Implement authorization checks for all HTTP methods.',
              references: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'
              ],
              cvss: 7.5,
              cwe: 'CWE-287'
            });
            break;
          }
        } catch {}
      }
    }
    
    return vulnerabilities;
  }
  
  async testPathBypass(urls) {
    const vulnerabilities = [];
    
    const protectedUrls = urls.filter(url => 
      /admin|dashboard|manage/i.test(url)
    );
    
    const bypassPayloads = [
      '..;/',
      '/..;/',
      '%2e%2e%3b/',
      '/.;/',
      '/;/',
      '/.//',
      '/%2e/',
      '/./'
    ];
    
    for (const url of protectedUrls.slice(0, 3)) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        const baseline = await this.makeRequest(url);
        
        if (!baseline || baseline.status === 200) continue;
        
        for (const payload of bypassPayloads) {
          const testPath = parsedUrl.pathname + payload;
          const testUrl = `${parsedUrl.origin}${testPath}`;
          
          const response = await this.makeRequest(testUrl);
          
          if (response && response.status === 200 && baseline.status !== 200) {
            vulnerabilities.push({
              type: 'Authentication Bypass',
              subType: 'Path Traversal Bypass',
              severity: 'high',
              url: url,
              payload: payload,
              evidence: `Path ${testPath} bypassed authentication`,
              description: 'Authentication can be bypassed using path manipulation.',
              remediation: 'Normalize paths before authorization checks. Use proper path parsing.',
              references: [
                'https://portswigger.net/web-security/authentication/other-mechanisms'
              ],
              cvss: 7.5,
              cwe: 'CWE-287'
            });
            break;
          }
        }
      } catch {}
    }
    
    return vulnerabilities;
  }
  
  async testJWTWeaknesses() {
    const vulnerabilities = [];
    
    try {
      const response = await this.makeRequest(this.targetUrl);
      if (!response) return vulnerabilities;
      
      // Check cookies for JWT
      const cookies = response.headers['set-cookie'];
      if (cookies) {
        const cookieStr = Array.isArray(cookies) ? cookies.join(' ') : cookies;
        const jwtMatch = cookieStr.match(/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/);
        
        if (jwtMatch) {
          const jwtVuln = this.analyzeJWT(jwtMatch[0]);
          if (jwtVuln) vulnerabilities.push(jwtVuln);
        }
      }
    } catch {}
    
    return vulnerabilities;
  }
  
  analyzeJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      
      // Check for none algorithm
      if (header.alg && header.alg.toLowerCase() === 'none') {
        return {
          type: 'Authentication Bypass',
          subType: 'JWT None Algorithm',
          severity: 'critical',
          url: this.targetUrl,
          evidence: 'JWT uses "none" algorithm',
          description: 'JWT accepts "none" algorithm, allowing signature bypass.',
          remediation: 'Explicitly reject "none" algorithm. Use strong algorithms like RS256.',
          references: [
            'https://portswigger.net/web-security/jwt/algorithm-confusion'
          ],
          cvss: 9.8,
          cwe: 'CWE-327'
        };
      }
      
      // Check for weak algorithms
      if (header.alg === 'HS256') {
        return {
          type: 'JWT Weakness',
          subType: 'Symmetric Algorithm',
          severity: 'info',
          url: this.targetUrl,
          evidence: 'JWT uses HS256 algorithm',
          description: 'JWT uses symmetric signing. Ensure key is strong and protected.',
          remediation: 'Consider using asymmetric algorithms (RS256) for better security.',
          references: [
            'https://portswigger.net/web-security/jwt'
          ],
          cvss: 3.0,
          cwe: 'CWE-327'
        };
      }
    } catch {}
    
    return null;
  }
}
