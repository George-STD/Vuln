import { BaseScanner } from './BaseScanner.js';

export class CSRFScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'CSRF Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { forms } = data;
    
    for (const form of forms) {
      if (this.stopped) break;
      
      // Check for POST forms without CSRF protection
      if (form.method === 'POST') {
        const csrfProtection = this.checkCSRFProtection(form);
        
        if (!csrfProtection.hasProtection) {
          // Verify if the form performs sensitive actions
          const isSensitive = this.isSensitiveForm(form);
          
          if (isSensitive) {
            vulnerabilities.push({
              type: 'CSRF',
              subType: 'Missing CSRF Token',
              severity: 'high',
              url: form.action,
              method: form.method,
              evidence: `Form at ${form.action} lacks CSRF protection. Missing tokens: ${csrfProtection.missingChecks.join(', ')}`,
              description: 'Cross-Site Request Forgery vulnerability detected. The form performs sensitive actions without CSRF token protection.',
              remediation: 'Implement CSRF tokens using the Synchronizer Token Pattern. Use SameSite cookie attribute. Verify Origin/Referer headers.',
              references: [
                'https://portswigger.net/web-security/csrf',
                'https://owasp.org/www-community/attacks/csrf',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
              ],
              cvss: 6.5,
              cwe: 'CWE-352',
              formDetails: {
                action: form.action,
                inputs: form.inputs.map(i => i.name).filter(Boolean)
              }
            });
          }
        }
        
        // Check for weak CSRF tokens
        if (csrfProtection.hasProtection && csrfProtection.tokenValue) {
          const tokenWeakness = this.analyzeTokenStrength(csrfProtection.tokenValue);
          
          if (tokenWeakness) {
            vulnerabilities.push({
              type: 'CSRF',
              subType: 'Weak CSRF Token',
              severity: 'medium',
              url: form.action,
              method: form.method,
              evidence: `CSRF token weakness: ${tokenWeakness}`,
              description: 'The CSRF token implementation appears to be weak and potentially bypassable.',
              remediation: 'Use cryptographically secure random tokens of sufficient length (at least 128 bits). Regenerate tokens per session.',
              references: [
                'https://portswigger.net/web-security/csrf/tokens'
              ],
              cvss: 5.0,
              cwe: 'CWE-352'
            });
          }
        }
      }
    }
    
    // Check for SameSite cookie attribute on main page
    const cookieVuln = await this.checkSameSiteCookie();
    if (cookieVuln) {
      vulnerabilities.push(cookieVuln);
    }
    
    return vulnerabilities;
  }
  
  checkCSRFProtection(form) {
    const csrfTokenNames = [
      'csrf', 'csrf_token', 'csrftoken', '_csrf', 'csrf-token',
      'xsrf', 'xsrf_token', 'xsrftoken', '_xsrf',
      'token', '_token', 'authenticity_token',
      'anti-csrf-token', 'anticsrf',
      '__RequestVerificationToken', // ASP.NET
      'form_token', 'form_key',
      'nonce', '_wpnonce' // WordPress
    ];
    
    let hasProtection = false;
    let tokenValue = null;
    const missingChecks = [];
    
    // Check for CSRF token in form inputs
    for (const input of form.inputs) {
      const inputName = (input.name || '').toLowerCase();
      const inputType = (input.type || '').toLowerCase();
      
      if (inputType === 'hidden') {
        for (const tokenName of csrfTokenNames) {
          if (inputName.includes(tokenName)) {
            hasProtection = true;
            tokenValue = input.value;
            break;
          }
        }
      }
    }
    
    if (!hasProtection) {
      missingChecks.push('No CSRF token in form fields');
    }
    
    return { hasProtection, tokenValue, missingChecks };
  }
  
  isSensitiveForm(form) {
    const sensitiveActions = [
      'login', 'signin', 'sign-in',
      'logout', 'signout', 'sign-out',
      'register', 'signup', 'sign-up',
      'password', 'passwd', 'pwd',
      'delete', 'remove',
      'update', 'edit', 'modify',
      'transfer', 'payment', 'pay',
      'admin', 'settings', 'config',
      'profile', 'account',
      'email', 'mail',
      'order', 'checkout', 'purchase'
    ];
    
    const actionUrl = (form.action || '').toLowerCase();
    const inputNames = form.inputs.map(i => (i.name || '').toLowerCase());
    
    // Check action URL
    for (const action of sensitiveActions) {
      if (actionUrl.includes(action)) return true;
    }
    
    // Check input names for sensitive fields
    const sensitiveFields = ['password', 'email', 'amount', 'transfer', 'delete'];
    for (const field of sensitiveFields) {
      if (inputNames.some(name => name.includes(field))) return true;
    }
    
    return false;
  }
  
  analyzeTokenStrength(token) {
    if (!token) return 'Empty token';
    
    // Check token length
    if (token.length < 16) {
      return `Token too short (${token.length} chars, minimum 16 recommended)`;
    }
    
    // Check for predictable patterns
    if (/^[0-9]+$/.test(token)) {
      return 'Token contains only numeric characters (potentially predictable)';
    }
    
    // Check if token is a simple timestamp
    const timestamp = parseInt(token);
    if (!isNaN(timestamp) && timestamp > 1000000000 && timestamp < 9999999999) {
      return 'Token appears to be a Unix timestamp (predictable)';
    }
    
    // Check for sequential patterns
    if (/^(.)\1+$/.test(token) || token === token.split('').reverse().join('')) {
      return 'Token has a predictable pattern';
    }
    
    return null; // Token appears strong
  }
  
  async checkSameSiteCookie() {
    try {
      const response = await this.makeRequest(this.targetUrl);
      if (!response) return null;
      
      const setCookieHeaders = response.headers['set-cookie'];
      if (!setCookieHeaders) return null;
      
      const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
      
      for (const cookie of cookies) {
        // Check for session cookies without SameSite
        if (cookie.toLowerCase().includes('session') || 
            cookie.toLowerCase().includes('auth') ||
            cookie.toLowerCase().includes('token')) {
          
          if (!cookie.toLowerCase().includes('samesite')) {
            return {
              type: 'CSRF',
              subType: 'Missing SameSite Cookie Attribute',
              severity: 'medium',
              url: this.targetUrl,
              evidence: `Session cookie lacks SameSite attribute: ${cookie.substring(0, 50)}...`,
              description: 'Session cookies are set without SameSite attribute, making them vulnerable to CSRF attacks in older browsers.',
              remediation: 'Set SameSite=Strict or SameSite=Lax on all session cookies.',
              references: [
                'https://portswigger.net/web-security/csrf/samesite-cookies',
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
              ],
              cvss: 4.0,
              cwe: 'CWE-1275'
            };
          }
        }
      }
    } catch (error) {
      this.log(`SameSite check error: ${error.message}`, 'debug');
    }
    
    return null;
  }
}
