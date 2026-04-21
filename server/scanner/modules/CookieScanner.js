import { BaseScanner } from './BaseScanner.js';

export class CookieScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Cookie Security Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls } = data;
    
    // Collect cookies from main page and other URLs
    const allCookies = await this.collectCookies(urls);
    
    // Analyze each cookie
    for (const cookie of allCookies) {
      const vulns = this.analyzeCookie(cookie);
      vulnerabilities.push(...vulns);
    }
    
    // Check for cookie poisoning vulnerabilities
    const poisoningVulns = await this.testCookiePoisoning();
    vulnerabilities.push(...poisoningVulns);
    
    return vulnerabilities;
  }
  
  async collectCookies(urls) {
    const cookies = new Map();
    
    const urlsToCheck = [this.targetUrl, ...urls.slice(0, 10)];
    
    for (const url of urlsToCheck) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(url);
        if (!response) continue;
        
        const setCookies = response.headers['set-cookie'];
        if (!setCookies) continue;
        
        const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];
        
        for (const cookieStr of cookieArray) {
          const parsed = this.parseCookie(cookieStr, url);
          if (parsed) {
            cookies.set(parsed.name, parsed);
          }
        }
      } catch {}
    }
    
    return Array.from(cookies.values());
  }
  
  parseCookie(cookieStr, sourceUrl) {
    try {
      const parts = cookieStr.split(';').map(p => p.trim());
      const [nameValue, ...attributes] = parts;
      const [name, ...valueParts] = nameValue.split('=');
      const value = valueParts.join('=');
      
      if (!name) return null;
      
      const cookie = {
        name: name.trim(),
        value: value,
        sourceUrl: sourceUrl,
        raw: cookieStr,
        httpOnly: false,
        secure: false,
        sameSite: null,
        path: '/',
        domain: null,
        expires: null,
        maxAge: null
      };
      
      for (const attr of attributes) {
        const lowerAttr = attr.toLowerCase();
        
        if (lowerAttr === 'httponly') {
          cookie.httpOnly = true;
        } else if (lowerAttr === 'secure') {
          cookie.secure = true;
        } else if (lowerAttr.startsWith('samesite=')) {
          cookie.sameSite = attr.split('=')[1]?.trim().toLowerCase();
        } else if (lowerAttr.startsWith('path=')) {
          cookie.path = attr.split('=')[1]?.trim();
        } else if (lowerAttr.startsWith('domain=')) {
          cookie.domain = attr.split('=')[1]?.trim();
        } else if (lowerAttr.startsWith('expires=')) {
          cookie.expires = attr.split('=')[1]?.trim();
        } else if (lowerAttr.startsWith('max-age=')) {
          cookie.maxAge = parseInt(attr.split('=')[1]?.trim());
        }
      }
      
      return cookie;
    } catch {
      return null;
    }
  }
  
  analyzeCookie(cookie) {
    const vulnerabilities = [];
    const isSessionCookie = this.isSessionCookie(cookie);
    const isAuthCookie = this.isAuthCookie(cookie);
    const isSensitive = isSessionCookie || isAuthCookie;
    
    // Check for missing HttpOnly flag
    if (!cookie.httpOnly && isSensitive) {
      vulnerabilities.push({
        type: 'Cookie Security',
        subType: 'Missing HttpOnly Flag',
        severity: 'medium',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" missing HttpOnly flag`,
        description: 'Session/auth cookie is accessible via JavaScript, enabling XSS attacks to steal it.',
        remediation: 'Add HttpOnly flag to prevent JavaScript access.',
        references: [
          'https://owasp.org/www-community/HttpOnly',
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'
        ],
        cvss: 5.3,
        cwe: 'CWE-1004'
      });
    }
    
    // Check for missing Secure flag
    const isHttps = this.targetUrl.startsWith('https');
    if (!cookie.secure && isSensitive) {
      vulnerabilities.push({
        type: 'Cookie Security',
        subType: 'Missing Secure Flag',
        severity: isHttps ? 'medium' : 'high',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" missing Secure flag`,
        description: 'Cookie can be transmitted over unencrypted HTTP connections.',
        remediation: 'Add Secure flag to ensure cookie is only sent over HTTPS.',
        references: [
          'https://owasp.org/www-community/controls/SecureCookieAttribute'
        ],
        cvss: isHttps ? 4.3 : 6.5,
        cwe: 'CWE-614'
      });
    }
    
    // Check for missing or weak SameSite attribute
    if (!cookie.sameSite && isSensitive) {
      vulnerabilities.push({
        type: 'Cookie Security',
        subType: 'Missing SameSite Attribute',
        severity: 'medium',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" missing SameSite attribute`,
        description: 'Cookie vulnerable to CSRF attacks without SameSite protection.',
        remediation: 'Add SameSite=Strict or SameSite=Lax attribute.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
        ],
        cvss: 4.3,
        cwe: 'CWE-1275'
      });
    } else if (cookie.sameSite === 'none' && !cookie.secure) {
      vulnerabilities.push({
        type: 'Cookie Security',
        subType: 'SameSite=None Without Secure',
        severity: 'medium',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" has SameSite=None but missing Secure flag`,
        description: 'SameSite=None requires Secure flag. Cookie may be rejected by browsers.',
        remediation: 'Add Secure flag when using SameSite=None.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
        ],
        cvss: 4.3,
        cwe: 'CWE-1275'
      });
    }
    
    // Check for overly broad domain
    if (cookie.domain && isSensitive) {
      const domainParts = cookie.domain.replace(/^\./, '').split('.');
      if (domainParts.length <= 2) {
        vulnerabilities.push({
          type: 'Cookie Security',
          subType: 'Broad Cookie Domain',
          severity: 'low',
          url: cookie.sourceUrl,
          cookie: cookie.name,
          evidence: `Cookie "${cookie.name}" has broad domain: ${cookie.domain}`,
          description: 'Cookie shared across all subdomains, increasing attack surface.',
          remediation: 'Limit cookie domain to specific subdomain if possible.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
          ],
          cvss: 3.1,
          cwe: 'CWE-784'
        });
      }
    }
    
    // Check for weak session ID
    if (isSessionCookie && cookie.value) {
      const weaknessCheck = this.checkSessionStrength(cookie.value);
      if (weaknessCheck) {
        vulnerabilities.push({
          type: 'Session Management',
          subType: weaknessCheck.type,
          severity: weaknessCheck.severity,
          url: cookie.sourceUrl,
          cookie: cookie.name,
          evidence: weaknessCheck.evidence,
          description: weaknessCheck.description,
          remediation: 'Use cryptographically secure random session IDs with sufficient entropy.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema'
          ],
          cvss: weaknessCheck.cvss,
          cwe: 'CWE-330'
        });
      }
    }
    
    // Check for sensitive data in cookie
    if (this.containsSensitiveData(cookie.name, cookie.value)) {
      vulnerabilities.push({
        type: 'Cookie Security',
        subType: 'Sensitive Data in Cookie',
        severity: 'medium',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" may contain sensitive data`,
        description: 'Cookie appears to contain sensitive information that could be exposed.',
        remediation: 'Avoid storing sensitive data in cookies. Use server-side sessions.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
        ],
        cvss: 5.3,
        cwe: 'CWE-315'
      });
    }
    
    // Check for very long expiration
    if (cookie.maxAge && cookie.maxAge > 31536000 && isSensitive) {
      vulnerabilities.push({
        type: 'Session Management',
        subType: 'Excessive Session Duration',
        severity: 'low',
        url: cookie.sourceUrl,
        cookie: cookie.name,
        evidence: `Cookie "${cookie.name}" expires in ${Math.round(cookie.maxAge / 86400)} days`,
        description: 'Session cookie has very long expiration, increasing window for attacks.',
        remediation: 'Use shorter session durations and implement session timeout.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Session_Timeout'
        ],
        cvss: 3.1,
        cwe: 'CWE-613'
      });
    }
    
    return vulnerabilities;
  }
  
  isSessionCookie(cookie) {
    const name = cookie.name.toLowerCase();
    const sessionIndicators = [
      'session', 'sess', 'sid', 'ssid', 'phpsessid', 'jsessionid',
      'asp.net_sessionid', 'aspsessionid', 'cfid', 'cftoken'
    ];
    return sessionIndicators.some(i => name.includes(i));
  }
  
  isAuthCookie(cookie) {
    const name = cookie.name.toLowerCase();
    const authIndicators = [
      'auth', 'token', 'jwt', 'access', 'refresh', 'login',
      'user', 'remember', 'credential', 'identity'
    ];
    return authIndicators.some(i => name.includes(i));
  }
  
  checkSessionStrength(value) {
    // Check for very short session ID
    if (value.length < 16) {
      return {
        type: 'Weak Session ID Length',
        severity: 'high',
        evidence: `Session ID length: ${value.length} characters (minimum 128 bits recommended)`,
        description: 'Session ID is too short, making it susceptible to brute force attacks.',
        cvss: 7.5
      };
    }
    
    // Check for low entropy (numeric only)
    if (/^\d+$/.test(value)) {
      return {
        type: 'Numeric Only Session ID',
        severity: 'high',
        evidence: 'Session ID contains only numeric characters',
        description: 'Session ID has low entropy due to numeric-only character set.',
        cvss: 7.5
      };
    }
    
    // Check for sequential patterns
    if (/^[0-9]+$/.test(value) && !isNaN(parseInt(value))) {
      const num = parseInt(value);
      if (num < 1000000) {
        return {
          type: 'Predictable Session ID',
          severity: 'critical',
          evidence: 'Session ID appears to be a small sequential number',
          description: 'Session ID may be predictable and enumerable.',
          cvss: 9.1
        };
      }
    }
    
    // Check for base64 encoded simple values
    try {
      const decoded = Buffer.from(value, 'base64').toString();
      if (decoded.length < value.length * 0.5 && /^[\w\s:=]+$/.test(decoded)) {
        if (/user|admin|id|session/i.test(decoded)) {
          return {
            type: 'Encoded Session Data',
            severity: 'medium',
            evidence: 'Session ID appears to be base64 encoded simple data',
            description: 'Session ID may contain predictable encoded information.',
            cvss: 5.3
          };
        }
      }
    } catch {}
    
    return null;
  }
  
  containsSensitiveData(name, value) {
    const sensitivePatterns = [
      /password/i,
      /passwd/i,
      /secret/i,
      /credit/i,
      /card/i,
      /ssn/i,
      /email=.*@/i,
      /user=\w+/i
    ];
    
    const combined = `${name}=${value}`;
    return sensitivePatterns.some(p => p.test(combined));
  }
  
  async testCookiePoisoning() {
    const vulnerabilities = [];
    
    // Test for cookie injection via HTTP response splitting
    const injectionPayloads = [
      '%0d%0aSet-Cookie:%20injected=true',
      '%0aSet-Cookie:%20injected=true',
      '\r\nSet-Cookie: injected=true'
    ];
    
    try {
      const parsedUrl = new URL(this.targetUrl);
      
      for (const payload of injectionPayloads) {
        if (this.stopped) break;
        
        const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?redirect=${encodeURIComponent(payload)}`;
        
        const response = await this.makeRequest(testUrl, {
          maxRedirects: 0,
          validateStatus: () => true
        });
        
        if (!response) continue;
        
        const setCookies = response.headers['set-cookie'];
        if (setCookies) {
          const cookieStr = Array.isArray(setCookies) ? setCookies.join(' ') : setCookies;
          if (cookieStr.includes('injected=true')) {
            vulnerabilities.push({
              type: 'Cookie Security',
              subType: 'Cookie Injection',
              severity: 'high',
              url: testUrl,
              evidence: 'Successfully injected cookie via HTTP response splitting',
              description: 'Application vulnerable to HTTP response splitting allowing cookie injection.',
              remediation: 'Sanitize all user input that ends up in HTTP headers.',
              references: [
                'https://owasp.org/www-community/attacks/HTTP_Response_Splitting'
              ],
              cvss: 7.5,
              cwe: 'CWE-113'
            });
            break;
          }
        }
      }
    } catch {}
    
    return vulnerabilities;
  }
}
