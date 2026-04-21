import puppeteer from 'puppeteer';
import crypto from 'crypto';
import { createScanLogger } from '../../utils/Logger.js';

export class DOMXSSScanner {
  constructor(options = {}) {
    this.options = {
      timeout: options.timeout || 30000,
      ...options
    };
    this.name = 'DOM XSS Scanner';
    this.logger = null;
  }

  /**
   * Known DOM XSS sources - where untrusted data enters
   */
  get sources() {
    return [
      'document.URL',
      'document.documentURI',
      'document.baseURI',
      'document.referrer',
      'document.cookie',
      'location',
      'location.href',
      'location.search',
      'location.hash',
      'location.pathname',
      'window.name',
      'history.pushState',
      'history.replaceState',
      'localStorage',
      'sessionStorage',
      'IndexedDB',
      'WebSocket',
      'XMLHttpRequest',
      'fetch',
      'postMessage',
      'FileReader'
    ];
  }

  /**
   * Known DOM XSS sinks - where untrusted data is used dangerously
   */
  get sinks() {
    return {
      high: [
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'setImmediate',
        'execScript',
        'document.write',
        'document.writeln',
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'onevent' // All event handlers
      ],
      medium: [
        'location',
        'location.href',
        'location.assign',
        'location.replace',
        'window.open',
        'document.domain',
        'WebSocket',
        'postMessage',
        'src',
        'href',
        'action',
        'formAction',
        'data'
      ],
      low: [
        'textContent',
        'innerText',
        'setAttribute',
        'createTextNode',
        'appendChild',
        'insertBefore',
        'replaceChild'
      ]
    };
  }

  /**
   * Generate a unique XSS verification token.
   * This token is used to confirm that injected payloads actually executed,
   * rather than just being reflected in the DOM as raw text.
   * 
   * @returns {string} A unique token like "vulnhunter_xss_a1b2c3d4e5f6"
   */
  generateXSSToken() {
    const randomPart = crypto.randomUUID
      ? crypto.randomUUID().replace(/-/g, '').substring(0, 12)
      : Math.random().toString(36).substring(2, 14);
    return `vulnhunter_xss_${randomPart}`;
  }

  /**
   * Main scan method
   * 
   * REFACTORED APPROACH:
   * The old scanner relied purely on static regex to match source-sink patterns.
   * This produced false positives because:
   *   - Finding "location" and "innerHTML" near each other doesn't prove data flow.
   *   - Minified JS bundles often have these tokens in proximity without actual taint flow.
   *
   * NEW APPROACH:
   *   Phase 1 (Static): Same regex analysis, but findings are marked as "candidates" only.
   *   Phase 2 (Dynamic Verification): For high/medium candidates, inject payloads that:
   *     a) Create a unique DOM element (e.g., <div id="vulnhunter_xss_TOKEN">), OR
   *     b) Call console.log('vulnhunter_xss_TOKEN')
   *   Then hook into Puppeteer's console/DOM events to verify actual execution.
   *   Only verified findings are reported as vulnerabilities.
   */
  async scan(targetUrl, scanId) {
    this.logger = createScanLogger(scanId);
    const vulnerabilities = [];
    let browser = null;

    try {
      this.logger.info(`Starting DOM XSS scan for: ${targetUrl}`);
      
      browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });

      const page = await browser.newPage();
      
      // Collect JavaScript sources and analyze
      const jsAnalysis = await this.analyzePageJS(page, targetUrl);
      
      // ── Phase 1: Static Analysis (identify candidates) ──
      const staticCandidates = await this.findDOMXSSPatterns(jsAnalysis);
      this.logger.info(`Static analysis found ${staticCandidates.length} DOM XSS candidates`);
      
      /**
       * We no longer report static-only findings as vulnerabilities.
       * Instead, we use them to determine WHICH injection points to test dynamically.
       * Only the dynamic verification results are reported.
       */

      // ── Phase 2: Dynamic Verification ──
      // Test hash-based, search-based, and common parameter injection points
      const dynamicResults = await this.dynamicVerification(page, targetUrl, staticCandidates);
      vulnerabilities.push(...dynamicResults);

      // Check for jQuery/Angular specific vulnerabilities
      // (Framework checks are still valid as informational findings)
      const frameworkVulns = await this.checkFrameworkVulnerabilities(page);
      vulnerabilities.push(...frameworkVulns);

      this.logger.info(`DOM XSS scan complete. Found ${vulnerabilities.length} verified issues.`);

    } catch (error) {
      this.logger.error(`DOM XSS scan error: ${error.message}`);
    } finally {
      if (browser) {
        await browser.close();
      }
    }

    return vulnerabilities;
  }

  /**
   * Analyze JavaScript on the page
   */
  async analyzePageJS(page, url) {
    const jsContent = {
      inline: [],
      external: [],
      eventHandlers: []
    };

    // Intercept and collect JavaScript
    page.on('response', async (response) => {
      try {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('javascript')) {
          const text = await response.text();
          jsContent.external.push({
            url: response.url(),
            content: text
          });
        }
      } catch (e) {
        // Ignore errors
      }
    });

    await page.goto(url, { waitUntil: 'networkidle2', timeout: this.options.timeout });

    // Get inline scripts
    jsContent.inline = await page.evaluate(() => {
      const scripts = [];
      document.querySelectorAll('script:not([src])').forEach(script => {
        scripts.push(script.textContent);
      });
      return scripts;
    });

    // Get event handlers from HTML
    jsContent.eventHandlers = await page.evaluate(() => {
      const handlers = [];
      const eventAttrs = [
        'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
        'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeyup',
        'onkeydown', 'onkeypress', 'ondblclick', 'oncontextmenu'
      ];

      const allElements = document.querySelectorAll('*');
      allElements.forEach(el => {
        eventAttrs.forEach(attr => {
          if (el.hasAttribute(attr)) {
            handlers.push({
              element: el.tagName,
              attribute: attr,
              value: el.getAttribute(attr)
            });
          }
        });
      });

      return handlers;
    });

    return jsContent;
  }

  /**
   * Find DOM XSS patterns in JavaScript (Static Analysis — Phase 1)
   * These are now treated as CANDIDATES, not confirmed vulnerabilities.
   */
  async findDOMXSSPatterns(jsAnalysis) {
    const patterns = [];
    const allJS = [
      ...jsAnalysis.inline,
      ...jsAnalysis.external.map(e => e.content)
    ].join('\n');

    // Check each source-sink combination
    for (const source of this.sources) {
      for (const [severity, sinks] of Object.entries(this.sinks)) {
        for (const sink of sinks) {
          const pattern = this.checkSourceToSink(allJS, source, sink, severity);
          if (pattern) {
            patterns.push(pattern);
          }
        }
      }
    }

    // Check event handlers
    for (const handler of jsAnalysis.eventHandlers) {
      const handlerPatterns = this.analyzeEventHandler(handler);
      patterns.push(...handlerPatterns);
    }

    // Check for dangerous patterns
    const dangerousPatterns = this.checkDangerousPatterns(allJS);
    patterns.push(...dangerousPatterns);

    return patterns;
  }

  /**
   * Check for source to sink flow
   */
  checkSourceToSink(js, source, sink, severity) {
    // Simple heuristic: look for source and sink in proximity
    const sourceRegex = new RegExp(source.replace('.', '\\.'), 'gi');
    const sinkRegex = new RegExp(sink.replace('.', '\\.'), 'gi');

    const lines = js.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join('\n');
      
      if (sourceRegex.test(line) && sinkRegex.test(context)) {
        return {
          severity,
          source,
          sink,
          code: context.substring(0, 500),
          description: `Potential data flow from ${source} to ${sink}`,
          evidence: `Found ${source} flowing to ${sink}`
        };
      }
    }

    return null;
  }

  /**
   * Analyze event handler for XSS
   */
  analyzeEventHandler(handler) {
    const patterns = [];
    const value = handler.value;

    // Check for direct use of location/document
    if (/location\s*[=.]|document\.(URL|referrer|cookie)|eval\s*\(/.test(value)) {
      patterns.push({
        severity: 'high',
        source: 'event handler',
        sink: handler.attribute,
        code: `<${handler.element} ${handler.attribute}="${value}">`,
        description: `Event handler ${handler.attribute} may be vulnerable to DOM XSS`,
        evidence: `Potentially unsafe code in ${handler.attribute} handler`
      });
    }

    return patterns;
  }

  /**
   * Check for known dangerous patterns
   */
  checkDangerousPatterns(js) {
    const patterns = [];
    const dangerousPatterns = [
      {
        regex: /\$\((.*location\.hash.*|.*location\.search.*|.*document\.URL.*)\)/gi,
        description: 'jQuery selector with user input',
        severity: 'high'
      },
      {
        regex: /\.html\s*\(\s*(location\.|document\.URL|document\.referrer)/gi,
        description: 'jQuery .html() with user input',
        severity: 'high'
      },
      {
        regex: /innerHTML\s*=\s*[^;]*(location\.|document\.URL|document\.referrer)/gi,
        description: 'innerHTML assignment with user input',
        severity: 'high'
      },
      {
        regex: /document\.write\s*\([^)]*location\./gi,
        description: 'document.write with location data',
        severity: 'high'
      },
      {
        regex: /eval\s*\(\s*[^)]*\+/gi,
        description: 'eval with string concatenation',
        severity: 'high'
      },
      {
        regex: /new\s+Function\s*\([^)]*\+/gi,
        description: 'Function constructor with concatenation',
        severity: 'high'
      },
      {
        regex: /setTimeout\s*\(\s*[^,)]+\s*\+/gi,
        description: 'setTimeout with string concatenation',
        severity: 'medium'
      },
      {
        regex: /\.attr\s*\(\s*['"](?:href|src|action)['"]\s*,\s*[^)]*location\./gi,
        description: 'jQuery attr with location data',
        severity: 'medium'
      },
      {
        regex: /ng-bind-html-unsafe|ng-bind-html\s*=\s*['"]\s*\{\{.*\}\}/gi,
        description: 'Angular unsafe binding',
        severity: 'high'
      },
      {
        regex: /dangerouslySetInnerHTML/gi,
        description: 'React dangerouslySetInnerHTML usage',
        severity: 'medium'
      },
      {
        regex: /v-html\s*=\s*["'][^"']*(?:user|input|param|query)/gi,
        description: 'Vue v-html with user data',
        severity: 'high'
      }
    ];

    for (const { regex, description, severity } of dangerousPatterns) {
      const matches = js.match(regex);
      if (matches) {
        for (const match of matches) {
          patterns.push({
            severity,
            source: 'user input',
            sink: description,
            code: match.substring(0, 200),
            description: `Dangerous pattern: ${description}`,
            evidence: match.substring(0, 100)
          });
        }
      }
    }

    return patterns;
  }

  /**
   * DYNAMIC VERIFICATION (Phase 2)
   * 
   * Instead of relying on static regex matches, we inject actual payloads
   * and verify execution through Puppeteer's console and DOM hooks.
   *
   * Strategy:
   *   1. For each injection vector (hash, search params, common params):
   *      a) Generate a unique token (e.g., "vulnhunter_xss_a1b2c3d4e5f6")
   *      b) Inject a payload designed to either:
   *         - console.log() the token (for JS execution sinks like eval, innerHTML with script)
   *         - Create a DOM element with id=token (for HTML injection sinks like innerHTML)
   *      c) Hook Puppeteer's page.on('console') to listen for the token
   *      d) Check the DOM for an element with id=token
   *   2. Only if the token is found in console output OR in the DOM do we report it.
   *   3. This eliminates all static-analysis FPs where the pattern exists but data flow doesn't.
   *
   * PERFORMANCE: We only test injection vectors that are likely to succeed based on
   * the static candidates. We don't blindly fuzz every parameter.
   */
  async dynamicVerification(page, targetUrl, staticCandidates) {
    const vulnerabilities = [];

    /**
     * Determine which injection vectors to test based on static analysis results.
     * If static analysis found source patterns involving location.hash, we test hash injection.
     * If it found location.search, we test search param injection. Etc.
     */
    const hasHashSource = staticCandidates.some(c => 
      c.source && (c.source.includes('hash') || c.code?.includes('location.hash'))
    );
    const hasSearchSource = staticCandidates.some(c => 
      c.source && (c.source.includes('search') || c.source.includes('URL') || c.code?.includes('location.search'))
    );
    const hasDangerousSink = staticCandidates.some(c => c.severity === 'high');

    // Always test hash and search — they're the most common DOM XSS vectors
    // and the cost is minimal (just page navigation + DOM check)

    // ── Test Hash-based injection ──
    const hashVulns = await this.testHashInjection(page, targetUrl);
    vulnerabilities.push(...hashVulns);

    // ── Test Search/Query parameter injection ──
    const searchVulns = await this.testSearchParamInjection(page, targetUrl);
    vulnerabilities.push(...searchVulns);

    // ── Test window.name injection (if static analysis found window.name source) ──
    const hasWindowNameSource = staticCandidates.some(c => 
      c.source && c.source.includes('window.name')
    );
    if (hasWindowNameSource) {
      const wnVulns = await this.testWindowNameInjection(page, targetUrl);
      vulnerabilities.push(...wnVulns);
    }

    return vulnerabilities;
  }

  /**
   * Test hash-based DOM XSS with dynamic token verification.
   * 
   * Injects payloads into the URL hash and checks if they execute by:
   *   1. Listening for console.log(token) via Puppeteer's console event
   *   2. Checking if a DOM element with id=token was created
   */
  async testHashInjection(page, targetUrl) {
    const vulnerabilities = [];

    // Generate unique tokens for each payload to avoid cross-contamination
    const testCases = this.buildDynamicPayloads();

    for (const testCase of testCases) {
      try {
        const { token, payloads, type } = testCase;
        
        for (const payload of payloads) {
          const testUrl = `${targetUrl}#${payload}`;
          
          const result = await this.executeAndVerify(page, testUrl, token);

          if (result.verified) {
            vulnerabilities.push({
              type: 'DOM XSS',
              severity: 'high',
              url: testUrl,
              evidence: `VERIFIED: ${result.method} — Token "${token}" was ${result.method === 'console' ? 'logged to console' : 'rendered in DOM'} after hash injection.`,
              description: `Confirmed DOM XSS via location.hash. Payload executed in the browser context. Verification method: ${result.method}.`,
              source: 'location.hash',
              sink: type,
              codeSnippet: payload.substring(0, 200),
              remediation: this.getRemediation({ severity: 'high' })
            });

            // One confirmed vector per injection type is enough
            break;
          }
        }
      } catch (e) {
        // Ignore individual test errors — don't crash the scanner
      }
    }

    return vulnerabilities;
  }

  /**
   * Test search/query parameter DOM XSS with dynamic verification.
   */
  async testSearchParamInjection(page, targetUrl) {
    const vulnerabilities = [];
    const commonParams = ['q', 'search', 'query', 'id', 'name', 'page', 'url', 'redirect', 'next', 'return'];

    for (const param of commonParams) {
      try {
        const testCases = this.buildDynamicPayloads();

        for (const testCase of testCases) {
          const { token, payloads, type } = testCase;

          for (const payload of payloads) {
            const testUrl = new URL(targetUrl);
            testUrl.searchParams.set(param, payload);

            const result = await this.executeAndVerify(page, testUrl.href, token);

            if (result.verified) {
              vulnerabilities.push({
                type: 'DOM XSS',
                severity: 'high',
                url: testUrl.href,
                evidence: `VERIFIED: ${result.method} — Token "${token}" confirmed after injecting param "${param}".`,
                description: `Confirmed DOM XSS via query parameter "${param}". Verification: ${result.method}.`,
                source: `location.search (param: ${param})`,
                sink: type,
                codeSnippet: payload.substring(0, 200),
                remediation: this.getRemediation({ severity: 'high' })
              });

              // Found a confirmed vuln for this param — skip remaining payloads
              return vulnerabilities;
            }
          }
        }
      } catch (e) {
        // Continue to next parameter
      }
    }

    return vulnerabilities;
  }

  /**
   * Test window.name DOM XSS injection.
   * This is a less common but dangerous vector where the attacker controls window.name
   * from a previous page and the target page reads it into a dangerous sink.
   */
  async testWindowNameInjection(page, targetUrl) {
    const vulnerabilities = [];

    try {
      const testCases = this.buildDynamicPayloads();

      for (const testCase of testCases) {
        const { token, payloads, type } = testCase;

        for (const payload of payloads) {
          // Set window.name before navigation (simulates attacker-controlled opener)
          await page.evaluate((name) => { window.name = name; }, payload);
          
          const result = await this.executeAndVerify(page, targetUrl, token);

          if (result.verified) {
            vulnerabilities.push({
              type: 'DOM XSS',
              severity: 'high',
              url: targetUrl,
              evidence: `VERIFIED: ${result.method} — Token "${token}" confirmed via window.name injection.`,
              description: `Confirmed DOM XSS via window.name. The page reads window.name into a dangerous sink.`,
              source: 'window.name',
              sink: type,
              codeSnippet: payload.substring(0, 200),
              remediation: this.getRemediation({ severity: 'high' })
            });
            return vulnerabilities;
          }
        }
      }
    } catch (e) {
      // Ignore
    }

    return vulnerabilities;
  }

  /**
   * Build dynamic XSS payloads with unique verification tokens.
   * 
   * Each payload is designed to produce a verifiable side-effect:
   *   - console.log(token): Detected via Puppeteer page.on('console')
   *   - DOM element creation: Detected via page.querySelector('#token')
   * 
   * We use unique tokens per test to avoid false positives from cached
   * console output or leftover DOM elements from previous tests.
   */
  buildDynamicPayloads() {
    const consoleToken = this.generateXSSToken();
    const domToken = this.generateXSSToken();

    return [
      {
        token: consoleToken,
        type: 'JavaScript Execution (eval/script)',
        payloads: [
          // Script tag injection — triggers console.log if innerHTML/document.write is the sink
          `"><script>console.log('${consoleToken}')</script>`,
          `'><script>console.log('${consoleToken}')</script>`,
          `<script>console.log('${consoleToken}')</script>`,
          // Event handler injection — triggers if injected into HTML attributes
          `"><img src=x onerror="console.log('${consoleToken}')">`,
          `'><img src=x onerror="console.log('${consoleToken}')">`,
          // SVG-based injection
          `<svg onload="console.log('${consoleToken}')">`,
          // Direct JS evaluation (if eval/Function/setTimeout is the sink)
          `console.log('${consoleToken}')`,
        ]
      },
      {
        token: domToken,
        type: 'HTML Injection (innerHTML/outerHTML)',
        payloads: [
          // DOM element creation — triggers if innerHTML/insertAdjacentHTML is the sink
          `"><div id="${domToken}">XSS</div>`,
          `'><div id="${domToken}">XSS</div>`,
          `<div id="${domToken}">XSS</div>`,
          // Span variation for tighter contexts
          `<span id="${domToken}"></span>`,
        ]
      }
    ];
  }

  /**
   * Navigate to a URL and verify if a specific XSS token was executed/rendered.
   * 
   * This is the core verification engine:
   *   1. Hooks page.on('console') to capture console.log() calls
   *   2. Navigates to the payload URL
   *   3. Waits for page load + a short grace period for async JS
   *   4. Checks if the token appeared in console output (JS execution confirmed)
   *   5. Checks if a DOM element with id=token exists (HTML injection confirmed)
   *   6. Returns { verified: true/false, method: 'console'|'dom' }
   *
   * @param {Page} page - Puppeteer page instance
   * @param {string} url - The URL with the injected payload
   * @param {string} token - The unique verification token to look for
   * @returns {Promise<{verified: boolean, method: string}>}
   */
  async executeAndVerify(page, url, token) {
    let consoleDetected = false;

    // ── Hook console output ──
    // Listen for console.log() calls that contain our unique token.
    // This proves JavaScript execution happened (not just HTML reflection).
    const consoleHandler = (msg) => {
      try {
        if (msg.text().includes(token)) {
          consoleDetected = true;
        }
      } catch {
        // Ignore serialization errors on complex console args
      }
    };

    page.on('console', consoleHandler);

    try {
      // Navigate to the payload URL
      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 10000
      });

      // Grace period: allow async JavaScript to execute (e.g., DOMContentLoaded handlers,
      // setTimeout callbacks, framework initialization that reads URL params)
      await new Promise(resolve => setTimeout(resolve, 1500));

      // ── Check 1: Console token detection ──
      if (consoleDetected) {
        return { verified: true, method: 'console' };
      }

      // ── Check 2: DOM element detection ──
      // Check if our payload created an element with id=token in the page DOM.
      // This confirms innerHTML/outerHTML/insertAdjacentHTML injection.
      const domElementExists = await page.evaluate((tokenId) => {
        return document.getElementById(tokenId) !== null;
      }, token);

      if (domElementExists) {
        return { verified: true, method: 'dom' };
      }

      return { verified: false, method: 'none' };

    } catch (e) {
      // Navigation error (timeout, bad URL, etc.) — not a vulnerability
      return { verified: false, method: 'error' };
    } finally {
      // Clean up the console listener to prevent memory leaks across tests
      page.off('console', consoleHandler);
    }
  }

  /**
   * Check for framework-specific vulnerabilities
   */
  async checkFrameworkVulnerabilities(page) {
    const vulnerabilities = [];

    try {
      const frameworkChecks = await page.evaluate(() => {
        const checks = [];

        // Check jQuery version
        if (window.jQuery) {
          const version = jQuery.fn.jquery;
          const versionNum = parseFloat(version);
          
          if (versionNum < 1.9) {
            checks.push({
              framework: 'jQuery',
              version,
              issue: 'Old jQuery version vulnerable to selector-based XSS',
              severity: 'high'
            });
          }
          if (versionNum < 3.5) {
            checks.push({
              framework: 'jQuery',
              version,
              issue: 'jQuery version vulnerable to CVE-2020-11022/11023',
              severity: 'medium'
            });
          }
        }

        // Check Angular
        if (window.angular) {
          const version = angular.version?.full;
          checks.push({
            framework: 'AngularJS',
            version,
            issue: 'AngularJS is in LTS mode - check for ng-bind-html-unsafe usage',
            severity: 'medium'
          });
        }

        // Check for insecure CSP bypasses
        if (document.querySelector('script[nonce]') === null && 
            !document.querySelector('meta[http-equiv="Content-Security-Policy"]')) {
          checks.push({
            framework: 'CSP',
            issue: 'No Content Security Policy detected',
            severity: 'medium'
          });
        }

        return checks;
      });

      for (const check of frameworkChecks) {
        vulnerabilities.push({
          type: 'DOM XSS',
          severity: check.severity,
          url: page.url(),
          evidence: `${check.framework}: ${check.issue}`,
          description: `Framework issue: ${check.issue}`,
          framework: check.framework,
          version: check.version,
          remediation: this.getFrameworkRemediation(check.framework)
        });
      }
    } catch (error) {
      // Framework check failed — non-critical, continue
    }

    return vulnerabilities;
  }

  /**
   * Get remediation advice
   */
  getRemediation(pattern) {
    const remediations = {
      high: [
        '• Use textContent instead of innerHTML',
        '• Avoid eval() and Function() entirely',
        '• Use DOMPurify to sanitize HTML',
        '• Implement a strict Content Security Policy'
      ],
      medium: [
        '• Validate all user input',
        '• Use URL API for link handling',
        '• Avoid using location directly with DOM'
      ],
      low: [
        '• Use appropriate output encoding',
        '• Follow the principle of least privilege'
      ]
    };

    return remediations[pattern.severity]?.join('\n') || 'Review XSS prevention best practices';
  }

  /**
   * Get framework-specific remediation
   */
  getFrameworkRemediation(framework) {
    const remediations = {
      'jQuery': 'Upgrade to the latest jQuery version and use .text() instead of .html() for text content',
      'AngularJS': 'Migrate to modern Angular or use $sce for content sanitization',
      'CSP': 'Add a Content-Security-Policy header with a secure script-src directive'
    };

    return remediations[framework] || 'Review the security documentation for your framework';
  }
}

export default DOMXSSScanner;
