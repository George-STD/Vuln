import puppeteer from 'puppeteer';
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
   * Main scan method
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
      
      // Check for DOM XSS patterns
      const domXSSPatterns = await this.findDOMXSSPatterns(jsAnalysis);
      
      for (const pattern of domXSSPatterns) {
        vulnerabilities.push({
          type: 'DOM XSS',
          severity: pattern.severity,
          url: targetUrl,
          evidence: pattern.evidence,
          description: pattern.description,
          source: pattern.source,
          sink: pattern.sink,
          codeSnippet: pattern.code,
          remediation: this.getRemediation(pattern)
        });
      }

      // Test with actual payloads
      const payloadResults = await this.testPayloads(page, targetUrl);
      vulnerabilities.push(...payloadResults);

      // Check for jQuery/Angular specific vulnerabilities
      const frameworkVulns = await this.checkFrameworkVulnerabilities(page);
      vulnerabilities.push(...frameworkVulns);

      this.logger.info(`DOM XSS scan complete. Found ${vulnerabilities.length} issues.`);

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
   * Find DOM XSS patterns in JavaScript
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
          description: `تدفق بيانات محتمل من ${source} إلى ${sink}`,
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
        description: `معالج حدث ${handler.attribute} قد يكون عرضة لـ DOM XSS`,
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
            description: `نمط خطير: ${description}`,
            evidence: match.substring(0, 100)
          });
        }
      }
    }

    return patterns;
  }

  /**
   * Test with actual XSS payloads
   */
  async testPayloads(page, url) {
    const vulnerabilities = [];
    const payloads = [
      { param: 'q', value: '<img src=x onerror=alert(1)>', marker: 'onerror=alert(1)' },
      { param: 'search', value: '"><script>alert(1)</script>', marker: '<script>alert(1)' },
      { param: 'id', value: "'-alert(1)-'", marker: '-alert(1)-' },
      { param: 'name', value: 'javascript:alert(1)', marker: 'javascript:alert(1)' }
    ];

    // Test hash-based XSS
    const hashPayloads = [
      '#<img src=x onerror=alert(1)>',
      '#"><script>alert(1)</script>',
      '#javascript:alert(1)'
    ];

    for (const hashPayload of hashPayloads) {
      try {
        const testUrl = url + hashPayload;
        await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        
        // Check if payload appears in DOM unencoded
        const content = await page.content();
        if (content.includes('onerror=alert(1)') || content.includes('<script>alert(1)')) {
          vulnerabilities.push({
            type: 'DOM XSS',
            severity: 'high',
            url: testUrl,
            evidence: 'Hash-based DOM XSS detected',
            description: 'الموقع عرضة لـ DOM XSS عبر hash URL',
            source: 'location.hash',
            sink: 'innerHTML/document.write',
            remediation: 'استخدم textContent بدلاً من innerHTML وتحقق من جميع المدخلات'
          });
        }
      } catch (e) {
        // Ignore navigation errors
      }
    }

    return vulnerabilities;
  }

  /**
   * Check for framework-specific vulnerabilities
   */
  async checkFrameworkVulnerabilities(page) {
    const vulnerabilities = [];

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
        description: `مشكلة في إطار العمل: ${check.issue}`,
        framework: check.framework,
        version: check.version,
        remediation: this.getFrameworkRemediation(check.framework)
      });
    }

    return vulnerabilities;
  }

  /**
   * Get remediation advice
   */
  getRemediation(pattern) {
    const remediations = {
      high: [
        '• استخدم textContent بدلاً من innerHTML',
        '• تجنب eval() و Function() تماماً',
        '• استخدم DOMPurify لتنظيف HTML',
        '• طبق Content Security Policy صارم'
      ],
      medium: [
        '• تحقق من صحة جميع مدخلات المستخدم',
        '• استخدم URL API لمعالجة الروابط',
        '• تجنب استخدام location مباشرة مع DOM'
      ],
      low: [
        '• استخدم encoding مناسب للمخرجات',
        '• اتبع مبدأ أقل الصلاحيات'
      ]
    };

    return remediations[pattern.severity]?.join('\n') || 'راجع أفضل الممارسات لمنع XSS';
  }

  /**
   * Get framework-specific remediation
   */
  getFrameworkRemediation(framework) {
    const remediations = {
      'jQuery': 'قم بالترقية إلى أحدث إصدار من jQuery واستخدم .text() بدلاً من .html() للمحتوى النصي',
      'AngularJS': 'انتقل إلى Angular الحديث أو استخدم $sce لتنظيف المحتوى',
      'CSP': 'أضف Content-Security-Policy header مع script-src آمن'
    };

    return remediations[framework] || 'راجع وثائق الأمان لإطار العمل المستخدم';
  }
}

export default DOMXSSScanner;
