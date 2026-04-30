import puppeteer from 'puppeteer';

export class InteractiveBrowserScanner {
  constructor(config = {}) {
    this.targetUrl = config.targetUrl;
    this.options = config.options || {};
    this.onLog = config.onLog;
    this.name = 'Interactive Browser Scanner';
  }

  log(message, type = 'info') {
    if (this.onLog) {
      this.onLog({
        message: `[${this.name}] ${message}`,
        type,
        timestamp: new Date().toISOString()
      });
    }
  }

  async scan(data = {}) {
    const vulnerabilities = [];
    const targetUrl = data.targetUrl || this.targetUrl;
    if (!targetUrl) {
      return vulnerabilities;
    }

    let browser = null;

    try {
      browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
      });

      const page = await browser.newPage();
      await page.setUserAgent(this.options.userAgent || 'VulnHunter Pro/1.0 (Interactive Browser Scanner)');
      await page.setViewport({ width: 1440, height: 900 });

      const networkLog = [];
      page.on('response', (response) => {
        try {
          const request = response.request();
          networkLog.push({
            url: response.url(),
            method: request.method(),
            status: response.status(),
            resourceType: request.resourceType()
          });
        } catch {
          // Ignore per-response parser errors.
        }
      });

      await page.goto(targetUrl, {
        timeout: this.options.timeout || 30000,
        waitUntil: 'networkidle2'
      });
      await this.delay(1200);

      const discovered = {
        links: new Set([this.normalizeUrl(page.url())]),
        forms: []
      };
      const configuredPaths = this.normalizeConfiguredPaths(
        targetUrl,
        data.interactionPaths || this.options.interactionPaths
      );
      for (const configuredPath of configuredPaths) {
        discovered.links.add(configuredPath);
      }

      this.mergeForms(discovered.forms, await this.collectForms(page));
      await this.visitConfiguredPaths(browser, targetUrl, configuredPaths, discovered, networkLog);
      await this.performHumanLikeInteractions(page, discovered);
      const postInteractionForms = await this.collectForms(page);
      this.mergeForms(discovered.forms, postInteractionForms);

      vulnerabilities.push(
        ...this.detectSensitiveGetWorkflows(discovered.forms),
        ...this.detectSensitiveFormsMissingCsrf(discovered.forms),
        ...await this.detectStepBypass(browser, discovered.links),
        ...await this.detectExposedAdminRoutes(browser, discovered.links),
        ...this.detectSuspiciousStateChanges(networkLog)
      );

      await page.close();
    } catch (error) {
      this.log(`Interactive scan error: ${error.message}`, 'warn');
    } finally {
      if (browser) {
        await browser.close();
      }
    }

    return vulnerabilities;
  }

  async visitConfiguredPaths(browser, targetUrl, configuredPaths, discovered, networkLog) {
    if (!Array.isArray(configuredPaths) || configuredPaths.length === 0) {
      return;
    }

    const maxGuidedPaths = Math.max(1, Math.min(30, Number(this.options.maxGuidedPaths || 12)));
    const selectedPaths = configuredPaths.slice(0, maxGuidedPaths);
    this.log(`Visiting ${selectedPaths.length} user-defined interaction paths`, 'info');

    for (const pathUrl of selectedPaths) {
      const page = await browser.newPage();
      await page.setUserAgent(this.options.userAgent || 'VulnHunter Pro/1.0 (Interactive Browser Scanner)');
      await page.setViewport({ width: 1440, height: 900 });

      page.on('response', (response) => {
        try {
          const request = response.request();
          networkLog.push({
            url: response.url(),
            method: request.method(),
            status: response.status(),
            resourceType: request.resourceType()
          });
        } catch {
          // Ignore per-response parser errors.
        }
      });

      try {
        await page.goto(pathUrl, {
          timeout: Math.min(20000, this.options.timeout || 30000),
          waitUntil: 'networkidle2'
        });
        discovered.links.add(this.normalizeUrl(page.url()));
        this.mergeForms(discovered.forms, await this.collectForms(page));

        // Do a smaller interaction pass on each guided path.
        await this.performHumanLikeInteractions(page, discovered);
        this.mergeForms(discovered.forms, await this.collectForms(page));
      } catch (error) {
        this.log(`Guided path navigation failed for ${pathUrl}: ${error.message}`, 'debug');
      } finally {
        await page.close();
      }
    }
  }

  async performHumanLikeInteractions(page, discovered) {
    const maxClicks = Math.max(3, Math.min(20, Number(this.options.humanInteractionClicks || 10)));
    const maxScrolls = Math.max(2, Math.min(10, Number(this.options.humanInteractionScrolls || 5)));

    for (let i = 0; i < maxScrolls; i++) {
      await page.mouse.wheel({ deltaY: 400 + (i * 60) });
      await this.delay(250);
    }

    for (let i = 0; i < maxClicks; i++) {
      const clickables = await page.$$('a[href], button, [role="button"], [data-testid*="button"], input[type="button"]');
      if (clickables.length === 0) break;

      const element = clickables[i % clickables.length];
      const beforeUrl = this.normalizeUrl(page.url());

      try {
        await page.evaluate((el) => {
          if (el && typeof el.scrollIntoView === 'function') {
            el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
          }
        }, element);
      } catch {
        // Ignore detached element scroll errors.
      }

      const navPromise = page.waitForNavigation({
        timeout: Math.min(6000, this.options.timeout || 30000),
        waitUntil: 'networkidle2'
      }).catch(() => null);

      try {
        await element.click({ delay: 80 });
      } catch {
        // Some elements are not clickable in current state.
      }

      await Promise.race([navPromise, this.delay(700)]);
      const afterUrl = this.normalizeUrl(page.url());
      if (afterUrl) discovered.links.add(afterUrl);
      if (beforeUrl) discovered.links.add(beforeUrl);

      this.mergeForms(discovered.forms, await this.collectForms(page));
      await this.delay(250);
    }
  }

  async collectForms(page) {
    return page.evaluate(() => {
      const isSensitive = (text) => /(delete|remove|transfer|payment|checkout|password|role|admin|approve|withdraw|purchase|change|email)/i.test(text);
      const forms = [];

      document.querySelectorAll('form').forEach((form) => {
        const action = form.action || window.location.href;
        const method = (form.method || 'GET').toUpperCase();
        const fields = Array.from(form.querySelectorAll('input, select, textarea'))
          .map((field) => ({
            name: field.name || '',
            type: field.type || field.tagName.toLowerCase(),
            value: field.value || ''
          }));

        const fieldNames = fields.map((f) => f.name).filter(Boolean);
        const fieldNameBlob = fieldNames.join(' ');
        const hasCsrf = fields.some((field) => {
          const name = String(field.name || '').toLowerCase();
          return name.includes('csrf') || name.includes('_token') || name.includes('xsrf');
        });

        forms.push({
          pageUrl: window.location.href,
          action,
          method,
          hasCsrf,
          sensitive: isSensitive(`${action} ${fieldNameBlob}`),
          fields: fieldNames.slice(0, 30)
        });
      });

      return forms;
    });
  }

  detectSensitiveGetWorkflows(forms = []) {
    const vulnerabilities = [];
    const seen = new Set();

    for (const form of forms) {
      if (!form || form.method !== 'GET' || !form.sensitive) continue;
      const key = `${form.action}|${form.method}`;
      if (seen.has(key)) continue;
      seen.add(key);

      vulnerabilities.push({
        type: 'Business Logic',
        subType: 'Sensitive Workflow Uses GET',
        severity: 'medium',
        url: form.pageUrl || form.action,
        method: 'GET',
        evidence: `Sensitive form action "${form.action}" uses GET with fields: ${form.fields.join(', ') || 'N/A'}`,
        description: 'A sensitive browser workflow appears to use GET parameters, which can be replayed/bookmarked and often bypass workflow controls.',
        remediation: 'Use POST for state-changing operations and validate request origin, intent, and anti-CSRF tokens server-side.',
        references: [
          'https://owasp.org/www-community/attacks/csrf',
          'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'
        ],
        cvss: 5.4,
        cwe: 'CWE-840'
      });
    }

    return vulnerabilities;
  }

  detectSensitiveFormsMissingCsrf(forms = []) {
    const vulnerabilities = [];
    const seen = new Set();

    for (const form of forms) {
      if (!form || form.method !== 'POST' || !form.sensitive || form.hasCsrf) continue;
      const key = `${form.action}|${form.method}|csrf`;
      if (seen.has(key)) continue;
      seen.add(key);

      vulnerabilities.push({
        type: 'CSRF',
        subType: 'Interactive Sensitive Form Missing CSRF Token',
        severity: 'medium',
        url: form.pageUrl || form.action,
        method: 'POST',
        evidence: `Sensitive POST form "${form.action}" was observed without recognizable CSRF token fields.`,
        description: 'A sensitive browser interaction form appears to be missing anti-CSRF protections.',
        remediation: 'Add robust anti-CSRF tokens and verify origin/referer on state-changing requests.',
        references: [
          'https://owasp.org/www-community/attacks/csrf',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
        ],
        cvss: 6.1,
        cwe: 'CWE-352'
      });
    }

    return vulnerabilities;
  }

  async detectStepBypass(browser, linksSet) {
    const vulnerabilities = [];
    const links = Array.from(linksSet || []);
    const candidates = links
      .filter((link) => /(step(?:-|_|\/)?[2-9]|checkout|payment|confirm|review|final)/i.test(link))
      .slice(0, 8);

    for (const candidateUrl of candidates) {
      const page = await browser.newPage();
      await page.setUserAgent(this.options.userAgent || 'VulnHunter Pro/1.0 (Interactive Browser Scanner)');

      try {
        const response = await page.goto(candidateUrl, {
          timeout: Math.min(10000, this.options.timeout || 30000),
          waitUntil: 'domcontentloaded'
        });
        const status = response?.status?.() || 0;
        const finalUrl = this.normalizeUrl(page.url());
        const html = await page.content();
        const redirectedToLogin = /(login|signin|auth)/i.test(finalUrl || '');
        const looksLikeWorkflowPage = /(checkout|payment|confirm|review|order|transfer|step)/i.test(html);

        if (status >= 200 && status < 300 && !redirectedToLogin && looksLikeWorkflowPage) {
          vulnerabilities.push({
            type: 'Business Logic',
            subType: 'Workflow Step Bypass Candidate',
            severity: 'medium',
            url: candidateUrl,
            method: 'GET',
            evidence: `Direct navigation to "${candidateUrl}" returned HTTP ${status} and rendered workflow markers without prior step state.`,
            description: 'A later-step workflow page appears directly reachable without preceding browser steps. This may indicate step-sequencing logic bypass.',
            remediation: 'Enforce server-side step state and transaction context validation for each workflow step.',
            references: [
              'https://owasp.org/www-project-top-ten/',
              'https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability'
            ],
            cvss: 5.3,
            cwe: 'CWE-840'
          });
        }
      } catch {
        // Ignore candidate page navigation errors.
      } finally {
        await page.close();
      }
    }

    return vulnerabilities;
  }

  async detectExposedAdminRoutes(browser, linksSet) {
    const vulnerabilities = [];
    const links = Array.from(linksSet || []);
    const candidates = links
      .filter((link) => /(\/admin|\/manage|\/internal|\/superuser|\/dashboard\/admin)/i.test(link))
      .slice(0, 6);

    for (const candidateUrl of candidates) {
      const page = await browser.newPage();
      await page.setUserAgent(this.options.userAgent || 'VulnHunter Pro/1.0 (Interactive Browser Scanner)');

      try {
        const response = await page.goto(candidateUrl, {
          timeout: Math.min(10000, this.options.timeout || 30000),
          waitUntil: 'domcontentloaded'
        });
        const status = response?.status?.() || 0;
        const finalUrl = this.normalizeUrl(page.url());

        const redirectedToLogin = /(login|signin|auth)/i.test(finalUrl || '');
        if (status >= 200 && status < 300 && !redirectedToLogin) {
          vulnerabilities.push({
            type: 'Authentication Bypass',
            subType: 'Potential Unauthenticated Admin Route Exposure',
            severity: 'high',
            url: candidateUrl,
            method: 'GET',
            evidence: `Candidate admin route responded with HTTP ${status} without redirecting to an authentication endpoint.`,
            description: 'A likely admin/internal route appears accessible from an unauthenticated browser context.',
            remediation: 'Enforce server-side authentication and role authorization checks on all privileged routes.',
            references: [
              'https://owasp.org/www-community/Broken_Access_Control',
              'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
            ],
            cvss: 8.1,
            cwe: 'CWE-284'
          });
        }
      } catch {
        // Ignore route check errors.
      } finally {
        await page.close();
      }
    }

    return vulnerabilities;
  }

  detectSuspiciousStateChanges(networkLog = []) {
    const vulnerabilities = [];
    const seen = new Set();

    for (const event of networkLog) {
      if (!event || event.method !== 'GET' || !event.url) continue;
      if (!/(delete|remove|update|change|transfer|purchase|checkout|approve|role|password|email)/i.test(event.url)) {
        continue;
      }
      if (event.status < 200 || event.status >= 300) continue;

      const key = `${event.url}|${event.method}`;
      if (seen.has(key)) continue;
      seen.add(key);

      vulnerabilities.push({
        type: 'Business Logic',
        subType: 'State Change via GET Request Pattern',
        severity: 'medium',
        url: event.url,
        method: event.method,
        evidence: `Browser interaction observed GET request to state-changing path pattern with HTTP ${event.status}.`,
        description: 'Navigation flow indicates potential state-changing operations over GET, which can weaken workflow integrity and replay protections.',
        remediation: 'Move state-changing operations to POST/PUT/PATCH and enforce anti-replay and anti-CSRF controls server-side.',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'
        ],
        cvss: 5.0,
        cwe: 'CWE-840'
      });
    }

    return vulnerabilities;
  }

  mergeForms(target, incoming) {
    if (!Array.isArray(target) || !Array.isArray(incoming)) return;
    const seen = new Set(target.map((form) => `${form.action}|${form.method}|${form.pageUrl}`));

    for (const form of incoming) {
      const key = `${form.action}|${form.method}|${form.pageUrl}`;
      if (seen.has(key)) continue;
      seen.add(key);
      target.push(form);
    }
  }

  normalizeConfiguredPaths(targetUrl, rawPaths) {
    const target = String(targetUrl || '').trim();
    const baseUrl = this.normalizeUrl(target);
    if (!baseUrl) {
      return [];
    }

    const normalized = this.normalizeStringList(rawPaths);
    const expanded = [];

    for (const rawPath of normalized) {
      // Support simple step sequences: /login > /checkout > /confirm
      const segments = rawPath.split('>').map((segment) => segment.trim()).filter(Boolean);
      if (segments.length > 1) {
        expanded.push(...segments);
      } else {
        expanded.push(rawPath);
      }
    }

    const result = [];
    const seen = new Set();
    for (const item of expanded) {
      const resolved = this.resolvePath(target, item);
      if (!resolved) continue;
      if (!this.isSameOrigin(baseUrl, resolved)) {
        continue;
      }

      const canonical = this.normalizeUrl(resolved);
      if (!canonical || seen.has(canonical)) continue;
      seen.add(canonical);
      result.push(canonical);
    }

    return result;
  }

  normalizeStringList(value) {
    if (Array.isArray(value)) {
      return value.map((item) => String(item || '').trim()).filter(Boolean);
    }

    if (typeof value === 'string') {
      return value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
    }

    return [];
  }

  resolvePath(baseUrl, pathValue) {
    try {
      const raw = String(pathValue || '').trim();
      if (!raw) return null;

      if (/^https?:\/\//i.test(raw)) {
        return new URL(raw).href;
      }

      if (raw.startsWith('/')) {
        return new URL(raw, baseUrl).href;
      }

      return new URL(`/${raw}`, baseUrl).href;
    } catch {
      return null;
    }
  }

  isSameOrigin(baseUrl, candidateUrl) {
    try {
      const base = new URL(baseUrl);
      const candidate = new URL(candidateUrl);
      return base.protocol === candidate.protocol && base.host === candidate.host;
    } catch {
      return false;
    }
  }

  normalizeUrl(value) {
    try {
      const parsed = new URL(value);
      parsed.hash = '';
      return parsed.href;
    } catch {
      return null;
    }
  }

  async delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export default InteractiveBrowserScanner;
