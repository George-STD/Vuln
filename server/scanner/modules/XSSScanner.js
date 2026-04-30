import { BaseScanner } from './BaseScanner.js';

export class XSSScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'XSS Scanner';

    // High-signal payload templates that support deterministic token verification.
    this.primaryPayloadTemplates = [
      '"><svg onload=window.__vhxss="{{token}}">',
      "'><img src=x onerror=window.__vhxss='{{token}}'>",
      '<script>window.__vhxss="{{token}}"</script>'
    ];

    this.confirmationPayloadTemplates = [
      '"><body onpageshow=window.__vhxss="{{token}}">',
      "'><svg/onload=window.__vhxss='{{token}}'>",
      '"><a href="javascript:window.__vhxss=\'{{token}}\'">click</a>'
    ];
  }

  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms } = data;

    for (const url of urls) {
      if (this.stopped) break;
      const vulns = await this.testUrlParameters(url);
      vulnerabilities.push(...vulns);
    }

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

      const baselineResponse = await this.makeRequest(url);
      const baselineHtml = baselineResponse?.data?.toString() || '';

      for (const [key] of params.entries()) {
        if (this.stopped) break;

        for (const pair of this.getPayloadPairs()) {
          if (this.stopped) break;

          const token = this.generateToken();
          const primaryPayload = this.injectToken(pair.primary, token);
          const primaryUrl = new URL(url);
          primaryUrl.searchParams.set(key, primaryPayload);

          const primaryResponse = await this.makeRequest(primaryUrl.href);
          if (!primaryResponse) continue;

          const primarySignal = this.checkReflection(
            primaryResponse.data,
            token,
            baselineHtml
          );

          if (!primarySignal) continue;

          const confirmToken = this.generateToken();
          const confirmPayload = this.injectToken(pair.confirmation, confirmToken);
          const confirmUrl = new URL(url);
          confirmUrl.searchParams.set(key, confirmPayload);

          const confirmResponse = await this.makeRequest(confirmUrl.href);
          if (!confirmResponse) continue;

          const confirmSignal = this.checkReflection(
            confirmResponse.data,
            confirmToken,
            baselineHtml
          );

          if (!confirmSignal) continue;

          if (primarySignal.context !== confirmSignal.context) {
            continue;
          }

          vulnerabilities.push({
            type: 'XSS',
            subType: `Reflected (${primarySignal.context})`,
            severity: this.getSeverity(primarySignal.context),
            url,
            parameter: key,
            payload: primaryPayload,
            evidence: `Primary: ${primarySignal.evidence}\nConfirmation: ${confirmSignal.evidence}`,
            description: `Reflected XSS confirmed in parameter "${key}" using two payload syntaxes.`,
            remediation: 'Apply context-aware output encoding and strict input validation. Enforce Content-Security-Policy and avoid unsafe inline execution sinks.',
            references: [
              'https://portswigger.net/web-security/cross-site-scripting',
              'https://owasp.org/www-community/attacks/xss/',
              'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            ],
            cvss: 7.1,
            cwe: 'CWE-79'
          });
          break;
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
      const baselineData = {};
      for (const input of form.inputs) {
        if (!input.name) continue;
        baselineData[input.name] = input.value || 'baseline-value';
      }

      const baselineResponse = await this.makeRequest(form.action, {
        method: form.method,
        data: form.method === 'POST' ? baselineData : undefined,
        params: form.method === 'GET' ? baselineData : undefined
      });
      const baselineHtml = baselineResponse?.data?.toString() || '';

      for (const input of form.inputs) {
        if (!input.name || this.stopped) continue;
        if (input.type === 'hidden' || input.type === 'submit') continue;

        for (const pair of this.getPayloadPairs()) {
          if (this.stopped) break;

          const token = this.generateToken();
          const payload = this.injectToken(pair.primary, token);
          const formData = {};

          for (const field of form.inputs) {
            if (!field.name) continue;
            formData[field.name] = field.name === input.name
              ? payload
              : (field.value || 'baseline-value');
          }

          const primaryResponse = await this.makeRequest(form.action, {
            method: form.method,
            data: form.method === 'POST' ? formData : undefined,
            params: form.method === 'GET' ? formData : undefined
          });

          if (!primaryResponse) continue;

          const primarySignal = this.checkReflection(
            primaryResponse.data,
            token,
            baselineHtml
          );
          if (!primarySignal) continue;

          const confirmToken = this.generateToken();
          const confirmPayload = this.injectToken(pair.confirmation, confirmToken);
          formData[input.name] = confirmPayload;

          const confirmResponse = await this.makeRequest(form.action, {
            method: form.method,
            data: form.method === 'POST' ? formData : undefined,
            params: form.method === 'GET' ? formData : undefined
          });
          if (!confirmResponse) continue;

          const confirmSignal = this.checkReflection(
            confirmResponse.data,
            confirmToken,
            baselineHtml
          );
          if (!confirmSignal) continue;

          if (primarySignal.context !== confirmSignal.context) {
            continue;
          }

          vulnerabilities.push({
            type: 'XSS',
            subType: `Reflected (${primarySignal.context})`,
            severity: this.getSeverity(primarySignal.context),
            url: form.action,
            method: form.method,
            parameter: input.name,
            payload,
            evidence: `Primary: ${primarySignal.evidence}\nConfirmation: ${confirmSignal.evidence}`,
            description: `Reflected XSS confirmed in form field "${input.name}" with reproducible evidence.`,
            remediation: 'Apply context-aware encoding on rendered output and sanitize untrusted input before persistence or rendering.',
            references: [
              'https://portswigger.net/web-security/cross-site-scripting',
              'https://owasp.org/www-community/attacks/xss/'
            ],
            cvss: 7.1,
            cwe: 'CWE-79'
          });
          break;
        }
      }
    } catch (error) {
      this.log(`XSS form test error: ${error.message}`, 'debug');
    }

    return vulnerabilities;
  }

  checkReflection(html, token, baselineHtml = '') {
    if (!html || typeof html !== 'string' || !token) return null;
    if (baselineHtml && baselineHtml.includes(token)) return null;
    if (!html.includes(token)) return null;

    const context = this.detectExecutionContext(html, token);
    if (!context) return null;

    return {
      type: 'reflected',
      context,
      evidence: this.extractEvidence(html, token)
    };
  }

  detectExecutionContext(html, token) {
    const escapedToken = this.escapeRegExp(token);

    const scriptPattern = new RegExp(
      `<script[^>]*>[\\s\\S]{0,600}${escapedToken}[\\s\\S]{0,600}</script>`,
      'i'
    );
    if (scriptPattern.test(html)) {
      return 'script';
    }

    const eventHandlerPattern = new RegExp(
      `on[a-z]+\\s*=\\s*["'][^"']*${escapedToken}[^"']*["']`,
      'i'
    );
    if (eventHandlerPattern.test(html)) {
      return 'event-handler';
    }

    const javascriptUrlPattern = new RegExp(
      `(?:href|src|action)\\s*=\\s*["']javascript:[^"']*${escapedToken}[^"']*["']`,
      'i'
    );
    if (javascriptUrlPattern.test(html)) {
      return 'javascript-url';
    }

    return null;
  }

  extractEvidence(html, token) {
    const index = html.indexOf(token);
    if (index === -1) return token;

    const start = Math.max(0, index - 80);
    const end = Math.min(html.length, index + token.length + 80);
    return '...' + html.substring(start, end) + '...';
  }

  getSeverity(context) {
    if (context === 'script') return 'high';
    if (context === 'event-handler') return 'high';
    if (context === 'javascript-url') return 'high';
    return 'medium';
  }

  getPayloadPairs() {
    return this.primaryPayloadTemplates.map((primary, index) => ({
      primary,
      confirmation: this.confirmationPayloadTemplates[index % this.confirmationPayloadTemplates.length]
    }));
  }

  injectToken(template, token) {
    return String(template || '').replaceAll('{{token}}', token);
  }

  generateToken() {
    const randomPart = Math.random().toString(36).slice(2, 10);
    return `vhxss_${Date.now()}_${randomPart}`;
  }

  escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
