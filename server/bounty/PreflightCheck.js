/**
 * Preflight Check - فحوصات ما قبل الفحص
 * يتأكد من أن كل شيء جاهز وآمن قبل بدء الفحص
 */

import { scopeManager } from './ScopeManager.js';
import { safetyController } from './SafetyController.js';

class PreflightCheck {
  constructor() {
    this.checks = [];
    this.warnings = [];
    this.errors = [];
    this.confirmations = [];
  }

  /**
   * تنفيذ جميع الفحوصات قبل بدء الفحص
   */
  async runChecks(targetUrl, options = {}) {
    this.reset();
    
    const results = {
      passed: true,
      checks: [],
      warnings: [],
      errors: [],
      confirmations: [],
      summary: {}
    };

    // 1. فحص صحة الـ URL
    const urlCheck = this.checkUrl(targetUrl);
    results.checks.push(urlCheck);
    if (!urlCheck.passed) {
      results.passed = false;
      results.errors.push(urlCheck.message);
    }

    // 2. فحص الـ Scope (لو مفعل)
    if (scopeManager.enabled) {
      const scopeCheck = this.checkScope(targetUrl);
      results.checks.push(scopeCheck);
      if (!scopeCheck.passed) {
        results.passed = false;
        results.errors.push(scopeCheck.message);
      }
    } else {
      results.warnings.push('⚠️ Scope checking is disabled - ensure you have permission to scan this target');
    }

    // 3. فحص إعدادات السلامة
    if (safetyController.enabled) {
      const safetyCheck = this.checkSafetySettings(options);
      results.checks.push(safetyCheck);
      if (!safetyCheck.passed) {
        results.warnings.push(safetyCheck.message);
      }
    } else {
      results.warnings.push('⚠️ Safety controls are disabled - proceed with caution');
    }

    // 4. فحص HTTP Methods المطلوبة
    if (options.methods) {
      const methodsCheck = this.checkMethods(options.methods);
      results.checks.push(methodsCheck);
      if (!methodsCheck.passed) {
        results.passed = false;
        results.errors.push(methodsCheck.message);
      }
    }

    // 5. فحص الـ Rate Limits
    const rateCheck = this.checkRateLimits(options);
    results.checks.push(rateCheck);
    if (rateCheck.warning) {
      results.warnings.push(rateCheck.warning);
    }

    // 6. فحص الـ Modules المطلوبة
    if (options.modules) {
      const modulesCheck = this.checkModules(options.modules);
      results.checks.push(modulesCheck);
      if (!modulesCheck.passed) {
        results.errors.push(modulesCheck.message);
        // لا نفشل كلياً، فقط نحذف الـ modules الممنوعة
      }
    }

    // 7. فحص وقت الفحص (Time Window)
    if (safetyController.security?.timeWindow?.enabled) {
      const timeCheck = this.checkTimeWindow();
      results.checks.push(timeCheck);
      if (!timeCheck.passed) {
        results.passed = false;
        results.errors.push(timeCheck.message);
      }
    }

    // 8. فحص البورتات (لو Port Scanner مفعل)
    if (options.modules?.includes('port') || options.enablePortScan) {
      const portCheck = this.checkPortScanPermission();
      results.checks.push(portCheck);
      if (!portCheck.passed) {
        results.warnings.push(portCheck.message);
      }
    }

    // 9. إنشاء قائمة التأكيدات المطلوبة
    results.confirmations = this.generateConfirmations(targetUrl, options, results);

    // 10. ملخص
    results.summary = {
      totalChecks: results.checks.length,
      passed: results.checks.filter(c => c.passed).length,
      failed: results.checks.filter(c => !c.passed).length,
      warnings: results.warnings.length,
      requiresConfirmation: results.confirmations.length > 0
    };

    return results;
  }

  /**
   * فحص صحة الـ URL
   */
  checkUrl(url) {
    try {
      const parsed = new URL(url);
      
      // فحص البروتوكول
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return {
          name: 'URL Validation',
          passed: false,
          message: `Invalid protocol: ${parsed.protocol}. Only HTTP/HTTPS allowed.`
        };
      }

      // فحص أنه ليس localhost (إلا لو مسموح)
      if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
        return {
          name: 'URL Validation',
          passed: true,
          warning: 'Target is localhost - this is usually for testing only'
        };
      }

      return {
        name: 'URL Validation',
        passed: true,
        message: 'URL is valid'
      };
    } catch (error) {
      return {
        name: 'URL Validation',
        passed: false,
        message: `Invalid URL: ${error.message}`
      };
    }
  }

  /**
   * فحص الـ Scope
   */
  checkScope(url) {
    const result = scopeManager.isInScope(url);
    
    return {
      name: 'Scope Check',
      passed: result.allowed,
      message: result.allowed 
        ? 'Target is within defined scope'
        : `Target is out of scope: ${result.reason}`,
      details: result
    };
  }

  /**
   * فحص إعدادات السلامة
   */
  checkSafetySettings(options) {
    const issues = [];

    // فحص Safe Mode
    if (!safetyController.security.safeMode && options.destructiveMethods) {
      issues.push('Safe Mode is disabled and destructive methods are enabled');
    }

    // فحص WAF Bypass
    if (options.bypassWAF && !safetyController.security.disableWAFBypass) {
      issues.push('WAF Bypass is enabled - ensure you have explicit permission');
    }

    // فحص Bruteforce
    if (options.enableBruteforce && safetyController.security.disableBruteforce) {
      issues.push('Bruteforce is blocked by safety settings');
    }

    return {
      name: 'Safety Settings',
      passed: issues.length === 0,
      message: issues.length > 0 ? issues.join('; ') : 'Safety settings are appropriate',
      issues
    };
  }

  /**
   * فحص HTTP Methods
   */
  checkMethods(methods) {
    const blocked = [];
    
    for (const method of methods) {
      if (!safetyController.crawling.allowedMethods.includes(method.toUpperCase())) {
        if (safetyController.crawling.blockDestructiveMethods) {
          blocked.push(method);
        }
      }
    }

    return {
      name: 'HTTP Methods',
      passed: blocked.length === 0,
      message: blocked.length > 0 
        ? `Methods blocked: ${blocked.join(', ')}`
        : 'All requested methods are allowed',
      blocked
    };
  }

  /**
   * فحص Rate Limits
   */
  checkRateLimits(options) {
    const warnings = [];
    
    // فحص لو الـ rate عالي جداً
    if (options.rps && options.rps > 10) {
      warnings.push(`High RPS (${options.rps}) may trigger rate limiting or blocks`);
    }
    
    if (options.threads && options.threads > 5) {
      warnings.push(`High concurrency (${options.threads}) may cause issues`);
    }

    return {
      name: 'Rate Limits',
      passed: true,
      warning: warnings.length > 0 ? warnings.join('; ') : null,
      currentLimits: {
        globalRPS: safetyController.rateLimiting.globalRPS,
        perHostRPS: safetyController.rateLimiting.perHostRPS,
        maxConcurrency: safetyController.rateLimiting.maxConcurrency
      }
    };
  }

  /**
   * فحص الـ Modules
   */
  checkModules(modules) {
    const blocked = [];
    
    for (const mod of modules) {
      const check = safetyController.isModuleAllowed(mod);
      if (!check.allowed) {
        blocked.push({ module: mod, reason: check.reason });
      }
    }

    return {
      name: 'Scan Modules',
      passed: blocked.length === 0,
      message: blocked.length > 0
        ? `Modules blocked: ${blocked.map(b => b.module).join(', ')}`
        : 'All modules allowed',
      blocked
    };
  }

  /**
   * فحص Time Window
   */
  checkTimeWindow() {
    const now = new Date();
    const hour = now.getHours();
    const day = now.getDay() || 7;
    const tw = safetyController.security.timeWindow;

    if (!tw.allowedDays.includes(day)) {
      return {
        name: 'Time Window',
        passed: false,
        message: 'Scanning is not allowed on this day of the week'
      };
    }

    if (hour < tw.startHour || hour >= tw.endHour) {
      return {
        name: 'Time Window',
        passed: false,
        message: `Scanning only allowed between ${tw.startHour}:00 and ${tw.endHour}:00`
      };
    }

    return {
      name: 'Time Window',
      passed: true,
      message: 'Current time is within allowed window'
    };
  }

  /**
   * فحص إذن Port Scanning
   */
  checkPortScanPermission() {
    // Port scanning يمكن أن يُفسر كـ aggressive
    return {
      name: 'Port Scanning',
      passed: true,
      message: 'Port scanning enabled - ensure this is explicitly allowed by the program',
      warning: '⚠️ Port scanning may be considered aggressive by some programs'
    };
  }

  /**
   * إنشاء قائمة التأكيدات
   */
  generateConfirmations(targetUrl, options, results) {
    const confirmations = [];

    // تأكيد الإذن
    confirmations.push({
      id: 'permission',
      text: 'I confirm that I have explicit permission to scan this target',
      required: true
    });

    // تأكيد الـ Scope
    if (scopeManager.enabled) {
      confirmations.push({
        id: 'scope',
        text: `I confirm that ${new URL(targetUrl).hostname} is within the program's scope`,
        required: true
      });
    }

    // تأكيد لو فيه تحذيرات
    if (results.warnings.length > 0) {
      confirmations.push({
        id: 'warnings',
        text: `I acknowledge the ${results.warnings.length} warning(s) and wish to proceed`,
        required: true
      });
    }

    // تأكيد لو الـ Safe Mode معطل
    if (!safetyController.security.safeMode) {
      confirmations.push({
        id: 'safe-mode',
        text: 'I understand that Safe Mode is disabled and destructive actions may occur',
        required: true
      });
    }

    // تأكيد لو Rate Limits عالية
    if (options.rps > 10 || options.threads > 5) {
      confirmations.push({
        id: 'rate-limits',
        text: 'I accept responsibility for any rate limiting or IP blocks that may occur',
        required: false
      });
    }

    return confirmations;
  }

  /**
   * التحقق من أن المستخدم وافق على كل التأكيدات
   */
  validateConfirmations(confirmations, userConfirmations) {
    const required = confirmations.filter(c => c.required);
    const missing = required.filter(c => !userConfirmations.includes(c.id));
    
    return {
      valid: missing.length === 0,
      missing: missing.map(c => c.id)
    };
  }

  /**
   * إعادة تعيين
   */
  reset() {
    this.checks = [];
    this.warnings = [];
    this.errors = [];
    this.confirmations = [];
  }

  /**
   * إنشاء سجل للموافقة (للإثبات)
   */
  createConsentLog(targetUrl, options, userConfirmations) {
    return {
      timestamp: new Date().toISOString(),
      target: targetUrl,
      hostname: new URL(targetUrl).hostname,
      scanOptions: {
        modules: options.modules || [],
        safeMode: safetyController.security.safeMode,
        scopeEnabled: scopeManager.enabled
      },
      confirmations: userConfirmations,
      scopeSnapshot: scopeManager.enabled ? scopeManager.getSummary() : null,
      safetySnapshot: safetyController.getSummary(),
      userAgent: safetyController.userAgent.custom,
      checksum: this.generateChecksum(targetUrl, userConfirmations)
    };
  }

  /**
   * توليد checksum للإثبات
   */
  generateChecksum(targetUrl, confirmations) {
    const data = `${targetUrl}|${confirmations.join(',')}|${Date.now()}`;
    // Simple hash for logging purposes
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }
}

export const preflightCheck = new PreflightCheck();
export default PreflightCheck;
