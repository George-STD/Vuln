/**
 * Safety Controller - ضوابط السلامة والحماية من الـ DoS
 * يتحكم في معدلات الطلبات والقيود الأمنية
 */

import { EventEmitter } from 'events';

class SafetyController extends EventEmitter {
  constructor() {
    super();
    
    // حالة التفعيل العامة
    this.enabled = false;
    
    // إعدادات Rate Limiting
    this.rateLimiting = {
      enabled: true,
      globalRPS: 10,            // طلبات/ثانية للكل
      perHostRPS: 3,            // طلبات/ثانية لكل host
      maxConcurrency: 5,        // أقصى عدد طلبات متوازية
      burstLimit: 20,           // حد الانفجار
      
      // Backoff settings
      backoff: {
        enabled: true,
        on429: true,            // Backoff عند Too Many Requests
        on503: true,            // Backoff عند Service Unavailable
        on504: true,            // Backoff عند Gateway Timeout
        onHighLatency: true,    // Backoff عند ارتفاع الـ latency
        latencyThreshold: 5000, // ms - متى نعتبر الـ latency عالي
        initialDelay: 1000,     // ms
        maxDelay: 30000,        // ms
        multiplier: 2
      }
    };
    
    // إعدادات الزحف
    this.crawling = {
      maxUrls: 200,             // أقصى عدد URLs
      maxDepth: 3,              // أقصى عمق الزحف
      maxParamsPerUrl: 10,      // أقصى عدد parameters لكل URL
      maxResponseSize: 5242880, // 5MB أقصى حجم استجابة
      
      // Endpoints خطيرة ممنوعة
      dangerousEndpoints: [
        '/logout', '/signout', '/sign-out',
        '/delete', '/remove', '/destroy',
        '/admin/delete', '/admin/remove',
        '/api/delete', '/api/remove',
        '/unsubscribe', '/deactivate',
        '/password/reset', '/account/delete',
        '/billing/cancel', '/subscription/cancel'
      ],
      
      // HTTP Methods
      allowedMethods: ['GET', 'HEAD'],  // افتراضي Safe Mode
      blockDestructiveMethods: true,     // منع POST/PUT/DELETE
    };
    
    // إعدادات الأمان
    this.security = {
      // أنماط الاختبار الخطيرة
      disableWAFBypass: true,           // منع محاولات تجاوز WAF
      disableBruteforce: true,          // منع bruteforce
      disableCredentialStuffing: true,  // منع credential stuffing
      disablePasswordSpraying: true,    // منع password spraying
      disableDoSPayloads: true,         // منع payloads قد تسبب DoS
      
      // Safe Mode
      safeMode: true,                   // الوضع الآمن
      
      // Time restrictions
      timeWindow: {
        enabled: false,
        startHour: 9,                   // ساعة البدء (24h)
        endHour: 17,                    // ساعة الانتهاء
        timezone: 'UTC',
        allowedDays: [1, 2, 3, 4, 5]    // الأيام المسموحة (1=Monday)
      }
    };
    
    // حدود الميزانية
    this.budgetLimits = {
      enabled: false,
      maxScanTime: 3600000,      // 1 hour max
      maxRequests: 5000,         // أقصى عدد طلبات
      maxHosts: 10,              // أقصى عدد hosts
      maxFindings: 500           // أقصى عدد نتائج
    };
    
    // User-Agent
    this.userAgent = {
      custom: 'VulnHunterPro/2.0 (Security Scanner; contact: security@example.com)',
      includeContact: true,
      contactEmail: 'security@example.com'
    };
    
    // Headers مخصصة
    this.customHeaders = {};
    
    // إحصائيات الجلسة الحالية
    this.stats = {
      requestsSent: 0,
      requestsBlocked: 0,
      backoffsTriggered: 0,
      currentLatency: 0,
      startTime: null
    };
    
    // حالة الـ backoff الحالية
    this.backoffState = {
      active: false,
      currentDelay: 0,
      until: null
    };
    
    // طوابير الطلبات لكل host
    this.hostQueues = new Map();
  }

  /**
   * تفعيل/تعطيل النظام
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    if (enabled) {
      this.stats.startTime = Date.now();
    }
    this.emit('status-changed', { enabled });
    return this;
  }

  /**
   * تطبيق ملف تعريف Bug Bounty الآمن
   */
  applyBugBountyProfile() {
    this.enabled = true;
    
    this.rateLimiting = {
      enabled: true,
      globalRPS: 3,
      perHostRPS: 1,
      maxConcurrency: 2,
      burstLimit: 5,
      backoff: {
        enabled: true,
        on429: true,
        on503: true,
        on504: true,
        onHighLatency: true,
        latencyThreshold: 3000,
        initialDelay: 2000,
        maxDelay: 60000,
        multiplier: 2
      }
    };
    
    this.crawling.maxUrls = 200;
    this.crawling.maxDepth = 2;
    this.crawling.allowedMethods = ['GET', 'HEAD'];
    this.crawling.blockDestructiveMethods = true;
    
    this.security.safeMode = true;
    this.security.disableWAFBypass = true;
    
    this.emit('profile-applied', { name: 'bug-bounty-safe' });
    return this;
  }

  /**
   * تطبيق ملف تعريف عدواني (للاستخدام المرخص فقط)
   */
  applyAggressiveProfile() {
    console.warn('⚠️ Aggressive profile applied - ensure you have explicit permission!');
    
    this.rateLimiting.globalRPS = 20;
    this.rateLimiting.perHostRPS = 10;
    this.rateLimiting.maxConcurrency = 10;
    
    this.crawling.maxUrls = 1000;
    this.crawling.maxDepth = 5;
    this.crawling.allowedMethods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'];
    this.crawling.blockDestructiveMethods = false;
    
    this.security.safeMode = false;
    
    this.emit('profile-applied', { name: 'aggressive' });
    return this;
  }

  /**
   * فحص هل يمكن إرسال طلب الآن
   */
  async canMakeRequest(url, method = 'GET') {
    if (!this.enabled) {
      return { allowed: true };
    }

    const checks = [];

    // 1. فحص Safe Mode و HTTP Method
    if (this.security.safeMode && this.crawling.blockDestructiveMethods) {
      if (!this.crawling.allowedMethods.includes(method.toUpperCase())) {
        return {
          allowed: false,
          reason: `Method ${method} blocked in Safe Mode`,
          type: 'method-blocked'
        };
      }
    }

    // 2. فحص Dangerous Endpoints
    try {
      const pathname = new URL(url).pathname.toLowerCase();
      for (const dangerous of this.crawling.dangerousEndpoints) {
        if (pathname.includes(dangerous)) {
          return {
            allowed: false,
            reason: `Dangerous endpoint blocked: ${dangerous}`,
            type: 'dangerous-endpoint'
          };
        }
      }
    } catch {}

    // 3. فحص Budget Limits
    if (this.budgetLimits.enabled) {
      if (this.stats.requestsSent >= this.budgetLimits.maxRequests) {
        return {
          allowed: false,
          reason: `Max requests limit reached: ${this.budgetLimits.maxRequests}`,
          type: 'budget-exceeded'
        };
      }

      if (this.stats.startTime) {
        const elapsed = Date.now() - this.stats.startTime;
        if (elapsed >= this.budgetLimits.maxScanTime) {
          return {
            allowed: false,
            reason: 'Max scan time exceeded',
            type: 'time-exceeded'
          };
        }
      }
    }

    // 4. فحص Time Window
    if (this.security.timeWindow.enabled) {
      const now = new Date();
      const hour = now.getHours();
      const day = now.getDay() || 7; // Sunday = 7
      
      if (!this.security.timeWindow.allowedDays.includes(day)) {
        return {
          allowed: false,
          reason: 'Scanning not allowed on this day',
          type: 'time-window'
        };
      }
      
      if (hour < this.security.timeWindow.startHour || hour >= this.security.timeWindow.endHour) {
        return {
          allowed: false,
          reason: `Scanning only allowed between ${this.security.timeWindow.startHour}:00 and ${this.security.timeWindow.endHour}:00`,
          type: 'time-window'
        };
      }
    }

    // 5. فحص Backoff
    if (this.backoffState.active && this.backoffState.until > Date.now()) {
      return {
        allowed: false,
        reason: 'Backoff active, waiting...',
        type: 'backoff',
        retryAfter: this.backoffState.until - Date.now()
      };
    } else if (this.backoffState.active) {
      this.backoffState.active = false;
    }

    // 6. Rate Limiting
    if (this.rateLimiting.enabled) {
      // فحص هل نحتاج انتظار
      const waitTime = this.calculateWaitTime(url);
      if (waitTime > 0) {
        await this.delay(waitTime);
      }
    }

    return { allowed: true };
  }

  /**
   * حساب وقت الانتظار بناءً على Rate Limits
   */
  calculateWaitTime(url) {
    try {
      const host = new URL(url).hostname;
      const now = Date.now();
      
      // جلب/إنشاء queue للـ host
      if (!this.hostQueues.has(host)) {
        this.hostQueues.set(host, {
          lastRequest: 0,
          requestCount: 0
        });
      }
      
      const hostQueue = this.hostQueues.get(host);
      const minInterval = 1000 / this.rateLimiting.perHostRPS;
      const elapsed = now - hostQueue.lastRequest;
      
      if (elapsed < minInterval) {
        return minInterval - elapsed;
      }
      
      return 0;
    } catch {
      return 0;
    }
  }

  /**
   * تسجيل طلب تم إرساله
   */
  recordRequest(url, method = 'GET') {
    this.stats.requestsSent++;
    
    try {
      const host = new URL(url).hostname;
      if (!this.hostQueues.has(host)) {
        this.hostQueues.set(host, { lastRequest: 0, requestCount: 0 });
      }
      const queue = this.hostQueues.get(host);
      queue.lastRequest = Date.now();
      queue.requestCount++;
    } catch {}
    
    this.emit('request-sent', { url, method, total: this.stats.requestsSent });
  }

  /**
   * تسجيل استجابة وتفعيل backoff إذا لزم
   */
  recordResponse(url, statusCode, latency) {
    this.stats.currentLatency = latency;
    
    // فحص هل نحتاج backoff
    if (this.rateLimiting.backoff.enabled) {
      let shouldBackoff = false;
      let reason = '';
      
      if (statusCode === 429 && this.rateLimiting.backoff.on429) {
        shouldBackoff = true;
        reason = '429 Too Many Requests';
      } else if (statusCode === 503 && this.rateLimiting.backoff.on503) {
        shouldBackoff = true;
        reason = '503 Service Unavailable';
      } else if (statusCode === 504 && this.rateLimiting.backoff.on504) {
        shouldBackoff = true;
        reason = '504 Gateway Timeout';
      } else if (this.rateLimiting.backoff.onHighLatency && 
                 latency > this.rateLimiting.backoff.latencyThreshold) {
        shouldBackoff = true;
        reason = `High latency: ${latency}ms`;
      }
      
      if (shouldBackoff) {
        this.triggerBackoff(reason);
      }
    }
  }

  /**
   * تفعيل Backoff
   */
  triggerBackoff(reason) {
    if (this.backoffState.active) {
      // مضاعفة الـ delay
      this.backoffState.currentDelay = Math.min(
        this.backoffState.currentDelay * this.rateLimiting.backoff.multiplier,
        this.rateLimiting.backoff.maxDelay
      );
    } else {
      this.backoffState.currentDelay = this.rateLimiting.backoff.initialDelay;
    }
    
    this.backoffState.active = true;
    this.backoffState.until = Date.now() + this.backoffState.currentDelay;
    this.stats.backoffsTriggered++;
    
    this.emit('backoff', { 
      reason, 
      delay: this.backoffState.currentDelay,
      until: new Date(this.backoffState.until).toISOString()
    });
  }

  /**
   * إعادة تعيين Backoff
   */
  resetBackoff() {
    this.backoffState = {
      active: false,
      currentDelay: 0,
      until: null
    };
  }

  /**
   * فحص هل Payload آمن
   */
  isPayloadSafe(payload) {
    if (!this.enabled || !this.security.safeMode) {
      return { safe: true };
    }

    // أنماط خطيرة
    const dangerousPatterns = [
      // DoS payloads
      /(\w)\1{100,}/i,                    // تكرار حروف كثير
      /\[\[.*\]\]/,                        // نمط قد يسبب ReDoS
      /{{\s*constructor/i,                 // Prototype pollution
      
      // Bruteforce indicators
      /password[=:]/i,
      /pass[=:]/i,
      /pwd[=:]/i
    ];

    if (this.security.disableDoSPayloads) {
      for (const pattern of dangerousPatterns) {
        if (pattern.test(payload)) {
          return {
            safe: false,
            reason: 'Payload contains potentially dangerous pattern',
            pattern: pattern.toString()
          };
        }
      }
    }

    return { safe: true };
  }

  /**
   * فحص هل الـ module مسموح
   */
  isModuleAllowed(moduleName) {
    if (!this.enabled) {
      return { allowed: true };
    }

    const restrictedModules = [];

    if (this.security.disableWAFBypass) {
      restrictedModules.push('waf-bypass', 'wafbypass');
    }
    if (this.security.disableBruteforce) {
      restrictedModules.push('bruteforce', 'brute-force', 'password-spray');
    }

    const moduleNameLower = moduleName.toLowerCase();
    for (const restricted of restrictedModules) {
      if (moduleNameLower.includes(restricted)) {
        return {
          allowed: false,
          reason: `Module ${moduleName} is restricted in current safety profile`
        };
      }
    }

    return { allowed: true };
  }

  /**
   * الحصول على Headers للطلبات
   */
  getRequestHeaders() {
    const headers = {
      'User-Agent': this.userAgent.custom,
      ...this.customHeaders
    };

    return headers;
  }

  /**
   * تحديث User-Agent
   */
  setUserAgent(userAgent, contactEmail = null) {
    if (contactEmail) {
      this.userAgent.custom = `${userAgent} (contact: ${contactEmail})`;
      this.userAgent.contactEmail = contactEmail;
    } else {
      this.userAgent.custom = userAgent;
    }
    return this;
  }

  /**
   * إضافة Header مخصص
   */
  addCustomHeader(name, value) {
    this.customHeaders[name] = value;
    return this;
  }

  /**
   * مساعد: تأخير
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * إعادة تعيين الإحصائيات
   */
  resetStats() {
    this.stats = {
      requestsSent: 0,
      requestsBlocked: 0,
      backoffsTriggered: 0,
      currentLatency: 0,
      startTime: Date.now()
    };
    this.hostQueues.clear();
    this.resetBackoff();
    return this;
  }

  /**
   * الحصول على الإحصائيات
   */
  getStats() {
    return {
      ...this.stats,
      runningTime: this.stats.startTime ? Date.now() - this.stats.startTime : 0,
      backoffActive: this.backoffState.active,
      currentBackoffDelay: this.backoffState.currentDelay
    };
  }

  /**
   * الحصول على ملخص الإعدادات
   */
  getSummary() {
    return {
      enabled: this.enabled,
      rateLimiting: {
        enabled: this.rateLimiting.enabled,
        globalRPS: this.rateLimiting.globalRPS,
        perHostRPS: this.rateLimiting.perHostRPS
      },
      safeMode: this.security.safeMode,
      allowedMethods: this.crawling.allowedMethods,
      maxUrls: this.crawling.maxUrls,
      budgetLimits: this.budgetLimits.enabled ? this.budgetLimits : null
    };
  }

  /**
   * تصدير الإعدادات
   */
  export() {
    return {
      enabled: this.enabled,
      rateLimiting: this.rateLimiting,
      crawling: this.crawling,
      security: this.security,
      budgetLimits: this.budgetLimits,
      userAgent: this.userAgent,
      customHeaders: this.customHeaders
    };
  }

  /**
   * استيراد الإعدادات
   */
  import(config) {
    if (config.rateLimiting) this.rateLimiting = { ...this.rateLimiting, ...config.rateLimiting };
    if (config.crawling) this.crawling = { ...this.crawling, ...config.crawling };
    if (config.security) this.security = { ...this.security, ...config.security };
    if (config.budgetLimits) this.budgetLimits = { ...this.budgetLimits, ...config.budgetLimits };
    if (config.userAgent) this.userAgent = { ...this.userAgent, ...config.userAgent };
    if (config.customHeaders) this.customHeaders = { ...this.customHeaders, ...config.customHeaders };
    if (typeof config.enabled === 'boolean') this.enabled = config.enabled;
    
    return this;
  }

  /**
   * إعادة تعيين كل شيء
   */
  reset() {
    this.enabled = false;
    this.rateLimiting = {
      enabled: true,
      globalRPS: 10,
      perHostRPS: 3,
      maxConcurrency: 5,
      burstLimit: 20,
      backoff: {
        enabled: true,
        on429: true,
        on503: true,
        on504: true,
        onHighLatency: true,
        latencyThreshold: 5000,
        initialDelay: 1000,
        maxDelay: 30000,
        multiplier: 2
      }
    };
    this.resetStats();
    this.emit('reset');
    return this;
  }
}

export const safetyController = new SafetyController();
export default SafetyController;
