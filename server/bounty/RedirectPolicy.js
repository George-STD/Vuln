/**
 * Redirect Policy Controller - التحكم في سياسة إعادة التوجيه
 * يتحكم في كيفية التعامل مع الـ redirects
 */

import { scopeManager } from './ScopeManager.js';

class RedirectPolicyController {
  constructor() {
    this.enabled = true;
    
    // إعدادات السياسة
    this.policy = {
      // اتباع الـ redirects
      followRedirects: true,
      
      // أقصى عدد redirects
      maxRedirects: 5,
      
      // اتباع فقط داخل الـ scope
      onlyInScope: true,
      
      // تسجيل الـ redirects الخارجية
      logOutOfScope: true,
      
      // منع redirect إلى بروتوكولات أخرى
      sameProtocolOnly: false,
      
      // منع redirect إلى ports مختلفة
      samePortOnly: false
    };
    
    // سجل الـ redirects
    this.redirectLog = [];
    this.blockedRedirects = [];
  }

  /**
   * تفعيل/تعطيل
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    return this;
  }

  /**
   * تحديث السياسة
   */
  updatePolicy(updates) {
    this.policy = { ...this.policy, ...updates };
    return this;
  }

  /**
   * فحص هل redirect مسموح
   */
  isRedirectAllowed(fromUrl, toUrl) {
    if (!this.enabled) {
      return { allowed: true };
    }

    try {
      const fromParsed = new URL(fromUrl);
      const toParsed = new URL(toUrl);

      // فحص البروتوكول
      if (this.policy.sameProtocolOnly) {
        if (fromParsed.protocol !== toParsed.protocol) {
          this.logBlocked(fromUrl, toUrl, 'Protocol change not allowed');
          return {
            allowed: false,
            reason: `Protocol change not allowed: ${fromParsed.protocol} -> ${toParsed.protocol}`
          };
        }
      }

      // فحص أنه ليس بروتوكول خطير
      const dangerousProtocols = ['file:', 'ftp:', 'gopher:', 'javascript:', 'data:'];
      if (dangerousProtocols.includes(toParsed.protocol)) {
        this.logBlocked(fromUrl, toUrl, 'Dangerous protocol');
        return {
          allowed: false,
          reason: `Dangerous protocol: ${toParsed.protocol}`
        };
      }

      // فحص الـ Port
      if (this.policy.samePortOnly) {
        const fromPort = fromParsed.port || (fromParsed.protocol === 'https:' ? '443' : '80');
        const toPort = toParsed.port || (toParsed.protocol === 'https:' ? '443' : '80');
        
        if (fromPort !== toPort) {
          this.logBlocked(fromUrl, toUrl, 'Port change not allowed');
          return {
            allowed: false,
            reason: `Port change not allowed: ${fromPort} -> ${toPort}`
          };
        }
      }

      // فحص الـ Scope
      if (this.policy.onlyInScope && scopeManager.enabled) {
        const scopeCheck = scopeManager.isInScope(toUrl);
        
        if (!scopeCheck.allowed) {
          this.logBlocked(fromUrl, toUrl, `Out of scope: ${scopeCheck.reason}`);
          return {
            allowed: false,
            reason: `Redirect to out-of-scope URL: ${toParsed.hostname}`,
            scopeReason: scopeCheck.reason
          };
        }
      }

      // سجل الـ redirect الناجح
      this.logRedirect(fromUrl, toUrl);

      return { allowed: true };

    } catch (error) {
      this.logBlocked(fromUrl, toUrl, `Parse error: ${error.message}`);
      return {
        allowed: false,
        reason: `Invalid redirect URL: ${error.message}`
      };
    }
  }

  /**
   * تسجيل redirect ناجح
   */
  logRedirect(from, to) {
    this.redirectLog.push({
      from,
      to,
      timestamp: new Date().toISOString(),
      allowed: true
    });
    
    // حد أقصى للسجل
    if (this.redirectLog.length > 1000) {
      this.redirectLog = this.redirectLog.slice(-500);
    }
  }

  /**
   * تسجيل redirect محظور
   */
  logBlocked(from, to, reason) {
    const entry = {
      from,
      to,
      reason,
      timestamp: new Date().toISOString()
    };
    
    this.blockedRedirects.push(entry);
    
    if (this.policy.logOutOfScope) {
      console.log(`🚫 Blocked redirect: ${from} -> ${to} (${reason})`);
    }
    
    // حد أقصى
    if (this.blockedRedirects.length > 500) {
      this.blockedRedirects = this.blockedRedirects.slice(-250);
    }
  }

  /**
   * الحصول على سجل الـ redirects
   */
  getLog() {
    return {
      allowed: this.redirectLog,
      blocked: this.blockedRedirects
    };
  }

  /**
   * مسح السجل
   */
  clearLog() {
    this.redirectLog = [];
    this.blockedRedirects = [];
    return this;
  }

  /**
   * الحصول على إحصائيات
   */
  getStats() {
    return {
      totalRedirects: this.redirectLog.length,
      blockedRedirects: this.blockedRedirects.length,
      policy: this.policy
    };
  }

  /**
   * إعادة تعيين
   */
  reset() {
    this.clearLog();
    this.policy = {
      followRedirects: true,
      maxRedirects: 5,
      onlyInScope: true,
      logOutOfScope: true,
      sameProtocolOnly: false,
      samePortOnly: false
    };
    return this;
  }
}

export const redirectPolicy = new RedirectPolicyController();
export default RedirectPolicyController;
