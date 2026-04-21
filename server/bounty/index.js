/**
 * Bounty Module - التصدير الرئيسي لنظام Bug Bounty
 */

import { scopeManager, default as ScopeManager } from './ScopeManager.js';
import { safetyController, default as SafetyController } from './SafetyController.js';
import { preflightCheck, default as PreflightCheck } from './PreflightCheck.js';
import { bountyProfileManager, default as BountyProfileManager } from './BountyProfileManager.js';
import { killSwitch, KillSwitchError, default as KillSwitch } from './KillSwitch.js';
import { redirectPolicy, default as RedirectPolicyController } from './RedirectPolicy.js';

/**
 * Bounty System - الواجهة الموحدة لنظام Bug Bounty
 */
class BountySystem {
  constructor() {
    this.scope = scopeManager;
    this.safety = safetyController;
    this.preflight = preflightCheck;
    this.profiles = bountyProfileManager;
    this.killSwitch = killSwitch;
    this.redirect = redirectPolicy;
    
    // حالة النظام
    this.enabled = false;
  }

  /**
   * تفعيل نظام Bug Bounty
   */
  enable() {
    this.enabled = true;
    console.log('🎯 Bug Bounty safety system enabled');
    return this;
  }

  /**
   * تعطيل نظام Bug Bounty
   */
  disable() {
    this.enabled = false;
    this.scope.setEnabled(false);
    this.safety.setEnabled(false);
    this.redirect.setEnabled(false);
    console.log('⚠️ Bug Bounty safety system disabled');
    return this;
  }

  /**
   * Check if Bug Bounty system is enabled
   */
  isEnabled() {
    return this.enabled;
  }

  /**
   * تطبيق ملف تعريف آمن للـ Bug Bounty
   */
  applySafeProfile(targetDomains = []) {
    this.enable();
    
    // تطبيق إعدادات السلامة
    this.safety.applyBugBountyProfile();
    
    // إضافة الـ domains
    if (targetDomains.length > 0) {
      this.scope.reset();
      this.scope.addInScopeDomains(targetDomains);
      this.scope.setEnabled(true);
    }
    
    // تفعيل Redirect Policy
    this.redirect.setEnabled(true);
    this.redirect.updatePolicy({
      onlyInScope: true,
      maxRedirects: 3
    });
    
    console.log('✅ Bug Bounty safe profile applied');
    
    return this;
  }

  /**
   * تحميل ملف تعريف برنامج
   */
  async loadProgram(profileId) {
    const result = await this.profiles.loadProfile(profileId);
    if (result.success) {
      this.enable();
    }
    return result;
  }

  /**
   * تحميل قالب جاهز
   */
  async loadTemplate(templateName) {
    const result = await this.profiles.loadTemplate(templateName);
    if (result.success) {
      this.enable();
    }
    return result;
  }

  /**
   * فحص ما قبل الفحص
   */
  async runPreflight(targetUrl, options = {}) {
    return this.preflight.runChecks(targetUrl, options);
  }

  /**
   * فحص هل يمكن المتابعة
   */
  canProceed(url, method = 'GET') {
    // فحص Kill Switch
    if (this.killSwitch.isActive()) {
      return { 
        allowed: false, 
        reason: 'Kill switch is active',
        type: 'kill-switch'
      };
    }

    // لو النظام معطل
    if (!this.enabled) {
      return { allowed: true, reason: 'Bounty system disabled' };
    }

    // فحص Scope
    if (this.scope.enabled) {
      const scopeCheck = this.scope.isInScope(url);
      if (!scopeCheck.allowed) {
        return { 
          allowed: false, 
          reason: scopeCheck.reason,
          type: 'scope'
        };
      }
    }

    return { allowed: true };
  }

  /**
   * فحص هل يمكن إرسال طلب
   */
  async canMakeRequest(url, method = 'GET') {
    // فحص أساسي
    const proceedCheck = this.canProceed(url, method);
    if (!proceedCheck.allowed) {
      return proceedCheck;
    }

    // فحص Safety Controller
    if (this.safety.enabled) {
      const safetyCheck = await this.safety.canMakeRequest(url, method);
      if (!safetyCheck.allowed) {
        return safetyCheck;
      }
    }

    return { allowed: true };
  }

  /**
   * إيقاف فوري
   */
  emergencyStop(reason = 'Emergency stop') {
    return this.killSwitch.activate(reason);
  }

  /**
   * استئناف بعد الإيقاف
   */
  resume() {
    this.killSwitch.deactivate();
    return this;
  }

  /**
   * الحصول على الحالة الكاملة
   */
  getStatus() {
    return {
      enabled: this.enabled,
      scope: this.scope.getSummary(),
      safety: this.safety.getSummary(),
      killSwitch: this.killSwitch.getStatus(),
      redirect: this.redirect.getStats(),
      currentProfile: this.profiles.getCurrentProfile()?.name || null
    };
  }

  /**
   * تصدير كل الإعدادات
   */
  exportConfig() {
    return {
      enabled: this.enabled,
      scope: this.scope.export(),
      safety: this.safety.export(),
      redirect: this.redirect.policy
    };
  }

  /**
   * استيراد الإعدادات
   */
  importConfig(config) {
    if (config.scope) this.scope.import(config.scope);
    if (config.safety) this.safety.import(config.safety);
    if (config.redirect) this.redirect.updatePolicy(config.redirect);
    if (typeof config.enabled === 'boolean') this.enabled = config.enabled;
    
    return this;
  }

  /**
   * إعادة تعيين كل شيء
   */
  reset() {
    this.enabled = false;
    this.scope.reset();
    this.safety.reset();
    this.redirect.reset();
    this.killSwitch.reset();
    return this;
  }
}

// Instance واحد
const bountySystem = new BountySystem();

// Exports
export {
  bountySystem,
  scopeManager,
  safetyController,
  preflightCheck,
  bountyProfileManager,
  killSwitch,
  KillSwitchError,
  redirectPolicy,
  ScopeManager,
  SafetyController,
  PreflightCheck,
  BountyProfileManager,
  KillSwitch,
  RedirectPolicyController
};

export default bountySystem;
