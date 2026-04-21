/**
 * Kill Switch - مفتاح الإيقاف الفوري
 * يوقف كل العمليات فوراً
 */

import { EventEmitter } from 'events';

class KillSwitch extends EventEmitter {
  constructor() {
    super();
    this.isActivated = false;
    this.activationTime = null;
    this.reason = null;
    this.activeScans = new Set();
    this.activeWorkers = new Set();
    this.pendingRequests = new Set();
  }

  /**
   * تفعيل مفتاح الإيقاف
   */
  activate(reason = 'Manual activation') {
    this.isActivated = true;
    this.activationTime = new Date().toISOString();
    this.reason = reason;
    
    console.log('\n🛑 ═══════════════════════════════════════════');
    console.log('   KILL SWITCH ACTIVATED');
    console.log(`   Reason: ${reason}`);
    console.log(`   Time: ${this.activationTime}`);
    console.log('═══════════════════════════════════════════ 🛑\n');
    
    // إشعار كل المستمعين
    this.emit('activated', {
      reason,
      time: this.activationTime,
      activeScans: this.activeScans.size,
      activeWorkers: this.activeWorkers.size,
      pendingRequests: this.pendingRequests.size
    });
    
    // إلغاء كل الطلبات المعلقة
    for (const controller of this.pendingRequests) {
      try {
        controller.abort();
      } catch {}
    }
    this.pendingRequests.clear();
    
    return {
      activated: true,
      reason,
      time: this.activationTime,
      stoppedScans: this.activeScans.size,
      stoppedWorkers: this.activeWorkers.size
    };
  }

  /**
   * إلغاء تفعيل مفتاح الإيقاف
   */
  deactivate() {
    this.isActivated = false;
    this.reason = null;
    
    console.log('✅ Kill switch deactivated');
    
    this.emit('deactivated');
    
    return { deactivated: true };
  }

  /**
   * فحص هل مفتاح الإيقاف مفعل
   */
  isActive() {
    return this.isActivated;
  }

  /**
   * تسجيل فحص نشط
   */
  registerScan(scanId) {
    this.activeScans.add(scanId);
    return this;
  }

  /**
   * إلغاء تسجيل فحص
   */
  unregisterScan(scanId) {
    this.activeScans.delete(scanId);
    return this;
  }

  /**
   * تسجيل worker نشط
   */
  registerWorker(workerId) {
    this.activeWorkers.add(workerId);
    return this;
  }

  /**
   * إلغاء تسجيل worker
   */
  unregisterWorker(workerId) {
    this.activeWorkers.delete(workerId);
    return this;
  }

  /**
   * تسجيل AbortController لطلب
   */
  registerRequest(controller) {
    this.pendingRequests.add(controller);
    return controller;
  }

  /**
   * إلغاء تسجيل AbortController
   */
  unregisterRequest(controller) {
    this.pendingRequests.delete(controller);
    return this;
  }

  /**
   * إنشاء AbortController جديد مربوط بالـ Kill Switch
   */
  createAbortController() {
    const controller = new AbortController();
    this.registerRequest(controller);
    
    // لو Kill Switch مفعل، ألغِ فوراً
    if (this.isActivated) {
      controller.abort();
    }
    
    return controller;
  }

  /**
   * التحقق قبل أي عملية
   * يُستدعى قبل كل طلب HTTP أو عملية مهمة
   */
  checkBeforeOperation() {
    if (this.isActivated) {
      throw new KillSwitchError('Operation aborted: Kill switch is active', this.reason);
    }
    return true;
  }

  /**
   * الحصول على الحالة
   */
  getStatus() {
    return {
      isActivated: this.isActivated,
      activationTime: this.activationTime,
      reason: this.reason,
      activeScans: this.activeScans.size,
      activeWorkers: this.activeWorkers.size,
      pendingRequests: this.pendingRequests.size
    };
  }

  /**
   * إعادة تعيين كل شيء
   */
  reset() {
    this.isActivated = false;
    this.activationTime = null;
    this.reason = null;
    this.activeScans.clear();
    this.activeWorkers.clear();
    this.pendingRequests.clear();
    return this;
  }
}

/**
 * خطأ Kill Switch مخصص
 */
class KillSwitchError extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'KillSwitchError';
    this.reason = reason;
    this.isKillSwitch = true;
  }
}

export const killSwitch = new KillSwitch();
export { KillSwitchError };
export default KillSwitch;
