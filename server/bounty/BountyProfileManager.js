/**
 * Bounty Profile Manager - إدارة ملفات تعريف برامج Bug Bounty
 * يخزن إعدادات كل برنامج (Scope + Rules + Restrictions)
 */

import { EventEmitter } from 'events';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { scopeManager } from './ScopeManager.js';
import { safetyController } from './SafetyController.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class BountyProfileManager extends EventEmitter {
  constructor() {
    super();
    this.profilesDir = path.join(__dirname, '../data/bounty-profiles');
    this.currentProfile = null;
    
    // قوالب جاهزة للبرامج الشائعة
    this.templates = {
      'bugcrowd-standard': {
        name: 'Bugcrowd Standard',
        description: 'إعدادات آمنة لبرامج Bugcrowd',
        safety: {
          globalRPS: 2,
          perHostRPS: 1,
          maxConcurrency: 2,
          safeMode: true,
          allowedMethods: ['GET', 'HEAD'],
          maxUrls: 200,
          maxDepth: 2
        },
        restrictions: {
          noDoS: true,
          noSocialEngineering: true,
          noPhysicalAccess: true,
          noRealUserData: true,
          noEmployeeTargeting: true
        },
        headers: {
          'X-Bugcrowd-Research': 'true'
        }
      },
      'hackerone-standard': {
        name: 'HackerOne Standard',
        description: 'إعدادات آمنة لبرامج HackerOne',
        safety: {
          globalRPS: 3,
          perHostRPS: 1,
          maxConcurrency: 2,
          safeMode: true,
          allowedMethods: ['GET', 'HEAD'],
          maxUrls: 300,
          maxDepth: 3
        },
        restrictions: {
          noDoS: true,
          noSocialEngineering: true,
          noPhysicalAccess: true,
          noRealUserData: true,
          noEmployeeTargeting: true,
          noPrivacyViolation: true
        },
        headers: {}
      },
      'intigriti-standard': {
        name: 'Intigriti Standard',
        description: 'إعدادات آمنة لبرامج Intigriti',
        safety: {
          globalRPS: 2,
          perHostRPS: 1,
          maxConcurrency: 2,
          safeMode: true,
          allowedMethods: ['GET', 'HEAD'],
          maxUrls: 200,
          maxDepth: 2
        },
        restrictions: {
          noDoS: true,
          noSocialEngineering: true,
          noRealUserData: true
        },
        headers: {}
      },
      'aggressive': {
        name: 'Aggressive (Authorized Only)',
        description: '⚠️ للاستخدام المرخص فقط',
        safety: {
          globalRPS: 20,
          perHostRPS: 10,
          maxConcurrency: 10,
          safeMode: false,
          allowedMethods: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH'],
          maxUrls: 2000,
          maxDepth: 5
        },
        restrictions: {},
        headers: {}
      },
      'minimal': {
        name: 'Minimal Safe',
        description: 'أقل إعدادات ممكنة - للفحص السريع',
        safety: {
          globalRPS: 1,
          perHostRPS: 1,
          maxConcurrency: 1,
          safeMode: true,
          allowedMethods: ['GET', 'HEAD'],
          maxUrls: 50,
          maxDepth: 1
        },
        restrictions: {
          noDoS: true,
          noSocialEngineering: true,
          noRealUserData: true,
          noDestructive: true
        },
        headers: {}
      }
    };

    this.init();
  }

  async init() {
    try {
      await fs.mkdir(this.profilesDir, { recursive: true });
    } catch (error) {
      console.error('Failed to create profiles directory:', error);
    }
  }

  /**
   * إنشاء ملف تعريف جديد
   */
  async createProfile(config) {
    const profile = {
      id: this.generateId(),
      name: config.name,
      platform: config.platform || 'custom', // bugcrowd, hackerone, intigriti, custom
      programUrl: config.programUrl || null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      
      // النطاقات
      scope: {
        inScope: config.inScope || {
          domains: [],
          subdomains: [],
          ipRanges: [],
          urls: [],
          ports: config.allowedPorts || [80, 443],
          protocols: ['http', 'https'],
          apiEndpoints: [],
          mobileEndpoints: []
        },
        outOfScope: config.outOfScope || {
          domains: [],
          subdomains: [],
          ipRanges: [],
          paths: [],
          endpoints: [],
          ports: [],
          keywords: []
        },
        thirdPartyAllowed: config.thirdPartyAllowed || []
      },
      
      // إعدادات السلامة
      safety: config.safety || {
        globalRPS: 3,
        perHostRPS: 1,
        maxConcurrency: 2,
        safeMode: true,
        allowedMethods: ['GET', 'HEAD'],
        maxUrls: 200,
        maxDepth: 2,
        maxResponseSize: 5242880,
        backoffEnabled: true
      },
      
      // القيود والقواعد
      restrictions: config.restrictions || {
        noDoS: true,
        noLoadTesting: true,
        noSocialEngineering: true,
        noPhysicalAccess: true,
        noRealUserData: true,
        noEmployeeTargeting: true,
        noPrivacyViolation: true,
        noDestructive: true,
        testAccountOnly: true
      },
      
      // الوحدات المسموحة/الممنوعة
      modules: {
        allowed: config.allowedModules || ['headers', 'ssl', 'cors', 'tech', 'xss', 'sqli', 'csrf'],
        blocked: config.blockedModules || ['bruteforce', 'waf-bypass', 'dos']
      },
      
      // Headers مخصصة
      customHeaders: config.customHeaders || {},
      
      // User-Agent
      userAgent: config.userAgent || 'VulnHunterPro/2.0 (Security Research)',
      
      // ملاحظات
      notes: config.notes || '',
      
      // إحصائيات
      stats: {
        lastUsed: null,
        scansCount: 0,
        findingsCount: 0
      }
    };

    // حفظ الملف
    const filePath = path.join(this.profilesDir, `${profile.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(profile, null, 2));
    
    this.emit('profile-created', { id: profile.id, name: profile.name });
    
    return profile;
  }

  /**
   * تحميل ملف تعريف
   */
  async loadProfile(profileId) {
    try {
      const filePath = path.join(this.profilesDir, `${profileId}.json`);
      const data = await fs.readFile(filePath, 'utf-8');
      const profile = JSON.parse(data);
      
      this.currentProfile = profile;
      this.applyProfile(profile);
      
      // تحديث إحصائيات
      profile.stats.lastUsed = new Date().toISOString();
      await fs.writeFile(filePath, JSON.stringify(profile, null, 2));
      
      this.emit('profile-loaded', { id: profileId, name: profile.name });
      
      return { success: true, profile };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * تطبيق ملف تعريف على Scope Manager و Safety Controller
   */
  applyProfile(profile) {
    // تطبيق الـ Scope
    scopeManager.reset();
    scopeManager.import({
      enabled: true,
      inScope: profile.scope.inScope,
      outOfScope: profile.scope.outOfScope,
      thirdPartyAllowlist: profile.scope.thirdPartyAllowed
    });
    scopeManager.setEnabled(true);

    // تطبيق إعدادات السلامة
    safetyController.reset();
    safetyController.import({
      enabled: true,
      rateLimiting: {
        enabled: true,
        globalRPS: profile.safety.globalRPS,
        perHostRPS: profile.safety.perHostRPS,
        maxConcurrency: profile.safety.maxConcurrency,
        backoff: {
          enabled: profile.safety.backoffEnabled !== false,
          on429: true,
          on503: true,
          on504: true,
          onHighLatency: true
        }
      },
      crawling: {
        maxUrls: profile.safety.maxUrls,
        maxDepth: profile.safety.maxDepth,
        allowedMethods: profile.safety.allowedMethods,
        blockDestructiveMethods: profile.safety.safeMode,
        maxResponseSize: profile.safety.maxResponseSize
      },
      security: {
        safeMode: profile.safety.safeMode,
        disableWAFBypass: true,
        disableBruteforce: true
      },
      userAgent: {
        custom: profile.userAgent
      },
      customHeaders: profile.customHeaders
    });
    safetyController.setEnabled(true);

    return this;
  }

  /**
   * تحميل قالب جاهز
   */
  async loadTemplate(templateName) {
    const template = this.templates[templateName];
    if (!template) {
      return { success: false, error: 'Template not found' };
    }

    // تطبيق القالب على Safety Controller
    safetyController.reset();
    safetyController.import({
      enabled: true,
      rateLimiting: {
        enabled: true,
        globalRPS: template.safety.globalRPS,
        perHostRPS: template.safety.perHostRPS,
        maxConcurrency: template.safety.maxConcurrency
      },
      crawling: {
        maxUrls: template.safety.maxUrls,
        maxDepth: template.safety.maxDepth,
        allowedMethods: template.safety.allowedMethods,
        blockDestructiveMethods: template.safety.safeMode
      },
      security: {
        safeMode: template.safety.safeMode
      },
      customHeaders: template.headers
    });
    safetyController.setEnabled(true);

    this.emit('template-loaded', { name: templateName });
    
    return { success: true, template };
  }

  /**
   * جلب جميع الملفات المحفوظة
   */
  async getProfiles() {
    try {
      const files = await fs.readdir(this.profilesDir);
      const profiles = [];
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const data = await fs.readFile(path.join(this.profilesDir, file), 'utf-8');
          const profile = JSON.parse(data);
          profiles.push({
            id: profile.id,
            name: profile.name,
            platform: profile.platform,
            createdAt: profile.createdAt,
            lastUsed: profile.stats?.lastUsed,
            domainsCount: profile.scope?.inScope?.domains?.length || 0,
            scansCount: profile.stats?.scansCount || 0
          });
        }
      }
      
      return profiles;
    } catch (error) {
      return [];
    }
  }

  /**
   * جلب القوالب المتاحة
   */
  getTemplates() {
    return Object.entries(this.templates).map(([id, template]) => ({
      id,
      name: template.name,
      description: template.description,
      safeMode: template.safety.safeMode
    }));
  }

  /**
   * تحديث ملف تعريف
   */
  async updateProfile(profileId, updates) {
    try {
      const filePath = path.join(this.profilesDir, `${profileId}.json`);
      const data = await fs.readFile(filePath, 'utf-8');
      const profile = JSON.parse(data);
      
      // دمج التحديثات
      const updated = this.deepMerge(profile, updates);
      updated.updatedAt = new Date().toISOString();
      
      await fs.writeFile(filePath, JSON.stringify(updated, null, 2));
      
      this.emit('profile-updated', { id: profileId });
      
      return { success: true, profile: updated };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * حذف ملف تعريف
   */
  async deleteProfile(profileId) {
    try {
      const filePath = path.join(this.profilesDir, `${profileId}.json`);
      await fs.unlink(filePath);
      
      if (this.currentProfile?.id === profileId) {
        this.currentProfile = null;
      }
      
      this.emit('profile-deleted', { id: profileId });
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * استنساخ ملف تعريف
   */
  async cloneProfile(profileId, newName) {
    try {
      const result = await this.loadProfile(profileId);
      if (!result.success) {
        return result;
      }
      
      const profile = result.profile;
      profile.id = this.generateId();
      profile.name = newName;
      profile.createdAt = new Date().toISOString();
      profile.stats = { lastUsed: null, scansCount: 0, findingsCount: 0 };
      
      const filePath = path.join(this.profilesDir, `${profile.id}.json`);
      await fs.writeFile(filePath, JSON.stringify(profile, null, 2));
      
      return { success: true, profile };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * تصدير ملف تعريف
   */
  async exportProfile(profileId) {
    try {
      const filePath = path.join(this.profilesDir, `${profileId}.json`);
      const data = await fs.readFile(filePath, 'utf-8');
      return { success: true, data: JSON.parse(data) };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * استيراد ملف تعريف
   */
  async importProfile(profileData) {
    try {
      profileData.id = this.generateId();
      profileData.createdAt = new Date().toISOString();
      
      const filePath = path.join(this.profilesDir, `${profileData.id}.json`);
      await fs.writeFile(filePath, JSON.stringify(profileData, null, 2));
      
      return { success: true, id: profileData.id };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * جلب الملف التعريف الحالي
   */
  getCurrentProfile() {
    return this.currentProfile;
  }

  /**
   * إلغاء تحميل الملف الحالي
   */
  unloadProfile() {
    this.currentProfile = null;
    scopeManager.setEnabled(false);
    safetyController.setEnabled(false);
    this.emit('profile-unloaded');
    return this;
  }

  /**
   * توليد ID فريد
   */
  generateId() {
    return `profile-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * دمج عميق للكائنات
   */
  deepMerge(target, source) {
    const result = { ...target };
    
    for (const key of Object.keys(source)) {
      if (source[key] instanceof Object && key in target) {
        result[key] = this.deepMerge(target[key], source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }
}

export const bountyProfileManager = new BountyProfileManager();
export default BountyProfileManager;
