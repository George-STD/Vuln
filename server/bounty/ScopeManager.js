/**
 * Scope Manager - إدارة نطاقات Bug Bounty
 * يتحكم في ما هو مسموح وممنوع فحصه
 */

import { EventEmitter } from 'events';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class ScopeManager extends EventEmitter {
  constructor() {
    super();
    
    // حالة التفعيل
    this.enabled = false;
    
    // النطاقات المسموحة (In-Scope)
    this.inScope = {
      domains: [],           // ['example.com', '*.example.com']
      subdomains: [],        // ['api.example.com', 'app.example.com']
      ipRanges: [],          // ['192.168.1.0/24', '10.0.0.1']
      urls: [],              // ['https://example.com/api/*']
      ports: [],             // [80, 443, 8080]
      protocols: ['http', 'https'],  // البروتوكولات المسموحة
      apiEndpoints: [],      // ['/api/v1/*', '/graphql']
      mobileEndpoints: []    // للتطبيقات
    };
    
    // النطاقات الممنوعة (Out-of-Scope / Denylist)
    this.outOfScope = {
      domains: [],           // ['admin.example.com']
      subdomains: [],        
      ipRanges: [],          
      paths: [],             // ['/logout', '/admin/delete', '/billing/*']
      endpoints: [],         // ['*/graphql', '*/api/internal/*']
      ports: [],             // [22, 3306]
      keywords: []           // كلمات في URL تمنع الفحص
    };
    
    // Third-party المحظورة تلقائياً
    this.thirdPartyBlacklist = [
      // CDN
      'cloudfront.net', 'akamai.net', 'akamaized.net', 'fastly.net',
      'cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
      // Analytics
      'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
      'hotjar.com', 'mixpanel.com', 'segment.io', 'amplitude.com',
      // Auth Providers
      'auth0.com', 'okta.com', 'onelogin.com', 'login.microsoftonline.com',
      'accounts.google.com', 'facebook.com', 'appleid.apple.com',
      // Storage
      'googleusercontent.com', 's3.amazonaws.com', 'blob.core.windows.net',
      'storage.googleapis.com',
      // Payment
      'stripe.com', 'paypal.com', 'braintreegateway.com', 'adyen.com',
      // Other
      'recaptcha.net', 'gstatic.com', 'googleapis.com', 'sentry.io',
      'newrelic.com', 'nr-data.net', 'bugsnag.com'
    ];
    
    // Third-party مسموحة (استثناءات)
    this.thirdPartyAllowlist = [];
    
    // مسار حفظ الـ profiles
    this.profilesDir = path.join(__dirname, '../data/bounty-profiles');
    
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
   * تفعيل/تعطيل نظام الـ Scope
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    this.emit('status-changed', { enabled });
    return this;
  }

  /**
   * تحميل Scope من ملف تعريف
   */
  async loadProfile(profileName) {
    try {
      const filePath = path.join(this.profilesDir, `${profileName}.json`);
      const data = await fs.readFile(filePath, 'utf-8');
      const profile = JSON.parse(data);
      
      this.inScope = profile.inScope || this.inScope;
      this.outOfScope = profile.outOfScope || this.outOfScope;
      this.thirdPartyAllowlist = profile.thirdPartyAllowlist || [];
      this.enabled = true;
      
      this.emit('profile-loaded', { name: profileName, profile });
      return { success: true, profile };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * حفظ Scope كملف تعريف
   */
  async saveProfile(profileName, metadata = {}) {
    try {
      const profile = {
        name: profileName,
        createdAt: new Date().toISOString(),
        metadata,
        inScope: this.inScope,
        outOfScope: this.outOfScope,
        thirdPartyAllowlist: this.thirdPartyAllowlist
      };
      
      const filePath = path.join(this.profilesDir, `${profileName}.json`);
      await fs.writeFile(filePath, JSON.stringify(profile, null, 2));
      
      this.emit('profile-saved', { name: profileName });
      return { success: true, path: filePath };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * جلب جميع الـ profiles المحفوظة
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
            name: profile.name,
            createdAt: profile.createdAt,
            metadata: profile.metadata,
            domainsCount: profile.inScope?.domains?.length || 0
          });
        }
      }
      
      return profiles;
    } catch (error) {
      return [];
    }
  }

  /**
   * إضافة domain إلى In-Scope
   */
  addInScopeDomain(domain) {
    const normalized = this.normalizeDomain(domain);
    if (!this.inScope.domains.includes(normalized)) {
      this.inScope.domains.push(normalized);
    }
    return this;
  }

  /**
   * إضافة مجموعة domains
   */
  addInScopeDomains(domains) {
    domains.forEach(d => this.addInScopeDomain(d));
    return this;
  }

  /**
   * إضافة domain إلى Out-of-Scope
   */
  addOutOfScopeDomain(domain) {
    const normalized = this.normalizeDomain(domain);
    if (!this.outOfScope.domains.includes(normalized)) {
      this.outOfScope.domains.push(normalized);
    }
    return this;
  }

  /**
   * إضافة path ممنوع
   */
  addOutOfScopePath(pathPattern) {
    if (!this.outOfScope.paths.includes(pathPattern)) {
      this.outOfScope.paths.push(pathPattern);
    }
    return this;
  }

  /**
   * إضافة ports مسموحة
   */
  setAllowedPorts(ports) {
    this.inScope.ports = ports;
    return this;
  }

  /**
   * تطبيع اسم الـ domain
   */
  normalizeDomain(domain) {
    return domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  }

  /**
   * فحص هل URL داخل النطاق المسموح
   * هذه الدالة الأهم - تطبق قواعد allowlist ثم denylist ثم fail-closed
   */
  isInScope(url) {
    // لو النظام معطل، كل شيء مسموح
    if (!this.enabled) {
      return { allowed: true, reason: 'Scope checking disabled' };
    }

    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();
      const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
      const pathname = parsedUrl.pathname;
      const protocol = parsedUrl.protocol.replace(':', '');

      // 1. فحص البروتوكول
      if (!this.inScope.protocols.includes(protocol)) {
        return { 
          allowed: false, 
          reason: `Protocol '${protocol}' not allowed`,
          type: 'protocol'
        };
      }

      // 2. فحص Third-party blacklist
      const isThirdParty = this.thirdPartyBlacklist.some(tp => 
        hostname.includes(tp) || hostname.endsWith(`.${tp}`)
      );
      
      if (isThirdParty) {
        // هل هو في الـ allowlist؟
        const isAllowed = this.thirdPartyAllowlist.some(allowed =>
          hostname.includes(allowed) || hostname.endsWith(`.${allowed}`)
        );
        
        if (!isAllowed) {
          return { 
            allowed: false, 
            reason: `Third-party domain blocked: ${hostname}`,
            type: 'third-party'
          };
        }
      }

      // 3. فحص Out-of-Scope أولاً (Denylist)
      
      // 3.1 فحص domains الممنوعة
      if (this.matchesDomainPattern(hostname, this.outOfScope.domains)) {
        return { 
          allowed: false, 
          reason: `Domain is out-of-scope: ${hostname}`,
          type: 'out-of-scope-domain'
        };
      }

      // 3.2 فحص paths الممنوعة
      if (this.matchesPathPattern(pathname, this.outOfScope.paths)) {
        return { 
          allowed: false, 
          reason: `Path is out-of-scope: ${pathname}`,
          type: 'out-of-scope-path'
        };
      }

      // 3.3 فحص endpoints الممنوعة
      if (this.matchesPathPattern(pathname, this.outOfScope.endpoints)) {
        return { 
          allowed: false, 
          reason: `Endpoint is out-of-scope: ${pathname}`,
          type: 'out-of-scope-endpoint'
        };
      }

      // 3.4 فحص ports الممنوعة
      if (this.outOfScope.ports.includes(parseInt(port))) {
        return { 
          allowed: false, 
          reason: `Port ${port} is out-of-scope`,
          type: 'out-of-scope-port'
        };
      }

      // 3.5 فحص keywords الممنوعة
      const urlLower = url.toLowerCase();
      for (const keyword of this.outOfScope.keywords) {
        if (urlLower.includes(keyword.toLowerCase())) {
          return { 
            allowed: false, 
            reason: `URL contains blocked keyword: ${keyword}`,
            type: 'blocked-keyword'
          };
        }
      }

      // 4. فحص In-Scope (Allowlist)
      
      // لو فيه domains محددة، لازم يكون ضمنها
      if (this.inScope.domains.length > 0) {
        if (!this.matchesDomainPattern(hostname, this.inScope.domains)) {
          return { 
            allowed: false, 
            reason: `Domain not in scope: ${hostname}`,
            type: 'not-in-scope'
          };
        }
      }

      // 4.1 فحص ports المسموحة
      if (this.inScope.ports.length > 0) {
        if (!this.inScope.ports.includes(parseInt(port))) {
          return { 
            allowed: false, 
            reason: `Port ${port} not in allowed list`,
            type: 'port-not-allowed'
          };
        }
      }

      // 5. نجح كل الفحوصات
      return { 
        allowed: true, 
        reason: 'URL is in scope'
      };

    } catch (error) {
      // Fail-closed: لو فيه خطأ، امنع
      return { 
        allowed: false, 
        reason: `Invalid URL or parse error: ${error.message}`,
        type: 'parse-error'
      };
    }
  }

  /**
   * فحص هل redirect مسموح
   */
  isRedirectAllowed(fromUrl, toUrl) {
    if (!this.enabled) {
      return { allowed: true, reason: 'Scope checking disabled' };
    }

    const toCheck = this.isInScope(toUrl);
    
    if (!toCheck.allowed) {
      return {
        allowed: false,
        reason: `Redirect to out-of-scope URL blocked: ${toUrl}`,
        from: fromUrl,
        to: toUrl,
        originalReason: toCheck.reason
      };
    }

    return { allowed: true, from: fromUrl, to: toUrl };
  }

  /**
   * مطابقة نمط domain (يدعم wildcards)
   */
  matchesDomainPattern(hostname, patterns) {
    for (const pattern of patterns) {
      // Wildcard pattern: *.example.com
      if (pattern.startsWith('*.')) {
        const baseDomain = pattern.slice(2);
        if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) {
          return true;
        }
      }
      // Exact match
      else if (hostname === pattern) {
        return true;
      }
    }
    return false;
  }

  /**
   * مطابقة نمط path (يدعم wildcards)
   */
  matchesPathPattern(pathname, patterns) {
    for (const pattern of patterns) {
      // Wildcard at end: /api/*
      if (pattern.endsWith('*')) {
        const prefix = pattern.slice(0, -1);
        if (pathname.startsWith(prefix)) {
          return true;
        }
      }
      // Wildcard at start: */graphql
      else if (pattern.startsWith('*')) {
        const suffix = pattern.slice(1);
        if (pathname.endsWith(suffix)) {
          return true;
        }
      }
      // Exact match
      else if (pathname === pattern || pathname.startsWith(pattern + '/')) {
        return true;
      }
    }
    return false;
  }

  /**
   * فحص IP range (CIDR)
   */
  isIpInRange(ip, cidr) {
    // تنفيذ بسيط - يمكن تحسينه
    const [range, bits] = cidr.split('/');
    if (!bits) return ip === range;
    
    // للتبسيط، نستخدم مقارنة prefix
    const prefix = range.split('.').slice(0, Math.ceil(parseInt(bits) / 8)).join('.');
    return ip.startsWith(prefix);
  }

  /**
   * استيراد scope من نص (Bugcrowd/HackerOne format)
   */
  parseFromText(text) {
    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const result = {
      inScope: { domains: [], paths: [], urls: [] },
      outOfScope: { domains: [], paths: [] }
    };

    let currentSection = 'in';

    for (const line of lines) {
      // تحديد القسم
      if (line.toLowerCase().includes('out of scope') || line.toLowerCase().includes('out-of-scope')) {
        currentSection = 'out';
        continue;
      }
      if (line.toLowerCase().includes('in scope') || line.toLowerCase().includes('in-scope')) {
        currentSection = 'in';
        continue;
      }

      // إزالة bullet points
      const cleanLine = line.replace(/^[-*•]\s*/, '').trim();
      
      // تحليل النوع
      if (cleanLine.startsWith('http://') || cleanLine.startsWith('https://')) {
        if (currentSection === 'in') {
          result.inScope.urls.push(cleanLine);
          try {
            const domain = new URL(cleanLine).hostname;
            if (!result.inScope.domains.includes(domain)) {
              result.inScope.domains.push(domain);
            }
          } catch {}
        } else {
          result.outOfScope.domains.push(cleanLine);
        }
      } else if (cleanLine.startsWith('/')) {
        if (currentSection === 'out') {
          result.outOfScope.paths.push(cleanLine);
        } else {
          result.inScope.paths.push(cleanLine);
        }
      } else if (cleanLine.includes('.') && !cleanLine.includes(' ')) {
        if (currentSection === 'in') {
          result.inScope.domains.push(this.normalizeDomain(cleanLine));
        } else {
          result.outOfScope.domains.push(this.normalizeDomain(cleanLine));
        }
      }
    }

    return result;
  }

  /**
   * تطبيق scope من نص
   */
  importFromText(text) {
    const parsed = this.parseFromText(text);
    
    this.inScope.domains.push(...parsed.inScope.domains);
    this.inScope.urls.push(...parsed.inScope.urls);
    this.outOfScope.domains.push(...parsed.outOfScope.domains);
    this.outOfScope.paths.push(...parsed.outOfScope.paths);
    
    // إزالة التكرار
    this.inScope.domains = [...new Set(this.inScope.domains)];
    this.outOfScope.domains = [...new Set(this.outOfScope.domains)];
    this.outOfScope.paths = [...new Set(this.outOfScope.paths)];
    
    this.enabled = true;
    
    return parsed;
  }

  /**
   * إعادة تعيين كل الإعدادات
   */
  reset() {
    this.enabled = false;
    this.inScope = {
      domains: [],
      subdomains: [],
      ipRanges: [],
      urls: [],
      ports: [],
      protocols: ['http', 'https'],
      apiEndpoints: [],
      mobileEndpoints: []
    };
    this.outOfScope = {
      domains: [],
      subdomains: [],
      ipRanges: [],
      paths: [],
      endpoints: [],
      ports: [],
      keywords: []
    };
    this.thirdPartyAllowlist = [];
    
    this.emit('reset');
    return this;
  }

  /**
   * الحصول على ملخص الإعدادات الحالية
   */
  getSummary() {
    return {
      enabled: this.enabled,
      inScope: {
        domainsCount: this.inScope.domains.length,
        domains: this.inScope.domains.slice(0, 10),
        portsCount: this.inScope.ports.length,
        protocols: this.inScope.protocols
      },
      outOfScope: {
        domainsCount: this.outOfScope.domains.length,
        pathsCount: this.outOfScope.paths.length,
        endpointsCount: this.outOfScope.endpoints.length
      },
      thirdPartyBlocked: this.thirdPartyBlacklist.length,
      thirdPartyAllowed: this.thirdPartyAllowlist.length
    };
  }

  /**
   * تصدير الإعدادات
   */
  export() {
    return {
      enabled: this.enabled,
      inScope: this.inScope,
      outOfScope: this.outOfScope,
      thirdPartyAllowlist: this.thirdPartyAllowlist
    };
  }

  /**
   * استيراد الإعدادات
   */
  import(config) {
    if (config.inScope) this.inScope = { ...this.inScope, ...config.inScope };
    if (config.outOfScope) this.outOfScope = { ...this.outOfScope, ...config.outOfScope };
    if (config.thirdPartyAllowlist) this.thirdPartyAllowlist = config.thirdPartyAllowlist;
    if (typeof config.enabled === 'boolean') this.enabled = config.enabled;
    
    return this;
  }
}

export const scopeManager = new ScopeManager();
export default ScopeManager;
