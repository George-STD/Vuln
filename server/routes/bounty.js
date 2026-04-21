/**
 * Bug Bounty Routes - واجهات API لنظام Bug Bounty
 */

import express from 'express';
import {
  bountySystem,
  scopeManager,
  safetyController,
  bountyProfileManager,
  preflightCheck,
  killSwitch
} from '../bounty/index.js';
import { auditLogger, AUDIT_EVENTS } from '../audit/AuditLogger.js';

const router = express.Router();

// ============ نظام Bug Bounty العام ============

/**
 * GET /api/bounty/status
 * الحصول على حالة النظام
 */
router.get('/status', (req, res) => {
  res.json({
    success: true,
    status: bountySystem.getStatus()
  });
});

/**
 * POST /api/bounty/enable
 * تفعيل النظام
 */
router.post('/enable', async (req, res) => {
  bountySystem.enable();
  
  await auditLogger.log({
    eventType: 'BOUNTY_SYSTEM_ENABLED',
    actor: req.user?.id || 'anonymous',
    resource: 'bounty-system'
  });
  
  res.json({
    success: true,
    message: 'Bug Bounty safety system enabled',
    status: bountySystem.getStatus()
  });
});

/**
 * POST /api/bounty/disable
 * تعطيل النظام
 */
router.post('/disable', async (req, res) => {
  bountySystem.disable();
  
  await auditLogger.log({
    eventType: 'BOUNTY_SYSTEM_DISABLED',
    actor: req.user?.id || 'anonymous',
    resource: 'bounty-system'
  });
  
  res.json({
    success: true,
    message: 'Bug Bounty safety system disabled'
  });
});

/**
 * POST /api/bounty/apply-safe-profile
 * تطبيق ملف تعريف آمن
 */
router.post('/apply-safe-profile', (req, res) => {
  const { domains } = req.body;
  
  bountySystem.applySafeProfile(domains || []);
  
  res.json({
    success: true,
    message: 'Safe Bug Bounty profile applied',
    status: bountySystem.getStatus()
  });
});

// ============ Scope Management ============

/**
 * GET /api/bounty/scope
 * الحصول على إعدادات الـ Scope
 */
router.get('/scope', (req, res) => {
  res.json({
    success: true,
    enabled: scopeManager.enabled,
    scope: scopeManager.export(),
    summary: scopeManager.getSummary()
  });
});

/**
 * POST /api/bounty/scope/enable
 * تفعيل Scope checking
 */
router.post('/scope/enable', (req, res) => {
  scopeManager.setEnabled(true);
  
  res.json({
    success: true,
    message: 'Scope checking enabled'
  });
});

/**
 * POST /api/bounty/scope/disable
 * تعطيل Scope checking
 */
router.post('/scope/disable', (req, res) => {
  scopeManager.setEnabled(false);
  
  res.json({
    success: true,
    message: 'Scope checking disabled'
  });
});

/**
 * POST /api/bounty/scope/in-scope
 * إضافة domains إلى In-Scope
 */
router.post('/scope/in-scope', (req, res) => {
  const { domains, ports, protocols } = req.body;
  
  if (domains) {
    scopeManager.addInScopeDomains(domains);
  }
  
  if (ports) {
    scopeManager.setAllowedPorts(ports);
  }
  
  if (protocols) {
    scopeManager.inScope.protocols = protocols;
  }
  
  res.json({
    success: true,
    message: 'In-scope updated',
    inScope: scopeManager.inScope
  });
});

/**
 * POST /api/bounty/scope/out-of-scope
 * إضافة إلى Out-of-Scope
 */
router.post('/scope/out-of-scope', (req, res) => {
  const { domains, paths, endpoints, ports, keywords } = req.body;
  
  if (domains) {
    domains.forEach(d => scopeManager.addOutOfScopeDomain(d));
  }
  
  if (paths) {
    paths.forEach(p => scopeManager.addOutOfScopePath(p));
  }
  
  if (endpoints) {
    scopeManager.outOfScope.endpoints.push(...endpoints);
  }
  
  if (ports) {
    scopeManager.outOfScope.ports.push(...ports);
  }
  
  if (keywords) {
    scopeManager.outOfScope.keywords.push(...keywords);
  }
  
  res.json({
    success: true,
    message: 'Out-of-scope updated',
    outOfScope: scopeManager.outOfScope
  });
});

/**
 * POST /api/bounty/scope/check
 * فحص هل URL داخل الـ Scope
 */
router.post('/scope/check', (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  const result = scopeManager.isInScope(url);
  
  res.json({
    success: true,
    url,
    ...result
  });
});

/**
 * POST /api/bounty/scope/import-text
 * استيراد Scope من نص
 */
router.post('/scope/import-text', (req, res) => {
  const { text } = req.body;
  
  if (!text) {
    return res.status(400).json({ error: 'Text is required' });
  }
  
  const result = scopeManager.importFromText(text);
  
  res.json({
    success: true,
    message: 'Scope imported from text',
    imported: result,
    summary: scopeManager.getSummary()
  });
});

/**
 * POST /api/bounty/scope/reset
 * إعادة تعيين الـ Scope
 */
router.post('/scope/reset', (req, res) => {
  scopeManager.reset();
  
  res.json({
    success: true,
    message: 'Scope reset'
  });
});

// ============ Safety Controller ============

/**
 * GET /api/bounty/safety
 * الحصول على إعدادات السلامة
 */
router.get('/safety', (req, res) => {
  res.json({
    success: true,
    enabled: safetyController.enabled,
    settings: safetyController.export(),
    stats: safetyController.getStats(),
    summary: safetyController.getSummary()
  });
});

/**
 * POST /api/bounty/safety/enable
 * تفعيل ضوابط السلامة
 */
router.post('/safety/enable', (req, res) => {
  safetyController.setEnabled(true);
  
  res.json({
    success: true,
    message: 'Safety controls enabled'
  });
});

/**
 * POST /api/bounty/safety/disable
 * تعطيل ضوابط السلامة
 */
router.post('/safety/disable', (req, res) => {
  safetyController.setEnabled(false);
  
  res.json({
    success: true,
    message: 'Safety controls disabled'
  });
});

/**
 * POST /api/bounty/safety/rate-limits
 * تحديث Rate Limits
 */
router.post('/safety/rate-limits', (req, res) => {
  const { globalRPS, perHostRPS, maxConcurrency, burstLimit } = req.body;
  
  if (globalRPS !== undefined) safetyController.rateLimiting.globalRPS = globalRPS;
  if (perHostRPS !== undefined) safetyController.rateLimiting.perHostRPS = perHostRPS;
  if (maxConcurrency !== undefined) safetyController.rateLimiting.maxConcurrency = maxConcurrency;
  if (burstLimit !== undefined) safetyController.rateLimiting.burstLimit = burstLimit;
  
  res.json({
    success: true,
    message: 'Rate limits updated',
    rateLimiting: safetyController.rateLimiting
  });
});

/**
 * POST /api/bounty/safety/crawling
 * تحديث إعدادات الزحف
 */
router.post('/safety/crawling', (req, res) => {
  const { maxUrls, maxDepth, allowedMethods, maxResponseSize } = req.body;
  
  if (maxUrls !== undefined) safetyController.crawling.maxUrls = maxUrls;
  if (maxDepth !== undefined) safetyController.crawling.maxDepth = maxDepth;
  if (allowedMethods !== undefined) safetyController.crawling.allowedMethods = allowedMethods;
  if (maxResponseSize !== undefined) safetyController.crawling.maxResponseSize = maxResponseSize;
  
  res.json({
    success: true,
    message: 'Crawling settings updated',
    crawling: safetyController.crawling
  });
});

/**
 * POST /api/bounty/safety/safe-mode
 * تفعيل/تعطيل Safe Mode
 */
router.post('/safety/safe-mode', (req, res) => {
  const { enabled } = req.body;
  
  safetyController.security.safeMode = enabled !== false;
  safetyController.crawling.blockDestructiveMethods = enabled !== false;
  
  if (enabled) {
    safetyController.crawling.allowedMethods = ['GET', 'HEAD'];
  }
  
  res.json({
    success: true,
    safeMode: safetyController.security.safeMode,
    message: enabled ? 'Safe Mode enabled' : 'Safe Mode disabled'
  });
});

/**
 * POST /api/bounty/safety/user-agent
 * تحديث User-Agent
 */
router.post('/safety/user-agent', (req, res) => {
  const { userAgent, contactEmail } = req.body;
  
  safetyController.setUserAgent(userAgent, contactEmail);
  
  res.json({
    success: true,
    userAgent: safetyController.userAgent.custom
  });
});

/**
 * POST /api/bounty/safety/headers
 * إضافة Headers مخصصة
 */
router.post('/safety/headers', (req, res) => {
  const { headers } = req.body;
  
  if (headers && typeof headers === 'object') {
    Object.entries(headers).forEach(([name, value]) => {
      safetyController.addCustomHeader(name, value);
    });
  }
  
  res.json({
    success: true,
    customHeaders: safetyController.customHeaders
  });
});

/**
 * POST /api/bounty/safety/budget
 * تحديث Budget Limits
 */
router.post('/safety/budget', (req, res) => {
  const { enabled, maxScanTime, maxRequests, maxHosts, maxFindings } = req.body;
  
  if (typeof enabled === 'boolean') safetyController.budgetLimits.enabled = enabled;
  if (maxScanTime !== undefined) safetyController.budgetLimits.maxScanTime = maxScanTime;
  if (maxRequests !== undefined) safetyController.budgetLimits.maxRequests = maxRequests;
  if (maxHosts !== undefined) safetyController.budgetLimits.maxHosts = maxHosts;
  if (maxFindings !== undefined) safetyController.budgetLimits.maxFindings = maxFindings;
  
  res.json({
    success: true,
    budgetLimits: safetyController.budgetLimits
  });
});

// ============ Profiles ============

/**
 * GET /api/bounty/profiles
 * جلب كل الـ profiles
 */
router.get('/profiles', async (req, res) => {
  const profiles = await bountyProfileManager.getProfiles();
  
  res.json({
    success: true,
    profiles
  });
});

/**
 * GET /api/bounty/profiles/templates
 * جلب القوالب الجاهزة
 */
router.get('/profiles/templates', (req, res) => {
  const templates = bountyProfileManager.getTemplates();
  
  res.json({
    success: true,
    templates
  });
});

/**
 * POST /api/bounty/profiles
 * إنشاء profile جديد
 */
router.post('/profiles', async (req, res) => {
  try {
    const profile = await bountyProfileManager.createProfile(req.body);
    
    await auditLogger.log({
      eventType: 'BOUNTY_PROFILE_CREATED',
      actor: req.user?.id || 'anonymous',
      resource: profile.id,
      details: { name: profile.name }
    });
    
    res.json({
      success: true,
      profile
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/bounty/profiles/:id
 * جلب profile معين
 */
router.get('/profiles/:id', async (req, res) => {
  const result = await bountyProfileManager.exportProfile(req.params.id);
  
  if (!result.success) {
    return res.status(404).json(result);
  }
  
  res.json({
    success: true,
    profile: result.data
  });
});

/**
 * POST /api/bounty/profiles/:id/load
 * تحميل وتطبيق profile
 */
router.post('/profiles/:id/load', async (req, res) => {
  const result = await bountyProfileManager.loadProfile(req.params.id);
  
  if (!result.success) {
    return res.status(404).json(result);
  }
  
  bountySystem.enable();
  
  res.json({
    success: true,
    message: 'Profile loaded and applied',
    profile: result.profile
  });
});

/**
 * POST /api/bounty/profiles/template/:name/load
 * تحميل قالب جاهز
 */
router.post('/profiles/template/:name/load', async (req, res) => {
  const result = await bountyProfileManager.loadTemplate(req.params.name);
  
  if (!result.success) {
    return res.status(404).json(result);
  }
  
  bountySystem.enable();
  
  res.json({
    success: true,
    message: 'Template loaded',
    template: result.template
  });
});

/**
 * PUT /api/bounty/profiles/:id
 * تحديث profile
 */
router.put('/profiles/:id', async (req, res) => {
  const result = await bountyProfileManager.updateProfile(req.params.id, req.body);
  
  res.json(result);
});

/**
 * DELETE /api/bounty/profiles/:id
 * حذف profile
 */
router.delete('/profiles/:id', async (req, res) => {
  const result = await bountyProfileManager.deleteProfile(req.params.id);
  
  res.json(result);
});

/**
 * POST /api/bounty/profiles/:id/clone
 * استنساخ profile
 */
router.post('/profiles/:id/clone', async (req, res) => {
  const { name } = req.body;
  
  const result = await bountyProfileManager.cloneProfile(req.params.id, name);
  
  res.json(result);
});

// ============ Preflight ============

/**
 * POST /api/bounty/preflight
 * تنفيذ فحوصات ما قبل الفحص
 */
router.post('/preflight', async (req, res) => {
  const { targetUrl, options } = req.body;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required' });
  }
  
  const result = await preflightCheck.runChecks(targetUrl, options || {});
  
  res.json({
    success: true,
    preflight: result
  });
});

/**
 * POST /api/bounty/preflight/confirm
 * تأكيد الموافقات وإنشاء سجل
 */
router.post('/preflight/confirm', async (req, res) => {
  const { targetUrl, options, confirmations } = req.body;
  
  const consentLog = preflightCheck.createConsentLog(targetUrl, options || {}, confirmations || []);
  
  await auditLogger.log({
    eventType: 'SCAN_CONSENT_LOGGED',
    actor: req.user?.id || 'anonymous',
    resource: targetUrl,
    details: consentLog
  });
  
  res.json({
    success: true,
    consentLog
  });
});

// ============ Kill Switch ============

/**
 * GET /api/bounty/kill-switch
 * حالة Kill Switch
 */
router.get('/kill-switch', (req, res) => {
  res.json({
    success: true,
    status: killSwitch.getStatus()
  });
});

/**
 * POST /api/bounty/kill-switch/activate
 * تفعيل Kill Switch
 */
router.post('/kill-switch/activate', async (req, res) => {
  const { reason } = req.body;
  
  const result = killSwitch.activate(reason || 'Manual activation via API');
  
  await auditLogger.log({
    eventType: 'KILL_SWITCH_ACTIVATED',
    actor: req.user?.id || 'anonymous',
    resource: 'kill-switch',
    details: { reason: result.reason }
  });
  
  res.json({
    success: true,
    ...result
  });
});

/**
 * POST /api/bounty/kill-switch/deactivate
 * إلغاء تفعيل Kill Switch
 */
router.post('/kill-switch/deactivate', async (req, res) => {
  killSwitch.deactivate();
  
  await auditLogger.log({
    eventType: 'KILL_SWITCH_DEACTIVATED',
    actor: req.user?.id || 'anonymous',
    resource: 'kill-switch'
  });
  
  res.json({
    success: true,
    message: 'Kill switch deactivated'
  });
});

// ============ Export/Import ============

/**
 * GET /api/bounty/export
 * تصدير كل الإعدادات
 */
router.get('/export', (req, res) => {
  const config = bountySystem.exportConfig();
  
  res.json({
    success: true,
    config,
    exportedAt: new Date().toISOString()
  });
});

/**
 * POST /api/bounty/import
 * استيراد الإعدادات
 */
router.post('/import', (req, res) => {
  const { config } = req.body;
  
  if (!config) {
    return res.status(400).json({ error: 'config is required' });
  }
  
  bountySystem.importConfig(config);
  
  res.json({
    success: true,
    message: 'Configuration imported',
    status: bountySystem.getStatus()
  });
});

/**
 * POST /api/bounty/reset
 * إعادة تعيين كل شيء
 */
router.post('/reset', async (req, res) => {
  bountySystem.reset();
  
  await auditLogger.log({
    eventType: 'BOUNTY_SYSTEM_RESET',
    actor: req.user?.id || 'anonymous',
    resource: 'bounty-system'
  });
  
  res.json({
    success: true,
    message: 'Bug Bounty system reset',
    status: bountySystem.getStatus()
  });
});

export default router;
