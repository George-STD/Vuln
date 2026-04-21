/**
 * Enterprise API Routes
 * Routes for multi-tenant, RBAC, integrations, and other enterprise features
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';

// Auth & RBAC
import { 
  authMiddleware, 
  requirePermission, 
  tenantMiddleware,
  PERMISSIONS,
  generateToken,
  hashPassword,
  verifyPassword
} from '../auth/index.js';
import { ssoManager } from '../auth/sso.js';

// Tenants
import { tenantManager } from '../tenants/TenantManager.js';

// Workers
import { workerManager } from '../workers/WorkerManager.js';

// Integrations
import { 
  integrationManager, 
  INTEGRATION_TYPES 
} from '../integrations/index.js';

// Audit
import { auditLogger, AUDIT_EVENTS } from '../audit/AuditLogger.js';

// Vault
import { credentialVault, CREDENTIAL_TYPES } from '../vault/CredentialVault.js';

// Plugins
import { pluginManager, PLUGIN_TYPES } from '../plugins/PluginSystem.js';

const router = express.Router();

// ==================== Authentication Routes ====================

/**
 * Login
 */
router.post('/auth/login', async (req, res) => {
  try {
    const { email, password, tenantId } = req.body;
    
    // In production, validate against database
    // This is a simplified example
    if (!email || !password) {
      await auditLogger.logAuth(AUDIT_EVENTS.AUTH_LOGIN_FAILED, { email }, req, { reason: 'Missing credentials' });
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Mock user - replace with database lookup
    const user = {
      id: uuidv4(),
      email,
      name: email.split('@')[0],
      role: 'security_analyst',
      tenantId: tenantId || 'default',
      permissions: ['scan:create', 'scan:read', 'report:read']
    };
    
    const token = generateToken(user);
    
    await auditLogger.logAuth(AUDIT_EVENTS.AUTH_LOGIN, user, req);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * SSO Initiate
 */
router.get('/auth/sso/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { tenantId } = req.query;
    
    const authUrl = await ssoManager.initiateLogin(tenantId, provider);
    res.redirect(authUrl);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * SSO Callback
 */
router.post('/auth/sso/:provider/callback', async (req, res) => {
  try {
    const { provider } = req.params;
    const { tenantId, code, SAMLResponse } = req.body;
    
    const user = await ssoManager.handleCallback(tenantId, provider, req.body);
    const token = generateToken(user);
    
    await auditLogger.logAuth(AUDIT_EVENTS.AUTH_SSO_LOGIN, user, req, { provider });
    
    res.json({ success: true, token, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== Tenant Routes ====================

/**
 * Create tenant
 */
router.post('/tenants', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const tenant = tenantManager.createTenant(req.body);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.TENANT_CREATED,
      req.user,
      'create',
      'tenant',
      tenant.id,
      { name: tenant.name },
      req
    );
    
    res.json({ success: true, tenant });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * List tenants
 */
router.get('/tenants', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const tenants = tenantManager.listTenants(req.query);
    res.json({ success: true, tenants });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get tenant
 */
router.get('/tenants/:id', authMiddleware, tenantMiddleware, async (req, res) => {
  try {
    const tenant = tenantManager.getTenant(req.params.id);
    if (!tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    res.json({ success: true, tenant: tenant.toJSON() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Update tenant
 */
router.put('/tenants/:id', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const tenant = tenantManager.updateTenant(req.params.id, req.body);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.TENANT_UPDATED,
      req.user,
      'update',
      'tenant',
      req.params.id,
      req.body,
      req
    );
    
    res.json({ success: true, tenant });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== Worker Routes ====================

/**
 * List workers
 */
router.get('/workers', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const workers = workerManager.listWorkers();
    const queueStatus = workerManager.getQueueStatus();
    res.json({ success: true, workers, queueStatus });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Register worker
 */
router.post('/workers', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const worker = workerManager.registerWorker(req.body);
    
    await auditLogger.logSystem(AUDIT_EVENTS.WORKER_REGISTERED, { 
      workerId: worker.id,
      host: worker.host 
    });
    
    res.json({ success: true, worker: worker.toJSON() });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Worker heartbeat
 */
router.post('/workers/:id/heartbeat', async (req, res) => {
  try {
    const success = workerManager.heartbeat(req.params.id, req.body);
    res.json({ success });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Unregister worker
 */
router.delete('/workers/:id', authMiddleware, requirePermission(PERMISSIONS.ADMIN_ALL), async (req, res) => {
  try {
    const success = workerManager.unregisterWorker(req.params.id);
    
    if (success) {
      await auditLogger.logSystem(AUDIT_EVENTS.WORKER_UNREGISTERED, { 
        workerId: req.params.id 
      });
    }
    
    res.json({ success });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== Integration Routes ====================

/**
 * List configured integrations
 */
router.get('/integrations', authMiddleware, tenantMiddleware, async (req, res) => {
  try {
    const configured = integrationManager.getConfiguredIntegrations(req.tenantId);
    res.json({ 
      success: true, 
      configured,
      available: Object.values(INTEGRATION_TYPES)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Configure integration
 */
router.post('/integrations/:type', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.INTEGRATION_WRITE), async (req, res) => {
  try {
    await integrationManager.configure(req.tenantId, req.params.type, req.body);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.INTEGRATION_CONFIGURED,
      req.user,
      'configure',
      'integration',
      req.params.type,
      { type: req.params.type },
      req
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Test integration
 */
router.post('/integrations/:type/test', authMiddleware, tenantMiddleware, async (req, res) => {
  try {
    const result = await integrationManager.testConnection(req.tenantId, req.params.type);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Remove integration
 */
router.delete('/integrations/:type', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.INTEGRATION_WRITE), async (req, res) => {
  try {
    integrationManager.removeIntegration(req.tenantId, req.params.type);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.INTEGRATION_REMOVED,
      req.user,
      'remove',
      'integration',
      req.params.type,
      {},
      req
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== Audit Log Routes ====================

/**
 * Query audit logs
 */
router.get('/audit', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  try {
    const logs = await auditLogger.query({
      tenantId: req.tenantId,
      ...req.query
    });
    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get audit statistics
 */
router.get('/audit/stats', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.AUDIT_READ), async (req, res) => {
  try {
    const stats = await auditLogger.getStats(req.tenantId, req.query.period);
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Export audit logs
 */
router.get('/audit/export', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.AUDIT_EXPORT), async (req, res) => {
  try {
    const format = req.query.format || 'json';
    const data = await auditLogger.export({
      tenantId: req.tenantId,
      ...req.query
    }, format);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.DATA_EXPORT,
      req.user,
      'export',
      'audit',
      null,
      { format },
      req
    );
    
    const contentType = format === 'csv' ? 'text/csv' : 'application/json';
    const ext = format === 'csv' ? 'csv' : 'json';
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename=audit-log.${ext}`);
    res.send(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Credential Vault Routes ====================

/**
 * List credentials
 */
router.get('/vault/credentials', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_READ), async (req, res) => {
  try {
    const credentials = credentialVault.list(req.tenantId, req.query);
    res.json({ 
      success: true, 
      credentials,
      types: Object.values(CREDENTIAL_TYPES)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Store credential
 */
router.post('/vault/credentials', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_WRITE), async (req, res) => {
  try {
    const { secret, ...metadata } = req.body;
    
    const credential = await credentialVault.store(
      req.tenantId,
      { ...metadata, createdBy: req.user.id },
      secret
    );
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.CREDENTIAL_CREATED,
      req.user,
      'create',
      'credential',
      credential.id,
      { name: credential.name, type: credential.type },
      req
    );
    
    res.json({ success: true, credential });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Get credential (without secret)
 */
router.get('/vault/credentials/:id', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_READ), async (req, res) => {
  try {
    const credential = credentialVault.get(req.tenantId, req.params.id);
    if (!credential) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    res.json({ success: true, credential });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Update credential
 */
router.put('/vault/credentials/:id', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_WRITE), async (req, res) => {
  try {
    const { secret, ...updates } = req.body;
    
    const credential = await credentialVault.update(
      req.tenantId,
      req.params.id,
      updates,
      secret || null
    );
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.CREDENTIAL_UPDATED,
      req.user,
      'update',
      'credential',
      req.params.id,
      { name: credential.name },
      req
    );
    
    res.json({ success: true, credential });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Delete credential
 */
router.delete('/vault/credentials/:id', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_DELETE), async (req, res) => {
  try {
    await credentialVault.delete(req.tenantId, req.params.id);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.CREDENTIAL_DELETED,
      req.user,
      'delete',
      'credential',
      req.params.id,
      {},
      req
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Get expiring credentials
 */
router.get('/vault/expiring', authMiddleware, tenantMiddleware, requirePermission(PERMISSIONS.CREDENTIAL_READ), async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const credentials = credentialVault.getExpiringSoon(req.tenantId, days);
    res.json({ success: true, credentials });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Plugin Routes ====================

/**
 * List plugins
 */
router.get('/plugins', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_READ), async (req, res) => {
  try {
    const plugins = pluginManager.listPlugins(req.query);
    res.json({ 
      success: true, 
      plugins,
      types: Object.values(PLUGIN_TYPES)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get plugin
 */
router.get('/plugins/:id', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_READ), async (req, res) => {
  try {
    const plugin = pluginManager.getPlugin(req.params.id);
    if (!plugin) {
      return res.status(404).json({ error: 'Plugin not found' });
    }
    res.json({ success: true, plugin });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Install plugin from code
 */
router.post('/plugins', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_INSTALL), async (req, res) => {
  try {
    const { manifest, code } = req.body;
    const plugin = await pluginManager.installFromCode(manifest, code);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.PLUGIN_INSTALLED,
      req.user,
      'install',
      'plugin',
      plugin.id,
      { name: plugin.name },
      req
    );
    
    res.json({ success: true, plugin });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Enable plugin
 */
router.post('/plugins/:id/enable', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_MANAGE), async (req, res) => {
  try {
    const plugin = await pluginManager.enablePlugin(req.params.id);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.PLUGIN_ENABLED,
      req.user,
      'enable',
      'plugin',
      req.params.id,
      { name: plugin.name },
      req
    );
    
    res.json({ success: true, plugin });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Disable plugin
 */
router.post('/plugins/:id/disable', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_MANAGE), async (req, res) => {
  try {
    const plugin = await pluginManager.disablePlugin(req.params.id);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.PLUGIN_DISABLED,
      req.user,
      'disable',
      'plugin',
      req.params.id,
      { name: plugin.name },
      req
    );
    
    res.json({ success: true, plugin });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Update plugin config
 */
router.put('/plugins/:id/config', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_MANAGE), async (req, res) => {
  try {
    const plugin = await pluginManager.updateConfig(req.params.id, req.body);
    res.json({ success: true, plugin });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Uninstall plugin
 */
router.delete('/plugins/:id', authMiddleware, requirePermission(PERMISSIONS.PLUGIN_INSTALL), async (req, res) => {
  try {
    await pluginManager.uninstallPlugin(req.params.id);
    
    await auditLogger.logUserAction(
      AUDIT_EVENTS.PLUGIN_UNINSTALLED,
      req.user,
      'uninstall',
      'plugin',
      req.params.id,
      {},
      req
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

export default router;
