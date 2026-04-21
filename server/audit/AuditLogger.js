/**
 * Audit Logger
 * Comprehensive logging of all user actions and system events
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';

/**
 * Audit Event Types
 */
export const AUDIT_EVENTS = {
  // Authentication
  AUTH_LOGIN: 'auth.login',
  AUTH_LOGOUT: 'auth.logout',
  AUTH_LOGIN_FAILED: 'auth.login_failed',
  AUTH_PASSWORD_CHANGE: 'auth.password_change',
  AUTH_MFA_ENABLED: 'auth.mfa_enabled',
  AUTH_MFA_DISABLED: 'auth.mfa_disabled',
  AUTH_SSO_LOGIN: 'auth.sso_login',
  AUTH_API_KEY_CREATED: 'auth.api_key_created',
  AUTH_API_KEY_REVOKED: 'auth.api_key_revoked',
  
  // User Management
  USER_CREATED: 'user.created',
  USER_UPDATED: 'user.updated',
  USER_DELETED: 'user.deleted',
  USER_ROLE_CHANGED: 'user.role_changed',
  USER_SUSPENDED: 'user.suspended',
  USER_ACTIVATED: 'user.activated',
  USER_INVITED: 'user.invited',
  
  // Tenant Management
  TENANT_CREATED: 'tenant.created',
  TENANT_UPDATED: 'tenant.updated',
  TENANT_DELETED: 'tenant.deleted',
  TENANT_PLAN_CHANGED: 'tenant.plan_changed',
  TENANT_SETTINGS_UPDATED: 'tenant.settings_updated',
  
  // Scan Operations
  SCAN_STARTED: 'scan.started',
  SCAN_COMPLETED: 'scan.completed',
  SCAN_FAILED: 'scan.failed',
  SCAN_CANCELLED: 'scan.cancelled',
  SCAN_PAUSED: 'scan.paused',
  SCAN_RESUMED: 'scan.resumed',
  SCAN_SCHEDULED: 'scan.scheduled',
  SCAN_SCHEDULE_DELETED: 'scan.schedule_deleted',
  
  // Vulnerability Management
  VULN_FOUND: 'vulnerability.found',
  VULN_STATUS_CHANGED: 'vulnerability.status_changed',
  VULN_ASSIGNED: 'vulnerability.assigned',
  VULN_RESOLVED: 'vulnerability.resolved',
  VULN_FALSE_POSITIVE: 'vulnerability.false_positive',
  VULN_EXPORTED: 'vulnerability.exported',
  
  // Report Operations
  REPORT_GENERATED: 'report.generated',
  REPORT_DOWNLOADED: 'report.downloaded',
  REPORT_SHARED: 'report.shared',
  REPORT_DELETED: 'report.deleted',
  
  // Integration Events
  INTEGRATION_CONFIGURED: 'integration.configured',
  INTEGRATION_REMOVED: 'integration.removed',
  INTEGRATION_SYNCED: 'integration.synced',
  INTEGRATION_ERROR: 'integration.error',
  
  // Target Management
  TARGET_ADDED: 'target.added',
  TARGET_REMOVED: 'target.removed',
  TARGET_VERIFIED: 'target.verified',
  TARGET_VERIFICATION_FAILED: 'target.verification_failed',
  
  // Credential Vault
  CREDENTIAL_CREATED: 'credential.created',
  CREDENTIAL_UPDATED: 'credential.updated',
  CREDENTIAL_DELETED: 'credential.deleted',
  CREDENTIAL_ACCESSED: 'credential.accessed',
  
  // System Events
  SYSTEM_STARTUP: 'system.startup',
  SYSTEM_SHUTDOWN: 'system.shutdown',
  SYSTEM_ERROR: 'system.error',
  SYSTEM_MAINTENANCE: 'system.maintenance',
  WORKER_REGISTERED: 'worker.registered',
  WORKER_UNREGISTERED: 'worker.unregistered',
  
  // Settings
  SETTINGS_UPDATED: 'settings.updated',
  PLUGIN_INSTALLED: 'plugin.installed',
  PLUGIN_UNINSTALLED: 'plugin.uninstalled',
  PLUGIN_ENABLED: 'plugin.enabled',
  PLUGIN_DISABLED: 'plugin.disabled',
  
  // Data Access
  DATA_EXPORT: 'data.export',
  DATA_IMPORT: 'data.import',
  DATA_DELETED: 'data.deleted'
};

/**
 * Audit Severity Levels
 */
export const AUDIT_SEVERITY = {
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
  CRITICAL: 'critical'
};

/**
 * Audit Log Entry
 */
export class AuditEntry {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.timestamp = data.timestamp || new Date().toISOString();
    this.event = data.event;
    this.severity = data.severity || AUDIT_SEVERITY.INFO;
    this.tenantId = data.tenantId || null;
    this.userId = data.userId || null;
    this.userName = data.userName || null;
    this.userEmail = data.userEmail || null;
    this.ipAddress = data.ipAddress || null;
    this.userAgent = data.userAgent || null;
    this.resource = data.resource || null;
    this.resourceId = data.resourceId || null;
    this.action = data.action || null;
    this.status = data.status || 'success';
    this.details = data.details || {};
    this.metadata = data.metadata || {};
    
    // Sensitive data masking
    this.sensitiveFields = data.sensitiveFields || [];
  }

  toJSON() {
    const entry = {
      id: this.id,
      timestamp: this.timestamp,
      event: this.event,
      severity: this.severity,
      tenantId: this.tenantId,
      userId: this.userId,
      userName: this.userName,
      userEmail: this.userEmail,
      ipAddress: this.ipAddress,
      resource: this.resource,
      resourceId: this.resourceId,
      action: this.action,
      status: this.status,
      details: this.details
    };

    // Mask sensitive fields
    if (this.sensitiveFields.length > 0) {
      for (const field of this.sensitiveFields) {
        if (entry.details && entry.details[field]) {
          entry.details[field] = '***REDACTED***';
        }
      }
    }

    return entry;
  }

  toString() {
    return `[${this.timestamp}] [${this.severity.toUpperCase()}] ${this.event} - ${this.action || 'N/A'} by ${this.userName || this.userId || 'System'}`;
  }
}

/**
 * Audit Logger
 */
export class AuditLogger extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      storageDir: options.storageDir || './logs/audit',
      retentionDays: options.retentionDays || 365,
      maxEntriesPerFile: options.maxEntriesPerFile || 10000,
      enableConsole: options.enableConsole !== false,
      enableFile: options.enableFile !== false,
      enableDatabase: options.enableDatabase || false,
      ...options
    };
    
    this.currentFile = null;
    this.currentFileEntries = 0;
    this.buffer = [];
    this.bufferSize = 100;
    this.flushInterval = null;
    
    this.init();
  }

  /**
   * Initialize audit logger
   */
  async init() {
    if (this.options.enableFile) {
      await fs.mkdir(this.options.storageDir, { recursive: true });
      await this.rotateFile();
      
      // Flush buffer periodically
      this.flushInterval = setInterval(() => {
        this.flushBuffer();
      }, 5000);
    }
  }

  /**
   * Log audit event
   */
  async log(eventOrData, data = {}) {
    let entry;
    
    if (typeof eventOrData === 'string') {
      entry = new AuditEntry({
        event: eventOrData,
        ...data
      });
    } else {
      entry = new AuditEntry(eventOrData);
    }
    
    // Console output
    if (this.options.enableConsole) {
      this.logToConsole(entry);
    }
    
    // File output
    if (this.options.enableFile) {
      this.buffer.push(entry);
      
      if (this.buffer.length >= this.bufferSize) {
        await this.flushBuffer();
      }
    }
    
    // Emit event for external handlers
    this.emit('audit', entry);
    this.emit(`audit:${entry.event}`, entry);
    
    return entry;
  }

  /**
   * Log to console
   */
  logToConsole(entry) {
    const colors = {
      info: '\x1b[36m',
      warning: '\x1b[33m',
      error: '\x1b[31m',
      critical: '\x1b[35m'
    };
    
    const reset = '\x1b[0m';
    const color = colors[entry.severity] || colors.info;
    
    console.log(`${color}[AUDIT]${reset} ${entry.toString()}`);
  }

  /**
   * Flush buffer to file
   */
  async flushBuffer() {
    if (this.buffer.length === 0) return;
    
    const entries = [...this.buffer];
    this.buffer = [];
    
    try {
      const lines = entries.map(e => JSON.stringify(e.toJSON())).join('\n') + '\n';
      await fs.appendFile(this.currentFile, lines);
      this.currentFileEntries += entries.length;
      
      // Rotate if needed
      if (this.currentFileEntries >= this.options.maxEntriesPerFile) {
        await this.rotateFile();
      }
    } catch (error) {
      console.error('Failed to write audit log:', error);
      // Re-add entries to buffer
      this.buffer.unshift(...entries);
    }
  }

  /**
   * Rotate log file
   */
  async rotateFile() {
    const date = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `audit-${date}.jsonl`;
    this.currentFile = path.join(this.options.storageDir, filename);
    this.currentFileEntries = 0;
    
    // Create new file
    await fs.writeFile(this.currentFile, '');
    
    // Clean up old files
    await this.cleanupOldFiles();
  }

  /**
   * Clean up old audit files
   */
  async cleanupOldFiles() {
    try {
      const files = await fs.readdir(this.options.storageDir);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.options.retentionDays);
      
      for (const file of files) {
        if (!file.startsWith('audit-')) continue;
        
        const filePath = path.join(this.options.storageDir, file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
        }
      }
    } catch (error) {
      console.error('Failed to cleanup old audit files:', error);
    }
  }

  /**
   * Helper: Log authentication event
   */
  async logAuth(event, user, request = {}, details = {}) {
    return this.log({
      event,
      severity: event.includes('failed') ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
      userId: user?.id,
      userName: user?.name,
      userEmail: user?.email,
      tenantId: user?.tenantId,
      ipAddress: request.ip || request.connection?.remoteAddress,
      userAgent: request.headers?.['user-agent'],
      action: 'authenticate',
      resource: 'auth',
      details
    });
  }

  /**
   * Helper: Log user action
   */
  async logUserAction(event, user, action, resource, resourceId, details = {}, request = {}) {
    return this.log({
      event,
      userId: user?.id,
      userName: user?.name,
      userEmail: user?.email,
      tenantId: user?.tenantId,
      ipAddress: request.ip || request.connection?.remoteAddress,
      userAgent: request.headers?.['user-agent'],
      action,
      resource,
      resourceId,
      details
    });
  }

  /**
   * Helper: Log scan event
   */
  async logScan(event, scanId, user, details = {}) {
    return this.log({
      event,
      userId: user?.id,
      userName: user?.name,
      tenantId: user?.tenantId,
      action: event.split('.')[1],
      resource: 'scan',
      resourceId: scanId,
      details
    });
  }

  /**
   * Helper: Log security event
   */
  async logSecurity(event, severity, details = {}, request = {}) {
    return this.log({
      event,
      severity,
      ipAddress: request.ip || request.connection?.remoteAddress,
      userAgent: request.headers?.['user-agent'],
      resource: 'security',
      details
    });
  }

  /**
   * Helper: Log system event
   */
  async logSystem(event, details = {}) {
    return this.log({
      event,
      severity: event.includes('error') ? AUDIT_SEVERITY.ERROR : AUDIT_SEVERITY.INFO,
      resource: 'system',
      details
    });
  }

  /**
   * Query audit logs
   */
  async query(filters = {}) {
    const results = [];
    
    try {
      const files = await fs.readdir(this.options.storageDir);
      const auditFiles = files.filter(f => f.startsWith('audit-')).sort().reverse();
      
      // Apply date filter
      let filesToRead = auditFiles;
      if (filters.startDate || filters.endDate) {
        filesToRead = auditFiles.filter(file => {
          const dateMatch = file.match(/audit-(\d{4}-\d{2}-\d{2})/);
          if (!dateMatch) return false;
          
          const fileDate = new Date(dateMatch[1]);
          if (filters.startDate && fileDate < new Date(filters.startDate)) return false;
          if (filters.endDate && fileDate > new Date(filters.endDate)) return false;
          return true;
        });
      }
      
      // Read and filter entries
      const limit = filters.limit || 1000;
      
      for (const file of filesToRead) {
        if (results.length >= limit) break;
        
        const content = await fs.readFile(path.join(this.options.storageDir, file), 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        
        for (const line of lines.reverse()) {
          if (results.length >= limit) break;
          
          try {
            const entry = JSON.parse(line);
            
            // Apply filters
            if (filters.event && entry.event !== filters.event) continue;
            if (filters.tenantId && entry.tenantId !== filters.tenantId) continue;
            if (filters.userId && entry.userId !== filters.userId) continue;
            if (filters.severity && entry.severity !== filters.severity) continue;
            if (filters.resource && entry.resource !== filters.resource) continue;
            if (filters.status && entry.status !== filters.status) continue;
            
            results.push(entry);
          } catch (e) {
            // Skip invalid lines
          }
        }
      }
    } catch (error) {
      console.error('Failed to query audit logs:', error);
    }
    
    return results;
  }

  /**
   * Get audit statistics
   */
  async getStats(tenantId = null, period = '24h') {
    const now = new Date();
    let startDate;
    
    switch (period) {
      case '1h':
        startDate = new Date(now - 60 * 60 * 1000);
        break;
      case '24h':
        startDate = new Date(now - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now - 24 * 60 * 60 * 1000);
    }
    
    const entries = await this.query({
      tenantId,
      startDate: startDate.toISOString(),
      limit: 10000
    });
    
    const stats = {
      total: entries.length,
      byEvent: {},
      bySeverity: {},
      byUser: {},
      byHour: {},
      recentAlerts: []
    };
    
    for (const entry of entries) {
      // By event
      stats.byEvent[entry.event] = (stats.byEvent[entry.event] || 0) + 1;
      
      // By severity
      stats.bySeverity[entry.severity] = (stats.bySeverity[entry.severity] || 0) + 1;
      
      // By user
      if (entry.userId) {
        stats.byUser[entry.userId] = (stats.byUser[entry.userId] || 0) + 1;
      }
      
      // By hour
      const hour = entry.timestamp.substring(0, 13);
      stats.byHour[hour] = (stats.byHour[hour] || 0) + 1;
      
      // Recent alerts (warning, error, critical)
      if (['warning', 'error', 'critical'].includes(entry.severity)) {
        if (stats.recentAlerts.length < 10) {
          stats.recentAlerts.push(entry);
        }
      }
    }
    
    return stats;
  }

  /**
   * Export audit logs
   */
  async export(filters = {}, format = 'json') {
    const entries = await this.query(filters);
    
    switch (format) {
      case 'csv':
        return this.toCSV(entries);
      case 'json':
      default:
        return JSON.stringify(entries, null, 2);
    }
  }

  /**
   * Convert entries to CSV
   */
  toCSV(entries) {
    if (entries.length === 0) return '';
    
    const headers = ['timestamp', 'event', 'severity', 'userId', 'userName', 'action', 'resource', 'resourceId', 'status'];
    const rows = entries.map(e => 
      headers.map(h => `"${(e[h] || '').toString().replace(/"/g, '""')}"`).join(',')
    );
    
    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Shutdown
   */
  async shutdown() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    
    await this.flushBuffer();
  }
}

export const auditLogger = new AuditLogger();

export default {
  AUDIT_EVENTS,
  AUDIT_SEVERITY,
  AuditEntry,
  AuditLogger,
  auditLogger
};
