/**
 * Multi-Tenant Workspace Manager
 * Supports isolated workspaces for different organizations
 */

import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Tenant Status
 */
export const TENANT_STATUS = {
  ACTIVE: 'active',
  SUSPENDED: 'suspended',
  PENDING: 'pending',
  DELETED: 'deleted'
};

/**
 * Tenant Plans
 */
export const TENANT_PLANS = {
  FREE: {
    name: 'free',
    maxUsers: 3,
    maxScansPerMonth: 10,
    maxTargets: 5,
    maxScheduledScans: 1,
    features: ['basic_scan', 'report_html', 'report_json']
  },
  PRO: {
    name: 'pro',
    maxUsers: 20,
    maxScansPerMonth: 100,
    maxTargets: 50,
    maxScheduledScans: 10,
    features: ['basic_scan', 'deep_scan', 'report_html', 'report_json', 'report_pdf', 'api_access', 'slack_integration']
  },
  ENTERPRISE: {
    name: 'enterprise',
    maxUsers: -1, // unlimited
    maxScansPerMonth: -1,
    maxTargets: -1,
    maxScheduledScans: -1,
    features: ['all']
  }
};

/**
 * Tenant Model
 */
export class Tenant {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.name = data.name;
    this.slug = data.slug || this.generateSlug(data.name);
    this.domain = data.domain || null;
    this.plan = data.plan || 'free';
    this.status = data.status || TENANT_STATUS.ACTIVE;
    this.settings = data.settings || {};
    this.metadata = data.metadata || {};
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = data.updatedAt || new Date().toISOString();
    this.ownerId = data.ownerId;
    this.apiKey = data.apiKey || this.generateApiKey();
    
    // Usage tracking
    this.usage = data.usage || {
      scansThisMonth: 0,
      totalScans: 0,
      lastScanAt: null,
      storageUsed: 0
    };
  }

  generateSlug(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  generateApiKey() {
    return `vht_${crypto.randomBytes(32).toString('hex')}`;
  }

  getPlanLimits() {
    return TENANT_PLANS[this.plan.toUpperCase()] || TENANT_PLANS.FREE;
  }

  hasFeature(feature) {
    const plan = this.getPlanLimits();
    return plan.features.includes('all') || plan.features.includes(feature);
  }

  canCreateScan() {
    const plan = this.getPlanLimits();
    if (plan.maxScansPerMonth === -1) return true;
    return this.usage.scansThisMonth < plan.maxScansPerMonth;
  }

  incrementScanCount() {
    this.usage.scansThisMonth++;
    this.usage.totalScans++;
    this.usage.lastScanAt = new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      slug: this.slug,
      domain: this.domain,
      plan: this.plan,
      status: this.status,
      settings: this.settings,
      usage: this.usage,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }
}

/**
 * Tenant Manager
 */
export class TenantManager {
  constructor() {
    this.tenants = new Map();
    this.dataDir = path.join(__dirname, '../data/tenants');
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;
    
    try {
      await fs.mkdir(this.dataDir, { recursive: true });
      await this.loadTenants();
      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize TenantManager:', error);
    }
  }

  async loadTenants() {
    try {
      const files = await fs.readdir(this.dataDir);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(this.dataDir, file), 'utf-8');
          const data = JSON.parse(content);
          this.tenants.set(data.id, new Tenant(data));
        }
      }
    } catch (error) {
      // Directory might not exist yet
    }
  }

  async saveTenant(tenant) {
    const filePath = path.join(this.dataDir, `${tenant.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(tenant, null, 2));
  }

  /**
   * Create new tenant
   */
  async create(data) {
    await this.initialize();
    
    // Check if slug is unique
    for (const tenant of this.tenants.values()) {
      if (tenant.slug === this.generateSlug(data.name)) {
        throw new Error('Tenant with this name already exists');
      }
    }

    const tenant = new Tenant(data);
    this.tenants.set(tenant.id, tenant);
    await this.saveTenant(tenant);
    
    // Create tenant-specific directories
    await this.createTenantDirectories(tenant.id);
    
    return tenant;
  }

  generateSlug(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  async createTenantDirectories(tenantId) {
    const dirs = [
      path.join(__dirname, `../data/tenants/${tenantId}/scans`),
      path.join(__dirname, `../data/tenants/${tenantId}/reports`),
      path.join(__dirname, `../data/tenants/${tenantId}/credentials`),
      path.join(__dirname, `../data/tenants/${tenantId}/logs`)
    ];

    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  /**
   * Get tenant by ID
   */
  async get(id) {
    await this.initialize();
    return this.tenants.get(id);
  }

  /**
   * Get tenant by slug
   */
  async getBySlug(slug) {
    await this.initialize();
    for (const tenant of this.tenants.values()) {
      if (tenant.slug === slug) {
        return tenant;
      }
    }
    return null;
  }

  /**
   * Get tenant by API key
   */
  async getByApiKey(apiKey) {
    await this.initialize();
    for (const tenant of this.tenants.values()) {
      if (tenant.apiKey === apiKey) {
        return tenant;
      }
    }
    return null;
  }

  /**
   * Get tenant by domain
   */
  async getByDomain(domain) {
    await this.initialize();
    for (const tenant of this.tenants.values()) {
      if (tenant.domain === domain) {
        return tenant;
      }
    }
    return null;
  }

  /**
   * Update tenant
   */
  async update(id, data) {
    await this.initialize();
    const tenant = this.tenants.get(id);
    
    if (!tenant) {
      throw new Error('Tenant not found');
    }

    Object.assign(tenant, data, { updatedAt: new Date().toISOString() });
    await this.saveTenant(tenant);
    
    return tenant;
  }

  /**
   * Delete tenant (soft delete)
   */
  async delete(id) {
    await this.initialize();
    const tenant = this.tenants.get(id);
    
    if (!tenant) {
      throw new Error('Tenant not found');
    }

    tenant.status = TENANT_STATUS.DELETED;
    tenant.updatedAt = new Date().toISOString();
    await this.saveTenant(tenant);
    
    return tenant;
  }

  /**
   * List all tenants
   */
  async list(options = {}) {
    await this.initialize();
    
    let tenants = Array.from(this.tenants.values());
    
    // Filter by status
    if (options.status) {
      tenants = tenants.filter(t => t.status === options.status);
    }
    
    // Filter by plan
    if (options.plan) {
      tenants = tenants.filter(t => t.plan === options.plan);
    }
    
    // Pagination
    const page = options.page || 1;
    const limit = options.limit || 20;
    const start = (page - 1) * limit;
    
    return {
      tenants: tenants.slice(start, start + limit).map(t => t.toJSON()),
      total: tenants.length,
      page,
      limit,
      totalPages: Math.ceil(tenants.length / limit)
    };
  }

  /**
   * Reset monthly usage for all tenants
   */
  async resetMonthlyUsage() {
    await this.initialize();
    
    for (const tenant of this.tenants.values()) {
      tenant.usage.scansThisMonth = 0;
      await this.saveTenant(tenant);
    }
  }

  /**
   * Get tenant statistics
   */
  async getStats() {
    await this.initialize();
    
    const stats = {
      total: this.tenants.size,
      byStatus: {},
      byPlan: {},
      totalScans: 0,
      activeThisMonth: 0
    };

    for (const tenant of this.tenants.values()) {
      // By status
      stats.byStatus[tenant.status] = (stats.byStatus[tenant.status] || 0) + 1;
      
      // By plan
      stats.byPlan[tenant.plan] = (stats.byPlan[tenant.plan] || 0) + 1;
      
      // Total scans
      stats.totalScans += tenant.usage.totalScans;
      
      // Active this month
      if (tenant.usage.scansThisMonth > 0) {
        stats.activeThisMonth++;
      }
    }

    return stats;
  }
}

export const tenantManager = new TenantManager();

export default {
  TENANT_STATUS,
  TENANT_PLANS,
  Tenant,
  TenantManager,
  tenantManager
};
