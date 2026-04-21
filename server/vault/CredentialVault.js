/**
 * Credential Vault
 * Secure storage for authentication credentials used in scans
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

/**
 * Credential Types
 */
export const CREDENTIAL_TYPES = {
  BASIC_AUTH: 'basic_auth',
  BEARER_TOKEN: 'bearer_token',
  API_KEY: 'api_key',
  OAUTH2: 'oauth2',
  COOKIE: 'cookie',
  CUSTOM_HEADER: 'custom_header',
  FORM_AUTH: 'form_auth',
  NTLM: 'ntlm',
  CERTIFICATE: 'certificate'
};

/**
 * Encryption utilities
 */
class EncryptionService {
  constructor(masterKey) {
    // Derive key from master key
    this.key = crypto.scryptSync(masterKey || process.env.VAULT_MASTER_KEY || 'default-insecure-key', 'salt', 32);
    this.algorithm = 'aes-256-gcm';
  }

  /**
   * Encrypt data
   */
  encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    
    const stringData = typeof data === 'string' ? data : JSON.stringify(data);
    let encrypted = cipher.update(stringData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      data: encrypted,
      authTag: authTag.toString('hex')
    };
  }

  /**
   * Decrypt data
   */
  decrypt(encryptedData) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  }

  /**
   * Hash sensitive data for comparison
   */
  hash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

/**
 * Credential Entry
 */
export class Credential {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.name = data.name;
    this.type = data.type;
    this.description = data.description || '';
    this.tenantId = data.tenantId;
    this.createdBy = data.createdBy;
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = data.updatedAt || new Date().toISOString();
    this.lastUsed = data.lastUsed || null;
    this.usageCount = data.usageCount || 0;
    this.expiresAt = data.expiresAt || null;
    this.tags = data.tags || [];
    this.domains = data.domains || []; // Restrict to specific domains
    
    // Encrypted credential data
    this.encryptedData = data.encryptedData || null;
    
    // Metadata (not encrypted)
    this.metadata = data.metadata || {};
  }

  isExpired() {
    if (!this.expiresAt) return false;
    return new Date(this.expiresAt) < new Date();
  }

  isValidForDomain(domain) {
    if (this.domains.length === 0) return true;
    return this.domains.some(d => domain.includes(d) || d.includes(domain));
  }

  toJSON(includeSecret = false) {
    const obj = {
      id: this.id,
      name: this.name,
      type: this.type,
      description: this.description,
      tenantId: this.tenantId,
      createdBy: this.createdBy,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      lastUsed: this.lastUsed,
      usageCount: this.usageCount,
      expiresAt: this.expiresAt,
      tags: this.tags,
      domains: this.domains,
      metadata: this.metadata,
      isExpired: this.isExpired()
    };

    if (includeSecret) {
      obj.encryptedData = this.encryptedData;
    }

    return obj;
  }
}

/**
 * Credential Vault
 */
export class CredentialVault extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      storageDir: options.storageDir || './data/vault',
      masterKey: options.masterKey || process.env.VAULT_MASTER_KEY,
      autoRotateDays: options.autoRotateDays || 90,
      ...options
    };
    
    this.encryption = new EncryptionService(this.options.masterKey);
    this.credentials = new Map(); // tenantId -> Map<credId, Credential>
    this.accessLog = [];
    
    this.init();
  }

  /**
   * Initialize vault
   */
  async init() {
    await fs.mkdir(this.options.storageDir, { recursive: true });
    await this.loadCredentials();
  }

  /**
   * Load credentials from storage
   */
  async loadCredentials() {
    try {
      const files = await fs.readdir(this.options.storageDir);
      
      for (const file of files) {
        if (!file.endsWith('.vault')) continue;
        
        const filePath = path.join(this.options.storageDir, file);
        const content = await fs.readFile(filePath, 'utf8');
        const data = JSON.parse(content);
        
        const tenantId = file.replace('.vault', '');
        const tenantCredentials = new Map();
        
        for (const credData of data.credentials || []) {
          const credential = new Credential(credData);
          tenantCredentials.set(credential.id, credential);
        }
        
        this.credentials.set(tenantId, tenantCredentials);
      }
    } catch (error) {
      console.error('Failed to load credentials:', error);
    }
  }

  /**
   * Save credentials to storage
   */
  async saveCredentials(tenantId) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) return;
    
    const data = {
      tenantId,
      credentials: Array.from(tenantCredentials.values()).map(c => c.toJSON(true))
    };
    
    const filePath = path.join(this.options.storageDir, `${tenantId}.vault`);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
  }

  /**
   * Store credential
   */
  async store(tenantId, credentialData, secretData) {
    // Encrypt the secret data
    const encryptedData = this.encryption.encrypt(secretData);
    
    const credential = new Credential({
      ...credentialData,
      tenantId,
      encryptedData
    });
    
    // Get or create tenant credentials map
    if (!this.credentials.has(tenantId)) {
      this.credentials.set(tenantId, new Map());
    }
    
    this.credentials.get(tenantId).set(credential.id, credential);
    await this.saveCredentials(tenantId);
    
    this.emit('credential:stored', {
      id: credential.id,
      name: credential.name,
      type: credential.type,
      tenantId
    });
    
    return credential.toJSON();
  }

  /**
   * Retrieve credential (decrypted)
   */
  async retrieve(tenantId, credentialId, userId = null) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      throw new Error('Tenant not found');
    }
    
    const credential = tenantCredentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    
    if (credential.isExpired()) {
      throw new Error('Credential has expired');
    }
    
    // Decrypt the secret data
    const secretData = this.encryption.decrypt(credential.encryptedData);
    
    // Update usage stats
    credential.lastUsed = new Date().toISOString();
    credential.usageCount++;
    await this.saveCredentials(tenantId);
    
    // Log access
    this.logAccess(tenantId, credentialId, userId, 'retrieve');
    
    this.emit('credential:accessed', {
      id: credential.id,
      name: credential.name,
      tenantId,
      userId
    });
    
    return {
      ...credential.toJSON(),
      secret: secretData
    };
  }

  /**
   * Get credential for scan (formatted for use)
   */
  async getForScan(tenantId, credentialId, targetDomain) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      throw new Error('Tenant not found');
    }
    
    const credential = tenantCredentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    
    // Validate domain
    if (!credential.isValidForDomain(targetDomain)) {
      throw new Error('Credential not valid for this domain');
    }
    
    if (credential.isExpired()) {
      throw new Error('Credential has expired');
    }
    
    const secretData = this.encryption.decrypt(credential.encryptedData);
    
    // Format for scan use
    return this.formatForScan(credential.type, secretData);
  }

  /**
   * Format credential for scan use
   */
  formatForScan(type, secretData) {
    switch (type) {
      case CREDENTIAL_TYPES.BASIC_AUTH:
        const auth = Buffer.from(`${secretData.username}:${secretData.password}`).toString('base64');
        return {
          headers: {
            'Authorization': `Basic ${auth}`
          }
        };

      case CREDENTIAL_TYPES.BEARER_TOKEN:
        return {
          headers: {
            'Authorization': `Bearer ${secretData.token}`
          }
        };

      case CREDENTIAL_TYPES.API_KEY:
        const header = secretData.headerName || 'X-API-Key';
        return {
          headers: {
            [header]: secretData.apiKey
          }
        };

      case CREDENTIAL_TYPES.COOKIE:
        return {
          headers: {
            'Cookie': secretData.cookies
          }
        };

      case CREDENTIAL_TYPES.CUSTOM_HEADER:
        return {
          headers: secretData.headers
        };

      case CREDENTIAL_TYPES.FORM_AUTH:
        return {
          formAuth: {
            loginUrl: secretData.loginUrl,
            username: secretData.username,
            password: secretData.password,
            usernameField: secretData.usernameField || 'username',
            passwordField: secretData.passwordField || 'password',
            submitButton: secretData.submitButton
          }
        };

      case CREDENTIAL_TYPES.OAUTH2:
        return {
          oauth2: {
            clientId: secretData.clientId,
            clientSecret: secretData.clientSecret,
            tokenUrl: secretData.tokenUrl,
            scope: secretData.scope
          }
        };

      default:
        return { custom: secretData };
    }
  }

  /**
   * Update credential
   */
  async update(tenantId, credentialId, updates, newSecretData = null) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      throw new Error('Tenant not found');
    }
    
    const credential = tenantCredentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    
    // Update non-secret fields
    if (updates.name) credential.name = updates.name;
    if (updates.description !== undefined) credential.description = updates.description;
    if (updates.expiresAt !== undefined) credential.expiresAt = updates.expiresAt;
    if (updates.tags) credential.tags = updates.tags;
    if (updates.domains) credential.domains = updates.domains;
    if (updates.metadata) credential.metadata = { ...credential.metadata, ...updates.metadata };
    
    // Update secret if provided
    if (newSecretData) {
      credential.encryptedData = this.encryption.encrypt(newSecretData);
    }
    
    credential.updatedAt = new Date().toISOString();
    
    await this.saveCredentials(tenantId);
    
    this.emit('credential:updated', {
      id: credential.id,
      name: credential.name,
      tenantId
    });
    
    return credential.toJSON();
  }

  /**
   * Delete credential
   */
  async delete(tenantId, credentialId) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      throw new Error('Tenant not found');
    }
    
    const credential = tenantCredentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    
    tenantCredentials.delete(credentialId);
    await this.saveCredentials(tenantId);
    
    this.emit('credential:deleted', {
      id: credentialId,
      name: credential.name,
      tenantId
    });
    
    return true;
  }

  /**
   * List credentials for tenant
   */
  list(tenantId, filters = {}) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      return [];
    }
    
    let credentials = Array.from(tenantCredentials.values());
    
    // Apply filters
    if (filters.type) {
      credentials = credentials.filter(c => c.type === filters.type);
    }
    
    if (filters.tag) {
      credentials = credentials.filter(c => c.tags.includes(filters.tag));
    }
    
    if (filters.domain) {
      credentials = credentials.filter(c => c.isValidForDomain(filters.domain));
    }
    
    if (filters.includeExpired === false) {
      credentials = credentials.filter(c => !c.isExpired());
    }
    
    return credentials.map(c => c.toJSON());
  }

  /**
   * Get credential by ID
   */
  get(tenantId, credentialId) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      return null;
    }
    
    const credential = tenantCredentials.get(credentialId);
    return credential ? credential.toJSON() : null;
  }

  /**
   * Log credential access
   */
  logAccess(tenantId, credentialId, userId, action) {
    this.accessLog.push({
      timestamp: new Date().toISOString(),
      tenantId,
      credentialId,
      userId,
      action
    });
    
    // Keep only last 1000 entries
    if (this.accessLog.length > 1000) {
      this.accessLog.shift();
    }
  }

  /**
   * Get access log
   */
  getAccessLog(tenantId, credentialId = null) {
    return this.accessLog.filter(log => {
      if (log.tenantId !== tenantId) return false;
      if (credentialId && log.credentialId !== credentialId) return false;
      return true;
    });
  }

  /**
   * Rotate credential
   */
  async rotate(tenantId, credentialId, newSecretData) {
    const credential = this.get(tenantId, credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    
    await this.update(tenantId, credentialId, {
      metadata: {
        ...credential.metadata,
        lastRotated: new Date().toISOString(),
        rotationCount: (credential.metadata.rotationCount || 0) + 1
      }
    }, newSecretData);
    
    this.emit('credential:rotated', {
      id: credentialId,
      name: credential.name,
      tenantId
    });
    
    return this.get(tenantId, credentialId);
  }

  /**
   * Get credentials needing rotation
   */
  getExpiringSoon(tenantId, daysThreshold = 7) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      return [];
    }
    
    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);
    
    return Array.from(tenantCredentials.values())
      .filter(c => {
        if (!c.expiresAt) return false;
        const expiryDate = new Date(c.expiresAt);
        return expiryDate <= thresholdDate && expiryDate > new Date();
      })
      .map(c => c.toJSON());
  }

  /**
   * Import credentials
   */
  async import(tenantId, credentials, userId) {
    const results = [];
    
    for (const cred of credentials) {
      try {
        const stored = await this.store(tenantId, {
          name: cred.name,
          type: cred.type,
          description: cred.description,
          tags: cred.tags,
          domains: cred.domains,
          createdBy: userId
        }, cred.secret);
        
        results.push({ success: true, id: stored.id, name: stored.name });
      } catch (error) {
        results.push({ success: false, name: cred.name, error: error.message });
      }
    }
    
    return results;
  }

  /**
   * Export credentials (encrypted)
   */
  async export(tenantId, credentialIds = null) {
    const tenantCredentials = this.credentials.get(tenantId);
    if (!tenantCredentials) {
      return [];
    }
    
    let credentials = Array.from(tenantCredentials.values());
    
    if (credentialIds) {
      credentials = credentials.filter(c => credentialIds.includes(c.id));
    }
    
    return credentials.map(c => c.toJSON(true));
  }
}

export const credentialVault = new CredentialVault();

export default {
  CREDENTIAL_TYPES,
  Credential,
  CredentialVault,
  credentialVault
};
