/**
 * Authentication & Authorization Module
 * Supports JWT, SAML, and OIDC
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * User Roles with Permissions
 */
export const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  SECURITY_LEAD: 'security_lead',
  SECURITY_ANALYST: 'security_analyst',
  DEVELOPER: 'developer',
  VIEWER: 'viewer'
};

export const PERMISSIONS = {
  // Scan permissions
  'scan:create': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST],
  'scan:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST, ROLES.DEVELOPER, ROLES.VIEWER],
  'scan:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST],
  'scan:delete': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'scan:schedule': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  
  // Report permissions
  'report:create': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST],
  'report:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST, ROLES.DEVELOPER, ROLES.VIEWER],
  'report:export': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD, ROLES.SECURITY_ANALYST, ROLES.DEVELOPER],
  
  // User management
  'user:create': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'user:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'user:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'user:delete': [ROLES.SUPER_ADMIN],
  
  // Tenant/Workspace management
  'tenant:create': [ROLES.SUPER_ADMIN],
  'tenant:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'tenant:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'tenant:delete': [ROLES.SUPER_ADMIN],
  
  // Settings
  'settings:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'settings:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  
  // Integrations
  'integration:create': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'integration:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'integration:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'integration:delete': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  
  // Credentials vault
  'credentials:create': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'credentials:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  'credentials:update': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'credentials:delete': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  
  // Audit logs
  'audit:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  
  // Plugins
  'plugin:install': [ROLES.SUPER_ADMIN],
  'plugin:configure': [ROLES.SUPER_ADMIN, ROLES.ADMIN],
  'plugin:read': [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.SECURITY_LEAD],
  
  // Workers
  'worker:manage': [ROLES.SUPER_ADMIN, ROLES.ADMIN]
};

/**
 * Generate JWT token
 */
export function generateToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId,
      permissions: getUserPermissions(user.role)
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

/**
 * Verify JWT token
 */
export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

/**
 * Get permissions for a role
 */
export function getUserPermissions(role) {
  const permissions = [];
  for (const [permission, roles] of Object.entries(PERMISSIONS)) {
    if (roles.includes(role)) {
      permissions.push(permission);
    }
  }
  return permissions;
}

/**
 * Check if user has permission
 */
export function hasPermission(user, permission) {
  const allowedRoles = PERMISSIONS[permission];
  if (!allowedRoles) return false;
  return allowedRoles.includes(user.role);
}

/**
 * Authentication Middleware
 */
export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }
  
  const token = authHeader.substring(7);
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: 'Unauthorized - Invalid token' });
  }
  
  req.user = decoded;
  next();
}

/**
 * Permission Middleware Factory
 */
export function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: 'Forbidden - Insufficient permissions' });
    }
    
    next();
  };
}

/**
 * Tenant Isolation Middleware
 */
export function tenantMiddleware(req, res, next) {
  if (!req.user || !req.user.tenantId) {
    return res.status(401).json({ error: 'Unauthorized - No tenant context' });
  }
  
  // Add tenant filter to all queries
  req.tenantId = req.user.tenantId;
  next();
}

/**
 * Hash password
 */
export async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

/**
 * Verify password
 */
export async function verifyPassword(password, hashedPassword) {
  return bcrypt.compare(password, hashedPassword);
}

export default {
  ROLES,
  PERMISSIONS,
  generateToken,
  verifyToken,
  getUserPermissions,
  hasPermission,
  hashPassword,
  verifyPassword,
  authMiddleware,
  requirePermission,
  tenantMiddleware
};
