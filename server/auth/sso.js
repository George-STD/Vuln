/**
 * SSO Provider - SAML & OIDC Support
 */

import crypto from 'crypto';
import { generateToken } from './index.js';

/**
 * SSO Configuration Store
 */
const ssoConfigs = new Map();

/**
 * SAML Configuration
 */
export class SAMLProvider {
  constructor(config) {
    this.config = {
      entityId: config.entityId,
      ssoLoginUrl: config.ssoLoginUrl,
      ssoLogoutUrl: config.ssoLogoutUrl,
      certificate: config.certificate,
      privateKey: config.privateKey,
      issuer: config.issuer || 'VulnHunter Pro',
      callbackUrl: config.callbackUrl,
      signatureAlgorithm: config.signatureAlgorithm || 'sha256',
      ...config
    };
  }

  /**
   * Generate SAML Request
   */
  generateAuthRequest() {
    const id = '_' + crypto.randomBytes(16).toString('hex');
    const issueInstant = new Date().toISOString();
    
    const samlRequest = `
      <samlp:AuthnRequest 
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${id}"
        Version="2.0"
        IssueInstant="${issueInstant}"
        Destination="${this.config.ssoLoginUrl}"
        AssertionConsumerServiceURL="${this.config.callbackUrl}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>${this.config.issuer}</saml:Issuer>
        <samlp:NameIDPolicy 
          Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          AllowCreate="true"/>
      </samlp:AuthnRequest>
    `;

    // Encode and deflate
    const encoded = Buffer.from(samlRequest).toString('base64');
    return {
      id,
      request: encoded,
      redirectUrl: `${this.config.ssoLoginUrl}?SAMLRequest=${encodeURIComponent(encoded)}`
    };
  }

  /**
   * Parse SAML Response
   */
  async parseResponse(samlResponse) {
    try {
      const decoded = Buffer.from(samlResponse, 'base64').toString('utf8');
      
      // Extract user info from SAML assertion
      // This is a simplified parser - use a proper SAML library in production
      const emailMatch = decoded.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
      const firstNameMatch = decoded.match(/<saml:Attribute Name="firstName"[^>]*>.*?<saml:AttributeValue[^>]*>([^<]+)/s);
      const lastNameMatch = decoded.match(/<saml:Attribute Name="lastName"[^>]*>.*?<saml:AttributeValue[^>]*>([^<]+)/s);
      const groupsMatch = decoded.match(/<saml:Attribute Name="groups"[^>]*>(.*?)<\/saml:Attribute>/s);

      if (!emailMatch) {
        throw new Error('Invalid SAML response - no email found');
      }

      return {
        email: emailMatch[1],
        firstName: firstNameMatch?.[1] || '',
        lastName: lastNameMatch?.[1] || '',
        groups: groupsMatch ? this.parseGroups(groupsMatch[1]) : [],
        rawAssertion: decoded
      };
    } catch (error) {
      throw new Error(`SAML parsing error: ${error.message}`);
    }
  }

  parseGroups(groupsXml) {
    const groups = [];
    const regex = /<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/g;
    let match;
    while ((match = regex.exec(groupsXml)) !== null) {
      groups.push(match[1]);
    }
    return groups;
  }

  /**
   * Generate Logout Request
   */
  generateLogoutRequest(sessionId, nameId) {
    const id = '_' + crypto.randomBytes(16).toString('hex');
    const issueInstant = new Date().toISOString();
    
    const logoutRequest = `
      <samlp:LogoutRequest 
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${id}"
        Version="2.0"
        IssueInstant="${issueInstant}"
        Destination="${this.config.ssoLogoutUrl}">
        <saml:Issuer>${this.config.issuer}</saml:Issuer>
        <saml:NameID>${nameId}</saml:NameID>
        <samlp:SessionIndex>${sessionId}</samlp:SessionIndex>
      </samlp:LogoutRequest>
    `;

    const encoded = Buffer.from(logoutRequest).toString('base64');
    return {
      id,
      request: encoded,
      redirectUrl: `${this.config.ssoLogoutUrl}?SAMLRequest=${encodeURIComponent(encoded)}`
    };
  }
}

/**
 * OIDC Configuration
 */
export class OIDCProvider {
  constructor(config) {
    this.config = {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      authorizationEndpoint: config.authorizationEndpoint,
      tokenEndpoint: config.tokenEndpoint,
      userInfoEndpoint: config.userInfoEndpoint,
      jwksUri: config.jwksUri,
      redirectUri: config.redirectUri,
      scopes: config.scopes || ['openid', 'profile', 'email'],
      issuer: config.issuer,
      ...config
    };
    
    this.states = new Map();
    this.nonces = new Map();
  }

  /**
   * Generate Authorization URL
   */
  generateAuthUrl() {
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    
    // Store state and nonce for validation
    this.states.set(state, { created: Date.now(), nonce });
    this.nonces.set(nonce, { created: Date.now(), state });
    
    // Clean old states/nonces (5 min expiry)
    this.cleanupOldEntries();
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      state,
      nonce
    });

    return {
      state,
      nonce,
      url: `${this.config.authorizationEndpoint}?${params.toString()}`
    };
  }

  /**
   * Exchange code for tokens
   */
  async exchangeCode(code, state) {
    // Validate state
    if (!this.states.has(state)) {
      throw new Error('Invalid state parameter');
    }
    this.states.delete(state);

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });

    try {
      const response = await fetch(this.config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params.toString()
      });

      if (!response.ok) {
        throw new Error(`Token exchange failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`OIDC token exchange error: ${error.message}`);
    }
  }

  /**
   * Get user info from access token
   */
  async getUserInfo(accessToken) {
    try {
      const response = await fetch(this.config.userInfoEndpoint, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });

      if (!response.ok) {
        throw new Error(`User info request failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`OIDC user info error: ${error.message}`);
    }
  }

  /**
   * Cleanup old states and nonces
   */
  cleanupOldEntries() {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    
    for (const [key, value] of this.states.entries()) {
      if (value.created < fiveMinutesAgo) {
        this.states.delete(key);
      }
    }
    
    for (const [key, value] of this.nonces.entries()) {
      if (value.created < fiveMinutesAgo) {
        this.nonces.delete(key);
      }
    }
  }
}

/**
 * SSO Manager
 */
export class SSOManager {
  constructor() {
    this.providers = new Map();
  }

  /**
   * Register SSO provider for tenant
   */
  registerProvider(tenantId, type, config) {
    const key = `${tenantId}:${type}`;
    
    let provider;
    if (type === 'saml') {
      provider = new SAMLProvider(config);
    } else if (type === 'oidc') {
      provider = new OIDCProvider(config);
    } else {
      throw new Error(`Unsupported SSO type: ${type}`);
    }
    
    this.providers.set(key, {
      type,
      provider,
      config,
      enabled: config.enabled !== false
    });
    
    return provider;
  }

  /**
   * Get provider for tenant
   */
  getProvider(tenantId, type) {
    const key = `${tenantId}:${type}`;
    return this.providers.get(key);
  }

  /**
   * Remove provider
   */
  removeProvider(tenantId, type) {
    const key = `${tenantId}:${type}`;
    return this.providers.delete(key);
  }

  /**
   * List providers for tenant
   */
  listProviders(tenantId) {
    const result = [];
    for (const [key, value] of this.providers.entries()) {
      if (key.startsWith(`${tenantId}:`)) {
        result.push({
          type: value.type,
          enabled: value.enabled,
          config: {
            ...value.config,
            clientSecret: '[REDACTED]',
            privateKey: '[REDACTED]'
          }
        });
      }
    }
    return result;
  }

  /**
   * Handle SSO callback and create/update user
   */
  async handleCallback(tenantId, type, data, userService) {
    const providerData = this.getProvider(tenantId, type);
    if (!providerData || !providerData.enabled) {
      throw new Error('SSO provider not found or disabled');
    }

    let userInfo;
    
    if (type === 'saml') {
      userInfo = await providerData.provider.parseResponse(data.SAMLResponse);
    } else if (type === 'oidc') {
      const tokens = await providerData.provider.exchangeCode(data.code, data.state);
      userInfo = await providerData.provider.getUserInfo(tokens.access_token);
    }

    // Find or create user
    let user = await userService.findByEmail(userInfo.email, tenantId);
    
    if (!user) {
      // Auto-provision user
      user = await userService.create({
        email: userInfo.email,
        firstName: userInfo.firstName || userInfo.given_name,
        lastName: userInfo.lastName || userInfo.family_name,
        tenantId,
        role: providerData.config.defaultRole || 'viewer',
        ssoProvider: type,
        ssoId: userInfo.sub || userInfo.email
      });
    }

    // Generate JWT token
    const token = generateToken(user);

    return {
      user,
      token
    };
  }
}

export const ssoManager = new SSOManager();

export default {
  SAMLProvider,
  OIDCProvider,
  SSOManager,
  ssoManager
};
