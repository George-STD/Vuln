/**
 * Integrations Index
 * Central hub for all third-party integrations
 */

import { jiraIntegration, JiraClient, JiraIntegration } from './JiraIntegration.js';
import { githubIntegration, GitHubClient, GitHubIntegration } from './GitHubIntegration.js';
import { slackIntegration, SlackClient, SlackIntegration } from './SlackIntegration.js';

/**
 * Integration Types
 */
export const INTEGRATION_TYPES = {
  JIRA: 'jira',
  GITHUB: 'github',
  SLACK: 'slack',
  TEAMS: 'teams', // Future
  PAGERDUTY: 'pagerduty', // Future
  WEBHOOK: 'webhook' // Future
};

/**
 * Integration Manager
 * Manages all integrations for a tenant
 */
export class IntegrationManager {
  constructor() {
    this.integrations = {
      [INTEGRATION_TYPES.JIRA]: jiraIntegration,
      [INTEGRATION_TYPES.GITHUB]: githubIntegration,
      [INTEGRATION_TYPES.SLACK]: slackIntegration
    };
  }

  /**
   * Configure an integration for a tenant
   */
  async configure(tenantId, type, config) {
    const integration = this.integrations[type];
    if (!integration) {
      throw new Error(`Unknown integration type: ${type}`);
    }

    return integration.configure(tenantId, config);
  }

  /**
   * Test integration connection
   */
  async testConnection(tenantId, type) {
    const integration = this.integrations[type];
    if (!integration) {
      return { success: false, error: `Unknown integration type: ${type}` };
    }

    return integration.testConnection(tenantId);
  }

  /**
   * Remove integration
   */
  removeIntegration(tenantId, type) {
    const integration = this.integrations[type];
    if (!integration) {
      return false;
    }

    return integration.removeConfig(tenantId);
  }

  /**
   * Check if integration is configured
   */
  isConfigured(tenantId, type) {
    const integration = this.integrations[type];
    if (!integration) {
      return false;
    }

    return integration.isConfigured(tenantId);
  }

  /**
   * Get all configured integrations for a tenant
   */
  getConfiguredIntegrations(tenantId) {
    const configured = [];
    
    for (const [type, integration] of Object.entries(this.integrations)) {
      if (integration.isConfigured(tenantId)) {
        configured.push(type);
      }
    }

    return configured;
  }

  /**
   * Process scan completion across all integrations
   */
  async onScanComplete(tenantId, scanResults, options = {}) {
    const results = {};

    // Jira: Create issues
    if (this.isConfigured(tenantId, INTEGRATION_TYPES.JIRA) && options.createJiraIssues) {
      try {
        results.jira = await jiraIntegration.createIssuesFromScan(
          tenantId, 
          scanResults, 
          options.jiraOptions || {}
        );
      } catch (error) {
        results.jira = { error: error.message };
      }
    }

    // GitHub: Create issues
    if (this.isConfigured(tenantId, INTEGRATION_TYPES.GITHUB) && options.createGithubIssues) {
      try {
        results.github = await githubIntegration.createIssuesFromScan(
          tenantId, 
          scanResults, 
          options.githubOptions || {}
        );
      } catch (error) {
        results.github = { error: error.message };
      }
    }

    // Slack: Send notification
    if (this.isConfigured(tenantId, INTEGRATION_TYPES.SLACK)) {
      try {
        await slackIntegration.notifyScanComplete(tenantId, scanResults, options.slackOptions || {});
        results.slack = { success: true };
      } catch (error) {
        results.slack = { error: error.message };
      }
    }

    return results;
  }

  /**
   * Process vulnerability found across all integrations
   */
  async onVulnerabilityFound(tenantId, vulnerability, options = {}) {
    // Slack: Send alert for critical/high vulnerabilities
    if (this.isConfigured(tenantId, INTEGRATION_TYPES.SLACK)) {
      try {
        await slackIntegration.notifyVulnerability(tenantId, vulnerability, options);
      } catch (error) {
        console.error('Slack notification failed:', error);
      }
    }
  }

  /**
   * Process error across all integrations
   */
  async onError(tenantId, error, context = {}) {
    if (this.isConfigured(tenantId, INTEGRATION_TYPES.SLACK)) {
      try {
        await slackIntegration.notifyError(tenantId, error, context);
      } catch (err) {
        console.error('Slack error notification failed:', err);
      }
    }
  }
}

export const integrationManager = new IntegrationManager();

// Re-export individual integrations
export {
  jiraIntegration,
  JiraClient,
  JiraIntegration,
  githubIntegration,
  GitHubClient,
  GitHubIntegration,
  slackIntegration,
  SlackClient,
  SlackIntegration
};

export default {
  INTEGRATION_TYPES,
  IntegrationManager,
  integrationManager,
  jiraIntegration,
  githubIntegration,
  slackIntegration
};
