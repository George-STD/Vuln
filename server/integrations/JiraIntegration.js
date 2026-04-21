/**
 * Jira Integration
 * Create and manage Jira issues from vulnerability findings
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

/**
 * Jira API Client
 */
export class JiraClient {
  constructor(config) {
    this.baseUrl = config.baseUrl; // e.g., https://company.atlassian.net
    this.email = config.email;
    this.apiToken = config.apiToken;
    this.projectKey = config.projectKey;
  }

  /**
   * Get authorization header
   */
  getAuthHeader() {
    const auth = Buffer.from(`${this.email}:${this.apiToken}`).toString('base64');
    return `Basic ${auth}`;
  }

  /**
   * Make API request
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}/rest/api/3${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': this.getAuthHeader(),
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...options.headers
      }
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.errorMessages?.join(', ') || `Jira API error: ${response.status}`);
    }

    return response.json();
  }

  /**
   * Test connection
   */
  async testConnection() {
    try {
      await this.request('/myself');
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get project info
   */
  async getProject() {
    return this.request(`/project/${this.projectKey}`);
  }

  /**
   * Get issue types
   */
  async getIssueTypes() {
    const project = await this.getProject();
    return project.issueTypes;
  }

  /**
   * Get priorities
   */
  async getPriorities() {
    return this.request('/priority');
  }

  /**
   * Create issue from vulnerability
   */
  async createIssue(vulnerability, options = {}) {
    const severityToPriority = {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      informational: 'Lowest'
    };

    const issueType = options.issueType || 'Bug';
    const priority = options.priority || severityToPriority[vulnerability.severity] || 'Medium';

    const description = this.formatVulnerabilityDescription(vulnerability);

    const issueData = {
      fields: {
        project: {
          key: this.projectKey
        },
        summary: `[${vulnerability.severity.toUpperCase()}] ${vulnerability.name}`,
        description: description,
        issuetype: {
          name: issueType
        },
        priority: {
          name: priority
        },
        labels: [
          'security',
          'vulnerability',
          `severity-${vulnerability.severity}`,
          vulnerability.category?.toLowerCase().replace(/\s+/g, '-') || 'general'
        ]
      }
    };

    // Add custom fields if provided
    if (options.customFields) {
      Object.assign(issueData.fields, options.customFields);
    }

    // Add component if specified
    if (options.component) {
      issueData.fields.components = [{ name: options.component }];
    }

    // Add assignee if specified
    if (options.assignee) {
      issueData.fields.assignee = { accountId: options.assignee };
    }

    const result = await this.request('/issue', {
      method: 'POST',
      body: JSON.stringify(issueData)
    });

    return {
      key: result.key,
      id: result.id,
      url: `${this.baseUrl}/browse/${result.key}`
    };
  }

  /**
   * Format vulnerability description for Jira
   */
  formatVulnerabilityDescription(vulnerability) {
    return {
      type: 'doc',
      version: 1,
      content: [
        {
          type: 'heading',
          attrs: { level: 2 },
          content: [{ type: 'text', text: 'Vulnerability Details' }]
        },
        {
          type: 'table',
          content: [
            this.createTableRow('Severity', vulnerability.severity?.toUpperCase()),
            this.createTableRow('Category', vulnerability.category),
            this.createTableRow('URL', vulnerability.url),
            this.createTableRow('Confidence', `${vulnerability.confidence}%`),
            this.createTableRow('CVSS Score', vulnerability.cvssScore?.toString())
          ].filter(row => row)
        },
        {
          type: 'heading',
          attrs: { level: 3 },
          content: [{ type: 'text', text: 'Description' }]
        },
        {
          type: 'paragraph',
          content: [{ type: 'text', text: vulnerability.description || 'No description provided' }]
        },
        {
          type: 'heading',
          attrs: { level: 3 },
          content: [{ type: 'text', text: 'Evidence' }]
        },
        {
          type: 'codeBlock',
          attrs: { language: 'text' },
          content: [{ type: 'text', text: vulnerability.evidence || 'N/A' }]
        },
        {
          type: 'heading',
          attrs: { level: 3 },
          content: [{ type: 'text', text: 'Remediation' }]
        },
        {
          type: 'paragraph',
          content: [{ type: 'text', text: vulnerability.remediation || 'Follow security best practices' }]
        },
        {
          type: 'heading',
          attrs: { level: 3 },
          content: [{ type: 'text', text: 'References' }]
        },
        {
          type: 'bulletList',
          content: (vulnerability.references || []).map(ref => ({
            type: 'listItem',
            content: [{
              type: 'paragraph',
              content: [{
                type: 'text',
                text: ref,
                marks: [{ type: 'link', attrs: { href: ref } }]
              }]
            }]
          }))
        }
      ]
    };
  }

  /**
   * Create table row for Jira document format
   */
  createTableRow(label, value) {
    if (!value) return null;
    return {
      type: 'tableRow',
      content: [
        {
          type: 'tableCell',
          content: [{ type: 'paragraph', content: [{ type: 'text', text: label, marks: [{ type: 'strong' }] }] }]
        },
        {
          type: 'tableCell',
          content: [{ type: 'paragraph', content: [{ type: 'text', text: value }] }]
        }
      ]
    };
  }

  /**
   * Update issue
   */
  async updateIssue(issueKey, fields) {
    return this.request(`/issue/${issueKey}`, {
      method: 'PUT',
      body: JSON.stringify({ fields })
    });
  }

  /**
   * Add comment to issue
   */
  async addComment(issueKey, comment) {
    return this.request(`/issue/${issueKey}/comment`, {
      method: 'POST',
      body: JSON.stringify({
        body: {
          type: 'doc',
          version: 1,
          content: [{
            type: 'paragraph',
            content: [{ type: 'text', text: comment }]
          }]
        }
      })
    });
  }

  /**
   * Transition issue (change status)
   */
  async transitionIssue(issueKey, transitionId) {
    return this.request(`/issue/${issueKey}/transitions`, {
      method: 'POST',
      body: JSON.stringify({
        transition: { id: transitionId }
      })
    });
  }

  /**
   * Get available transitions
   */
  async getTransitions(issueKey) {
    return this.request(`/issue/${issueKey}/transitions`);
  }

  /**
   * Search issues
   */
  async searchIssues(jql, maxResults = 50) {
    return this.request('/search', {
      method: 'POST',
      body: JSON.stringify({
        jql,
        maxResults,
        fields: ['summary', 'status', 'priority', 'labels', 'created', 'updated']
      })
    });
  }

  /**
   * Find existing issue for vulnerability
   */
  async findExistingIssue(vulnerability) {
    const jql = `project = "${this.projectKey}" AND labels = "vulnerability" AND summary ~ "${vulnerability.name.replace(/"/g, '\\"')}"`;
    const result = await this.searchIssues(jql, 1);
    return result.issues?.[0] || null;
  }
}

/**
 * Jira Integration Manager
 */
export class JiraIntegration extends EventEmitter {
  constructor() {
    super();
    this.configs = new Map(); // tenantId -> config
    this.clients = new Map(); // tenantId -> JiraClient
  }

  /**
   * Configure Jira for tenant
   */
  configure(tenantId, config) {
    this.configs.set(tenantId, {
      id: uuidv4(),
      ...config,
      createdAt: new Date().toISOString()
    });
    
    this.clients.set(tenantId, new JiraClient(config));
    return true;
  }

  /**
   * Get client for tenant
   */
  getClient(tenantId) {
    return this.clients.get(tenantId);
  }

  /**
   * Test connection
   */
  async testConnection(tenantId) {
    const client = this.getClient(tenantId);
    if (!client) {
      return { success: false, error: 'Jira not configured' };
    }
    return client.testConnection();
  }

  /**
   * Create issues for scan results
   */
  async createIssuesFromScan(tenantId, scanResults, options = {}) {
    const client = this.getClient(tenantId);
    if (!client) {
      throw new Error('Jira not configured');
    }

    const results = [];
    const minSeverity = options.minSeverity || 'low';
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    const minSeverityIndex = severityOrder.indexOf(minSeverity);

    for (const vulnerability of scanResults.vulnerabilities || []) {
      const severityIndex = severityOrder.indexOf(vulnerability.severity);
      
      // Skip if below minimum severity
      if (severityIndex > minSeverityIndex) continue;

      // Skip duplicates if enabled
      if (options.skipDuplicates) {
        const existing = await client.findExistingIssue(vulnerability);
        if (existing) {
          results.push({
            vulnerability: vulnerability.name,
            skipped: true,
            existingIssue: existing.key
          });
          continue;
        }
      }

      try {
        const issue = await client.createIssue(vulnerability, options);
        results.push({
          vulnerability: vulnerability.name,
          success: true,
          issueKey: issue.key,
          issueUrl: issue.url
        });
        
        this.emit('issue:created', { tenantId, vulnerability, issue });
      } catch (error) {
        results.push({
          vulnerability: vulnerability.name,
          success: false,
          error: error.message
        });
        
        this.emit('issue:error', { tenantId, vulnerability, error });
      }
    }

    return results;
  }

  /**
   * Remove configuration
   */
  removeConfig(tenantId) {
    this.configs.delete(tenantId);
    this.clients.delete(tenantId);
    return true;
  }

  /**
   * Check if configured
   */
  isConfigured(tenantId) {
    return this.configs.has(tenantId);
  }
}

export const jiraIntegration = new JiraIntegration();

export default {
  JiraClient,
  JiraIntegration,
  jiraIntegration
};
