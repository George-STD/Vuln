/**
 * GitHub Integration
 * Create GitHub issues and integrate with GitHub Security
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

/**
 * GitHub API Client
 */
export class GitHubClient {
  constructor(config) {
    this.token = config.token;
    this.owner = config.owner;
    this.repo = config.repo;
    this.baseUrl = config.baseUrl || 'https://api.github.com';
  }

  /**
   * Make API request
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...options.headers
      }
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || `GitHub API error: ${response.status}`);
    }

    return response.json();
  }

  /**
   * Test connection
   */
  async testConnection() {
    try {
      await this.request(`/repos/${this.owner}/${this.repo}`);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get repository
   */
  async getRepository() {
    return this.request(`/repos/${this.owner}/${this.repo}`);
  }

  /**
   * Get labels
   */
  async getLabels() {
    return this.request(`/repos/${this.owner}/${this.repo}/labels`);
  }

  /**
   * Create label if not exists
   */
  async ensureLabel(name, color, description) {
    try {
      const labels = await this.getLabels();
      const exists = labels.find(l => l.name.toLowerCase() === name.toLowerCase());
      
      if (!exists) {
        await this.request(`/repos/${this.owner}/${this.repo}/labels`, {
          method: 'POST',
          body: JSON.stringify({ name, color, description })
        });
      }
    } catch (error) {
      // Ignore label creation errors
      console.log(`Label creation failed: ${error.message}`);
    }
  }

  /**
   * Ensure security labels exist
   */
  async ensureSecurityLabels() {
    const labels = [
      { name: 'security', color: 'd73a4a', description: 'Security related issue' },
      { name: 'vulnerability', color: 'b60205', description: 'Security vulnerability' },
      { name: 'critical', color: '000000', description: 'Critical severity' },
      { name: 'high', color: 'd93f0b', description: 'High severity' },
      { name: 'medium', color: 'fbca04', description: 'Medium severity' },
      { name: 'low', color: '0e8a16', description: 'Low severity' }
    ];

    for (const label of labels) {
      await this.ensureLabel(label.name, label.color, label.description);
    }
  }

  /**
   * Create issue from vulnerability
   */
  async createIssue(vulnerability, options = {}) {
    const labels = [
      'security',
      'vulnerability',
      vulnerability.severity
    ];

    if (options.additionalLabels) {
      labels.push(...options.additionalLabels);
    }

    const body = this.formatVulnerabilityBody(vulnerability);

    const issueData = {
      title: `[${vulnerability.severity.toUpperCase()}] ${vulnerability.name}`,
      body,
      labels
    };

    if (options.assignees) {
      issueData.assignees = options.assignees;
    }

    if (options.milestone) {
      issueData.milestone = options.milestone;
    }

    const result = await this.request(`/repos/${this.owner}/${this.repo}/issues`, {
      method: 'POST',
      body: JSON.stringify(issueData)
    });

    return {
      number: result.number,
      id: result.id,
      url: result.html_url
    };
  }

  /**
   * Format vulnerability body for GitHub
   */
  formatVulnerabilityBody(vulnerability) {
    const severityEmoji = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      informational: '🔵'
    };

    return `## ${severityEmoji[vulnerability.severity] || '⚪'} Vulnerability Report

### Summary
| Property | Value |
|----------|-------|
| **Severity** | ${vulnerability.severity?.toUpperCase()} |
| **Category** | ${vulnerability.category || 'N/A'} |
| **URL** | ${vulnerability.url || 'N/A'} |
| **Confidence** | ${vulnerability.confidence || 0}% |
| **CVSS Score** | ${vulnerability.cvssScore || 'N/A'} |
| **Found At** | ${vulnerability.foundAt || new Date().toISOString()} |

### Description
${vulnerability.description || 'No description provided'}

### Evidence
\`\`\`
${vulnerability.evidence || 'N/A'}
\`\`\`

${vulnerability.request ? `### Request
\`\`\`http
${vulnerability.request}
\`\`\`` : ''}

${vulnerability.response ? `### Response
\`\`\`
${vulnerability.response}
\`\`\`` : ''}

### Remediation
${vulnerability.remediation || 'Follow security best practices'}

### References
${(vulnerability.references || []).map(ref => `- ${ref}`).join('\n') || '- N/A'}

---
*This issue was automatically created by the Vulnerability Scanner*
`;
  }

  /**
   * Update issue
   */
  async updateIssue(issueNumber, data) {
    return this.request(`/repos/${this.owner}/${this.repo}/issues/${issueNumber}`, {
      method: 'PATCH',
      body: JSON.stringify(data)
    });
  }

  /**
   * Add comment to issue
   */
  async addComment(issueNumber, body) {
    return this.request(`/repos/${this.owner}/${this.repo}/issues/${issueNumber}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body })
    });
  }

  /**
   * Close issue
   */
  async closeIssue(issueNumber) {
    return this.updateIssue(issueNumber, { state: 'closed' });
  }

  /**
   * Search issues
   */
  async searchIssues(query) {
    const fullQuery = `repo:${this.owner}/${this.repo} ${query}`;
    return this.request(`/search/issues?q=${encodeURIComponent(fullQuery)}`);
  }

  /**
   * Find existing issue for vulnerability
   */
  async findExistingIssue(vulnerability) {
    const query = `is:issue label:vulnerability "${vulnerability.name.replace(/"/g, '')}" in:title`;
    const result = await this.searchIssues(query);
    return result.items?.[0] || null;
  }

  /**
   * Create security advisory (for private repos with GitHub Advanced Security)
   */
  async createSecurityAdvisory(vulnerability) {
    // This requires GitHub Advanced Security
    const advisoryData = {
      summary: vulnerability.name,
      description: vulnerability.description,
      severity: vulnerability.severity === 'critical' ? 'critical' : 
                vulnerability.severity === 'high' ? 'high' :
                vulnerability.severity === 'medium' ? 'moderate' : 'low',
      vulnerabilities: [{
        package: {
          ecosystem: 'other',
          name: vulnerability.category || 'web'
        },
        vulnerable_version_range: '*',
        patched_versions: 'N/A'
      }]
    };

    try {
      return await this.request(`/repos/${this.owner}/${this.repo}/security-advisories`, {
        method: 'POST',
        body: JSON.stringify(advisoryData)
      });
    } catch (error) {
      // Security advisories may not be available
      console.log(`Security advisory creation failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Upload SARIF report (for GitHub Code Scanning)
   */
  async uploadSARIF(sarifContent, commitSha, ref = 'refs/heads/main') {
    const compressedSarif = Buffer.from(sarifContent).toString('base64');
    
    return this.request(`/repos/${this.owner}/${this.repo}/code-scanning/sarifs`, {
      method: 'POST',
      body: JSON.stringify({
        commit_sha: commitSha,
        ref,
        sarif: compressedSarif,
        tool_name: 'VulnerabilityScanner'
      })
    });
  }
}

/**
 * GitHub Integration Manager
 */
export class GitHubIntegration extends EventEmitter {
  constructor() {
    super();
    this.configs = new Map();
    this.clients = new Map();
  }

  /**
   * Configure GitHub for tenant
   */
  async configure(tenantId, config) {
    this.configs.set(tenantId, {
      id: uuidv4(),
      ...config,
      createdAt: new Date().toISOString()
    });
    
    const client = new GitHubClient(config);
    this.clients.set(tenantId, client);
    
    // Ensure security labels exist
    try {
      await client.ensureSecurityLabels();
    } catch (error) {
      console.log(`Failed to create labels: ${error.message}`);
    }
    
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
      return { success: false, error: 'GitHub not configured' };
    }
    return client.testConnection();
  }

  /**
   * Create issues from scan results
   */
  async createIssuesFromScan(tenantId, scanResults, options = {}) {
    const client = this.getClient(tenantId);
    if (!client) {
      throw new Error('GitHub not configured');
    }

    const results = [];
    const minSeverity = options.minSeverity || 'low';
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    const minSeverityIndex = severityOrder.indexOf(minSeverity);

    for (const vulnerability of scanResults.vulnerabilities || []) {
      const severityIndex = severityOrder.indexOf(vulnerability.severity);
      
      if (severityIndex > minSeverityIndex) continue;

      if (options.skipDuplicates) {
        const existing = await client.findExistingIssue(vulnerability);
        if (existing) {
          results.push({
            vulnerability: vulnerability.name,
            skipped: true,
            existingIssue: existing.number
          });
          continue;
        }
      }

      try {
        const issue = await client.createIssue(vulnerability, options);
        results.push({
          vulnerability: vulnerability.name,
          success: true,
          issueNumber: issue.number,
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

export const githubIntegration = new GitHubIntegration();

export default {
  GitHubClient,
  GitHubIntegration,
  githubIntegration
};
