/**
 * Slack Integration
 * Send vulnerability notifications and alerts to Slack
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

/**
 * Slack Webhook Client
 */
export class SlackClient {
  constructor(config) {
    this.webhookUrl = config.webhookUrl;
    this.botToken = config.botToken; // Optional: for more advanced features
    this.defaultChannel = config.defaultChannel || '#security-alerts';
  }

  /**
   * Send message via webhook
   */
  async sendWebhook(payload) {
    const response = await fetch(this.webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Slack webhook error: ${text}`);
    }

    return { success: true };
  }

  /**
   * Send message via Bot API
   */
  async sendBotMessage(channel, blocks, text) {
    if (!this.botToken) {
      throw new Error('Bot token not configured');
    }

    const response = await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.botToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        channel,
        blocks,
        text
      })
    });

    const result = await response.json();
    if (!result.ok) {
      throw new Error(`Slack API error: ${result.error}`);
    }

    return result;
  }

  /**
   * Test connection
   */
  async testConnection() {
    try {
      await this.sendWebhook({
        text: '🔗 Vulnerability Scanner connected successfully!'
      });
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Send vulnerability alert
   */
  async sendVulnerabilityAlert(vulnerability, options = {}) {
    const severityColors = {
      critical: '#000000',
      high: '#d73a4a',
      medium: '#fbca04',
      low: '#0e8a16',
      informational: '#0366d6'
    };

    const severityEmoji = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      informational: '🔵'
    };

    const blocks = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${severityEmoji[vulnerability.severity]} Security Alert: ${vulnerability.name}`,
          emoji: true
        }
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Severity:*\n${vulnerability.severity?.toUpperCase()}`
          },
          {
            type: 'mrkdwn',
            text: `*Category:*\n${vulnerability.category || 'N/A'}`
          },
          {
            type: 'mrkdwn',
            text: `*Confidence:*\n${vulnerability.confidence || 0}%`
          },
          {
            type: 'mrkdwn',
            text: `*CVSS:*\n${vulnerability.cvssScore || 'N/A'}`
          }
        ]
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*URL:*\n${vulnerability.url || 'N/A'}`
        }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Description:*\n${vulnerability.description || 'No description'}`
        }
      },
      {
        type: 'divider'
      }
    ];

    // Add evidence if available
    if (vulnerability.evidence) {
      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Evidence:*\n\`\`\`${vulnerability.evidence.substring(0, 500)}${vulnerability.evidence.length > 500 ? '...' : ''}\`\`\``
        }
      });
    }

    // Add actions if specified
    if (options.showActions) {
      blocks.push({
        type: 'actions',
        elements: [
          {
            type: 'button',
            text: {
              type: 'plain_text',
              text: 'View Details',
              emoji: true
            },
            url: options.detailsUrl || '#',
            action_id: 'view_details'
          },
          {
            type: 'button',
            text: {
              type: 'plain_text',
              text: 'Mark as Resolved',
              emoji: true
            },
            style: 'primary',
            action_id: 'mark_resolved'
          }
        ]
      });
    }

    // Add context
    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `Found at ${new Date().toISOString()} | Scan ID: ${options.scanId || 'N/A'}`
        }
      ]
    });

    const payload = {
      blocks,
      attachments: [{
        color: severityColors[vulnerability.severity] || '#808080'
      }]
    };

    return this.sendWebhook(payload);
  }

  /**
   * Send scan summary
   */
  async sendScanSummary(scanResults, options = {}) {
    const stats = this.calculateStats(scanResults.vulnerabilities || []);
    
    const blocks = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '🔍 Vulnerability Scan Complete',
          emoji: true
        }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Target:* ${scanResults.targetUrl || scanResults.target || 'N/A'}`
        }
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Total Vulnerabilities:*\n${stats.total}`
          },
          {
            type: 'mrkdwn',
            text: `*Scan Duration:*\n${scanResults.duration || 'N/A'}`
          }
        ]
      },
      {
        type: 'divider'
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: '*Severity Breakdown:*'
        }
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `🔴 *Critical:* ${stats.critical}`
          },
          {
            type: 'mrkdwn',
            text: `🟠 *High:* ${stats.high}`
          },
          {
            type: 'mrkdwn',
            text: `🟡 *Medium:* ${stats.medium}`
          },
          {
            type: 'mrkdwn',
            text: `🟢 *Low:* ${stats.low}`
          }
        ]
      }
    ];

    // Add top vulnerabilities
    if (scanResults.vulnerabilities?.length > 0) {
      const topVulns = scanResults.vulnerabilities
        .sort((a, b) => {
          const order = ['critical', 'high', 'medium', 'low', 'informational'];
          return order.indexOf(a.severity) - order.indexOf(b.severity);
        })
        .slice(0, 5);

      blocks.push({
        type: 'divider'
      });

      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: '*Top Findings:*'
        }
      });

      for (const vuln of topVulns) {
        const emoji = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🟢'
        };

        blocks.push({
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${emoji[vuln.severity] || '⚪'} *${vuln.name}* - ${vuln.severity?.toUpperCase()}`
          }
        });
      }
    }

    // Add report link if available
    if (options.reportUrl) {
      blocks.push({
        type: 'divider'
      });
      blocks.push({
        type: 'actions',
        elements: [
          {
            type: 'button',
            text: {
              type: 'plain_text',
              text: '📄 View Full Report',
              emoji: true
            },
            url: options.reportUrl,
            action_id: 'view_report'
          }
        ]
      });
    }

    // Add context
    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `Completed at ${new Date().toISOString()}`
        }
      ]
    });

    const payload = { blocks };

    return this.sendWebhook(payload);
  }

  /**
   * Calculate vulnerability stats
   */
  calculateStats(vulnerabilities) {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      informational: vulnerabilities.filter(v => v.severity === 'informational').length
    };
  }

  /**
   * Send scheduled scan reminder
   */
  async sendScheduleReminder(schedule) {
    const blocks = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '⏰ Scheduled Scan Starting',
          emoji: true
        }
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Schedule:*\n${schedule.name}`
          },
          {
            type: 'mrkdwn',
            text: `*Target:*\n${schedule.targetUrl}`
          }
        ]
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `Starting at ${new Date().toISOString()}`
          }
        ]
      }
    ];

    return this.sendWebhook({ blocks });
  }

  /**
   * Send error notification
   */
  async sendError(error, context = {}) {
    const blocks = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: '❌ Scan Error',
          emoji: true
        }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Error:*\n${error.message || error}`
        }
      }
    ];

    if (context.scanId) {
      blocks.push({
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Scan ID:*\n${context.scanId}`
          },
          {
            type: 'mrkdwn',
            text: `*Target:*\n${context.targetUrl || 'N/A'}`
          }
        ]
      });
    }

    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `Occurred at ${new Date().toISOString()}`
        }
      ]
    });

    return this.sendWebhook({
      blocks,
      attachments: [{ color: '#d73a4a' }]
    });
  }
}

/**
 * Slack Integration Manager
 */
export class SlackIntegration extends EventEmitter {
  constructor() {
    super();
    this.configs = new Map();
    this.clients = new Map();
  }

  /**
   * Configure Slack for tenant
   */
  configure(tenantId, config) {
    this.configs.set(tenantId, {
      id: uuidv4(),
      ...config,
      notifyOn: config.notifyOn || {
        scanComplete: true,
        criticalVuln: true,
        highVuln: true,
        scheduledStart: false,
        errors: true
      },
      createdAt: new Date().toISOString()
    });
    
    this.clients.set(tenantId, new SlackClient(config));
    return true;
  }

  /**
   * Get client for tenant
   */
  getClient(tenantId) {
    return this.clients.get(tenantId);
  }

  /**
   * Get config for tenant
   */
  getConfig(tenantId) {
    return this.configs.get(tenantId);
  }

  /**
   * Test connection
   */
  async testConnection(tenantId) {
    const client = this.getClient(tenantId);
    if (!client) {
      return { success: false, error: 'Slack not configured' };
    }
    return client.testConnection();
  }

  /**
   * Notify on vulnerability found
   */
  async notifyVulnerability(tenantId, vulnerability, options = {}) {
    const client = this.getClient(tenantId);
    const config = this.getConfig(tenantId);
    
    if (!client || !config) return;

    // Check notification settings
    const shouldNotify = 
      (vulnerability.severity === 'critical' && config.notifyOn.criticalVuln) ||
      (vulnerability.severity === 'high' && config.notifyOn.highVuln);

    if (!shouldNotify) return;

    try {
      await client.sendVulnerabilityAlert(vulnerability, options);
      this.emit('notification:sent', { tenantId, type: 'vulnerability' });
    } catch (error) {
      this.emit('notification:error', { tenantId, error });
    }
  }

  /**
   * Notify on scan complete
   */
  async notifyScanComplete(tenantId, scanResults, options = {}) {
    const client = this.getClient(tenantId);
    const config = this.getConfig(tenantId);
    
    if (!client || !config) return;
    if (!config.notifyOn.scanComplete) return;

    try {
      await client.sendScanSummary(scanResults, options);
      this.emit('notification:sent', { tenantId, type: 'scanComplete' });
    } catch (error) {
      this.emit('notification:error', { tenantId, error });
    }
  }

  /**
   * Notify on scheduled scan start
   */
  async notifyScheduledStart(tenantId, schedule) {
    const client = this.getClient(tenantId);
    const config = this.getConfig(tenantId);
    
    if (!client || !config) return;
    if (!config.notifyOn.scheduledStart) return;

    try {
      await client.sendScheduleReminder(schedule);
      this.emit('notification:sent', { tenantId, type: 'scheduledStart' });
    } catch (error) {
      this.emit('notification:error', { tenantId, error });
    }
  }

  /**
   * Notify on error
   */
  async notifyError(tenantId, error, context = {}) {
    const client = this.getClient(tenantId);
    const config = this.getConfig(tenantId);
    
    if (!client || !config) return;
    if (!config.notifyOn.errors) return;

    try {
      await client.sendError(error, context);
      this.emit('notification:sent', { tenantId, type: 'error' });
    } catch (err) {
      this.emit('notification:error', { tenantId, error: err });
    }
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

export const slackIntegration = new SlackIntegration();

export default {
  SlackClient,
  SlackIntegration,
  slackIntegration
};
