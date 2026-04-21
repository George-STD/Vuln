/**
 * Example Scanner Plugin Template
 * Use this as a starting point for creating custom scanner plugins
 */

/**
 * Plugin Manifest (manifest.json)
 * {
 *   "name": "Example Scanner",
 *   "version": "1.0.0",
 *   "type": "scanner",
 *   "main": "index.js",
 *   "description": "An example custom vulnerability scanner plugin",
 *   "author": "Your Name",
 *   "license": "MIT",
 *   "permissions": ["network"],
 *   "hooks": ["beforeScan", "afterScan"],
 *   "config": {
 *     "enabled": {
 *       "type": "boolean",
 *       "default": true,
 *       "description": "Enable this scanner"
 *     },
 *     "customOption": {
 *       "type": "string",
 *       "default": "",
 *       "description": "Custom configuration option"
 *     }
 *   }
 * }
 */

/**
 * Example Scanner Plugin
 */
export class ExampleScanner {
  constructor(context) {
    this.context = context;
    this.logger = context.logger;
    this.api = context.api;
    this.storage = context.storage;
    
    this.name = 'Example Scanner';
    this.description = 'An example custom vulnerability scanner';
    this.version = '1.0.0';
    
    // Scanner configuration
    this.enabled = true;
    this.severity = 'medium';
  }

  /**
   * Called when plugin starts
   */
  async onStartup() {
    this.logger.info('Example Scanner started');
    
    // Load any saved state
    const state = await this.storage.get('state');
    if (state) {
      this.logger.info('Loaded saved state:', state);
    }
  }

  /**
   * Called when plugin stops
   */
  async onShutdown() {
    this.logger.info('Example Scanner stopping');
    
    // Save state
    await this.storage.set('state', {
      lastShutdown: new Date().toISOString()
    });
  }

  /**
   * Called when configuration changes
   */
  async onConfigChange(newConfig) {
    this.logger.info('Configuration changed:', newConfig);
    
    if (newConfig.enabled !== undefined) {
      this.enabled = newConfig.enabled;
    }
  }

  /**
   * Hook: Before scan starts
   */
  async beforeScan(scanContext) {
    this.logger.info('Preparing for scan:', scanContext.targetUrl);
    
    // You can modify the scan context here
    // For example, add custom headers
    return {
      ...scanContext,
      customData: {
        examplePlugin: true,
        timestamp: Date.now()
      }
    };
  }

  /**
   * Hook: After scan completes
   */
  async afterScan(scanResults) {
    this.logger.info('Scan completed, found', scanResults.vulnerabilities?.length || 0, 'vulnerabilities');
    
    // You can modify or enhance results here
    return scanResults;
  }

  /**
   * Main scan method - required for scanner plugins
   * @param {string} url - Target URL to scan
   * @param {object} options - Scan options
   * @returns {Promise<Array>} - Array of vulnerabilities found
   */
  async scan(url, options = {}) {
    if (!this.enabled) {
      return [];
    }

    this.logger.info(`Scanning ${url} for example vulnerabilities...`);
    
    const vulnerabilities = [];
    
    try {
      // Example: Check for a specific pattern
      const response = await this.api.fetch(url, {
        method: 'GET',
        timeout: 10000
      });
      
      const html = await response.text();
      const headers = response.headers;
      
      // Example check 1: Look for sensitive comments
      const sensitiveComments = this.checkSensitiveComments(html, url);
      vulnerabilities.push(...sensitiveComments);
      
      // Example check 2: Look for debug endpoints
      const debugEndpoints = await this.checkDebugEndpoints(url);
      vulnerabilities.push(...debugEndpoints);
      
      // Example check 3: Custom header check
      const headerIssues = this.checkCustomHeaders(headers, url);
      vulnerabilities.push(...headerIssues);
      
    } catch (error) {
      this.logger.error('Scan error:', error.message);
    }
    
    return vulnerabilities;
  }

  /**
   * Example check: Look for sensitive comments in HTML
   */
  checkSensitiveComments(html, url) {
    const vulnerabilities = [];
    
    // Pattern to find HTML comments
    const commentPattern = /<!--[\s\S]*?-->/g;
    const matches = html.matchAll(commentPattern);
    
    const sensitivePatterns = [
      /password/i,
      /api[_-]?key/i,
      /secret/i,
      /token/i,
      /todo/i,
      /fixme/i,
      /hack/i,
      /debug/i
    ];
    
    for (const match of matches) {
      const comment = match[0];
      
      for (const pattern of sensitivePatterns) {
        if (pattern.test(comment)) {
          vulnerabilities.push({
            name: 'Sensitive Information in HTML Comment',
            description: 'Found potentially sensitive information in an HTML comment that may expose internal details or security-sensitive data.',
            severity: 'low',
            confidence: 60,
            category: 'Information Disclosure',
            url: url,
            evidence: comment.substring(0, 200),
            remediation: 'Remove all sensitive information from HTML comments before deploying to production.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage'
            ]
          });
          break;
        }
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Example check: Look for debug endpoints
   */
  async checkDebugEndpoints(baseUrl) {
    const vulnerabilities = [];
    
    const debugPaths = [
      '/debug',
      '/debug.php',
      '/debug.aspx',
      '/_debug',
      '/console',
      '/phpinfo.php',
      '/info.php',
      '/server-status',
      '/server-info',
      '/.env',
      '/config.json'
    ];
    
    for (const path of debugPaths) {
      try {
        const url = new URL(path, baseUrl).href;
        const response = await this.api.fetch(url, {
          method: 'GET',
          timeout: 5000
        });
        
        if (response.status === 200) {
          const contentType = response.headers.get('content-type') || '';
          
          // Check if it's not a generic error page
          if (!contentType.includes('text/html') || 
              (await response.text()).length > 100) {
            vulnerabilities.push({
              name: 'Debug Endpoint Exposed',
              description: `Found an accessible debug or configuration endpoint at ${path}`,
              severity: 'medium',
              confidence: 70,
              category: 'Information Disclosure',
              url: url,
              evidence: `HTTP ${response.status} - ${contentType}`,
              remediation: 'Disable or restrict access to debug endpoints in production environments.',
              references: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces'
              ]
            });
          }
        }
      } catch (error) {
        // Ignore errors (endpoint not accessible)
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Example check: Custom header validation
   */
  checkCustomHeaders(headers, url) {
    const vulnerabilities = [];
    
    // Check for exposed server version
    const serverHeader = headers.get('server');
    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      vulnerabilities.push({
        name: 'Server Version Disclosure',
        description: 'The server reveals detailed version information in the Server header.',
        severity: 'informational',
        confidence: 90,
        category: 'Information Disclosure',
        url: url,
        evidence: `Server: ${serverHeader}`,
        remediation: 'Configure the server to hide or generalize version information.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'
        ]
      });
    }
    
    // Check for exposed technology stack
    const xPoweredBy = headers.get('x-powered-by');
    if (xPoweredBy) {
      vulnerabilities.push({
        name: 'Technology Stack Disclosure',
        description: 'The X-Powered-By header reveals the technology stack being used.',
        severity: 'informational',
        confidence: 95,
        category: 'Information Disclosure',
        url: url,
        evidence: `X-Powered-By: ${xPoweredBy}`,
        remediation: 'Remove the X-Powered-By header from server responses.',
        references: [
          'https://owasp.org/www-project-secure-headers/#x-powered-by'
        ]
      });
    }
    
    return vulnerabilities;
  }

  /**
   * Get scanner info - used by the plugin system
   */
  getInfo() {
    return {
      name: this.name,
      description: this.description,
      version: this.version,
      enabled: this.enabled,
      checks: [
        'Sensitive HTML Comments',
        'Debug Endpoints',
        'Header Information Disclosure'
      ]
    };
  }
}

// Export for plugin system
export default ExampleScanner;

// Also export init function for alternative loading
export function init(context) {
  return new ExampleScanner(context);
}
