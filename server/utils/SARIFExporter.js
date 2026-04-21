/**
 * SARIF (Static Analysis Results Interchange Format) Exporter
 * Exports vulnerability scan results in SARIF 2.1.0 format
 * Compatible with GitHub Security, Azure DevOps, and other CI/CD tools
 */

export class SARIFExporter {
  constructor(options = {}) {
    this.options = {
      toolName: options.toolName || 'Auto Vulnerability Tester',
      toolVersion: options.toolVersion || '1.0.0',
      toolUri: options.toolUri || 'https://github.com/vulnerability-scanner',
      ...options
    };
  }

  /**
   * Export scan results to SARIF format
   */
  export(scanResults, targetUrl) {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        this.createRun(scanResults, targetUrl)
      ]
    };

    return sarif;
  }

  /**
   * Create a SARIF run
   */
  createRun(scanResults, targetUrl) {
    const { vulnerabilities = [], summary = {} } = scanResults;

    return {
      tool: this.createTool(vulnerabilities),
      results: vulnerabilities.map((vuln, index) => this.createResult(vuln, index)),
      invocations: [this.createInvocation(targetUrl, summary)],
      artifacts: this.createArtifacts(vulnerabilities, targetUrl),
      automationDetails: {
        id: `vulnerability-scan/${new Date().toISOString()}`,
        guid: this.generateGuid(),
        correlationGuid: this.generateGuid()
      },
      properties: {
        scanTarget: targetUrl,
        scanTimestamp: new Date().toISOString(),
        summary: {
          totalVulnerabilities: summary.total || vulnerabilities.length,
          criticalCount: summary.critical || 0,
          highCount: summary.high || 0,
          mediumCount: summary.medium || 0,
          lowCount: summary.low || 0
        }
      }
    };
  }

  /**
   * Create tool descriptor with rules
   */
  createTool(vulnerabilities) {
    // Extract unique vulnerability types as rules
    const rules = this.extractRules(vulnerabilities);

    return {
      driver: {
        name: this.options.toolName,
        version: this.options.toolVersion,
        informationUri: this.options.toolUri,
        organization: 'Security Scanner',
        fullName: `${this.options.toolName} v${this.options.toolVersion}`,
        semanticVersion: this.options.toolVersion,
        language: 'ar-EG',
        rules,
        supportedTaxonomies: [
          {
            name: 'CWE',
            guid: 'a5a7c25c-f0f1-4d5e-a3a0-b5f2c1d2e3f4'
          },
          {
            name: 'OWASP',
            guid: 'b6b8d36d-f1f2-5e6f-b4b1-c6f3d2e4f5a6'
          }
        ]
      }
    };
  }

  /**
   * Extract unique rules from vulnerabilities
   */
  extractRules(vulnerabilities) {
    const ruleMap = new Map();

    for (const vuln of vulnerabilities) {
      const ruleId = this.getRuleId(vuln.type);
      
      if (!ruleMap.has(ruleId)) {
        ruleMap.set(ruleId, this.createRule(vuln));
      }
    }

    return Array.from(ruleMap.values());
  }

  /**
   * Create a rule from vulnerability type
   */
  createRule(vuln) {
    const ruleId = this.getRuleId(vuln.type);
    const cweMappings = this.getCWEMapping(vuln.type);
    const owaspMappings = this.getOWASPMapping(vuln.type);

    return {
      id: ruleId,
      name: vuln.type,
      shortDescription: {
        text: this.getShortDescription(vuln.type)
      },
      fullDescription: {
        text: this.getFullDescription(vuln.type),
        markdown: this.getMarkdownDescription(vuln.type)
      },
      help: {
        text: this.getRemediation(vuln.type),
        markdown: this.getMarkdownRemediation(vuln.type)
      },
      helpUri: this.getHelpUri(vuln.type),
      defaultConfiguration: {
        level: this.getSeverityLevel(vuln.severity)
      },
      properties: {
        tags: this.getTags(vuln.type),
        precision: 'high',
        'security-severity': this.getSecuritySeverity(vuln.severity)
      },
      relationships: [
        ...cweMappings.map(cwe => ({
          target: {
            id: cwe.id,
            guid: cwe.guid,
            toolComponent: { name: 'CWE' }
          },
          kinds: ['superset']
        })),
        ...owaspMappings.map(owasp => ({
          target: {
            id: owasp.id,
            guid: owasp.guid,
            toolComponent: { name: 'OWASP' }
          },
          kinds: ['superset']
        }))
      ]
    };
  }

  /**
   * Create a SARIF result from vulnerability
   */
  createResult(vuln, index) {
    return {
      ruleId: this.getRuleId(vuln.type),
      ruleIndex: 0,
      level: this.getSeverityLevel(vuln.severity),
      message: {
        text: vuln.description || `تم اكتشاف ثغرة ${vuln.type}`,
        markdown: `**${vuln.type}** detected\n\n${vuln.description || ''}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: vuln.url || vuln.endpoint || 'unknown',
              uriBaseId: '%SRCROOT%'
            }
          },
          logicalLocations: vuln.parameter ? [
            {
              name: vuln.parameter,
              kind: 'parameter'
            }
          ] : []
        }
      ],
      fingerprints: {
        'primaryLocationLineHash': this.hashString(`${vuln.type}:${vuln.url}:${vuln.parameter || ''}`),
        'primaryLocationHash/v1': this.hashString(JSON.stringify(vuln))
      },
      partialFingerprints: {
        'primaryLocationHash': this.hashString(vuln.url || '')
      },
      codeFlows: vuln.payload ? [
        {
          message: { text: 'Attack flow' },
          threadFlows: [
            {
              locations: [
                {
                  location: {
                    message: { text: `Payload: ${vuln.payload}` },
                    physicalLocation: {
                      artifactLocation: {
                        uri: vuln.url || 'unknown'
                      }
                    }
                  }
                }
              ]
            }
          ]
        }
      ] : [],
      properties: {
        evidence: vuln.evidence,
        payload: vuln.payload,
        remediation: vuln.remediation,
        confidence: vuln.confidence || 'medium',
        cvss: this.getCVSS(vuln.severity),
        cwe: this.getCWEMapping(vuln.type),
        owasp: this.getOWASPMapping(vuln.type)
      }
    };
  }

  /**
   * Create invocation details
   */
  createInvocation(targetUrl, summary) {
    return {
      executionSuccessful: true,
      startTimeUtc: summary.startTime || new Date().toISOString(),
      endTimeUtc: summary.endTime || new Date().toISOString(),
      workingDirectory: {
        uri: targetUrl
      },
      toolExecutionNotifications: [],
      properties: {
        targetUrl,
        scanDuration: summary.duration || 0
      }
    };
  }

  /**
   * Create artifacts list
   */
  createArtifacts(vulnerabilities, targetUrl) {
    const artifactSet = new Set([targetUrl]);
    
    for (const vuln of vulnerabilities) {
      if (vuln.url) {
        artifactSet.add(vuln.url);
      }
    }

    return Array.from(artifactSet).map((uri, index) => ({
      location: {
        uri,
        index
      },
      sourceLanguage: 'html',
      properties: {
        scanned: true
      }
    }));
  }

  /**
   * Get rule ID from vulnerability type
   */
  getRuleId(type) {
    const typeMap = {
      'XSS': 'VULN001',
      'SQL Injection': 'VULN002',
      'CSRF': 'VULN003',
      'SSRF': 'VULN004',
      'LFI': 'VULN005',
      'RCE': 'VULN006',
      'XXE': 'VULN007',
      'IDOR': 'VULN008',
      'Open Redirect': 'VULN009',
      'Security Header': 'VULN010',
      'CORS': 'VULN011',
      'SSL/TLS': 'VULN012',
      'Directory Traversal': 'VULN013',
      'Sensitive Data': 'VULN014',
      'Auth Bypass': 'VULN015',
      'Cookie Security': 'VULN016',
      'Clickjacking': 'VULN017',
      'DOM XSS': 'VULN018'
    };

    return typeMap[type] || `VULN-${type.replace(/\s+/g, '-').toUpperCase()}`;
  }

  /**
   * Get short description
   */
  getShortDescription(type) {
    const descriptions = {
      'XSS': 'Cross-Site Scripting vulnerability',
      'SQL Injection': 'SQL Injection vulnerability',
      'CSRF': 'Cross-Site Request Forgery vulnerability',
      'SSRF': 'Server-Side Request Forgery vulnerability',
      'LFI': 'Local File Inclusion vulnerability',
      'RCE': 'Remote Code Execution vulnerability',
      'XXE': 'XML External Entity vulnerability',
      'IDOR': 'Insecure Direct Object Reference vulnerability',
      'Open Redirect': 'Open Redirect vulnerability',
      'Security Header': 'Missing or misconfigured security header',
      'CORS': 'Cross-Origin Resource Sharing misconfiguration',
      'SSL/TLS': 'SSL/TLS configuration issue',
      'DOM XSS': 'DOM-based Cross-Site Scripting vulnerability'
    };

    return descriptions[type] || `${type} vulnerability detected`;
  }

  /**
   * Get full description
   */
  getFullDescription(type) {
    const descriptions = {
      'XSS': 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. This can lead to session hijacking, defacement, or malicious redirects.',
      'SQL Injection': 'SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data, and in some cases executing system commands.',
      'CSRF': 'Cross-Site Request Forgery forces authenticated users to submit requests they did not intend, potentially changing account settings or making unauthorized transactions.',
      'SSRF': 'Server-Side Request Forgery allows attackers to make requests from the server, potentially accessing internal services, cloud metadata, or pivoting to internal networks.',
      'DOM XSS': 'DOM-based XSS occurs when JavaScript takes user input and writes it to the DOM without sanitization, allowing client-side script injection.'
    };

    return descriptions[type] || `A ${type} vulnerability has been detected that could compromise application security.`;
  }

  /**
   * Get markdown description
   */
  getMarkdownDescription(type) {
    return `## ${type}\n\n${this.getFullDescription(type)}`;
  }

  /**
   * Get remediation advice
   */
  getRemediation(type) {
    const remediations = {
      'XSS': 'Use context-aware output encoding. Implement Content Security Policy. Use HttpOnly cookies.',
      'SQL Injection': 'Use parameterized queries or prepared statements. Implement input validation. Use ORM where possible.',
      'CSRF': 'Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Referer header.',
      'SSRF': 'Whitelist allowed URLs and domains. Disable unnecessary URL schemes. Use network segmentation.',
      'DOM XSS': 'Use textContent instead of innerHTML. Sanitize with DOMPurify. Implement strict CSP.'
    };

    return remediations[type] || 'Review and fix the identified vulnerability according to security best practices.';
  }

  /**
   * Get markdown remediation
   */
  getMarkdownRemediation(type) {
    return `## Remediation\n\n${this.getRemediation(type)}\n\n### References\n- [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/)`;
  }

  /**
   * Get help URI
   */
  getHelpUri(type) {
    const uris = {
      'XSS': 'https://owasp.org/www-community/attacks/xss/',
      'SQL Injection': 'https://owasp.org/www-community/attacks/SQL_Injection',
      'CSRF': 'https://owasp.org/www-community/attacks/csrf',
      'SSRF': 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
      'DOM XSS': 'https://owasp.org/www-community/attacks/DOM_Based_XSS'
    };

    return uris[type] || 'https://owasp.org/www-community/vulnerabilities/';
  }

  /**
   * Get SARIF severity level
   */
  getSeverityLevel(severity) {
    const levels = {
      'critical': 'error',
      'high': 'error',
      'medium': 'warning',
      'low': 'note',
      'info': 'none'
    };

    return levels[severity?.toLowerCase()] || 'warning';
  }

  /**
   * Get security severity score (0-10)
   */
  getSecuritySeverity(severity) {
    const scores = {
      'critical': '9.0',
      'high': '7.5',
      'medium': '5.5',
      'low': '3.0',
      'info': '1.0'
    };

    return scores[severity?.toLowerCase()] || '5.0';
  }

  /**
   * Get CVSS score
   */
  getCVSS(severity) {
    const cvss = {
      'critical': { score: 9.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      'high': { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
      'medium': { score: 5.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N' },
      'low': { score: 3.0, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N' }
    };

    return cvss[severity?.toLowerCase()] || cvss['medium'];
  }

  /**
   * Get CWE mappings
   */
  getCWEMapping(type) {
    const mappings = {
      'XSS': [{ id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation', guid: 'cwe-79-guid' }],
      'SQL Injection': [{ id: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command', guid: 'cwe-89-guid' }],
      'CSRF': [{ id: 'CWE-352', name: 'Cross-Site Request Forgery', guid: 'cwe-352-guid' }],
      'SSRF': [{ id: 'CWE-918', name: 'Server-Side Request Forgery', guid: 'cwe-918-guid' }],
      'LFI': [{ id: 'CWE-98', name: 'Improper Control of Filename for Include/Require Statement', guid: 'cwe-98-guid' }],
      'RCE': [{ id: 'CWE-94', name: 'Improper Control of Generation of Code', guid: 'cwe-94-guid' }],
      'XXE': [{ id: 'CWE-611', name: 'Improper Restriction of XML External Entity Reference', guid: 'cwe-611-guid' }],
      'IDOR': [{ id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key', guid: 'cwe-639-guid' }],
      'Open Redirect': [{ id: 'CWE-601', name: 'URL Redirection to Untrusted Site', guid: 'cwe-601-guid' }],
      'DOM XSS': [{ id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation', guid: 'cwe-79-dom-guid' }]
    };

    return mappings[type] || [];
  }

  /**
   * Get OWASP mappings
   */
  getOWASPMapping(type) {
    const mappings = {
      'XSS': [{ id: 'A03:2021', name: 'Injection', guid: 'owasp-a03-guid' }],
      'SQL Injection': [{ id: 'A03:2021', name: 'Injection', guid: 'owasp-a03-guid' }],
      'CSRF': [{ id: 'A01:2021', name: 'Broken Access Control', guid: 'owasp-a01-guid' }],
      'SSRF': [{ id: 'A10:2021', name: 'Server-Side Request Forgery', guid: 'owasp-a10-guid' }],
      'IDOR': [{ id: 'A01:2021', name: 'Broken Access Control', guid: 'owasp-a01-guid' }],
      'Security Header': [{ id: 'A05:2021', name: 'Security Misconfiguration', guid: 'owasp-a05-guid' }]
    };

    return mappings[type] || [];
  }

  /**
   * Get tags for vulnerability type
   */
  getTags(type) {
    const baseTags = ['security', 'vulnerability'];
    const typeTags = {
      'XSS': ['xss', 'injection', 'client-side'],
      'SQL Injection': ['sqli', 'injection', 'database'],
      'CSRF': ['csrf', 'session'],
      'SSRF': ['ssrf', 'server-side'],
      'DOM XSS': ['xss', 'dom', 'client-side']
    };

    return [...baseTags, ...(typeTags[type] || [type.toLowerCase().replace(/\s+/g, '-')])];
  }

  /**
   * Generate a random GUID
   */
  generateGuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Simple string hash
   */
  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(16, '0');
  }

  /**
   * Export to string
   */
  toString(scanResults, targetUrl) {
    return JSON.stringify(this.export(scanResults, targetUrl), null, 2);
  }

  /**
   * Export to file-ready buffer
   */
  toBuffer(scanResults, targetUrl) {
    return Buffer.from(this.toString(scanResults, targetUrl), 'utf-8');
  }
}

export default SARIFExporter;
