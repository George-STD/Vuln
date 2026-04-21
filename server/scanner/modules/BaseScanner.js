import axios from 'axios';

export class BaseScanner {
  constructor(config) {
    this.targetUrl = config.targetUrl;
    this.options = config.options || {};
    this.onVulnerability = config.onVulnerability;
    this.onLog = config.onLog;
    this.stopped = false;
    this.name = 'Base Scanner';
  }
  
  stop() {
    this.stopped = true;
  }
  
  log(message, type = 'info') {
    if (this.onLog) {
      this.onLog({ 
        message: `[${this.name}] ${message}`, 
        type, 
        timestamp: new Date().toISOString() 
      });
    }
  }
  
  async makeRequest(url, options = {}) {
    if (this.stopped) return null;
    
    try {
      const response = await axios({
        url,
        method: options.method || 'GET',
        headers: {
          'User-Agent': this.options.userAgent || 'VulnHunter Pro/1.0',
          ...options.headers
        },
        data: options.data,
        params: options.params,
        timeout: options.timeout || this.options.timeout || 10000,
        maxRedirects: options.maxRedirects !== undefined ? options.maxRedirects : 5,
        validateStatus: () => true,
        httpsAgent: options.httpsAgent
      });
      
      return response;
    } catch (error) {
      this.log(`Request error: ${error.message}`, 'debug');
      return null;
    }
  }
  
  async scan(data) {
    throw new Error('scan() method must be implemented');
  }
  
  createVulnerability(options) {
    const vuln = {
      id: this.generateId(),
      type: options.type || 'Unknown',
      subType: options.subType || null,
      severity: options.severity || 'info',
      url: options.url || this.targetUrl,
      method: options.method || 'GET',
      parameter: options.parameter || null,
      payload: options.payload || null,
      evidence: options.evidence || null,
      description: options.description || '',
      remediation: options.remediation || '',
      references: options.references || [],
      cvss: options.cvss || null,
      cwe: options.cwe || null,
      timestamp: new Date().toISOString()
    };
    
    if (this.onVulnerability) {
      this.onVulnerability(vuln);
    }
    
    return vuln;
  }
  
  generateId() {
    return `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  encodePayload(payload) {
    return encodeURIComponent(payload);
  }
  
  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }
  
  isSameDomain(url) {
    try {
      const targetDomain = new URL(this.targetUrl).hostname;
      const urlDomain = new URL(url).hostname;
      return urlDomain === targetDomain || urlDomain.endsWith('.' + targetDomain);
    } catch {
      return false;
    }
  }
}
