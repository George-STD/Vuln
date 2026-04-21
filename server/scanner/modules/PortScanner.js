import { BaseScanner } from './BaseScanner.js';
import net from 'net';

export class PortScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Port Scanner';
    
    // Common ports to scan
    this.ports = [
      21,    // FTP
      22,    // SSH
      23,    // Telnet
      25,    // SMTP
      53,    // DNS
      80,    // HTTP
      110,   // POP3
      143,   // IMAP
      443,   // HTTPS
      445,   // SMB
      587,   // SMTP (submission)
      993,   // IMAPS
      995,   // POP3S
      1433,  // MSSQL
      1521,  // Oracle
      3306,  // MySQL
      3389,  // RDP
      5432,  // PostgreSQL
      5900,  // VNC
      6379,  // Redis
      8080,  // HTTP Alt
      8443,  // HTTPS Alt
      9200,  // Elasticsearch
      27017  // MongoDB
    ];
    
    this.portServices = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      445: 'SMB',
      587: 'SMTP',
      993: 'IMAPS',
      995: 'POP3S',
      1433: 'MSSQL',
      1521: 'Oracle',
      3306: 'MySQL',
      3389: 'RDP',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      8080: 'HTTP',
      8443: 'HTTPS',
      9200: 'Elasticsearch',
      27017: 'MongoDB'
    };
    
    this.riskyPorts = [23, 21, 3389, 5900, 6379, 27017, 9200, 1433, 3306, 5432];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const openPorts = [];
    
    try {
      const hostname = new URL(this.targetUrl).hostname;
      
      this.log(`Scanning common ports for ${hostname}...`);
      
      // Scan ports in batches
      const batchSize = 10;
      for (let i = 0; i < this.ports.length && !this.stopped; i += batchSize) {
        const batch = this.ports.slice(i, i + batchSize);
        
        const results = await Promise.all(
          batch.map(port => this.checkPort(hostname, port))
        );
        
        results.forEach((result, idx) => {
          if (result.open) {
            openPorts.push({
              port: batch[idx],
              service: this.portServices[batch[idx]] || 'Unknown'
            });
          }
        });
      }
      
      // Report open ports
      if (openPorts.length > 0) {
        // Check for risky open ports
        const riskyOpenPorts = openPorts.filter(p => this.riskyPorts.includes(p.port));
        
        if (riskyOpenPorts.length > 0) {
          for (const rp of riskyOpenPorts) {
            vulnerabilities.push({
              type: 'Network Security',
              subType: 'Risky Port Open',
              severity: this.getPortSeverity(rp.port),
              url: this.targetUrl,
              evidence: `Port ${rp.port} (${rp.service}) is open`,
              description: `Potentially risky port ${rp.port} (${rp.service}) is accessible. This may expose sensitive services.`,
              remediation: 'Restrict access to this port using firewall rules. Only allow trusted IPs.',
              references: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
              ],
              cvss: this.getPortCVSS(rp.port),
              cwe: 'CWE-200'
            });
          }
        }
        
        // Info about all open ports
        vulnerabilities.push({
          type: 'Information',
          subType: 'Open Ports',
          severity: 'info',
          url: this.targetUrl,
          evidence: `Found ${openPorts.length} open ports`,
          description: `Open ports: ${openPorts.map(p => `${p.port} (${p.service})`).join(', ')}`,
          remediation: 'Review all open ports and close unnecessary services.',
          references: [],
          cvss: 1.0,
          cwe: 'CWE-200'
        });
      }
      
    } catch (error) {
      this.log(`Port scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  checkPort(hostname, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      
      socket.setTimeout(2000);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve({ port, open: true });
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ port, open: false });
      });
      
      socket.on('error', () => {
        socket.destroy();
        resolve({ port, open: false });
      });
      
      socket.connect(port, hostname);
    });
  }
  
  getPortSeverity(port) {
    const critical = [23, 6379, 27017, 9200]; // Telnet, Redis, MongoDB, Elasticsearch
    const high = [3389, 5900, 1433, 3306, 5432]; // RDP, VNC, DB ports
    const medium = [21, 445]; // FTP, SMB
    
    if (critical.includes(port)) return 'critical';
    if (high.includes(port)) return 'high';
    if (medium.includes(port)) return 'medium';
    return 'low';
  }
  
  getPortCVSS(port) {
    const severity = this.getPortSeverity(port);
    const mapping = { critical: 9.0, high: 7.0, medium: 5.0, low: 3.0 };
    return mapping[severity] || 3.0;
  }
}
