import { BaseScanner } from './BaseScanner.js';
import https from 'https';

export class SSLScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'SSL/TLS Scanner';
  }
  
  async scan(data) {
    const vulnerabilities = [];
    
    try {
      const url = new URL(this.targetUrl);
      
      if (url.protocol !== 'https:') {
        return vulnerabilities;
      }
      
      const sslInfo = await this.getSSLInfo(url.hostname, url.port || 443);
      
      if (sslInfo) {
        // Check certificate validity
        const certVulns = this.analyzeCertificate(sslInfo);
        vulnerabilities.push(...certVulns);
      }
      
    } catch (error) {
      this.log(`SSL scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  getSSLInfo(hostname, port) {
    return new Promise((resolve) => {
      const options = {
        hostname,
        port: port,
        method: 'GET',
        path: '/',
        rejectUnauthorized: false,
        timeout: 10000
      };
      
      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          resolve({
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint: cert.fingerprint,
            fingerprint256: cert.fingerprint256,
            subjectaltname: cert.subjectaltname,
            authorized: res.socket.authorized
          });
        } else {
          resolve(null);
        }
      });
      
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
      
      req.end();
    });
  }
  
  analyzeCertificate(sslInfo) {
    const vulnerabilities = [];
    
    // Check expiration
    const validTo = new Date(sslInfo.validTo);
    const now = new Date();
    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiry < 0) {
      vulnerabilities.push({
        type: 'SSL/TLS',
        subType: 'Expired Certificate',
        severity: 'critical',
        url: this.targetUrl,
        evidence: `Certificate expired on ${sslInfo.validTo}`,
        description: 'The SSL certificate has expired. Browsers will show security warnings.',
        remediation: 'Renew the SSL certificate immediately.',
        references: [
          'https://letsencrypt.org/'
        ],
        cvss: 7.5,
        cwe: 'CWE-295'
      });
    } else if (daysUntilExpiry < 30) {
      vulnerabilities.push({
        type: 'SSL/TLS',
        subType: 'Certificate Expiring Soon',
        severity: 'medium',
        url: this.targetUrl,
        evidence: `Certificate expires in ${daysUntilExpiry} days (${sslInfo.validTo})`,
        description: 'The SSL certificate will expire soon.',
        remediation: 'Renew the SSL certificate before expiration.',
        references: [],
        cvss: 4.0,
        cwe: 'CWE-295'
      });
    }
    
    // Check if self-signed
    if (sslInfo.issuer && sslInfo.subject) {
      const issuerCN = sslInfo.issuer.CN || '';
      const subjectCN = sslInfo.subject.CN || '';
      
      if (issuerCN === subjectCN) {
        vulnerabilities.push({
          type: 'SSL/TLS',
          subType: 'Self-Signed Certificate',
          severity: 'medium',
          url: this.targetUrl,
          evidence: `Certificate issued by: ${issuerCN}`,
          description: 'The SSL certificate appears to be self-signed. Browsers will show security warnings.',
          remediation: 'Use a certificate from a trusted Certificate Authority.',
          references: [
            'https://letsencrypt.org/'
          ],
          cvss: 5.0,
          cwe: 'CWE-295'
        });
      }
    }
    
    // Check for weak signature
    if (sslInfo.fingerprint) {
      // SHA-1 fingerprint indicates potential SHA-1 signing
      if (sslInfo.fingerprint.length < 60 && !sslInfo.fingerprint256) {
        vulnerabilities.push({
          type: 'SSL/TLS',
          subType: 'Weak Certificate Signature',
          severity: 'medium',
          url: this.targetUrl,
          evidence: 'Certificate may use weak SHA-1 signature',
          description: 'The certificate may be signed with SHA-1, which is considered weak.',
          remediation: 'Use a certificate with SHA-256 or stronger signature.',
          references: [],
          cvss: 4.0,
          cwe: 'CWE-326'
        });
      }
    }
    
    // Check authorization
    if (!sslInfo.authorized) {
      vulnerabilities.push({
        type: 'SSL/TLS',
        subType: 'Certificate Not Trusted',
        severity: 'high',
        url: this.targetUrl,
        evidence: 'Certificate is not authorized/trusted',
        description: 'The SSL certificate is not trusted by the system.',
        remediation: 'Use a valid certificate from a trusted Certificate Authority.',
        references: [],
        cvss: 6.5,
        cwe: 'CWE-295'
      });
    }
    
    return vulnerabilities;
  }
}
