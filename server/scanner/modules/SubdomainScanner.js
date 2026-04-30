import { BaseScanner } from './BaseScanner.js';

export class SubdomainScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Subdomain Scanner';
    
    // Common subdomain wordlist
    this.subdomains = [
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
      'ns', 'dns', 'cpanel', 'whm', 'admin', 'administrator', 'api', 'app',
      'dev', 'development', 'stage', 'staging', 'test', 'testing', 'uat',
      'qa', 'demo', 'beta', 'alpha', 'prod', 'production', 'live',
      'static', 'assets', 'cdn', 'media', 'images', 'img', 'files', 'upload',
      'uploads', 'download', 'downloads', 'backup', 'backups', 'bak',
      'old', 'new', 'legacy', 'archive', 'archives',
      'blog', 'shop', 'store', 'cart', 'checkout', 'pay', 'payment', 'billing',
      'dashboard', 'portal', 'control', 'panel', 'manage', 'management',
      'cms', 'crm', 'erp', 'vpn', 'remote', 'gateway', 'proxy',
      'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'elasticsearch',
      'jenkins', 'gitlab', 'github', 'git', 'svn', 'ci', 'cd', 'build',
      'docs', 'doc', 'documentation', 'wiki', 'help', 'support', 'status',
      'monitor', 'monitoring', 'metrics', 'grafana', 'kibana', 'logs', 'log',
      'auth', 'oauth', 'sso', 'login', 'signin', 'account', 'accounts', 'user', 'users',
      'customer', 'clients', 'partner', 'partners', 'internal', 'intranet', 'extranet',
      'secure', 'security', 'ssl', 'wss', 'ws', 'socket', 'websocket',
      'mobile', 'm', 'app', 'apps', 'android', 'ios',
      'v1', 'v2', 'v3', 'api-v1', 'api-v2', 'rest', 'graphql',
      'mail1', 'mail2', 'mx', 'mx1', 'mx2', 'email', 'newsletter',
      's3', 'aws', 'azure', 'cloud', 'gcp', 'storage',
      'web', 'web1', 'web2', 'server', 'server1', 'server2', 'host', 'node',
      'analytics', 'track', 'tracking', 'pixel', 'ads', 'ad', 'adserver',
      'forum', 'community', 'social', 'chat', 'message', 'messages',
      'search', 'solr', 'sphinx', 'lucene'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const discoveredSubdomains = [];
    
    try {
      const domain = this.extractDomain(this.targetUrl);
      if (!domain) return vulnerabilities;
      
      this.log(`Scanning subdomains for ${domain}...`);
      
      // Test subdomains in parallel batches
      const batchSize = 10;
      for (let i = 0; i < this.subdomains.length && !this.stopped; i += batchSize) {
        const batch = this.subdomains.slice(i, i + batchSize);
        
        const results = await Promise.all(
          batch.map(sub => this.checkSubdomain(sub, domain))
        );
        
        results.forEach(result => {
          if (result) {
            discoveredSubdomains.push(result);
          }
        });
      }
      
      // Report discovered subdomains as info
      const reportableSubdomains = discoveredSubdomains.filter((subdomainInfo) =>
        this.isReportableSubdomainStatus(subdomainInfo.status)
      );

      if (reportableSubdomains.length > 0) {
        vulnerabilities.push({
          type: 'Information Disclosure',
          subType: 'Subdomain Enumeration',
          severity: 'info',
          url: this.targetUrl,
          evidence: `Discovered ${reportableSubdomains.length} reachable subdomains`,
          description: `Found subdomains: ${reportableSubdomains.map(s => s.subdomain).join(', ')}`,
          remediation: 'Review exposed subdomains for sensitive functionality. Consider using DNS CAA records.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information'
          ],
          cvss: 2.0,
          cwe: 'CWE-200',
          details: reportableSubdomains
        });
        
        // Check for interesting/sensitive subdomains
        const sensitiveSubdomains = reportableSubdomains.filter(s => 
          ['admin', 'dev', 'staging', 'test', 'backup', 'internal', 'vpn', 'jenkins', 'gitlab'].some(
            sens => s.subdomain.includes(sens)
          )
        );
        
        if (sensitiveSubdomains.length > 0) {
          vulnerabilities.push({
            type: 'Information Disclosure',
            subType: 'Sensitive Subdomain Exposure',
            severity: 'medium',
            url: this.targetUrl,
            evidence: `Sensitive subdomains found: ${sensitiveSubdomains.map(s => s.subdomain).join(', ')}`,
            description: 'Potentially sensitive subdomains are publicly accessible. These may expose development, admin, or backup systems.',
            remediation: 'Restrict access to sensitive subdomains. Use VPN or IP whitelisting for internal resources.',
            references: [
              'https://portswigger.net/web-security/host-header/exploiting/subdomain-takeover'
            ],
            cvss: 5.0,
            cwe: 'CWE-200'
          });
        }
      }
      
      // Check for subdomain takeover
      const takeoverVulns = await this.checkSubdomainTakeover(discoveredSubdomains);
      vulnerabilities.push(...takeoverVulns);
      
    } catch (error) {
      this.log(`Subdomain scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  async checkSubdomain(subdomain, domain) {
    const fullDomain = `${subdomain}.${domain}`;
    
    try {
      const response = await this.makeRequest(`https://${fullDomain}`, {
        timeout: 5000
      });
      
      if (response && response.status < 500) {
        return {
          subdomain: fullDomain,
          status: response.status,
          server: response.headers['server'],
          https: true
        };
      }
    } catch {}
    
    try {
      const response = await this.makeRequest(`http://${fullDomain}`, {
        timeout: 5000
      });
      
      if (response && response.status < 500) {
        return {
          subdomain: fullDomain,
          status: response.status,
          server: response.headers['server'],
          https: false
        };
      }
    } catch {}
    
    return null;
  }
  
  async checkSubdomainTakeover(subdomains) {
    const vulnerabilities = [];
    
    // Subdomain takeover signatures
    const takeoverSignatures = [
      { service: 'GitHub Pages', pattern: /there isn't a github pages site here/i },
      { service: 'Heroku', pattern: /no such app/i },
      { service: 'AWS S3', pattern: /NoSuchBucket/i },
      { service: 'Shopify', pattern: /sorry, this shop is currently unavailable/i },
      { service: 'Tumblr', pattern: /there's nothing here/i },
      { service: 'WordPress', pattern: /do you want to register/i },
      { service: 'Zendesk', pattern: /help center closed/i },
      { service: 'Bitbucket', pattern: /repository not found/i },
      { service: 'Ghost', pattern: /the thing you were looking for is no longer here/i },
      { service: 'Surge.sh', pattern: /project not found/i },
      { service: 'Fastly', pattern: /fastly error: unknown domain/i },
      { service: 'Pantheon', pattern: /the gods are wise/i },
      { service: 'Unbounce', pattern: /the requested url was not found/i },
      { service: 'Azure', pattern: /404 web site not found/i }
    ];
    
    for (const sub of subdomains) {
      if (this.stopped) break;
      
      try {
        const url = sub.https ? `https://${sub.subdomain}` : `http://${sub.subdomain}`;
        const response = await this.makeRequest(url);
        
        if (!response) continue;
        
        const body = response.data?.toString() || '';
        
        for (const sig of takeoverSignatures) {
          if (sig.pattern.test(body)) {
            vulnerabilities.push({
              type: 'Subdomain Takeover',
              subType: sig.service,
              severity: 'critical',
              url: url,
              evidence: `Subdomain ${sub.subdomain} shows ${sig.service} takeover signature`,
              description: `Subdomain takeover vulnerability. The subdomain points to ${sig.service} but the resource has been released.`,
              remediation: `Remove the DNS record pointing to ${sig.service} or reclaim the resource.`,
              references: [
                'https://portswigger.net/web-security/host-header/exploiting/subdomain-takeover',
                'https://github.com/EdOverflow/can-i-take-over-xyz'
              ],
              cvss: 9.0,
              cwe: 'CWE-284'
            });
            break;
          }
        }
      } catch (error) {
        this.log(`Takeover check error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }

  isReportableSubdomainStatus(status) {
    return [200, 201, 204, 301, 302, 307, 308].includes(Number(status));
  }
}
