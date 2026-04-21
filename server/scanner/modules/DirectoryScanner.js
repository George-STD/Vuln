import { BaseScanner } from './BaseScanner.js';

export class DirectoryScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Directory Scanner';
    
    // Common sensitive directories and files
    this.paths = [
      // Admin panels
      '/admin', '/admin/', '/administrator/', '/admin.php', '/admin.html',
      '/wp-admin/', '/wp-login.php', '/adminpanel/', '/controlpanel/',
      '/manage/', '/management/', '/manager/', '/cpanel/', '/phpmyadmin/',
      
      // Backup files
      '/backup/', '/backups/', '/backup.zip', '/backup.tar.gz', '/backup.sql',
      '/db.sql', '/database.sql', '/dump.sql', '/.sql', '/site.zip',
      '/www.zip', '/web.zip', '/backup.rar', '/old/', '/bak/',
      
      // Configuration files
      '/.env', '/config.php', '/configuration.php', '/settings.php',
      '/config.yml', '/config.yaml', '/config.json', '/config.xml',
      '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
      '/web.config', '/appsettings.json', '/database.yml', '/.htaccess',
      '/.htpasswd', '/php.ini', '/.user.ini',
      
      // Version control
      '/.git/', '/.git/config', '/.git/HEAD', '/.gitignore',
      '/.svn/', '/.svn/entries', '/.hg/', '/.bzr/',
      
      // IDE and dev files
      '/.idea/', '/.vscode/', '/.DS_Store', '/Thumbs.db',
      '/.project', '/.settings/', '/nbproject/', '/.buildpath',
      
      // Debug and log files
      '/debug.log', '/error.log', '/access.log', '/debug/', '/logs/',
      '/log/', '/error_log', '/errors.txt', '/debug.txt',
      '/server.log', '/app.log', '/application.log',
      
      // Source code
      '/source/', '/src/', '/app/', '/application/', '/includes/',
      '/inc/', '/lib/', '/library/', '/classes/', '/core/',
      '/index.php~', '/index.php.bak', '/index.php.old',
      
      // API documentation
      '/swagger/', '/swagger-ui/', '/api-docs/', '/swagger.json',
      '/openapi.json', '/api/swagger/', '/docs/', '/documentation/',
      '/graphql', '/graphiql', '/__graphql',
      
      // Framework specific
      '/composer.json', '/composer.lock', '/package.json', '/package-lock.json',
      '/yarn.lock', '/Gemfile', '/Gemfile.lock', '/requirements.txt',
      '/Pipfile', '/Pipfile.lock', '/go.mod', '/go.sum',
      
      // Common info disclosure
      '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
      '/phpinfo.php', '/info.php', '/test.php', '/i.php', '/php_info.php',
      '/server-status', '/server-info', '/.well-known/',
      
      // Database interfaces
      '/phpmyadmin/', '/pma/', '/myadmin/', '/mysql/', '/phpMyAdmin/',
      '/adminer/', '/adminer.php', '/db/', '/dbadmin/',
      
      // File upload directories
      '/upload/', '/uploads/', '/files/', '/attachments/', '/media/',
      '/images/', '/img/', '/assets/', '/static/', '/public/',
      
      // User data
      '/users/', '/user/', '/members/', '/customers/', '/clients/',
      '/accounts/', '/profiles/', '/data/', '/export/',
      
      // Cron and scripts
      '/cron/', '/cron.php', '/scripts/', '/batch/', '/jobs/',
      
      // Install and setup
      '/install/', '/setup/', '/installer/', '/install.php', '/setup.php',
      
      // Temp files
      '/temp/', '/tmp/', '/cache/', '/session/', '/sessions/',
      
      // API endpoints
      '/api/', '/api/v1/', '/api/v2/', '/rest/', '/json/', '/xml/',
      '/webservice/', '/ws/', '/service/', '/services/',
      
      // Cloud/DevOps
      '/.aws/', '/.docker/', '/docker-compose.yml', '/Dockerfile',
      '/.kubernetes/', '/k8s/', '/terraform/', '/.terraform/',
      '/ansible/', '/playbook.yml', '/.circleci/', '/.github/',
      '/Jenkinsfile', '/jenkins/', '/.travis.yml', '/bitbucket-pipelines.yml'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const discoveredPaths = [];
    
    try {
      const baseUrl = new URL(this.targetUrl).origin;
      
      this.log(`Scanning directories for ${baseUrl}...`);
      
      // Get baseline 404 response
      const baseline404 = await this.getBaseline404(baseUrl);
      
      // Test paths in parallel batches
      const batchSize = 10;
      for (let i = 0; i < this.paths.length && !this.stopped; i += batchSize) {
        const batch = this.paths.slice(i, i + batchSize);
        
        const results = await Promise.all(
          batch.map(path => this.checkPath(baseUrl, path, baseline404))
        );
        
        results.forEach(result => {
          if (result && result.found) {
            discoveredPaths.push(result);
            
            // Create vulnerability for sensitive findings
            const vuln = this.categorizeDiscovery(result);
            if (vuln) vulnerabilities.push(vuln);
          }
        });
      }
      
      // Summary of all discovered paths
      if (discoveredPaths.length > 0) {
        this.log(`Found ${discoveredPaths.length} accessible paths`);
      }
      
    } catch (error) {
      this.log(`Directory scan error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  async getBaseline404(baseUrl) {
    try {
      const randomPath = `/nonexistent_${Math.random().toString(36).substring(7)}`;
      const response = await this.makeRequest(`${baseUrl}${randomPath}`);
      
      if (response) {
        return {
          status: response.status,
          length: response.data?.length || 0
        };
      }
    } catch {}
    
    return { status: 404, length: 0 };
  }
  
  async checkPath(baseUrl, path, baseline404) {
    try {
      const url = `${baseUrl}${path}`;
      const response = await this.makeRequest(url, { timeout: 5000 });
      
      if (!response) return null;
      
      const status = response.status;
      const length = response.data?.length || 0;
      
      // Determine if path exists
      if (status === 200 || status === 301 || status === 302 || status === 403) {
        // Exclude if same as 404 baseline
        if (status === baseline404.status && Math.abs(length - baseline404.length) < 100) {
          return null;
        }
        
        return {
          found: true,
          path: path,
          url: url,
          status: status,
          length: length,
          contentType: response.headers['content-type'],
          server: response.headers['server']
        };
      }
      
      return null;
    } catch {
      return null;
    }
  }
  
  categorizeDiscovery(result) {
    const path = result.path.toLowerCase();
    const url = result.url;
    
    // Git exposure
    if (path.includes('.git')) {
      return {
        type: 'Information Disclosure',
        subType: 'Git Repository Exposure',
        severity: 'critical',
        url: url,
        evidence: `Git repository accessible at ${path}`,
        description: 'Git repository is exposed. Source code and commit history may be downloadable.',
        remediation: 'Block access to .git directory in web server configuration.',
        references: [
          'https://portswigger.net/kb/issues/00600800_source-code-disclosure-in-git-folder'
        ],
        cvss: 9.0,
        cwe: 'CWE-527'
      };
    }
    
    // Environment files
    if (path.includes('.env') || path.includes('config') && path.includes('.')) {
      return {
        type: 'Information Disclosure',
        subType: 'Configuration File Exposure',
        severity: 'critical',
        url: url,
        evidence: `Configuration file accessible at ${path}`,
        description: 'Configuration file is publicly accessible. May contain credentials and sensitive settings.',
        remediation: 'Block access to configuration files. Move them outside web root.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces'
        ],
        cvss: 9.0,
        cwe: 'CWE-200'
      };
    }
    
    // Backup files
    if (path.includes('backup') || path.includes('.sql') || 
        path.includes('.zip') || path.includes('.tar') || path.includes('.bak')) {
      return {
        type: 'Information Disclosure',
        subType: 'Backup File Exposure',
        severity: 'high',
        url: url,
        evidence: `Backup file accessible at ${path}`,
        description: 'Backup file is publicly accessible. May contain source code or database dumps.',
        remediation: 'Remove backup files from web-accessible directories.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'
        ],
        cvss: 7.5,
        cwe: 'CWE-530'
      };
    }
    
    // Admin panels
    if (path.includes('admin') || path.includes('phpmyadmin') || 
        path.includes('cpanel') || path.includes('manage')) {
      return {
        type: 'Information Disclosure',
        subType: 'Admin Panel Exposure',
        severity: 'medium',
        url: url,
        evidence: `Admin panel found at ${path}`,
        description: 'Administrative interface is accessible. Should be restricted to authorized users.',
        remediation: 'Restrict access to admin panels via IP whitelisting or VPN.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces'
        ],
        cvss: 5.0,
        cwe: 'CWE-200'
      };
    }
    
    // phpinfo
    if (path.includes('phpinfo') || path.includes('info.php')) {
      return {
        type: 'Information Disclosure',
        subType: 'PHP Info Exposure',
        severity: 'medium',
        url: url,
        evidence: `PHP info page at ${path}`,
        description: 'PHP configuration is exposed. Reveals system and configuration details.',
        remediation: 'Remove phpinfo files from production servers.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
        ],
        cvss: 5.0,
        cwe: 'CWE-200'
      };
    }
    
    // API documentation
    if (path.includes('swagger') || path.includes('api-docs') || 
        path.includes('graphql') || path.includes('graphiql')) {
      return {
        type: 'Information Disclosure',
        subType: 'API Documentation Exposure',
        severity: 'low',
        url: url,
        evidence: `API documentation at ${path}`,
        description: 'API documentation is publicly accessible.',
        remediation: 'Consider restricting access to API documentation in production.',
        references: [
          'https://owasp.org/www-project-api-security/'
        ],
        cvss: 3.0,
        cwe: 'CWE-200'
      };
    }
    
    // Log files
    if (path.includes('log') || path.includes('.log')) {
      return {
        type: 'Information Disclosure',
        subType: 'Log File Exposure',
        severity: 'medium',
        url: url,
        evidence: `Log file accessible at ${path}`,
        description: 'Log files are publicly accessible. May contain sensitive data.',
        remediation: 'Block access to log files and store them outside web root.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'
        ],
        cvss: 5.0,
        cwe: 'CWE-532'
      };
    }
    
    // Install pages
    if (path.includes('install') || path.includes('setup')) {
      if (result.status === 200) {
        return {
          type: 'Misconfiguration',
          subType: 'Installation Page Accessible',
          severity: 'high',
          url: url,
          evidence: `Installation page at ${path}`,
          description: 'Installation/setup page is still accessible. Could allow reinstallation.',
          remediation: 'Remove or protect installation files after setup.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
          ],
          cvss: 7.5,
          cwe: 'CWE-489'
        };
      }
    }
    
    // Default info severity for other discoveries
    return {
      type: 'Directory/File Discovery',
      subType: 'Path Accessible',
      severity: 'info',
      url: url,
      evidence: `Path accessible: ${path} (Status: ${result.status})`,
      description: `Discovered accessible path: ${path}`,
      remediation: 'Review if this path should be publicly accessible.',
      references: [],
      cvss: 1.0,
      cwe: 'CWE-200'
    };
  }
}
