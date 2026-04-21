import { BaseScanner } from './BaseScanner.js';
import crypto from 'crypto';

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
      
      /**
       * CATCH-ALL FINGERPRINTER:
       * Many enterprise targets (e.g., Google, Cloudflare, AWS) return a custom
       * "soft 404" or "catch-all" error page with a 200 OK status for ANY path.
       * The old single-probe baseline was insufficient because:
       *   1. A single probe can't establish variance (some servers return slightly
       *      different content per request due to timestamps, nonces, etc.)
       *   2. A simple length comparison with a fixed delta (100 bytes) missed pages
       *      with dynamic content that varied by more than 100 bytes.
       *
       * NEW APPROACH — Multi-probe baseline with content hashing:
       *   - Request 3 guaranteed-nonexistent, highly randomized paths.
       *   - Collect status, content length, and content hash for each.
       *   - Use these as a fingerprint set for the "not found" response.
       *   - When evaluating a discovery, compare against ALL baselines using
       *     content hash similarity (not just length delta).
       */
      const baselineFingerprints = await this.buildBaselineFingerprints(baseUrl);
      
      // Test paths in parallel batches
      const batchSize = 10;
      for (let i = 0; i < this.paths.length && !this.stopped; i += batchSize) {
        const batch = this.paths.slice(i, i + batchSize);
        
        const results = await Promise.all(
          batch.map(path => this.checkPath(baseUrl, path, baselineFingerprints))
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
  
  /**
   * Build baseline fingerprints by probing multiple guaranteed-nonexistent paths.
   * Uses crypto.randomUUID() for truly random path segments that cannot collide
   * with real resources.
   * 
   * @param {string} baseUrl - The origin URL to probe against
   * @returns {Promise<Object>} Fingerprint data with status codes, lengths, and content hashes
   */
  async buildBaselineFingerprints(baseUrl) {
    const probeCount = 3;
    const fingerprints = [];

    this.log('Building catch-all baseline fingerprints with 3 random probes...', 'debug');

    for (let i = 0; i < probeCount; i++) {
      try {
        // Generate a highly random path that cannot possibly exist on any server
        const randomSlug = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);
        const probePath = `/vulnhunter_fp_${randomSlug}_${Date.now()}`;
        const response = await this.makeRequest(`${baseUrl}${probePath}`);
        
        if (response) {
          const bodyStr = response.data ? response.data.toString() : '';
          fingerprints.push({
            status: response.status,
            length: bodyStr.length,
            // Content hash for exact-match comparison
            contentHash: this.hashContent(bodyStr),
            // Normalized content hash (strips dynamic tokens like timestamps, nonces, CSRF tokens)
            normalizedHash: this.hashContent(this.normalizeContent(bodyStr))
          });
        }
      } catch (err) {
        this.log(`Baseline probe ${i + 1} failed: ${err.message}`, 'debug');
      }
    }

    // If we got no fingerprints at all, fall back to a safe default
    if (fingerprints.length === 0) {
      this.log('All baseline probes failed. Using conservative defaults.', 'debug');
      return {
        fingerprints: [{ status: 404, length: 0, contentHash: '', normalizedHash: '' }],
        avgLength: 0,
        lengthVariance: 0
      };
    }

    // Calculate average length and variance across probes to understand how much
    // the catch-all page varies between requests
    const lengths = fingerprints.map(f => f.length);
    const avgLength = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const lengthVariance = Math.max(...lengths) - Math.min(...lengths);

    this.log(`Baseline fingerprints: ${fingerprints.length} probes, avg length=${avgLength.toFixed(0)}, variance=${lengthVariance}`, 'debug');

    return {
      fingerprints,
      avgLength,
      lengthVariance
    };
  }

  /**
   * Simple djb2 hash of content string for fast comparison.
   * Not cryptographic — used only for content similarity checks.
   */
  hashContent(content) {
    if (!content) return '';
    let hash = 5381;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) + hash) + content.charCodeAt(i);
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Normalize HTML content by removing dynamic elements that change per request.
   * This handles servers that inject timestamps, nonces, CSRF tokens, or request IDs
   * into their error pages, which would cause exact hash comparisons to fail.
   */
  normalizeContent(content) {
    if (!content) return '';
    return content
      // Remove common dynamic tokens: timestamps, UUIDs, hex nonces, CSRF tokens
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '') // UUIDs
      .replace(/\b\d{10,13}\b/g, '')       // Unix timestamps (10-13 digits)
      .replace(/nonce="[^"]*"/gi, '')       // CSP nonces
      .replace(/csrf[_-]?token[^"]*"[^"]*"/gi, '') // CSRF tokens
      .replace(/\s+/g, ' ')                 // Normalize whitespace
      .trim();
  }

  /**
   * Check if a response matches the catch-all baseline fingerprints.
   * Uses a multi-signal approach: status code, content hash, normalized hash,
   * and length similarity.
   * 
   * @returns {boolean} true if the response looks like a catch-all/soft-404 page
   */
  matchesBaseline(status, bodyStr, baselineFingerprints) {
    const { fingerprints, avgLength, lengthVariance } = baselineFingerprints;
    const responseHash = this.hashContent(bodyStr);
    const responseNormalizedHash = this.hashContent(this.normalizeContent(bodyStr));
    const responseLength = bodyStr.length;

    for (const fp of fingerprints) {
      // ── Signal 1: Exact content hash match ──
      // If the response body is byte-for-byte identical to a baseline probe,
      // it's almost certainly the same catch-all page.
      if (responseHash === fp.contentHash && fp.contentHash !== '') {
        return true;
      }

      // ── Signal 2: Normalized content hash match ──
      // Catches catch-all pages with dynamic tokens (timestamps, nonces)
      // that change per request but have the same structural content.
      if (responseNormalizedHash === fp.normalizedHash && fp.normalizedHash !== '') {
        return true;
      }

      // ── Signal 3: Status + length similarity ──
      // If the status matches a baseline AND the length is within the observed
      // variance range (plus a tolerance), it's likely the same page.
      // The tolerance accounts for minor dynamic changes we didn't normalize.
      if (status === fp.status) {
        const tolerance = Math.max(200, lengthVariance * 2);
        if (Math.abs(responseLength - fp.length) < tolerance) {
          return true;
        }
      }
    }

    return false;
  }
  
  async checkPath(baseUrl, path, baselineFingerprints) {
    try {
      const url = `${baseUrl}${path}`;
      const response = await this.makeRequest(url, { timeout: 5000 });
      
      if (!response) return null;
      
      const status = response.status;
      const bodyStr = response.data ? response.data.toString() : '';
      const length = bodyStr.length;
      
      // Determine if path exists
      if (status === 200 || status === 301 || status === 302 || status === 403) {
        /**
         * CATCH-ALL DETECTION:
         * Before accepting this as a real discovery, compare the response
         * against our baseline fingerprints. If it matches the catch-all
         * signature, discard it as a false positive.
         *
         * This is critical for enterprise targets like Google, GitHub, etc.
         * that return styled 200 OK pages for any path.
         */
        if (this.matchesBaseline(status, bodyStr, baselineFingerprints)) {
          this.log(`Catch-all FP discarded: ${path} (matches baseline fingerprint)`, 'debug');
          return null;
        }

        /**
         * CONTENT VALIDATION:
         * Additional heuristic — if the response body contains common
         * "not found" indicators despite returning 200 OK, discard it.
         * This catches custom error pages that our fingerprinter might miss
         * if they have per-request dynamic content.
         */
        if (status === 200 && this.looksLikeErrorPage(bodyStr)) {
          this.log(`Soft-404 FP discarded: ${path} (content looks like error page)`, 'debug');
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

  /**
   * Heuristic check: does this 200 OK response body look like a "Not Found" page?
   * Many servers return custom error pages with 200 status codes.
   * We check for common error-page language patterns.
   */
  looksLikeErrorPage(bodyStr) {
    if (!bodyStr || bodyStr.length < 50) return false;
    
    const lowerBody = bodyStr.toLowerCase();
    const errorIndicators = [
      'page not found',
      '404 not found',
      'not found',
      'does not exist',
      'could not be found',
      'no longer available',
      'the page you requested',
      'error 404',
      'we couldn\'t find',
      'nothing here',
      'page doesn\'t exist',
      'الصفحة غير موجودة' // Arabic "page not found"
    ];

    // Count how many error indicators appear. A single match could be coincidental
    // (e.g., a page about handling 404 errors), so we require context.
    let matchCount = 0;
    for (const indicator of errorIndicators) {
      if (lowerBody.includes(indicator)) matchCount++;
    }

    // If 2+ error indicators are found AND the page is relatively short,
    // it's almost certainly a custom error page.
    if (matchCount >= 2) return true;

    // Single match + short page (< 5KB) is also suspicious
    if (matchCount === 1 && bodyStr.length < 5000) return true;

    return false;
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
