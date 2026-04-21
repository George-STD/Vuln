import puppeteer from 'puppeteer';
import { URL } from 'url';

export class HeadlessCrawler {
  constructor(options = {}) {
    this.options = {
      timeout: options.timeout || 30000,
      waitUntil: options.waitUntil || 'networkidle2',
      userAgent: options.userAgent || 'VulnHunter Pro/1.0 (Security Scanner)',
      viewport: options.viewport || { width: 1920, height: 1080 },
      maxDepth: options.maxDepth || 3,
      maxUrls: options.maxUrls || 100,
      ...options
    };
    
    this.browser = null;
    this.crawledUrls = new Set();
    this.discoveredUrls = new Set();
    this.forms = [];
    this.apiCalls = [];
    this.jsRoutes = [];
  }

  async init() {
    this.browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920x1080'
      ]
    });
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  async crawl(startUrl) {
    if (!this.browser) {
      await this.init();
    }

    const baseUrl = new URL(startUrl);
    const urlQueue = [{ url: startUrl, depth: 0 }];
    
    while (urlQueue.length > 0 && this.crawledUrls.size < this.options.maxUrls) {
      const { url, depth } = urlQueue.shift();
      
      if (this.crawledUrls.has(url) || depth > this.options.maxDepth) {
        continue;
      }

      try {
        const result = await this.crawlPage(url, baseUrl);
        this.crawledUrls.add(url);
        
        // Add discovered URLs to queue
        for (const newUrl of result.links) {
          if (!this.crawledUrls.has(newUrl) && !this.discoveredUrls.has(newUrl)) {
            this.discoveredUrls.add(newUrl);
            urlQueue.push({ url: newUrl, depth: depth + 1 });
          }
        }
        
        // Collect forms
        this.forms.push(...result.forms);
        
        // Collect API calls
        this.apiCalls.push(...result.apiCalls);
        
        // Collect JS routes
        this.jsRoutes.push(...result.jsRoutes);
        
      } catch (error) {
        console.error(`Error crawling ${url}: ${error.message}`);
      }
    }

    await this.close();

    return {
      urls: Array.from(this.crawledUrls),
      forms: this.forms,
      apiCalls: [...new Set(this.apiCalls)],
      jsRoutes: [...new Set(this.jsRoutes)],
      totalDiscovered: this.discoveredUrls.size
    };
  }

  async crawlPage(url, baseUrl) {
    const page = await this.browser.newPage();
    
    await page.setUserAgent(this.options.userAgent);
    await page.setViewport(this.options.viewport);
    
    // Collect network requests (API calls)
    const apiCalls = [];
    page.on('request', request => {
      const reqUrl = request.url();
      if (reqUrl.includes('/api/') || reqUrl.includes('/v1/') || reqUrl.includes('/v2/')) {
        apiCalls.push({
          url: reqUrl,
          method: request.method(),
          headers: request.headers(),
          postData: request.postData()
        });
      }
    });

    try {
      await page.goto(url, {
        timeout: this.options.timeout,
        waitUntil: this.options.waitUntil
      });

      // Wait for dynamic content
      await page.waitForTimeout(2000);

      // Extract links, forms, and JS routes
      const result = await page.evaluate((baseOrigin) => {
        const links = [];
        const forms = [];
        const jsRoutes = [];

        // Collect all links
        document.querySelectorAll('a[href]').forEach(a => {
          try {
            const href = a.href;
            if (href && href.startsWith(baseOrigin)) {
              links.push(href.split('#')[0].split('?')[0]);
            }
          } catch (e) {}
        });

        // Collect forms
        document.querySelectorAll('form').forEach(form => {
          const inputs = [];
          form.querySelectorAll('input, textarea, select').forEach(input => {
            inputs.push({
              name: input.name || input.id,
              type: input.type || 'text',
              value: input.value || ''
            });
          });
          
          forms.push({
            action: form.action || window.location.href,
            method: (form.method || 'GET').toUpperCase(),
            inputs: inputs
          });
        });

        // Detect SPA routes from common frameworks
        // React Router
        const reactLinks = document.querySelectorAll('[data-reactroot] a, [id="root"] a');
        reactLinks.forEach(a => {
          if (a.href && a.href.startsWith(baseOrigin)) {
            jsRoutes.push(a.href);
          }
        });

        // Vue Router
        const vueLinks = document.querySelectorAll('[data-v-] a, [id="app"] a');
        vueLinks.forEach(a => {
          if (a.href && a.href.startsWith(baseOrigin)) {
            jsRoutes.push(a.href);
          }
        });

        // Angular Router
        const angularLinks = document.querySelectorAll('[ng-] a, [_ngcontent-] a, router-outlet ~ a');
        angularLinks.forEach(a => {
          if (a.href && a.href.startsWith(baseOrigin)) {
            jsRoutes.push(a.href);
          }
        });

        // Look for route definitions in scripts
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
          const content = script.textContent || '';
          
          // Match common route patterns
          const routePatterns = [
            /['"`](\/[\w\-\/\:]+)['"`]/g,  // '/path/to/route'
            /path:\s*['"`](\/[\w\-\/\:]+)['"`]/g,  // path: '/route'
            /route:\s*['"`](\/[\w\-\/\:]+)['"`]/g,  // route: '/route'
          ];
          
          routePatterns.forEach(pattern => {
            let match;
            while ((match = pattern.exec(content)) !== null) {
              const route = match[1];
              if (route && route.length < 100 && !route.includes('{{')) {
                jsRoutes.push(baseOrigin + route);
              }
            }
          });
        });

        // Click handlers that might navigate
        const clickables = document.querySelectorAll('[onclick], [ng-click], [@click], [v-on\\:click]');
        clickables.forEach(el => {
          const onclick = el.getAttribute('onclick') || 
                         el.getAttribute('ng-click') || 
                         el.getAttribute('@click') ||
                         el.getAttribute('v-on:click');
          if (onclick) {
            const routeMatch = onclick.match(/['"`](\/[\w\-\/]+)['"`]/);
            if (routeMatch) {
              jsRoutes.push(baseOrigin + routeMatch[1]);
            }
          }
        });

        return {
          links: [...new Set(links)],
          forms,
          jsRoutes: [...new Set(jsRoutes)]
        };
      }, baseUrl.origin);

      await page.close();

      return {
        ...result,
        apiCalls
      };

    } catch (error) {
      await page.close();
      throw error;
    }
  }

  /**
   * Discover SPA routes by interacting with the page
   */
  async discoverSPARoutes(url) {
    if (!this.browser) {
      await this.init();
    }

    const page = await this.browser.newPage();
    await page.setUserAgent(this.options.userAgent);
    
    const discoveredRoutes = new Set();

    try {
      await page.goto(url, {
        timeout: this.options.timeout,
        waitUntil: this.options.waitUntil
      });

      // Listen for navigation events
      page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) {
          discoveredRoutes.add(frame.url());
        }
      });

      // Click on interactive elements
      const clickableSelectors = [
        'a[href^="/"]',
        'button',
        '[role="button"]',
        '[role="link"]',
        '.nav-link',
        '.menu-item',
        '[data-toggle]'
      ];

      for (const selector of clickableSelectors) {
        try {
          const elements = await page.$$(selector);
          for (const element of elements.slice(0, 10)) {
            try {
              await element.click();
              await page.waitForTimeout(500);
              discoveredRoutes.add(page.url());
              await page.goBack();
              await page.waitForTimeout(300);
            } catch (e) {}
          }
        } catch (e) {}
      }

      await page.close();
      return Array.from(discoveredRoutes);

    } catch (error) {
      await page.close();
      throw error;
    }
  }
}

export default HeadlessCrawler;
