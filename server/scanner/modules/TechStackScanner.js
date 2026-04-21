import { BaseScanner } from './BaseScanner.js';

export class TechStackScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'Technology Stack Scanner';
  }
  
  async scan(data) {
    const technologies = {
      frameworks: [],
      cms: [],
      servers: [],
      languages: [],
      libraries: [],
      analytics: [],
      cdn: [],
      security: [],
      other: []
    };
    
    try {
      const response = await this.makeRequest(this.targetUrl);
      if (!response) return technologies;
      
      const headers = response.headers;
      const html = response.data?.toString() || '';
      
      // Detect from headers
      this.detectFromHeaders(headers, technologies);
      
      // Detect from HTML
      this.detectFromHTML(html, technologies);
      
      // Detect from cookies
      this.detectFromCookies(headers['set-cookie'], technologies);
      
    } catch (error) {
      this.log(`Tech stack scan error: ${error.message}`, 'debug');
    }
    
    return technologies;
  }
  
  detectFromHeaders(headers, tech) {
    // Server
    if (headers['server']) {
      const server = headers['server'];
      tech.servers.push(server);
      
      if (/nginx/i.test(server)) tech.servers.push('Nginx');
      if (/apache/i.test(server)) tech.servers.push('Apache');
      if (/iis/i.test(server)) tech.servers.push('Microsoft IIS');
      if (/cloudflare/i.test(server)) tech.cdn.push('Cloudflare');
      if (/gunicorn/i.test(server)) tech.languages.push('Python');
    }
    
    // X-Powered-By
    if (headers['x-powered-by']) {
      const poweredBy = headers['x-powered-by'];
      tech.languages.push(poweredBy);
      
      if (/php/i.test(poweredBy)) tech.languages.push('PHP');
      if (/asp\.net/i.test(poweredBy)) tech.languages.push('ASP.NET');
      if (/express/i.test(poweredBy)) tech.frameworks.push('Express.js');
      if (/next\.js/i.test(poweredBy)) tech.frameworks.push('Next.js');
    }
    
    // CDN detection
    if (headers['cf-ray']) tech.cdn.push('Cloudflare');
    if (headers['x-amz-cf-id']) tech.cdn.push('Amazon CloudFront');
    if (headers['x-cache'] && /HIT.*Fastly/i.test(headers['x-cache'])) tech.cdn.push('Fastly');
    if (headers['x-served-by'] && /cache/i.test(headers['x-served-by'])) tech.cdn.push('Varnish');
    
    // Security products
    if (headers['x-sucuri-id']) tech.security.push('Sucuri');
    if (headers['x-waf-status']) tech.security.push('WAF Detected');
  }
  
  detectFromHTML(html, tech) {
    // WordPress
    if (/wp-content|wp-includes|wordpress/i.test(html)) {
      tech.cms.push('WordPress');
      tech.languages.push('PHP');
    }
    
    // Drupal
    if (/drupal|sites\/default/i.test(html)) {
      tech.cms.push('Drupal');
      tech.languages.push('PHP');
    }
    
    // Joomla
    if (/joomla|\/media\/system\/js/i.test(html)) {
      tech.cms.push('Joomla');
      tech.languages.push('PHP');
    }
    
    // Shopify
    if (/cdn\.shopify\.com|shopify/i.test(html)) {
      tech.cms.push('Shopify');
    }
    
    // Wix
    if (/wix\.com|wixsite/i.test(html)) {
      tech.cms.push('Wix');
    }
    
    // React
    if (/react|__react|data-reactroot|_reactRootContainer/i.test(html)) {
      tech.frameworks.push('React');
    }
    
    // Vue.js
    if (/vue\.js|v-cloak|data-v-|vue-/i.test(html)) {
      tech.frameworks.push('Vue.js');
    }
    
    // Angular
    if (/ng-version|angular|ng-app|ng-controller/i.test(html)) {
      tech.frameworks.push('Angular');
    }
    
    // Next.js
    if (/__NEXT_DATA__|next\.js|_next\//i.test(html)) {
      tech.frameworks.push('Next.js');
    }
    
    // Nuxt.js
    if (/__NUXT__|nuxt\.js|_nuxt\//i.test(html)) {
      tech.frameworks.push('Nuxt.js');
    }
    
    // jQuery
    if (/jquery/i.test(html)) {
      tech.libraries.push('jQuery');
    }
    
    // Bootstrap
    if (/bootstrap/i.test(html)) {
      tech.libraries.push('Bootstrap');
    }
    
    // Tailwind
    if (/tailwind|tw-/i.test(html)) {
      tech.libraries.push('Tailwind CSS');
    }
    
    // Google Analytics
    if (/google-analytics|ga\.js|gtag|analytics\.js/i.test(html)) {
      tech.analytics.push('Google Analytics');
    }
    
    // Google Tag Manager
    if (/googletagmanager|gtm\.js/i.test(html)) {
      tech.analytics.push('Google Tag Manager');
    }
    
    // Facebook Pixel
    if (/facebook\.net\/.*\/fbevents|fbq\(/i.test(html)) {
      tech.analytics.push('Facebook Pixel');
    }
    
    // reCAPTCHA
    if (/recaptcha|grecaptcha/i.test(html)) {
      tech.security.push('Google reCAPTCHA');
    }
    
    // Cloudflare
    if (/cloudflare|__cf_bm/i.test(html)) {
      tech.cdn.push('Cloudflare');
    }
    
    // Laravel
    if (/laravel|csrf-token.*content.*[A-Za-z0-9]{40}/i.test(html)) {
      tech.frameworks.push('Laravel');
      tech.languages.push('PHP');
    }
    
    // Django
    if (/csrfmiddlewaretoken|django/i.test(html)) {
      tech.frameworks.push('Django');
      tech.languages.push('Python');
    }
    
    // Ruby on Rails
    if (/csrf-token|rails|ruby/i.test(html)) {
      tech.frameworks.push('Ruby on Rails');
      tech.languages.push('Ruby');
    }
    
    // ASP.NET
    if (/__VIEWSTATE|__EVENTVALIDATION|aspnet/i.test(html)) {
      tech.frameworks.push('ASP.NET');
      tech.languages.push('C#/.NET');
    }
    
    // Strapi
    if (/strapi/i.test(html)) {
      tech.cms.push('Strapi');
    }
    
    // GraphQL
    if (/graphql/i.test(html)) {
      tech.other.push('GraphQL');
    }
  }
  
  detectFromCookies(setCookie, tech) {
    if (!setCookie) return;
    
    const cookies = Array.isArray(setCookie) ? setCookie.join(' ') : setCookie;
    
    // PHP Session
    if (/PHPSESSID/i.test(cookies)) {
      tech.languages.push('PHP');
    }
    
    // ASP.NET Session
    if (/ASP\.NET_SessionId|\.ASPXAUTH/i.test(cookies)) {
      tech.languages.push('ASP.NET');
    }
    
    // Java
    if (/JSESSIONID/i.test(cookies)) {
      tech.languages.push('Java');
    }
    
    // WordPress
    if (/wordpress_logged_in/i.test(cookies)) {
      tech.cms.push('WordPress');
    }
    
    // Django
    if (/sessionid.*csrftoken/i.test(cookies)) {
      tech.frameworks.push('Django');
    }
    
    // Laravel
    if (/laravel_session/i.test(cookies)) {
      tech.frameworks.push('Laravel');
    }
    
    // Express.js
    if (/connect\.sid/i.test(cookies)) {
      tech.frameworks.push('Express.js');
    }
  }
}
