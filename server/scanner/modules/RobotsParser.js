import axios from 'axios';

export class RobotsParser {
  constructor(targetUrl, options = {}) {
    this.targetUrl = targetUrl;
    this.options = options;
    this.rules = {
      allowed: [],
      disallowed: [],
      sitemaps: [],
      crawlDelay: null
    };
    this.parsed = false;
  }
  
  async parse() {
    try {
      const parsedUrl = new URL(this.targetUrl);
      const robotsUrl = `${parsedUrl.origin}/robots.txt`;
      
      const response = await axios.get(robotsUrl, {
        timeout: 10000,
        validateStatus: (status) => status < 500,
        headers: {
          'User-Agent': this.options.userAgent || 'VulnHunter Pro/1.0'
        }
      });
      
      if (response.status !== 200) {
        this.parsed = true;
        return this.rules;
      }
      
      const content = response.data;
      this.parseContent(content);
      this.parsed = true;
      
      return this.rules;
      
    } catch (error) {
      this.parsed = true;
      return this.rules;
    }
  }
  
  parseContent(content) {
    const lines = content.split('\n');
    let isRelevantUserAgent = false;
    
    for (let line of lines) {
      line = line.trim();
      
      // Skip comments and empty lines
      if (!line || line.startsWith('#')) continue;
      
      const [directive, ...valueParts] = line.split(':');
      const value = valueParts.join(':').trim();
      
      if (!directive || !value) continue;
      
      const lowerDirective = directive.toLowerCase().trim();
      
      switch (lowerDirective) {
        case 'user-agent':
          isRelevantUserAgent = value === '*' || 
            value.toLowerCase().includes('vulnhunter') ||
            value.toLowerCase().includes('bot');
          break;
          
        case 'disallow':
          if (value) {
            this.rules.disallowed.push(this.normalizePattern(value));
          }
          break;
          
        case 'allow':
          if (value) {
            this.rules.allowed.push(this.normalizePattern(value));
          }
          break;
          
        case 'sitemap':
          this.rules.sitemaps.push(value);
          break;
          
        case 'crawl-delay':
          const delay = parseInt(value);
          if (!isNaN(delay)) {
            this.rules.crawlDelay = delay * 1000; // Convert to ms
          }
          break;
      }
    }
  }
  
  normalizePattern(pattern) {
    // Convert robots.txt wildcards to regex
    return pattern
      .replace(/\*/g, '.*')
      .replace(/\$/g, '$')
      .replace(/\?/g, '\\?');
  }
  
  isAllowed(url) {
    if (!this.parsed) return true;
    
    try {
      const parsedUrl = new URL(url);
      const path = parsedUrl.pathname + parsedUrl.search;
      
      // Check allowed first (more specific)
      for (const pattern of this.rules.allowed) {
        const regex = new RegExp(`^${pattern}`);
        if (regex.test(path)) {
          return true;
        }
      }
      
      // Check disallowed
      for (const pattern of this.rules.disallowed) {
        const regex = new RegExp(`^${pattern}`);
        if (regex.test(path)) {
          return false;
        }
      }
      
      return true;
      
    } catch {
      return true;
    }
  }
  
  isDisallowed(url) {
    return !this.isAllowed(url);
  }
  
  getCrawlDelay() {
    return this.rules.crawlDelay;
  }
  
  getSitemaps() {
    return this.rules.sitemaps;
  }
  
  getDisallowedPaths() {
    return this.rules.disallowed;
  }
  
  getSummary() {
    return {
      hasRobotsTxt: this.rules.disallowed.length > 0 || this.rules.allowed.length > 0,
      disallowedCount: this.rules.disallowed.length,
      allowedCount: this.rules.allowed.length,
      sitemapsCount: this.rules.sitemaps.length,
      crawlDelay: this.rules.crawlDelay,
      sitemaps: this.rules.sitemaps
    };
  }
}
