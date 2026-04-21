import { BaseScanner } from './BaseScanner.js';

export class WAFDetector extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'WAF/CDN Detector';
  }
  
  // WAF signatures database
  wafSignatures = {
    // Cloud WAFs
    'Cloudflare': {
      headers: ['cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid'],
      cookies: ['__cfduid', '__cf_bm'],
      bodyPatterns: [/cloudflare/i, /cf-ray/i, /attention required/i],
      serverHeader: /cloudflare/i
    },
    'AWS WAF': {
      headers: ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-id-2'],
      cookies: ['awsalb', 'awsalbcors'],
      bodyPatterns: [/aws/i, /amazon/i],
      serverHeader: /amazons3|cloudfront/i
    },
    'Akamai': {
      headers: ['akamai-origin-hop', 'x-akamai-transformed', 'x-akamai-session-info'],
      cookies: ['akamai', 'ak_bmsc'],
      bodyPatterns: [/akamai/i, /access denied.*akamai/i],
      serverHeader: /akamaighost|akamai/i
    },
    'Sucuri': {
      headers: ['x-sucuri-id', 'x-sucuri-cache'],
      cookies: ['sucuri_cloudproxy'],
      bodyPatterns: [/sucuri/i, /sucuri website firewall/i],
      serverHeader: /sucuri/i
    },
    'Imperva/Incapsula': {
      headers: ['x-iinfo', 'x-cdn'],
      cookies: ['visid_incap', 'incap_ses', 'nlbi_'],
      bodyPatterns: [/incapsula/i, /imperva/i],
      serverHeader: /imperva|incapsula/i
    },
    'F5 BIG-IP': {
      headers: ['x-wa-info', 'x-cnection'],
      cookies: ['bigipserver', 'big-ip', 'f5_'],
      bodyPatterns: [/f5 networks/i, /big-ip/i],
      serverHeader: /big-?ip/i
    },
    'ModSecurity': {
      headers: ['mod_security', 'modsecurity'],
      cookies: [],
      bodyPatterns: [/mod_security/i, /modsecurity/i, /not acceptable/i],
      serverHeader: /mod_security/i
    },
    'Barracuda': {
      headers: ['barra_counter_session'],
      cookies: ['barra_counter_session'],
      bodyPatterns: [/barracuda/i],
      serverHeader: /barracuda/i
    },
    'Fortinet FortiWeb': {
      headers: ['fortiwafsid'],
      cookies: ['cookiesession1'],
      bodyPatterns: [/fortigate|fortinet|fortiweb/i],
      serverHeader: /fortiweb/i
    },
    'Wordfence': {
      headers: ['x-wordfence'],
      cookies: ['wfwaf-authcookie'],
      bodyPatterns: [/wordfence/i, /blocked by wordfence/i],
      serverHeader: null
    },
    'DDoS-Guard': {
      headers: ['x-ddos-protection'],
      cookies: ['__ddg'],
      bodyPatterns: [/ddos-guard/i],
      serverHeader: /ddos-guard/i
    },
    'Reblaze': {
      headers: ['x-reblaze-protection'],
      cookies: ['rbzid'],
      bodyPatterns: [/reblaze/i],
      serverHeader: /reblaze/i
    }
  };
  
  // CDN signatures database
  cdnSignatures = {
    'Cloudflare CDN': {
      headers: ['cf-cache-status', 'cf-ray'],
      serverHeader: /cloudflare/i
    },
    'AWS CloudFront': {
      headers: ['x-amz-cf-id', 'x-amz-cf-pop'],
      serverHeader: /cloudfront/i
    },
    'Fastly': {
      headers: ['x-served-by', 'x-cache', 'x-fastly-request-id'],
      serverHeader: /fastly/i
    },
    'Akamai CDN': {
      headers: ['x-akamai-transformed'],
      serverHeader: /akamai/i
    },
    'KeyCDN': {
      headers: ['x-edge-location', 'x-cache'],
      serverHeader: /keycdn/i
    },
    'StackPath': {
      headers: ['x-hw'],
      serverHeader: /stackpath|highwinds/i
    },
    'Verizon Edgecast': {
      headers: ['x-ec-custom-error'],
      serverHeader: /ecacc|edgecast/i
    },
    'Google Cloud CDN': {
      headers: ['x-goog-hash', 'x-guploader-uploadid'],
      serverHeader: /gws|google/i
    },
    'Microsoft Azure CDN': {
      headers: ['x-azure-ref', 'x-ms-request-id'],
      serverHeader: /azure/i
    },
    'Netlify': {
      headers: ['x-nf-request-id'],
      serverHeader: /netlify/i
    },
    'Vercel': {
      headers: ['x-vercel-id', 'x-vercel-cache'],
      serverHeader: /vercel/i
    }
  };
  
  async scan(data) {
    const results = {
      waf: null,
      cdn: null,
      details: {},
      recommendations: []
    };
    
    try {
      // Fetch main page
      const response = await this.makeRequest(this.targetUrl);
      if (!response) return results;
      
      const headers = response.headers;
      const cookies = headers['set-cookie'] || [];
      const body = response.data?.toString() || '';
      const serverHeader = headers['server'] || '';
      
      // Detect WAF
      for (const [wafName, signatures] of Object.entries(this.wafSignatures)) {
        const detected = this.checkSignatures(headers, cookies, body, serverHeader, signatures);
        if (detected.match) {
          results.waf = {
            name: wafName,
            confidence: detected.confidence,
            evidence: detected.evidence
          };
          break;
        }
      }
      
      // Detect CDN
      for (const [cdnName, signatures] of Object.entries(this.cdnSignatures)) {
        const detected = this.checkCDNSignatures(headers, serverHeader, signatures);
        if (detected.match) {
          results.cdn = {
            name: cdnName,
            confidence: detected.confidence,
            evidence: detected.evidence
          };
          break;
        }
      }
      
      // WAF behavior test (safe probes)
      const behaviorTest = await this.testWAFBehavior();
      results.details.behaviorTest = behaviorTest;
      
      // Generate recommendations
      if (results.waf) {
        results.recommendations.push({
          type: 'info',
          message: `تم اكتشاف WAF: ${results.waf.name}. قد تحتاج لتخفيض سرعة الفحص.`,
          action: 'reduce_rate'
        });
      }
      
      if (results.cdn) {
        results.recommendations.push({
          type: 'info',
          message: `تم اكتشاف CDN: ${results.cdn.name}. بعض الثغرات قد تكون في الـ origin server.`,
          action: 'note_cdn'
        });
      }
      
    } catch (error) {
      this.log(`WAF/CDN detection error: ${error.message}`, 'debug');
    }
    
    return results;
  }
  
  checkSignatures(headers, cookies, body, serverHeader, signatures) {
    let matchCount = 0;
    let evidence = [];
    
    // Check headers
    if (signatures.headers) {
      for (const header of signatures.headers) {
        if (headers[header.toLowerCase()]) {
          matchCount++;
          evidence.push(`Header: ${header}`);
        }
      }
    }
    
    // Check cookies
    if (signatures.cookies) {
      const cookieStr = Array.isArray(cookies) ? cookies.join(' ') : cookies;
      for (const cookie of signatures.cookies) {
        if (cookieStr.toLowerCase().includes(cookie.toLowerCase())) {
          matchCount++;
          evidence.push(`Cookie: ${cookie}`);
        }
      }
    }
    
    // Check body patterns
    if (signatures.bodyPatterns) {
      for (const pattern of signatures.bodyPatterns) {
        if (pattern.test(body)) {
          matchCount++;
          evidence.push(`Body pattern match`);
          break;
        }
      }
    }
    
    // Check server header
    if (signatures.serverHeader && signatures.serverHeader.test(serverHeader)) {
      matchCount += 2;
      evidence.push(`Server: ${serverHeader}`);
    }
    
    const confidence = matchCount >= 3 ? 'high' : matchCount >= 2 ? 'medium' : matchCount >= 1 ? 'low' : null;
    
    return {
      match: matchCount >= 1,
      confidence,
      evidence
    };
  }
  
  checkCDNSignatures(headers, serverHeader, signatures) {
    let matchCount = 0;
    let evidence = [];
    
    if (signatures.headers) {
      for (const header of signatures.headers) {
        if (headers[header.toLowerCase()]) {
          matchCount++;
          evidence.push(`Header: ${header}`);
        }
      }
    }
    
    if (signatures.serverHeader && signatures.serverHeader.test(serverHeader)) {
      matchCount += 2;
      evidence.push(`Server: ${serverHeader}`);
    }
    
    const confidence = matchCount >= 2 ? 'high' : matchCount >= 1 ? 'medium' : null;
    
    return {
      match: matchCount >= 1,
      confidence,
      evidence
    };
  }
  
  async testWAFBehavior() {
    const results = {
      blocksXSSPayload: false,
      blocksSQLiPayload: false,
      blocksPathTraversal: false,
      rateLimit: null
    };
    
    try {
      // Test with benign XSS-like payload
      const xssTest = await this.makeRequest(`${this.targetUrl}?test=<script>`);
      if (xssTest && (xssTest.status === 403 || xssTest.status === 406)) {
        results.blocksXSSPayload = true;
      }
      
      // Test with benign SQLi-like payload
      const sqliTest = await this.makeRequest(`${this.targetUrl}?id=1'`);
      if (sqliTest && (sqliTest.status === 403 || sqliTest.status === 406)) {
        results.blocksSQLiPayload = true;
      }
      
      // Test path traversal
      const lfiTest = await this.makeRequest(`${this.targetUrl}/../../../etc/passwd`);
      if (lfiTest && (lfiTest.status === 403 || lfiTest.status === 400)) {
        results.blocksPathTraversal = true;
      }
      
    } catch (error) {
      // Errors might indicate WAF blocking
    }
    
    return results;
  }
}
