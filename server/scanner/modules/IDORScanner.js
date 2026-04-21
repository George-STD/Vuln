import { BaseScanner } from './BaseScanner.js';

export class IDORScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'IDOR Scanner';
    
    // Common IDOR parameter names
    this.idParameters = [
      'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
      'profile_id', 'profileId', 'order_id', 'orderId', 'doc_id', 'docId',
      'document_id', 'documentId', 'file_id', 'fileId', 'msg_id', 'msgId',
      'message_id', 'messageId', 'invoice_id', 'invoiceId', 'transaction_id',
      'transactionId', 'item_id', 'itemId', 'product_id', 'productId',
      'record_id', 'recordId', 'customer_id', 'customerId', 'client_id',
      'clientId', 'member_id', 'memberId', 'num', 'number', 'no',
      'ref', 'reference', 'key', 'token'
    ];
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, endpoints } = data;
    
    // Find URLs with numeric ID parameters
    for (const url of urls) {
      if (this.stopped) break;
      
      try {
        const parsedUrl = new URL(url);
        
        for (const [key, value] of parsedUrl.searchParams.entries()) {
          // Check if this looks like an ID parameter
          if (this.isIdParameter(key, value)) {
            const vuln = await this.testIDOR(url, key, value);
            if (vuln) vulnerabilities.push(vuln);
          }
        }
        
        // Check URL path for numeric IDs (e.g., /users/123)
        const pathVulns = await this.testPathIDOR(url);
        vulnerabilities.push(...pathVulns);
        
      } catch (error) {
        this.log(`IDOR URL parse error: ${error.message}`, 'debug');
      }
    }
    
    return vulnerabilities;
  }
  
  isIdParameter(key, value) {
    const keyLower = key.toLowerCase();
    
    // Check against known ID parameter names
    if (this.idParameters.some(p => keyLower.includes(p.toLowerCase()))) {
      return true;
    }
    
    // Check if value looks like an ID
    if (/^\d+$/.test(value) && value.length < 15) return true;
    if (/^[a-f0-9]{8,32}$/i.test(value)) return true; // UUID/hash-like
    
    return false;
  }
  
  async testIDOR(baseUrl, paramName, originalValue) {
    try {
      // Get baseline response
      const baselineResponse = await this.makeRequest(baseUrl);
      if (!baselineResponse) return null;
      
      const baselineStatus = baselineResponse.status;
      const baselineLength = baselineResponse.data?.length || 0;
      
      // Test with different ID values
      const testIds = this.generateTestIds(originalValue);
      
      for (const testId of testIds) {
        if (this.stopped) break;
        
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(paramName, testId);
        
        const response = await this.makeRequest(testUrl.href);
        if (!response) continue;
        
        // Check for IDOR indicators
        const indicators = this.detectIDOR(response, baselineResponse, originalValue, testId);
        
        if (indicators.detected) {
          return {
            type: 'IDOR',
            subType: 'Insecure Direct Object Reference',
            severity: 'high',
            url: baseUrl,
            parameter: paramName,
            payload: `Original: ${originalValue}, Test: ${testId}`,
            evidence: indicators.evidence,
            description: `Potential IDOR vulnerability in parameter "${paramName}". ${indicators.description}`,
            remediation: 'Implement proper authorization checks. Use indirect references (mapping to internal IDs). Verify user has permission to access the requested resource.',
            references: [
              'https://portswigger.net/web-security/access-control/idor',
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'
            ],
            cvss: 6.5,
            cwe: 'CWE-639'
          };
        }
      }
    } catch (error) {
      this.log(`IDOR test error: ${error.message}`, 'debug');
    }
    
    return null;
  }
  
  async testPathIDOR(url) {
    const vulnerabilities = [];
    
    try {
      const parsedUrl = new URL(url);
      const pathParts = parsedUrl.pathname.split('/').filter(Boolean);
      
      // Find numeric segments in path
      for (let i = 0; i < pathParts.length; i++) {
        const part = pathParts[i];
        
        if (/^\d+$/.test(part)) {
          // Found numeric ID in path
          const originalId = parseInt(part);
          const testIds = [originalId - 1, originalId + 1, 1, 0];
          
          // Get baseline
          const baselineResponse = await this.makeRequest(url);
          if (!baselineResponse) continue;
          
          for (const testId of testIds) {
            if (this.stopped) break;
            if (testId === originalId) continue;
            
            const newPathParts = [...pathParts];
            newPathParts[i] = testId.toString();
            
            const testUrl = new URL(url);
            testUrl.pathname = '/' + newPathParts.join('/');
            
            const response = await this.makeRequest(testUrl.href);
            if (!response) continue;
            
            const indicators = this.detectIDOR(response, baselineResponse, part, testId.toString());
            
            if (indicators.detected) {
              vulnerabilities.push({
                type: 'IDOR',
                subType: 'Path-based IDOR',
                severity: 'high',
                url: url,
                parameter: `Path segment ${i + 1}`,
                payload: `Original: ${part}, Test: ${testId}`,
                evidence: indicators.evidence,
                description: `Potential IDOR in URL path. Different resource accessed by changing ID.`,
                remediation: 'Implement authorization checks based on user context, not just object IDs.',
                references: [
                  'https://portswigger.net/web-security/access-control/idor'
                ],
                cvss: 6.5,
                cwe: 'CWE-639'
              });
              break;
            }
          }
        }
      }
    } catch (error) {
      this.log(`Path IDOR test error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  generateTestIds(originalValue) {
    const testIds = [];
    
    if (/^\d+$/.test(originalValue)) {
      const numValue = parseInt(originalValue);
      testIds.push(
        (numValue + 1).toString(),
        (numValue - 1).toString(),
        '1',
        '0',
        (numValue * 2).toString()
      );
    } else if (/^[a-f0-9]{8,32}$/i.test(originalValue)) {
      // UUID-like, try common test values
      testIds.push(
        '00000000-0000-0000-0000-000000000000',
        '11111111-1111-1111-1111-111111111111',
        originalValue.replace(/[0-9]/g, '1')
      );
    }
    
    return testIds.filter(id => id !== originalValue);
  }
  
  detectIDOR(response, baselineResponse, originalId, testId) {
    const result = {
      detected: false,
      evidence: '',
      description: ''
    };
    
    const responseStatus = response.status;
    const baselineStatus = baselineResponse.status;
    const responseBody = response.data?.toString() || '';
    const baselineBody = baselineResponse.data?.toString() || '';
    
    // If both requests return 200 with different content
    if (responseStatus === 200 && baselineStatus === 200) {
      // Check if content is different (indicating different resource)
      const lengthDiff = Math.abs(responseBody.length - baselineBody.length);
      
      if (lengthDiff > 100 && responseBody.length > 200) {
        // Check for user-specific data indicators
        const sensitivePatterns = [
          /email.*@/i,
          /"name"\s*:/i,
          /"username"\s*:/i,
          /"user"\s*:/i,
          /"account"\s*:/i,
          /phone.*\d{3}/i,
          /address/i
        ];
        
        for (const pattern of sensitivePatterns) {
          if (pattern.test(responseBody)) {
            result.detected = true;
            result.evidence = `Different resource returned for ID ${testId}. Response contains sensitive fields.`;
            result.description = 'Accessed different user/resource data by manipulating ID.';
            return result;
          }
        }
        
        // Even without sensitive patterns, significant content difference is suspicious
        result.detected = true;
        result.evidence = `Response differs by ${lengthDiff} bytes when changing ID from ${originalId} to ${testId}`;
        result.description = 'Different resource content accessible with modified ID.';
        return result;
      }
    }
    
    return result;
  }
}
