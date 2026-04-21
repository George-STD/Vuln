import axios from 'axios';
import yaml from 'js-yaml';
import { URL } from 'url';

export class OpenAPIImporter {
  constructor(options = {}) {
    this.options = {
      timeout: options.timeout || 30000,
      ...options
    };
  }

  /**
   * Import OpenAPI/Swagger specification from URL or content
   */
  async import(source) {
    let spec;
    
    if (typeof source === 'string' && (source.startsWith('http://') || source.startsWith('https://'))) {
      spec = await this.fetchSpec(source);
    } else if (typeof source === 'string') {
      spec = this.parseSpec(source);
    } else {
      spec = source;
    }

    return this.extractEndpoints(spec);
  }

  /**
   * Fetch OpenAPI spec from URL
   */
  async fetchSpec(url) {
    try {
      const response = await axios.get(url, {
        timeout: this.options.timeout,
        headers: {
          'Accept': 'application/json, application/yaml, text/yaml, */*'
        }
      });

      return this.parseSpec(response.data);
    } catch (error) {
      throw new Error(`Failed to fetch OpenAPI spec: ${error.message}`);
    }
  }

  /**
   * Parse OpenAPI spec from string or object
   */
  parseSpec(content) {
    if (typeof content === 'object') {
      return content;
    }

    // Try JSON first
    try {
      return JSON.parse(content);
    } catch (e) {
      // Try YAML
      try {
        return yaml.load(content);
      } catch (e2) {
        throw new Error('Failed to parse OpenAPI spec as JSON or YAML');
      }
    }
  }

  /**
   * Extract endpoints from OpenAPI spec
   */
  extractEndpoints(spec) {
    const endpoints = [];
    const baseUrl = this.getBaseUrl(spec);
    const securitySchemes = this.getSecuritySchemes(spec);

    const paths = spec.paths || {};
    
    for (const [path, methods] of Object.entries(paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method.toLowerCase())) {
          const endpoint = this.extractEndpoint(path, method, operation, baseUrl, securitySchemes);
          endpoints.push(endpoint);
        }
      }
    }

    return {
      info: {
        title: spec.info?.title || 'Unknown API',
        version: spec.info?.version || '1.0.0',
        description: spec.info?.description || ''
      },
      baseUrl,
      securitySchemes,
      endpoints,
      totalEndpoints: endpoints.length
    };
  }

  /**
   * Get base URL from OpenAPI spec
   */
  getBaseUrl(spec) {
    // OpenAPI 3.x
    if (spec.servers && spec.servers.length > 0) {
      return spec.servers[0].url;
    }

    // Swagger 2.x
    if (spec.host) {
      const scheme = spec.schemes?.[0] || 'https';
      const basePath = spec.basePath || '';
      return `${scheme}://${spec.host}${basePath}`;
    }

    return '';
  }

  /**
   * Extract security schemes
   */
  getSecuritySchemes(spec) {
    // OpenAPI 3.x
    if (spec.components?.securitySchemes) {
      return spec.components.securitySchemes;
    }

    // Swagger 2.x
    if (spec.securityDefinitions) {
      return spec.securityDefinitions;
    }

    return {};
  }

  /**
   * Extract single endpoint details
   */
  extractEndpoint(path, method, operation, baseUrl, securitySchemes) {
    const endpoint = {
      path,
      method: method.toUpperCase(),
      url: baseUrl + path,
      operationId: operation.operationId || `${method}_${path.replace(/\//g, '_')}`,
      summary: operation.summary || '',
      description: operation.description || '',
      tags: operation.tags || [],
      deprecated: operation.deprecated || false,
      parameters: [],
      requestBody: null,
      responses: {},
      security: [],
      testCases: []
    };

    // Extract parameters
    if (operation.parameters) {
      endpoint.parameters = operation.parameters.map(param => ({
        name: param.name,
        in: param.in, // path, query, header, cookie
        required: param.required || false,
        type: param.schema?.type || param.type || 'string',
        format: param.schema?.format || param.format,
        enum: param.schema?.enum || param.enum,
        example: param.example || param.schema?.example,
        description: param.description || ''
      }));
    }

    // Extract request body (OpenAPI 3.x)
    if (operation.requestBody) {
      const content = operation.requestBody.content || {};
      const mediaTypes = Object.keys(content);
      
      endpoint.requestBody = {
        required: operation.requestBody.required || false,
        mediaTypes,
        schema: content[mediaTypes[0]]?.schema || {},
        examples: content[mediaTypes[0]]?.examples || {}
      };
    }

    // Extract responses
    if (operation.responses) {
      for (const [code, response] of Object.entries(operation.responses)) {
        endpoint.responses[code] = {
          description: response.description || '',
          schema: response.content?.['application/json']?.schema || response.schema || {}
        };
      }
    }

    // Extract security requirements
    if (operation.security) {
      endpoint.security = operation.security;
    }

    // Generate test cases
    endpoint.testCases = this.generateTestCases(endpoint);

    return endpoint;
  }

  /**
   * Generate test cases for an endpoint
   */
  generateTestCases(endpoint) {
    const testCases = [];

    // Test with valid parameters
    testCases.push({
      name: 'Valid Request',
      type: 'positive',
      parameters: this.generateValidParams(endpoint.parameters),
      expectedStatus: [200, 201, 204]
    });

    // Test without required parameters
    const requiredParams = endpoint.parameters.filter(p => p.required);
    if (requiredParams.length > 0) {
      testCases.push({
        name: 'Missing Required Parameters',
        type: 'negative',
        parameters: {},
        expectedStatus: [400, 422]
      });
    }

    // Test with invalid types
    testCases.push({
      name: 'Invalid Parameter Types',
      type: 'negative',
      parameters: this.generateInvalidTypeParams(endpoint.parameters),
      expectedStatus: [400, 422]
    });

    // SQL Injection test
    testCases.push({
      name: 'SQL Injection Test',
      type: 'security',
      parameters: this.generateSQLiParams(endpoint.parameters),
      checkFor: ['sql', 'error', 'syntax', 'mysql', 'postgresql']
    });

    // XSS test
    testCases.push({
      name: 'XSS Test',
      type: 'security',
      parameters: this.generateXSSParams(endpoint.parameters),
      checkFor: ['<script>', 'javascript:', 'onerror']
    });

    // IDOR test for ID parameters
    const idParams = endpoint.parameters.filter(p => 
      p.name.toLowerCase().includes('id') || 
      p.in === 'path'
    );
    if (idParams.length > 0) {
      testCases.push({
        name: 'IDOR Test',
        type: 'security',
        parameters: this.generateIDORParams(endpoint.parameters, idParams),
        checkFor: ['different user data', 'unauthorized access']
      });
    }

    return testCases;
  }

  generateValidParams(parameters) {
    const params = {};
    for (const param of parameters) {
      params[param.name] = param.example || this.getDefaultValue(param.type, param.format);
    }
    return params;
  }

  generateInvalidTypeParams(parameters) {
    const params = {};
    for (const param of parameters) {
      // Use wrong type
      if (param.type === 'integer' || param.type === 'number') {
        params[param.name] = 'not_a_number';
      } else if (param.type === 'boolean') {
        params[param.name] = 'not_a_boolean';
      } else if (param.type === 'array') {
        params[param.name] = 'not_an_array';
      } else {
        params[param.name] = null;
      }
    }
    return params;
  }

  generateSQLiParams(parameters) {
    const params = {};
    const sqliPayload = "' OR '1'='1";
    for (const param of parameters) {
      params[param.name] = sqliPayload;
    }
    return params;
  }

  generateXSSParams(parameters) {
    const params = {};
    const xssPayload = '<script>alert(1)</script>';
    for (const param of parameters) {
      params[param.name] = xssPayload;
    }
    return params;
  }

  generateIDORParams(parameters, idParams) {
    const params = this.generateValidParams(parameters);
    for (const idParam of idParams) {
      // Try to access different IDs
      params[idParam.name] = '1';
    }
    return params;
  }

  getDefaultValue(type, format) {
    switch (type) {
      case 'integer':
        return 1;
      case 'number':
        return 1.0;
      case 'boolean':
        return true;
      case 'string':
        if (format === 'email') return 'test@example.com';
        if (format === 'date') return '2024-01-01';
        if (format === 'date-time') return '2024-01-01T00:00:00Z';
        if (format === 'uuid') return '00000000-0000-0000-0000-000000000000';
        return 'test';
      case 'array':
        return [];
      case 'object':
        return {};
      default:
        return 'test';
    }
  }

  /**
   * Auto-discover OpenAPI spec URL
   */
  async discoverSpec(baseUrl) {
    const commonPaths = [
      '/swagger.json',
      '/swagger.yaml',
      '/openapi.json',
      '/openapi.yaml',
      '/api-docs',
      '/api-docs.json',
      '/v1/swagger.json',
      '/v2/swagger.json',
      '/v3/swagger.json',
      '/api/swagger.json',
      '/api/openapi.json',
      '/docs/swagger.json',
      '/.well-known/openapi.json'
    ];

    for (const path of commonPaths) {
      try {
        const url = new URL(path, baseUrl).href;
        const response = await axios.get(url, {
          timeout: 5000,
          validateStatus: status => status === 200
        });
        
        if (response.data) {
          const spec = this.parseSpec(response.data);
          if (spec.openapi || spec.swagger) {
            return {
              found: true,
              url,
              spec
            };
          }
        }
      } catch (e) {
        continue;
      }
    }

    return { found: false };
  }
}

export default OpenAPIImporter;
