import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import puppeteer from 'puppeteer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ReportGenerator {
  constructor() {
    this.reportsDir = path.join(__dirname, '../../reports');
    this.ensureReportsDir();
  }
  
  ensureReportsDir() {
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, { recursive: true });
    }
  }
  
  async generateReport(scanResults, format = 'html') {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `scan-report-${timestamp}`;
    
    switch (format.toLowerCase()) {
      case 'html':
        return this.generateHTML(scanResults, filename);
      case 'json':
        return this.generateJSON(scanResults, filename);
      case 'markdown':
      case 'md':
        return this.generateMarkdown(scanResults, filename);
      case 'pdf':
        return this.generatePDF(scanResults, filename);
      case 'walkthrough':
      case 'portswigger':
      case 'steps':
        return this.generateWalkthroughPDF(scanResults, filename);
      default:
        return this.generateHTML(scanResults, filename);
    }
  }
  
  generateHTML(results, filename) {
    const html = `
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>تقرير فحص الثغرات | Vulnerability Scan Report</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%);
      color: #e0e0e0;
      min-height: 100vh;
      padding: 20px;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    
    header {
      text-align: center;
      padding: 30px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 15px;
      margin-bottom: 30px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    h1 {
      font-size: 2.5em;
      background: linear-gradient(45deg, #00d4ff, #00ff88);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 10px;
    }
    
    .target-url {
      font-size: 1.2em;
      color: #00d4ff;
      word-break: break-all;
    }
    
    .scan-info {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-top: 20px;
    }
    
    .info-card {
      background: rgba(0, 212, 255, 0.1);
      padding: 15px;
      border-radius: 10px;
      border: 1px solid rgba(0, 212, 255, 0.3);
    }
    
    .summary {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 15px;
      margin-bottom: 30px;
    }
    
    .summary-card {
      padding: 20px;
      border-radius: 10px;
      text-align: center;
      border: 2px solid;
    }
    
    .summary-card.critical {
      background: rgba(255, 0, 0, 0.1);
      border-color: #ff0000;
    }
    
    .summary-card.high {
      background: rgba(255, 100, 0, 0.1);
      border-color: #ff6400;
    }
    
    .summary-card.medium {
      background: rgba(255, 200, 0, 0.1);
      border-color: #ffc800;
    }
    
    .summary-card.low {
      background: rgba(0, 200, 255, 0.1);
      border-color: #00c8ff;
    }
    
    .summary-card.info {
      background: rgba(150, 150, 150, 0.1);
      border-color: #969696;
    }
    
    .summary-card h3 {
      font-size: 2.5em;
      margin-bottom: 5px;
    }
    
    .vulnerability {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 10px;
      margin-bottom: 20px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .vuln-header {
      padding: 15px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
    }
    
    .vuln-header.critical { background: rgba(255, 0, 0, 0.2); }
    .vuln-header.high { background: rgba(255, 100, 0, 0.2); }
    .vuln-header.medium { background: rgba(255, 200, 0, 0.2); }
    .vuln-header.low { background: rgba(0, 200, 255, 0.2); }
    .vuln-header.info { background: rgba(150, 150, 150, 0.2); }
    
    .vuln-title {
      font-size: 1.2em;
      font-weight: bold;
    }
    
    .severity-badge {
      padding: 5px 15px;
      border-radius: 20px;
      font-weight: bold;
      text-transform: uppercase;
      font-size: 0.8em;
    }
    
    .severity-badge.critical { background: #ff0000; color: white; }
    .severity-badge.high { background: #ff6400; color: white; }
    .severity-badge.medium { background: #ffc800; color: black; }
    .severity-badge.low { background: #00c8ff; color: black; }
    .severity-badge.info { background: #969696; color: white; }
    
    .vuln-body {
      padding: 20px;
    }
    
    .vuln-section {
      margin-bottom: 15px;
    }
    
    .vuln-section h4 {
      color: #00d4ff;
      margin-bottom: 5px;
      font-size: 0.9em;
      text-transform: uppercase;
    }
    
    .vuln-section p, .vuln-section code {
      color: #ccc;
    }
    
    code {
      background: rgba(0, 0, 0, 0.3);
      padding: 10px 15px;
      border-radius: 5px;
      display: block;
      overflow-x: auto;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
      white-space: pre-wrap;
      word-break: break-all;
    }
    
    .references a {
      color: #00d4ff;
      text-decoration: none;
      display: block;
      margin-bottom: 5px;
    }
    
    .references a:hover {
      text-decoration: underline;
    }
    
    .cvss-score {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 5px;
      font-weight: bold;
    }
    
    .cvss-critical { background: #ff0000; }
    .cvss-high { background: #ff6400; }
    .cvss-medium { background: #ffc800; color: black; }
    .cvss-low { background: #00c8ff; color: black; }
    
    footer {
      text-align: center;
      padding: 20px;
      margin-top: 30px;
      color: #666;
    }
    
    @media print {
      body {
        background: white;
        color: black;
      }
      
      .vulnerability {
        page-break-inside: avoid;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔐 تقرير فحص الثغرات</h1>
      <div class="target-url">${this.escapeHtml(results.target)}</div>
      <div class="scan-info">
        <div class="info-card">
          <strong>تاريخ الفحص:</strong><br>
          ${new Date(results.startTime).toLocaleString('ar-EG')}
        </div>
        <div class="info-card">
          <strong>مدة الفحص:</strong><br>
          ${results.summary?.duration || 'N/A'}
        </div>
        <div class="info-card">
          <strong>الصفحات المفحوصة:</strong><br>
          ${results.summary?.urlsScanned || 0}
        </div>
        <div class="info-card">
          <strong>النماذج المفحوصة:</strong><br>
          ${results.summary?.formsFound || 0}
        </div>
      </div>
    </header>
    
    <section class="summary">
      <div class="summary-card critical">
        <h3>${this.countBySeverity(results.vulnerabilities, 'critical')}</h3>
        <p>حرجة | Critical</p>
      </div>
      <div class="summary-card high">
        <h3>${this.countBySeverity(results.vulnerabilities, 'high')}</h3>
        <p>عالية | High</p>
      </div>
      <div class="summary-card medium">
        <h3>${this.countBySeverity(results.vulnerabilities, 'medium')}</h3>
        <p>متوسطة | Medium</p>
      </div>
      <div class="summary-card low">
        <h3>${this.countBySeverity(results.vulnerabilities, 'low')}</h3>
        <p>منخفضة | Low</p>
      </div>
      <div class="summary-card info">
        <h3>${this.countBySeverity(results.vulnerabilities, 'info')}</h3>
        <p>معلومات | Info</p>
      </div>
    </section>
    
    <section class="vulnerabilities">
      ${this.renderVulnerabilities(results.vulnerabilities)}
    </section>
    
    <footer>
      <p>تم إنشاء هذا التقرير بواسطة ماسح الثغرات الآلي | Auto Vulnerability Scanner</p>
      <p>© ${new Date().getFullYear()} - للاستخدام الأخلاقي فقط | For Ethical Use Only</p>
    </footer>
  </div>
  
  <script>
    document.querySelectorAll('.vuln-header').forEach(header => {
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        body.style.display = body.style.display === 'none' ? 'block' : 'none';
      });
    });
  </script>
</body>
</html>`;
    
    const filePath = path.join(this.reportsDir, `${filename}.html`);
    fs.writeFileSync(filePath, html, 'utf8');
    
    return {
      path: filePath,
      filename: `${filename}.html`,
      format: 'html'
    };
  }
  
  renderVulnerabilities(vulnerabilities) {
    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...vulnerabilities].sort((a, b) => 
      (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
    );
    
    return sorted.map((vuln, index) => `
      <div class="vulnerability">
        <div class="vuln-header ${vuln.severity}">
          <span class="vuln-title">${index + 1}. ${this.escapeHtml(vuln.type)}${vuln.subType ? ` - ${this.escapeHtml(vuln.subType)}` : ''}</span>
          <span class="severity-badge ${vuln.severity}">${vuln.severity}</span>
        </div>
        <div class="vuln-body">
          <div class="vuln-section">
            <h4>🔗 الرابط | URL</h4>
            <code>${this.escapeHtml(vuln.url)}</code>
          </div>
          
          <div class="vuln-section">
            <h4>📝 الوصف | Description</h4>
            <p>${this.escapeHtml(vuln.description)}</p>
          </div>
          
          ${vuln.evidence ? `
          <div class="vuln-section">
            <h4>🔍 الدليل | Evidence</h4>
            <code>${this.escapeHtml(vuln.evidence)}</code>
          </div>
          ` : ''}
          
          ${vuln.payload ? `
          <div class="vuln-section">
            <h4>💉 الحمولة | Payload</h4>
            <code>${this.escapeHtml(vuln.payload)}</code>
          </div>
          ` : ''}
          
          <div class="vuln-section">
            <h4>🛡️ طريقة الإصلاح | Remediation</h4>
            <p>${this.escapeHtml(vuln.remediation)}</p>
          </div>
          
          ${vuln.cvss ? `
          <div class="vuln-section">
            <h4>📊 CVSS Score</h4>
            <span class="cvss-score ${this.getCVSSClass(vuln.cvss)}">${vuln.cvss}</span>
            ${vuln.cwe ? ` | ${vuln.cwe}` : ''}
          </div>
          ` : ''}
          
          ${vuln.references && vuln.references.length > 0 ? `
          <div class="vuln-section references">
            <h4>📚 المراجع | References</h4>
            ${vuln.references.map(ref => `<a href="${this.escapeHtml(ref)}" target="_blank">${this.escapeHtml(ref)}</a>`).join('')}
          </div>
          ` : ''}
        </div>
      </div>
    `).join('');
  }
  
  generateJSON(results, filename) {
    const filePath = path.join(this.reportsDir, `${filename}.json`);
    fs.writeFileSync(filePath, JSON.stringify(results, null, 2), 'utf8');
    
    return {
      path: filePath,
      filename: `${filename}.json`,
      format: 'json'
    };
  }
  
  generateMarkdown(results, filename) {
    let md = `# 🔐 تقرير فحص الثغرات | Vulnerability Scan Report

## معلومات الفحص | Scan Information

| Property | Value |
|----------|-------|
| Target | ${results.target} |
| Scan Date | ${new Date(results.startTime).toISOString()} |
| Duration | ${results.summary?.duration || 'N/A'} |
| URLs Scanned | ${results.summary?.urlsScanned || 0} |
| Forms Found | ${results.summary?.formsFound || 0} |

## ملخص الثغرات | Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${this.countBySeverity(results.vulnerabilities, 'critical')} |
| 🟠 High | ${this.countBySeverity(results.vulnerabilities, 'high')} |
| 🟡 Medium | ${this.countBySeverity(results.vulnerabilities, 'medium')} |
| 🔵 Low | ${this.countBySeverity(results.vulnerabilities, 'low')} |
| ⚪ Info | ${this.countBySeverity(results.vulnerabilities, 'info')} |

## تفاصيل الثغرات | Vulnerability Details

`;
    
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...results.vulnerabilities].sort((a, b) => 
      (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
    );
    
    sorted.forEach((vuln, index) => {
      const severityEmoji = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🔵',
        info: '⚪'
      };
      
      md += `### ${index + 1}. ${severityEmoji[vuln.severity] || '⚪'} ${vuln.type}${vuln.subType ? ` - ${vuln.subType}` : ''}

**Severity:** ${vuln.severity.toUpperCase()}
**URL:** \`${vuln.url}\`

**Description:**
${vuln.description}

`;
      
      if (vuln.evidence) {
        md += `**Evidence:**
\`\`\`
${vuln.evidence}
\`\`\`

`;
      }
      
      if (vuln.payload) {
        md += `**Payload:**
\`\`\`
${vuln.payload}
\`\`\`

`;
      }
      
      md += `**Remediation:**
${vuln.remediation}

`;
      
      if (vuln.cvss) {
        md += `**CVSS Score:** ${vuln.cvss}${vuln.cwe ? ` | ${vuln.cwe}` : ''}\n\n`;
      }
      
      if (vuln.references && vuln.references.length > 0) {
        md += `**References:**\n`;
        vuln.references.forEach(ref => {
          md += `- ${ref}\n`;
        });
        md += '\n';
      }
      
      md += '---\n\n';
    });
    
    md += `
## ملاحظات | Notes

- هذا التقرير تم إنشاؤه تلقائياً بواسطة ماسح الثغرات
- This report was automatically generated by the Vulnerability Scanner
- للاستخدام الأخلاقي فقط | For ethical use only

---
*Generated on ${new Date().toISOString()}*
`;
    
    const filePath = path.join(this.reportsDir, `${filename}.md`);
    fs.writeFileSync(filePath, md, 'utf8');
    
    return {
      path: filePath,
      filename: `${filename}.md`,
      format: 'markdown'
    };
  }
  
  async generatePDF(results, filename) {
    // Generate HTML first
    const htmlReport = this.generateHTML(results, `${filename}-temp`);
    
    try {
      const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const page = await browser.newPage();
      
      // Read the HTML content
      const htmlContent = fs.readFileSync(htmlReport.path, 'utf8');
      
      // Set content
      await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
      
      // Generate PDF
      const pdfPath = path.join(this.reportsDir, `${filename}.pdf`);
      await page.pdf({
        path: pdfPath,
        format: 'A4',
        printBackground: true,
        margin: {
          top: '20mm',
          right: '15mm',
          bottom: '20mm',
          left: '15mm'
        },
        displayHeaderFooter: true,
        headerTemplate: `
          <div style="font-size: 10px; width: 100%; text-align: center; color: #666;">
            تقرير فحص الثغرات | Vulnerability Scan Report
          </div>
        `,
        footerTemplate: `
          <div style="font-size: 10px; width: 100%; text-align: center; color: #666;">
            <span class="pageNumber"></span> / <span class="totalPages"></span>
          </div>
        `
      });
      
      await browser.close();
      
      // Delete temporary HTML file
      fs.unlinkSync(htmlReport.path);
      
      return {
        path: pdfPath,
        filename: `${filename}.pdf`,
        format: 'pdf'
      };
    } catch (error) {
      console.error('PDF generation error:', error);
      // Fallback to HTML if PDF generation fails
      return {
        path: htmlReport.path,
        filename: htmlReport.filename,
        format: 'html',
        note: 'PDF generation failed, HTML report generated instead'
      };
    }
  }
  
  countBySeverity(vulnerabilities, severity) {
    return vulnerabilities.filter(v => v.severity === severity).length;
  }
  
  getCVSSClass(score) {
    if (score >= 9.0) return 'cvss-critical';
    if (score >= 7.0) return 'cvss-high';
    if (score >= 4.0) return 'cvss-medium';
    return 'cvss-low';
  }
  
  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Generate PortSwigger-style Walkthrough PDF
   * Shows step-by-step exploitation process for each vulnerability
   */
  async generateWalkthroughPDF(results, filename) {
    const vulnerabilities = results.vulnerabilities || [];
    const targetUrl = results.targetUrl || results.target || 'Unknown';
    const scanDate = results.completedAt || new Date().toISOString();
    
    const html = `
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>دليل الاستغلال - Exploitation Walkthrough</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, sans-serif;
      background: #ffffff;
      color: #1a1a2e;
      font-size: 14px;
      line-height: 1.6;
    }
    
    .page {
      padding: 40px;
      page-break-after: always;
    }
    
    .page:last-child {
      page-break-after: avoid;
    }
    
    /* Cover Page */
    .cover-page {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      min-height: 90vh;
      text-align: center;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border-radius: 0;
    }
    
    .cover-logo {
      font-size: 80px;
      margin-bottom: 20px;
    }
    
    .cover-title {
      font-size: 42px;
      font-weight: bold;
      margin-bottom: 10px;
    }
    
    .cover-subtitle {
      font-size: 24px;
      opacity: 0.9;
      margin-bottom: 40px;
    }
    
    .cover-target {
      background: rgba(255, 255, 255, 0.2);
      padding: 15px 30px;
      border-radius: 10px;
      font-size: 18px;
      margin-bottom: 20px;
      word-break: break-all;
      max-width: 80%;
    }
    
    .cover-date {
      font-size: 16px;
      opacity: 0.8;
    }
    
    .cover-stats {
      display: flex;
      gap: 30px;
      margin-top: 40px;
    }
    
    .stat-box {
      background: rgba(255, 255, 255, 0.2);
      padding: 15px 25px;
      border-radius: 10px;
      text-align: center;
    }
    
    .stat-number {
      font-size: 36px;
      font-weight: bold;
    }
    
    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      opacity: 0.8;
    }
    
    /* TOC */
    .toc {
      padding: 40px;
    }
    
    .toc h2 {
      color: #667eea;
      font-size: 28px;
      margin-bottom: 30px;
      padding-bottom: 10px;
      border-bottom: 3px solid #667eea;
    }
    
    .toc-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 0;
      border-bottom: 1px dashed #ddd;
    }
    
    .toc-vuln-name {
      font-weight: 600;
      color: #333;
    }
    
    .toc-severity {
      padding: 4px 12px;
      border-radius: 15px;
      font-size: 11px;
      font-weight: bold;
      text-transform: uppercase;
    }
    
    .toc-severity.critical { background: #ff0000; color: white; }
    .toc-severity.high { background: #ff6b35; color: white; }
    .toc-severity.medium { background: #f7c948; color: #333; }
    .toc-severity.low { background: #3498db; color: white; }
    .toc-severity.informational { background: #95a5a6; color: white; }
    
    /* Vulnerability Walkthrough */
    .vuln-walkthrough {
      padding: 40px;
    }
    
    .vuln-header-section {
      background: linear-gradient(135deg, #1a1a2e 0%, #2d2d44 100%);
      color: white;
      padding: 30px;
      border-radius: 15px;
      margin-bottom: 30px;
    }
    
    .vuln-number {
      font-size: 14px;
      opacity: 0.7;
      margin-bottom: 10px;
    }
    
    .vuln-name {
      font-size: 28px;
      font-weight: bold;
      margin-bottom: 15px;
    }
    
    .vuln-meta {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .meta-item {
      background: rgba(255, 255, 255, 0.1);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
    }
    
    .meta-label {
      opacity: 0.7;
    }
    
    .meta-value {
      font-weight: bold;
      color: #00d4ff;
    }
    
    /* Steps */
    .steps-section {
      margin-bottom: 30px;
    }
    
    .section-title {
      font-size: 20px;
      color: #667eea;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 2px solid #667eea;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .section-icon {
      font-size: 24px;
    }
    
    .step {
      background: #f8f9fa;
      border-right: 4px solid #667eea;
      padding: 20px;
      margin-bottom: 15px;
      border-radius: 0 10px 10px 0;
      position: relative;
    }
    
    .step-number {
      position: absolute;
      right: -40px;
      top: 50%;
      transform: translateY(-50%);
      width: 30px;
      height: 30px;
      background: #667eea;
      color: white;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
      font-size: 14px;
    }
    
    .step-title {
      font-weight: bold;
      color: #333;
      margin-bottom: 10px;
      font-size: 16px;
    }
    
    .step-description {
      color: #666;
      margin-bottom: 15px;
    }
    
    /* Code Blocks */
    .code-block {
      background: #1e1e2e;
      color: #cdd6f4;
      padding: 15px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      direction: ltr;
      text-align: left;
    }
    
    .code-label {
      background: #667eea;
      color: white;
      padding: 4px 12px;
      border-radius: 5px 5px 0 0;
      font-size: 11px;
      font-weight: bold;
      display: inline-block;
      margin-bottom: -5px;
    }
    
    /* HTTP Request/Response */
    .http-block {
      margin: 15px 0;
    }
    
    .http-method {
      color: #89b4fa;
      font-weight: bold;
    }
    
    .http-url {
      color: #a6e3a1;
    }
    
    .http-header-name {
      color: #f9e2af;
    }
    
    .http-header-value {
      color: #cdd6f4;
    }
    
    .http-body {
      color: #fab387;
    }
    
    .highlight {
      background: rgba(255, 0, 0, 0.2);
      padding: 2px 4px;
      border-radius: 3px;
      color: #ff6b6b;
    }
    
    /* Evidence Box */
    .evidence-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .evidence-title {
      color: #856404;
      font-weight: bold;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .evidence-content {
      color: #856404;
    }
    
    /* Remediation Box */
    .remediation-box {
      background: #d4edda;
      border: 1px solid #28a745;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .remediation-title {
      color: #155724;
      font-weight: bold;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .remediation-content {
      color: #155724;
    }
    
    .remediation-list {
      margin-top: 10px;
      padding-right: 20px;
    }
    
    .remediation-list li {
      margin-bottom: 8px;
    }
    
    /* References */
    .references-box {
      background: #e7f1ff;
      border: 1px solid #007bff;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .references-title {
      color: #004085;
      font-weight: bold;
      margin-bottom: 10px;
    }
    
    .references-list {
      list-style: none;
    }
    
    .references-list li {
      margin-bottom: 8px;
    }
    
    .references-list a {
      color: #007bff;
      text-decoration: none;
    }
    
    /* Impact */
    .impact-box {
      background: #f8d7da;
      border: 1px solid #dc3545;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .impact-title {
      color: #721c24;
      font-weight: bold;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .impact-content {
      color: #721c24;
    }
    
    /* cURL Command */
    .curl-box {
      background: #2d2d44;
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .curl-title {
      color: #00d4ff;
      font-weight: bold;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .curl-command {
      background: #1a1a2e;
      color: #00ff88;
      padding: 15px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      direction: ltr;
      text-align: left;
      word-break: break-all;
    }
    
    /* Footer */
    .page-footer {
      text-align: center;
      color: #999;
      font-size: 11px;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #eee;
    }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="cover-page page">
    <div class="cover-logo">🔍</div>
    <div class="cover-title">دليل استغلال الثغرات</div>
    <div class="cover-subtitle">Vulnerability Exploitation Walkthrough</div>
    <div class="cover-target">🎯 ${this.escapeHtml(targetUrl)}</div>
    <div class="cover-date">📅 ${new Date(scanDate).toLocaleDateString('ar-EG', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })}</div>
    <div class="cover-stats">
      <div class="stat-box">
        <div class="stat-number" style="color: #ff0000;">${this.countBySeverity(vulnerabilities, 'critical')}</div>
        <div class="stat-label">حرجة</div>
      </div>
      <div class="stat-box">
        <div class="stat-number" style="color: #ff6b35;">${this.countBySeverity(vulnerabilities, 'high')}</div>
        <div class="stat-label">عالية</div>
      </div>
      <div class="stat-box">
        <div class="stat-number" style="color: #f7c948;">${this.countBySeverity(vulnerabilities, 'medium')}</div>
        <div class="stat-label">متوسطة</div>
      </div>
      <div class="stat-box">
        <div class="stat-number" style="color: #3498db;">${this.countBySeverity(vulnerabilities, 'low')}</div>
        <div class="stat-label">منخفضة</div>
      </div>
    </div>
  </div>
  
  <!-- Table of Contents -->
  <div class="toc page">
    <h2>📋 جدول المحتويات</h2>
    ${vulnerabilities.map((vuln, index) => `
      <div class="toc-item">
        <span class="toc-vuln-name">${index + 1}. ${this.escapeHtml(vuln.name || vuln.type)}</span>
        <span class="toc-severity ${vuln.severity}">${this.getSeverityArabic(vuln.severity)}</span>
      </div>
    `).join('')}
  </div>
  
  <!-- Vulnerability Walkthroughs -->
  ${vulnerabilities.map((vuln, index) => this.generateVulnWalkthrough(vuln, index, targetUrl)).join('')}
  
</body>
</html>`;

    // Save HTML first
    const htmlPath = path.join(this.reportsDir, `${filename}-walkthrough.html`);
    fs.writeFileSync(htmlPath, html);
    
    // Convert to PDF
    try {
      const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'networkidle0' });
      
      const pdfPath = path.join(this.reportsDir, `${filename}-walkthrough.pdf`);
      
      await page.pdf({
        path: pdfPath,
        format: 'A4',
        printBackground: true,
        margin: {
          top: '15mm',
          right: '15mm',
          bottom: '15mm',
          left: '15mm'
        }
      });
      
      await browser.close();
      
      // Delete temp HTML
      fs.unlinkSync(htmlPath);
      
      return {
        path: pdfPath,
        filename: `${filename}-walkthrough.pdf`,
        format: 'pdf'
      };
    } catch (error) {
      console.error('Walkthrough PDF generation error:', error);
      return {
        path: htmlPath,
        filename: `${filename}-walkthrough.html`,
        format: 'html',
        note: 'PDF generation failed, HTML generated instead'
      };
    }
  }

  /**
   * Generate detailed walkthrough for a single vulnerability
   */
  generateVulnWalkthrough(vuln, index, targetUrl) {
    const steps = this.generateExploitationSteps(vuln);
    const curlCommand = this.generateCurlCommand(vuln, targetUrl);
    
    return `
  <div class="vuln-walkthrough page">
    <div class="vuln-header-section">
      <div class="vuln-number">ثغرة رقم ${index + 1}</div>
      <div class="vuln-name">${this.escapeHtml(vuln.name || vuln.type)}</div>
      <div class="vuln-meta">
        <div class="meta-item">
          <span class="meta-label">الخطورة: </span>
          <span class="meta-value">${this.getSeverityArabic(vuln.severity)}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">الثقة: </span>
          <span class="meta-value">${vuln.confidence || 0}%</span>
        </div>
        ${vuln.cvssScore ? `
        <div class="meta-item">
          <span class="meta-label">CVSS: </span>
          <span class="meta-value">${vuln.cvssScore}</span>
        </div>
        ` : ''}
        <div class="meta-item">
          <span class="meta-label">الفئة: </span>
          <span class="meta-value">${this.escapeHtml(vuln.category || 'عام')}</span>
        </div>
      </div>
    </div>
    
    <!-- Description -->
    <div class="steps-section">
      <div class="section-title">
        <span class="section-icon">📖</span>
        وصف الثغرة
      </div>
      <p>${this.escapeHtml(vuln.description || 'لم يتم توفير وصف')}</p>
    </div>
    
    <!-- Target URL -->
    <div class="steps-section">
      <div class="section-title">
        <span class="section-icon">🎯</span>
        الهدف المصاب
      </div>
      <div class="code-block">${this.escapeHtml(vuln.url || targetUrl)}</div>
    </div>
    
    <!-- Exploitation Steps -->
    <div class="steps-section">
      <div class="section-title">
        <span class="section-icon">🚀</span>
        خطوات الاستغلال
      </div>
      ${steps.map((step, i) => `
        <div class="step">
          <div class="step-number">${i + 1}</div>
          <div class="step-title">${this.escapeHtml(step.title)}</div>
          <div class="step-description">${this.escapeHtml(step.description)}</div>
          ${step.code ? `
            <div class="http-block">
              <div class="code-label">${step.codeLabel || 'الكود'}</div>
              <div class="code-block">${this.escapeHtml(step.code)}</div>
            </div>
          ` : ''}
        </div>
      `).join('')}
    </div>
    
    <!-- Evidence -->
    ${vuln.evidence ? `
    <div class="evidence-box">
      <div class="evidence-title">⚠️ الدليل (Evidence)</div>
      <div class="evidence-content">
        <div class="code-block">${this.escapeHtml(vuln.evidence)}</div>
      </div>
    </div>
    ` : ''}
    
    <!-- Request/Response if available -->
    ${vuln.request ? `
    <div class="steps-section">
      <div class="section-title">
        <span class="section-icon">📤</span>
        الطلب (Request)
      </div>
      <div class="code-block">${this.escapeHtml(vuln.request)}</div>
    </div>
    ` : ''}
    
    ${vuln.response ? `
    <div class="steps-section">
      <div class="section-title">
        <span class="section-icon">📥</span>
        الاستجابة (Response)
      </div>
      <div class="code-block">${this.escapeHtml(typeof vuln.response === 'string' ? vuln.response.substring(0, 2000) : JSON.stringify(vuln.response, null, 2))}</div>
    </div>
    ` : ''}
    
    <!-- cURL Command -->
    ${curlCommand ? `
    <div class="curl-box">
      <div class="curl-title">💻 أمر cURL للإعادة</div>
      <div class="curl-command">${this.escapeHtml(curlCommand)}</div>
    </div>
    ` : ''}
    
    <!-- Impact -->
    <div class="impact-box">
      <div class="impact-title">💥 التأثير المحتمل</div>
      <div class="impact-content">${this.getImpactDescription(vuln)}</div>
    </div>
    
    <!-- Remediation -->
    <div class="remediation-box">
      <div class="remediation-title">✅ كيفية الإصلاح</div>
      <div class="remediation-content">
        ${vuln.remediation || this.getDefaultRemediation(vuln)}
      </div>
    </div>
    
    <!-- References -->
    ${vuln.references && vuln.references.length > 0 ? `
    <div class="references-box">
      <div class="references-title">📚 مراجع إضافية</div>
      <ul class="references-list">
        ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
      </ul>
    </div>
    ` : ''}
    
    <div class="page-footer">
      تم إنشاء هذا التقرير بواسطة VulnHunter Pro | ${new Date().toLocaleDateString('ar-EG')}
    </div>
  </div>`;
  }

  /**
   * Generate exploitation steps based on vulnerability type
   */
  generateExploitationSteps(vuln) {
    const vulnType = (vuln.type || vuln.name || '').toLowerCase();
    const vulnUrl = vuln.url || '';
    const payload = vuln.payload || vuln.evidence || '';
    
    // XSS Steps
    if (vulnType.includes('xss') || vulnType.includes('cross-site scripting')) {
      return [
        {
          title: 'تحديد نقطة الحقن',
          description: 'تم اكتشاف معامل (parameter) يعكس المدخلات في الصفحة بدون تصفية كافية.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'اختبار الحقن الأساسي',
          description: 'تم إرسال payload بسيط لاختبار إمكانية تنفيذ JavaScript.',
          code: payload || '<script>alert(1)</script>',
          codeLabel: 'Payload'
        },
        {
          title: 'التحقق من التنفيذ',
          description: 'تم التأكد من أن الكود تم تنفيذه في المتصفح عن طريق ملاحظة الاستجابة.',
          code: vuln.evidence || 'تم تأكيد تنفيذ الـ JavaScript في الصفحة',
          codeLabel: 'النتيجة'
        },
        {
          title: 'تحليل السياق',
          description: 'تحديد السياق الذي يظهر فيه الـ payload (HTML, JavaScript, Attribute).',
          code: `السياق: ${vuln.context || 'HTML Body'}`,
          codeLabel: 'التحليل'
        }
      ];
    }
    
    // SQL Injection Steps
    if (vulnType.includes('sql') || vulnType.includes('sqli')) {
      return [
        {
          title: 'تحديد نقطة الحقن',
          description: 'تم اكتشاف معامل يتم تمريره مباشرة إلى استعلام SQL.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'اختبار الحقن',
          description: 'تم إرسال علامة اقتباس مفردة لاختبار وجود خطأ SQL.',
          code: payload || "' OR '1'='1",
          codeLabel: 'Payload'
        },
        {
          title: 'تحليل الاستجابة',
          description: 'تمت ملاحظة تغير في سلوك التطبيق أو رسالة خطأ SQL.',
          code: vuln.evidence || 'تم اكتشاف خطأ SQL أو تغير في الاستجابة',
          codeLabel: 'الدليل'
        },
        {
          title: 'تأكيد الثغرة',
          description: 'تم التأكد من إمكانية التلاعب بالاستعلام.',
          code: "UNION SELECT NULL, username, password FROM users--",
          codeLabel: 'Payload متقدم'
        }
      ];
    }
    
    // CSRF Steps
    if (vulnType.includes('csrf')) {
      return [
        {
          title: 'فحص الـ Token',
          description: 'تم فحص النموذج بحثاً عن CSRF token.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'تحليل الحماية',
          description: 'لم يتم العثور على token أو أنه قابل للتخمين.',
          code: vuln.evidence || 'لا يوجد CSRF Token في النموذج',
          codeLabel: 'الدليل'
        },
        {
          title: 'إنشاء صفحة استغلال',
          description: 'يمكن إنشاء صفحة HTML تقوم بإرسال الطلب تلقائياً.',
          code: `<form action="${vulnUrl}" method="POST">
  <input type="hidden" name="action" value="delete">
  <script>document.forms[0].submit();</script>
</form>`,
          codeLabel: 'PoC'
        }
      ];
    }
    
    // SSRF Steps
    if (vulnType.includes('ssrf')) {
      return [
        {
          title: 'تحديد وظيفة جلب URL',
          description: 'تم اكتشاف وظيفة تقوم بجلب محتوى من URL خارجي.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'اختبار الوصول الداخلي',
          description: 'تم محاولة الوصول لعناوين داخلية.',
          code: payload || 'http://127.0.0.1:80 أو http://169.254.169.254',
          codeLabel: 'Payload'
        },
        {
          title: 'التأكد من الثغرة',
          description: 'تمت ملاحظة استجابة من الخادم الداخلي.',
          code: vuln.evidence || 'تم الوصول لموارد داخلية',
          codeLabel: 'النتيجة'
        }
      ];
    }
    
    // LFI Steps
    if (vulnType.includes('lfi') || vulnType.includes('local file')) {
      return [
        {
          title: 'تحديد معامل الملف',
          description: 'تم اكتشاف معامل يقوم بتضمين ملفات.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'اختبار التجاوز',
          description: 'تم محاولة قراءة ملفات النظام باستخدام ../.',
          code: payload || '../../../../etc/passwd',
          codeLabel: 'Payload'
        },
        {
          title: 'قراءة الملف',
          description: 'تم التأكد من قراءة محتوى الملف.',
          code: vuln.evidence || 'root:x:0:0:root:/root:/bin/bash',
          codeLabel: 'محتوى الملف'
        }
      ];
    }
    
    // Header Issues
    if (vulnType.includes('header') || vulnType.includes('cors') || vulnType.includes('clickjack')) {
      return [
        {
          title: 'فحص الـ Headers',
          description: 'تم فحص headers الاستجابة للبحث عن مشاكل أمنية.',
          code: vulnUrl,
          codeLabel: 'URL'
        },
        {
          title: 'تحليل المشكلة',
          description: vuln.description || 'تم اكتشاف header مفقود أو غير آمن.',
          code: vuln.evidence || 'Header غير موجود أو قيمة غير آمنة',
          codeLabel: 'التفاصيل'
        }
      ];
    }
    
    // Default steps
    return [
      {
        title: 'اكتشاف الثغرة',
        description: 'تم اكتشاف الثغرة أثناء الفحص الآلي.',
        code: vulnUrl,
        codeLabel: 'الهدف'
      },
      {
        title: 'التحليل',
        description: vuln.description || 'تم تحليل الثغرة وتأكيد وجودها.',
        code: vuln.evidence || payload || 'تم التأكد من وجود الثغرة',
        codeLabel: 'الدليل'
      },
      {
        title: 'التأثير',
        description: this.getImpactDescription(vuln),
        code: null
      }
    ];
  }

  /**
   * Generate cURL command for vulnerability
   */
  generateCurlCommand(vuln, targetUrl) {
    const url = vuln.url || targetUrl;
    const method = vuln.method || 'GET';
    const payload = vuln.payload || '';
    
    if (method === 'POST' && payload) {
      return `curl -X POST "${url}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "${payload}"`;
    }
    
    if (payload && url.includes('?')) {
      return `curl "${url}"`;
    }
    
    return `curl -X ${method} "${url}"`;
  }

  /**
   * Get impact description based on vulnerability type
   */
  getImpactDescription(vuln) {
    const vulnType = (vuln.type || vuln.name || '').toLowerCase();
    
    if (vulnType.includes('xss')) {
      return 'يمكن للمهاجم سرقة cookies الجلسة، تنفيذ إجراءات نيابة عن المستخدم، سرقة بيانات حساسة، أو توجيه المستخدمين لمواقع ضارة.';
    }
    if (vulnType.includes('sql')) {
      return 'يمكن للمهاجم قراءة أو تعديل أو حذف بيانات قاعدة البيانات بالكامل، وفي بعض الحالات تنفيذ أوامر على الخادم.';
    }
    if (vulnType.includes('csrf')) {
      return 'يمكن للمهاجم إجبار المستخدم على تنفيذ إجراءات غير مرغوبة مثل تغيير كلمة المرور أو حذف الحساب.';
    }
    if (vulnType.includes('ssrf')) {
      return 'يمكن للمهاجم الوصول لموارد داخلية، قراءة metadata السحابية، أو مهاجمة خدمات داخلية.';
    }
    if (vulnType.includes('lfi')) {
      return 'يمكن للمهاجم قراءة ملفات حساسة من الخادم مثل ملفات الإعدادات وكلمات المرور.';
    }
    if (vulnType.includes('rce')) {
      return 'يمكن للمهاجم تنفيذ أوامر على الخادم والسيطرة الكاملة عليه.';
    }
    
    return vuln.impact || 'قد يؤدي استغلال هذه الثغرة إلى تعريض أمن التطبيق والبيانات للخطر.';
  }

  /**
   * Get default remediation based on vulnerability type
   */
  getDefaultRemediation(vuln) {
    const vulnType = (vuln.type || vuln.name || '').toLowerCase();
    
    if (vulnType.includes('xss')) {
      return `<ul class="remediation-list">
        <li>استخدم encoding للمخرجات حسب السياق (HTML, JavaScript, URL)</li>
        <li>طبق Content Security Policy (CSP)</li>
        <li>استخدم HttpOnly و Secure flags للـ cookies</li>
        <li>استخدم مكتبات تصفية موثوقة مثل DOMPurify</li>
      </ul>`;
    }
    if (vulnType.includes('sql')) {
      return `<ul class="remediation-list">
        <li>استخدم Prepared Statements مع معاملات</li>
        <li>استخدم ORM لتجنب SQL المباشر</li>
        <li>طبق مبدأ الحد الأدنى من الصلاحيات لمستخدم قاعدة البيانات</li>
        <li>تحقق من صحة المدخلات على الخادم</li>
      </ul>`;
    }
    if (vulnType.includes('csrf')) {
      return `<ul class="remediation-list">
        <li>أضف CSRF Token لكل نموذج</li>
        <li>استخدم SameSite Cookie attribute</li>
        <li>تحقق من header الـ Origin/Referer</li>
        <li>استخدم Double Submit Cookie pattern</li>
      </ul>`;
    }
    
    return 'اتبع أفضل الممارسات الأمنية وراجع دليل OWASP للحصول على تفاصيل الإصلاح.';
  }

  /**
   * Get Arabic severity name
   */
  getSeverityArabic(severity) {
    const map = {
      critical: 'حرجة',
      high: 'عالية',
      medium: 'متوسطة',
      low: 'منخفضة',
      informational: 'معلوماتية',
      info: 'معلوماتية'
    };
    return map[severity?.toLowerCase()] || severity;
  }
}

export default new ReportGenerator();
