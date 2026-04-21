import puppeteer from 'puppeteer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ScreenshotCapture {
  constructor(options = {}) {
    this.options = {
      width: options.width || 1920,
      height: options.height || 1080,
      fullPage: options.fullPage !== false,
      timeout: options.timeout || 30000,
      ...options
    };
    this.screenshotsDir = path.join(__dirname, '../../screenshots');
    this.ensureDir();
  }
  
  ensureDir() {
    if (!fs.existsSync(this.screenshotsDir)) {
      fs.mkdirSync(this.screenshotsDir, { recursive: true });
    }
  }
  
  async captureUrl(url, filename = null) {
    let browser = null;
    
    try {
      browser = await puppeteer.launch({
        headless: 'new',
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--window-size=1920,1080'
        ]
      });
      
      const page = await browser.newPage();
      
      await page.setViewport({
        width: this.options.width,
        height: this.options.height
      });
      
      await page.setUserAgent(this.options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      
      // Navigate to URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait a bit for any lazy-loaded content
      await this.delay(1000);
      
      // Generate filename if not provided
      if (!filename) {
        const timestamp = Date.now();
        const urlHash = this.hashUrl(url);
        filename = `screenshot-${urlHash}-${timestamp}.png`;
      }
      
      const filepath = path.join(this.screenshotsDir, filename);
      
      // Take screenshot
      await page.screenshot({
        path: filepath,
        fullPage: this.options.fullPage,
        type: 'png'
      });
      
      await browser.close();
      
      return {
        success: true,
        filepath,
        filename,
        url
      };
      
    } catch (error) {
      if (browser) await browser.close();
      
      return {
        success: false,
        error: error.message,
        url
      };
    }
  }
  
  async captureMultiple(urls, scanId) {
    const results = [];
    const scanDir = path.join(this.screenshotsDir, scanId);
    
    if (!fs.existsSync(scanDir)) {
      fs.mkdirSync(scanDir, { recursive: true });
    }
    
    let browser = null;
    
    try {
      browser = await puppeteer.launch({
        headless: 'new',
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu'
        ]
      });
      
      const page = await browser.newPage();
      await page.setViewport({
        width: this.options.width,
        height: this.options.height
      });
      
      for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        
        try {
          await page.goto(url, {
            waitUntil: 'networkidle2',
            timeout: this.options.timeout
          });
          
          await this.delay(500);
          
          const filename = `page-${i + 1}-${this.hashUrl(url)}.png`;
          const filepath = path.join(scanDir, filename);
          
          await page.screenshot({
            path: filepath,
            fullPage: false,
            type: 'png'
          });
          
          results.push({
            success: true,
            filepath,
            filename,
            url,
            index: i + 1
          });
          
        } catch (error) {
          results.push({
            success: false,
            error: error.message,
            url,
            index: i + 1
          });
        }
      }
      
      await browser.close();
      
    } catch (error) {
      if (browser) await browser.close();
    }
    
    return results;
  }
  
  async captureVulnerability(vuln, scanId) {
    const scanDir = path.join(this.screenshotsDir, scanId, 'vulnerabilities');
    
    if (!fs.existsSync(scanDir)) {
      fs.mkdirSync(scanDir, { recursive: true });
    }
    
    const filename = `vuln-${vuln.type}-${this.hashUrl(vuln.url)}.png`;
    const filepath = path.join(scanDir, filename);
    
    const result = await this.captureUrl(vuln.url, null);
    
    if (result.success) {
      // Move to correct location
      fs.renameSync(result.filepath, filepath);
      return {
        ...result,
        filepath,
        filename
      };
    }
    
    return result;
  }
  
  hashUrl(url) {
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      const char = url.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).substring(0, 8);
  }
  
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  getScreenshotsForScan(scanId) {
    const scanDir = path.join(this.screenshotsDir, scanId);
    
    if (!fs.existsSync(scanDir)) {
      return [];
    }
    
    const files = [];
    
    const readDir = (dir, prefix = '') => {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          readDir(fullPath, path.join(prefix, item));
        } else if (item.endsWith('.png')) {
          files.push({
            filename: item,
            path: fullPath,
            relativePath: path.join(prefix, item)
          });
        }
      }
    };
    
    readDir(scanDir);
    return files;
  }
  
  cleanupScan(scanId) {
    const scanDir = path.join(this.screenshotsDir, scanId);
    
    if (fs.existsSync(scanDir)) {
      fs.rmSync(scanDir, { recursive: true, force: true });
    }
  }
}
