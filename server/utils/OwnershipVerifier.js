import axios from 'axios';
import dns from 'dns';
import { promisify } from 'util';
import crypto from 'crypto';

const resolveTxt = promisify(dns.resolveTxt);

export class OwnershipVerifier {
  constructor() {
    this.verificationTokenPrefix = 'vulnhunter-verify=';
    this.tokenExpiry = 24 * 60 * 60 * 1000; // 24 hours
  }

  /**
   * Generate a unique verification token for a domain
   */
  generateToken(domain) {
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256')
      .update(`${domain}:${timestamp}:${randomBytes}`)
      .digest('hex')
      .substring(0, 32);
    
    return {
      token: hash,
      domain: domain,
      createdAt: timestamp,
      expiresAt: timestamp + this.tokenExpiry,
      dnsRecord: `${this.verificationTokenPrefix}${hash}`,
      httpPath: `/.well-known/vulnhunter-verification.txt`,
      httpContent: hash
    };
  }

  /**
   * Verify domain ownership via DNS TXT record
   */
  async verifyDNS(domain, expectedToken) {
    try {
      const records = await resolveTxt(domain);
      
      for (const record of records) {
        const txt = record.join('');
        if (txt === `${this.verificationTokenPrefix}${expectedToken}`) {
          return {
            verified: true,
            method: 'DNS',
            message: 'تم التحقق من الملكية عبر DNS TXT record'
          };
        }
      }
      
      return {
        verified: false,
        method: 'DNS',
        message: 'لم يتم العثور على سجل DNS TXT المطلوب'
      };
    } catch (error) {
      return {
        verified: false,
        method: 'DNS',
        message: `فشل التحقق من DNS: ${error.message}`
      };
    }
  }

  /**
   * Verify domain ownership via HTTP file
   */
  async verifyHTTP(domain, expectedToken, protocol = 'https') {
    const url = `${protocol}://${domain}/.well-known/vulnhunter-verification.txt`;
    
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'VulnHunter-Ownership-Verifier/1.0'
        }
      });
      
      if (response.status === 200) {
        const content = response.data.toString().trim();
        if (content === expectedToken) {
          return {
            verified: true,
            method: 'HTTP',
            message: 'تم التحقق من الملكية عبر ملف HTTP'
          };
        }
      }
      
      // Try HTTP if HTTPS failed
      if (protocol === 'https') {
        return this.verifyHTTP(domain, expectedToken, 'http');
      }
      
      return {
        verified: false,
        method: 'HTTP',
        message: 'محتوى ملف التحقق غير صحيح'
      };
    } catch (error) {
      // Try HTTP if HTTPS failed
      if (protocol === 'https') {
        return this.verifyHTTP(domain, expectedToken, 'http');
      }
      
      return {
        verified: false,
        method: 'HTTP',
        message: `فشل التحقق عبر HTTP: ${error.message}`
      };
    }
  }

  /**
   * Verify domain ownership using any available method
   */
  async verify(domain, expectedToken) {
    // Try DNS first
    const dnsResult = await this.verifyDNS(domain, expectedToken);
    if (dnsResult.verified) {
      return dnsResult;
    }
    
    // Try HTTP
    const httpResult = await this.verifyHTTP(domain, expectedToken);
    if (httpResult.verified) {
      return httpResult;
    }
    
    return {
      verified: false,
      method: 'none',
      message: 'فشل التحقق من الملكية. تأكد من إضافة سجل DNS TXT أو ملف التحقق.',
      dnsError: dnsResult.message,
      httpError: httpResult.message
    };
  }

  /**
   * Check if a token is still valid (not expired)
   */
  isTokenValid(tokenData) {
    return Date.now() < tokenData.expiresAt;
  }

  /**
   * Get verification instructions
   */
  getInstructions(tokenData) {
    return {
      ar: {
        title: 'تعليمات التحقق من ملكية الدومين',
        methods: [
          {
            name: 'طريقة DNS TXT (مستحسنة)',
            steps: [
              `سجل الدخول إلى لوحة تحكم DNS الخاصة بك`,
              `أضف سجل TXT جديد للدومين: ${tokenData.domain}`,
              `القيمة: ${tokenData.dnsRecord}`,
              `انتظر حتى تنتشر التغييرات (قد يستغرق حتى 24 ساعة)`,
              `اضغط "تحقق" للتأكيد`
            ]
          },
          {
            name: 'طريقة ملف HTTP',
            steps: [
              `أنشئ مجلد ".well-known" في جذر موقعك`,
              `أنشئ ملف باسم "vulnhunter-verification.txt"`,
              `أضف المحتوى التالي: ${tokenData.httpContent}`,
              `تأكد من إمكانية الوصول: ${tokenData.domain}${tokenData.httpPath}`,
              `اضغط "تحقق" للتأكيد`
            ]
          }
        ],
        warning: 'ينتهي صلاحية رمز التحقق خلال 24 ساعة'
      },
      en: {
        title: 'Domain Ownership Verification Instructions',
        methods: [
          {
            name: 'DNS TXT Method (Recommended)',
            steps: [
              `Log in to your DNS control panel`,
              `Add a new TXT record for domain: ${tokenData.domain}`,
              `Value: ${tokenData.dnsRecord}`,
              `Wait for DNS propagation (may take up to 24 hours)`,
              `Click "Verify" to confirm`
            ]
          },
          {
            name: 'HTTP File Method',
            steps: [
              `Create ".well-known" folder in your website root`,
              `Create file named "vulnhunter-verification.txt"`,
              `Add content: ${tokenData.httpContent}`,
              `Ensure accessibility: ${tokenData.domain}${tokenData.httpPath}`,
              `Click "Verify" to confirm`
            ]
          }
        ],
        warning: 'Verification token expires in 24 hours'
      }
    };
  }
}

export default new OwnershipVerifier();
