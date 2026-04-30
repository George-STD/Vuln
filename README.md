# 🔐 VulnHunter Pro | ماسح الثغرات الاحترافي

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node](https://img.shields.io/badge/node-18%2B-brightgreen.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

**أقوى ماسح ثغرات عربي لصائدي الجوائز | Enterprise-Grade Vulnerability Scanner**

[المميزات](#-المميزات) • [التثبيت](#-التثبيت) • [الاستخدام](#-طريقة-الاستخدام) • [Enterprise](#-enterprise-features) • [API](#-api-endpoints)

</div>

---

<div dir="rtl">

## 🎯 نظرة عامة

**VulnHunter Pro** هو ماسح ثغرات أمنية احترافي ومتكامل مصمم لصائدي الجوائز (Bug Bounty) ومختبري الاختراق. يجمع بين قوة أكثر من 21 وحدة فحص متخصصة مع واجهة عربية أنيقة وميزات مؤسسية متقدمة.

### 🌟 لماذا VulnHunter Pro؟

- 🎯 **مصمم للـ Bug Bounty**: متوافق مع Bugcrowd, HackerOne, Intigriti
- 📖 **تقارير PortSwigger-Style**: خطوات استغلال مفصلة لكل ثغرة
- 🏢 **Enterprise Ready**: Multi-tenant, RBAC, SSO, Audit Logs
- 🌐 **دعم عربي كامل**: واجهة وتقارير بالعربية

---

## ✨ المميزات

### 🔍 محركات الفحص (21+ وحدة)

| الوحدة | الوصف | الخطورة |
|--------|--------|---------|
| **XSSScanner** | Reflected, Stored, DOM-based XSS | عالية |
| **DOMXSSScanner** | فحص DOM XSS بـ Headless Browser | عالية |
| **SQLiScanner** | Error-based, Boolean, Time-based SQLi | حرجة |
| **CSRFScanner** | Cross-Site Request Forgery | متوسطة |
| **SSRFScanner** | Server-Side Request Forgery | عالية |
| **LFIScanner** | Local File Inclusion & Path Traversal | عالية |
| **RCEScanner** | Remote Code Execution | حرجة |
| **XXEScanner** | XML External Entity Injection | عالية |
| **IDORScanner** | Insecure Direct Object Reference | عالية |
| **OpenRedirectScanner** | Open Redirect vulnerabilities | متوسطة |
| **CORSScanner** | CORS Misconfiguration | متوسطة |
| **ClickjackingScanner** | X-Frame-Options & CSP | منخفضة |
| **HeaderScanner** | Security Headers Analysis | منخفضة |
| **CookieScanner** | Cookie Security Flags | متوسطة |
| **SSLScanner** | SSL/TLS Certificate Analysis | متوسطة |
| **AuthBypassScanner** | Authentication Bypass | حرجة |
| **SensitiveDataScanner** | Exposed Secrets & API Keys | عالية |
| **DirectoryScanner** | Directory Traversal & Bruteforce | متوسطة |
| **SubdomainScanner** | Subdomain Enumeration | معلوماتية |
| **PortScanner** | Common Port Scanning | معلوماتية |
| **TechStackScanner** | Technology Detection | معلوماتية |

### 🛠️ أدوات متقدمة

| الأداة | الوصف |
|--------|--------|
| **HeadlessCrawler** | زاحف ذكي بـ Puppeteer لاكتشاف SPAs |
| **WAFDetector** | كشف 30+ WAF/CDN |
| **ScreenshotCapture** | التقاط صور للثغرات |
| **OpenAPIImporter** | استيراد Swagger/OpenAPI specs |
| **RobotsParser** | تحليل robots.txt و sitemap.xml |
| **ScanScheduler** | جدولة فحوصات مؤقتة |
| **LearningEngine** | ذاكرة تكيفية لتقليل FP + استيراد قواعد من write-ups |
| **InteractiveBrowserScanner** | تفاعلات متصفح شبيهة بالبشر لاكتشاف إشارات ثغرات منطقية |

### 📊 تنسيقات التقارير

| التنسيق | الوصف | الاستخدام |
|---------|--------|-----------|
| **Walkthrough PDF** | 📖 دليل استغلال PortSwigger-style | Bug Bounty Reports |
| **PDF** | تقرير PDF احترافي | العملاء |
| **HTML** | تقرير تفاعلي | العرض |
| **JSON** | بيانات خام | Integration |
| **Markdown** | توثيق | GitHub |
| **SARIF** | Static Analysis Results | CI/CD Integration |

---

## 🏢 Enterprise Features

### 🔐 الأمان والتحكم

| الميزة | الوصف |
|--------|--------|
| **RBAC** | 6 أدوار: Super Admin, Admin, Manager, Analyst, Viewer, API |
| **SSO** | SAML 2.0 و OpenID Connect |
| **MFA** | مصادقة متعددة العوامل |
| **Audit Logs** | 50+ نوع حدث مع تتبع كامل |

### 👥 Multi-Tenancy

| الخطة | الحد | الميزات |
|-------|------|---------|
| **FREE** | 10 فحوصات/شهر | أساسية |
| **PRO** | 100 فحوصات/شهر | API + تقارير |
| **ENTERPRISE** | غير محدود | كل شيء + SSO |

### 🔗 التكاملات

| المنصة | الميزات |
|--------|---------|
| **Jira** | إنشاء tickets تلقائي |
| **GitHub** | Issues + Security Advisories |
| **Slack** | إشعارات فورية |

### 🔧 إضافي

| الميزة | الوصف |
|--------|--------|
| **Worker Manager** | فحص موزع على عدة workers |
| **Credential Vault** | تخزين مشفر AES-256-GCM |
| **Plugin System** | نظام إضافات قابل للتوسيع |

---

## 🚀 التثبيت

### المتطلبات
- Node.js 18+
- npm أو yarn
- Chrome/Chromium (للـ Headless Browser)

### التثبيت السريع

```bash
# استنساخ المشروع
git clone <repository-url>
cd "Auto vulnerability tester"

# تثبيت جميع الحزم
npm run install:all

# أو بشكل منفصل:
cd server && npm install
cd ../client && npm install
```

### إعداد البيئة

```bash
# إنشاء ملف .env في مجلد server
cp server/.env.example server/.env

# تعديل المتغيرات
PORT=3001
CLIENT_URL=http://localhost:5173
JWT_SECRET=your-secret-key
ENCRYPTION_KEY=your-32-char-key

# التعلم التلقائي من write-ups (اختياري)
AUTO_LEARN_WRITEUPS_ENABLED=true
AUTO_LEARN_INTERVAL_MS=60000
AUTO_LEARN_DISCOVERY_INTERVAL_MS=600000
AUTO_LEARN_MAX_RULES_PER_LINK=4
AUTO_LEARN_MAX_PER_SOURCE=40
```

---

## 💻 التشغيل

### وضع التطوير

```bash
# تشغيل السيرفر والواجهة معاً
npm run dev

# أو بشكل منفصل:
# Terminal 1 - السيرفر
cd server && npm run dev

# Terminal 2 - الواجهة
cd client && npm run dev
```

### وضع الإنتاج

```bash
# بناء الواجهة
cd client && npm run build

# تشغيل السيرفر
cd server && npm start
```

### الوصول
- **الواجهة**: http://localhost:5173
- **API**: http://localhost:3001
- **Health Check**: http://localhost:3001/api/health

---

## 📖 طريقة الاستخدام

### 1️⃣ الفحص الأساسي

1. افتح الواجهة على `http://localhost:5173`
2. أدخل رابط الموقع المراد فحصه
3. اختر نوع الفحص (سريع/شامل/مخصص)
4. اضغط **"ابدأ الفحص"**
5. تابع التقدم في الوقت الحقيقي

إعدادات متقدمة جديدة في الواجهة:
- **مدة الفحص الزمني (بالدقائق)**: يستمر تشغيل دورات الفحص النشط حتى انتهاء الوقت المحدد.
- **نسبة استخدام قواعد التعلّم (%)**: استخدام نسبة محددة فقط من قواعد الـ write-ups المتعلّمة في الفحص التالي لموازنة السرعة مع التغطية.

### 2️⃣ تصدير التقارير

بعد اكتمال الفحص:

| الزر | الناتج |
|------|--------|
| **Walkthrough** | 📖 PDF مع خطوات استغلال مفصلة |
| **PDF** | تقرير PDF قياسي |
| **HTML** | تقرير HTML تفاعلي |
| **JSON** | بيانات خام |
| **SARIF** | لـ CI/CD pipelines |

### 3️⃣ التحقق من الملكية

للفحص الكامل، يجب إثبات ملكية الموقع:
- **HTTP**: إضافة ملف `.well-known/vulnhunter.txt`
- **DNS**: إضافة TXT record

---

## �️ Bug Bounty Safety System

نظام شامل للحفاظ على الالتزام بقواعد برامج Bug Bounty:

### 📋 إدارة النطاقات (Scope Management)

| الميزة | الوصف |
|--------|--------|
| **In-Scope Domains** | تحديد الدومينات المسموحة مع wildcards (`*.example.com`) |
| **Out-of-Scope Paths** | استبعاد مسارات معينة (`/admin/*`, `/logout`) |
| **IP Ranges** | تحديد نطاقات IP المسموحة |
| **Ports & Protocols** | تقييد المنافذ والبروتوكولات |
| **Third-Party Blacklist** | حظر تلقائي لـ 40+ CDN/Auth provider |

### 🚦 ضوابط السلامة (Safety Controls)

| الميزة | الوصف | القيمة الافتراضية |
|--------|--------|------------------|
| **Global RPS** | الحد الأقصى للطلبات/ثانية | 3 |
| **Per-Host RPS** | طلبات لكل host | 1 |
| **Max URLs** | عدد URLs المفحوصة | 200 |
| **Max Depth** | عمق الزحف | 2 |
| **Safe Mode** | GET/HEAD فقط، لا payloads خطيرة | ✅ |
| **Anti-DoS** | backoff تلقائي عند 429/503 | ✅ |

### 🎯 ملفات تعريف البرامج (Program Profiles)

قوالب جاهزة لمختلف المنصات:

```javascript
// استخدام قالب جاهز
bountySystem.loadTemplate('hackerone-standard');

// القوالب المتاحة:
- bugcrowd-standard   // آمن جداً
- hackerone-standard  // متوازن
- intigriti-standard  // متوازن
- aggressive          // للمواقع الخاصة فقط
- minimal             // فحص headers فقط
```

### ✅ فحص ما قبل البدء (Preflight Checks)

فحوصات تلقائية قبل بدء أي scan:

1. ✅ التحقق من صحة URL
2. ✅ التحقق من الـ Scope
3. ✅ التحقق من إعدادات السلامة
4. ✅ التحقق من نافذة الوقت المسموحة
5. ✅ طلب تأكيدات المستخدم

### 🛑 Kill Switch

إيقاف طوارئ فوري لكل العمليات:

| الميزة | الوصف |
|--------|--------|
| **Activate** | إيقاف جميع الفحوصات فوراً |
| **AbortController** | إلغاء كل الطلبات المعلقة |
| **Worker Stop** | إيقاف جميع workers |
| **Resume** | استئناف بعد التأكد من الأمان |

### 🌐 API Endpoints للـ Bug Bounty

```
GET  /api/bounty/status        - حالة النظام
POST /api/bounty/enable        - تفعيل النظام
POST /api/bounty/disable       - تعطيل النظام
POST /api/bounty/scope/in-scope    - تعيين domains مسموحة
POST /api/bounty/scope/out-of-scope - تعيين مسارات ممنوعة
POST /api/bounty/safety/rate-limits - تعديل rate limiting
POST /api/bounty/profiles/load/:id  - تحميل profile
POST /api/bounty/preflight     - تنفيذ preflight check
POST /api/bounty/kill-switch/activate   - تفعيل Kill Switch
POST /api/bounty/kill-switch/deactivate - إلغاء Kill Switch
```

---

## �🔧 API Endpoints

### الفحص الأساسي

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `POST` | `/api/scan` | بدء فحص جديد |
| `GET` | `/api/scan/:id` | جلب حالة الفحص |
| `POST` | `/api/scan/:id/stop` | إيقاف الفحص |

### التقارير

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `GET` | `/api/scan/:id/report?format=pdf` | تقرير PDF |
| `GET` | `/api/scan/:id/walkthrough` | 📖 Walkthrough PDF |
| `GET` | `/api/scan/:id/sarif` | تصدير SARIF |
| `POST` | `/api/walkthrough/generate` | إنشاء walkthrough من JSON |

### التعلم التكيفي (Adaptive Learning)

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `GET` | `/api/learning/status` | حالة ذاكرة التعلم والقواعد |
| `GET` | `/api/learning/writeups` | عرض قواعد write-ups المستوردة |
| `POST` | `/api/learning/writeups/import` | استيراد قواعد كشف جديدة من write-ups |
| `POST` | `/api/learning/writeups/import-links` | جلب روابط write-ups وتوليد قواعد كشف تلقائياً |
| `POST` | `/api/learning/feedback` | تسجيل ملاحظات true/false positive |
| `GET` | `/api/learning/auto/status` | حالة التعلم التلقائي |
| `POST` | `/api/learning/auto/start` | بدء التعلم التلقائي من write-ups |
| `POST` | `/api/learning/auto/stop` | إيقاف التعلم التلقائي |
| `POST` | `/api/learning/auto/tick` | تنفيذ دورة تعلّم واحدة فوراً |
| `POST` | `/api/learning/cleanup` | تنظيف القواعد المتعلمة (حذف المكرر/ضعيف الفائدة) |

يتم حفظ بيانات التعلّم وحالة المعلّم التلقائي داخل `server/data/learning/`:
`feedback.json` و`writeup-rules.json` و`writeup-history.json` و`auto-learner-state.json`.

### الجدولة

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `GET` | `/api/schedules` | جلب الجداول |
| `POST` | `/api/schedules` | إنشاء جدول جديد |
| `DELETE` | `/api/schedules/:id` | حذف جدول |

### OpenAPI

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `POST` | `/api/openapi/import` | استيراد OpenAPI spec |
| `POST` | `/api/openapi/discover` | اكتشاف spec تلقائياً |

### Enterprise

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `POST` | `/api/enterprise/auth/login` | تسجيل الدخول |
| `GET` | `/api/enterprise/tenants` | إدارة المستأجرين |
| `GET` | `/api/enterprise/audit/logs` | سجلات التدقيق |
| `GET` | `/api/enterprise/workers/status` | حالة الـ workers |

---

## 🏗️ البنية المعمارية

```
VulnHunter Pro/
├── 📁 server/
│   ├── index.js                      # Express + Socket.IO Server
│   ├── 📁 scanner/
│   │   ├── VulnerabilityScanner.js   # المنسق الرئيسي
│   │   └── 📁 modules/               # 21+ Scanner Modules
│   │       ├── BaseScanner.js
│   │       ├── XSSScanner.js
│   │       ├── DOMXSSScanner.js
│   │       ├── SQLiScanner.js
│   │       ├── HeadlessCrawler.js
│   │       ├── ScanScheduler.js
│   │       └── ...
│   ├── 📁 utils/
│   │   ├── ReportGenerator.js        # HTML/PDF/Walkthrough
│   │   ├── SARIFExporter.js
│   │   ├── OwnershipVerifier.js
│   │   └── Logger.js
│   ├── 📁 auth/                      # RBAC + SSO
│   ├── 📁 tenants/                   # Multi-tenancy
│   ├── 📁 workers/                   # Distributed Scanning
│   ├── 📁 integrations/              # Jira/GitHub/Slack
│   ├── 📁 audit/                     # Audit Logging
│   ├── 📁 vault/                     # Credential Storage
│   └── 📁 plugins/                   # Plugin System
├── 📁 client/
│   ├── 📁 src/
│   │   ├── App.jsx
│   │   └── 📁 components/
│   │       ├── ScanForm.jsx
│   │       ├── ScanProgress.jsx
│   │       ├── ScanSummary.jsx
│   │       ├── VulnerabilityList.jsx
│   │       ├── EnterpriseDashboard.jsx
│   │       ├── ScheduledScans.jsx
│   │       └── OwnershipVerification.jsx
│   └── ...
├── 📁 reports/                       # Generated Reports
└── 📁 logs/                          # Application Logs
```

---

## ⚙️ الإعدادات المتقدمة

### خيارات الفحص

```javascript
{
  depth: 3,           // عمق الزحف
  maxUrls: 100,       // أقصى عدد روابط
  timeout: 30000,     // المهلة بالميلي ثانية
  threads: 5,         // عدد الخيوط المتوازية
  enableScreenshots: true,  // التقاط صور
  bypassWAF: false,   // محاولة تجاوز WAF
  scanModules: [      // الوحدات المفعلة
    'xss', 'sqli', 'csrf', 'ssrf', 'lfi', 
    'rce', 'xxe', 'idor', 'headers', 'ssl'
  ]
}
```

### Scan Templates

| القالب | الوحدات | الوقت |
|--------|---------|-------|
| **Quick** | Headers, SSL, CORS | ~1 دقيقة |
| **Standard** | 10 وحدات أساسية | ~5 دقائق |
| **Full** | جميع الوحدات الـ 21 | ~15 دقيقة |
| **Custom** | اختيار يدوي | متغير |

---

## ⚠️ تحذيرات مهمة

> **⚖️ للاستخدام الأخلاقي والقانوني فقط!**
> 
> - ✅ افحص فقط المواقع التي تملكها
> - ✅ استخدم في برامج Bug Bounty المصرح بها
> - ✅ احصل على إذن كتابي قبل الفحص
> - ❌ لا تفحص مواقع بدون إذن
> - ❌ لا تستخدم لأغراض ضارة
> 
> **المطورون غير مسؤولين عن أي استخدام غير قانوني**

---

## 📚 المراجع والمصادر

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy)

---

## 🤝 المساهمة

نرحب بمساهماتكم! 

```bash
# 1. Fork المشروع
# 2. أنشئ branch جديد
git checkout -b feature/amazing-feature

# 3. Commit التغييرات
git commit -m 'Add amazing feature'

# 4. Push
git push origin feature/amazing-feature

# 5. افتح Pull Request
```

### مجالات المساهمة
- 🔍 إضافة وحدات فحص جديدة
- 🌐 تحسين الترجمة العربية
- 📖 توثيق وأمثلة
- 🐛 إصلاح الأخطاء

---

## 📜 الرخصة

MIT License - للاستخدام الأخلاقي فقط

---

<div align="center">

**صُنع بـ ❤️ للمجتمع العربي**

⭐ إذا أعجبك المشروع، لا تنسى النجمة!

[🇬🇧 Read in English](README-EN.md)

</div>

</div>
