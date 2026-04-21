import { createContext, useContext, useState, useEffect } from 'react';

// الترجمات
const translations = {
  en: {
    // Header
    appName: 'VulnHunter',
    appSubtitle: 'Vulnerability Scanner Pro',
    scanner: 'Scanner',
    schedules: 'Schedules',
    enterprise: 'Enterprise',
    bugBounty: 'Bug Bounty',
    connected: 'Connected',
    disconnected: 'Disconnected',
    
    // ScanForm
    heroTitle: 'Discover Security Vulnerabilities',
    heroDescription: 'The most powerful automated vulnerability scanner - scans websites and discovers all security vulnerabilities with detailed explanations of how they were found and how to fix them',
    urlPlaceholder: 'Enter website URL to scan... (e.g., example.com)',
    selectScanType: 'Select scan type:',
    startScan: 'Start Scan Now',
    ethicalWarning: '⚠️ For ethical use only - make sure to get permission before scanning any website',
    
    // Scan Templates
    quickScan: 'Quick Scan',
    quickScanDesc: 'Basic scan for common vulnerabilities - 5 minutes',
    standardScan: 'Standard Scan',
    standardScanDesc: 'Balanced vulnerability scan - 15 minutes',
    deepScan: 'Deep Scan',
    deepScanDesc: 'Comprehensive intensive scan - 30+ minutes',
    owaspScan: 'OWASP Top 10',
    owaspScanDesc: 'Scan for top 10 OWASP vulnerabilities',
    apiScan: 'API Scan',
    apiScanDesc: 'Custom scan for REST APIs',
    
    // Features
    features: 'Features',
    comprehensiveScan: 'Comprehensive Scan',
    comprehensiveScanDesc: 'More than 20 vulnerability types',
    fastEfficient: 'Fast & Efficient',
    fastEfficientDesc: 'Parallel scanning for better performance',
    detailedReports: 'Detailed Reports',
    detailedReportsDesc: 'Explanation of how each vulnerability was found',
    highAccuracy: 'High Accuracy',
    highAccuracyDesc: 'Advanced payloads from PortSwigger',
    
    // Advanced Options
    advancedOptions: 'Advanced Options',
    crawlingSettings: 'Crawling Settings',
    scanDepth: 'Scan Depth',
    maxUrls: 'Max URLs',
    timeout: 'Timeout (seconds)',
    rateControl: 'Rate Control',
    requestsPerSecond: 'Requests/Second',
    delayMs: 'Delay (ms)',
    parallelThreads: 'Parallel Threads',
    lowerIsSafer: 'Lower = safer for the site',
    delayBetweenRequests: 'Delay between requests',
    moreIsFasterButHeavier: 'More = faster but heavier',
    
    // Safety Settings
    safetySettings: 'Safety Settings',
    respectRobots: '🤖 Respect robots.txt',
    followRedirects: '↪️ Follow redirects',
    detectWAF: '🛡️ Detect WAF/CDN',
    captureScreenshots: '📸 Capture Screenshots',
    aggressiveMode: '⚔️ Aggressive Mode ⚠️',
    ownershipVerification: '🔐 Ownership Verification',
    headlessCrawling: '🌐 JavaScript Crawling (SPA)',
    
    // Vulnerability Types
    vulnTypesTitle: 'Detected Vulnerability Types:',
    vulnTypesHint: '💡 Click on any vulnerability to learn more about it and how to protect against it',
    
    // Vulnerability Education
    whatIsThis: 'What is this vulnerability?',
    vulnTypes: 'Vulnerability Types',
    potentialImpact: 'Potential Impact',
    example: 'Example',
    howToProtect: 'How to Protect',
    learningResources: 'Learning Resources',
    quickTips: 'Quick Tips',
    tip1: 'Always validate inputs (Input Validation)',
    tip2: 'Use trusted and updated security libraries',
    tip3: 'Apply the principle of least privilege',
    tip4: 'Regularly test code using scanning tools',
    noVulnInfoAvailable: 'No information available for this vulnerability',
    
    // Scan Progress
    scanningTarget: 'Scanning Target',
    progress: 'Progress',
    phase: 'Phase',
    stopScan: 'Stop Scan',
    discoveredVulns: 'Discovered Vulnerabilities',
    
    // Phases
    phaseReconnaissance: 'Reconnaissance',
    phaseCrawling: 'Crawling',
    phaseTechDetection: 'Technology Detection',
    phaseVulnScanning: 'Vulnerability Scanning',
    phaseGeneratingSummary: 'Generating Summary',
    phaseCapturingScreenshots: 'Capturing Screenshots',
    phaseCompleted: 'Completed',
    
    // Scan Summary
    scanComplete: 'Scan Complete!',
    totalVulns: 'Total Vulnerabilities',
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
    scanDuration: 'Scan Duration',
    urlsScanned: 'URLs Scanned',
    formsFound: 'Forms Found',
    
    // Export
    exportReport: 'Export Report',
    walkthrough: 'Walkthrough',
    walkthroughTooltip: 'Detailed exploitation guide - PortSwigger style',
    exportForCICD: 'Export for CI/CD',
    newScan: 'New Scan',
    scanResults: 'Scan Results',
    forms: 'Forms',
    detectedTechnologies: 'Detected Technologies:',
    
    // Toast Messages
    scanCompleted: '✅ Scan completed successfully!',
    criticalVuln: '🔴 Critical vulnerability:',
    highVuln: '🟠 High vulnerability:',
    pleaseEnterUrl: 'Please enter a website URL',
    scanStarting: '🔍 Starting scan...',
    scanStopped: '⏹️ Scan stopped',
    failedStopScan: 'Failed to stop scan',
    sarifExportSuccess: '📄 SARIF export successful',
    sarifExportFailed: 'Failed to export SARIF',
    walkthroughSuccess: '📖 Walkthrough created successfully!',
    walkthroughFailed: 'Failed to create walkthrough',
    reportFailed: 'Failed to create report',
    
    // Vulnerability List
    vulnerabilities: 'Vulnerabilities',
    severity: 'Severity',
    confidence: 'Confidence',
    evidence: 'Evidence',
    payload: 'Payload',
    recommendation: 'Recommendation',
    copyCurl: 'Copy cURL',
    copyDetails: 'Copy Details',
    vulnType: 'Vulnerability Type',
    url: 'URL',
    description: 'Description',
    fixMethod: 'Fix Method',
    curlCopied: 'cURL command copied!',
    noVulnsFound: 'No vulnerabilities found!',
    siteAppearsSecure: 'The site appears to be secure based on the current scan',
    searchVulnerabilities: 'Search vulnerabilities...',
    all: 'All',
    type: 'Type',
    allTypes: 'All Types',
    
    // Bug Bounty Settings
    bugBountySettings: 'Bug Bounty Settings',
    systemStatus: 'System Status',
    enabled: 'Enabled',
    disabled: 'Disabled',
    emergencyStop: 'Emergency Stop',
    resume: 'Resume',
    killSwitchActive: 'Kill Switch Active - All scan operations stopped',
    
    // Tabs
    overview: 'Overview',
    scope: 'Scope',
    safety: 'Safety',
    profiles: 'Profiles',
    preflight: 'Preflight',
    
    // Scope
    inScope: 'In-Scope (Allowed)',
    outOfScope: 'Out-of-Scope (Blocked)',
    saveScope: 'Save Scope',
    importFromText: 'Import from Text (Bugcrowd/HackerOne format)',
    import: 'Import',
    
    // Safety
    safeMode: 'Safe Mode',
    safeModeDesc: 'Restricts requests to GET/HEAD only and prevents destructive actions',
    rateLimiting: 'Rate Limiting',
    globalRPS: 'Global RPS',
    perHostRPS: 'Per-Host RPS',
    maxConcurrency: 'Max Concurrency',
    crawlingLimits: 'Crawling Limits',
    maxDepth: 'Max Depth',
    saveSafetySettings: 'Save Safety Settings',
    
    // Profiles
    readyTemplates: 'Ready Templates',
    savedProfiles: 'Saved Profiles',
    noSavedProfiles: 'No saved profiles',
    load: 'Load',
    
    // Preflight
    preflightCheck: 'Preflight Check',
    preflightDesc: 'Verify that the URL is within the allowed scope and all settings are correct before starting the scan',
    target: 'Target',
    check: 'Check',
    checkResults: 'Check Results:',
    readyToScan: '✓ Ready to scan',
    hasIssues: '✗ Has issues',
    warnings: 'Warnings:',
    requiredConfirmations: 'Required Confirmations:',
    
    // Quick Setup
    quickSetup: 'Quick Setup',
    enterAllowedDomains: 'Enter allowed domains (one per line)',
    applySafeSettings: 'Apply Safe Settings',
    currentSettings: 'Current Settings',
    rateLimit: 'Rate Limit',
    methods: 'Methods',
    profile: 'Profile',
    none: 'None',
    
    // Confirmations
    havePermission: 'I have permission',
    havePermissionDesc: 'I confirm that I have written permission from the site owner or it is part of an active Bug Bounty program',
    withinScope: 'Within Scope',
    withinScopeDesc: 'I confirm that the target is within the allowed scope according to program rules',
    takeResponsibility: 'Take Responsibility',
    takeResponsibilityDesc: 'I understand that I am responsible for any damage that may occur and I commit to ethical scanning only',
    cancel: 'Cancel',
    completeConfirmations: 'Complete Confirmations',
    cannotStart: '⚠️ Cannot start - check settings first',
    
    // Scheduled Scans
    scheduledScans: 'Scheduled Scans',
    scheduleNewScan: 'Schedule New Scan',
    noScheduledScans: 'No scheduled scans',
    back: 'Back',
    everyHour: 'Every Hour',
    every6Hours: 'Every 6 Hours',
    dailyMidnight: 'Daily at Midnight',
    daily8AM: 'Daily at 8 AM',
    weeklySunday: 'Weekly (Sunday)',
    monthly: 'Monthly',
    confirmDeleteSchedule: 'Are you sure you want to delete this schedule?',
    scanStarted: 'Scan started',
    
    // Enterprise
    enterpriseDashboard: 'Enterprise Dashboard',
    manageWorkersIntegrations: 'Manage workers, integrations, and settings',
    refresh: 'Refresh',
    workers: 'Workers',
    integrations: 'Integrations',
    auditLog: 'Audit Log',
    credentialVault: 'Credential Vault',
    plugins: 'Plugins',
    
    // Status
    available: 'Available',
    busy: 'Busy',
    offline: 'Offline',
    installed: 'Installed',
    active: 'Active',
    pending: 'Pending',
    total: 'Total',
    queue: 'Queue',
    
    // Workers
    distributedWorkers: 'Distributed Scan Workers',
    addWorker: 'Add Worker',
    noWorkersRegistered: 'No workers registered',
    workerStatus: 'Worker Status',
    lastSeen: 'Last Seen',
    capabilities: 'Capabilities',
    registerNew: 'Register New',
    removeWorker: 'Remove Worker',
    
    // Integrations
    externalIntegrations: 'External Integrations',
    configure: 'Configure',
    slackIntegration: 'Slack Integration',
    jiraIntegration: 'Jira Integration',
    githubIntegration: 'GitHub Integration',
    notConnected: 'Not Connected',
    connect: 'Connect',
    disconnect: 'Disconnect',
    
    // Audit Log
    auditLogTitle: 'Audit Log & Events',
    loadMoreLogs: 'Load More',
    noAuditLogs: 'No audit logs',
    action: 'Action',
    user: 'User',
    timestamp: 'Timestamp',
    details: 'Details',
    
    // Credential Vault
    credentialVaultTitle: 'Credential Vault',
    addCredential: 'Add Credential',
    noCredentials: 'No saved credentials',
    credentialName: 'Credential Name',
    credentialType: 'Type',
    createdAt: 'Created At',
    lastUsed: 'Last Used',
    deleteCredential: 'Delete',
    
    // Plugins
    pluginsTitle: 'Plugin System',
    installPlugin: 'Install Plugin',
    noPlugins: 'No plugins installed',
    pluginName: 'Plugin Name',
    pluginVersion: 'Version',
    pluginAuthor: 'Author',
    enablePlugin: 'Enable',
    disablePlugin: 'Disable',
    uninstallPlugin: 'Uninstall',
    
    // Scheduled Scans - Additional
    addNewSchedule: 'Add New Schedule',
    scheduleName: 'Schedule Name',
    targetUrl: 'Target URL',
    runTiming: 'Run Timing',
    customCron: 'Custom (CRON expression)',
    cronExpression: 'CRON Expression',
    enableSchedule: 'Enable Schedule',
    createSchedule: 'Create Schedule',
    editSchedule: 'Edit Schedule',
    saveChanges: 'Save Changes',
    runNow: 'Run Now',
    enable: 'Enable',
    nextRun: 'Next Run',
    lastRun: 'Last Run',
    never: 'Never',
    
    // Bug Bounty - Additional
    systemDisabled: 'System disabled',
    systemEnabled: 'System enabled',
    failedChangeStatus: 'Failed to change system status',
    killSwitchActiveMessage: 'Kill Switch Active - All operations stopped',
    settingsLoadFailed: 'Failed to load settings',
    settingsSaved: 'Settings saved',
    settingsSaveFailed: 'Failed to save settings',
    scopeSaved: 'Scope saved',
    scopeSaveFailed: 'Failed to save scope',
    profileLoaded: 'Profile loaded',
    profileLoadFailed: 'Failed to load profile',
    
    // Ownership Verification
    ownershipVerificationTitle: 'Website Ownership Verification',
    ownershipVerificationDesc: 'For safe and ethical scanning, please verify your website ownership',
    generateTokenInfo: 'We will generate a unique verification token that you can use to prove your website ownership',
    generateTokenButton: 'Generate Verification Token',
    verifyOwnership: 'Verify Ownership',
    verifyingOwnership: 'Verifying...',
    verificationMethod: 'Verification Method',
    httpFileMethod: 'HTTP File',
    dnsRecordMethod: 'DNS Record',
    uploadFileInfo: 'Upload a file with the following content to your website',
    addDnsRecordInfo: 'Add the following TXT record to your DNS',
    skipVerification: 'Skip Verification',
    verificationSuccess: 'Verification successful!',
    verificationFailed: 'Verification failed',
    failedToGenerateToken: 'Failed to generate verification token',
    failedToVerifyOwnership: 'Failed to verify ownership',
    copyToClipboard: 'Copy to clipboard',
    copied: 'Copied!',
    
    // Preflight Confirmation
    checkingSettings: 'Checking settings...',
    preflightSuccess: 'Preflight Check Passed',
    preflightFailed: 'Preflight Check Failed',
    connectionFailed: 'Connection failed',
    couldNotVerifyBountySettings: 'Could not verify Bug Bounty settings',
    proceedWithScan: 'Proceed with Scan',
    currentScans: 'Current Scans',
    completed: 'Completed',
    
    // Errors
    failedLoadData: 'Failed to load data',
    failedLoadSchedules: 'Failed to load schedules',
    failedCreateSchedule: 'Failed to create schedule',
    failedUpdateSchedule: 'Failed to update schedule',
    failedDeleteSchedule: 'Failed to delete schedule',
    failedStartScan: 'Failed to start scan',
    
    // Footer
    footerText: 'Built for Bug Bounty Hunters',
    madeWith: 'Made with',
    forCommunity: 'for the community',
    allRightsReserved: 'All Rights Reserved',
    
    // Scan Progress
    scanningInProgress: 'Scanning in progress...',
    stop: 'Stop',
    currentPhase: 'Current Phase',
    vulnerabilitiesFound: 'Vulnerabilities Found',
    recentVulnerabilities: 'Recently Discovered Vulnerabilities',
    searchingForVulns: 'Searching for vulnerabilities...',
    
    // ScanForm additions
    discoverVulnerabilities: 'Discover Security Vulnerabilities',
    scanFormDescription: 'The most powerful automated vulnerability scanner - scans websites and discovers all security vulnerabilities with detailed explanations of how they were found and how to fix them',
    enterUrlPlaceholder: 'Enter website URL to scan... (e.g., example.com)',
    chooseScanType: 'Choose scan type:',
    advancedSettings: 'Advanced Settings',
    delay: 'Delay (ms)',
    jsCrawling: 'JavaScript Crawling (SPA)',
    resultQuality: 'Result Quality',
    verificationMode: 'Verification Mode (reduce false positives)',
    includePotentialFindings: 'Include potential findings',
    enableDomXssHeadless: 'Enable DOM XSS headless verification',
    minimumConfidenceScore: 'Minimum Confidence Score',
    verificationQuality: 'Verification Quality',
    confirmedFindings: 'Confirmed',
    probableFindings: 'Probable',
    potentialFindings: 'Potential',
    filteredOutFindings: 'Filtered Out',
    verificationEnabledText: 'Verification',
    minimumConfidenceText: 'Minimum confidence',
    enabledText: 'enabled',
    disabledText: 'disabled',
    startScanNow: 'Start Scan Now',
    ethicalUseWarning: 'For ethical use only - make sure to get permission before scanning any website',
    vulnerabilityTypesTitle: 'Detected Vulnerability Types:',
    clickToLearnMore: 'Click on any vulnerability to learn more about it and how to protect against it',
    
    // Misc
    loading: 'Loading...',
    error: 'Error',
    success: 'Success',
    save: 'Save',
    delete: 'Delete',
    edit: 'Edit',
    close: 'Close',
    confirm: 'Confirm',
    domains: 'domains',
    scans: 'scans'
  },
  
  ar: {
    // Header
    appName: 'ماسح الثغرات',
    appSubtitle: 'Vulnerability Scanner Pro',
    scanner: 'الماسح',
    schedules: 'الجدولة',
    enterprise: 'المؤسسات',
    bugBounty: 'Bug Bounty',
    connected: 'متصل',
    disconnected: 'غير متصل',
    
    // ScanForm
    heroTitle: 'اكتشف الثغرات الأمنية',
    heroDescription: 'أداة فحص الثغرات الآلية الأقوى - تفحص المواقع وتكتشف جميع الثغرات الأمنية مع شرح تفصيلي لكيفية اكتشافها وطريقة إصلاحها',
    urlPlaceholder: 'أدخل رابط الموقع للفحص... (مثال: example.com)',
    selectScanType: 'اختر نوع الفحص:',
    startScan: 'ابدأ الفحص الآن',
    ethicalWarning: '⚠️ للاستخدام الأخلاقي فقط - تأكد من الحصول على إذن قبل فحص أي موقع',
    
    // Scan Templates
    quickScan: 'فحص سريع',
    quickScanDesc: 'فحص أساسي للثغرات الشائعة - 5 دقائق',
    standardScan: 'فحص قياسي',
    standardScanDesc: 'فحص متوازن للثغرات - 15 دقيقة',
    deepScan: 'فحص عميق',
    deepScanDesc: 'فحص شامل ومكثف - 30+ دقيقة',
    owaspScan: 'OWASP Top 10',
    owaspScanDesc: 'فحص أهم 10 ثغرات حسب OWASP',
    apiScan: 'فحص API',
    apiScanDesc: 'فحص مخصص لـ REST APIs',
    
    // Features
    features: 'المميزات',
    comprehensiveScan: 'فحص شامل',
    comprehensiveScanDesc: 'أكثر من 20 نوع من الثغرات',
    fastEfficient: 'سريع وفعال',
    fastEfficientDesc: 'فحص متوازي لأداء أفضل',
    detailedReports: 'تقارير مفصلة',
    detailedReportsDesc: 'شرح كيفية اكتشاف كل ثغرة',
    highAccuracy: 'دقة عالية',
    highAccuracyDesc: 'payloads متقدمة من PortSwigger',
    
    // Advanced Options
    advancedOptions: 'إعدادات متقدمة',
    crawlingSettings: 'إعدادات الزحف',
    scanDepth: 'عمق الفحص',
    maxUrls: 'أقصى عدد روابط',
    timeout: 'المهلة (ثانية)',
    rateControl: 'التحكم في السرعة (Rate Limiting)',
    requestsPerSecond: 'الطلبات/ثانية',
    delayMs: 'التأخير (مللي ثانية)',
    parallelThreads: 'الخيوط المتوازية',
    lowerIsSafer: 'أقل = أكثر أماناً للموقع',
    delayBetweenRequests: 'تأخير بين الطلبات',
    moreIsFasterButHeavier: 'أكثر = أسرع لكن أثقل',
    
    // Safety Settings
    safetySettings: 'إعدادات الأمان',
    respectRobots: '🤖 احترام robots.txt',
    followRedirects: '↪️ تتبع التحويلات',
    detectWAF: '🛡️ اكتشاف WAF/CDN',
    captureScreenshots: '📸 التقاط Screenshots',
    aggressiveMode: '⚔️ وضع عدواني ⚠️',
    ownershipVerification: '🔐 التحقق من الملكية',
    headlessCrawling: '🌐 زحف JavaScript (SPA)',
    
    // Vulnerability Types
    vulnTypesTitle: 'أنواع الثغرات المكتشفة:',
    vulnTypesHint: '💡 اضغط على أي ثغرة لتعرف المزيد عنها وكيفية الحماية منها',
    
    // Vulnerability Education
    whatIsThis: 'ما هي هذه الثغرة؟',
    vulnTypes: 'أنواع الثغرة',
    potentialImpact: 'التأثير المحتمل',
    example: 'مثال',
    howToProtect: 'كيفية الحماية',
    learningResources: 'مصادر للتعلم',
    quickTips: 'نصائح سريعة',
    tip1: 'تحقق دائماً من المدخلات (Input Validation)',
    tip2: 'استخدم مكتبات أمان موثوقة ومُحدّثة',
    tip3: 'طبق مبدأ أقل الصلاحيات (Least Privilege)',
    tip4: 'اختبر الكود بانتظام باستخدام أدوات الفحص',
    noVulnInfoAvailable: 'معلومات غير متوفرة لهذه الثغرة',
    
    // Scan Progress
    scanningTarget: 'جاري فحص',
    progress: 'التقدم',
    phase: 'المرحلة',
    stopScan: 'إيقاف الفحص',
    discoveredVulns: 'الثغرات المكتشفة',
    
    // Phases
    phaseReconnaissance: 'الاستطلاع',
    phaseCrawling: 'الزحف',
    phaseTechDetection: 'اكتشاف التقنيات',
    phaseVulnScanning: 'فحص الثغرات',
    phaseGeneratingSummary: 'إنشاء الملخص',
    phaseCapturingScreenshots: 'التقاط الصور',
    phaseCompleted: 'مكتمل',
    
    // Scan Summary
    scanComplete: 'اكتمل الفحص!',
    totalVulns: 'إجمالي الثغرات',
    critical: 'حرجة',
    high: 'عالية',
    medium: 'متوسطة',
    low: 'منخفضة',
    info: 'معلوماتية',
    scanDuration: 'مدة الفحص',
    urlsScanned: 'الروابط المفحوصة',
    formsFound: 'النماذج المكتشفة',
    
    // Export
    exportReport: 'تصدير التقرير',
    walkthrough: 'Walkthrough',
    walkthroughTooltip: 'دليل استغلال مفصل - مثل PortSwigger',
    exportForCICD: 'تصدير لـ CI/CD',
    newScan: 'فحص جديد',
    scanResults: 'نتائج الفحص',
    forms: 'نماذج',
    detectedTechnologies: 'التقنيات المكتشفة:',
    
    // Toast Messages
    scanCompleted: '✅ اكتمل الفحص بنجاح!',
    criticalVuln: '🔴 ثغرة حرجة:',
    highVuln: '🟠 ثغرة عالية:',
    pleaseEnterUrl: 'الرجاء إدخال رابط الموقع',
    scanStarting: '🔍 بدأ الفحص...',
    scanStopped: '⏹️ تم إيقاف الفحص',
    failedStopScan: 'فشل في إيقاف الفحص',
    sarifExportSuccess: '📄 تم تصدير SARIF بنجاح',
    sarifExportFailed: 'فشل في تصدير SARIF',
    walkthroughSuccess: '📖 تم إنشاء دليل الاستغلال بنجاح!',
    walkthroughFailed: 'فشل في إنشاء دليل الاستغلال',
    reportFailed: 'فشل في إنشاء التقرير',
    
    // Vulnerability List
    vulnerabilities: 'الثغرات',
    severity: 'الخطورة',
    confidence: 'الثقة',
    evidence: 'الدليل',
    payload: 'الحمولة',
    recommendation: 'التوصية',
    copyCurl: 'نسخ cURL',
    copyDetails: 'نسخ التفاصيل',
    vulnType: 'نوع الثغرة',
    url: 'الرابط',
    description: 'الوصف',
    fixMethod: 'طريقة الإصلاح',
    curlCopied: 'تم نسخ أمر cURL!',
    noVulnsFound: 'لم يتم العثور على ثغرات!',
    siteAppearsSecure: 'الموقع يبدو آمناً بناءً على الفحص الحالي',
    searchVulnerabilities: 'ابحث في الثغرات...',
    all: 'الكل',
    type: 'النوع',
    allTypes: 'جميع الأنواع',
    
    // Bug Bounty Settings
    bugBountySettings: 'إعدادات Bug Bounty',
    systemStatus: 'حالة النظام',
    enabled: 'مفعل',
    disabled: 'معطل',
    emergencyStop: 'إيقاف طوارئ',
    resume: 'استئناف',
    killSwitchActive: 'Kill Switch مفعل - كل عمليات الفحص متوقفة',
    
    // Tabs
    overview: 'نظرة عامة',
    scope: 'النطاقات',
    safety: 'السلامة',
    profiles: 'الملفات',
    preflight: 'ما قبل الفحص',
    
    // Scope
    inScope: 'In-Scope (مسموح)',
    outOfScope: 'Out-of-Scope (ممنوع)',
    saveScope: 'حفظ الـ Scope',
    importFromText: 'استيراد من نص (Bugcrowd/HackerOne format)',
    import: 'استيراد',
    
    // Safety
    safeMode: 'Safe Mode',
    safeModeDesc: 'يقيد الطلبات إلى GET/HEAD فقط ويمنع الإجراءات المدمرة',
    rateLimiting: 'Rate Limiting',
    globalRPS: 'Global RPS',
    perHostRPS: 'Per-Host RPS',
    maxConcurrency: 'Max Concurrency',
    crawlingLimits: 'حدود الزحف',
    maxDepth: 'Max Depth',
    saveSafetySettings: 'حفظ إعدادات السلامة',
    
    // Profiles
    readyTemplates: 'القوالب الجاهزة',
    savedProfiles: 'الملفات المحفوظة',
    noSavedProfiles: 'لا توجد ملفات محفوظة',
    load: 'تحميل',
    
    // Preflight
    preflightCheck: 'فحص ما قبل البدء',
    preflightDesc: 'تحقق من أن الـ URL داخل النطاق المسموح وأن كل الإعدادات صحيحة قبل بدء الفحص',
    target: 'الهدف',
    check: 'فحص',
    checkResults: 'نتائج الفحص:',
    readyToScan: '✓ جاهز للفحص',
    hasIssues: '✗ يوجد مشاكل',
    warnings: 'تحذيرات:',
    requiredConfirmations: 'تأكيدات مطلوبة:',
    
    // Quick Setup
    quickSetup: 'إعداد سريع',
    enterAllowedDomains: 'أدخل الـ Domains المسموحة (واحد في كل سطر)',
    applySafeSettings: 'تطبيق الإعدادات الآمنة',
    currentSettings: 'الإعدادات الحالية',
    rateLimit: 'Rate Limit',
    methods: 'Methods',
    profile: 'Profile',
    none: 'لا يوجد',
    
    // Confirmations
    havePermission: 'لدي إذن',
    havePermissionDesc: 'أؤكد أن لدي إذن كتابي من مالك الموقع أو أنه ضمن برنامج Bug Bounty مفعل',
    withinScope: 'ضمن النطاق',
    withinScopeDesc: 'أؤكد أن الهدف ضمن النطاق المسموح (In-Scope) حسب قواعد البرنامج',
    takeResponsibility: 'تحمل المسؤولية',
    takeResponsibilityDesc: 'أفهم أنني مسؤول عن أي ضرر قد يحدث وأتعهد بالفحص الأخلاقي فقط',
    cancel: 'إلغاء',
    completeConfirmations: 'أكمل التأكيدات',
    cannotStart: '⚠️ لا يمكن البدء - تحقق من الإعدادات أولاً',
    
    // Scheduled Scans
    scheduledScans: 'الفحوصات المجدولة',
    scheduleNewScan: 'جدولة فحص جديد',
    noScheduledScans: 'لا توجد فحوصات مجدولة',
    back: 'رجوع',
    everyHour: 'كل ساعة',
    every6Hours: 'كل 6 ساعات',
    dailyMidnight: 'يومياً منتصف الليل',
    daily8AM: 'يومياً 8 صباحاً',
    weeklySunday: 'أسبوعياً (الأحد)',
    monthly: 'شهرياً',
    confirmDeleteSchedule: 'هل أنت متأكد من حذف هذه الجدولة؟',
    scanStarted: 'تم بدء الفحص',
    
    // Enterprise
    enterpriseDashboard: 'لوحة تحكم المؤسسات',
    manageWorkersIntegrations: 'إدارة العمال والتكاملات والإعدادات',
    refresh: 'تحديث',
    workers: 'العمال',
    integrations: 'التكاملات',
    auditLog: 'سجل التدقيق',
    credentialVault: 'خزنة الاعتمادات',
    plugins: 'الإضافات',
    
    // Status
    available: 'متاح',
    busy: 'مشغول',
    offline: 'غير متصل',
    installed: 'مثبت',
    active: 'نشط',
    pending: 'في الانتظار',
    total: 'الإجمالي',
    queue: 'قائمة الانتظار',
    
    // Workers
    distributedWorkers: 'عمال الفحص الموزع',
    addWorker: 'إضافة عامل',
    noWorkersRegistered: 'لا يوجد عمال مسجلين',
    workerStatus: 'حالة العامل',
    lastSeen: 'آخر اتصال',
    capabilities: 'القدرات',
    registerNew: 'تسجيل جديد',
    removeWorker: 'إزالة عامل',
    
    // Integrations
    externalIntegrations: 'التكاملات الخارجية',
    configure: 'تكوين',
    slackIntegration: 'Slack Integration',
    jiraIntegration: 'Jira Integration',
    githubIntegration: 'GitHub Integration',
    notConnected: 'غير متصل',
    connect: 'ربط',
    disconnect: 'فصل',
    
    // Audit Log
    auditLogTitle: 'سجل التدقيق والأحداث',
    loadMoreLogs: 'تحميل المزيد',
    noAuditLogs: 'لا توجد سجلات',
    action: 'الإجراء',
    user: 'المستخدم',
    timestamp: 'الوقت',
    details: 'التفاصيل',
    
    // Credential Vault
    credentialVaultTitle: 'خزنة بيانات الاعتماد',
    addCredential: 'إضافة اعتماد',
    noCredentials: 'لا توجد اعتمادات محفوظة',
    credentialName: 'اسم الاعتماد',
    credentialType: 'النوع',
    createdAt: 'تاريخ الإنشاء',
    lastUsed: 'آخر استخدام',
    deleteCredential: 'حذف',
    
    // Plugins
    pluginsTitle: 'نظام الإضافات',
    installPlugin: 'تثبيت إضافة',
    noPlugins: 'لا توجد إضافات',
    pluginName: 'اسم الإضافة',
    pluginVersion: 'الإصدار',
    pluginAuthor: 'المؤلف',
    enablePlugin: 'تفعيل',
    disablePlugin: 'تعطيل',
    uninstallPlugin: 'إلغاء التثبيت',
    
    // Scheduled Scans - Additional
    addNewSchedule: 'إضافة جدولة جديدة',
    scheduleName: 'اسم الجدولة',
    targetUrl: 'رابط الموقع',
    runTiming: 'توقيت التشغيل',
    customCron: 'Custom (تعبير CRON)',
    cronExpression: 'تعبير CRON',
    enableSchedule: 'تفعيل الجدولة',
    createSchedule: 'إنشاء الجدولة',
    editSchedule: 'تعديل الجدولة',
    saveChanges: 'حفظ التغييرات',
    runNow: 'تشغيل الآن',
    enable: 'تفعيل',
    nextRun: 'التشغيل القادم',
    lastRun: 'آخر تشغيل',
    never: 'أبداً',
    
    // Bug Bounty - Additional
    systemDisabled: 'تم تعطيل النظام',
    systemEnabled: 'تم تفعيل النظام',
    failedChangeStatus: 'فشل في تغيير حالة النظام',
    killSwitchActiveMessage: 'Kill Switch مفعل - كل العمليات متوقفة',
    settingsLoadFailed: 'فشل في تحميل الإعدادات',
    settingsSaved: 'تم حفظ الإعدادات',
    settingsSaveFailed: 'فشل في حفظ الإعدادات',
    scopeSaved: 'تم حفظ النطاق',
    scopeSaveFailed: 'فشل في حفظ النطاق',
    profileLoaded: 'تم تحميل الملف الشخصي',
    profileLoadFailed: 'فشل في تحميل الملف الشخصي',
    
    // Ownership Verification
    ownershipVerificationTitle: 'التحقق من ملكية الموقع',
    ownershipVerificationDesc: 'للفحص الآمن والأخلاقي، يرجى التحقق من ملكيتك للموقع',
    generateTokenInfo: 'سنقوم بإنشاء رمز تحقق فريد يمكنك استخدامه لإثبات ملكيتك للموقع',
    generateTokenButton: 'إنشاء رمز التحقق',
    verifyOwnership: 'التحقق من الملكية',
    verifyingOwnership: 'جاري التحقق...',
    verificationMethod: 'طريقة التحقق',
    httpFileMethod: 'ملف HTTP',
    dnsRecordMethod: 'سجل DNS',
    uploadFileInfo: 'ارفع ملفاً يحتوي على المحتوى التالي إلى موقعك',
    addDnsRecordInfo: 'أضف سجل TXT التالي إلى DNS الخاص بك',
    skipVerification: 'تخطي التحقق',
    verificationSuccess: 'تم التحقق بنجاح!',
    verificationFailed: 'فشل التحقق',
    failedToGenerateToken: 'فشل في إنشاء رمز التحقق',
    failedToVerifyOwnership: 'فشل في التحقق من الملكية',
    copyToClipboard: 'نسخ إلى الحافظة',
    copied: 'تم النسخ!',
    
    // Preflight Confirmation
    checkingSettings: 'جاري التحقق من الإعدادات...',
    preflightSuccess: 'نجح الفحص التمهيدي',
    preflightFailed: 'فشل الفحص التمهيدي',
    connectionFailed: 'فشل الاتصال',
    couldNotVerifyBountySettings: 'لم نتمكن من التحقق من إعدادات Bug Bounty',
    proceedWithScan: 'متابعة الفحص',
    currentScans: 'الفحوصات الحالية',
    completed: 'مكتمل',
    
    // Errors
    failedLoadData: 'فشل في تحميل البيانات',
    failedLoadSchedules: 'فشل في تحميل الجدولات',
    failedCreateSchedule: 'فشل في إنشاء الجدولة',
    failedUpdateSchedule: 'فشل في تحديث الجدولة',
    failedDeleteSchedule: 'فشل في حذف الجدولة',
    failedStartScan: 'فشل في بدء الفحص',
    
    // Footer
    footerText: 'مصمم لصائدي الجوائز',
    madeWith: 'صنع بـ',
    forCommunity: 'للمجتمع',
    allRightsReserved: 'جميع الحقوق محفوظة',
    
    // Scan Progress
    scanningInProgress: 'جاري الفحص...',
    stop: 'إيقاف',
    currentPhase: 'المرحلة الحالية',
    vulnerabilitiesFound: 'الثغرات المكتشفة',
    recentVulnerabilities: 'الثغرات المكتشفة حديثاً',
    searchingForVulns: 'جاري البحث عن ثغرات...',
    
    // ScanForm additions
    discoverVulnerabilities: 'اكتشف الثغرات الأمنية',
    scanFormDescription: 'أداة فحص الثغرات الآلية الأقوى - تفحص المواقع وتكتشف جميع الثغرات الأمنية مع شرح تفصيلي لكيفية اكتشافها وطريقة إصلاحها',
    enterUrlPlaceholder: 'أدخل رابط الموقع للفحص... (مثال: example.com)',
    chooseScanType: 'اختر نوع الفحص:',
    advancedSettings: 'إعدادات متقدمة',
    delay: 'التأخير (مللي ثانية)',
    jsCrawling: 'زحف JavaScript (SPA)',
    resultQuality: 'جودة النتائج',
    verificationMode: 'وضع التحقق (تقليل النتائج الخاطئة)',
    includePotentialFindings: 'تضمين النتائج المحتملة',
    enableDomXssHeadless: 'تفعيل تحقق DOM XSS عبر المتصفح الخفي',
    minimumConfidenceScore: 'أدنى درجة ثقة',
    verificationQuality: 'جودة التحقق',
    confirmedFindings: 'مؤكدة',
    probableFindings: 'مرجحة',
    potentialFindings: 'محتملة',
    filteredOutFindings: 'تمت تصفيتها',
    verificationEnabledText: 'التحقق',
    minimumConfidenceText: 'أدنى ثقة',
    enabledText: 'مفعل',
    disabledText: 'معطل',
    startScanNow: 'ابدأ الفحص الآن',
    ethicalUseWarning: 'للاستخدام الأخلاقي فقط - تأكد من الحصول على إذن قبل فحص أي موقع',
    vulnerabilityTypesTitle: 'أنواع الثغرات المكتشفة:',
    clickToLearnMore: 'اضغط على أي ثغرة لتعرف المزيد عنها وكيفية الحماية منها',
    
    // Misc
    loading: 'جاري التحميل...',
    error: 'خطأ',
    success: 'تم بنجاح',
    save: 'حفظ',
    delete: 'حذف',
    edit: 'تعديل',
    close: 'إغلاق',
    confirm: 'تأكيد',
    domains: 'domains',
    scans: 'فحوصات'
  }
};

const LanguageContext = createContext();

export function LanguageProvider({ children }) {
  const [language, setLanguage] = useState(() => {
    // جلب اللغة المحفوظة أو استخدام الإنجليزية كافتراضي
    const saved = localStorage.getItem('language');
    return saved || 'en';
  });

  useEffect(() => {
    // حفظ اللغة في localStorage
    localStorage.setItem('language', language);
    
    // تغيير اتجاه الصفحة
    document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
    document.documentElement.lang = language;
  }, [language]);

  const t = (key) => {
    return translations[language][key] || translations['en'][key] || key;
  };

  const toggleLanguage = () => {
    setLanguage(prev => prev === 'en' ? 'ar' : 'en');
  };

  const isRTL = language === 'ar';

  return (
    <LanguageContext.Provider value={{ language, setLanguage, toggleLanguage, t, isRTL }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}

export default LanguageContext;
