import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FaSearch, FaCog, FaRocket, FaBug, FaSpider, FaBolt, FaShieldAlt, FaCode, FaServer, FaGraduationCap } from 'react-icons/fa'
import VulnerabilityEducation from './VulnerabilityEducation'
import { useLanguage } from '../contexts/LanguageContext'

const resultQualityDefaults = {
  verifyFindings: true,
  includePotential: false,
  minConfidenceScore: 55,
  enableDomXss: false
}

// Scan Templates
const scanTemplates = {
  quick: {
    nameKey: 'quickScan',
    descKey: 'quickScanDesc',
    icon: '⚡',
    color: 'from-green-500 to-emerald-600',
    options: {
      ...resultQualityDefaults,
      depth: 2,
      maxUrls: 30,
      timeout: 15000,
      threads: 3,
      requestsPerSecond: 10,
      delay: 100,
      minConfidenceScore: 65,
      scanModules: ['headers', 'cors', 'clickjacking', 'ssl', 'sensitiveData', 'directory']
    }
  },
  standard: {
    nameKey: 'standardScan',
    descKey: 'standardScanDesc',
    icon: '🔍',
    color: 'from-blue-500 to-cyan-600',
    options: {
      ...resultQualityDefaults,
      depth: 3,
      maxUrls: 100,
      timeout: 30000,
      threads: 5,
      requestsPerSecond: 5,
      delay: 200,
      scanModules: 'all'
    }
  },
  deep: {
    nameKey: 'deepScan',
    descKey: 'deepScanDesc',
    icon: '🔬',
    color: 'from-purple-500 to-pink-600',
    options: {
      ...resultQualityDefaults,
      depth: 5,
      maxUrls: 300,
      timeout: 60000,
      threads: 3,
      requestsPerSecond: 2,
      delay: 500,
      scanModules: 'all',
      aggressive: true,
      includePotential: true,
      minConfidenceScore: 45,
      enableDomXss: true
    }
  },
  owasp: {
    nameKey: 'owaspScan',
    descKey: 'owaspScanDesc',
    icon: '🛡️',
    color: 'from-orange-500 to-red-600',
    options: {
      ...resultQualityDefaults,
      depth: 3,
      maxUrls: 100,
      timeout: 30000,
      threads: 4,
      requestsPerSecond: 5,
      delay: 200,
      minConfidenceScore: 60,
      scanModules: ['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'rce', 'xxe', 'idor', 'authBypass', 'sensitiveData']
    }
  },
  api: {
    nameKey: 'apiScan',
    descKey: 'apiScanDesc',
    icon: '🔌',
    color: 'from-yellow-500 to-orange-600',
    options: {
      ...resultQualityDefaults,
      depth: 2,
      maxUrls: 50,
      timeout: 30000,
      threads: 5,
      requestsPerSecond: 5,
      delay: 200,
      minConfidenceScore: 60,
      scanModules: ['sqli', 'ssrf', 'idor', 'authBypass', 'headers', 'cors', 'sensitiveData']
    }
  }
}

function ScanForm({ onSubmit }) {
  const { t, isRTL } = useLanguage()
  const [url, setUrl] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState('standard')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [options, setOptions] = useState(scanTemplates.standard.options)
  const [selectedVuln, setSelectedVuln] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    
    // Validate URL
    let finalUrl = url.trim()
    if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
      finalUrl = 'https://' + finalUrl
    }
    
    onSubmit(finalUrl, { ...options, template: selectedTemplate })
  }

  const handleTemplateChange = (templateKey) => {
    setSelectedTemplate(templateKey)
    setOptions(scanTemplates[templateKey].options)
  }

  const features = [
    { icon: '🔍', titleKey: 'comprehensiveScan', descKey: 'comprehensiveScanDesc' },
    { icon: '⚡', titleKey: 'fastEfficient', descKey: 'fastEfficientDesc' },
    { icon: '📊', titleKey: 'detailedReports', descKey: 'detailedReportsDesc' },
    { icon: '🎯', titleKey: 'highAccuracy', descKey: 'highAccuracyDesc' }
  ]

  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <motion.div 
        className="text-center space-y-4"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex justify-center items-center gap-4 mb-4">
          <FaBug className="text-5xl text-cyber-red animate-bounce" />
          <FaSpider className="text-5xl text-cyber-blue animate-float" />
        </div>
        <h2 className="text-4xl font-bold gradient-text">
          {t('discoverVulnerabilities')}
        </h2>
        <p className="text-gray-400 max-w-2xl mx-auto text-lg">
          {t('scanFormDescription')}
        </p>
      </motion.div>

      {/* Features */}
      <motion.div 
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        {features.map((feature, i) => (
          <motion.div
            key={i}
            className="bg-dark-700/50 rounded-xl p-4 text-center card-hover border border-dark-600"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * i }}
          >
            <span className="text-3xl">{feature.icon}</span>
            <h3 className="font-bold mt-2 text-cyber-blue">{t(feature.titleKey)}</h3>
            <p className="text-xs text-gray-500 mt-1">{t(feature.descKey)}</p>
          </motion.div>
        ))}
      </motion.div>

      {/* Scan Form */}
      <motion.form 
        onSubmit={handleSubmit}
        className="bg-dark-700/50 rounded-2xl p-6 border border-dark-600 space-y-4"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.3 }}
      >
        <div className="relative">
          <FaSearch className={`absolute ${isRTL ? 'right-4' : 'left-4'} top-1/2 -translate-y-1/2 text-cyber-blue text-xl`} />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={t('enterUrlPlaceholder')}
            className={`w-full bg-dark-800 border-2 border-dark-600 focus:border-cyber-blue rounded-xl py-4 ${isRTL ? 'pr-12 pl-4' : 'pl-12 pr-4'} text-lg outline-none transition-all placeholder-gray-500`}
            dir="ltr"
          />
        </div>

        {/* Scan Templates */}
        <div className="space-y-3">
          <h4 className="text-sm font-bold text-gray-400">{t('chooseScanType')}</h4>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {Object.entries(scanTemplates).map(([key, template]) => (
              <motion.button
                key={key}
                type="button"
                onClick={() => handleTemplateChange(key)}
                className={`p-3 rounded-xl border-2 transition-all text-center ${
                  selectedTemplate === key
                    ? `border-cyber-blue bg-gradient-to-br ${template.color} text-white`
                    : 'border-dark-600 bg-dark-800 hover:border-cyber-blue/50'
                }`}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <span className="text-2xl block mb-1">{template.icon}</span>
                <span className="text-sm font-bold block">{t(template.nameKey)}</span>
              </motion.button>
            ))}
          </div>
          <p className="text-xs text-gray-500 text-center">
            {t(scanTemplates[selectedTemplate].descKey)}
          </p>
        </div>

        {/* Advanced Options Toggle */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 text-gray-400 hover:text-cyber-blue transition-colors"
        >
          <FaCog className={`transition-transform ${showAdvanced ? 'rotate-90' : ''}`} />
          <span>{t('advancedSettings')}</span>
        </button>

        {/* Advanced Options */}
        {showAdvanced && (
          <motion.div 
            className="space-y-4 bg-dark-800/50 rounded-xl p-4"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
          >
            {/* Crawling Settings */}
            <div>
              <h5 className="text-sm font-bold text-cyber-blue mb-3">⚙️ {t('crawlingSettings')}</h5>
              <div className="grid md:grid-cols-3 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('scanDepth')}</label>
                  <input
                    type="number"
                    min="1"
                    max="10"
                    value={options.depth}
                    onChange={(e) => setOptions({ ...options, depth: parseInt(e.target.value) })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('maxUrls')}</label>
                  <input
                    type="number"
                    min="10"
                    max="1000"
                    value={options.maxUrls}
                    onChange={(e) => setOptions({ ...options, maxUrls: parseInt(e.target.value) })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('timeout')}</label>
                  <input
                    type="number"
                    min="5"
                    max="120"
                    value={options.timeout / 1000}
                    onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) * 1000 })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                </div>
              </div>
            </div>

            {/* Rate Limiting Settings */}
            <div>
              <h5 className="text-sm font-bold text-cyber-green mb-3">🚦 {t('rateLimiting')}</h5>
              <div className="grid md:grid-cols-3 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('requestsPerSecond')}</label>
                  <input
                    type="number"
                    min="1"
                    max="50"
                    value={options.requestsPerSecond || 5}
                    onChange={(e) => setOptions({ ...options, requestsPerSecond: parseInt(e.target.value) })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                  <span className="text-xs text-gray-500">{t('lowerIsSafer')}</span>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('delay')}</label>
                  <input
                    type="number"
                    min="0"
                    max="5000"
                    step="100"
                    value={options.delay || 200}
                    onChange={(e) => setOptions({ ...options, delay: parseInt(e.target.value) })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                  <span className="text-xs text-gray-500">{t('delayBetweenRequests')}</span>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('parallelThreads')}</label>
                  <input
                    type="number"
                    min="1"
                    max="20"
                    value={options.threads || 5}
                    onChange={(e) => setOptions({ ...options, threads: parseInt(e.target.value) })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                  <span className="text-xs text-gray-500">{t('moreIsFasterButHeavier')}</span>
                </div>
              </div>
            </div>

            {/* Safety Settings */}
            <div>
              <h5 className="text-sm font-bold text-cyber-blue mb-3">🎯 Result Quality</h5>
              <div className="grid md:grid-cols-2 gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.verifyFindings !== false}
                    onChange={(e) => setOptions({ ...options, verifyFindings: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">Verification Mode (reduce false positives)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includePotential || false}
                    onChange={(e) => setOptions({ ...options, includePotential: e.target.checked })}
                    className="w-4 h-4 accent-cyber-yellow"
                    disabled={options.verifyFindings === false}
                  />
                  <span className="text-sm text-gray-300">Include potential findings</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.enableDomXss || false}
                    onChange={(e) => setOptions({ ...options, enableDomXss: e.target.checked })}
                    className="w-4 h-4 accent-cyber-green"
                  />
                  <span className="text-sm text-gray-300">Enable DOM XSS headless verification</span>
                </label>

                <div>
                  <label className="text-sm text-gray-400 block mb-1">Minimum Confidence Score</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={options.minConfidenceScore ?? 55}
                    onChange={(e) => setOptions({ ...options, minConfidenceScore: parseInt(e.target.value, 10) || 0 })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                </div>
              </div>
            </div>

            {/* Safety Settings */}
            <div>
              <h5 className="text-sm font-bold text-cyber-yellow mb-3">⚠️ {t('safetySettings')}</h5>
              <div className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.respectRobotsTxt !== false}
                    onChange={(e) => setOptions({ ...options, respectRobotsTxt: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">🤖 {t('respectRobots')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.followRedirects !== false}
                    onChange={(e) => setOptions({ ...options, followRedirects: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">↪️ {t('followRedirects')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.detectWAF !== false}
                    onChange={(e) => setOptions({ ...options, detectWAF: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">🛡️ {t('detectWAF')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.captureScreenshots || false}
                    onChange={(e) => setOptions({ ...options, captureScreenshots: e.target.checked })}
                    className="w-4 h-4 accent-cyber-green"
                  />
                  <span className="text-sm text-gray-300">📸 {t('captureScreenshots')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.aggressive || false}
                    onChange={(e) => setOptions({ ...options, aggressive: e.target.checked })}
                    className="w-4 h-4 accent-cyber-red"
                  />
                  <span className="text-sm text-cyber-red">⚔️ {t('aggressiveMode')} ⚠️</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.requireVerification || false}
                    onChange={(e) => setOptions({ ...options, requireVerification: e.target.checked })}
                    className="w-4 h-4 accent-cyber-yellow"
                  />
                  <span className="text-sm text-amber-400">🔐 {t('ownershipVerification')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.useHeadlessCrawler || false}
                    onChange={(e) => setOptions({ ...options, useHeadlessCrawler: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">🌐 {t('jsCrawling')}</span>
                </label>
              </div>
            </div>
          </motion.div>
        )}

        {/* Submit Button */}
        <motion.button
          type="submit"
          className="w-full bg-gradient-to-r from-cyber-blue to-cyber-green text-dark-900 font-bold py-4 rounded-xl text-lg flex items-center justify-center gap-3 hover:opacity-90 transition-opacity"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <FaRocket className="text-xl" />
          <span>{t('startScanNow')}</span>
        </motion.button>

        <p className="text-center text-xs text-gray-500">
          ⚠️ {t('ethicalUseWarning')}
        </p>
      </motion.form>

      {/* Vulnerability Types */}
      <motion.div 
        className="bg-dark-700/30 rounded-xl p-6 border border-dark-600"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
      >
        <h3 className="text-lg font-bold mb-2 text-cyber-blue flex items-center gap-2">
          <FaGraduationCap />
          {t('vulnerabilityTypesTitle')}
        </h3>
        <p className="text-sm text-gray-500 mb-4">
          💡 {t('clickToLearnMore')}
        </p>
        <div className="flex flex-wrap gap-2">
          {[
            'XSS', 'SQL Injection', 'CSRF', 'SSRF', 'LFI', 'RCE', 'XXE', 'IDOR',
            'Open Redirect', 'CORS', 'Clickjacking', 'Security Headers', 
            'SSL/TLS', 'Sensitive Data', 'Authentication Bypass', 'Directory Traversal'
          ].map((type, i) => (
            <motion.button 
              key={i}
              onClick={() => setSelectedVuln(type)}
              className="bg-dark-600 px-3 py-1.5 rounded-full text-sm text-gray-300 hover:bg-gradient-to-r hover:from-cyber-blue hover:to-cyber-green hover:text-dark-900 transition-all cursor-pointer border border-transparent hover:border-cyber-blue/50"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              {type}
            </motion.button>
          ))}
        </div>
      </motion.div>

      {/* Vulnerability Education Modal */}
      <AnimatePresence>
        {selectedVuln && (
          <VulnerabilityEducation
            vulnType={selectedVuln}
            onClose={() => setSelectedVuln(null)}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

export default ScanForm
