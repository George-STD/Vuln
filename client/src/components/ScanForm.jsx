import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FaSearch, FaCog, FaRocket, FaBug, FaSpider, FaBolt, FaPause, FaPlay, FaSyncAlt, FaGraduationCap } from 'react-icons/fa'
import VulnerabilityEducation from './VulnerabilityEducation'
import { useLanguage } from '../contexts/LanguageContext'

const resultQualityDefaults = {
  verifyFindings: true,
  includePotential: false,
  minConfidenceScore: 55,
  scanDurationMinutes: 0,
  learningRuleUsagePercent: 100,
  enableDomXss: false,
  enableHumanLikeInteraction: false,
  writeupLinksText: '',
  interactionPathsText: ''
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
      enableDomXss: true,
      enableHumanLikeInteraction: true
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
  const [autoLearnerStatus, setAutoLearnerStatus] = useState(null)
  const [autoLearnerBusy, setAutoLearnerBusy] = useState(false)
  const [autoLearnerError, setAutoLearnerError] = useState('')
  const [cleanupMessage, setCleanupMessage] = useState('')

  const parseMultiLineInput = (input) => {
    return String(input || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
  }

  const fetchAutoLearnerStatus = async () => {
    setAutoLearnerBusy(true)
    try {
      const response = await fetch('/api/learning/auto/status')
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || t('failedLoadData'))
      }
      setAutoLearnerStatus(data.autoLearner || null)
      setAutoLearnerError('')
    } catch (error) {
      setAutoLearnerError(error.message)
    } finally {
      setAutoLearnerBusy(false)
    }
  }

  const controlAutoLearner = async (action) => {
    const endpoint = action === 'resume'
      ? '/api/learning/auto/start'
      : action === 'pause'
        ? '/api/learning/auto/stop'
        : '/api/learning/auto/tick'

    setAutoLearnerBusy(true)
    try {
      const response = await fetch(endpoint, { method: 'POST' })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || t('error'))
      }
      setAutoLearnerStatus(data.status || autoLearnerStatus)
      setAutoLearnerError('')
      setCleanupMessage('')
    } catch (error) {
      setAutoLearnerError(error.message)
    } finally {
      setAutoLearnerBusy(false)
    }
  }

  const cleanupLearnedWriteups = async () => {
    setAutoLearnerBusy(true)
    try {
      const response = await fetch('/api/learning/cleanup', { method: 'POST' })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || t('error'))
      }

      const cleaned = data.cleanup || {}
      setCleanupMessage(
        `${t('learningCleanupDone')}: ${cleaned.beforeRules ?? 0} → ${cleaned.afterRules ?? 0}`
      )
      setAutoLearnerError('')
      await fetchAutoLearnerStatus()
    } catch (error) {
      setAutoLearnerError(error.message)
      setCleanupMessage('')
    } finally {
      setAutoLearnerBusy(false)
    }
  }

  useEffect(() => {
    if (showAdvanced && !autoLearnerStatus && !autoLearnerBusy) {
      fetchAutoLearnerStatus()
    }
  }, [showAdvanced, autoLearnerStatus, autoLearnerBusy])

  const handleSubmit = (e) => {
    e.preventDefault()
    
    // Validate URL
    let finalUrl = url.trim()
    if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
      finalUrl = 'https://' + finalUrl
    }

    const writeupLinks = parseMultiLineInput(options.writeupLinksText)
    const interactionPaths = parseMultiLineInput(options.interactionPathsText)
    const finalOptions = {
      ...options,
      template: selectedTemplate,
      writeupLinks,
      interactionPaths,
      scanDurationMinutes: Math.max(0, Number(options.scanDurationMinutes || 0)),
      learningRuleUsagePercent: Math.max(1, Math.min(100, Number(options.learningRuleUsagePercent || 100)))
    }

    delete finalOptions.writeupLinksText
    delete finalOptions.interactionPathsText

    onSubmit(finalUrl, finalOptions)
  }

  const handleTemplateChange = (templateKey) => {
    setSelectedTemplate(templateKey)
    setOptions((prev) => ({
      ...scanTemplates[templateKey].options,
      writeupLinksText: prev.writeupLinksText || '',
      interactionPathsText: prev.interactionPathsText || '',
      scanDurationMinutes: prev.scanDurationMinutes ?? 0,
      learningRuleUsagePercent: prev.learningRuleUsagePercent ?? 100
    }))
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
              <h5 className="text-sm font-bold text-cyber-blue mb-3">🎯 {t('resultQuality')}</h5>
              <div className="grid md:grid-cols-2 gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.verifyFindings !== false}
                    onChange={(e) => setOptions({ ...options, verifyFindings: e.target.checked })}
                    className="w-4 h-4 accent-cyber-blue"
                  />
                  <span className="text-sm text-gray-300">{t('verificationMode')}</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includePotential || false}
                    onChange={(e) => setOptions({ ...options, includePotential: e.target.checked })}
                    className="w-4 h-4 accent-cyber-yellow"
                    disabled={options.verifyFindings === false}
                  />
                  <span className="text-sm text-gray-300">{t('includePotentialFindings')}</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.enableDomXss || false}
                    onChange={(e) => setOptions({ ...options, enableDomXss: e.target.checked })}
                    className="w-4 h-4 accent-cyber-green"
                  />
                  <span className="text-sm text-gray-300">{t('enableDomXssHeadless')}</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.enableHumanLikeInteraction || false}
                    onChange={(e) => setOptions({ ...options, enableHumanLikeInteraction: e.target.checked })}
                    className="w-4 h-4 accent-cyber-purple"
                  />
                  <span className="text-sm text-gray-300">{t('enableHumanLikeInteraction')}</span>
                </label>

                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('minimumConfidenceScore')}</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={options.minConfidenceScore ?? 55}
                    onChange={(e) => setOptions({ ...options, minConfidenceScore: parseInt(e.target.value, 10) || 0 })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                </div>

                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('scanDurationMinutes')}</label>
                  <input
                    type="number"
                    min="0"
                    max="1440"
                    value={options.scanDurationMinutes ?? 0}
                    onChange={(e) => setOptions({ ...options, scanDurationMinutes: parseInt(e.target.value, 10) || 0 })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                  <span className="text-xs text-gray-500">{t('scanDurationHint')}</span>
                </div>

                <div>
                  <label className="text-sm text-gray-400 block mb-1">{t('learningRuleUsagePercent')}</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={options.learningRuleUsagePercent ?? 100}
                    onChange={(e) => setOptions({ ...options, learningRuleUsagePercent: parseInt(e.target.value, 10) || 100 })}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue"
                  />
                  <span className="text-xs text-gray-500">{t('learningRuleUsageHint')}</span>
                </div>
              </div>
            </div>

            <div>
              <h5 className="text-sm font-bold text-cyber-purple mb-3">🧠 {t('learningAndGuidance')}</h5>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-300 block mb-1">{t('writeupLinksInputLabel')}</label>
                  <textarea
                    value={options.writeupLinksText || ''}
                    onChange={(e) => setOptions({ ...options, writeupLinksText: e.target.value })}
                    placeholder={t('writeupLinksPlaceholder')}
                    rows={6}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue resize-y"
                  />
                  <span className="text-xs text-gray-500">{t('oneItemPerLineHint')}</span>
                </div>

                <div>
                  <label className="text-sm text-gray-300 block mb-1">{t('interactionPathsInputLabel')}</label>
                  <textarea
                    value={options.interactionPathsText || ''}
                    onChange={(e) => setOptions({ ...options, interactionPathsText: e.target.value })}
                    placeholder={t('interactionPathsPlaceholder')}
                    rows={6}
                    className="w-full bg-dark-700 border border-dark-600 rounded-lg py-2 px-3 outline-none focus:border-cyber-blue resize-y"
                  />
                  <span className="text-xs text-gray-500">{t('interactionPathsHint')}</span>
                </div>
              </div>

              <div className="mt-4 bg-dark-900/40 border border-dark-600 rounded-xl p-3 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-cyber-blue">{t('autoLearnerControlsTitle')}</span>
                  <button
                    type="button"
                    onClick={fetchAutoLearnerStatus}
                    disabled={autoLearnerBusy}
                    className="text-xs px-3 py-1.5 rounded-lg border border-dark-500 bg-dark-700 hover:border-cyber-blue/60 disabled:opacity-60 flex items-center gap-2"
                  >
                    <FaSyncAlt className={autoLearnerBusy ? 'animate-spin' : ''} />
                    {t('refresh')}
                  </button>
                </div>

                <div className="grid md:grid-cols-4 gap-2 text-xs text-gray-300">
                  <div>
                    <span className="text-gray-500">{t('autoLearnerStatusLabel')}: </span>
                    <span className={autoLearnerStatus?.running ? 'text-cyber-green' : 'text-gray-300'}>
                      {autoLearnerStatus
                        ? autoLearnerStatus.running
                          ? t('autoLearnerRunning')
                          : t('autoLearnerPaused')
                        : t('loading')}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500">{t('autoLearnerQueueLabel')}: </span>
                    <span>{autoLearnerStatus?.queueSize ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">{t('autoLearnerLearnedLabel')}: </span>
                    <span>{autoLearnerStatus?.learnedWriteups ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">{t('autoLearnerRulesLabel')}: </span>
                    <span>{autoLearnerStatus?.importedRules ?? 0}</span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => controlAutoLearner(autoLearnerStatus?.running ? 'pause' : 'resume')}
                    disabled={autoLearnerBusy}
                    className="text-sm px-3 py-2 rounded-lg border border-dark-500 bg-dark-700 hover:border-cyber-blue/60 disabled:opacity-60 flex items-center gap-2"
                  >
                    {autoLearnerStatus?.running ? <FaPause /> : <FaPlay />}
                    {autoLearnerStatus?.running ? t('pauseAutoLearner') : t('resumeAutoLearner')}
                  </button>

                  <button
                    type="button"
                    onClick={() => controlAutoLearner('tick')}
                    disabled={autoLearnerBusy}
                    className="text-sm px-3 py-2 rounded-lg border border-dark-500 bg-dark-700 hover:border-cyber-green/60 disabled:opacity-60 flex items-center gap-2"
                  >
                    <FaBolt />
                    {t('learnOneNow')}
                  </button>

                  <button
                    type="button"
                    onClick={cleanupLearnedWriteups}
                    disabled={autoLearnerBusy}
                    className="text-sm px-3 py-2 rounded-lg border border-dark-500 bg-dark-700 hover:border-cyber-yellow/60 disabled:opacity-60 flex items-center gap-2"
                  >
                    <FaCog />
                    {t('cleanupLearningData')}
                  </button>
                </div>

                {autoLearnerStatus?.lastLearnedUrl && (
                  <p className="text-xs text-gray-500 break-all">
                    {t('autoLearnerLastLearned')}: {autoLearnerStatus.lastLearnedUrl}
                  </p>
                )}

                {autoLearnerError && (
                  <p className="text-xs text-cyber-red">{autoLearnerError}</p>
                )}
                {cleanupMessage && (
                  <p className="text-xs text-cyber-green">{cleanupMessage}</p>
                )}
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
