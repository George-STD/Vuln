import { motion } from 'framer-motion'
import { FaStop, FaSpinner, FaExclamationTriangle, FaCheckCircle } from 'react-icons/fa'
import { useLanguage } from '../contexts/LanguageContext'

function ScanProgress({ progress, phase, targetUrl, vulnerabilities, onStop }) {
  const { t, language } = useLanguage()
  
  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length
  }

  const phaseLabels = {
    en: {
      'reconnaissance': 'Reconnaissance',
      'crawling': 'Crawling',
      'tech_detection': 'Tech Detection',
      'vulnerability_scanning': 'Vulnerability Scanning',
      'generating_summary': 'Generating Summary'
    },
    ar: {
      'reconnaissance': 'الاستطلاع',
      'crawling': 'الزحف',
      'tech_detection': 'اكتشاف التقنيات',
      'vulnerability_scanning': 'فحص الثغرات',
      'generating_summary': 'إنشاء الملخص'
    }
  }

  const severityLabels = [
    { key: 'critical', labelKey: 'critical', color: 'bg-cyber-red' },
    { key: 'high', labelKey: 'high', color: 'bg-cyber-orange' },
    { key: 'medium', labelKey: 'medium', color: 'bg-cyber-yellow' },
    { key: 'low', labelKey: 'low', color: 'bg-cyber-blue' },
    { key: 'info', labelKey: 'info', color: 'bg-gray-500' }
  ]

  const recentVulns = vulnerabilities.slice(-5).reverse()

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div 
        className="bg-dark-700/50 rounded-2xl p-6 border border-dark-600"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <FaSpinner className="text-3xl text-cyber-blue animate-spin" />
            <div>
              <h2 className="text-xl font-bold text-cyber-blue">{t('scanningInProgress')}</h2>
              <p className="text-gray-400 text-sm" dir="ltr">{targetUrl}</p>
            </div>
          </div>
          <motion.button
            onClick={onStop}
            className="bg-cyber-red/20 text-cyber-red px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-cyber-red/30 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaStop />
            <span>{t('stop')}</span>
          </motion.button>
        </div>

        {/* Progress Bar */}
        <div className="relative h-4 bg-dark-800 rounded-full overflow-hidden">
          <motion.div 
            className="h-full progress-shine rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5 }}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xs font-bold text-white drop-shadow-lg">
              {progress.toFixed(0)}%
            </span>
          </div>
        </div>

        {/* Phase */}
        <div className="mt-4 flex items-center justify-between text-sm">
          <span className="text-gray-400">
            {t('currentPhase')}: <span className="text-cyber-green">{phaseLabels[language]?.[phase] || phase}</span>
          </span>
          <span className="text-gray-500">
            {t('vulnerabilitiesFound')}: <span className="text-cyber-blue font-bold">{vulnerabilities.length}</span>
          </span>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-5 gap-3">
        {severityLabels.map((item) => (
          <motion.div
            key={item.key}
            className="bg-dark-700/50 rounded-xl p-4 text-center border border-dark-600"
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
          >
            <div className={`text-3xl font-bold ${item.color.replace('bg-', 'text-')}`}>
              {severityCounts[item.key]}
            </div>
            <div className="text-xs text-gray-400 mt-1">{t(item.labelKey)}</div>
          </motion.div>
        ))}
      </div>

      {/* Live Vulnerabilities Feed */}
      <motion.div 
        className="bg-dark-700/50 rounded-2xl p-6 border border-dark-600"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
          <FaExclamationTriangle className="text-cyber-yellow" />
          {t('recentVulnerabilities')}
        </h3>

        {recentVulns.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <FaCheckCircle className="text-4xl mx-auto mb-2 opacity-50" />
            <p>{t('searchingForVulns')}</p>
          </div>
        ) : (
          <div className="space-y-3">
            {recentVulns.map((vuln, i) => (
              <motion.div
                key={i}
                className="bg-dark-800/50 rounded-lg p-4 border border-dark-600"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1 }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold severity-${vuln.severity}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <span className="font-medium">
                      {vuln.type}
                      {vuln.subType && <span className="text-gray-400"> - {vuln.subType}</span>}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mt-2 truncate" dir="ltr">
                  {vuln.url}
                </p>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>

      {/* Scanning Animation */}
      <div className="flex justify-center">
        <motion.div 
          className="flex gap-2"
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 1.5, repeat: Infinity }}
        >
          {[...Array(5)].map((_, i) => (
            <motion.div
              key={i}
              className="w-3 h-3 bg-cyber-blue rounded-full"
              animate={{ y: [0, -10, 0] }}
              transition={{ duration: 0.5, delay: i * 0.1, repeat: Infinity }}
            />
          ))}
        </motion.div>
      </div>
    </div>
  )
}

export default ScanProgress
