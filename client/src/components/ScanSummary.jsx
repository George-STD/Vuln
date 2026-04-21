import { motion } from 'framer-motion'
import { FaDownload, FaRedo, FaClock, FaLink, FaFileAlt, FaBug, FaShieldAlt, FaCloud, FaFilePdf, FaCode, FaBookOpen } from 'react-icons/fa'
import { useLanguage } from '../contexts/LanguageContext'

function ScanSummary({ summary, targetUrl, onExport, onExportSarif, onExportWalkthrough, onNewScan, wafInfo }) {
  const { t } = useLanguage()
  
  return (
    <motion.div 
      className="bg-dark-700/50 rounded-2xl p-6 border border-dark-600 mb-6"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold gradient-text flex items-center gap-3">
            <FaBug className="text-cyber-red" />
            {t('scanResults')}
          </h2>
          <p className="text-gray-400 text-sm mt-1" dir="ltr">{targetUrl}</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {/* Walkthrough PDF - PortSwigger Style */}
          <motion.button
            onClick={onExportWalkthrough}
            className="bg-gradient-to-r from-orange-500/20 to-red-500/20 text-orange-400 px-4 py-2 rounded-lg flex items-center gap-2 hover:from-orange-500/30 hover:to-red-500/30 transition-all border border-orange-500/30"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            title={t('walkthroughTooltip')}
          >
            <FaBookOpen />
            <span>{t('walkthrough')}</span>
          </motion.button>
          <motion.button
            onClick={() => onExport('pdf')}
            className="bg-red-500/20 text-red-400 px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-red-500/30 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaFilePdf />
            <span>PDF</span>
          </motion.button>
          <motion.button
            onClick={() => onExport('html')}
            className="bg-cyber-blue/20 text-cyber-blue px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-cyber-blue/30 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaDownload />
            <span>HTML</span>
          </motion.button>
          <motion.button
            onClick={() => onExport('json')}
            className="bg-cyber-green/20 text-cyber-green px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-cyber-green/30 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaDownload />
            <span>JSON</span>
          </motion.button>
          <motion.button
            onClick={onExportSarif}
            className="bg-purple-500/20 text-purple-400 px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-purple-500/30 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            title={t('exportForCICD')}
          >
            <FaCode />
            <span>SARIF</span>
          </motion.button>
          <motion.button
            onClick={onNewScan}
            className="bg-dark-600 text-gray-300 px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-dark-500 transition-colors"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaRedo />
            <span>{t('newScan')}</span>
          </motion.button>
        </div>
      </div>

      {/* WAF/CDN Detection */}
      {wafInfo && (wafInfo.waf?.detected || wafInfo.cdn?.detected) && (
        <div className="flex flex-wrap gap-3 mb-6">
          {wafInfo.waf?.detected && (
            <motion.div 
              className="bg-red-500/20 border border-red-500/50 rounded-xl px-4 py-2 flex items-center gap-2"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
            >
              <FaShieldAlt className="text-red-400" />
              <span className="text-red-400 font-bold">WAF:</span>
              <span className="text-gray-300">{wafInfo.waf.name}</span>
              <span className="text-xs text-gray-500">({wafInfo.waf.confidence}%)</span>
            </motion.div>
          )}
          {wafInfo.cdn?.detected && (
            <motion.div 
              className="bg-blue-500/20 border border-blue-500/50 rounded-xl px-4 py-2 flex items-center gap-2"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
            >
              <FaCloud className="text-blue-400" />
              <span className="text-blue-400 font-bold">CDN:</span>
              <span className="text-gray-300">{wafInfo.cdn.name}</span>
              <span className="text-xs text-gray-500">({wafInfo.cdn.confidence}%)</span>
            </motion.div>
          )}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-dark-800/50 rounded-xl p-4 flex items-center gap-3">
          <FaClock className="text-2xl text-cyber-blue" />
          <div>
            <div className="text-lg font-bold">{summary.duration}</div>
            <div className="text-xs text-gray-400">{t('scanDuration')}</div>
          </div>
        </div>
        <div className="bg-dark-800/50 rounded-xl p-4 flex items-center gap-3">
          <FaLink className="text-2xl text-cyber-green" />
          <div>
            <div className="text-lg font-bold">{summary.urlsScanned}</div>
            <div className="text-xs text-gray-400">{t('urlsScanned')}</div>
          </div>
        </div>
        <div className="bg-dark-800/50 rounded-xl p-4 flex items-center gap-3">
          <FaFileAlt className="text-2xl text-cyber-yellow" />
          <div>
            <div className="text-lg font-bold">{summary.formsFound}</div>
            <div className="text-xs text-gray-400">{t('forms')}</div>
          </div>
        </div>
        <div className="bg-dark-800/50 rounded-xl p-4 flex items-center gap-3">
          <FaBug className="text-2xl text-cyber-red" />
          <div>
            <div className="text-lg font-bold">{summary.totalVulnerabilities}</div>
            <div className="text-xs text-gray-400">{t('totalVulns')}</div>
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { key: 'critical', labelKey: 'critical', emoji: '🔴', color: 'from-red-500 to-red-600' },
          { key: 'high', labelKey: 'high', emoji: '🟠', color: 'from-orange-500 to-orange-600' },
          { key: 'medium', labelKey: 'medium', emoji: '🟡', color: 'from-yellow-500 to-yellow-600' },
          { key: 'low', labelKey: 'low', emoji: '🔵', color: 'from-blue-500 to-blue-600' },
          { key: 'info', labelKey: 'info', emoji: '⚪', color: 'from-gray-500 to-gray-600' }
        ].map((item) => (
          <motion.div
            key={item.key}
            className={`rounded-xl p-4 text-center bg-gradient-to-br ${item.color} shadow-lg`}
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            whileHover={{ scale: 1.05 }}
          >
            <div className="text-3xl mb-1">{item.emoji}</div>
            <div className="text-3xl font-bold text-white">
              {summary[item.key] || 0}
            </div>
            <div className="text-xs text-white/80">{t(item.labelKey)}</div>
          </motion.div>
        ))}
      </div>

      {/* Technologies */}
      {summary.technologies && summary.technologies.length > 0 && (
        <div className="mt-6 bg-dark-800/50 rounded-xl p-4">
          <h4 className="font-bold text-cyber-blue mb-3">{t('detectedTechnologies')}</h4>
          <div className="flex flex-wrap gap-2">
            {summary.technologies.map((tech, i) => (
              <span 
                key={i}
                className="bg-dark-600 px-3 py-1 rounded-full text-sm"
              >
                {tech.name} {tech.version && `(${tech.version})`}
              </span>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default ScanSummary
