import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  FaCheckCircle, FaTimes, FaExclamationTriangle, FaRocket,
  FaShieldAlt, FaGlobe, FaClock, FaLock
} from 'react-icons/fa'
import { useLanguage } from '../contexts/LanguageContext'

function PreflightConfirmation({ targetUrl, onConfirm, onCancel }) {
  const { t, isRTL } = useLanguage()
  const [loading, setLoading] = useState(true)
  const [preflightResult, setPreflightResult] = useState(null)
  const [confirmations, setConfirmations] = useState({
    permission: false,
    scope: false,
    responsibility: false
  })

  useEffect(() => {
    const runPreflight = async () => {
      try {
        const response = await fetch('/api/bounty/preflight', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetUrl })
        })

        const data = await response.json()
        setPreflightResult(data.preflight)
      } catch (error) {
        console.error('Preflight error:', error)
        setPreflightResult({
          passed: false,
          checks: [{ name: 'Connection', passed: false, message: t('connectionFailed') }],
          warnings: [t('couldNotVerifyBountySettings')],
          confirmations: []
        })
      } finally {
        setLoading(false)
      }
    }

    runPreflight()
  }, [targetUrl])

  const allConfirmed = Object.values(confirmations).every(v => v)
  const canProceed = preflightResult?.passed && allConfirmed

  const handleConfirmChange = (key) => {
    setConfirmations(prev => ({ ...prev, [key]: !prev[key] }))
  }

  if (loading) {
    return (
      <motion.div
        className="fixed inset-0 bg-black/80 flex items-center justify-center z-50"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <div className="bg-dark-800 rounded-xl p-8 text-center">
          <div className="animate-spin text-4xl text-cyber-blue mb-4">⏳</div>
          <p className="text-white">{t('checkingSettings')}</p>
        </div>
      </motion.div>
    )
  }

  return (
    <motion.div
      className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <motion.div
        className="bg-dark-800 rounded-2xl w-full max-w-2xl overflow-hidden border border-dark-600"
        initial={{ scale: 0.9, y: 20 }}
        animate={{ scale: 1, y: 0 }}
      >
        {/* Header */}
        <div className={`p-4 ${
          preflightResult?.passed 
            ? 'bg-gradient-to-r from-green-500 to-emerald-500' 
            : 'bg-gradient-to-r from-red-500 to-orange-500'
        }`}>
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FaShieldAlt />
              {t('preflightCheck')}
            </h2>
            <button onClick={onCancel} className="text-white/70 hover:text-white">
              <FaTimes size={20} />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Target URL */}
          <div className="bg-dark-700/50 rounded-lg p-4 border border-dark-600">
            <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
              <FaGlobe />
              {t('target')}
            </div>
            <div className="text-white font-mono text-lg">{targetUrl}</div>
          </div>

          {/* Checks */}
          <div className="space-y-2">
            <h3 className="text-lg font-bold text-white">{t('checkResults')}</h3>
            {preflightResult?.checks?.map((check, i) => (
              <div
                key={i}
                className={`flex items-center gap-3 p-3 rounded-lg ${
                  check.passed ? 'bg-green-500/10' : 'bg-red-500/10'
                }`}
              >
                {check.passed ? (
                  <FaCheckCircle className="text-green-400 text-lg" />
                ) : (
                  <FaTimes className="text-red-400 text-lg" />
                )}
                <div>
                  <div className="text-white">{check.name}</div>
                  {!check.passed && check.message && (
                    <div className="text-sm text-red-400">{check.message}</div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Warnings */}
          {preflightResult?.warnings?.length > 0 && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 text-yellow-400 font-bold mb-2">
                <FaExclamationTriangle />
                {t('warnings')}
              </div>
              <ul className="list-disc list-inside text-yellow-300 text-sm space-y-1">
                {preflightResult.warnings.map((warning, i) => (
                  <li key={i}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Confirmations */}
          {preflightResult?.passed && (
            <div className="space-y-3">
              <h3 className="text-lg font-bold text-white">{t('requiredConfirmations')}</h3>
              
              <label className="flex items-start gap-3 p-3 bg-dark-700/50 rounded-lg cursor-pointer hover:bg-dark-700">
                <input
                  type="checkbox"
                  checked={confirmations.permission}
                  onChange={() => handleConfirmChange('permission')}
                  className="w-5 h-5 mt-1 accent-green-500"
                />
                <div>
                  <div className="text-white font-medium">{t('havePermission')}</div>
                  <div className="text-sm text-gray-400">
                    {t('havePermissionDesc')}
                  </div>
                </div>
              </label>

              <label className="flex items-start gap-3 p-3 bg-dark-700/50 rounded-lg cursor-pointer hover:bg-dark-700">
                <input
                  type="checkbox"
                  checked={confirmations.scope}
                  onChange={() => handleConfirmChange('scope')}
                  className="w-5 h-5 mt-1 accent-green-500"
                />
                <div>
                  <div className="text-white font-medium">{t('withinScope')}</div>
                  <div className="text-sm text-gray-400">
                    {t('withinScopeDesc')}
                  </div>
                </div>
              </label>

              <label className="flex items-start gap-3 p-3 bg-dark-700/50 rounded-lg cursor-pointer hover:bg-dark-700">
                <input
                  type="checkbox"
                  checked={confirmations.responsibility}
                  onChange={() => handleConfirmChange('responsibility')}
                  className="w-5 h-5 mt-1 accent-green-500"
                />
                <div>
                  <div className="text-white font-medium">{t('takeResponsibility')}</div>
                  <div className="text-sm text-gray-400">
                    {t('takeResponsibilityDesc')}
                  </div>
                </div>
              </label>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="flex-1 bg-gray-600 hover:bg-gray-700 text-white font-bold py-3 rounded-lg transition-colors"
            >
              {t('cancel')}
            </button>
            
            <button
              onClick={() => onConfirm(confirmations)}
              disabled={!canProceed}
              className={`flex-1 font-bold py-3 rounded-lg transition-all flex items-center justify-center gap-2 ${
                canProceed
                  ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white hover:opacity-90'
                  : 'bg-gray-700 text-gray-500 cursor-not-allowed'
              }`}
            >
              <FaRocket />
              {canProceed ? t('startScan') : t('completeConfirmations')}
            </button>
          </div>

          {!preflightResult?.passed && (
            <p className="text-center text-red-400 text-sm">
              {t('cannotStart')}
            </p>
          )}
        </div>
      </motion.div>
    </motion.div>
  )
}

export default PreflightConfirmation
