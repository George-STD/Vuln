import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  FaShieldAlt, FaExclamationTriangle, FaCog, FaPlay, FaStop, 
  FaPlus, FaTrash, FaDownload, FaUpload, FaCheckCircle, FaTimes,
  FaToggleOn, FaToggleOff, FaGlobe, FaBan, FaClock, FaRocket,
  FaLock, FaUnlock, FaList, FaSave, FaFileImport, FaClipboardList
} from 'react-icons/fa'
import { toast } from 'react-toastify'
import { useLanguage } from '../contexts/LanguageContext'

const API_BASE = '/api/bounty'

function BugBountySettings({ onClose }) {
  const { t, isRTL } = useLanguage()
  
  // حالة النظام
  const [systemStatus, setSystemStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  
  // Scope
  const [inScopeDomains, setInScopeDomains] = useState('')
  const [outOfScopePaths, setOutOfScopePaths] = useState('')
  const [scopeText, setScopeText] = useState('')
  
  // Safety
  const [safetySettings, setSafetySettings] = useState({
    globalRPS: 3,
    perHostRPS: 1,
    maxConcurrency: 2,
    maxUrls: 200,
    maxDepth: 2,
    safeMode: true
  })
  
  // Profiles
  const [profiles, setProfiles] = useState([])
  const [templates, setTemplates] = useState([])
  const [newProfileName, setNewProfileName] = useState('')
  
  // Preflight
  const [preflightUrl, setPreflightUrl] = useState('')
  const [preflightResult, setPreflightResult] = useState(null)

  // جلب الحالة
  const fetchStatus = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/status`)
      const data = await response.json()
      setSystemStatus(data.status)
    } catch (error) {
      console.error('Failed to fetch status:', error)
    }
  }, [])

  // جلب البيانات الأولية
  useEffect(() => {
    const init = async () => {
      setLoading(true)
      await fetchStatus()
      
      // جلب الـ profiles
      try {
        const [profilesRes, templatesRes] = await Promise.all([
          fetch(`${API_BASE}/profiles`),
          fetch(`${API_BASE}/profiles/templates`)
        ])
        
        const profilesData = await profilesRes.json()
        const templatesData = await templatesRes.json()
        
        setProfiles(profilesData.profiles || [])
        setTemplates(templatesData.templates || [])
      } catch (error) {
        console.error('Failed to fetch profiles:', error)
      }
      
      setLoading(false)
    }
    
    init()
  }, [fetchStatus])

  // تفعيل/تعطيل النظام
  const toggleSystem = async () => {
    try {
      const endpoint = systemStatus?.enabled ? 'disable' : 'enable'
      const response = await fetch(`${API_BASE}/${endpoint}`, { method: 'POST' })
      const data = await response.json()
      
      if (data.success) {
        toast.success(systemStatus?.enabled ? t('systemDisabled') : t('systemEnabled'))
        fetchStatus()
      }
    } catch (error) {
      toast.error(t('failedChangeStatus'))
    }
  }

  // تفعيل Kill Switch
  const activateKillSwitch = async () => {
    try {
      const response = await fetch(`${API_BASE}/kill-switch/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual activation from UI' })
      })
      
      if (response.ok) {
        toast.success('🛑 ' + t('killSwitchActiveMessage'))
        fetchStatus()
      }
    } catch (error) {
      toast.error(t('error'))
    }
  }

  // إلغاء Kill Switch
  const deactivateKillSwitch = async () => {
    try {
      const response = await fetch(`${API_BASE}/kill-switch/deactivate`, { method: 'POST' })
      
      if (response.ok) {
        toast.success('✅ Kill Switch ' + t('disabled'))
        fetchStatus()
      }
    } catch (error) {
      toast.error(t('error'))
    }
  }

  // تطبيق ملف تعريف آمن
  const applySafeProfile = async () => {
    try {
      const domains = inScopeDomains.split('\n').filter(d => d.trim())
      
      const response = await fetch(`${API_BASE}/apply-safe-profile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains })
      })
      
      if (response.ok) {
        toast.success('✅ ' + t('settingsSaved'))
        fetchStatus()
      }
    } catch (error) {
      toast.error(t('settingsSaveFailed'))
    }
  }

  // تحديث الـ Scope
  const updateScope = async () => {
    try {
      const domains = inScopeDomains.split('\n').filter(d => d.trim())
      
      await fetch(`${API_BASE}/scope/in-scope`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains })
      })
      
      if (outOfScopePaths.trim()) {
        const paths = outOfScopePaths.split('\n').filter(p => p.trim())
        await fetch(`${API_BASE}/scope/out-of-scope`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ paths })
        })
      }
      
      toast.success(t('scopeSaved'))
      fetchStatus()
    } catch (error) {
      toast.error(t('scopeSaveFailed'))
    }
  }

  // استيراد Scope من نص
  const importScopeFromText = async () => {
    try {
      const response = await fetch(`${API_BASE}/scope/import-text`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: scopeText })
      })
      
      const data = await response.json()
      
      if (data.success) {
        toast.success(`${t('success')}: ${data.imported.inScope.domains.length} ${t('domains')}`)
        fetchStatus()
        setScopeText('')
      }
    } catch (error) {
      toast.error(t('error'))
    }
  }

  // تحديث إعدادات السلامة
  const updateSafetySettings = async () => {
    try {
      await fetch(`${API_BASE}/safety/rate-limits`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          globalRPS: safetySettings.globalRPS,
          perHostRPS: safetySettings.perHostRPS,
          maxConcurrency: safetySettings.maxConcurrency
        })
      })
      
      await fetch(`${API_BASE}/safety/crawling`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          maxUrls: safetySettings.maxUrls,
          maxDepth: safetySettings.maxDepth
        })
      })
      
      await fetch(`${API_BASE}/safety/safe-mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: safetySettings.safeMode })
      })
      
      toast.success(t('settingsSaved'))
      fetchStatus()
    } catch (error) {
      toast.error(t('settingsSaveFailed'))
    }
  }

  // تحميل قالب
  const loadTemplate = async (templateId) => {
    try {
      const response = await fetch(`${API_BASE}/profiles/template/${templateId}/load`, {
        method: 'POST'
      })
      
      if (response.ok) {
        toast.success(t('profileLoaded'))
        fetchStatus()
      }
    } catch (error) {
      toast.error(t('profileLoadFailed'))
    }
  }

  // تنفيذ Preflight
  const runPreflight = async () => {
    if (!preflightUrl) return
    
    try {
      const response = await fetch(`${API_BASE}/preflight`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: preflightUrl })
      })
      
      const data = await response.json()
      setPreflightResult(data.preflight)
    } catch (error) {
      toast.error(t('error'))
    }
  }

  // Tabs
  const tabs = [
    { id: 'overview', label: t('overview'), icon: FaShieldAlt },
    { id: 'scope', label: t('scope'), icon: FaGlobe },
    { id: 'safety', label: t('safety'), icon: FaCog },
    { id: 'profiles', label: t('profiles'), icon: FaList },
    { id: 'preflight', label: t('preflight'), icon: FaClipboardList }
  ]

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
        <div className="animate-spin text-4xl text-cyber-blue">⏳</div>
      </div>
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
        className="bg-dark-800 rounded-2xl w-full max-w-5xl max-h-[90vh] overflow-hidden border border-dark-600"
        initial={{ scale: 0.9, y: 20 }}
        animate={{ scale: 1, y: 0 }}
      >
        {/* Header */}
        <div className="bg-gradient-to-r from-orange-500 to-red-500 p-4 flex justify-between items-center">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FaShieldAlt />
            {t('bugBountySettings')}
          </h2>
          <div className="flex items-center gap-4">
            {/* Kill Switch */}
            <button
              onClick={systemStatus?.killSwitch?.isActivated ? deactivateKillSwitch : activateKillSwitch}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                systemStatus?.killSwitch?.isActivated
                  ? 'bg-green-500 hover:bg-green-600 text-white'
                  : 'bg-red-600 hover:bg-red-700 text-white'
              }`}
            >
              {systemStatus?.killSwitch?.isActivated ? (
                <>
                  <FaPlay className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('resume')}
                </>
              ) : (
                <>
                  <FaStop className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('emergencyStop')}
                </>
              )}
            </button>
            
            {/* Toggle System */}
            <button
              onClick={toggleSystem}
              className={`px-4 py-2 rounded-lg font-bold transition-all ${
                systemStatus?.enabled
                  ? 'bg-green-500/20 text-green-400 border border-green-500/50'
                  : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
              }`}
            >
              {systemStatus?.enabled ? (
                <>
                  <FaToggleOn className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('enabled')}
                </>
              ) : (
                <>
                  <FaToggleOff className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('disabled')}
                </>
              )}
            </button>
            
            <button onClick={onClose} className="text-white/70 hover:text-white">
              <FaTimes size={24} />
            </button>
          </div>
        </div>

        {/* Kill Switch Warning */}
        {systemStatus?.killSwitch?.isActivated && (
          <div className="bg-red-500/20 border-b border-red-500/50 p-3 text-center">
            <FaExclamationTriangle className={`inline ${isRTL ? 'ml-2' : 'mr-2'} text-red-400`} />
            <span className="text-red-400 font-bold">
              {t('killSwitchActiveMessage')}
            </span>
          </div>
        )}

        {/* Tabs */}
        <div className="flex border-b border-dark-600 overflow-x-auto">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-6 py-3 font-medium transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'text-orange-400 border-b-2 border-orange-400 bg-dark-700/50'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <tab.icon />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          <AnimatePresence mode="wait">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <motion.div
                key="overview"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Status Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* System Status */}
                  <div className={`p-4 rounded-xl border ${
                    systemStatus?.enabled
                      ? 'bg-green-500/10 border-green-500/30'
                      : 'bg-gray-500/10 border-gray-500/30'
                  }`}>
                    <div className="flex items-center gap-3">
                      {systemStatus?.enabled ? (
                        <FaLock className="text-green-400 text-2xl" />
                      ) : (
                        <FaUnlock className="text-gray-400 text-2xl" />
                      )}
                      <div>
                        <div className="text-sm text-gray-400">{t('systemStatus')}</div>
                        <div className={`font-bold ${
                          systemStatus?.enabled ? 'text-green-400' : 'text-gray-400'
                        }`}>
                          {systemStatus?.enabled ? t('enabled') : t('disabled')}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Scope Status */}
                  <div className={`p-4 rounded-xl border ${
                    systemStatus?.scope?.enabled
                      ? 'bg-blue-500/10 border-blue-500/30'
                      : 'bg-gray-500/10 border-gray-500/30'
                  }`}>
                    <div className="flex items-center gap-3">
                      <FaGlobe className={`text-2xl ${
                        systemStatus?.scope?.enabled ? 'text-blue-400' : 'text-gray-400'
                      }`} />
                      <div>
                        <div className="text-sm text-gray-400">{t('scope')}</div>
                        <div className={`font-bold ${
                          systemStatus?.scope?.enabled ? 'text-blue-400' : 'text-gray-400'
                        }`}>
                          {systemStatus?.scope?.domainsCount || 0} {t('domains')}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Safe Mode */}
                  <div className={`p-4 rounded-xl border ${
                    systemStatus?.safety?.safeMode
                      ? 'bg-orange-500/10 border-orange-500/30'
                      : 'bg-red-500/10 border-red-500/30'
                  }`}>
                    <div className="flex items-center gap-3">
                      <FaShieldAlt className={`text-2xl ${
                        systemStatus?.safety?.safeMode ? 'text-orange-400' : 'text-red-400'
                      }`} />
                      <div>
                        <div className="text-sm text-gray-400">{t('safeMode')}</div>
                        <div className={`font-bold ${
                          systemStatus?.safety?.safeMode ? 'text-orange-400' : 'text-red-400'
                        }`}>
                          {systemStatus?.safety?.safeMode ? t('enabled') : t('disabled') + ' ⚠️'}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Quick Settings */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <FaRocket className="text-orange-400" />
                    {t('quickSetup')}
                  </h3>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('enterAllowedDomains')}
                      </label>
                      <textarea
                        value={inScopeDomains}
                        onChange={(e) => setInScopeDomains(e.target.value)}
                        placeholder="example.com&#10;*.example.com&#10;api.example.com"
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-3 text-white text-sm h-24"
                        dir="ltr"
                      />
                    </div>
                    
                    <button
                      onClick={applySafeProfile}
                      className="w-full bg-gradient-to-r from-orange-500 to-red-500 text-white font-bold py-3 rounded-lg hover:opacity-90 transition-opacity"
                    >
                      <FaShieldAlt className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                      {t('applySafeSettings')}
                    </button>
                  </div>
                </div>

                {/* Current Settings Summary */}
                {systemStatus?.enabled && (
                  <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                    <h3 className="text-lg font-bold text-white mb-4">{t('currentSettings')}</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <div className="text-gray-400">Rate Limit</div>
                        <div className="text-white font-mono">
                          {systemStatus?.safety?.globalRPS || 0} RPS
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-400">Max URLs</div>
                        <div className="text-white font-mono">
                          {systemStatus?.safety?.maxUrls || 0}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-400">Methods</div>
                        <div className="text-white font-mono">
                          {systemStatus?.safety?.allowedMethods?.join(', ') || 'GET'}
                        </div>
                      </div>
                      <div>
                        <div className="text-gray-400">{t('profile')}</div>
                        <div className="text-white">
                          {systemStatus?.currentProfile || t('none')}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}

            {/* Scope Tab */}
            {activeTab === 'scope' && (
              <motion.div
                key="scope"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* In-Scope */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-green-400 mb-4 flex items-center gap-2">
                    <FaCheckCircle />
                    {t('inScope')}
                  </h3>
                  <textarea
                    value={inScopeDomains}
                    onChange={(e) => setInScopeDomains(e.target.value)}
                    placeholder="example.com&#10;*.example.com&#10;https://api.example.com/v1/*"
                    className="w-full bg-dark-600 border border-dark-500 rounded-lg p-3 text-white text-sm h-32"
                    dir="ltr"
                  />
                </div>

                {/* Out-of-Scope */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-red-400 mb-4 flex items-center gap-2">
                    <FaBan />
                    {t('outOfScope')}
                  </h3>
                  <textarea
                    value={outOfScopePaths}
                    onChange={(e) => setOutOfScopePaths(e.target.value)}
                    placeholder="/logout&#10;/admin/delete&#10;/billing/*&#10;/api/internal/*"
                    className="w-full bg-dark-600 border border-dark-500 rounded-lg p-3 text-white text-sm h-32"
                    dir="ltr"
                  />
                </div>

                <button
                  onClick={updateScope}
                  className="w-full bg-blue-500 text-white font-bold py-3 rounded-lg hover:bg-blue-600 transition-colors"
                >
                  <FaSave className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('saveScope')}
                </button>

                {/* Import from Text */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <FaFileImport />
                    {t('importFromText')}
                  </h3>
                  <textarea
                    value={scopeText}
                    onChange={(e) => setScopeText(e.target.value)}
                    placeholder="In Scope:&#10;- *.example.com&#10;- api.example.com&#10;&#10;Out of Scope:&#10;- admin.example.com&#10;- /logout"
                    className="w-full bg-dark-600 border border-dark-500 rounded-lg p-3 text-white text-sm h-40"
                    dir="ltr"
                  />
                  <button
                    onClick={importScopeFromText}
                    className="mt-3 bg-purple-500 text-white px-4 py-2 rounded-lg hover:bg-purple-600 transition-colors"
                  >
                    <FaUpload className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                    {t('import')}
                  </button>
                </div>
              </motion.div>
            )}

            {/* Safety Tab */}
            {activeTab === 'safety' && (
              <motion.div
                key="safety"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Safe Mode Toggle */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-bold text-white">{t('safeMode')}</h3>
                      <p className="text-sm text-gray-400">
                        {t('safeModeDesc')}
                      </p>
                    </div>
                    <button
                      onClick={() => setSafetySettings(s => ({ ...s, safeMode: !s.safeMode }))}
                      className={`text-4xl ${
                        safetySettings.safeMode ? 'text-green-400' : 'text-gray-500'
                      }`}
                    >
                      {safetySettings.safeMode ? <FaToggleOn /> : <FaToggleOff />}
                    </button>
                  </div>
                </div>

                {/* Rate Limits */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4">{t('rateLimiting')}</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('globalRPS')}
                      </label>
                      <input
                        type="number"
                        value={safetySettings.globalRPS}
                        onChange={(e) => setSafetySettings(s => ({ ...s, globalRPS: parseInt(e.target.value) }))}
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-2 text-white"
                        min="1"
                        max="50"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('perHostRPS')}
                      </label>
                      <input
                        type="number"
                        value={safetySettings.perHostRPS}
                        onChange={(e) => setSafetySettings(s => ({ ...s, perHostRPS: parseInt(e.target.value) }))}
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-2 text-white"
                        min="1"
                        max="20"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('maxConcurrency')}
                      </label>
                      <input
                        type="number"
                        value={safetySettings.maxConcurrency}
                        onChange={(e) => setSafetySettings(s => ({ ...s, maxConcurrency: parseInt(e.target.value) }))}
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-2 text-white"
                        min="1"
                        max="20"
                      />
                    </div>
                  </div>
                </div>

                {/* Crawling Limits */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4">{t('crawlingLimits')}</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('maxUrls')}
                      </label>
                      <input
                        type="number"
                        value={safetySettings.maxUrls}
                        onChange={(e) => setSafetySettings(s => ({ ...s, maxUrls: parseInt(e.target.value) }))}
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-2 text-white"
                        min="10"
                        max="5000"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">
                        {t('maxDepth')}
                      </label>
                      <input
                        type="number"
                        value={safetySettings.maxDepth}
                        onChange={(e) => setSafetySettings(s => ({ ...s, maxDepth: parseInt(e.target.value) }))}
                        className="w-full bg-dark-600 border border-dark-500 rounded-lg p-2 text-white"
                        min="1"
                        max="10"
                      />
                    </div>
                  </div>
                </div>

                <button
                  onClick={updateSafetySettings}
                  className="w-full bg-blue-500 text-white font-bold py-3 rounded-lg hover:bg-blue-600 transition-colors"
                >
                  <FaSave className={`inline ${isRTL ? 'ml-2' : 'mr-2'}`} />
                  {t('saveSafetySettings')}
                </button>
              </motion.div>
            )}

            {/* Profiles Tab */}
            {activeTab === 'profiles' && (
              <motion.div
                key="profiles"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Templates */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4">{t('readyTemplates')}</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {templates.map(template => (
                      <button
                        key={template.id}
                        onClick={() => loadTemplate(template.id)}
                        className={`bg-dark-600 hover:bg-dark-500 border border-dark-500 rounded-lg p-4 ${isRTL ? 'text-right' : 'text-left'} transition-colors`}
                      >
                        <div className="font-bold text-white">{template.name}</div>
                        <div className="text-sm text-gray-400">{template.description}</div>
                        <div className={`text-xs mt-2 ${
                          template.safeMode ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {template.safeMode ? '✓ Safe Mode' : '⚠️ Aggressive'}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Saved Profiles */}
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4">{t('savedProfiles')}</h3>
                  {profiles.length === 0 ? (
                    <p className="text-gray-400 text-center py-4">{t('noSavedProfiles')}</p>
                  ) : (
                    <div className="space-y-2">
                      {profiles.map(profile => (
                        <div
                          key={profile.id}
                          className="flex items-center justify-between bg-dark-600 rounded-lg p-3"
                        >
                          <div>
                            <div className="font-bold text-white">{profile.name}</div>
                            <div className="text-sm text-gray-400">
                              {profile.domainsCount} {t('domains')} • {profile.scansCount} {t('scans')}
                            </div>
                          </div>
                          <button
                            onClick={() => bountyProfileManager.loadProfile(profile.id)}
                            className="bg-blue-500 text-white px-3 py-1 rounded-lg text-sm hover:bg-blue-600"
                          >
                            {t('load')}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* Preflight Tab */}
            {activeTab === 'preflight' && (
              <motion.div
                key="preflight"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                <div className="bg-dark-700/50 rounded-xl p-4 border border-dark-600">
                  <h3 className="text-lg font-bold text-white mb-4">{t('preflightCheck')}</h3>
                  <p className="text-gray-400 mb-4">
                    {t('preflightDesc')}
                  </p>
                  
                  <div className="flex gap-2">
                    <input
                      type="url"
                      value={preflightUrl}
                      onChange={(e) => setPreflightUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="flex-1 bg-dark-600 border border-dark-500 rounded-lg p-3 text-white"
                      dir="ltr"
                    />
                    <button
                      onClick={runPreflight}
                      className="bg-orange-500 text-white px-6 rounded-lg hover:bg-orange-600 transition-colors"
                    >
                      {t('check')}
                    </button>
                  </div>
                </div>

                {/* Preflight Results */}
                {preflightResult && (
                  <div className={`bg-dark-700/50 rounded-xl p-4 border ${
                    preflightResult.passed ? 'border-green-500/50' : 'border-red-500/50'
                  }`}>
                    <h3 className={`text-lg font-bold mb-4 ${
                      preflightResult.passed ? 'text-green-400' : 'text-red-400'
                    }`}>
                      {preflightResult.passed ? t('readyToScan') : t('hasIssues')}
                    </h3>

                    {/* Checks */}
                    <div className="space-y-2 mb-4">
                      {preflightResult.checks.map((check, i) => (
                        <div key={i} className="flex items-center gap-2">
                          {check.passed ? (
                            <FaCheckCircle className="text-green-400" />
                          ) : (
                            <FaTimes className="text-red-400" />
                          )}
                          <span className="text-gray-300">{check.name}</span>
                          {!check.passed && (
                            <span className="text-red-400 text-sm">- {check.message}</span>
                          )}
                        </div>
                      ))}
                    </div>

                    {/* Warnings */}
                    {preflightResult.warnings.length > 0 && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                        <div className="text-yellow-400 font-bold mb-2">{t('warnings')}</div>
                        <ul className="list-disc list-inside text-sm text-yellow-300">
                          {preflightResult.warnings.map((w, i) => (
                            <li key={i}>{w}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Confirmations */}
                    {preflightResult.confirmations.length > 0 && (
                      <div className="mt-4 space-y-2">
                        <div className="text-white font-bold">{t('requiredConfirmations')}</div>
                        {preflightResult.confirmations.map((conf, i) => (
                          <label key={i} className="flex items-center gap-2 text-sm text-gray-300">
                            <input type="checkbox" className="rounded" />
                            {conf.text}
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </motion.div>
  )
}

export default BugBountySettings
