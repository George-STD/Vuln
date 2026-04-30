import { useState, useEffect, useCallback } from 'react'
import { io } from 'socket.io-client'
import { toast } from 'react-toastify'
import { motion, AnimatePresence } from 'framer-motion'
import Header from './components/Header'
import ScanForm from './components/ScanForm'
import ScanProgress from './components/ScanProgress'
import VulnerabilityList from './components/VulnerabilityList'
import ScanSummary from './components/ScanSummary'
import Footer from './components/Footer'
import ScheduledScans from './components/ScheduledScans'
import OwnershipVerification from './components/OwnershipVerification'
import EnterpriseDashboard from './components/EnterpriseDashboard'
import BugBountySettings from './components/BugBountySettings'
import { useLanguage } from './contexts/LanguageContext'

function App() {
  const { t } = useLanguage()
  const [socket, setSocket] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const [scanState, setScanState] = useState('idle') // idle, verifying, scanning, completed, error
  const [currentView, setCurrentView] = useState('scanner') // scanner, schedules, enterprise
  const [showBountySettings, setShowBountySettings] = useState(false)
  const [scanId, setScanId] = useState(null)
  const [progress, setProgress] = useState(0)
  const [currentPhase, setCurrentPhase] = useState('')
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [scanSummary, setScanSummary] = useState(null)
  const [targetUrl, setTargetUrl] = useState('')
  const [wafInfo, setWafInfo] = useState(null)
  const [pendingScanOptions, setPendingScanOptions] = useState(null)

  // Initialize socket connection
  useEffect(() => {
    const newSocket = io('http://localhost:3001', {
      transports: ['websocket', 'polling']
    })

    newSocket.on('connect', () => {
      setIsConnected(true)
      console.log('Connected to server')
    })

    newSocket.on('disconnect', () => {
      setIsConnected(false)
      console.log('Disconnected from server')
    })

    newSocket.on('scan:progress', (data) => {
      setProgress(data.progress)
      setCurrentPhase(data.phase || '')
    })

    newSocket.on('scan:vulnerability', (vuln) => {
      setVulnerabilities(prev => [...prev, vuln])
      
      // Show toast for high/critical vulnerabilities
      if (vuln.severity === 'critical') {
        toast.error(`🔴 Critical vulnerability: ${vuln.type}`, { icon: false })
      } else if (vuln.severity === 'high') {
        toast.warning(`🟠 High vulnerability: ${vuln.type}`, { icon: false })
      }
    })

    newSocket.on('scan:complete', (data) => {
      setScanState('completed')
      setScanSummary(data.summary)
      if (data.wafInfo) {
        setWafInfo(data.wafInfo)
      }
      toast.success('✅ Scan completed successfully!', { icon: false })
    })

    newSocket.on('scan:error', (data) => {
      setScanState('error')
      toast.error(`❌ Error: ${data.message}`, { icon: false })
    })

    setSocket(newSocket)

    return () => {
      newSocket.close()
    }
  }, [])

  const startScan = useCallback(async (url, options) => {
    if (!url) {
      toast.error(t('pleaseEnterUrl'))
      return
    }

    // Check if ownership verification is required
    if (options.requireVerification) {
      setTargetUrl(url)
      setPendingScanOptions(options)
      setScanState('verifying')
      return
    }

    // Proceed with scan
    await executeScan(url, options)
  }, [socket, t])

  const executeScan = useCallback(async (url, options) => {
    // Reset state
    setVulnerabilities([])
    setProgress(0)
    setCurrentPhase('')
    setScanSummary(null)
    setScanState('scanning')
    setTargetUrl(url)

    const normalizeStringList = (value) => {
      if (Array.isArray(value)) {
        return value.map((item) => String(item || '').trim()).filter(Boolean)
      }

      if (typeof value === 'string') {
        return value
          .split(/\r?\n/)
          .map((item) => item.trim())
          .filter(Boolean)
      }

      return []
    }

    const normalizedWriteupLinks = normalizeStringList(options.writeupLinks)
    const normalizedInteractionPaths = normalizeStringList(options.interactionPaths)

    const normalizedOptions = {
      ...options,
      maxDepth: options.maxDepth ?? options.depth ?? 3,
      scanDurationMinutes: Number.isFinite(Number(options.scanDurationMinutes))
        ? Math.max(0, Math.min(1440, Number(options.scanDurationMinutes)))
        : 0,
      learningRuleUsagePercent: Number.isFinite(Number(options.learningRuleUsagePercent))
        ? Math.max(1, Math.min(100, Math.round(Number(options.learningRuleUsagePercent))))
        : 100,
      writeupLinks: normalizedWriteupLinks,
      interactionPaths: normalizedInteractionPaths
    }

    delete normalizedOptions.depth

    if (normalizedInteractionPaths.length > 0) {
      normalizedOptions.enableHumanLikeInteraction = true
    }

    if (normalizedWriteupLinks.length > 0) {
      normalizedOptions.learningMode = true
    }

    if (Array.isArray(normalizedOptions.scanModules)) {
      const moduleSet = new Set(normalizedOptions.scanModules.map((moduleName) => String(moduleName)))

      if (normalizedOptions.enableDomXss) {
        moduleSet.add('domXss')
      }

      if (normalizedOptions.enableHumanLikeInteraction || normalizedInteractionPaths.length > 0) {
        moduleSet.add('interactiveLogic')
      }

      normalizedOptions.scanModules = Array.from(moduleSet)
    }

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url, options: normalizedOptions })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || t('failedStartScan'))
      }

      setScanId(data.scanId)

      // Join scan room
      if (socket) {
        socket.emit('join:scan', data.scanId)
      }

      toast.info(t('scanStarting'), { icon: false })
    } catch (error) {
      setScanState('error')
      toast.error(`❌ ${error.message}`)
    }
  }, [socket, t])

  const stopScan = useCallback(async () => {
    if (!scanId) return

    try {
      await fetch(`/api/scan/${scanId}/stop`, {
        method: 'POST'
      })
      setScanState('idle')
      toast.info(t('scanStopped'))
    } catch (error) {
      toast.error(t('failedStopScan'))
    }
  }, [scanId, t])

  const resetScan = useCallback(() => {
    setScanState('idle')
    setScanId(null)
    setProgress(0)
    setCurrentPhase('')
    setVulnerabilities([])
    setScanSummary(null)
    setTargetUrl('')
    setWafInfo(null)
    setPendingScanOptions(null)
  }, [])

  const handleVerified = useCallback(() => {
    if (pendingScanOptions) {
      executeScan(targetUrl, pendingScanOptions)
    }
  }, [targetUrl, pendingScanOptions, executeScan])

  const handleSkipVerification = useCallback(() => {
    if (pendingScanOptions) {
      const limitedOptions = { ...pendingScanOptions, limitedScan: true }
      executeScan(targetUrl, limitedOptions)
    }
  }, [targetUrl, pendingScanOptions, executeScan])

  const exportSarif = useCallback(async () => {
    if (!scanId) return

    try {
      const response = await fetch(`/api/scan/${scanId}/sarif`)
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan-${scanId}.sarif`
      a.click()
      window.URL.revokeObjectURL(url)
      toast.success(t('sarifExportSuccess'))
    } catch (error) {
      toast.error(t('sarifExportFailed'))
    }
  }, [scanId, t])

  const exportWalkthrough = useCallback(async () => {
    if (!scanId) return

    try {
      toast.loading('⏳ Creating walkthrough...', { id: 'walkthrough' })
      
      const response = await fetch(`/api/scan/${scanId}/walkthrough`)
      
      if (!response.ok) {
        throw new Error('Failed to create walkthrough')
      }
      
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `walkthrough-${scanId}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
      
      toast.success(t('walkthroughSuccess'), { id: 'walkthrough' })
    } catch (error) {
      toast.error(t('walkthroughFailed'), { id: 'walkthrough' })
    }
  }, [scanId, t])

  const exportReport = useCallback(async (format) => {
    if (!scanId) return

    try {
      const response = await fetch(`/api/scan/${scanId}/report?format=${format}`)
      const data = await response.json()
      
      if (data.path) {
        toast.success(`📄 Report created: ${data.filename}`)
      }
    } catch (error) {
      toast.error(t('reportFailed'))
    }
  }, [scanId, t])

  return (
    <div className="min-h-screen matrix-bg">
      <Header 
        isConnected={isConnected} 
        currentView={currentView}
        onViewChange={setCurrentView}
        onShowBountySettings={() => setShowBountySettings(true)}
      />
      
      {/* Bug Bounty Settings Modal */}
      <AnimatePresence>
        {showBountySettings && (
          <BugBountySettings onClose={() => setShowBountySettings(false)} />
        )}
      </AnimatePresence>
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        <AnimatePresence mode="wait">
          {currentView === 'schedules' && (
            <motion.div
              key="schedules"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <ScheduledScans onBack={() => setCurrentView('scanner')} />
            </motion.div>
          )}

          {currentView === 'scanner' && scanState === 'idle' && (
            <motion.div
              key="form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <ScanForm onSubmit={startScan} />
            </motion.div>
          )}

          {currentView === 'scanner' && scanState === 'verifying' && (
            <motion.div
              key="verification"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <OwnershipVerification
                url={targetUrl}
                onVerified={handleVerified}
                onSkip={handleSkipVerification}
              />
            </motion.div>
          )}

          {currentView === 'scanner' && scanState === 'scanning' && (
            <motion.div
              key="progress"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <ScanProgress
                progress={progress}
                phase={currentPhase}
                targetUrl={targetUrl}
                vulnerabilities={vulnerabilities}
                onStop={stopScan}
              />
            </motion.div>
          )}

          {currentView === 'scanner' && (scanState === 'completed' || scanState === 'error') && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              {scanSummary && (
                <ScanSummary 
                  summary={scanSummary} 
                  targetUrl={targetUrl}
                  onExport={exportReport}
                  onExportSarif={exportSarif}
                  onExportWalkthrough={exportWalkthrough}
                  onNewScan={resetScan}
                />
              )}
              
              <VulnerabilityList vulnerabilities={vulnerabilities} />
            </motion.div>
          )}

          {currentView === 'enterprise' && (
            <motion.div
              key="enterprise"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <EnterpriseDashboard />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
      
      <Footer />
    </div>
  )
}

export default App
