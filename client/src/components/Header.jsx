import { motion } from 'framer-motion'
import { FaShieldAlt, FaWifi, FaCircle, FaClock, FaSearch, FaBuilding, FaBug, FaGlobe } from 'react-icons/fa'
import { useLanguage } from '../contexts/LanguageContext'

function Header({ isConnected, currentView, onViewChange, onShowBountySettings }) {
  const { language, toggleLanguage, t, isRTL } = useLanguage();
  
  return (
    <header className="border-b border-dark-600 bg-dark-800/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4 max-w-6xl">
        <div className="flex items-center justify-between">
          <motion.div 
            className="flex items-center gap-3"
            initial={{ opacity: 0, x: isRTL ? 20 : -20 }}
            animate={{ opacity: 1, x: 0 }}
          >
            <div className="relative">
              <FaShieldAlt className="text-4xl text-cyber-blue" />
              <motion.div
                className="absolute inset-0"
                animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <FaShieldAlt className="text-4xl text-cyber-blue" />
              </motion.div>
            </div>
            <div>
              <h1 className="text-2xl font-bold gradient-text">
                {t('appName')}
              </h1>
              <p className="text-xs text-gray-500">{t('appSubtitle')}</p>
            </div>
          </motion.div>

          {/* Navigation */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => onViewChange?.('scanner')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                currentView === 'scanner'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-700/50'
              }`}
            >
              <FaSearch className="text-sm" />
              <span className="hidden sm:inline">{t('scanner')}</span>
            </button>
            
            <button
              onClick={() => onViewChange?.('schedules')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                currentView === 'schedules'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-700/50'
              }`}
            >
              <FaClock className="text-sm" />
              <span className="hidden sm:inline">{t('schedules')}</span>
            </button>

            <button
              onClick={() => onViewChange?.('enterprise')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                currentView === 'enterprise'
                  ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-700/50'
              }`}
            >
              <FaBuilding className="text-sm" />
              <span className="hidden sm:inline">{t('enterprise')}</span>
            </button>

            {/* Bug Bounty Settings Button */}
            <button
              onClick={() => onShowBountySettings?.()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg transition-all bg-gradient-to-r from-orange-500/20 to-red-500/20 text-orange-400 border border-orange-500/30 hover:from-orange-500/30 hover:to-red-500/30"
            >
              <FaBug className="text-sm" />
              <span className="hidden sm:inline">{t('bugBounty')}</span>
            </button>

            {/* Language Toggle */}
            <button
              onClick={toggleLanguage}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-all bg-dark-700 hover:bg-dark-600 text-gray-300 border border-dark-500"
              title={language === 'en' ? 'Switch to Arabic' : 'التبديل للإنجليزية'}
            >
              <FaGlobe className="text-sm" />
              <span className="text-sm font-medium">{language === 'en' ? 'عربي' : 'EN'}</span>
            </button>
          </div>

          <motion.div 
            className="flex items-center gap-2 text-sm"
            initial={{ opacity: 0, x: isRTL ? -20 : 20 }}
            animate={{ opacity: 1, x: 0 }}
          >
            <FaWifi className={isConnected ? 'text-cyber-green' : 'text-gray-500'} />
            <span className={isConnected ? 'text-cyber-green' : 'text-gray-500'}>
              {isConnected ? t('connected') : t('disconnected')}
            </span>
            <FaCircle className={`text-xs ${isConnected ? 'text-cyber-green animate-pulse' : 'text-gray-500'}`} />
          </motion.div>
        </div>
      </div>
    </header>
  )
}

export default Header
