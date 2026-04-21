import { FaGithub, FaHeart, FaShieldAlt } from 'react-icons/fa'
import { useLanguage } from '../contexts/LanguageContext'

function Footer() {
  const { t } = useLanguage()
  
  return (
    <footer className="border-t border-dark-600 bg-dark-800/50 mt-12">
      <div className="container mx-auto px-4 py-6 max-w-6xl">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-gray-400">
            <FaShieldAlt className="text-cyber-blue" />
            <span>{t('appName')}</span>
          </div>
          
          <div className="text-center text-sm text-gray-500">
            <p>⚠️ {t('ethicalUseWarning')}</p>
            <p className="flex items-center justify-center gap-1 mt-1">
              {t('madeWith')} <FaHeart className="text-cyber-red" /> {t('forCommunity')}
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            <a 
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-cyber-blue transition-colors"
            >
              <FaGithub className="text-2xl" />
            </a>
          </div>
        </div>
        
        <div className="text-center text-xs text-gray-600 mt-4">
          © {new Date().getFullYear()} - {t('allRightsReserved')}
        </div>
      </div>
    </footer>
  )
}

export default Footer
