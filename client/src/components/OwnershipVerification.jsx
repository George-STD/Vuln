import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLanguage } from '../contexts/LanguageContext';

export default function OwnershipVerification({ url, onVerified, onSkip }) {
  const { t, isRTL } = useLanguage();
  const [step, setStep] = useState('generate'); // generate, verify
  const [method, setMethod] = useState('http'); // http, dns
  const [token, setToken] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [error, setError] = useState(null);

  const generateToken = async () => {
    try {
      setError(null);
      const response = await fetch('http://localhost:3001/api/verify/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      
      const data = await response.json();
      setToken(data);
      setStep('verify');
    } catch (err) {
      setError(t('failedToGenerateToken'));
    }
  };

  const verifyOwnership = async () => {
    try {
      setVerifying(true);
      setError(null);
      
      const response = await fetch('http://localhost:3001/api/verify/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, method })
      });
      
      const result = await response.json();
      setVerificationResult(result);
      
      if (result.verified) {
        setTimeout(() => onVerified(), 1500);
      }
    } catch (err) {
      setError(t('failedToVerifyOwnership'));
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-2xl border border-gray-700 p-8 max-w-2xl mx-auto"
      dir={isRTL ? 'rtl' : 'ltr'}
    >
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-amber-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
          <svg className="w-8 h-8 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold">{t('ownershipVerificationTitle')}</h2>
        <p className="text-gray-400 mt-2">
          {t('ownershipVerificationDesc')}
        </p>
        <p className="text-cyan-400 mt-1">{url}</p>
      </div>

      {step === 'generate' && (
        <div className="text-center">
          <p className="text-gray-300 mb-6">
            {t('generateTokenInfo')}
          </p>
          
          <button
            onClick={generateToken}
            className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl font-bold hover:shadow-lg hover:shadow-cyan-500/25 transition-all"
          >
            {t('generateTokenButton')}
          </button>
          
          <button
            onClick={onSkip}
            className="block mx-auto mt-4 text-gray-400 hover:text-gray-300 text-sm"
          >
            {t('skipVerification')}
          </button>
        </div>
      )}

      {step === 'verify' && token && (
        <div className="space-y-6">
          {/* Method Selection */}
          <div className="flex gap-4 justify-center">
            <button
              onClick={() => setMethod('http')}
              className={`px-6 py-3 rounded-xl border-2 transition-all ${
                method === 'http'
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                  : 'border-gray-600 text-gray-400 hover:border-gray-500'
              }`}
            >
              <span className="block font-bold">{t('httpFileMethod')}</span>
            </button>
            
            <button
              onClick={() => setMethod('dns')}
              className={`px-6 py-3 rounded-xl border-2 transition-all ${
                method === 'dns'
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                  : 'border-gray-600 text-gray-400 hover:border-gray-500'
              }`}
            >
              <span className="block font-bold">{t('dnsRecordMethod')}</span>
            </button>
          </div>

          {/* Instructions */}
          <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-700">
            {method === 'http' ? (
              <div className="space-y-4">
                <h3 className="font-bold text-lg">{t('uploadFileInfo')}:</h3>
                
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm flex-shrink-0">1</span>
                    <p className="text-gray-300">{t('targetUrl')}:</p>
                  </div>
                  
                  <div className="bg-gray-800 rounded-lg p-3 font-mono text-sm flex items-center justify-between">
                    <span className="text-green-400">{token.methods.http.path}</span>
                    <button
                      onClick={() => copyToClipboard(token.methods.http.path)}
                      className="p-1 hover:bg-gray-700 rounded"
                      title={t('copyToClipboard')}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                  
                  <div className="flex items-start gap-3">
                    <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm flex-shrink-0">2</span>
                    <p className="text-gray-300">Content:</p>
                  </div>
                  
                  <div className="bg-gray-800 rounded-lg p-3 font-mono text-sm flex items-center justify-between">
                    <span className="text-amber-400 break-all">{token.methods.http.content}</span>
                    <button
                      onClick={() => copyToClipboard(token.methods.http.content)}
                      className="p-1 hover:bg-gray-700 rounded flex-shrink-0"
                      title={t('copyToClipboard')}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <h3 className="font-bold text-lg">{t('addDnsRecordInfo')}:</h3>
                
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-sm flex-shrink-0">1</span>
                    <p className="text-gray-300">TXT Record:</p>
                  </div>
                  
                  <div className="bg-gray-800 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Type:</span>
                      <span className="text-green-400 font-mono">TXT</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Name:</span>
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-400 font-mono text-sm">{token.methods.dns.name}</span>
                        <button
                          onClick={() => copyToClipboard(token.methods.dns.name)}
                          className="p-1 hover:bg-gray-700 rounded"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Value:</span>
                      <div className="flex items-center gap-2">
                        <span className="text-amber-400 font-mono text-sm break-all">{token.methods.dns.value}</span>
                        <button
                          onClick={() => copyToClipboard(token.methods.dns.value)}
                          className="p-1 hover:bg-gray-700 rounded"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-amber-400 text-sm">
                    ⚠️ DNS propagation may take up to 48 hours
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Verification Result */}
          <AnimatePresence>
            {verificationResult && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className={`rounded-xl p-4 border ${
                  verificationResult.verified
                    ? 'bg-green-500/10 border-green-500/30'
                    : 'bg-red-500/10 border-red-500/30'
                }`}
              >
                <div className="flex items-center gap-3">
                  {verificationResult.verified ? (
                    <>
                      <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-green-400 font-bold">{t('verificationSuccess')} ✓</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-red-400">{t('verificationFailed')}</span>
                    </>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-4">
            <button
              onClick={() => setStep('generate')}
              className="flex-1 px-6 py-3 bg-gray-700 rounded-xl font-bold hover:bg-gray-600 transition-colors"
            >
              {t('back')}
            </button>
            
            <button
              onClick={verifyOwnership}
              disabled={verifying}
              className="flex-1 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl font-bold hover:shadow-lg hover:shadow-cyan-500/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {verifying ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  {t('verifyingOwnership')}
                </>
              ) : (
                t('verifyOwnership')
              )}
            </button>
          </div>
          
          <button
            onClick={onSkip}
            className="block mx-auto text-gray-400 hover:text-gray-300 text-sm"
          >
            {t('skipVerification')}
          </button>
        </div>
      )}
    </motion.div>
  );
}
