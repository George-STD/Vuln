import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLanguage } from '../contexts/LanguageContext';

/**
 * Enterprise Dashboard Component
 * Shows workers, integrations, audit logs, and system status
 */
const EnterpriseDashboard = ({ baseUrl = 'http://localhost:3001' }) => {
  const { t, isRTL } = useLanguage();
  const [activeTab, setActiveTab] = useState('overview');
  const [workers, setWorkers] = useState([]);
  const [queueStatus, setQueueStatus] = useState({});
  const [integrations, setIntegrations] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [plugins, setPlugins] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch enterprise data
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      
      // Fetch workers
      const workersRes = await fetch(`${baseUrl}/api/enterprise/workers`);
      if (workersRes.ok) {
        const data = await workersRes.json();
        setWorkers(data.workers || []);
        setQueueStatus(data.queueStatus || {});
      }

      // Fetch plugins
      const pluginsRes = await fetch(`${baseUrl}/api/enterprise/plugins`);
      if (pluginsRes.ok) {
        const data = await pluginsRes.json();
        setPlugins(data.plugins || []);
      }

      setError(null);
    } catch (err) {
      setError(t('failedLoadData'));
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'overview', label: t('overview'), icon: '📊' },
    { id: 'workers', label: t('workers'), icon: '⚙️' },
    { id: 'integrations', label: t('integrations'), icon: '🔗' },
    { id: 'audit', label: t('auditLog'), icon: '📝' },
    { id: 'credentials', label: t('credentialVault'), icon: '🔐' },
    { id: 'plugins', label: t('plugins'), icon: '🧩' },
  ];

  const getStatusColor = (status) => {
    switch (status) {
      case 'idle': return 'bg-green-500';
      case 'busy': return 'bg-yellow-500';
      case 'offline': return 'bg-red-500';
      case 'enabled': return 'bg-green-500';
      case 'disabled': return 'bg-gray-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusText = (status) => {
    const statusMap = {
      idle: t('available'),
      busy: t('busy'),
      offline: t('offline'),
      enabled: t('enabled'),
      disabled: t('disabled'),
      error: t('error'),
      installed: t('installed')
    };
    return statusMap[status] || status;
  };

  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-xl" dir={isRTL ? 'rtl' : 'ltr'}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <span className="text-3xl">🏢</span>
          <div>
            <h2 className="text-2xl font-bold text-white">{t('enterpriseDashboard')}</h2>
            <p className="text-gray-400 text-sm">{t('manageWorkersIntegrations')}</p>
          </div>
        </div>
        <button
          onClick={fetchData}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white flex items-center gap-2"
        >
          <span>🔄</span>
          {t('refresh')}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 rounded-lg flex items-center gap-2 whitespace-nowrap transition-all ${
              activeTab === tab.id
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-500 rounded-lg p-4 mb-6">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent"></div>
        </div>
      )}

      {/* Content */}
      {!loading && (
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
          >
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Workers Stats */}
                <div className="bg-gray-700/50 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-2xl">⚙️</span>
                    <h3 className="text-lg font-semibold text-white">{t('workers')}</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('total')}</span>
                      <span className="text-white font-bold">{queueStatus.workers?.total || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('available')}</span>
                      <span className="text-green-400 font-bold">{queueStatus.workers?.available || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('busy')}</span>
                      <span className="text-yellow-400 font-bold">{queueStatus.workers?.busy || 0}</span>
                    </div>
                  </div>
                </div>

                {/* Queue Stats */}
                <div className="bg-gray-700/50 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-2xl">📋</span>
                    <h3 className="text-lg font-semibold text-white">{t('queue')}</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('pending')}</span>
                      <span className="text-white font-bold">{queueStatus.pending || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('active')}</span>
                      <span className="text-blue-400 font-bold">{queueStatus.active || 0}</span>
                    </div>
                  </div>
                </div>

                {/* Plugins Stats */}
                <div className="bg-gray-700/50 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-2xl">🧩</span>
                    <h3 className="text-lg font-semibold text-white">{t('plugins')}</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('installed')}</span>
                      <span className="text-white font-bold">{plugins.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">{t('enabled')}</span>
                      <span className="text-green-400 font-bold">
                        {plugins.filter(p => p.status === 'enabled').length}
                      </span>
                    </div>
                  </div>
                </div>

                {/* System Status */}
                <div className="bg-gray-700/50 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-2xl">💚</span>
                    <h3 className="text-lg font-semibold text-white">{t('systemStatus')}</h3>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400">Server</span>
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                        <span className="text-green-400">{t('connected')}</span>
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400">WebSocket</span>
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                        <span className="text-green-400">{t('connected')}</span>
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Workers Tab */}
            {activeTab === 'workers' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold text-white">{t('distributedWorkers')}</h3>
                  <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white flex items-center gap-2">
                    <span>➕</span>
                    {t('addWorker')}
                  </button>
                </div>

                {workers.length === 0 ? (
                  <div className="bg-gray-700/30 rounded-xl p-8 text-center">
                    <span className="text-4xl mb-4 block">⚙️</span>
                    <p className="text-gray-400">{t('noWorkersRegistered')}</p>
                  </div>
                ) : (
                  <div className="grid gap-4">
                    {workers.map((worker) => (
                      <div
                        key={worker.id}
                        className="bg-gray-700/50 rounded-xl p-4 flex items-center justify-between"
                      >
                        <div className="flex items-center gap-4">
                          <div className={`w-3 h-3 rounded-full ${getStatusColor(worker.status)}`}></div>
                          <div>
                            <h4 className="text-white font-semibold">{worker.name}</h4>
                            <p className="text-gray-400 text-sm">{worker.host}:{worker.port}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-6">
                          <div className="text-center">
                            <p className="text-gray-400 text-sm">الفحوصات الحالية</p>
                            <p className="text-white font-bold">{worker.currentScans} / {worker.maxConcurrentScans}</p>
                          </div>
                          <div className="text-center">
                            <p className="text-gray-400 text-sm">المكتملة</p>
                            <p className="text-white font-bold">{worker.totalScansCompleted}</p>
                          </div>
                          <span className={`px-3 py-1 rounded-full text-sm ${getStatusColor(worker.status)} text-white`}>
                            {getStatusText(worker.status)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Integrations Tab */}
            {activeTab === 'integrations' && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-white">{t('externalIntegrations')}</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Jira */}
                  <div className="bg-gray-700/50 rounded-xl p-4">
                    <div className="flex items-center gap-3 mb-4">
                      <img src="https://cdn.worldvectorlogo.com/logos/jira-1.svg" alt="Jira" className="w-8 h-8" />
                      <h4 className="text-white font-semibold">Jira</h4>
                    </div>
                    <p className="text-gray-400 text-sm mb-4">{t('jiraIntegration')}</p>
                    <button className="w-full py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white">
                      {t('configure')}
                    </button>
                  </div>

                  {/* GitHub */}
                  <div className="bg-gray-700/50 rounded-xl p-4">
                    <div className="flex items-center gap-3 mb-4">
                      <span className="text-3xl">🐙</span>
                      <h4 className="text-white font-semibold">GitHub</h4>
                    </div>
                    <p className="text-gray-400 text-sm mb-4">{t('githubIntegration')}</p>
                    <button className="w-full py-2 bg-gray-600 hover:bg-gray-500 rounded-lg text-white">
                      {t('configure')}
                    </button>
                  </div>

                  {/* Slack */}
                  <div className="bg-gray-700/50 rounded-xl p-4">
                    <div className="flex items-center gap-3 mb-4">
                      <span className="text-3xl">💬</span>
                      <h4 className="text-white font-semibold">Slack</h4>
                    </div>
                    <p className="text-gray-400 text-sm mb-4">{t('slackIntegration')}</p>
                    <button className="w-full py-2 bg-gray-600 hover:bg-gray-500 rounded-lg text-white">
                      {t('configure')}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Audit Log Tab */}
            {activeTab === 'audit' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold text-white">{t('auditLogTitle')}</h3>
                  <button className="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded-lg text-white flex items-center gap-2">
                    <span>📥</span>
                    {t('exportReport')}
                  </button>
                </div>

                <div className="bg-gray-700/30 rounded-xl p-8 text-center">
                  <span className="text-4xl mb-4 block">📝</span>
                  <p className="text-gray-400">{t('noAuditLogs')}</p>
                </div>
              </div>
            )}

            {/* Credentials Tab */}
            {activeTab === 'credentials' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold text-white">{t('credentialVaultTitle')}</h3>
                  <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white flex items-center gap-2">
                    <span>➕</span>
                    {t('addCredential')}
                  </button>
                </div>

                <div className="bg-gray-700/30 rounded-xl p-8 text-center">
                  <span className="text-4xl mb-4 block">🔐</span>
                  <p className="text-gray-400">{t('noCredentials')}</p>
                </div>
              </div>
            )}

            {/* Plugins Tab */}
            {activeTab === 'plugins' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold text-white">{t('pluginsTitle')}</h3>
                  <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white flex items-center gap-2">
                    <span>➕</span>
                    {t('installPlugin')}
                  </button>
                </div>

                {plugins.length === 0 ? (
                  <div className="bg-gray-700/30 rounded-xl p-8 text-center">
                    <span className="text-4xl mb-4 block">🧩</span>
                    <p className="text-gray-400">{t('noPlugins')}</p>
                  </div>
                ) : (
                  <div className="grid gap-4">
                    {plugins.map((plugin) => (
                      <div
                        key={plugin.id}
                        className="bg-gray-700/50 rounded-xl p-4 flex items-center justify-between"
                      >
                        <div className="flex items-center gap-4">
                          <span className="text-3xl">🧩</span>
                          <div>
                            <h4 className="text-white font-semibold">{plugin.name}</h4>
                            <p className="text-gray-400 text-sm">{plugin.description}</p>
                            <p className="text-gray-500 text-xs">الإصدار {plugin.version} • {plugin.type}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <span className={`px-3 py-1 rounded-full text-sm ${getStatusColor(plugin.status)} text-white`}>
                            {getStatusText(plugin.status)}
                          </span>
                          <button className="p-2 hover:bg-gray-600 rounded-lg">
                            <span>⚙️</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
};

export default EnterpriseDashboard;
