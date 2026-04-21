import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLanguage } from '../contexts/LanguageContext';

const getCronPresets = (t) => ({
  'every-hour': { expression: '0 * * * *', label: t('everyHour') },
  'every-6-hours': { expression: '0 */6 * * *', label: t('every6Hours') },
  'daily': { expression: '0 0 * * *', label: t('dailyMidnight') },
  'daily-morning': { expression: '0 8 * * *', label: t('daily8AM') },
  'weekly': { expression: '0 0 * * 0', label: t('weeklySunday') },
  'monthly': { expression: '0 0 1 * *', label: t('monthly') }
});

export default function ScheduledScans({ onBack }) {
  const { t, isRTL } = useLanguage();
  const CRON_PRESETS = getCronPresets(t);
  
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedSchedule, setSelectedSchedule] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    targetUrl: '',
    cronPreset: 'daily',
    cronExpression: '0 0 * * *',
    enabled: true,
    notifyWebhook: ''
  });

  useEffect(() => {
    fetchSchedules();
  }, []);

  const fetchSchedules = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/schedules');
      const data = await response.json();
      setSchedules(data);
    } catch (error) {
      console.error('Error fetching schedules:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      const method = selectedSchedule ? 'PUT' : 'POST';
      const url = selectedSchedule 
        ? `http://localhost:3001/api/schedules/${selectedSchedule.id}`
        : 'http://localhost:3001/api/schedules';

      await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          cronExpression: CRON_PRESETS[formData.cronPreset]?.expression || formData.cronExpression
        })
      });

      setShowModal(false);
      setSelectedSchedule(null);
      resetForm();
      fetchSchedules();
    } catch (error) {
      console.error('Error saving schedule:', error);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm(t('confirmDeleteSchedule'))) return;
    
    try {
      await fetch(`http://localhost:3001/api/schedules/${id}`, { method: 'DELETE' });
      fetchSchedules();
    } catch (error) {
      console.error('Error deleting schedule:', error);
    }
  };

  const handleToggle = async (id, enabled) => {
    try {
      await fetch(`http://localhost:3001/api/schedules/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled })
      });
      fetchSchedules();
    } catch (error) {
      console.error('Error toggling schedule:', error);
    }
  };

  const handleRunNow = async (id) => {
    try {
      await fetch(`http://localhost:3001/api/schedules/${id}/run`, { method: 'POST' });
      alert(t('scanStarted'));
    } catch (error) {
      console.error('Error running schedule:', error);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      targetUrl: '',
      cronPreset: 'daily',
      cronExpression: '0 0 * * *',
      enabled: true,
      notifyWebhook: ''
    });
  };

  const openEditModal = (schedule) => {
    setSelectedSchedule(schedule);
    setFormData({
      name: schedule.name,
      targetUrl: schedule.targetUrl,
      cronPreset: Object.keys(CRON_PRESETS).find(
        key => CRON_PRESETS[key].expression === schedule.cronExpression
      ) || 'custom',
      cronExpression: schedule.cronExpression,
      enabled: schedule.enabled,
      notifyWebhook: schedule.notifyWebhook || ''
    });
    setShowModal(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onBack}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <h2 className="text-2xl font-bold">{t('scheduledScans')}</h2>
        </div>
        
        <button
          onClick={() => { resetForm(); setSelectedSchedule(null); setShowModal(true); }}
          className="px-4 py-2 bg-gradient-to-r from-green-500 to-emerald-600 rounded-lg font-bold hover:shadow-lg hover:shadow-green-500/25 transition-all"
        >
          + {t('addNewSchedule')}
        </button>
      </div>

      {/* Schedules List */}
      {loading ? (
        <div className="text-center py-12">
          <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-400">{t('loading')}</p>
        </div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-12 bg-gray-800/50 rounded-xl border border-gray-700">
          <svg className="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="text-xl font-bold text-gray-400">{t('noScheduledScans')}</h3>
        </div>
      ) : (
        <div className="grid gap-4">
          {schedules.map((schedule) => (
            <motion.div
              key={schedule.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-gray-800/50 rounded-xl border border-gray-700 p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <h3 className="font-bold text-lg">{schedule.name}</h3>
                    <span className={`px-2 py-0.5 rounded-full text-xs ${
                      schedule.enabled 
                        ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                        : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                    }`}>
                      {schedule.enabled ? t('active') : t('disabled')}
                    </span>
                  </div>
                  
                  <a 
                    href={schedule.targetUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline text-sm mt-1 block"
                  >
                    {schedule.targetUrl}
                  </a>
                  
                  <div className="flex items-center gap-6 mt-4 text-sm text-gray-400">
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span>{CRON_PRESETS[Object.keys(CRON_PRESETS).find(
                        key => CRON_PRESETS[key].expression === schedule.cronExpression
                      )]?.label || schedule.cronExpression}</span>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                      </svg>
                      <span>{schedule.runCount} تشغيل</span>
                    </div>
                    
                    {schedule.lastRun && (
                      <div className="flex items-center gap-2">
                        <span>{t('lastRun')}: {new Date(schedule.lastRun).toLocaleDateString(isRTL ? 'ar-EG' : 'en-US')}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRunNow(schedule.id)}
                    className="p-2 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors"
                    title={t('runNow')}
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </button>
                  
                  <button
                    onClick={() => handleToggle(schedule.id, schedule.enabled)}
                    className={`p-2 rounded-lg transition-colors ${
                      schedule.enabled
                        ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30'
                        : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                    }`}
                    title={schedule.enabled ? t('stop') : t('enable')}
                  >
                    {schedule.enabled ? (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    ) : (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    )}
                  </button>
                  
                  <button
                    onClick={() => openEditModal(schedule)}
                    className="p-2 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition-colors"
                    title={t('edit')}
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                    </svg>
                  </button>
                  
                  <button
                    onClick={() => handleDelete(schedule.id)}
                    className="p-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors"
                    title={t('delete')}
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Modal */}
      <AnimatePresence>
        {showModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-xl font-bold mb-6">
                {selectedSchedule ? t('editSchedule') : t('addNewSchedule')}
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    {t('scheduleName')}
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                    placeholder="Main Site Scan"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    {t('targetUrl')}
                  </label>
                  <input
                    type="url"
                    value={formData.targetUrl}
                    onChange={(e) => setFormData({ ...formData, targetUrl: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                    placeholder="https://example.com"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    {t('runTiming')}
                  </label>
                  <select
                    value={formData.cronPreset}
                    onChange={(e) => setFormData({ 
                      ...formData, 
                      cronPreset: e.target.value,
                      cronExpression: CRON_PRESETS[e.target.value]?.expression || formData.cronExpression
                    })}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                  >
                    {Object.entries(CRON_PRESETS).map(([key, { label }]) => (
                      <option key={key} value={key}>{label}</option>
                    ))}
                    <option value="custom">{t('customCron')}</option>
                  </select>
                  
                  {formData.cronPreset === 'custom' && (
                    <input
                      type="text"
                      value={formData.cronExpression}
                      onChange={(e) => setFormData({ ...formData, cronExpression: e.target.value })}
                      className="w-full mt-2 px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                      placeholder="*/30 * * * *"
                    />
                  )}
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Webhook ({t('profiles')})
                  </label>
                  <input
                    type="url"
                    value={formData.notifyWebhook}
                    onChange={(e) => setFormData({ ...formData, notifyWebhook: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                    placeholder="https://hooks.slack.com/..."
                  />
                </div>
                
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    id="enabled"
                    checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                    className="w-5 h-5 rounded bg-gray-700 border-gray-600 text-cyan-500 focus:ring-cyan-500"
                  />
                  <label htmlFor="enabled" className="text-gray-300">{t('enableSchedule')}</label>
                </div>
                
                <div className="flex gap-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="flex-1 px-4 py-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
                  >
                    {t('cancel')}
                  </button>
                  <button
                    type="submit"
                    className="flex-1 px-4 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-bold hover:shadow-lg hover:shadow-cyan-500/25 transition-all"
                  >
                    {selectedSchedule ? t('saveChanges') : t('createSchedule')}
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
