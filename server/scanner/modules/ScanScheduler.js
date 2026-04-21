import cron from 'node-cron';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';
import { VulnerabilityScanner } from '../VulnerabilityScanner.js';
import { createScanLogger } from '../../utils/Logger.js';

export class ScanScheduler {
  constructor(options = {}) {
    this.options = {
      dataDir: options.dataDir || path.join(process.cwd(), 'data', 'schedules'),
      ...options
    };
    
    this.scheduledJobs = new Map();
    this.jobHistory = new Map();
    this.io = options.io; // Socket.IO instance
    this.logger = createScanLogger('scheduler');
  }

  /**
   * Initialize scheduler - load saved schedules
   */
  async initialize() {
    try {
      await fs.mkdir(this.options.dataDir, { recursive: true });
      await this.loadSavedSchedules();
      this.logger.info('Scan scheduler initialized');
    } catch (error) {
      this.logger.error(`Failed to initialize scheduler: ${error.message}`);
    }
  }

  /**
   * Create a new scheduled scan
   */
  async createSchedule(config) {
    const schedule = {
      id: uuidv4(),
      name: config.name || `Scheduled Scan - ${new Date().toLocaleDateString('ar-EG')}`,
      targetUrl: config.targetUrl,
      cronExpression: config.cronExpression,
      scanOptions: config.scanOptions || {},
      enabled: config.enabled !== false,
      createdAt: new Date().toISOString(),
      lastRun: null,
      nextRun: null,
      runCount: 0,
      notifyEmail: config.notifyEmail || null,
      notifyWebhook: config.notifyWebhook || null,
      maxRuns: config.maxRuns || null, // null = unlimited
      retainResults: config.retainResults || 10 // Keep last N results
    };

    // Validate cron expression
    if (!cron.validate(schedule.cronExpression)) {
      throw new Error('Invalid cron expression');
    }

    // Calculate next run time
    schedule.nextRun = this.getNextRunTime(schedule.cronExpression);

    // Start the job if enabled
    if (schedule.enabled) {
      this.startJob(schedule);
    }

    // Save to file
    await this.saveSchedule(schedule);

    this.logger.info(`Created schedule: ${schedule.id} for ${schedule.targetUrl}`);
    
    return schedule;
  }

  /**
   * Start a scheduled job
   */
  startJob(schedule) {
    if (this.scheduledJobs.has(schedule.id)) {
      this.scheduledJobs.get(schedule.id).stop();
    }

    const job = cron.schedule(schedule.cronExpression, async () => {
      await this.executeScheduledScan(schedule);
    }, {
      scheduled: true,
      timezone: 'Africa/Cairo' // Egypt timezone
    });

    this.scheduledJobs.set(schedule.id, job);
    
    this.logger.info(`Started job: ${schedule.id}`);
  }

  /**
   * Execute a scheduled scan
   */
  async executeScheduledScan(schedule) {
    const scanId = uuidv4();
    const logger = createScanLogger(scanId);
    
    logger.info(`Executing scheduled scan: ${schedule.name}`);

    try {
      // Check if max runs reached
      if (schedule.maxRuns && schedule.runCount >= schedule.maxRuns) {
        logger.info(`Max runs (${schedule.maxRuns}) reached for schedule ${schedule.id}`);
        await this.disableSchedule(schedule.id);
        return;
      }

      // Create scanner and run
      const scanner = new VulnerabilityScanner(schedule.scanOptions);
      
      // Emit start event
      if (this.io) {
        this.io.emit('scheduled:start', {
          scheduleId: schedule.id,
          scanId,
          targetUrl: schedule.targetUrl
        });
      }

      const results = await scanner.scan(schedule.targetUrl, scanId, {
        onProgress: (progress) => {
          if (this.io) {
            this.io.emit('scheduled:progress', {
              scheduleId: schedule.id,
              scanId,
              progress
            });
          }
        },
        onVulnerability: (vuln) => {
          if (this.io) {
            this.io.emit('scheduled:vulnerability', {
              scheduleId: schedule.id,
              scanId,
              vulnerability: vuln
            });
          }
        }
      });

      // Update schedule info
      schedule.lastRun = new Date().toISOString();
      schedule.nextRun = this.getNextRunTime(schedule.cronExpression);
      schedule.runCount++;

      // Save result to history
      await this.saveJobResult(schedule.id, scanId, results);

      // Save updated schedule
      await this.saveSchedule(schedule);

      // Send notifications
      await this.sendNotifications(schedule, results);

      // Emit complete event
      if (this.io) {
        this.io.emit('scheduled:complete', {
          scheduleId: schedule.id,
          scanId,
          summary: results.summary
        });
      }

      logger.info(`Scheduled scan complete: ${results.summary.total} vulnerabilities found`);

    } catch (error) {
      logger.error(`Scheduled scan failed: ${error.message}`);
      
      if (this.io) {
        this.io.emit('scheduled:error', {
          scheduleId: schedule.id,
          scanId,
          error: error.message
        });
      }
    }
  }

  /**
   * Send notifications for completed scan
   */
  async sendNotifications(schedule, results) {
    const { summary, vulnerabilities } = results;
    
    // Only notify if vulnerabilities found
    if (summary.total === 0) return;

    // Webhook notification
    if (schedule.notifyWebhook) {
      try {
        await fetch(schedule.notifyWebhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'scan_complete',
            schedule: {
              id: schedule.id,
              name: schedule.name,
              targetUrl: schedule.targetUrl
            },
            summary,
            criticalVulnerabilities: vulnerabilities.filter(v => v.severity === 'critical'),
            highVulnerabilities: vulnerabilities.filter(v => v.severity === 'high')
          })
        });
      } catch (error) {
        this.logger.error(`Webhook notification failed: ${error.message}`);
      }
    }

    // Email notification would go here (requires email service setup)
    // For now, just log
    if (schedule.notifyEmail) {
      this.logger.info(`Would send email to ${schedule.notifyEmail} with scan results`);
    }
  }

  /**
   * Get all schedules
   */
  async getSchedules() {
    const schedules = [];
    
    try {
      const files = await fs.readdir(this.options.dataDir);
      
      for (const file of files) {
        if (file.endsWith('.json') && !file.includes('_history')) {
          const content = await fs.readFile(
            path.join(this.options.dataDir, file),
            'utf-8'
          );
          schedules.push(JSON.parse(content));
        }
      }
    } catch (error) {
      this.logger.error(`Failed to get schedules: ${error.message}`);
    }

    return schedules;
  }

  /**
   * Get schedule by ID
   */
  async getSchedule(scheduleId) {
    try {
      const content = await fs.readFile(
        path.join(this.options.dataDir, `${scheduleId}.json`),
        'utf-8'
      );
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  /**
   * Update schedule
   */
  async updateSchedule(scheduleId, updates) {
    const schedule = await this.getSchedule(scheduleId);
    
    if (!schedule) {
      throw new Error('Schedule not found');
    }

    // Update fields
    Object.assign(schedule, updates, { updatedAt: new Date().toISOString() });

    // Validate cron if changed
    if (updates.cronExpression && !cron.validate(updates.cronExpression)) {
      throw new Error('Invalid cron expression');
    }

    // Restart job if cron or enabled changed
    if (updates.cronExpression || updates.enabled !== undefined) {
      if (this.scheduledJobs.has(scheduleId)) {
        this.scheduledJobs.get(scheduleId).stop();
        this.scheduledJobs.delete(scheduleId);
      }

      if (schedule.enabled) {
        schedule.nextRun = this.getNextRunTime(schedule.cronExpression);
        this.startJob(schedule);
      }
    }

    await this.saveSchedule(schedule);
    
    return schedule;
  }

  /**
   * Delete schedule
   */
  async deleteSchedule(scheduleId) {
    // Stop job
    if (this.scheduledJobs.has(scheduleId)) {
      this.scheduledJobs.get(scheduleId).stop();
      this.scheduledJobs.delete(scheduleId);
    }

    // Delete files
    try {
      await fs.unlink(path.join(this.options.dataDir, `${scheduleId}.json`));
      await fs.unlink(path.join(this.options.dataDir, `${scheduleId}_history.json`));
    } catch (error) {
      // Ignore if files don't exist
    }

    this.logger.info(`Deleted schedule: ${scheduleId}`);
  }

  /**
   * Enable/disable schedule
   */
  async toggleSchedule(scheduleId, enabled) {
    return this.updateSchedule(scheduleId, { enabled });
  }

  /**
   * Disable schedule
   */
  async disableSchedule(scheduleId) {
    return this.toggleSchedule(scheduleId, false);
  }

  /**
   * Run schedule immediately
   */
  async runNow(scheduleId) {
    const schedule = await this.getSchedule(scheduleId);
    
    if (!schedule) {
      throw new Error('Schedule not found');
    }

    await this.executeScheduledScan(schedule);
  }

  /**
   * Get job history
   */
  async getJobHistory(scheduleId, limit = 10) {
    try {
      const content = await fs.readFile(
        path.join(this.options.dataDir, `${scheduleId}_history.json`),
        'utf-8'
      );
      const history = JSON.parse(content);
      return history.slice(-limit);
    } catch (error) {
      return [];
    }
  }

  /**
   * Save job result to history
   */
  async saveJobResult(scheduleId, scanId, results) {
    const historyPath = path.join(this.options.dataDir, `${scheduleId}_history.json`);
    let history = [];

    try {
      const content = await fs.readFile(historyPath, 'utf-8');
      history = JSON.parse(content);
    } catch (error) {
      // Start fresh
    }

    // Add new result
    history.push({
      scanId,
      timestamp: new Date().toISOString(),
      summary: results.summary,
      vulnerabilityCount: results.vulnerabilities?.length || 0
    });

    // Get schedule to check retain limit
    const schedule = await this.getSchedule(scheduleId);
    const retainCount = schedule?.retainResults || 10;

    // Trim to retain limit
    if (history.length > retainCount) {
      history = history.slice(-retainCount);
    }

    await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
  }

  /**
   * Save schedule to file
   */
  async saveSchedule(schedule) {
    const filePath = path.join(this.options.dataDir, `${schedule.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(schedule, null, 2));
  }

  /**
   * Load saved schedules on startup
   */
  async loadSavedSchedules() {
    const schedules = await this.getSchedules();
    
    for (const schedule of schedules) {
      if (schedule.enabled) {
        schedule.nextRun = this.getNextRunTime(schedule.cronExpression);
        this.startJob(schedule);
      }
    }

    this.logger.info(`Loaded ${schedules.length} saved schedules`);
  }

  /**
   * Get next run time from cron expression
   */
  getNextRunTime(cronExpression) {
    const interval = cron.schedule(cronExpression, () => {}, { scheduled: false });
    
    // Parse cron parts
    const parts = cronExpression.split(' ');
    const now = new Date();
    
    // Simple approximation - proper cron parsing would be more complex
    // This returns when the next occurrence would be
    const next = new Date(now);
    
    // Move to next minute at minimum
    next.setSeconds(0);
    next.setMilliseconds(0);
    next.setMinutes(next.getMinutes() + 1);

    return next.toISOString();
  }

  /**
   * Get common cron presets
   */
  static getCronPresets() {
    return {
      'every-hour': {
        expression: '0 * * * *',
        label: 'كل ساعة',
        description: 'يعمل في بداية كل ساعة'
      },
      'every-6-hours': {
        expression: '0 */6 * * *',
        label: 'كل 6 ساعات',
        description: 'يعمل كل 6 ساعات'
      },
      'daily': {
        expression: '0 0 * * *',
        label: 'يومياً',
        description: 'يعمل يومياً عند منتصف الليل'
      },
      'daily-morning': {
        expression: '0 8 * * *',
        label: 'يومياً صباحاً',
        description: 'يعمل يومياً الساعة 8 صباحاً'
      },
      'weekly': {
        expression: '0 0 * * 0',
        label: 'أسبوعياً',
        description: 'يعمل كل يوم أحد عند منتصف الليل'
      },
      'monthly': {
        expression: '0 0 1 * *',
        label: 'شهرياً',
        description: 'يعمل في أول يوم من كل شهر'
      }
    };
  }

  /**
   * Shutdown scheduler
   */
  shutdown() {
    for (const [id, job] of this.scheduledJobs) {
      job.stop();
      this.logger.info(`Stopped job: ${id}`);
    }
    this.scheduledJobs.clear();
  }
}

export default ScanScheduler;
