import learningEngine from './LearningEngine.js';
import fs from 'fs/promises';
import path from 'path';

export class WriteupAutoLearner {
  constructor(options = {}) {
    this.learningEngine = options.learningEngine || learningEngine;
    this.intervalMs = Math.max(15000, Number(options.intervalMs || 60000));
    this.discoveryIntervalMs = Math.max(
      this.intervalMs,
      Number(options.discoveryIntervalMs || 10 * 60 * 1000)
    );
    this.maxRulesPerLink = Math.max(1, Math.min(8, Number(options.maxRulesPerLink || 4)));
    this.maxPerSource = Math.max(1, Math.min(80, Number(options.maxPerSource || 40)));
    this.sources = Array.isArray(options.sources) ? options.sources : undefined;
    this.onLog = options.onLog;
    this.enabled = options.enabled !== false;
    this.stateFile = options.stateFile || 'auto-learner-state.json';

    this.timer = null;
    this.runningTick = false;
    this.queue = [];
    this.lastDiscoveryAt = null;
    this.retryState = {};
    this.sourceStats = {};
    this.stateLoaded = false;
    this.status = {
      enabled: this.enabled,
      running: false,
      paused: false,
      pausedAt: null,
      intervalMs: this.intervalMs,
      discoveryIntervalMs: this.discoveryIntervalMs,
      ticks: 0,
      learnedWriteups: 0,
      importedRules: 0,
      queueSize: 0,
      skippedDueCooldown: 0,
      lastRunAt: null,
      lastLearnedAt: null,
      lastLearnedUrl: null,
      lastError: null,
      restoredFromStateAt: null
    };
  }

  get statePath() {
    const dataDir = this.learningEngine?.options?.dataDir || path.join(process.cwd(), 'data', 'learning');
    return path.join(dataDir, this.stateFile);
  }

  log(message, type = 'info') {
    if (this.onLog) {
      this.onLog({
        message: `[Writeup Auto Learner] ${message}`,
        type,
        timestamp: new Date().toISOString()
      });
      return;
    }

    if (type === 'error') {
      console.error(`[Writeup Auto Learner] ${message}`);
    } else if (type === 'warn') {
      console.warn(`[Writeup Auto Learner] ${message}`);
    } else {
      console.log(`[Writeup Auto Learner] ${message}`);
    }
  }

  getStatus() {
    return {
      ...this.status,
      queueSize: this.queue.length
    };
  }

  async start(options = {}) {
    if (this.timer) {
      return this.getStatus();
    }

    const force = options.force === true;

    if (!this.enabled && !force) {
      this.log('Auto learner is disabled by configuration.', 'warn');
      return this.getStatus();
    }

    await this.learningEngine.initialize();
    await this.ensureStateLoaded();

    if (this.status.paused && !force) {
      this.log('Auto learner remains paused from saved state.', 'info');
      return this.getStatus();
    }

    this.status.running = true;
    this.status.paused = false;
    this.status.pausedAt = null;
    this.status.lastError = null;
    this.timer = setInterval(() => {
      this.tick().catch((error) => {
        this.status.lastError = error.message;
        this.log(`Tick failed: ${error.message}`, 'error');
      });
    }, this.intervalMs);

    // Kick off immediately so the first write-up is learned without waiting.
    if (options.skipImmediateTick !== true) {
      try {
        await this.tick();
      } catch (error) {
        this.status.lastError = error.message;
        this.log(`Initial auto-learning tick failed: ${error.message}`, 'warn');
      }
    }

    await this.persistState();
    this.log(`Started auto learner (every ${Math.round(this.intervalMs / 1000)}s).`, 'info');
    return this.getStatus();
  }

  async stop(options = {}) {
    const pause = options.pause !== false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    this.status.running = false;
    this.status.paused = pause;
    this.status.pausedAt = pause ? new Date().toISOString() : null;
    await this.persistState();
    this.log('Stopped auto learner.', 'info');
    return this.getStatus();
  }

  async tick() {
    if (this.runningTick) {
      return this.getStatus();
    }

    this.runningTick = true;
    this.status.ticks += 1;
    this.status.lastRunAt = new Date().toISOString();

    try {
      await this.learningEngine.initialize();
      await this.ensureStateLoaded();
      await this.rebuildQueueIfNeeded();

      const nextUrl = this.dequeueNextEligibleUrl();
      this.status.queueSize = this.queue.length;
      this.status.skippedDueCooldown = this.getQueuedCooldownCount();

      if (!nextUrl) {
        this.log('No new write-up candidates found for this tick.', 'debug');
        await this.persistState();
        return this.getStatus();
      }

      const result = await this.learningEngine.importWriteupLinks({
        links: [nextUrl],
        maxLinks: 1,
        skipKnown: true,
        options: {
          maxRulesPerLink: this.maxRulesPerLink
        }
      });
      const sourceHost = this.extractHost(nextUrl);

      if (Array.isArray(result.failures) && result.failures.length > 0) {
        const error = result.failures[0]?.error || 'Import failed';
        this.registerRetryFailure(nextUrl, error);
        if (sourceHost) {
          this.updateSourceStats(sourceHost, false);
        }
        this.queue.push(nextUrl);
        this.queue = this.prioritizeQueue(this.queue);
        this.status.lastError = error;
        this.log(`Write-up failed and queued for retry: ${nextUrl} (${error})`, 'warn');
      } else {
        this.clearRetryFailure(nextUrl);
        if (sourceHost) {
          this.updateSourceStats(sourceHost, true);
        }
      }

      if (result.imported > 0 && (!result.failures || result.failures.length === 0)) {
        this.status.learnedWriteups += 1;
        this.status.importedRules += result.imported;
        this.status.lastLearnedAt = new Date().toISOString();
        this.status.lastLearnedUrl = nextUrl;
        this.log(`Learned write-up: ${nextUrl} (imported rules: ${result.imported})`, 'info');
      } else if (!result.failures || result.failures.length === 0) {
        this.log(`Skipped write-up (already known/no new rules): ${nextUrl}`, 'debug');
      }

      if (!result.failures || result.failures.length === 0) {
        this.status.lastError = null;
      }
      this.status.queueSize = this.queue.length;
      this.status.skippedDueCooldown = this.getQueuedCooldownCount();
      await this.persistState();
      return this.getStatus();
    } catch (error) {
      this.status.lastError = error.message;
      this.log(`Auto-learning tick failed: ${error.message}`, 'error');
      await this.persistState();
      throw error;
    } finally {
      this.runningTick = false;
    }
  }

  async rebuildQueueIfNeeded() {
    const now = Date.now();
    const shouldRefresh = this.queue.length === 0 ||
      !this.lastDiscoveryAt ||
      (now - this.lastDiscoveryAt) >= this.discoveryIntervalMs;

    if (!shouldRefresh) {
      return;
    }

    const knownUrls = new Set(this.learningEngine.getKnownWriteupUrls());
    const discovered = await this.learningEngine.discoverWriteupLinks({
      sources: this.sources,
      maxPerSource: this.maxPerSource
    });

    if (Array.isArray(discovered.failures) && discovered.failures.length > 0) {
      this.log(`Write-up discovery had ${discovered.failures.length} source errors.`, 'warn');
      for (const failure of discovered.failures) {
        const sourceHost = this.extractHost(failure?.source);
        if (sourceHost) {
          this.updateSourceStats(sourceHost, false);
        }
      }
    }

    const queued = new Set(this.queue);
    const discoveredCandidates = (discovered.links || []).filter((url) => {
      return !knownUrls.has(url) && !queued.has(url);
    });
    this.queue = this.prioritizeQueue([...this.queue, ...discoveredCandidates]);
    this.lastDiscoveryAt = now;
    this.status.queueSize = this.queue.length;
    this.log(`Discovered ${discovered.discovered} write-up links (${this.queue.length} new).`, 'info');
    await this.persistState();
  }

  dequeueNextEligibleUrl() {
    for (let i = 0; i < this.queue.length; i += 1) {
      const candidate = this.queue[i];
      if (this.learningEngine.isWriteupInCooldown(candidate)) {
        continue;
      }
      if (this.isRetryBlocked(candidate)) {
        continue;
      }
      this.queue.splice(i, 1);
      return candidate;
    }
    return null;
  }

  isRetryBlocked(url) {
    const state = this.retryState[url];
    if (!state?.nextRetryAt) return false;
    return Date.parse(state.nextRetryAt) > Date.now();
  }

  registerRetryFailure(url, errorMessage) {
    const current = this.retryState[url] || {
      failures: 0,
      nextRetryAt: null,
      lastError: null,
      lastFailedAt: null
    };
    const failures = Number(current.failures || 0) + 1;
    const retryMs = this.intervalMs * Math.pow(2, Math.min(6, failures - 1));
    this.retryState[url] = {
      failures,
      lastError: String(errorMessage || 'Unknown error').slice(0, 1000),
      lastFailedAt: new Date().toISOString(),
      nextRetryAt: new Date(Date.now() + retryMs).toISOString()
    };
  }

  clearRetryFailure(url) {
    delete this.retryState[url];
  }

  getQueuedCooldownCount() {
    return this.queue.reduce((count, url) => {
      if (this.learningEngine.isWriteupInCooldown(url) || this.isRetryBlocked(url)) {
        return count + 1;
      }
      return count;
    }, 0);
  }

  prioritizeQueue(candidates = []) {
    const unique = Array.from(new Set(candidates));
    return unique.sort((left, right) => this.scoreUrlCandidate(right) - this.scoreUrlCandidate(left));
  }

  scoreUrlCandidate(url) {
    let score = 0;
    const value = String(url || '').toLowerCase();
    if (value.includes('/research/')) score += 4;
    if (value.includes('/writeup') || value.includes('/write-up')) score += 4;
    if (value.includes('/report/')) score += 3;
    if (value.includes('hackerone.com/reports/')) score += 3;
    if (value.includes('portswigger.net/research/')) score += 3;

    const host = this.extractHost(url);
    const stats = host ? this.sourceStats[host] : null;
    if (stats) {
      const successes = Number(stats.successes || 0);
      const failures = Number(stats.failures || 0);
      score += Math.min(5, successes);
      score -= Math.min(5, failures);
    }

    const retry = this.retryState[url];
    if (retry) {
      score -= Math.min(8, Number(retry.failures || 0) * 2);
    }

    return score;
  }

  extractHost(url) {
    try {
      return new URL(String(url || '')).hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  updateSourceStats(host, wasSuccess) {
    if (!host) return;
    const current = this.sourceStats[host] || { successes: 0, failures: 0 };
    if (wasSuccess) {
      current.successes += 1;
    } else {
      current.failures += 1;
    }
    this.sourceStats[host] = current;
  }

  async ensureStateLoaded() {
    if (this.stateLoaded) {
      return;
    }
    await this.loadState();
    this.stateLoaded = true;
  }

  async loadState() {
    const loaded = await this.readJsonOrNull(this.statePath);
    if (!loaded || typeof loaded !== 'object') {
      return;
    }

    const loadedQueue = Array.isArray(loaded.queue) ? loaded.queue : [];
    this.queue = this.prioritizeQueue(
      loadedQueue
        .map((url) => this.learningEngine.normalizeHttpUrl(url))
        .filter(Boolean)
    );

    this.lastDiscoveryAt = Number.isFinite(Number(loaded.lastDiscoveryAt))
      ? Number(loaded.lastDiscoveryAt)
      : this.lastDiscoveryAt;

    const loadedStatus = loaded.status || {};
    this.status.ticks = Number(loadedStatus.ticks || this.status.ticks);
    this.status.learnedWriteups = Number(loadedStatus.learnedWriteups || this.status.learnedWriteups);
    this.status.importedRules = Number(loadedStatus.importedRules || this.status.importedRules);
    this.status.lastRunAt = loadedStatus.lastRunAt || this.status.lastRunAt;
    this.status.lastLearnedAt = loadedStatus.lastLearnedAt || this.status.lastLearnedAt;
    this.status.lastLearnedUrl = loadedStatus.lastLearnedUrl || this.status.lastLearnedUrl;
    this.status.lastError = loadedStatus.lastError || null;
    this.status.paused = loadedStatus.paused === true;
    this.status.pausedAt = loadedStatus.pausedAt || null;
    this.status.running = false;
    this.status.restoredFromStateAt = new Date().toISOString();

    this.retryState = loaded.retryState && typeof loaded.retryState === 'object'
      ? loaded.retryState
      : {};
    this.sourceStats = loaded.sourceStats && typeof loaded.sourceStats === 'object'
      ? loaded.sourceStats
      : {};
  }

  async persistState() {
    await this.learningEngine.initialize();
    await fs.mkdir(this.learningEngine.options.dataDir, { recursive: true });
    const state = {
      updatedAt: new Date().toISOString(),
      queue: this.queue,
      lastDiscoveryAt: this.lastDiscoveryAt,
      retryState: this.retryState,
      sourceStats: this.sourceStats,
      status: {
        ticks: this.status.ticks,
        learnedWriteups: this.status.learnedWriteups,
        importedRules: this.status.importedRules,
        lastRunAt: this.status.lastRunAt,
        lastLearnedAt: this.status.lastLearnedAt,
        lastLearnedUrl: this.status.lastLearnedUrl,
        lastError: this.status.lastError,
        paused: this.status.paused,
        pausedAt: this.status.pausedAt
      }
    };

    await fs.writeFile(this.statePath, JSON.stringify(state, null, 2), 'utf-8');
  }

  async readJsonOrNull(filePath) {
    try {
      const raw = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
}

export default WriteupAutoLearner;
