import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import axios from 'axios';
import * as cheerio from 'cheerio';

const DEFAULT_FEEDBACK_STORE = {
  version: 1,
  updatedAt: null,
  fingerprints: {}
};

const DEFAULT_WRITEUP_STORE = {
  version: 1,
  updatedAt: null,
  rules: []
};

const DEFAULT_WRITEUP_HISTORY_STORE = {
  version: 1,
  updatedAt: null,
  byUrl: {},
  byFingerprint: {}
};

const DEFAULT_WRITEUP_SOURCES = [
  'https://portswigger.net/research/rss',
  'https://hackerone.com/blog.rss',
  'https://infosecwriteups.com/feed',
  'https://medium.com/feed/tag/bug-bounty',
  'https://www.intigriti.com/researchers/blog/feed'
];

export class LearningEngine {
  constructor(options = {}) {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const defaultDataDir = path.resolve(currentDir, '..', 'data', 'learning');

    this.options = {
      dataDir: options.dataDir || defaultDataDir,
      feedbackFile: options.feedbackFile || 'feedback.json',
      writeupRulesFile: options.writeupRulesFile || 'writeup-rules.json',
      writeupHistoryFile: options.writeupHistoryFile || 'writeup-history.json',
      maxNotesPerFingerprint: options.maxNotesPerFingerprint || 25,
      writeupFailureCooldownMs: Math.max(
        60_000,
        Number(options.writeupFailureCooldownMs || 30 * 60 * 1000)
      ),
      writeupHistoryLimit: Math.max(250, Number(options.writeupHistoryLimit || 5000)),
      autoCleanupWriteupRules: options.autoCleanupWriteupRules !== false,
      autoCleanupMinRuleScore: Number.isFinite(Number(options.autoCleanupMinRuleScore))
        ? Number(options.autoCleanupMinRuleScore)
        : 4,
      autoCleanupFailedHistoryRetentionDays: Math.max(
        3,
        Number(options.autoCleanupFailedHistoryRetentionDays || 14)
      ),
      writeupSources: Array.isArray(options.writeupSources) && options.writeupSources.length > 0
        ? options.writeupSources
        : DEFAULT_WRITEUP_SOURCES,
      ...options
    };

    this.feedbackStore = { ...DEFAULT_FEEDBACK_STORE };
    this.writeupStore = { ...DEFAULT_WRITEUP_STORE };
    this.writeupHistoryStore = { ...DEFAULT_WRITEUP_HISTORY_STORE };
    this.initialized = false;
    this.legacyStoresMerged = false;
  }

  get feedbackPath() {
    return path.join(this.options.dataDir, this.options.feedbackFile);
  }

  get writeupRulesPath() {
    return path.join(this.options.dataDir, this.options.writeupRulesFile);
  }

  get writeupHistoryPath() {
    return path.join(this.options.dataDir, this.options.writeupHistoryFile);
  }

  async initialize() {
    if (this.initialized) {
      return;
    }

    await fs.mkdir(this.options.dataDir, { recursive: true });
    this.feedbackStore = await this.readOrCreateJson(this.feedbackPath, DEFAULT_FEEDBACK_STORE);
    this.writeupStore = await this.readOrCreateJson(this.writeupRulesPath, DEFAULT_WRITEUP_STORE);
    this.writeupHistoryStore = await this.readOrCreateJson(this.writeupHistoryPath, DEFAULT_WRITEUP_HISTORY_STORE);
    await this.mergeLegacyStores();
    if (this.options.autoCleanupWriteupRules) {
      await this.cleanupWriteupRules({
        reason: 'initialize',
        dryRun: false,
        minRuleScore: this.options.autoCleanupMinRuleScore
      });
    }
    this.initialized = true;
  }

  getStatus() {
    return {
      initialized: this.initialized,
      dataDir: this.options.dataDir,
      feedbackFingerprints: Object.keys(this.feedbackStore.fingerprints || {}).length,
      writeupRules: Array.isArray(this.writeupStore.rules) ? this.writeupStore.rules.length : 0,
      knownWriteupUrls: this.getKnownWriteupUrls().length,
      processedWriteups: Object.keys(this.writeupHistoryStore.byUrl || {}).length,
      knownWriteupFingerprints: Object.keys(this.writeupHistoryStore.byFingerprint || {}).length,
      cleanupPolicy: {
        autoCleanupWriteupRules: this.options.autoCleanupWriteupRules,
        autoCleanupMinRuleScore: this.options.autoCleanupMinRuleScore,
        autoCleanupFailedHistoryRetentionDays: this.options.autoCleanupFailedHistoryRetentionDays
      },
      writeupSources: this.options.writeupSources,
      updatedAt: {
        feedback: this.feedbackStore.updatedAt,
        writeups: this.writeupStore.updatedAt,
        writeupHistory: this.writeupHistoryStore.updatedAt
      }
    };
  }

  buildFingerprint(vuln = {}) {
    const url = String(vuln.url || '').toLowerCase();
    const type = String(vuln.type || '').toLowerCase();
    const subType = String(vuln.subType || '').toLowerCase();
    const parameter = String(vuln.parameter || '').toLowerCase();
    const method = String(vuln.method || 'GET').toUpperCase();
    return `${type}|${subType}|${url}|${parameter}|${method}`;
  }

  evaluateFinding(vuln, fingerprint, context = {}) {
    const result = {
      confidenceDelta: 0,
      suppress: false,
      reasons: [],
      sources: [],
      matchedRules: []
    };

    if (!this.initialized) {
      return result;
    }

    const fp = fingerprint || this.buildFingerprint(vuln);
    const memory = this.feedbackStore.fingerprints?.[fp];

    if (memory) {
      const falsePositive = Number(memory.falsePositive || 0);
      const truePositive = Number(memory.truePositive || 0);

      if (falsePositive >= 3 && truePositive === 0) {
        result.suppress = true;
        result.reasons.push('Suppressed by learning memory: repeated false-positive history.');
      } else if (falsePositive > truePositive) {
        const penalty = Math.min(30, (falsePositive - truePositive) * 5);
        result.confidenceDelta -= penalty;
        result.reasons.push(`Confidence reduced by historical feedback (${falsePositive} FP vs ${truePositive} TP).`);
      } else if (truePositive > falsePositive) {
        const boost = Math.min(20, (truePositive - falsePositive) * 4);
        result.confidenceDelta += boost;
        result.reasons.push(`Confidence increased by historical feedback (${truePositive} TP vs ${falsePositive} FP).`);
      }
    }

    const evidenceText = String(vuln.evidence || '');
    for (const rule of this.getMatchingRules(vuln, context)) {
      result.matchedRules.push(rule.id);

      if (Array.isArray(rule.sources)) {
        result.sources.push(...rule.sources);
      }

      if (rule.requiredEvidencePatterns?.length > 0) {
        const hasRequiredEvidence = rule.requiredEvidencePatterns.some((pattern) =>
          this.matchTextPattern(evidenceText, pattern)
        );

        if (!hasRequiredEvidence) {
          const penalty = Number.isFinite(rule.missingEvidencePenalty)
            ? rule.missingEvidencePenalty
            : 15;
          result.confidenceDelta -= penalty;
          result.reasons.push(
            `${rule.name || rule.id}: required evidence pattern not observed.`
          );

          if (rule.suppressIfMissingEvidence) {
            result.suppress = true;
            result.reasons.push(`${rule.name || rule.id}: suppressed due to missing hard proof.`);
          }
        }
      }

      const confidenceBoost = Number(rule.confidenceBoost || 0);
      const confidencePenalty = Number(rule.confidencePenalty || 0);
      result.confidenceDelta += confidenceBoost;
      result.confidenceDelta -= confidencePenalty;
    }

    result.sources = this.deduplicateSources(result.sources);
    return result;
  }

  async recordFeedback(entry = {}) {
    await this.initialize();

    const verdict = this.normalizeVerdict(entry.verdict);
    if (!verdict) {
      throw new Error('Invalid verdict. Use "true_positive" or "false_positive".');
    }

    const fingerprint = String(
      entry.fingerprint ||
      this.buildFingerprint(entry.vulnerability || entry)
    ).trim();

    if (!fingerprint) {
      throw new Error('Missing vulnerability fingerprint for feedback.');
    }

    if (!this.feedbackStore.fingerprints[fingerprint]) {
      this.feedbackStore.fingerprints[fingerprint] = {
        falsePositive: 0,
        truePositive: 0,
        notes: [],
        lastUpdated: null
      };
    }

    const record = this.feedbackStore.fingerprints[fingerprint];
    if (verdict === 'false_positive') {
      record.falsePositive += 1;
    } else {
      record.truePositive += 1;
    }

    if (entry.notes) {
      record.notes.push({
        verdict,
        note: String(entry.notes).slice(0, 1000),
        timestamp: new Date().toISOString()
      });

      if (record.notes.length > this.options.maxNotesPerFingerprint) {
        record.notes = record.notes.slice(-this.options.maxNotesPerFingerprint);
      }
    }

    record.lastUpdated = new Date().toISOString();
    this.feedbackStore.updatedAt = new Date().toISOString();
    await this.saveJson(this.feedbackPath, this.feedbackStore);

    return {
      fingerprint,
      verdict,
      stats: {
        falsePositive: record.falsePositive,
        truePositive: record.truePositive
      }
    };
  }

  async importWriteupRules(payload = {}) {
    await this.initialize();

    const incomingRules = Array.isArray(payload.rules) ? payload.rules : [];
    if (incomingRules.length === 0) {
      return { imported: 0, totalRules: this.writeupStore.rules.length };
    }

    const byId = new Map();
    const bySignature = new Map();
    for (const rule of (this.writeupStore.rules || [])) {
      byId.set(rule.id, rule);
      bySignature.set(this.buildRuleSignature(rule), rule.id);
    }

    let imported = 0;
    let updated = 0;
    for (const rule of incomingRules) {
      const normalized = this.normalizeRule(rule);
      if (!normalized) {
        continue;
      }

      const signature = this.buildRuleSignature(normalized);
      const existingId = bySignature.get(signature);
      if (existingId) {
        const existing = byId.get(existingId);
        const merged = this.mergeWriteupRules(existing, normalized);
        merged.id = existingId;
        byId.set(existingId, merged);
        updated += 1;
        continue;
      }

      byId.set(normalized.id, normalized);
      bySignature.set(signature, normalized.id);
      imported += 1;
    }

    this.writeupStore.rules = Array.from(byId.values());
    this.writeupStore.updatedAt = new Date().toISOString();
    await this.saveJson(this.writeupRulesPath, this.writeupStore);

    let cleanup = null;
    if (this.options.autoCleanupWriteupRules) {
      cleanup = await this.cleanupWriteupRules({
        reason: 'import',
        dryRun: false,
        minRuleScore: this.options.autoCleanupMinRuleScore
      });
    }

    return {
      imported,
      updated,
      cleaned: cleanup?.removedRules || 0,
      totalRules: this.writeupStore.rules.length
    };
  }

  async importWriteupLinks(payload = {}) {
    await this.initialize();

    const links = Array.isArray(payload.links)
      ? payload.links.filter((link) => typeof link === 'string' && link.trim().length > 0)
      : [];
    const skipKnown = payload.skipKnown !== false;
    const knownUrls = new Set(this.getKnownWriteupUrls());

    if (links.length === 0) {
      return {
        processed: 0,
        imported: 0,
        totalRules: this.writeupStore.rules.length,
        failures: [],
        skipped: []
      };
    }

    const maxLinks = Math.max(1, Math.min(50, Number(payload.maxLinks || links.length)));
    const selectedLinks = links.slice(0, maxLinks);
    const allRules = [];
    const failures = [];
    const skipped = [];
    const seenInBatch = new Set();
    let processed = 0;

    for (const link of selectedLinks) {
      const normalizedLink = this.normalizeHttpUrl(link);
      if (!normalizedLink) {
        failures.push({ url: link, error: 'Invalid write-up URL' });
        continue;
      }
      if (seenInBatch.has(normalizedLink)) {
        skipped.push({ url: normalizedLink, reason: 'duplicate_input' });
        continue;
      }
      seenInBatch.add(normalizedLink);
      if (skipKnown && knownUrls.has(normalizedLink)) {
        skipped.push({ url: normalizedLink, reason: 'already_known' });
        continue;
      }
      if (this.isWriteupInCooldown(normalizedLink)) {
        skipped.push({ url: normalizedLink, reason: 'cooldown_active' });
        continue;
      }

      try {
        const parsed = await this.extractRulesFromWriteupUrl(normalizedLink, payload.options || {});
        const duplicateContentOf = parsed.contentFingerprint
          ? this.getExistingWriteupByFingerprint(parsed.contentFingerprint, normalizedLink)
          : null;

        if (duplicateContentOf) {
          skipped.push({
            url: normalizedLink,
            reason: 'duplicate_content',
            duplicateOf: duplicateContentOf
          });
          await this.markWriteupProcessed({
            url: normalizedLink,
            title: parsed.title,
            contentFingerprint: parsed.contentFingerprint,
            status: 'duplicate_content'
          });
          knownUrls.add(normalizedLink);
          processed += 1;
          continue;
        }

        allRules.push(...parsed.rules);
        await this.markWriteupProcessed({
          url: normalizedLink,
          title: parsed.title,
          contentFingerprint: parsed.contentFingerprint,
          status: parsed.rules.length > 0 ? 'imported' : 'no_new_rules'
        });
        knownUrls.add(normalizedLink);
        processed += 1;
      } catch (error) {
        await this.markWriteupFailure(normalizedLink, error.message);
        failures.push({
          url: normalizedLink,
          error: error.message
        });
      }
    }

    const importResult = await this.importWriteupRules({ rules: allRules });
    return {
      processed,
      imported: importResult.imported,
      totalRules: importResult.totalRules,
      failures,
      skipped
    };
  }

  async discoverWriteupLinks(payload = {}) {
    await this.initialize();

    const sources = Array.isArray(payload.sources) && payload.sources.length > 0
      ? payload.sources
      : this.options.writeupSources;
    const maxPerSource = Math.max(1, Math.min(80, Number(payload.maxPerSource || 20)));
    const timeout = Number(payload.timeout || 20000);
    const links = [];
    const failures = [];

    for (const source of sources) {
      const normalizedSource = this.normalizeHttpUrl(source);
      if (!normalizedSource) {
        failures.push({ source, error: 'Invalid source URL' });
        continue;
      }

      try {
        const discovered = await this.fetchWriteupLinksFromSource(normalizedSource, {
          maxPerSource,
          timeout
        });
        links.push(...discovered);
      } catch (error) {
        failures.push({
          source: normalizedSource,
          error: error.message
        });
      }
    }

    const uniqueLinks = this.uniqueStrings(links)
      .map((link) => this.normalizeHttpUrl(link))
      .filter(Boolean);

    return {
      sourcesChecked: sources.length,
      discovered: uniqueLinks.length,
      links: uniqueLinks,
      failures
    };
  }

  listWriteupRules() {
    return Array.isArray(this.writeupStore.rules)
      ? this.writeupStore.rules
      : [];
  }

  getKnownWriteupUrls() {
    const known = new Set();
    for (const rule of this.listWriteupRules()) {
      const sources = Array.isArray(rule.sources) ? rule.sources : [];
      for (const source of sources) {
        const sourceUrl = this.normalizeHttpUrl(
          typeof source === 'string' ? source : source?.url
        );
        if (sourceUrl) {
          known.add(sourceUrl);
        }
      }
    }

    const byUrl = this.writeupHistoryStore?.byUrl || {};
    for (const [candidateUrl, entry] of Object.entries(byUrl)) {
      const normalized = this.normalizeHttpUrl(candidateUrl);
      if (!normalized) continue;
      const status = String(entry?.lastStatus || '').toLowerCase();
      if (status === 'imported' || status === 'no_new_rules' || status === 'duplicate_content') {
        known.add(normalized);
      }
    }

    return Array.from(known);
  }

  getExistingWriteupByFingerprint(fingerprint, currentUrl = null) {
    if (!fingerprint) return null;
    const entry = this.writeupHistoryStore?.byFingerprint?.[fingerprint];
    if (!entry) return null;
    const primary = this.normalizeHttpUrl(entry.primaryUrl);
    const current = this.normalizeHttpUrl(currentUrl);
    if (!primary) return null;
    if (current && current === primary) {
      return null;
    }
    return primary;
  }

  isWriteupInCooldown(url) {
    const normalized = this.normalizeHttpUrl(url);
    if (!normalized) return false;

    const entry = this.writeupHistoryStore?.byUrl?.[normalized];
    if (!entry) return false;
    if (String(entry.lastStatus || '') !== 'failed') return false;

    const nextRetryAt = Date.parse(entry.nextRetryAt || '');
    return Number.isFinite(nextRetryAt) && nextRetryAt > Date.now();
  }

  async markWriteupProcessed(payload = {}) {
    await this.initialize();

    const url = this.normalizeHttpUrl(payload.url);
    if (!url) return;

    const nowIso = new Date().toISOString();
    const existing = this.writeupHistoryStore.byUrl[url] || {
      url,
      title: null,
      firstSeenAt: nowIso,
      lastStatus: null,
      lastAttemptAt: null,
      lastError: null,
      attempts: 0,
      successfulAttempts: 0,
      failedAttempts: 0,
      nextRetryAt: null,
      contentFingerprint: null
    };

    existing.title = payload.title ? String(payload.title).slice(0, 500) : existing.title;
    existing.attempts += 1;
    existing.successfulAttempts += 1;
    existing.lastAttemptAt = nowIso;
    existing.lastStatus = String(payload.status || 'imported');
    existing.lastError = null;
    existing.nextRetryAt = null;

    const normalizedFingerprint = String(payload.contentFingerprint || '').trim();
    if (normalizedFingerprint) {
      existing.contentFingerprint = normalizedFingerprint;
      const fpEntry = this.writeupHistoryStore.byFingerprint[normalizedFingerprint] || {
        primaryUrl: url,
        firstSeenAt: nowIso,
        lastSeenAt: nowIso,
        seenCount: 0,
        seenUrls: []
      };

      fpEntry.lastSeenAt = nowIso;
      fpEntry.seenCount = Number(fpEntry.seenCount || 0) + 1;
      if (!Array.isArray(fpEntry.seenUrls)) {
        fpEntry.seenUrls = [];
      }
      if (!fpEntry.seenUrls.includes(url)) {
        fpEntry.seenUrls.push(url);
      }
      fpEntry.seenUrls = fpEntry.seenUrls.slice(-20);
      this.writeupHistoryStore.byFingerprint[normalizedFingerprint] = fpEntry;
    }

    this.writeupHistoryStore.byUrl[url] = existing;
    this.trimWriteupHistory();
    await this.saveWriteupHistory();
  }

  async markWriteupFailure(url, errorMessage = '') {
    await this.initialize();

    const normalized = this.normalizeHttpUrl(url);
    if (!normalized) return;

    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const existing = this.writeupHistoryStore.byUrl[normalized] || {
      url: normalized,
      title: null,
      firstSeenAt: nowIso,
      lastStatus: null,
      lastAttemptAt: null,
      lastError: null,
      attempts: 0,
      successfulAttempts: 0,
      failedAttempts: 0,
      nextRetryAt: null,
      contentFingerprint: null
    };

    existing.attempts += 1;
    existing.failedAttempts += 1;
    existing.lastAttemptAt = nowIso;
    existing.lastStatus = 'failed';
    existing.lastError = String(errorMessage || 'Unknown error').slice(0, 1000);

    const exponentialFactor = Math.min(6, Math.max(0, existing.failedAttempts - 1));
    const cooldownMs = this.options.writeupFailureCooldownMs * Math.pow(2, exponentialFactor);
    existing.nextRetryAt = new Date(now + cooldownMs).toISOString();

    this.writeupHistoryStore.byUrl[normalized] = existing;
    this.trimWriteupHistory();
    await this.saveWriteupHistory();
  }

  getMatchingRules(vuln = {}, context = {}) {
    const configuredRules = Array.isArray(this.writeupStore.rules)
      ? this.writeupStore.rules
      : [];
    let rules = configuredRules;

    if (Array.isArray(context.rulePool)) {
      rules = context.rulePool;
    } else if (context.ruleIds instanceof Set) {
      rules = configuredRules.filter((rule) => context.ruleIds.has(rule.id));
    } else if (Array.isArray(context.ruleIds)) {
      const selectedIds = new Set(context.ruleIds.map((id) => String(id)));
      rules = configuredRules.filter((rule) => selectedIds.has(rule.id));
    }

    return rules.filter((rule) => {
      const type = String(vuln.type || '');
      const subType = String(vuln.subType || '');
      const description = String(vuln.description || '');

      if (rule.typePattern && !this.matchTextPattern(type, rule.typePattern)) {
        return false;
      }

      if (rule.subTypePattern && !this.matchTextPattern(subType, rule.subTypePattern)) {
        return false;
      }

      if (rule.descriptionPattern && !this.matchTextPattern(description, rule.descriptionPattern)) {
        return false;
      }

      return true;
    });
  }

  normalizeRule(rule) {
    if (!rule || typeof rule !== 'object') {
      return null;
    }

    const id = String(rule.id || '').trim() || this.generateRuleId(rule);
    if (!id) {
      return null;
    }

    return {
      id,
      name: String(rule.name || id),
      typePattern: rule.typePattern || null,
      subTypePattern: rule.subTypePattern || null,
      descriptionPattern: rule.descriptionPattern || null,
      requiredEvidencePatterns: Array.isArray(rule.requiredEvidencePatterns)
        ? rule.requiredEvidencePatterns
        : [],
      confidenceBoost: Number(rule.confidenceBoost || 0),
      confidencePenalty: Number(rule.confidencePenalty || 0),
      missingEvidencePenalty: Number(rule.missingEvidencePenalty || 15),
      suppressIfMissingEvidence: rule.suppressIfMissingEvidence === true,
      sources: Array.isArray(rule.sources) ? rule.sources : [],
      updatedAt: new Date().toISOString()
    };
  }

  buildRuleSignature(rule = {}) {
    const typePattern = Array.isArray(rule.typePattern)
      ? [...rule.typePattern].map((v) => String(v)).sort()
      : String(rule.typePattern || '');
    const subTypePattern = Array.isArray(rule.subTypePattern)
      ? [...rule.subTypePattern].map((v) => String(v)).sort()
      : String(rule.subTypePattern || '');
    const descriptionPattern = String(rule.descriptionPattern || '');
    const evidencePatterns = Array.isArray(rule.requiredEvidencePatterns)
      ? [...rule.requiredEvidencePatterns].map((v) => String(v)).sort()
      : [];
    const sourceUrls = (Array.isArray(rule.sources) ? rule.sources : [])
      .map((source) => this.normalizeHttpUrl(typeof source === 'string' ? source : source?.url))
      .filter(Boolean)
      .sort();

    return JSON.stringify({
      typePattern,
      subTypePattern,
      descriptionPattern,
      evidencePatterns,
      sourceUrls
    });
  }

  async extractRulesFromWriteupUrl(writeupUrl, options = {}) {
    const normalizedUrl = String(writeupUrl || '').trim();
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      throw new Error('Write-up URL must start with http:// or https://');
    }

    const response = await axios.get(normalizedUrl, {
      timeout: Number(options.timeout || 20000),
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        'User-Agent': options.userAgent || 'VulnHunter Pro/1.0 (Writeup Learner)'
      }
    });

    if (response.status < 200 || response.status >= 400) {
      throw new Error(`Failed to fetch write-up (HTTP ${response.status})`);
    }

    const html = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data || '');
    const { title, text, codeSnippets } = this.extractReadableWriteupContent(html);
    const contentFingerprint = this.buildWriteupContentFingerprint({
      title,
      text,
      codeSnippets
    });
    const matchedProfiles = this.inferWriteupProfiles(text, title);

    const maxRulesPerLink = Math.max(
      1,
      Math.min(8, Number(options.maxRulesPerLink || 4))
    );
    const selectedProfiles = matchedProfiles.slice(0, maxRulesPerLink);

    const rules = selectedProfiles.map((profile) => {
      const snippetPatterns = this.extractSnippetPatterns(codeSnippets, profile);
      const requiredEvidencePatterns = this.uniqueStrings([
        ...(profile.requiredEvidencePatterns || []),
        ...snippetPatterns
      ]);

      const urlSlug = this.slugify(normalizedUrl).slice(0, 36);
      return {
        id: `writeup-${profile.key}-${urlSlug}`,
        name: `Write-up learned: ${profile.name}`,
        typePattern: profile.typePattern,
        subTypePattern: profile.subTypePattern || null,
        descriptionPattern: profile.descriptionPattern || null,
        requiredEvidencePatterns,
        confidenceBoost: profile.confidenceBoost ?? 8,
        confidencePenalty: profile.confidencePenalty ?? 0,
        missingEvidencePenalty: profile.missingEvidencePenalty ?? 12,
        suppressIfMissingEvidence: profile.suppressIfMissingEvidence === true,
        sources: [
          {
            title: title || profile.name,
            url: normalizedUrl
          }
        ]
      };
    });

    return {
      url: normalizedUrl,
      title,
      contentFingerprint,
      rules
    };
  }

  async fetchWriteupLinksFromSource(sourceUrl, options = {}) {
    const response = await axios.get(sourceUrl, {
      timeout: Number(options.timeout || 20000),
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        'User-Agent': options.userAgent || 'VulnHunter Pro/1.0 (Writeup Discovery)'
      }
    });

    if (response.status < 200 || response.status >= 400) {
      throw new Error(`Source fetch failed (HTTP ${response.status})`);
    }

    const content = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data || '');

    return this.extractCandidateWriteupLinksFromDocument(content, sourceUrl, options.maxPerSource || 20);
  }

  extractCandidateWriteupLinksFromDocument(content, sourceUrl, maxPerSource = 20) {
    const links = [];
    const xmlLinks = this.extractLinksFromXmlFeed(content);
    links.push(...xmlLinks);

    if (links.length < maxPerSource) {
      const htmlLinks = this.extractLinksFromHtml(content, sourceUrl);
      links.push(...htmlLinks);
    }

    const filtered = links
      .map((link) => this.normalizeHttpUrl(link))
      .filter((link) => link && this.looksLikeWriteupLink(link))
      .filter((link) => !this.isLikelyFeedLink(link));

    return this.uniqueStrings(filtered).slice(0, maxPerSource);
  }

  extractLinksFromXmlFeed(content) {
    const links = [];
    const text = String(content || '');

    const itemLinkRegex = /<item[\s\S]*?<link>([^<]+)<\/link>/gi;
    let match;
    while ((match = itemLinkRegex.exec(text)) !== null) {
      links.push(match[1]);
    }

    const atomLinkRegex = /<entry[\s\S]*?<link[^>]*href=["']([^"']+)["'][^>]*>/gi;
    while ((match = atomLinkRegex.exec(text)) !== null) {
      links.push(match[1]);
    }

    const guidRegex = /<guid[^>]*>([^<]+)<\/guid>/gi;
    while ((match = guidRegex.exec(text)) !== null) {
      links.push(match[1]);
    }

    return links;
  }

  extractLinksFromHtml(content, sourceUrl) {
    const $ = cheerio.load(String(content || ''));
    const links = [];
    $('a[href]').each((_, el) => {
      const href = $(el).attr('href');
      if (!href) return;
      const resolved = this.resolveUrl(sourceUrl, href);
      if (resolved) {
        links.push(resolved);
      }
    });
    return links;
  }

  resolveUrl(baseUrl, candidate) {
    try {
      return new URL(candidate, baseUrl).href;
    } catch {
      return null;
    }
  }

  looksLikeWriteupLink(url) {
    const value = String(url || '').toLowerCase();
    if (!value.startsWith('http://') && !value.startsWith('https://')) return false;

    const positiveSignals = [
      '/research/',
      '/blog/',
      '/writeup',
      '/write-up',
      '/reports/',
      '/report/',
      '/article/',
      '/post/',
      '/stories/'
    ];

    return positiveSignals.some((signal) => value.includes(signal)) ||
      /(xss|sqli|ssrf|idor|csrf|rce|bug bounty|vulnerability|writeup|write-up)/i.test(value);
  }

  isLikelyFeedLink(url) {
    const value = String(url || '').toLowerCase();
    return value.includes('/feed') ||
      value.endsWith('.rss') ||
      value.endsWith('.xml') ||
      value.includes('atom');
  }

  extractReadableWriteupContent(html) {
    const $ = cheerio.load(String(html || ''));
    $('script, style, noscript, svg').remove();

    const title = $('title').first().text().trim() || $('h1').first().text().trim() || 'Untitled write-up';

    const container = $('article').first().length > 0
      ? $('article').first()
      : $('main').first().length > 0
        ? $('main').first()
        : $('body');

    const text = container.text().replace(/\s+/g, ' ').trim().slice(0, 60000);
    const codeSnippets = [];
    container.find('pre code, code').each((_, el) => {
      const snippet = $(el).text().replace(/\s+/g, ' ').trim();
      if (snippet.length >= 4 && snippet.length <= 180) {
        codeSnippets.push(snippet);
      }
    });

    return {
      title,
      text,
      codeSnippets: this.uniqueStrings(codeSnippets).slice(0, 80)
    };
  }

  inferWriteupProfiles(text = '', title = '') {
    const corpus = `${title}\n${text}`.toLowerCase();

    const profiles = this.getWriteupProfiles()
      .map((profile) => {
        const score = (profile.indicators || []).reduce((total, indicator) => {
          return total + (corpus.includes(indicator.toLowerCase()) ? 1 : 0);
        }, 0);

        return {
          ...profile,
          score
        };
      })
      .filter((profile) => profile.score > 0)
      .sort((a, b) => b.score - a.score);

    if (profiles.length > 0) {
      return profiles;
    }

    // Fallback profile when write-up topic can't be confidently inferred.
    return [{
      key: 'general-security',
      name: 'General Security Finding',
      typePattern: ['xss', 'sql injection', 'ssrf', 'idor', 'csrf', 'authentication bypass', 'business logic'],
      requiredEvidencePatterns: ['proof', 'payload', 'request', 'response'],
      indicators: [],
      confidenceBoost: 4,
      missingEvidencePenalty: 8
    }];
  }

  extractSnippetPatterns(codeSnippets = [], profile = {}) {
    const patterns = [];
    const profileKeywords = (profile.indicators || []).map((v) => v.toLowerCase());

    for (const snippet of codeSnippets) {
      const lower = snippet.toLowerCase();
      const related = profileKeywords.length === 0 || profileKeywords.some((keyword) => lower.includes(keyword));
      if (!related) continue;

      if (snippet.length < 4 || snippet.length > 120) continue;
      if (!/[a-z]/i.test(snippet)) continue;

      const normalized = snippet
        .replace(/\s+/g, ' ')
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .trim();

      if (normalized.length >= 4 && normalized.length <= 120) {
        patterns.push(normalized);
      }
    }

    return this.uniqueStrings(patterns).slice(0, 12);
  }

  getWriteupProfiles() {
    return [
      {
        key: 'xss',
        name: 'Cross-Site Scripting',
        typePattern: ['xss', 'dom xss'],
        subTypePattern: ['reflected', 'stored', 'dom'],
        requiredEvidencePatterns: ['<script', 'onerror=', 'javascript:', 'svg onload'],
        indicators: ['xss', 'cross site scripting', 'dom xss', 'stored xss', 'reflected xss'],
        confidenceBoost: 10,
        missingEvidencePenalty: 14
      },
      {
        key: 'sqli',
        name: 'SQL Injection',
        typePattern: 'sql injection',
        subTypePattern: ['error-based', 'boolean', 'time-based'],
        requiredEvidencePatterns: ['sql syntax', 'union select', 'sleep(', 'waitfor delay', 'ora-'],
        indicators: ['sql injection', 'sqli', 'union select', 'blind sql', 'database error'],
        confidenceBoost: 10,
        missingEvidencePenalty: 15,
        suppressIfMissingEvidence: false
      },
      {
        key: 'ssrf',
        name: 'Server-Side Request Forgery',
        typePattern: 'ssrf',
        requiredEvidencePatterns: ['169.254.169.254', 'metadata', 'internal host', 'localhost'],
        indicators: ['ssrf', 'server-side request forgery', 'metadata service', 'internal network'],
        confidenceBoost: 10,
        missingEvidencePenalty: 14
      },
      {
        key: 'idor',
        name: 'Insecure Direct Object Reference',
        typePattern: 'idor',
        requiredEvidencePatterns: ['object id', 'user id', 'account id', 'horizontal privilege'],
        indicators: ['idor', 'insecure direct object reference', 'horizontal escalation', 'vertical escalation'],
        confidenceBoost: 9,
        missingEvidencePenalty: 13
      },
      {
        key: 'csrf',
        name: 'Cross-Site Request Forgery',
        typePattern: 'csrf',
        requiredEvidencePatterns: ['csrf token', 'state changing', 'forged request'],
        indicators: ['csrf', 'cross-site request forgery', 'anti csrf', 'same-site'],
        confidenceBoost: 8,
        missingEvidencePenalty: 12
      },
      {
        key: 'auth-bypass',
        name: 'Authentication/Authorization Bypass',
        typePattern: ['authentication bypass', 'authorization bypass', 'idor'],
        requiredEvidencePatterns: ['unauthorized', 'bypass', 'access control'],
        indicators: ['auth bypass', 'authorization bypass', 'access control', 'broken access control'],
        confidenceBoost: 9,
        missingEvidencePenalty: 13
      },
      {
        key: 'logic-bug',
        name: 'Business Logic Vulnerability',
        typePattern: ['business logic', 'idor', 'authentication bypass', 'csrf'],
        subTypePattern: ['workflow', 'race', 'step bypass', 'logic'],
        requiredEvidencePatterns: ['workflow', 'step', 'state change', 'race condition', 'double spend'],
        indicators: ['business logic', 'race condition', 'workflow bypass', 'logic flaw', 'step bypass'],
        confidenceBoost: 7,
        missingEvidencePenalty: 10
      },
      {
        key: 'open-redirect',
        name: 'Open Redirect',
        typePattern: 'open redirect',
        requiredEvidencePatterns: ['location:', 'redirect=', 'next=', 'return='],
        indicators: ['open redirect', 'url redirect', 'return url'],
        confidenceBoost: 7,
        missingEvidencePenalty: 10
      },
      {
        key: 'rce',
        name: 'Remote Code Execution',
        typePattern: 'rce',
        requiredEvidencePatterns: ['uid=', 'root:', 'command execution', 'shell'],
        indicators: ['rce', 'remote code execution', 'command injection'],
        confidenceBoost: 12,
        missingEvidencePenalty: 16,
        suppressIfMissingEvidence: false
      }
    ];
  }

  buildWriteupContentFingerprint({ title = '', text = '', codeSnippets = [] } = {}) {
    const normalizedTitle = String(title || '').toLowerCase().trim();
    const normalizedText = String(text || '')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 25000);
    const normalizedSnippets = this.uniqueStrings(codeSnippets)
      .map((snippet) => String(snippet).toLowerCase().replace(/\s+/g, ' ').trim())
      .slice(0, 40)
      .join('|');

    const digest = crypto
      .createHash('sha256')
      .update(`${normalizedTitle}\n${normalizedText}\n${normalizedSnippets}`)
      .digest('hex');

    return `sha256:${digest}`;
  }

  uniqueStrings(values = []) {
    const seen = new Set();
    const result = [];

    for (const value of values) {
      const normalized = String(value || '').trim();
      if (!normalized) continue;
      if (seen.has(normalized)) continue;
      seen.add(normalized);
      result.push(normalized);
    }

    return result;
  }

  slugify(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64) || 'source';
  }

  trimWriteupHistory() {
    const byUrl = this.writeupHistoryStore?.byUrl || {};
    const limit = Number(this.options.writeupHistoryLimit || 5000);
    const entries = Object.entries(byUrl);
    if (entries.length <= limit) {
      return;
    }

    entries.sort((a, b) => {
      const left = Date.parse(a[1]?.lastAttemptAt || a[1]?.firstSeenAt || 0) || 0;
      const right = Date.parse(b[1]?.lastAttemptAt || b[1]?.firstSeenAt || 0) || 0;
      return left - right;
    });

    const removeCount = entries.length - limit;
    for (let i = 0; i < removeCount; i += 1) {
      delete byUrl[entries[i][0]];
    }
    this.writeupHistoryStore.byUrl = byUrl;

    const byFingerprint = this.writeupHistoryStore?.byFingerprint || {};
    for (const [fingerprint, entry] of Object.entries(byFingerprint)) {
      const urls = Array.isArray(entry?.seenUrls)
        ? entry.seenUrls.filter((url) => Boolean(byUrl[url]))
        : [];

      if (urls.length === 0) {
        delete byFingerprint[fingerprint];
        continue;
      }

      const primaryCandidate = this.normalizeHttpUrl(entry.primaryUrl);
      const primaryUrl = primaryCandidate && urls.includes(primaryCandidate)
        ? primaryCandidate
        : urls[0];

      byFingerprint[fingerprint] = {
        ...entry,
        primaryUrl,
        seenUrls: urls,
        seenCount: urls.length
      };
    }
    this.writeupHistoryStore.byFingerprint = byFingerprint;
  }

  normalizeHttpUrl(value) {
    try {
      const parsed = new URL(String(value || '').trim());
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      parsed.hash = '';
      parsed.hostname = parsed.hostname.toLowerCase();
      if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
        parsed.port = '';
      }
      parsed.pathname = parsed.pathname.replace(/\/{2,}/g, '/');
      if (parsed.pathname.length > 1 && parsed.pathname.endsWith('/')) {
        parsed.pathname = parsed.pathname.slice(0, -1);
      }

      const retainedParams = [];
      for (const [key, val] of parsed.searchParams.entries()) {
        const lower = key.toLowerCase();
        if (
          lower.startsWith('utm_') ||
          lower === 'fbclid' ||
          lower === 'gclid' ||
          lower === 'mc_cid' ||
          lower === 'mc_eid' ||
          lower === 'ref' ||
          lower === 'source'
        ) {
          continue;
        }
        retainedParams.push([key, val]);
      }

      retainedParams.sort((a, b) => {
        const keyCmp = a[0].localeCompare(b[0]);
        if (keyCmp !== 0) return keyCmp;
        return String(a[1]).localeCompare(String(b[1]));
      });

      parsed.search = '';
      for (const [key, val] of retainedParams) {
        parsed.searchParams.append(key, val);
      }

      return parsed.href;
    } catch {
      return null;
    }
  }

  async saveWriteupHistory() {
    this.writeupHistoryStore.updatedAt = new Date().toISOString();
    await this.saveJson(this.writeupHistoryPath, this.writeupHistoryStore);
  }

  matchTextPattern(value, pattern) {
    const text = String(value || '');

    if (Array.isArray(pattern)) {
      return pattern.some((p) => this.matchTextPattern(text, p));
    }

    if (pattern instanceof RegExp) {
      return pattern.test(text);
    }

    if (typeof pattern !== 'string') {
      return false;
    }

    const regexMatch = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    if (regexMatch) {
      try {
        const [, source, flags] = regexMatch;
        const re = new RegExp(source, flags);
        return re.test(text);
      } catch {
        return false;
      }
    }

    return text.toLowerCase().includes(pattern.toLowerCase());
  }

  normalizeVerdict(verdict) {
    const value = String(verdict || '').trim().toLowerCase();
    if (value === 'false_positive' || value === 'false-positive' || value === 'fp') {
      return 'false_positive';
    }
    if (value === 'true_positive' || value === 'true-positive' || value === 'tp') {
      return 'true_positive';
    }
    return null;
  }

  deduplicateSources(sources = []) {
    const seen = new Set();
    const deduped = [];

    for (const src of sources) {
      if (!src) continue;

      const normalized = typeof src === 'string'
        ? { title: src, url: null }
        : {
            title: src.title || src.url || 'source',
            url: src.url || null
          };

      const key = `${normalized.title}|${normalized.url || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(normalized);
    }

    return deduped;
  }

  generateRuleId(rule = {}) {
    const typePart = String(rule.typePattern || rule.name || 'rule')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40);

    return `writeup-${typePart || 'rule'}-${Date.now()}`;
  }

  getWriteupTypePatternSignature(rule = {}) {
    const pattern = Array.isArray(rule.typePattern)
      ? rule.typePattern.map((item) => String(item).toLowerCase().trim()).sort().join('|')
      : String(rule.typePattern || '').toLowerCase().trim();
    return pattern || 'unknown';
  }

  buildRuleCoreSignature(rule = {}) {
    const typePattern = Array.isArray(rule.typePattern)
      ? [...rule.typePattern].map((v) => String(v).toLowerCase().trim()).sort()
      : [String(rule.typePattern || '').toLowerCase().trim()];
    const subTypePattern = Array.isArray(rule.subTypePattern)
      ? [...rule.subTypePattern].map((v) => String(v).toLowerCase().trim()).sort()
      : [String(rule.subTypePattern || '').toLowerCase().trim()];
    const descriptionPattern = String(rule.descriptionPattern || '').toLowerCase().trim();
    const evidencePatterns = Array.isArray(rule.requiredEvidencePatterns)
      ? [...rule.requiredEvidencePatterns].map((v) => String(v).toLowerCase().trim()).sort()
      : [];

    return JSON.stringify({
      typePattern,
      subTypePattern,
      descriptionPattern,
      evidencePatterns
    });
  }

  mergeWriteupRules(existing = {}, incoming = {}) {
    const existingSources = Array.isArray(existing.sources) ? existing.sources : [];
    const incomingSources = Array.isArray(incoming.sources) ? incoming.sources : [];
    const existingEvidence = Array.isArray(existing.requiredEvidencePatterns) ? existing.requiredEvidencePatterns : [];
    const incomingEvidence = Array.isArray(incoming.requiredEvidencePatterns) ? incoming.requiredEvidencePatterns : [];

    return {
      ...existing,
      ...incoming,
      id: String(existing.id || incoming.id || this.generateRuleId(incoming)),
      name: String(existing.name || incoming.name || existing.id || incoming.id || 'Write-up rule'),
      typePattern: existing.typePattern || incoming.typePattern || null,
      subTypePattern: existing.subTypePattern || incoming.subTypePattern || null,
      descriptionPattern: existing.descriptionPattern || incoming.descriptionPattern || null,
      requiredEvidencePatterns: this.uniqueStrings([...existingEvidence, ...incomingEvidence]).slice(0, 40),
      sources: this.deduplicateSources([...existingSources, ...incomingSources]),
      confidenceBoost: Math.max(Number(existing.confidenceBoost || 0), Number(incoming.confidenceBoost || 0)),
      confidencePenalty: Math.max(Number(existing.confidencePenalty || 0), Number(incoming.confidencePenalty || 0)),
      missingEvidencePenalty: Math.max(Number(existing.missingEvidencePenalty || 15), Number(incoming.missingEvidencePenalty || 15)),
      suppressIfMissingEvidence: existing.suppressIfMissingEvidence === true || incoming.suppressIfMissingEvidence === true,
      updatedAt: new Date().toISOString()
    };
  }

  scoreWriteupRule(rule = {}) {
    let score = 0;

    const hasTypePattern = Array.isArray(rule.typePattern)
      ? rule.typePattern.length > 0
      : Boolean(String(rule.typePattern || '').trim());
    if (hasTypePattern) score += 2;
    if (rule.subTypePattern) score += 1;
    if (rule.descriptionPattern) score += 1;

    const evidencePatterns = Array.isArray(rule.requiredEvidencePatterns)
      ? rule.requiredEvidencePatterns.map((entry) => String(entry || '').trim()).filter(Boolean)
      : [];
    score += Math.min(4, evidencePatterns.length);

    const genericEvidence = new Set([
      'proof',
      'payload',
      'request',
      'response',
      'vulnerability',
      'bug',
      'issue',
      'step'
    ]);
    const genericCount = evidencePatterns.filter((pattern) => genericEvidence.has(pattern.toLowerCase())).length;
    if (evidencePatterns.length > 0 && genericCount === evidencePatterns.length) {
      score -= 3;
    } else if (genericCount > 0) {
      score -= 1;
    }

    const knownHighSignalHosts = [
      'portswigger.net',
      'hackerone.com',
      'intigriti.com',
      'bugcrowd.com'
    ];
    const knownMediumSignalHosts = [
      'medium.com',
      'infosecwriteups.com'
    ];

    const sourceUrls = (Array.isArray(rule.sources) ? rule.sources : [])
      .map((source) => this.normalizeHttpUrl(typeof source === 'string' ? source : source?.url))
      .filter(Boolean);
    const uniqueSourceUrls = this.uniqueStrings(sourceUrls);
    score += Math.min(3, uniqueSourceUrls.length);
    let hostQualityScore = 0;
    for (const url of uniqueSourceUrls) {
      let hostname = '';
      try {
        hostname = new URL(url).hostname.toLowerCase();
      } catch {
        hostname = '';
      }
      if (knownHighSignalHosts.some((host) => hostname.endsWith(host))) {
        hostQualityScore += 2;
      } else if (knownMediumSignalHosts.some((host) => hostname.endsWith(host))) {
        hostQualityScore += 1;
      }
    }
    score += Math.min(8, hostQualityScore);

    const typeSignature = this.getWriteupTypePatternSignature(rule);
    if (typeSignature.includes('general-security') || typeSignature.includes('general security')) {
      score -= 3;
    }

    const confidenceBoost = Number(rule.confidenceBoost || 0);
    if (confidenceBoost >= 10) score += 1;
    if (confidenceBoost > 18) score -= 1;

    return score;
  }

  pickWriteupRulesByPercentage(rules = [], percentage = 100) {
    const list = Array.isArray(rules) ? rules : [];
    if (list.length === 0) return [];

    const normalizedPercent = Number.isFinite(Number(percentage))
      ? Math.max(1, Math.min(100, Math.round(Number(percentage))))
      : 100;

    const sorted = [...list].sort((left, right) => {
      const scoreDiff = this.scoreWriteupRule(right) - this.scoreWriteupRule(left);
      if (scoreDiff !== 0) return scoreDiff;
      const rightDate = Date.parse(right?.updatedAt || 0) || 0;
      const leftDate = Date.parse(left?.updatedAt || 0) || 0;
      return rightDate - leftDate;
    });

    if (normalizedPercent >= 100) {
      return sorted;
    }

    const pickCount = Math.max(1, Math.ceil((sorted.length * normalizedPercent) / 100));
    return sorted.slice(0, pickCount);
  }

  selectWriteupRulesByPercentage(percentage = 100) {
    const available = this.listWriteupRules();
    return this.pickWriteupRulesByPercentage(available, percentage);
  }

  async cleanupWriteupRules(payload = {}) {
    const dryRun = payload?.dryRun === true;
    const minRuleScore = Number.isFinite(Number(payload?.minRuleScore))
      ? Number(payload.minRuleScore)
      : this.options.autoCleanupMinRuleScore;
    const reason = String(payload?.reason || 'manual');

    const originalRules = Array.isArray(this.writeupStore.rules) ? this.writeupStore.rules : [];
    const uniqueByCore = new Map();
    const duplicatesMerged = [];

    for (const rule of originalRules) {
      const normalized = this.normalizeRule(rule);
      if (!normalized) continue;
      const core = this.buildRuleCoreSignature(normalized);
      const existing = uniqueByCore.get(core);
      if (!existing) {
        uniqueByCore.set(core, normalized);
      } else {
        uniqueByCore.set(core, this.mergeWriteupRules(existing, normalized));
        duplicatesMerged.push({
          keptId: existing.id,
          removedId: normalized.id
        });
      }
    }

    const removedLowQuality = [];
    const keptRules = [];
    for (const rule of uniqueByCore.values()) {
      const score = this.scoreWriteupRule(rule);
      if (score < minRuleScore) {
        removedLowQuality.push({
          id: rule.id,
          score,
          typePattern: rule.typePattern
        });
        continue;
      }
      keptRules.push({ ...rule, qualityScore: score });
    }

    keptRules.sort((left, right) => Number(right.qualityScore || 0) - Number(left.qualityScore || 0));
    const cleanedRules = keptRules.map((rule) => {
      const copy = { ...rule };
      delete copy.qualityScore;
      return copy;
    });

    const historyResult = this.cleanupWriteupHistory({
      retentionDays: this.options.autoCleanupFailedHistoryRetentionDays,
      dryRun
    });

    if (!dryRun) {
      this.writeupStore.rules = cleanedRules;
      this.writeupStore.updatedAt = new Date().toISOString();
      await this.saveJson(this.writeupRulesPath, this.writeupStore);
      if (historyResult.changed) {
        await this.saveWriteupHistory();
      }
    }

    return {
      reason,
      dryRun,
      minRuleScore,
      beforeRules: originalRules.length,
      afterRules: cleanedRules.length,
      removedRules: Math.max(0, originalRules.length - cleanedRules.length),
      duplicatesMerged: duplicatesMerged.length,
      removedLowQuality: removedLowQuality.length,
      historyRemovedUrls: historyResult.removedUrls,
      historyRemovedFingerprints: historyResult.removedFingerprints
    };
  }

  cleanupWriteupHistory({ retentionDays = 14, dryRun = false } = {}) {
    const byUrl = this.writeupHistoryStore?.byUrl || {};
    const byFingerprint = this.writeupHistoryStore?.byFingerprint || {};
    const keptByUrl = {};
    const now = Date.now();
    const maxAgeMs = Math.max(1, Number(retentionDays || 14)) * 24 * 60 * 60 * 1000;
    let removedUrls = 0;

    for (const [url, entry] of Object.entries(byUrl)) {
      const status = String(entry?.lastStatus || '').toLowerCase();
      const referenceDate = Date.parse(entry?.lastAttemptAt || entry?.firstSeenAt || '') || 0;
      const isOldFailed = status === 'failed' && referenceDate > 0 && (now - referenceDate) > maxAgeMs;
      if (isOldFailed) {
        removedUrls += 1;
        continue;
      }
      keptByUrl[url] = entry;
    }

    const keptByFingerprint = {};
    let removedFingerprints = 0;
    for (const [fingerprint, entry] of Object.entries(byFingerprint)) {
      const urls = Array.isArray(entry?.seenUrls)
        ? entry.seenUrls.filter((url) => Boolean(keptByUrl[url]))
        : [];
      if (urls.length === 0) {
        removedFingerprints += 1;
        continue;
      }
      const primaryUrl = urls.includes(entry?.primaryUrl) ? entry.primaryUrl : urls[0];
      keptByFingerprint[fingerprint] = {
        ...entry,
        primaryUrl,
        seenUrls: urls,
        seenCount: urls.length
      };
    }

    const changed = removedUrls > 0 || removedFingerprints > 0;
    if (changed && !dryRun) {
      this.writeupHistoryStore.byUrl = keptByUrl;
      this.writeupHistoryStore.byFingerprint = keptByFingerprint;
      this.trimWriteupHistory();
    }

    return {
      changed,
      removedUrls,
      removedFingerprints
    };
  }

  async mergeLegacyStores() {
    if (this.legacyStoresMerged) {
      return;
    }
    this.legacyStoresMerged = true;

    const legacyDir = path.join(process.cwd(), 'data', 'learning');
    const normalizedLegacy = path.resolve(legacyDir);
    const normalizedCurrent = path.resolve(this.options.dataDir);
    if (normalizedLegacy === normalizedCurrent) {
      return;
    }

    const exists = await this.pathExists(normalizedLegacy);
    if (!exists) {
      return;
    }

    const legacyFeedback = await this.readJsonOrNull(path.join(normalizedLegacy, this.options.feedbackFile));
    const legacyRules = await this.readJsonOrNull(path.join(normalizedLegacy, this.options.writeupRulesFile));
    const legacyHistory = await this.readJsonOrNull(path.join(normalizedLegacy, this.options.writeupHistoryFile));

    let changed = false;

    if (legacyFeedback && typeof legacyFeedback === 'object') {
      const fingerprints = legacyFeedback.fingerprints || {};
      for (const [key, value] of Object.entries(fingerprints)) {
        if (!this.feedbackStore.fingerprints[key]) {
          this.feedbackStore.fingerprints[key] = value;
          changed = true;
          continue;
        }
        const existing = this.feedbackStore.fingerprints[key];
        const merged = {
          falsePositive: Number(existing.falsePositive || 0) + Number(value.falsePositive || 0),
          truePositive: Number(existing.truePositive || 0) + Number(value.truePositive || 0),
          notes: [
            ...(Array.isArray(existing.notes) ? existing.notes : []),
            ...(Array.isArray(value.notes) ? value.notes : [])
          ].slice(-this.options.maxNotesPerFingerprint),
          lastUpdated: existing.lastUpdated || value.lastUpdated || null
        };
        this.feedbackStore.fingerprints[key] = merged;
        changed = true;
      }
    }

    if (legacyRules && Array.isArray(legacyRules.rules) && legacyRules.rules.length > 0) {
      const allRules = [...(this.writeupStore.rules || []), ...legacyRules.rules];
      const mergedByCore = new Map();
      for (const rule of allRules) {
        const normalized = this.normalizeRule(rule);
        if (!normalized) continue;
        const core = this.buildRuleCoreSignature(normalized);
        const existing = mergedByCore.get(core);
        mergedByCore.set(core, existing ? this.mergeWriteupRules(existing, normalized) : normalized);
      }
      this.writeupStore.rules = Array.from(mergedByCore.values());
      changed = true;
    }

    if (legacyHistory && typeof legacyHistory === 'object') {
      const legacyByUrl = legacyHistory.byUrl || {};
      for (const [url, value] of Object.entries(legacyByUrl)) {
        const normalizedUrl = this.normalizeHttpUrl(url);
        if (!normalizedUrl) continue;
        const existing = this.writeupHistoryStore.byUrl[normalizedUrl];
        if (!existing) {
          this.writeupHistoryStore.byUrl[normalizedUrl] = value;
          changed = true;
          continue;
        }
        const existingAttempt = Date.parse(existing.lastAttemptAt || existing.firstSeenAt || '') || 0;
        const incomingAttempt = Date.parse(value?.lastAttemptAt || value?.firstSeenAt || '') || 0;
        if (incomingAttempt >= existingAttempt) {
          this.writeupHistoryStore.byUrl[normalizedUrl] = {
            ...existing,
            ...value,
            url: normalizedUrl
          };
          changed = true;
        }
      }

      const legacyByFingerprint = legacyHistory.byFingerprint || {};
      for (const [fingerprint, value] of Object.entries(legacyByFingerprint)) {
        const existing = this.writeupHistoryStore.byFingerprint[fingerprint];
        if (!existing) {
          this.writeupHistoryStore.byFingerprint[fingerprint] = value;
          changed = true;
          continue;
        }
        const combinedUrls = this.uniqueStrings([
          ...(Array.isArray(existing.seenUrls) ? existing.seenUrls : []),
          ...(Array.isArray(value?.seenUrls) ? value.seenUrls : [])
        ]);
        this.writeupHistoryStore.byFingerprint[fingerprint] = {
          ...existing,
          ...value,
          seenUrls: combinedUrls,
          seenCount: combinedUrls.length,
          primaryUrl: existing.primaryUrl || value?.primaryUrl || combinedUrls[0] || null
        };
        changed = true;
      }
    }

    if (changed) {
      this.feedbackStore.updatedAt = new Date().toISOString();
      this.writeupStore.updatedAt = new Date().toISOString();
      this.writeupHistoryStore.updatedAt = new Date().toISOString();
      await this.saveJson(this.feedbackPath, this.feedbackStore);
      await this.saveJson(this.writeupRulesPath, this.writeupStore);
      await this.saveJson(this.writeupHistoryPath, this.writeupHistoryStore);
    }
  }

  async pathExists(targetPath) {
    try {
      await fs.access(targetPath);
      return true;
    } catch {
      return false;
    }
  }

  async readJsonOrNull(filePath) {
    try {
      const raw = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async readOrCreateJson(filePath, fallback) {
    try {
      const raw = await fs.readFile(filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Invalid JSON content');
      }
      return parsed;
    } catch {
      const clone = JSON.parse(JSON.stringify(fallback));
      await this.saveJson(filePath, clone);
      return clone;
    }
  }

  async saveJson(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }
}

const learningEngine = new LearningEngine();
export default learningEngine;
