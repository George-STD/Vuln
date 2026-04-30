import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { Server } from 'socket.io';
import { createServer } from 'http';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs/promises';

import { VulnerabilityScanner } from './scanner/VulnerabilityScanner.js';
import reportGenerator from './utils/ReportGenerator.js';
import logger from './utils/Logger.js';
import { OwnershipVerifier } from './utils/OwnershipVerifier.js';
import { SARIFExporter } from './utils/SARIFExporter.js';
import { OpenAPIImporter } from './scanner/modules/OpenAPIImporter.js';
import { ScanScheduler } from './scanner/modules/ScanScheduler.js';
import learningEngine from './scanner/LearningEngine.js';
import { WriteupAutoLearner } from './scanner/WriteupAutoLearner.js';

// Enterprise modules
import enterpriseRoutes from './routes/enterprise.js';
import { workerManager } from './workers/WorkerManager.js';
import { auditLogger, AUDIT_EVENTS } from './audit/AuditLogger.js';
import { pluginManager } from './plugins/PluginSystem.js';
import { integrationManager } from './integrations/index.js';

// Bug Bounty modules
import bountyRoutes from './routes/bounty.js';
import bountySystem, { killSwitch } from './bounty/index.js';

dotenv.config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:5173"
}));
app.use(express.json({ limit: '10mb' }));

// Store active scans
const activeScans = new Map();

// Initialize scheduler
const scheduler = new ScanScheduler({ io });
scheduler.initialize();

// Initialize ownership verifier
const ownershipVerifier = new OwnershipVerifier();

// Initialize SARIF exporter
const sarifExporter = new SARIFExporter();

// Initialize automatic write-up learner
const writeupAutoLearner = new WriteupAutoLearner({
  learningEngine,
  enabled: process.env.AUTO_LEARN_WRITEUPS_ENABLED !== 'false',
  intervalMs: Number(process.env.AUTO_LEARN_INTERVAL_MS || 60000),
  discoveryIntervalMs: Number(process.env.AUTO_LEARN_DISCOVERY_INTERVAL_MS || 600000),
  maxRulesPerLink: Number(process.env.AUTO_LEARN_MAX_RULES_PER_LINK || 4),
  maxPerSource: Number(process.env.AUTO_LEARN_MAX_PER_SOURCE || 40),
  onLog: (entry) => {
    const message = entry?.message || 'Writeup auto learner event';
    const type = entry?.type || 'info';
    if (typeof logger[type] === 'function') {
      logger[type](message);
    } else {
      logger.info(message);
    }
  }
});

// Initialize enterprise modules
(async () => {
  try {
    await pluginManager.init();
    workerManager.start();
    await writeupAutoLearner.start();
    await auditLogger.logSystem(AUDIT_EVENTS.SYSTEM_STARTUP, { version: '2.0.0' });
    logger.info('Enterprise modules initialized');
    logger.info('Bug Bounty safety system ready');
  } catch (error) {
    logger.error('Failed to initialize enterprise modules:', error);
  }
})();

// Enterprise API routes
app.use('/api/enterprise', enterpriseRoutes);

// Bug Bounty API routes
app.use('/api/bounty', bountyRoutes);

// Initialize OpenAPI importer
const openAPIImporter = new OpenAPIImporter();

// API Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    version: '1.0.0',
    name: 'VulnHunter Pro',
    activeScans: activeScans.size
  });
});

app.get('/api/learning/status', async (req, res) => {
  try {
    await learningEngine.initialize();
    res.json(learningEngine.getStatus());
  } catch (error) {
    res.status(500).json({ error: `Failed to load learning status: ${error.message}` });
  }
});

app.get('/api/learning/writeups', async (req, res) => {
  try {
    await learningEngine.initialize();
    res.json({
      rules: learningEngine.listWriteupRules(),
      status: learningEngine.getStatus()
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to load write-up rules: ${error.message}` });
  }
});

app.post('/api/learning/writeups/import', async (req, res) => {
  try {
    const rules = Array.isArray(req.body?.rules) ? req.body.rules : [];
    if (rules.length === 0) {
      return res.status(400).json({ error: 'rules array is required' });
    }

    const result = await learningEngine.importWriteupRules({ rules });
    res.json({
      message: 'Write-up rules imported successfully',
      ...result
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to import write-up rules: ${error.message}` });
  }
});

app.post('/api/learning/writeups/import-links', async (req, res) => {
  try {
    const links = Array.isArray(req.body?.links) ? req.body.links : [];
    if (links.length === 0) {
      return res.status(400).json({ error: 'links array is required' });
    }

    const result = await learningEngine.importWriteupLinks({
      links,
      maxLinks: req.body?.maxLinks,
      options: req.body?.options || {}
    });

    res.json({
      message: 'Write-up links processed successfully',
      ...result
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to import write-up links: ${error.message}` });
  }
});

app.post('/api/learning/feedback', async (req, res) => {
  try {
    const { verdict, notes, vulnerability, fingerprint } = req.body || {};
    if (!verdict) {
      return res.status(400).json({ error: 'verdict is required (true_positive or false_positive)' });
    }
    if (!fingerprint && !vulnerability) {
      return res.status(400).json({ error: 'fingerprint or vulnerability object is required' });
    }

    const result = await learningEngine.recordFeedback({
      verdict,
      notes,
      fingerprint,
      vulnerability
    });

    res.json({
      message: 'Feedback recorded successfully',
      ...result
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to record feedback: ${error.message}` });
  }
});

app.post('/api/learning/cleanup', async (req, res) => {
  try {
    await learningEngine.initialize();
    const cleanup = await learningEngine.cleanupWriteupRules({
      dryRun: req.body?.dryRun === true,
      minRuleScore: req.body?.minRuleScore,
      reason: 'api_manual'
    });

    res.json({
      message: cleanup.dryRun ? 'Learning cleanup preview completed' : 'Learning cleanup completed',
      cleanup,
      status: learningEngine.getStatus()
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to cleanup learning data: ${error.message}` });
  }
});

app.get('/api/learning/auto/status', async (req, res) => {
  try {
    await learningEngine.initialize();
    res.json({
      autoLearner: writeupAutoLearner.getStatus(),
      learning: learningEngine.getStatus()
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to read auto learner status: ${error.message}` });
  }
});

app.post('/api/learning/auto/start', async (req, res) => {
  try {
    const status = await writeupAutoLearner.start({ force: true });
    res.json({
      message: 'Automatic write-up learning started',
      status
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to start auto learner: ${error.message}` });
  }
});

app.post('/api/learning/auto/stop', async (req, res) => {
  try {
    const status = await writeupAutoLearner.stop();
    res.json({
      message: 'Automatic write-up learning stopped',
      status
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to stop auto learner: ${error.message}` });
  }
});

app.post('/api/learning/auto/tick', async (req, res) => {
  try {
    const status = await writeupAutoLearner.tick();
    res.json({
      message: 'Auto learner tick executed',
      status
    });
  } catch (error) {
    res.status(500).json({ error: `Auto learner tick failed: ${error.message}` });
  }
});

app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body;
    const options = (req.body.options && typeof req.body.options === 'object')
      ? req.body.options
      : (() => {
          const legacyOptions = { ...req.body };
          delete legacyOptions.url;
          return legacyOptions;
        })();
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Validate URL
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const scanId = uuidv4();
    
    res.json({ 
      scanId, 
      message: 'Scan initiated',
      status: 'started'
    });

    // Start scanning in background
    startScan(scanId, url, options);
    
  } catch (error) {
    logger.error('Scan initiation error:', error);
    res.status(500).json({ error: 'Failed to initiate scan' });
  }
});

app.get('/api/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scan = activeScans.get(scanId);
  
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  
  res.json(scan);
});

app.get('/api/scan/:scanId/report', async (req, res) => {
  const { scanId } = req.params;
  const scan = activeScans.get(scanId);
  
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  
  if (scan.status !== 'completed') {
    return res.status(400).json({ error: 'Scan not completed yet' });
  }
  
  const { format = 'html' } = req.query;
  const report = await reportGenerator.generateReport(scan, format);
  
  res.json(report);
});

app.post('/api/scan/:scanId/stop', (req, res) => {
  const { scanId } = req.params;
  const scan = activeScans.get(scanId);
  
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  
  if (scan.scanner) {
    scan.scanner.stop();
  }
  
  scan.status = 'stopped';
  io.emit(`scan:${scanId}`, { type: 'stopped', data: scan });
  
  res.json({ message: 'Scan stopped' });
});

// ============ Ownership Verification APIs ============

// Generate verification token
app.post('/api/verify/generate', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const token = await ownershipVerifier.generateToken(url);
    res.json({ 
      token, 
      methods: {
        dns: {
          type: 'TXT Record',
          name: `_vulnhunter.${new URL(url).hostname}`,
          value: token
        },
        http: {
          type: 'HTTP File',
          path: '/.well-known/vulnhunter-verify.txt',
          content: token
        }
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify domain ownership
app.post('/api/verify/check', async (req, res) => {
  try {
    const { url, method = 'http' } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const result = await ownershipVerifier.verify(url, method);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message, verified: false });
  }
});

// ============ SARIF Export API ============

app.get('/api/scan/:scanId/sarif', async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = activeScans.get(scanId);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    if (scan.status !== 'completed') {
      return res.status(400).json({ error: 'Scan not completed yet' });
    }
    
    const sarif = sarifExporter.export({
      vulnerabilities: scan.vulnerabilities,
      summary: scan.results?.summary
    }, scan.url);
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=scan-${scanId}.sarif`);
    res.json(sarif);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ Walkthrough PDF Export API ============

app.get('/api/scan/:scanId/walkthrough', async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = activeScans.get(scanId);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    if (scan.status !== 'completed') {
      return res.status(400).json({ error: 'Scan not completed yet' });
    }
    
    const result = await reportGenerator.generateReport({
      vulnerabilities: scan.vulnerabilities,
      targetUrl: scan.url,
      completedAt: scan.endTime,
      summary: scan.results?.summary
    }, 'walkthrough', `walkthrough-${scanId}`);
    
    // Read the PDF file
    const pdfPath = result.path;
    const pdfBuffer = await fs.readFile(pdfPath);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=walkthrough-${scanId}.pdf`);
    res.send(pdfBuffer);
    
  } catch (error) {
    logger.error('Walkthrough PDF generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate walkthrough from JSON body (for external use)
app.post('/api/walkthrough/generate', async (req, res) => {
  try {
    const { vulnerabilities, targetUrl, scanId } = req.body;
    
    if (!vulnerabilities || !Array.isArray(vulnerabilities)) {
      return res.status(400).json({ error: 'vulnerabilities array is required' });
    }
    
    const result = await reportGenerator.generateReport({
      vulnerabilities,
      targetUrl: targetUrl || 'Unknown Target',
      completedAt: new Date().toISOString()
    }, 'walkthrough', `walkthrough-${scanId || Date.now()}`);
    
    const pdfBuffer = await fs.readFile(result.path);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=${result.filename}`);
    res.send(pdfBuffer);
    
  } catch (error) {
    logger.error('Walkthrough generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============ OpenAPI Import API ============

app.post('/api/openapi/import', async (req, res) => {
  try {
    const { specUrl, specContent } = req.body;
    
    if (!specUrl && !specContent) {
      return res.status(400).json({ error: 'OpenAPI spec URL or content is required' });
    }

    const source = specUrl || specContent;
    const result = await openAPIImporter.import(source);
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/openapi/discover', async (req, res) => {
  try {
    const { baseUrl } = req.body;
    
    if (!baseUrl) {
      return res.status(400).json({ error: 'Base URL is required' });
    }

    const result = await openAPIImporter.discoverSpec(baseUrl);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ Scheduled Scans APIs ============

app.get('/api/schedules', async (req, res) => {
  try {
    const schedules = await scheduler.getSchedules();
    res.json(schedules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/schedules', async (req, res) => {
  try {
    const schedule = await scheduler.createSchedule(req.body);
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/schedules/presets', (req, res) => {
  res.json(ScanScheduler.getCronPresets());
});

app.get('/api/schedules/:id', async (req, res) => {
  try {
    const schedule = await scheduler.getSchedule(req.params.id);
    
    if (!schedule) {
      return res.status(404).json({ error: 'Schedule not found' });
    }
    
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/schedules/:id', async (req, res) => {
  try {
    const schedule = await scheduler.updateSchedule(req.params.id, req.body);
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/schedules/:id', async (req, res) => {
  try {
    await scheduler.deleteSchedule(req.params.id);
    res.json({ message: 'Schedule deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/schedules/:id/run', async (req, res) => {
  try {
    await scheduler.runNow(req.params.id);
    res.json({ message: 'Scan started' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/schedules/:id/history', async (req, res) => {
  try {
    const history = await scheduler.getJobHistory(req.params.id);
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO for real-time updates
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);
  
  socket.on('join:scan', (scanId) => {
    socket.join(`scan:${scanId}`);
    logger.info(`Client subscribed to scan: ${scanId}`);
  });
  
  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

async function startScan(scanId, url, options) {
  const scanner = new VulnerabilityScanner(url, {
    ...options,
    onProgress: (progress) => {
      const scan = activeScans.get(scanId);
      if (scan) {
        scan.progress = progress;
        io.to(`scan:${scanId}`).emit('scan:progress', progress);
      }
    },
    onVulnerability: (vuln) => {
      const scan = activeScans.get(scanId);
      if (scan) {
        scan.vulnerabilities.push(vuln);
        io.to(`scan:${scanId}`).emit('scan:vulnerability', vuln);
      }
    },
    onLog: (log) => {
      io.to(`scan:${scanId}`).emit('log', log);
    }
  });

  const scanData = {
    id: scanId,
    url,
    options,
    status: 'running',
    progress: 0,
    vulnerabilities: [],
    startTime: new Date().toISOString(),
    scanner
  };

  activeScans.set(scanId, scanData);

  try {
    const results = await scanner.scan();
    
    const scan = activeScans.get(scanId);
    if (scan) {
      scan.status = 'completed';
      scan.results = results;
      scan.endTime = new Date().toISOString();
      scan.progress = 100;
      delete scan.scanner; // Remove scanner instance
      
      io.to(`scan:${scanId}`).emit('scan:complete', { 
        summary: results.summary, 
        vulnerabilities: scan.vulnerabilities,
        wafInfo: results.wafInfo,
        robotsInfo: results.robotsInfo,
        screenshots: results.screenshots
      });
    }
  } catch (error) {
    logger.error(`Scan error for ${scanId}:`, error);
    
    const scan = activeScans.get(scanId);
    if (scan) {
      scan.status = 'error';
      scan.error = error.message;
      scan.endTime = new Date().toISOString();
      delete scan.scanner;
      
      io.to(`scan:${scanId}`).emit('scan:error', { message: error.message });
    }
  }
}

// Cleanup old scans periodically
setInterval(() => {
  const oneHourAgo = Date.now() - 3600000;
  for (const [scanId, scan] of activeScans.entries()) {
    if (new Date(scan.startTime).getTime() < oneHourAgo && scan.status !== 'running') {
      activeScans.delete(scanId);
    }
  }
}, 600000); // Every 10 minutes

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗     ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║     ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║     ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║     ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝     ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝      ║
║                                                              ║
║   🔥 VulnHunter Pro - Advanced Vulnerability Scanner 🔥      ║
║   🎯 Bug Bounty & Penetration Testing Tool                   ║
║   🏢 Enterprise Edition with RBAC & Multi-tenancy            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🚀 Server running on http://localhost:${PORT}
📡 WebSocket enabled for real-time updates
🔒 Security headers enabled
🏢 Enterprise features enabled
  `);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully...');
  await auditLogger.logSystem(AUDIT_EVENTS.SYSTEM_SHUTDOWN, { reason: 'SIGTERM' });
  await writeupAutoLearner.stop({ pause: false });
  workerManager.stop();
  await auditLogger.shutdown();
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully...');
  await auditLogger.logSystem(AUDIT_EVENTS.SYSTEM_SHUTDOWN, { reason: 'SIGINT' });
  await writeupAutoLearner.stop({ pause: false });
  workerManager.stop();
  await auditLogger.shutdown();
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

export default app;
