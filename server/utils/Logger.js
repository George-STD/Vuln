import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, scanId, module }) => {
    const prefix = scanId ? `[${scanId.substring(0, 8)}]` : '';
    const modulePrefix = module ? `[${module}]` : '';
    return `${timestamp} ${level} ${prefix}${modulePrefix} ${message}`;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.json()
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    // Console transport
    new winston.transports.Console({
      format: consoleFormat
    }),
    // File transport for errors
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/error.log'),
      level: 'error',
      format: fileFormat,
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    // File transport for all logs
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/combined.log'),
      format: fileFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 5
    })
  ]
});

// Create scan-specific logger
export function createScanLogger(scanId) {
  return {
    info: (message, meta = {}) => {
      logger.info(message, { scanId, ...meta });
    },
    warn: (message, meta = {}) => {
      logger.warn(message, { scanId, ...meta });
    },
    error: (message, meta = {}) => {
      logger.error(message, { scanId, ...meta });
    },
    debug: (message, meta = {}) => {
      logger.debug(message, { scanId, ...meta });
    },
    module: (moduleName) => ({
      info: (message, meta = {}) => {
        logger.info(message, { scanId, module: moduleName, ...meta });
      },
      warn: (message, meta = {}) => {
        logger.warn(message, { scanId, module: moduleName, ...meta });
      },
      error: (message, meta = {}) => {
        logger.error(message, { scanId, module: moduleName, ...meta });
      },
      debug: (message, meta = {}) => {
        logger.debug(message, { scanId, module: moduleName, ...meta });
      }
    })
  };
}

// Severity color codes for terminal
export const severityColors = {
  critical: '\x1b[91m', // Bright red
  high: '\x1b[31m',     // Red
  medium: '\x1b[33m',   // Yellow
  low: '\x1b[36m',      // Cyan
  info: '\x1b[37m',     // White
  reset: '\x1b[0m'
};

// Format vulnerability for console output
export function formatVulnerability(vuln) {
  const color = severityColors[vuln.severity] || severityColors.info;
  const reset = severityColors.reset;
  
  return `${color}[${vuln.severity.toUpperCase()}]${reset} ${vuln.type}: ${vuln.subType || ''}\n` +
         `   URL: ${vuln.url}\n` +
         `   ${vuln.description}`;
}

// Log vulnerability summary
export function logScanSummary(scanId, results) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  results.vulnerabilities.forEach(v => {
    counts[v.severity] = (counts[v.severity] || 0) + 1;
  });
  
  logger.info('Scan Summary', {
    scanId,
    total: results.vulnerabilities.length,
    ...counts,
    duration: results.summary?.duration
  });
  
  console.log('\n' + '='.repeat(60));
  console.log(`Scan Complete: ${scanId}`);
  console.log('='.repeat(60));
  console.log(`Total Vulnerabilities: ${results.vulnerabilities.length}`);
  console.log(`${severityColors.critical}Critical: ${counts.critical}${severityColors.reset}`);
  console.log(`${severityColors.high}High: ${counts.high}${severityColors.reset}`);
  console.log(`${severityColors.medium}Medium: ${counts.medium}${severityColors.reset}`);
  console.log(`${severityColors.low}Low: ${counts.low}${severityColors.reset}`);
  console.log(`${severityColors.info}Info: ${counts.info}${severityColors.reset}`);
  console.log('='.repeat(60) + '\n');
}

export default logger;
