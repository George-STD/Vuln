/**
 * Distributed Scanning Workers Manager
 * Supports multiple scanner workers for parallel/distributed scanning
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import os from 'os';

/**
 * Worker Status
 */
export const WORKER_STATUS = {
  IDLE: 'idle',
  BUSY: 'busy',
  OFFLINE: 'offline',
  ERROR: 'error',
  STARTING: 'starting',
  STOPPING: 'stopping'
};

/**
 * Task Status
 */
export const TASK_STATUS = {
  PENDING: 'pending',
  ASSIGNED: 'assigned',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled'
};

/**
 * Worker Node
 */
export class Worker {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.name = data.name || `Worker-${this.id.substring(0, 8)}`;
    this.host = data.host || 'localhost';
    this.port = data.port || 4000;
    this.status = data.status || WORKER_STATUS.OFFLINE;
    this.capabilities = data.capabilities || ['all'];
    this.maxConcurrentScans = data.maxConcurrentScans || 5;
    this.currentScans = 0;
    this.totalScansCompleted = 0;
    this.lastHeartbeat = null;
    this.metadata = data.metadata || {};
    this.registeredAt = data.registeredAt || new Date().toISOString();
    
    // System info
    this.systemInfo = {
      cpus: data.systemInfo?.cpus || 0,
      memory: data.systemInfo?.memory || 0,
      platform: data.systemInfo?.platform || '',
      nodeVersion: data.systemInfo?.nodeVersion || ''
    };
    
    // Performance metrics
    this.metrics = {
      avgScanTime: 0,
      successRate: 100,
      lastError: null,
      scanHistory: []
    };
  }

  isAvailable() {
    return this.status === WORKER_STATUS.IDLE && 
           this.currentScans < this.maxConcurrentScans;
  }

  canHandle(scanType) {
    return this.capabilities.includes('all') || 
           this.capabilities.includes(scanType);
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      host: this.host,
      port: this.port,
      status: this.status,
      capabilities: this.capabilities,
      currentScans: this.currentScans,
      maxConcurrentScans: this.maxConcurrentScans,
      totalScansCompleted: this.totalScansCompleted,
      lastHeartbeat: this.lastHeartbeat,
      systemInfo: this.systemInfo,
      metrics: {
        avgScanTime: this.metrics.avgScanTime,
        successRate: this.metrics.successRate
      }
    };
  }
}

/**
 * Scan Task
 */
export class ScanTask {
  constructor(data) {
    this.id = data.id || uuidv4();
    this.scanId = data.scanId;
    this.tenantId = data.tenantId;
    this.targetUrl = data.targetUrl;
    this.scanType = data.scanType || 'full';
    this.options = data.options || {};
    this.status = data.status || TASK_STATUS.PENDING;
    this.priority = data.priority || 5; // 1 (highest) - 10 (lowest)
    this.assignedWorker = null;
    this.createdAt = new Date().toISOString();
    this.startedAt = null;
    this.completedAt = null;
    this.result = null;
    this.error = null;
    this.retries = 0;
    this.maxRetries = data.maxRetries || 3;
  }

  toJSON() {
    return {
      id: this.id,
      scanId: this.scanId,
      tenantId: this.tenantId,
      targetUrl: this.targetUrl,
      scanType: this.scanType,
      status: this.status,
      priority: this.priority,
      assignedWorker: this.assignedWorker,
      createdAt: this.createdAt,
      startedAt: this.startedAt,
      completedAt: this.completedAt,
      retries: this.retries
    };
  }
}

/**
 * Worker Manager
 */
export class WorkerManager extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      heartbeatInterval: options.heartbeatInterval || 30000, // 30 seconds
      heartbeatTimeout: options.heartbeatTimeout || 90000, // 90 seconds
      taskTimeout: options.taskTimeout || 3600000, // 1 hour
      ...options
    };
    
    this.workers = new Map();
    this.taskQueue = [];
    this.activeTasks = new Map();
    this.isRunning = false;
    this.processInterval = null;
  }

  /**
   * Start the worker manager
   */
  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    
    // Process queue periodically
    this.processInterval = setInterval(() => {
      this.processQueue();
      this.checkWorkerHealth();
      this.checkTaskTimeouts();
    }, 5000);
    
    // Register local worker if no workers exist
    if (this.workers.size === 0) {
      this.registerLocalWorker();
    }
    
    this.emit('started');
  }

  /**
   * Stop the worker manager
   */
  stop() {
    if (!this.isRunning) return;
    
    this.isRunning = false;
    
    if (this.processInterval) {
      clearInterval(this.processInterval);
      this.processInterval = null;
    }
    
    this.emit('stopped');
  }

  /**
   * Register local worker (this machine)
   */
  registerLocalWorker() {
    const cpus = os.cpus();
    const totalMemory = os.totalmem();
    
    const worker = new Worker({
      id: 'local',
      name: 'Local Worker',
      host: 'localhost',
      port: 0, // Local, no port needed
      status: WORKER_STATUS.IDLE,
      capabilities: ['all'],
      maxConcurrentScans: Math.max(2, cpus.length - 1),
      systemInfo: {
        cpus: cpus.length,
        memory: totalMemory,
        platform: os.platform(),
        nodeVersion: process.version
      }
    });
    
    worker.lastHeartbeat = new Date().toISOString();
    this.workers.set(worker.id, worker);
    
    this.emit('worker:registered', worker);
    return worker;
  }

  /**
   * Register remote worker
   */
  registerWorker(data) {
    const worker = new Worker(data);
    worker.lastHeartbeat = new Date().toISOString();
    worker.status = WORKER_STATUS.IDLE;
    
    this.workers.set(worker.id, worker);
    this.emit('worker:registered', worker);
    
    return worker;
  }

  /**
   * Unregister worker
   */
  unregisterWorker(workerId) {
    const worker = this.workers.get(workerId);
    if (!worker) return false;
    
    // Reassign any active tasks
    for (const [taskId, task] of this.activeTasks.entries()) {
      if (task.assignedWorker === workerId) {
        task.status = TASK_STATUS.PENDING;
        task.assignedWorker = null;
        this.taskQueue.unshift(task); // Add back to front of queue
        this.activeTasks.delete(taskId);
      }
    }
    
    this.workers.delete(workerId);
    this.emit('worker:unregistered', worker);
    
    return true;
  }

  /**
   * Handle worker heartbeat
   */
  heartbeat(workerId, data = {}) {
    const worker = this.workers.get(workerId);
    if (!worker) return false;
    
    worker.lastHeartbeat = new Date().toISOString();
    worker.status = data.status || WORKER_STATUS.IDLE;
    worker.currentScans = data.currentScans || 0;
    
    if (data.systemInfo) {
      worker.systemInfo = data.systemInfo;
    }
    
    this.emit('worker:heartbeat', worker);
    return true;
  }

  /**
   * Submit scan task
   */
  submitTask(taskData) {
    const task = new ScanTask(taskData);
    
    // Insert based on priority
    const insertIndex = this.taskQueue.findIndex(t => t.priority > task.priority);
    if (insertIndex === -1) {
      this.taskQueue.push(task);
    } else {
      this.taskQueue.splice(insertIndex, 0, task);
    }
    
    this.emit('task:submitted', task);
    
    // Immediately try to process
    this.processQueue();
    
    return task;
  }

  /**
   * Process task queue
   */
  async processQueue() {
    if (this.taskQueue.length === 0) return;
    
    // Get available workers
    const availableWorkers = Array.from(this.workers.values())
      .filter(w => w.isAvailable())
      .sort((a, b) => a.currentScans - b.currentScans);
    
    if (availableWorkers.length === 0) return;
    
    // Assign tasks to workers
    for (const worker of availableWorkers) {
      if (this.taskQueue.length === 0) break;
      
      // Find suitable task for this worker
      const taskIndex = this.taskQueue.findIndex(t => 
        t.status === TASK_STATUS.PENDING && worker.canHandle(t.scanType)
      );
      
      if (taskIndex === -1) continue;
      
      const task = this.taskQueue.splice(taskIndex, 1)[0];
      await this.assignTaskToWorker(task, worker);
    }
  }

  /**
   * Assign task to worker
   */
  async assignTaskToWorker(task, worker) {
    task.status = TASK_STATUS.ASSIGNED;
    task.assignedWorker = worker.id;
    task.startedAt = new Date().toISOString();
    
    worker.currentScans++;
    if (worker.currentScans >= worker.maxConcurrentScans) {
      worker.status = WORKER_STATUS.BUSY;
    }
    
    this.activeTasks.set(task.id, task);
    this.emit('task:assigned', { task, worker });
    
    // If local worker, execute directly
    if (worker.id === 'local') {
      this.executeLocalTask(task);
    } else {
      // Send to remote worker
      await this.sendTaskToRemoteWorker(task, worker);
    }
  }

  /**
   * Execute task on local worker
   */
  async executeLocalTask(task) {
    task.status = TASK_STATUS.RUNNING;
    this.emit('task:started', task);
    
    try {
      // Dynamic import to avoid circular dependency
      const { VulnerabilityScanner } = await import('../scanner/VulnerabilityScanner.js');
      
      const scanner = new VulnerabilityScanner(task.targetUrl, {
        ...task.options,
        scanId: task.scanId,
        onProgress: (progress) => {
          this.emit('task:progress', { task, progress });
        },
        onVulnerability: (vuln) => {
          this.emit('task:vulnerability', { task, vulnerability: vuln });
        }
      });
      
      const results = await scanner.scan();
      
      this.completeTask(task.id, results);
    } catch (error) {
      this.failTask(task.id, error.message);
    }
  }

  /**
   * Send task to remote worker
   */
  async sendTaskToRemoteWorker(task, worker) {
    try {
      const response = await fetch(`http://${worker.host}:${worker.port}/api/worker/task`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(task)
      });
      
      if (!response.ok) {
        throw new Error(`Worker responded with ${response.status}`);
      }
      
      task.status = TASK_STATUS.RUNNING;
      this.emit('task:started', task);
    } catch (error) {
      // Reassign task
      this.failTask(task.id, error.message, true);
    }
  }

  /**
   * Complete task
   */
  completeTask(taskId, result) {
    const task = this.activeTasks.get(taskId);
    if (!task) return;
    
    task.status = TASK_STATUS.COMPLETED;
    task.completedAt = new Date().toISOString();
    task.result = result;
    
    // Update worker
    const worker = this.workers.get(task.assignedWorker);
    if (worker) {
      worker.currentScans = Math.max(0, worker.currentScans - 1);
      worker.totalScansCompleted++;
      if (worker.currentScans < worker.maxConcurrentScans) {
        worker.status = WORKER_STATUS.IDLE;
      }
      
      // Update metrics
      const scanTime = new Date(task.completedAt) - new Date(task.startedAt);
      worker.metrics.scanHistory.push({
        taskId: task.id,
        duration: scanTime,
        success: true
      });
      
      // Keep last 100 scans
      if (worker.metrics.scanHistory.length > 100) {
        worker.metrics.scanHistory.shift();
      }
      
      // Calculate average scan time
      const successfulScans = worker.metrics.scanHistory.filter(s => s.success);
      worker.metrics.avgScanTime = successfulScans.reduce((sum, s) => sum + s.duration, 0) / successfulScans.length;
      worker.metrics.successRate = (successfulScans.length / worker.metrics.scanHistory.length) * 100;
    }
    
    this.activeTasks.delete(taskId);
    this.emit('task:completed', task);
    
    // Process more tasks
    this.processQueue();
  }

  /**
   * Fail task
   */
  failTask(taskId, error, shouldRetry = false) {
    const task = this.activeTasks.get(taskId);
    if (!task) return;
    
    // Update worker
    const worker = this.workers.get(task.assignedWorker);
    if (worker) {
      worker.currentScans = Math.max(0, worker.currentScans - 1);
      worker.metrics.lastError = error;
      worker.metrics.scanHistory.push({
        taskId: task.id,
        duration: 0,
        success: false,
        error
      });
      
      if (worker.currentScans < worker.maxConcurrentScans) {
        worker.status = WORKER_STATUS.IDLE;
      }
    }
    
    // Retry logic
    if (shouldRetry && task.retries < task.maxRetries) {
      task.retries++;
      task.status = TASK_STATUS.PENDING;
      task.assignedWorker = null;
      this.activeTasks.delete(taskId);
      this.taskQueue.unshift(task);
      this.emit('task:retrying', task);
    } else {
      task.status = TASK_STATUS.FAILED;
      task.completedAt = new Date().toISOString();
      task.error = error;
      this.activeTasks.delete(taskId);
      this.emit('task:failed', task);
    }
    
    // Process more tasks
    this.processQueue();
  }

  /**
   * Cancel task
   */
  cancelTask(taskId) {
    // Check in queue first
    const queueIndex = this.taskQueue.findIndex(t => t.id === taskId);
    if (queueIndex !== -1) {
      const task = this.taskQueue.splice(queueIndex, 1)[0];
      task.status = TASK_STATUS.CANCELLED;
      this.emit('task:cancelled', task);
      return true;
    }
    
    // Check active tasks
    const task = this.activeTasks.get(taskId);
    if (task) {
      task.status = TASK_STATUS.CANCELLED;
      
      const worker = this.workers.get(task.assignedWorker);
      if (worker) {
        worker.currentScans = Math.max(0, worker.currentScans - 1);
        if (worker.currentScans < worker.maxConcurrentScans) {
          worker.status = WORKER_STATUS.IDLE;
        }
      }
      
      this.activeTasks.delete(taskId);
      this.emit('task:cancelled', task);
      return true;
    }
    
    return false;
  }

  /**
   * Check worker health
   */
  checkWorkerHealth() {
    const now = Date.now();
    
    for (const worker of this.workers.values()) {
      if (worker.id === 'local') {
        worker.lastHeartbeat = new Date().toISOString();
        continue;
      }
      
      const lastHeartbeat = new Date(worker.lastHeartbeat).getTime();
      if (now - lastHeartbeat > this.options.heartbeatTimeout) {
        worker.status = WORKER_STATUS.OFFLINE;
        this.emit('worker:offline', worker);
      }
    }
  }

  /**
   * Check for task timeouts
   */
  checkTaskTimeouts() {
    const now = Date.now();
    
    for (const [taskId, task] of this.activeTasks.entries()) {
      if (task.status === TASK_STATUS.RUNNING) {
        const startedAt = new Date(task.startedAt).getTime();
        if (now - startedAt > this.options.taskTimeout) {
          this.failTask(taskId, 'Task timeout', true);
        }
      }
    }
  }

  /**
   * Get worker by ID
   */
  getWorker(id) {
    return this.workers.get(id);
  }

  /**
   * List all workers
   */
  listWorkers() {
    return Array.from(this.workers.values()).map(w => w.toJSON());
  }

  /**
   * Get task by ID
   */
  getTask(id) {
    return this.activeTasks.get(id) || this.taskQueue.find(t => t.id === id);
  }

  /**
   * Get queue status
   */
  getQueueStatus() {
    return {
      pending: this.taskQueue.length,
      active: this.activeTasks.size,
      workers: {
        total: this.workers.size,
        available: Array.from(this.workers.values()).filter(w => w.isAvailable()).length,
        busy: Array.from(this.workers.values()).filter(w => w.status === WORKER_STATUS.BUSY).length,
        offline: Array.from(this.workers.values()).filter(w => w.status === WORKER_STATUS.OFFLINE).length
      }
    };
  }
}

export const workerManager = new WorkerManager();

export default {
  WORKER_STATUS,
  TASK_STATUS,
  Worker,
  ScanTask,
  WorkerManager,
  workerManager
};
