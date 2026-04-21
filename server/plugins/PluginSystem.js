/**
 * Plugin System
 * Extensible architecture for custom scanner modules and integrations
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';
import { pathToFileURL } from 'url';

/**
 * Plugin Types
 */
export const PLUGIN_TYPES = {
  SCANNER: 'scanner',          // Custom vulnerability scanner
  REPORTER: 'reporter',        // Custom report format
  INTEGRATION: 'integration',  // Third-party integration
  PREPROCESSOR: 'preprocessor', // Pre-scan processing
  POSTPROCESSOR: 'postprocessor', // Post-scan processing
  AUTH_PROVIDER: 'auth_provider', // Authentication provider
  NOTIFICATION: 'notification'  // Notification channel
};

/**
 * Plugin Status
 */
export const PLUGIN_STATUS = {
  INSTALLED: 'installed',
  ENABLED: 'enabled',
  DISABLED: 'disabled',
  ERROR: 'error',
  UPDATING: 'updating'
};

/**
 * Plugin Manifest Schema
 */
export const MANIFEST_SCHEMA = {
  required: ['name', 'version', 'type', 'main'],
  properties: {
    name: { type: 'string' },
    version: { type: 'string' },
    type: { type: 'string', enum: Object.values(PLUGIN_TYPES) },
    main: { type: 'string' },
    description: { type: 'string' },
    author: { type: 'string' },
    homepage: { type: 'string' },
    repository: { type: 'string' },
    license: { type: 'string' },
    engines: { type: 'object' },
    dependencies: { type: 'object' },
    permissions: { type: 'array' },
    config: { type: 'object' },
    hooks: { type: 'array' }
  }
};

/**
 * Plugin Permissions
 */
export const PLUGIN_PERMISSIONS = {
  NETWORK: 'network',           // Make HTTP requests
  FILESYSTEM: 'filesystem',     // Read/write files
  EXEC: 'exec',                 // Execute commands
  DATABASE: 'database',         // Access database
  CREDENTIALS: 'credentials',   // Access credential vault
  NOTIFICATIONS: 'notifications', // Send notifications
  CONFIG: 'config'              // Modify configuration
};

/**
 * Plugin Hooks
 */
export const PLUGIN_HOOKS = {
  // Scan lifecycle
  BEFORE_SCAN: 'beforeScan',
  AFTER_SCAN: 'afterScan',
  ON_SCAN_ERROR: 'onScanError',
  
  // Vulnerability handling
  ON_VULNERABILITY: 'onVulnerability',
  BEFORE_REPORT: 'beforeReport',
  AFTER_REPORT: 'afterReport',
  
  // Target processing
  BEFORE_TARGET: 'beforeTarget',
  AFTER_TARGET: 'afterTarget',
  
  // Authentication
  BEFORE_AUTH: 'beforeAuth',
  AFTER_AUTH: 'afterAuth',
  
  // System
  ON_STARTUP: 'onStartup',
  ON_SHUTDOWN: 'onShutdown'
};

/**
 * Plugin Instance
 */
export class Plugin {
  constructor(manifest) {
    this.id = manifest.id || uuidv4();
    this.name = manifest.name;
    this.version = manifest.version;
    this.type = manifest.type;
    this.description = manifest.description || '';
    this.author = manifest.author || '';
    this.homepage = manifest.homepage || '';
    this.license = manifest.license || 'MIT';
    this.main = manifest.main;
    this.permissions = manifest.permissions || [];
    this.config = manifest.config || {};
    this.hooks = manifest.hooks || [];
    
    this.status = PLUGIN_STATUS.INSTALLED;
    this.installedAt = new Date().toISOString();
    this.updatedAt = this.installedAt;
    this.enabledAt = null;
    this.error = null;
    
    // Runtime
    this.instance = null;
    this.configValues = {};
  }

  hasPermission(permission) {
    return this.permissions.includes(permission);
  }

  hasHook(hook) {
    return this.hooks.includes(hook);
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      version: this.version,
      type: this.type,
      description: this.description,
      author: this.author,
      status: this.status,
      permissions: this.permissions,
      hooks: this.hooks,
      config: this.config,
      configValues: this.configValues,
      installedAt: this.installedAt,
      updatedAt: this.updatedAt,
      enabledAt: this.enabledAt,
      error: this.error
    };
  }
}

/**
 * Plugin Context - Sandbox for plugin execution
 */
export class PluginContext {
  constructor(plugin, options = {}) {
    this.plugin = plugin;
    this.options = options;
    this.logger = this.createLogger();
    this.storage = this.createStorage();
    this.api = this.createAPI();
  }

  createLogger() {
    const prefix = `[Plugin:${this.plugin.name}]`;
    return {
      info: (...args) => console.log(prefix, ...args),
      warn: (...args) => console.warn(prefix, ...args),
      error: (...args) => console.error(prefix, ...args),
      debug: (...args) => console.debug(prefix, ...args)
    };
  }

  createStorage() {
    const storageDir = path.join('./data/plugins', this.plugin.id);
    
    return {
      get: async (key) => {
        try {
          const filePath = path.join(storageDir, `${key}.json`);
          const content = await fs.readFile(filePath, 'utf8');
          return JSON.parse(content);
        } catch {
          return null;
        }
      },
      set: async (key, value) => {
        await fs.mkdir(storageDir, { recursive: true });
        const filePath = path.join(storageDir, `${key}.json`);
        await fs.writeFile(filePath, JSON.stringify(value, null, 2));
      },
      delete: async (key) => {
        try {
          const filePath = path.join(storageDir, `${key}.json`);
          await fs.unlink(filePath);
          return true;
        } catch {
          return false;
        }
      }
    };
  }

  createAPI() {
    const plugin = this.plugin;
    
    return {
      getConfig: (key) => plugin.configValues[key],
      setConfig: (key, value) => {
        plugin.configValues[key] = value;
      },
      hasPermission: (permission) => plugin.hasPermission(permission),
      
      // HTTP helper (if network permission)
      fetch: async (url, options) => {
        if (!plugin.hasPermission(PLUGIN_PERMISSIONS.NETWORK)) {
          throw new Error('Network permission required');
        }
        return fetch(url, options);
      },
      
      // Events
      emit: (event, data) => {
        if (this.options.eventEmitter) {
          this.options.eventEmitter.emit(`plugin:${plugin.id}:${event}`, data);
        }
      }
    };
  }
}

/**
 * Plugin Manager
 */
export class PluginManager extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      pluginsDir: options.pluginsDir || './plugins',
      enableSandbox: options.enableSandbox !== false,
      ...options
    };
    
    this.plugins = new Map();
    this.hookHandlers = new Map(); // hook -> Plugin[]
    
    // Initialize hook handlers map
    for (const hook of Object.values(PLUGIN_HOOKS)) {
      this.hookHandlers.set(hook, []);
    }
  }

  /**
   * Initialize plugin manager
   */
  async init() {
    await fs.mkdir(this.options.pluginsDir, { recursive: true });
    await fs.mkdir('./data/plugins', { recursive: true });
    
    // Load installed plugins
    await this.loadInstalledPlugins();
  }

  /**
   * Load installed plugins
   */
  async loadInstalledPlugins() {
    try {
      const entries = await fs.readdir(this.options.pluginsDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        const pluginDir = path.join(this.options.pluginsDir, entry.name);
        const manifestPath = path.join(pluginDir, 'manifest.json');
        
        try {
          const manifestContent = await fs.readFile(manifestPath, 'utf8');
          const manifest = JSON.parse(manifestContent);
          manifest.id = entry.name;
          
          const plugin = new Plugin(manifest);
          plugin.path = pluginDir;
          
          // Load saved config
          const configPath = path.join(pluginDir, 'config.json');
          try {
            const configContent = await fs.readFile(configPath, 'utf8');
            plugin.configValues = JSON.parse(configContent);
          } catch {}
          
          // Load saved state
          const statePath = path.join(pluginDir, 'state.json');
          try {
            const stateContent = await fs.readFile(statePath, 'utf8');
            const state = JSON.parse(stateContent);
            plugin.status = state.status || PLUGIN_STATUS.INSTALLED;
            plugin.enabledAt = state.enabledAt;
          } catch {}
          
          this.plugins.set(plugin.id, plugin);
          
          // Auto-enable if was enabled
          if (plugin.status === PLUGIN_STATUS.ENABLED) {
            await this.enablePlugin(plugin.id);
          }
        } catch (error) {
          console.error(`Failed to load plugin ${entry.name}:`, error);
        }
      }
    } catch (error) {
      console.error('Failed to load plugins:', error);
    }
  }

  /**
   * Install plugin from directory
   */
  async installFromDirectory(sourcePath) {
    const manifestPath = path.join(sourcePath, 'manifest.json');
    const manifestContent = await fs.readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);
    
    // Validate manifest
    this.validateManifest(manifest);
    
    // Generate plugin ID
    const pluginId = `${manifest.name.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`;
    manifest.id = pluginId;
    
    // Copy to plugins directory
    const destPath = path.join(this.options.pluginsDir, pluginId);
    await fs.cp(sourcePath, destPath, { recursive: true });
    
    // Create plugin instance
    const plugin = new Plugin(manifest);
    plugin.path = destPath;
    
    this.plugins.set(pluginId, plugin);
    
    // Save state
    await this.savePluginState(plugin);
    
    this.emit('plugin:installed', plugin);
    
    return plugin.toJSON();
  }

  /**
   * Install plugin from code (for dynamic plugins)
   */
  async installFromCode(manifest, code) {
    // Validate manifest
    this.validateManifest(manifest);
    
    const pluginId = `${manifest.name.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`;
    manifest.id = pluginId;
    
    // Create plugin directory
    const pluginDir = path.join(this.options.pluginsDir, pluginId);
    await fs.mkdir(pluginDir, { recursive: true });
    
    // Write manifest
    await fs.writeFile(
      path.join(pluginDir, 'manifest.json'),
      JSON.stringify(manifest, null, 2)
    );
    
    // Write main file
    await fs.writeFile(path.join(pluginDir, manifest.main), code);
    
    // Create plugin instance
    const plugin = new Plugin(manifest);
    plugin.path = pluginDir;
    
    this.plugins.set(pluginId, plugin);
    
    // Save state
    await this.savePluginState(plugin);
    
    this.emit('plugin:installed', plugin);
    
    return plugin.toJSON();
  }

  /**
   * Validate plugin manifest
   */
  validateManifest(manifest) {
    for (const field of MANIFEST_SCHEMA.required) {
      if (!manifest[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
    
    if (!Object.values(PLUGIN_TYPES).includes(manifest.type)) {
      throw new Error(`Invalid plugin type: ${manifest.type}`);
    }
    
    // Validate permissions
    if (manifest.permissions) {
      for (const perm of manifest.permissions) {
        if (!Object.values(PLUGIN_PERMISSIONS).includes(perm)) {
          throw new Error(`Invalid permission: ${perm}`);
        }
      }
    }
    
    // Validate hooks
    if (manifest.hooks) {
      for (const hook of manifest.hooks) {
        if (!Object.values(PLUGIN_HOOKS).includes(hook)) {
          throw new Error(`Invalid hook: ${hook}`);
        }
      }
    }
    
    return true;
  }

  /**
   * Enable plugin
   */
  async enablePlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) {
      throw new Error('Plugin not found');
    }
    
    try {
      // Load plugin module
      const mainPath = path.join(plugin.path, plugin.main);
      const moduleUrl = pathToFileURL(mainPath).href;
      const module = await import(moduleUrl);
      
      // Create context
      const context = new PluginContext(plugin, { eventEmitter: this });
      
      // Initialize plugin
      if (module.default && typeof module.default === 'function') {
        plugin.instance = new module.default(context);
      } else if (module.init && typeof module.init === 'function') {
        plugin.instance = await module.init(context);
      } else {
        plugin.instance = module;
      }
      
      // Register hooks
      for (const hook of plugin.hooks) {
        const handlers = this.hookHandlers.get(hook) || [];
        handlers.push(plugin);
        this.hookHandlers.set(hook, handlers);
      }
      
      // Call onStartup hook
      if (plugin.hasHook(PLUGIN_HOOKS.ON_STARTUP) && plugin.instance.onStartup) {
        await plugin.instance.onStartup();
      }
      
      plugin.status = PLUGIN_STATUS.ENABLED;
      plugin.enabledAt = new Date().toISOString();
      plugin.error = null;
      
      await this.savePluginState(plugin);
      
      this.emit('plugin:enabled', plugin);
      
      return plugin.toJSON();
    } catch (error) {
      plugin.status = PLUGIN_STATUS.ERROR;
      plugin.error = error.message;
      await this.savePluginState(plugin);
      throw error;
    }
  }

  /**
   * Disable plugin
   */
  async disablePlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) {
      throw new Error('Plugin not found');
    }
    
    // Call onShutdown hook
    if (plugin.instance && plugin.hasHook(PLUGIN_HOOKS.ON_SHUTDOWN) && plugin.instance.onShutdown) {
      try {
        await plugin.instance.onShutdown();
      } catch (error) {
        console.error(`Plugin ${plugin.name} shutdown error:`, error);
      }
    }
    
    // Unregister hooks
    for (const hook of plugin.hooks) {
      const handlers = this.hookHandlers.get(hook) || [];
      const index = handlers.indexOf(plugin);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
    
    plugin.instance = null;
    plugin.status = PLUGIN_STATUS.DISABLED;
    plugin.enabledAt = null;
    
    await this.savePluginState(plugin);
    
    this.emit('plugin:disabled', plugin);
    
    return plugin.toJSON();
  }

  /**
   * Uninstall plugin
   */
  async uninstallPlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) {
      throw new Error('Plugin not found');
    }
    
    // Disable first
    if (plugin.status === PLUGIN_STATUS.ENABLED) {
      await this.disablePlugin(pluginId);
    }
    
    // Remove files
    await fs.rm(plugin.path, { recursive: true, force: true });
    
    // Remove plugin data
    const dataDir = path.join('./data/plugins', pluginId);
    await fs.rm(dataDir, { recursive: true, force: true });
    
    this.plugins.delete(pluginId);
    
    this.emit('plugin:uninstalled', plugin);
    
    return true;
  }

  /**
   * Save plugin state
   */
  async savePluginState(plugin) {
    const statePath = path.join(plugin.path, 'state.json');
    await fs.writeFile(statePath, JSON.stringify({
      status: plugin.status,
      enabledAt: plugin.enabledAt,
      updatedAt: new Date().toISOString()
    }, null, 2));
    
    const configPath = path.join(plugin.path, 'config.json');
    await fs.writeFile(configPath, JSON.stringify(plugin.configValues, null, 2));
  }

  /**
   * Update plugin configuration
   */
  async updateConfig(pluginId, config) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) {
      throw new Error('Plugin not found');
    }
    
    plugin.configValues = { ...plugin.configValues, ...config };
    await this.savePluginState(plugin);
    
    // Notify plugin of config change
    if (plugin.instance && plugin.instance.onConfigChange) {
      await plugin.instance.onConfigChange(config);
    }
    
    return plugin.toJSON();
  }

  /**
   * Execute hook
   */
  async executeHook(hook, data) {
    const handlers = this.hookHandlers.get(hook) || [];
    const results = [];
    
    for (const plugin of handlers) {
      if (plugin.status !== PLUGIN_STATUS.ENABLED || !plugin.instance) {
        continue;
      }
      
      const hookMethod = plugin.instance[hook];
      if (typeof hookMethod !== 'function') {
        continue;
      }
      
      try {
        const result = await hookMethod.call(plugin.instance, data);
        results.push({
          plugin: plugin.name,
          success: true,
          result
        });
        
        // Allow plugins to modify data
        if (result !== undefined) {
          data = result;
        }
      } catch (error) {
        results.push({
          plugin: plugin.name,
          success: false,
          error: error.message
        });
        
        this.emit('plugin:error', { plugin, hook, error });
      }
    }
    
    return { data, results };
  }

  /**
   * Get plugin by ID
   */
  getPlugin(pluginId) {
    const plugin = this.plugins.get(pluginId);
    return plugin ? plugin.toJSON() : null;
  }

  /**
   * List all plugins
   */
  listPlugins(filters = {}) {
    let plugins = Array.from(this.plugins.values());
    
    if (filters.type) {
      plugins = plugins.filter(p => p.type === filters.type);
    }
    
    if (filters.status) {
      plugins = plugins.filter(p => p.status === filters.status);
    }
    
    return plugins.map(p => p.toJSON());
  }

  /**
   * Get plugins by type
   */
  getPluginsByType(type) {
    return this.listPlugins({ type });
  }

  /**
   * Get enabled scanner plugins
   */
  getEnabledScanners() {
    return Array.from(this.plugins.values())
      .filter(p => p.type === PLUGIN_TYPES.SCANNER && p.status === PLUGIN_STATUS.ENABLED)
      .map(p => ({
        id: p.id,
        name: p.name,
        instance: p.instance
      }));
  }

  /**
   * Get enabled reporter plugins
   */
  getEnabledReporters() {
    return Array.from(this.plugins.values())
      .filter(p => p.type === PLUGIN_TYPES.REPORTER && p.status === PLUGIN_STATUS.ENABLED)
      .map(p => ({
        id: p.id,
        name: p.name,
        instance: p.instance
      }));
  }
}

export const pluginManager = new PluginManager();

export default {
  PLUGIN_TYPES,
  PLUGIN_STATUS,
  PLUGIN_PERMISSIONS,
  PLUGIN_HOOKS,
  Plugin,
  PluginContext,
  PluginManager,
  pluginManager
};
