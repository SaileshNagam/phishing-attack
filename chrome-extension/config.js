/**
 * PhishShield Configuration
 *
 * Centralized config for API URLs, timeouts, and environment settings.
 * This is the single source of truth for all network communication.
 */

const PHISHSHIELD_CONFIG = {
  // Backend API
  api: {
    baseUrl: 'http://localhost:8000',
    endpoints: {
      health: '/health',
      predict: '/predict',
    },
    timeout: 8000, // milliseconds
    retries: 1,
  },

  // Dashboard (optional feature)
  dashboard: {
    baseUrl: 'http://localhost:5173',
  },

  // Feature flags
  features: {
    autoScan: true,
    showBanner: true,
    highlightLinks: true,
    notifications: true,
    cachingEnabled: true,
    cacheTtlMs: 30 * 60 * 1000, // 30 minutes
  },

  // Logging
  logging: {
    enabled: true,
    prefix: '[PhishShield]',
  },

  /**
   * Validate config at runtime
   */
  validate() {
    if (!this.api.baseUrl) {
      throw new Error('API base URL not configured');
    }
    if (!this.api.baseUrl.startsWith('http')) {
      throw new Error('API base URL must start with http or https');
    }
    return true;
  },

  /**
   * Get full API URL for an endpoint
   */
  getApiUrl(endpoint) {
    return `${this.api.baseUrl}${endpoint}`;
  },

  /**
   * Log with phishshield prefix
   */
  log(...args) {
    if (this.logging.enabled) {
      console.log(this.logging.prefix, ...args);
    }
  },

  /**
   * Log with error
   */
  error(...args) {
    console.error(this.logging.prefix, ...args);
  },

  /**
   * Log with warning
   */
  warn(...args) {
    console.warn(this.logging.prefix, ...args);
  },
};

// Validate on load
try {
  PHISHSHIELD_CONFIG.validate();
} catch (e) {
  console.error('[PhishShield] Config validation failed:', e);
}
