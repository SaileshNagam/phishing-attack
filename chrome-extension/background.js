/**
 * PhishShield — Background Service Worker v3.0 (Fast & Responsive)
 *
 * Key improvements:
 *  1. Reduced timeout: 8 seconds for /predict (from 30s)
 *  2. Staged loading: "Extracting" → "Predicting" → "Complete"
 *  3. Scan state management with chrome.storage.local
 *  4. Separate ML prediction from external scans
 *  5. Non-blocking external intelligence (DNS, VT in background)
 */

'use strict';

const CONFIG = {
  api: {
    baseUrl: 'http://localhost:8000',
    endpoints: {
      health: '/health',
      predict: '/predict',
    },
    predictTimeout: 8000,  // 8 seconds - strict timeout for fast UI
    healthCheckTimeout: 5000,
  },
  cache: {
    ttlMs: 30 * 60 * 1000, // 30 minutes
    emailExtractionTimeout: 3000, // 3 seconds max for content script
  },
  logging: {
    enabled: true,
    prefix: '[PhishShield Background]',
  },
  log(...args) {
    if (this.logging.enabled) console.log(...[this.logging.prefix, ...args]);
  },
  error(...args) {
    console.error(...[this.logging.prefix, ...args]);
  },
  warn(...args) {
    console.warn(...[this.logging.prefix, ...args]);
  },
};

// In-memory scan cache
const scanCache = new Map();
// Track active scans: { messageId → { controller, timestamp } }
const activeScans = new Map();

// ────────────────────────────────────────────────────────────────────────────
// Initialization

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.sync.set({
      apiUrl: CONFIG.api.baseUrl,
      autoScan: true,
      showBanner: true,
      highlightLinks: true,
      notifications: true,
      dashboardUrl: 'http://127.0.0.1:8501/index.html',
    });
    CONFIG.log('Installed — defaults saved.');
  }
});

// ────────────────────────────────────────────────────────────────────────────
// Message Router

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Analyze email (popup trigger)
  if (request.action === 'analyze') {
    handleAnalyze(request.emailData, request.messageId)
      .then(sendResponse)
      .catch((err) => {
        CONFIG.error('Analyze error:', err);
        sendResponse({
          error: err.message,
          errorType: err.errorType || 'unknown',
          details: err.details,
        });
      });
    return true; // async
  }

  // Get cached result without triggering new scan
  if (request.action === 'getCachedResult') {
    const cached = getCached(request.messageId);
    sendResponse(cached ? { result: cached } : { result: null });
    return false;
  }

  // Check API health
  if (request.action === 'checkAPI') {
    checkAPIStatus().then(sendResponse);
    return true;
  }

  // Cancel active scan
  if (request.action === 'cancelScan') {
    const scan = activeScans.get(request.messageId);
    if (scan) {
      scan.controller.abort();
      activeScans.delete(request.messageId);
      CONFIG.log('Scan cancelled:', request.messageId);
    }
    sendResponse({ cancelled: true });
    return false;
  }
});

// ────────────────────────────────────────────────────────────────────────────
// Core: Analyze Email

async function handleAnalyze(emailData, messageId) {
  // STAGE 0: Cancel any existing scan for this message
  const existing = activeScans.get(messageId);
  if (existing) {
    existing.controller.abort();
  }

  // STAGE 1: Validate input
  if (!emailData || typeof emailData !== 'object') {
    const err = new Error('Invalid email data');
    err.errorType = 'invalid_input';
    throw err;
  }

  // Check cache first
  const cached = getCached(messageId);
  if (cached) {
    CONFIG.log('✓ Returning cached result for:', messageId);
    // Update state to show it's complete
    await updateScanState(messageId, 'completed', cached);
    return { result: cached, fromCache: true };
  }

  // Update state: extracting
  await updateScanState(messageId, 'extracting', null);

  const settings = await chrome.storage.sync.get({ apiUrl: CONFIG.api.baseUrl });
  const apiUrl = settings.apiUrl || CONFIG.api.baseUrl;

  try {
    // STAGE 2: Prepare payload (fast)
    const payload = {
      subject: emailData.subject || '',
      from_email: emailData.from_email || emailData.sender || '',
      body: emailData.body || '',
      urls: emailData.urls || [],
      reply_to: emailData.reply_to || emailData.replyTo || '',
      include_external_scan: false,  // KEY: Don't wait for DNS/VT
    };

    CONFIG.log('Payload ready:', {
      subject: payload.subject.substring(0, 50),
      from: payload.from_email,
      urls: payload.urls.length,
    });

    // Update state: predicting
    await updateScanState(messageId, 'predicting', null);

    // STAGE 3: Fetch with strict 8-second timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
      activeScans.delete(messageId);
    }, CONFIG.api.predictTimeout);

    activeScans.set(messageId, { controller, timestamp: Date.now() });

    let response;
    try {
      CONFIG.log('Calling /predict at:', apiUrl, '(timeout:', CONFIG.api.predictTimeout + 'ms)');

      response = await fetch(`${apiUrl}${CONFIG.api.endpoints.predict}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
      activeScans.delete(messageId);
    }

    // STAGE 4: Validate response
    if (!response.ok) {
      let errorDetail = response.statusText || 'Unknown error';
      const statusCode = response.status;
      try {
        const errorJson = await response.json();
        errorDetail = errorJson.detail || errorJson.message || errorDetail;
      } catch {
        // Not JSON, use status
      }

      const err = new Error(`API error ${statusCode}: ${errorDetail}`);
      err.errorType = 'api_error';
      err.statusCode = statusCode;
      throw err;
    }

    let result;
    try {
      result = await response.json();
    } catch (e) {
      const err = new Error('API response not JSON');
      err.errorType = 'invalid_response';
      throw err;
    }

    // Validate structure
    if (typeof result.phishing !== 'boolean') {
      const err = new Error('API response missing phishing field');
      err.errorType = 'invalid_response';
      throw err;
    }

    // Cache result
    if (messageId) {
      scanCache.set(messageId, {
        result,
        expires: Date.now() + CONFIG.cache.ttlMs,
      });
      CONFIG.log('✓ Result cached for:', messageId);
    }

    // Update state: completed
    await updateScanState(messageId, 'completed', result);

    // Save to chrome.storage.local for popup to read (phishshield_last_result)
    if (messageId) {
      await chrome.storage.local.set({
        phishshield_last_result: {
          emailKey: messageId,
          scanState: 'completed',
          result,
          error: null,
          updatedAt: new Date().toISOString(),
        },
      });
      CONFIG.log('✓ Result saved to chrome.storage.local for:', messageId);
    }

    // Fire notification for high-risk
    const notifSettings = await chrome.storage.sync.get({ notifications: true });
    if (notifSettings.notifications && isHighRisk(result)) {
      fireNotification(result);
    }

    CONFIG.log('✓ Analysis complete:', result.risk_level);
    return { result, fromCache: false };

  } catch (err) {
    // Enhanced error classification
    if (err.name === 'AbortError') {
      err.message = 'Scan timeout (no response in 8 seconds)';
      err.errorType = 'timeout';
    } else if (err.message.includes('Failed to fetch')) {
      err.message = `Backend offline at ${apiUrl}`;
      err.errorType = 'network_error';
    } else if (!err.errorType) {
      err.errorType = 'unknown';
    }

    // Update state: failed
    await updateScanState(messageId, 'failed', null, err.message);

    // Save error to chrome.storage.local for popup to read
    if (messageId) {
      await chrome.storage.local.set({
        phishshield_last_result: {
          emailKey: messageId,
          scanState: err.errorType === 'network_error' ? 'backend_offline' : 'failed',
          result: null,
          error: err.message,
          updatedAt: new Date().toISOString(),
        },
      });
      CONFIG.error('Error state saved to chrome.storage.local for:', messageId);
    }

    CONFIG.error('Analysis failed:', err.message);
    throw err;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// State Management

async function updateScanState(messageId, scanState, result, error = null) {
  if (!messageId) return;

  const state = {
    messageId,
    scanState, // idle | extracting | predicting | completed | failed | timeout
    lastResult: result,
    lastError: error,
    updatedAt: new Date().toISOString(),
  };

  await chrome.storage.local.set({
    [`scan:${messageId}`]: state,
  });

  CONFIG.log(`State updated: ${scanState}`, messageId);
}

async function getScanState(messageId) {
  if (!messageId) return null;
  const data = await chrome.storage.local.get(`scan:${messageId}`);
  return data[`scan:${messageId}`] || null;
}

// ────────────────────────────────────────────────────────────────────────────
// Cache & Helpers

function getCached(messageId) {
  if (!messageId) return null;
  const entry = scanCache.get(messageId);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    scanCache.delete(messageId);
    return null;
  }
  return entry.result;
}

function isHighRisk(result) {
  const level = (result.risk_level || '').toUpperCase();
  return level === 'CRITICAL' || level === 'HIGH';
}

function fireNotification(result) {
  const meta = result.email_meta || {};
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'images/icon128.png',
    title: `⚠️ PhishShield: ${result.risk_level} Risk`,
    message: `From: ${meta.sender || 'unknown'}\n${result.reasoning?.[0] || ''}`,
  });
}

async function checkAPIStatus() {
  const url = (await chrome.storage.sync.get('apiUrl')).apiUrl || CONFIG.api.baseUrl;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONFIG.api.healthCheckTimeout);

  try {
    const res = await fetch(`${url}${CONFIG.api.endpoints.health}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { online: true, version: data.version };
    } else {
      return { online: false, error: `HTTP ${res.status}` };
    }
  } catch (err) {
    clearTimeout(timeoutId);
    return { online: false, error: err.message };
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Tab Updates

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url?.includes('mail.google.com')) {
    chrome.tabs.sendMessage(tabId, { action: 'init' }).catch(() => {});
  }
});

CONFIG.log('Service Worker initialized');
