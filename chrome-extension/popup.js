/**
 * PhishShield — Popup Script v4.0
 *
 * Key features:
 *  1. Reads phishshield_last_result from chrome.storage.local on load
 *  2. Renders immediately if result exists and is <5 minutes old
 *  3. Proper state management with 10 states
 *  4. Timeout handling with AbortController
 *  5. Only scans on user click or email change
 *  6. External threat intelligence runs separately after local result
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Constants

const DEFAULT_API = 'http://localhost:8000';
const DEFAULT_DASHBOARD = 'http://127.0.0.1:8501/index.html';
const RESULT_FRESHNESS_MS = 5 * 60 * 1000; // 5 minutes
const EMAIL_EXTRACTION_TIMEOUT_MS = 3000; // 3 seconds
const PREDICT_TIMEOUT_MS = 8000; // 8 seconds
const EXTERNAL_POLL_INTERVAL_MS = 5000; // 5 seconds
const EXTERNAL_POLL_MAX_ATTEMPTS = 12;

// Scan states
const SCAN_STATES = {
  IDLE: 'idle',
  EXTRACTING: 'extracting',
  PREDICTING: 'predicting',
  COMPLETED: 'completed',
  EXTERNAL_QUEUED: 'external_queued',
  EXTERNAL_PROCESSING: 'external_processing',
  EXTERNAL_COMPLETED: 'external_completed',
  FAILED: 'failed',
  TIMEOUT: 'timeout',
  BACKEND_OFFLINE: 'backend_offline',
  EXTRACTION_FAILED: 'extraction_failed',
};

// ─────────────────────────────────────────────────────────────────────────────
// State

let currentResult = null;
let currentMessageId = null;
let currentScanState = SCAN_STATES.IDLE;
let scanAborted = false;
let externalScanInterval = null;
let externalPollAttempts = 0;

// ─────────────────────────────────────────────────────────────────────────────
// Boot

document.addEventListener('DOMContentLoaded', async () => {
  console.log('[PhishShield Popup] Loaded');

  await loadSettings();
  bindActions();

  // Check API status first
  const isOnline = await checkAPIStatus();

  // Try to show cached result IMMEDIATELY
  await loadAndShowCachedResult();

  // If backend is offline, show that state
  if (!isOnline && !currentResult) {
    showState(SCAN_STATES.BACKEND_OFFLINE);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Cached Result

async function loadAndShowCachedResult() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];

    if (!tab?.id || !isGmailUrl(tab.url)) {
      showState(SCAN_STATES.IDLE);
      return;
    }

    // Get email data to extract message ID
    const emailData = await extractEmailDataWithTimeout(tab.id);

    if (!emailData?.messageId) {
      console.log('[PhishShield Popup] No message ID');
      showState(SCAN_STATES.IDLE);
      return;
    }

    currentMessageId = emailData.messageId;

    // Get cached scan result from chrome.storage.local
    const storage = await chrome.storage.local.get('phishshield_last_result');
    const cachedResult = storage.phishshield_last_result;

    if (cachedResult && cachedResult.emailKey === currentMessageId) {
      const isStale = Date.now() - new Date(cachedResult.updatedAt).getTime() > RESULT_FRESHNESS_MS;

      console.log('[PhishShield Popup] Cached result found:', {
        age: Date.now() - new Date(cachedResult.updatedAt).getTime(),
        isStale,
        state: cachedResult.scanState,
      });

      // Handle different cached states
      switch (cachedResult.scanState) {
        case SCAN_STATES.COMPLETED:
          currentResult = cachedResult.result;
          renderResult(cachedResult.result);
          if (isStale) {
            showFreshnessWarning();
          }
          // Start external scan in background if not already done
          if (!cachedResult.result?.external_scan_id) {
            startExternalScan(cachedResult.result);
          }
          return;

        case SCAN_STATES.EXTRACTION_FAILED:
          showState(SCAN_STATES.EXTRACTION_FAILED, cachedResult.error);
          return;

        case SCAN_STATES.BACKEND_OFFLINE:
          showState(SCAN_STATES.BACKEND_OFFLINE, cachedResult.error);
          return;

        case SCAN_STATES.FAILED:
        case SCAN_STATES.TIMEOUT:
          showState(SCAN_STATES.FAILED, cachedResult.error);
          return;

        default:
          // Unknown state, show idle
          showState(SCAN_STATES.IDLE);
          return;
      }
    }

    // No cached result - show idle state
    showState(SCAN_STATES.IDLE);
  } catch (err) {
    console.error('[PhishShield Popup] Error loading cached result:', err);
    showState(SCAN_STATES.IDLE);
  }
}

async function extractEmailDataWithTimeout(tabId) {
  return Promise.race([
    new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, { action: 'getEmailData' }, (resp) => {
        if (chrome.runtime.lastError) {
          console.warn('[PhishShield Popup] Content script unreachable');
          resolve(null);
        } else {
          resolve(resp || null);
        }
      });
    }),
    new Promise((resolve) => {
      setTimeout(() => {
        console.warn('[PhishShield Popup] Email extraction timeout (3s)');
        resolve(null);
      }, EMAIL_EXTRACTION_TIMEOUT_MS);
    }),
  ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings

async function loadSettings() {
  const s = await chrome.storage.sync.get({
    apiUrl: DEFAULT_API,
    dashboardUrl: DEFAULT_DASHBOARD,
    showBanner: true,
    highlightLinks: true,
    notifications: true,
    autoScan: false, // Changed to false - don't auto-scan
  });

  document.getElementById('inp-api-url').value = s.apiUrl;
  document.getElementById('inp-dashboard-url').value = s.dashboardUrl;
  document.getElementById('chk-banner').checked = s.showBanner;
  document.getElementById('chk-links').checked = s.highlightLinks;
  document.getElementById('chk-notif').checked = s.notifications;
  document.getElementById('chk-autoscan').checked = s.autoScan;

  return s;
}

async function saveSettings() {
  await chrome.storage.sync.set({
    apiUrl: document.getElementById('inp-api-url').value.trim() || DEFAULT_API,
    dashboardUrl: document.getElementById('inp-dashboard-url').value.trim() || DEFAULT_DASHBOARD,
    showBanner: document.getElementById('chk-banner').checked,
    highlightLinks: document.getElementById('chk-links').checked,
    notifications: document.getElementById('chk-notif').checked,
    autoScan: document.getElementById('chk-autoscan').checked,
  });
  closeSettings();
  await checkAPIStatus();
}

// ─────────────────────────────────────────────────────────────────────────────
// API Status

async function checkAPIStatus() {
  const dot = document.querySelector('.dot');
  const label = document.getElementById('api-label');
  label.textContent = 'Checking…';

  try {
    const settings = await chrome.storage.sync.get({ apiUrl: DEFAULT_API });
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`${settings.apiUrl}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      dot.className = 'dot online';
      label.textContent = 'Online';
      console.log('[PhishShield Popup] API version:', data.version);
      return true;
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    dot.className = 'dot offline';
    label.textContent = 'Offline';
    console.warn('[PhishShield Popup] API offline:', err.message);
    return false;
  }
}

async function testAPI() {
  const url = document.getElementById('inp-api-url').value || DEFAULT_API;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`${url}/health`, { signal: controller.signal });
    clearTimeout(timeout);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    console.log('[PhishShield Popup] API health:', data);
    alert(`API Connected!\nStatus: ${data.status}\nVersion: ${data.version}`);
  } catch (e) {
    console.error('[PhishShield Popup] API test failed:', e);
    let errorMsg = `Cannot reach API at ${url}`;

    if (e.name === 'AbortError') {
      errorMsg += '\n\nError: Request timeout (no response in 5 seconds)';
    } else if (e.message.includes('Failed to fetch')) {
      errorMsg += '\n\nError: Network error (backend may not be running)';
    } else {
      errorMsg += `\n\nError: ${e.message}`;
    }

    errorMsg += '\n\nTroubleshooting:\n' +
      '1. Start backend: python3 -m uvicorn backend.api:app --port 8000\n' +
      '2. Check port 8000 is accessible\n' +
      '3. Verify URL is correct in extension settings';

    alert(errorMsg);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Control

async function startScan() {
  showState(SCAN_STATES.EXTRACTING);
  scanAborted = false;
  currentResult = null;

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];

    if (!tab || !isGmailUrl(tab.url)) {
      console.log('[PhishShield Popup] Not a Gmail tab:', tab?.url);
      showState(SCAN_STATES.IDLE);
      return;
    }

    console.log('[PhishShield Popup] Starting scan for Gmail tab');

    // Ask content script for email data with timeout
    const emailData = await extractEmailDataWithTimeout(tab.id);

    if (scanAborted) return;

    if (!emailData || !emailData.subject) {
      console.warn('[PhishShield Popup] Email extraction failed');
      showState(SCAN_STATES.EXTRACTION_FAILED, 'Could not extract email. Open an email in Gmail and try again.');
      return;
    }

    currentMessageId = emailData.messageId;
    console.log('[PhishShield Popup] Email extracted:', {
      subject: emailData.subject.substring(0, 40),
      from: emailData.from_email,
      urls: emailData.urls.length,
    });

    showState(SCAN_STATES.PREDICTING);

    // Call backend with timeout
    const settings = await chrome.storage.sync.get({ apiUrl: DEFAULT_API });
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PREDICT_TIMEOUT_MS);

    try {
      const response = await fetch(`${settings.apiUrl}${CONFIG.api.endpoints.predict}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: emailData.subject || '',
          from_email: emailData.from_email || '',
          body: emailData.body || '',
          urls: emailData.urls || [],
          reply_to: emailData.reply_to || '',
          include_external_scan: false, // KEY: Don't wait for DNS/VT
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const statusCode = response.status;
        let errorDetail = response.statusText || 'Unknown error';
        try {
          const errorJson = await response.json();
          errorDetail = errorJson.detail || errorJson.message || errorDetail;
        } catch { /* ignore */ }

        if (statusCode === 503 || statusCode === 502) {
          throw { errorType: 'backend_offline', message: `Backend returned HTTP ${statusCode}` };
        } else if (statusCode === 422) {
          throw { errorType: 'api_error', message: 'Invalid email data format' };
        } else {
          throw { errorType: 'api_error', message: `API error ${statusCode}: ${errorDetail}` };
        }
      }

      const result = await response.json();

      // Validate response
      if (typeof result.phishing !== 'boolean') {
        throw { errorType: 'invalid_response', message: 'Backend returned invalid response format' };
      }

      currentResult = result;
      console.log('[PhishShield Popup] Analysis complete, risk level:', result.risk_level);

      // Save to storage
      await chrome.storage.local.set({
        phishshield_last_result: {
          emailKey: currentMessageId,
          scanState: SCAN_STATES.COMPLETED,
          result,
          error: null,
          updatedAt: new Date().toISOString(),
        },
      });

      renderResult(result);

      // Start external scan in background if external_scan_id present
      if (result.external_scan_id) {
        startExternalScan(result);
      }

    } catch (err) {
      clearTimeout(timeoutId);

      if (err.name === 'AbortError' || err.message?.includes('timeout')) {
        throw { errorType: 'timeout', message: 'Scan timed out (8 seconds)' };
      } else if (err.message?.includes('Failed to fetch')) {
        throw { errorType: 'backend_offline', message: 'Backend not running' };
      } else {
        throw err;
      }
    }

  } catch (err) {
    console.error('[PhishShield Popup] Scan error:', err);

    const errorType = err.errorType || 'unknown';
    let errorMsg = err.message || 'Unknown error';

    // Determine state based on error type
    let state = SCAN_STATES.FAILED;
    if (errorType === 'timeout') {
      state = SCAN_STATES.TIMEOUT;
      errorMsg = 'Scan timed out (8 seconds). Backend may be slow.';
    } else if (errorType === 'backend_offline' || errorType === 'network_error') {
      state = SCAN_STATES.BACKEND_OFFLINE;
      errorMsg = 'Backend offline. Start the server and try again.';
    } else if (errorType === 'extraction_failed') {
      state = SCAN_STATES.EXTRACTION_FAILED;
    }

    // Save error state
    if (currentMessageId) {
      await chrome.storage.local.set({
        phishshield_last_result: {
          emailKey: currentMessageId,
          scanState: state,
          result: null,
          error: errorMsg,
          updatedAt: new Date().toISOString(),
        },
      });
    }

    showState(state, errorMsg);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// External Threat Intelligence Scan

async function startExternalScan(result) {
  if (!result?.external_scan_id) return;

  externalPollAttempts = 0;
  showExternalState('queued');

  // Clear any existing interval
  if (externalScanInterval) {
    clearInterval(externalScanInterval);
  }

  externalScanInterval = setInterval(async () => {
    externalPollAttempts++;

    if (externalPollAttempts > EXTERNAL_POLL_MAX_ATTEMPTS) {
      clearInterval(externalScanInterval);
      showExternalState('failed', 'External scan timed out');
      return;
    }

    try {
      const settings = await chrome.storage.sync.get({ apiUrl: DEFAULT_API });
      const response = await fetch(`${settings.apiUrl}/api/external-scan/${result.external_scan_id}`);

      if (!response.ok) {
        throw new Error(`External scan HTTP ${response.status}`);
      }

      const data = await response.json();

      if (data.status === 'completed') {
        clearInterval(externalScanInterval);
        renderExternalCompleted(data);
      } else if (data.status === 'failed') {
        clearInterval(externalScanInterval);
        showExternalState('failed', data.error || 'External scan failed');
      } else {
        // Still processing - update UI
        showExternalState('running', data);
      }
    } catch (err) {
      console.error('[PhishShield Popup] External scan poll error:', err);
      // Continue polling on transient errors
    }
  }, EXTERNAL_POLL_INTERVAL_MS);
}

function showExternalState(state, data = null) {
  const card = document.getElementById('external-threat-card');
  if (!card) return;

  // Hide all external states
  document.getElementById('ext-state-queued').style.display = 'none';
  document.getElementById('ext-state-running').style.display = 'none';
  document.getElementById('ext-state-completed').style.display = 'none';
  document.getElementById('ext-state-failed').style.display = 'none';

  const statusPill = document.getElementById('ext-status-pill');

  switch (state) {
    case 'queued':
      card.style.display = 'block';
      statusPill.textContent = 'Queued';
      statusPill.className = 'ext-status-pill ext-status-queued';
      document.getElementById('ext-state-queued').style.display = 'block';
      break;

    case 'running':
      card.style.display = 'block';
      statusPill.textContent = 'Scanning';
      statusPill.className = 'ext-status-pill ext-status-running';
      document.getElementById('ext-state-running').style.display = 'block';

      // Update step indicators if data available
      if (data?.results) {
        const steps = document.querySelectorAll('.ext-step');
        steps.forEach((step, idx) => {
          const stepData = data.results[idx];
          if (stepData?.status === 'completed') {
            step.classList.add('ext-step-complete');
            step.classList.remove('ext-step-active', 'ext-step-pending');
            step.querySelector('.ext-step-indicator').textContent = '✓';
          } else if (stepData?.status === 'processing') {
            step.classList.add('ext-step-active');
            step.classList.remove('ext-step-complete', 'ext-step-pending');
          } else {
            step.classList.add('ext-step-pending');
            step.classList.remove('ext-step-active', 'ext-step-complete');
          }
        });
      }
      break;

    case 'completed':
      // Handled by renderExternalCompleted
      break;

    case 'failed':
      card.style.display = 'block';
      statusPill.textContent = 'Failed';
      statusPill.className = 'ext-status-pill ext-status-failed';
      document.getElementById('ext-state-failed').style.display = 'block';
      document.getElementById('ext-error-message').textContent = data || 'External scan failed';
      break;
  }
}

function renderExternalCompleted(data) {
  const card = document.getElementById('external-threat-card');
  if (!card) return;

  card.style.display = 'block';
  const statusPill = document.getElementById('ext-status-pill');
  statusPill.textContent = 'Completed';
  statusPill.className = 'ext-status-pill ext-status-completed';

  // Hide other states
  document.getElementById('ext-state-queued').style.display = 'none';
  document.getElementById('ext-state-running').style.display = 'none';
  document.getElementById('ext-state-failed').style.display = 'none';

  // Show completed state
  document.getElementById('ext-state-completed').style.display = 'block';

  // Calculate external risk score from results
  let riskScore = 0;
  let riskLabel = 'Unknown';
  const results = data.results || [];

  results.forEach((r) => {
    if (r.dns_result?.resolves === false) riskScore += 30;
    if (r.virustotal_url?.malicious_count > 0) riskScore += 50;
    if (r.virustotal_url?.suspicious_count > 0) riskScore += 20;
  });

  riskScore = Math.min(100, riskScore);

  if (riskScore === 0) {
    riskLabel = 'Clean';
  } else if (riskScore < 30) {
    riskLabel = 'Low Risk';
  } else if (riskScore < 60) {
    riskLabel = 'Medium Risk';
  } else {
    riskLabel = 'High Risk';
  }

  document.getElementById('ext-risk-score').textContent = riskScore;
  document.getElementById('ext-risk-label').textContent = riskLabel;
  document.getElementById('ext-risk-label').className = `ext-risk-label ${riskLabel.toLowerCase().replace(' ', '-')}`;

  // Show first URL and DNS status
  if (results.length > 0) {
    const firstResult = results[0];
    document.getElementById('ext-url-display').textContent = firstResult.url || 'Unknown';
    document.getElementById('ext-url-display').title = firstResult.url || '';

    const dnsStatus = firstResult.dns_result?.resolves
      ? 'Resolved'
      : firstResult.dns_result?.resolves === false
        ? 'Failed'
        : 'Not checked';
    document.getElementById('ext-dns-status').textContent = dnsStatus;

    // Show signals if available
    const signalsList = document.getElementById('ext-signals-list');
    const signalsSection = document.getElementById('ext-signals-section');
    signalsList.innerHTML = '';

    const signals = [];
    if (firstResult.dns_result?.resolves === false) {
      signals.push('Domain failed DNS resolution');
    }
    if (firstResult.trust_analysis?.warnings?.length > 0) {
      firstResult.trust_analysis.warnings.slice(0, 2).forEach((w) => signals.push(w));
    }

    if (signals.length > 0) {
      signalsSection.style.display = 'block';
      signals.forEach((s) => {
        const li = document.createElement('li');
        li.textContent = s;
        signalsList.appendChild(li);
      });
    } else {
      signalsSection.style.display = 'none';
    }

    // Show VirusTotal summary if available
    const vtSection = document.getElementById('ext-vt-section');
    if (firstResult.virustotal_url?.status === 'completed') {
      vtSection.style.display = 'block';
      document.getElementById('ext-vt-malicious').textContent =
        firstResult.virustotal_url.malicious_count || '0';
      document.getElementById('ext-vt-suspicious').textContent =
        firstResult.virustotal_url.suspicious_count || '0';
    } else {
      vtSection.style.display = 'none';
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UI State Management

function showState(state, message = '') {
  // Hide all states
  document.getElementById('state-scanning').style.display = 'none';
  document.getElementById('state-no-email').style.display = 'none';
  document.getElementById('state-error').style.display = 'none';
  document.getElementById('state-result').style.display = 'none';

  currentScanState = state;

  switch (state) {
    case SCAN_STATES.IDLE:
      document.getElementById('state-no-email').style.display = 'flex';
      document.querySelector('.ps-empty-icon').textContent = '📧';
      document.querySelector('.ps-hint').textContent = 'Open an email in Gmail and click Inspect.';
      break;

    case SCAN_STATES.EXTRACTING:
      document.getElementById('state-scanning').style.display = 'flex';
      document.querySelector('.scanner-icon').textContent = '📥';
      document.querySelector('.ps-scanning-text').textContent = 'Extracting email...';
      break;

    case SCAN_STATES.PREDICTING:
      document.getElementById('state-scanning').style.display = 'flex';
      document.querySelector('.scanner-icon').textContent = '🔍';
      document.querySelector('.ps-scanning-text').textContent = 'Running AI scan...';
      break;

    case SCAN_STATES.COMPLETED:
      // Handled by renderResult
      document.getElementById('state-result').style.display = 'flex';
      break;

    case SCAN_STATES.EXTRACTION_FAILED:
    case SCAN_STATES.FAILED:
    case SCAN_STATES.TIMEOUT:
    case SCAN_STATES.BACKEND_OFFLINE:
      document.getElementById('state-error').style.display = 'flex';
      document.getElementById('error-msg').textContent = message;

      // Change icon based on state
      const errorIcon = document.querySelector('#state-error .ps-empty-icon');
      if (state === SCAN_STATES.BACKEND_OFFLINE) {
        errorIcon.textContent = '📡';
      } else if (state === SCAN_STATES.EXTRACTION_FAILED) {
        errorIcon.textContent = '📭';
      } else {
        errorIcon.textContent = '⚠️';
      }
      break;

    case SCAN_STATES.EXTERNAL_COMPLETED:
    case SCAN_STATES.EXTERNAL_PROCESSING:
    case SCAN_STATES.EXTERNAL_QUEUED:
      // External states handled separately
      break;
  }
}

function showFreshnessWarning() {
  const container = document.querySelector('.ps-reasons');
  if (container) {
    const warning = document.createElement('div');
    warning.style.cssText = `
      padding: 8px 12px;
      background: rgba(255, 149, 0, 0.15);
      border-left: 3px solid #FF9500;
      margin-bottom: 12px;
      border-radius: 4px;
      font-size: 11px;
      color: #FFB74D;
    `;
    warning.textContent = 'Result may be outdated. Click "Re-scan" for fresh analysis.';
    container.insertBefore(warning, container.firstChild);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Render Result

function renderResult(result) {
  document.getElementById('state-result').style.display = 'flex';

  const score = result.safety_score ?? 50;
  const level = (result.risk_level ?? 'UNKNOWN').toUpperCase();
  const reasons = result.reasoning ?? [];
  const conf = result.confidence ?? result.confidence_score ?? 0.5;

  const gaugeContainer = document.querySelector('.ps-gauge-wrap');
  if (!gaugeContainer) return;

  // Update gauge
  gaugeContainer.innerHTML = `
    <svg class="ps-gauge" viewBox="0 0 140 80" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="gauge-grad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:#34C759;stop-opacity:1" />
          <stop offset="50%" style="stop-color:#FF9500;stop-opacity:1" />
          <stop offset="100%" style="stop-color:#FF3B30;stop-opacity:1" />
        </linearGradient>
      </defs>
      <path d="M 20 70 A 50 50 0 0 1 120 70" fill="none" stroke="url(#gauge-grad)" stroke-width="8" stroke-linecap="round"/>
      <circle cx="${20 + (100 * (score / 100))}" cy="70" r="6" fill="#FFFFFF"/>
    </svg>
    <div class="ps-gauge-label">
      <span class="ps-score-num">${Math.round(score)}</span>
      <span class="ps-score-unit">/100</span>
    </div>
    <div class="ps-verdict verdict-${level.toLowerCase()}">
      ${level}
    </div>
  `;

  // Update risk badge
  const riskBadge = document.getElementById('risk-badge');
  if (riskBadge) {
    let badgeText = 'LOW';
    let badgeClass = 'badge-low';

    if (level === 'CRITICAL' || level === 'HIGH') {
      badgeText = 'HIGH';
      badgeClass = 'badge-high';
    } else if (level === 'MEDIUM') {
      badgeText = 'MEDIUM';
      badgeClass = 'badge-medium';
    }

    riskBadge.textContent = badgeText;
    riskBadge.className = `ps-risk-badge ${badgeClass}`;
  }

  // Update reasons
  const reasonsList = document.getElementById('reasons-list');
  if (reasonsList) {
    reasonsList.innerHTML = reasons.slice(0, 3).map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  }

  // Update confidence bar
  const confBar = document.getElementById('conf-bar');
  const confPct = document.getElementById('conf-pct');
  if (confBar && confPct) {
    confBar.style.width = `${conf * 100}%`;
    confBar.className = `ps-conf-bar ${getConfClass(level)}`;
    confPct.textContent = `${Math.round(conf * 100)}%`;
  }

  // Update action buttons
  const actions = document.querySelector('.ps-actions');
  if (actions) {
    actions.innerHTML = `
      <button id="btn-rescan" class="ps-btn ps-btn-ghost">↺ Re-scan</button>
      <button id="btn-dashboard" class="ps-btn ps-btn-primary">📊 Full Report</button>
    `;

    // Re-bind buttons
    document.getElementById('btn-rescan').addEventListener('click', startScan);
    document.getElementById('btn-dashboard').addEventListener('click', openDashboard);
  }
}

function getConfClass(level) {
  if (level === 'CRITICAL' || level === 'HIGH') return 'danger';
  if (level === 'MEDIUM') return 'warn';
  return 'safe';
}

// ─────────────────────────────────────────────────────────────────────────────
// Actions

function bindActions() {
  document.getElementById('btn-settings').addEventListener('click', openSettings);
  document.getElementById('btn-close-settings').addEventListener('click', closeSettings);
  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('btn-test-api').addEventListener('click', testAPI);
}

function openSettings() {
  document.querySelector('.ps-settings').style.display = 'flex';
}

function closeSettings() {
  document.querySelector('.ps-settings').style.display = 'none';
}

async function openDashboard() {
  // Save latest result to storage before opening dashboard
  if (currentResult) {
    await chrome.storage.local.set({
      phishshield_last_result: {
        emailKey: currentMessageId,
        scanState: SCAN_STATES.COMPLETED,
        result: currentResult,
        error: null,
        updatedAt: new Date().toISOString(),
      },
      phishshield_dashboard_result: currentResult,
    });
  }

  // URLs to try in order
  const REPORT_URLS = [
    'http://127.0.0.1:8501/index.html',
    'http://localhost:8501/index.html',
  ];

  for (const url of REPORT_URLS) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      // Use mode:'no-cors' — static file servers don't send CORS headers,
      // but an opaque response still proves the server is reachable.
      await fetch(url, { method: 'HEAD', mode: 'no-cors', signal: controller.signal });
      clearTimeout(timeoutId);

      // Server is reachable — open the report
      console.log('[PhishShield Popup] Dashboard reachable at:', url);
      chrome.tabs.create({ url });
      return;
    } catch (err) {
      console.warn('[PhishShield Popup] Dashboard not reachable at:', url, err.message);
      // Try next URL
    }
  }

  // Both URLs failed — show friendly message
  alert(
    'Report page is not running. Start dashboard server on port 8501.\n\n' +
    'Command:\n' +
    'cd dashboard\n' +
    'python -m http.server 8501'
  );
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function isGmailUrl(url) {
  return url && (url.includes('mail.google.com') || url.includes('inbox.google.com'));
}

// Config for API endpoints (inline to avoid external dependency)
const CONFIG = {
  api: {
    endpoints: {
      predict: '/predict',
    },
  },
};

console.log('[PhishShield Popup] Script loaded');
