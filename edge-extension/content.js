/**
 * PhishShield — Content Script v2.0
 *
 * Runs inside Gmail pages. Responsibilities:
 *  1. Detect when a user opens an email (MutationObserver on Gmail DOM)
 *  2. Extract: subject, sender, body text, URLs, Gmail message-ID
 *  3. Delegate scan to background service worker
 *  4. Inject a coloured Risk Banner at the top of the email
 *  5. Highlight suspicious links in the email body
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────
const BANNER_ID          = 'phishshield-risk-banner';
const PROCESSED_ATTR     = 'data-phishshield-scanned';
const SHORTENERS         = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly']);
const SUSPICIOUS_KW      = /login|verify|account|password|update|secure|confirm|banking|paypal|click here/i;

// ── State ─────────────────────────────────────────────────────────────────────
let currentMessageId = null;
let debounceTimer    = null;

// ── Init ──────────────────────────────────────────────────────────────────────
function init() {
  attachObserver();
  // Check if an email is already open on load
  runOnCurrentEmail();
}

// Listen for messages from background and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'init') {
    init();
    return;
  }

  // Popup requests email data directly (fast response)
  if (message.action === 'getEmailData') {
    try {
      const container = getEmailContainer();
      if (container) {
        const data = extractEmailData(container);
        data.messageId = getMessageId(container);
        console.log('[PhishShield Content] Email data extracted:', {
          subject: data.subject?.substring(0, 40),
          from: data.from_email,
          urls: data.urls?.length,
          messageId: data.messageId,
        });
        sendResponse(data);
      } else {
        console.warn('[PhishShield Content] Email container not found');
        sendResponse(null);
      }
    } catch (err) {
      console.error('[PhishShield Content] Error extracting email:', err);
      sendResponse(null);
    }
    return true; // keep channel open
  }
});

// ── MutationObserver ──────────────────────────────────────────────────────────
function attachObserver() {
  const target = document.body;
  if (!target) return;

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runOnCurrentEmail, 600);
  });

  observer.observe(target, { childList: true, subtree: true });
}

function runOnCurrentEmail() {
  const emailContainer = getEmailContainer();
  if (!emailContainer) return;

  const msgId = getMessageId(emailContainer);
  if (!msgId || msgId === currentMessageId) return;
  if (emailContainer.hasAttribute(PROCESSED_ATTR)) return;

  currentMessageId = msgId;
  emailContainer.setAttribute(PROCESSED_ATTR, '1');
  scanEmail(emailContainer, msgId);
}

// ── Gmail DOM Helpers ─────────────────────────────────────────────────────────
function getEmailContainer() {
  // Gmail wraps open emails in [data-message-id] or inside the main panel
  const container = (
    document.querySelector('[data-message-id]') ||
    document.querySelector('.ii.gt') ||
    document.querySelector('[role="main"] .a3s') ||
    null
  );
  
  if (!container) {
    console.warn('[PhishShield] Email container not found - Gmail layout may have changed');
  }
  
  return container;
}

function getMessageId(container) {
  return (
    container?.closest('[data-message-id]')?.getAttribute('data-message-id') ||
    container?.id ||
    // Fallback: extract from URL hash
    (window.location.hash.match(/#[^/]+\/([a-zA-Z0-9]+)/) || [])[1] ||
    null
  );
}

function extractEmailData(container) {
  // Subject
  const subjectEl = (
    document.querySelector('h2[data-subject-threading]') ||
    document.querySelector('.hP') ||       // Gmail subject class
    document.querySelector('[data-legacy-message-id] .nH .hP')
  );
  const subject = subjectEl ? subjectEl.innerText.trim() : document.title.replace(' - Gmail', '').trim();

  // Sender
  const fromEl      = document.querySelector('[email]');
  const from_email  = fromEl ? fromEl.getAttribute('email') : '';

  // Try to extract Reply-To from visible headers (if shown)
  let reply_to = '';
  const replyToEl = document.evaluate(
    "//span[contains(text(), 'Reply-To')]/../following-sibling::*/text()[1]",
    container,
    null,
    XPathResult.FIRST_ORDERED_NODE_TYPE,
    null
  ).singleNodeValue;
  if (replyToEl) {
    reply_to = replyToEl.textContent.trim();
  }

  // Body
  const bodyEl   = (
    container.querySelector('[data-message-body="true"]') ||
    container.querySelector('.a3s.aiL') ||
    container.querySelector('.ii.gt .a3s') ||
    container
  );
  const body = bodyEl ? bodyEl.innerText.trim() : '';

  // URLs — skip Gmail internals
  const linkEls = container.querySelectorAll('a[href]');
  const urls = [];
  linkEls.forEach((el) => {
    const href = el.getAttribute('href');
    if (href && !href.startsWith('javascript:') && !href.includes('mail.google.com')) {
      // Decode Google redirect wrapping (https://www.google.com/url?q=...)
      try {
        const qParam = new URL(href).searchParams.get('q');
        urls.push(qParam || href);
      } catch {
        urls.push(href);
      }
    }
  });

  return {
    subject,
    from_email,
    body,
    urls: [...new Set(urls)],
    reply_to,
    headers: {},
  };
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function scanEmail(container, messageId) {
  showBanner(container, 'scanning');

  try {
    const emailData = extractEmailData(container);

    if (!emailData.subject && !emailData.from_email && !emailData.body) {
      console.warn('[PhishShield] Email data extraction failed - all fields empty');
      showBanner(container, 'error');
      // Save extraction failed state
      await saveScanResultToStorage(messageId, 'extraction_failed', null, 'Failed to extract email content');
      return;
    }

    chrome.runtime.sendMessage(
      { action: 'analyze', emailData, messageId },
      async (response) => {
        if (chrome.runtime.lastError) {
          console.error('[PhishShield] Message error:', chrome.runtime.lastError.message);
          showBanner(container, 'error');
          await saveScanResultToStorage(messageId, 'failed', null, chrome.runtime.lastError.message);
          return;
        }

        if (!response) {
          console.error('[PhishShield] Background returned no response');
          showBanner(container, 'error');
          await saveScanResultToStorage(messageId, 'failed', null, 'Background service returned no response');
          return;
        }

        const result = response.result;
        if (!result) {
          console.error('[PhishShield] No prediction result in response:', response);
          showBanner(container, 'error');
          await saveScanResultToStorage(messageId, 'failed', null, 'No prediction result received');
          return;
        }

        console.log('[PhishShield] Prediction received:', result.risk_level, 'Score:', result.safety_score);
        showBanner(container, 'result', result);
        highlightSuspiciousLinks(container, result);

        // Save scan result to storage for popup to read
        await saveScanResultToStorage(messageId, 'completed', result, null);
      }
    );
  } catch (err) {
    console.error('[PhishShield] Scan failed:', err);
    showBanner(container, 'error');
    await saveScanResultToStorage(messageId, 'failed', null, err.message);
  }
}

// ── Storage Helpers ───────────────────────────────────────────────────────────
/**
 * Save scan result to chrome.storage.local for popup to read
 * @param {string} messageId - Gmail message ID
 * @param {string} scanState - State: completed | failed | extraction_failed | timeout
 * @param {object|null} result - Scan result from backend
 * @param {string|null} error - Error message if failed
 */
async function saveScanResultToStorage(messageId, scanState, result, error) {
  if (!messageId) return;

  const scanResult = {
    emailKey: messageId,
    scanState,
    result,
    error: error || null,
    updatedAt: new Date().toISOString(),
  };

  try {
    await chrome.storage.local.set({
      phishshield_last_result: scanResult,
    });
    console.log('[PhishShield] Scan result saved to storage:', { messageId, scanState });
  } catch (err) {
    console.error('[PhishShield] Failed to save scan result to storage:', err);
  }
}

// ── Risk Banner ───────────────────────────────────────────────────────────────
function showBanner(container, mode, result = null) {
  // Remove any existing banner
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = BANNER_ID;

  let statusClass, title, subtitle, showDismiss = false;

  if (mode === 'scanning') {
    statusClass = 'scanning';
    title = 'PhishShield analyzing email…';
    subtitle = '';
  } else if (mode === 'error') {
    statusClass = 'error';
    title = 'PhishShield: Detection unavailable';
    subtitle = 'Check if backend server is running';
    showDismiss = true;
  } else if (result) {
    const level = (result.risk_level || '').toUpperCase();

    if (level === 'CRITICAL' || level === 'HIGH') {
      statusClass = 'phishing';
      title = 'Phishing detected';
      subtitle = result.reasoning?.[0] || 'This email appears to be phishing';
    } else if (level === 'MEDIUM') {
      statusClass = 'suspicious';
      title = 'Suspicious email';
      subtitle = result.reasoning?.[0] || 'This email has suspicious characteristics';
    } else {
      statusClass = 'safe';
      title = 'Email appears safe';
      subtitle = result.reasoning?.[0] || 'No threats detected';
    }
    showDismiss = true;
  }

  banner.innerHTML = `
    <div class="phishshield-card">
      <div class="phishshield-status-dot ${statusClass}"></div>
      <div class="phishshield-content">
        <div class="phishshield-title ${statusClass}">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="phishshield-subtitle">${escapeHtml(subtitle)}</div>` : ''}
      </div>
      ${showDismiss ? `<button class="phishshield-dismiss-btn">✕</button>` : ''}
    </div>
  `;

  // Add click handler for dismiss button
  const dismissBtn = banner.querySelector('.phishshield-dismiss-btn');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => banner.remove());
  }

  // Insert before the email body
  const insertTarget = (
    container.closest('[role="main"]')?.querySelector('.nH .gs') ||
    container.closest('[role="main"]') ||
    container
  );
  insertTarget.insertBefore(banner, insertTarget.firstChild);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ── Suspicious Link Highlighting ──────────────────────────────────────────────
function highlightSuspiciousLinks(container, result) {
  const settings = { highlightLinks: true }; // Could be fetched from storage

  const linkEls = container.querySelectorAll('a[href]');
  linkEls.forEach((el) => {
    const href    = el.getAttribute('href') || '';
    const display = el.innerText.trim();
    if (isSuspiciousLink(href, display)) {
      el.style.textDecoration  = 'underline dashed #ff453a';
      el.style.color           = '#ff8a80';
      el.style.outline         = '1px dashed #ff453a44';
      el.title                 = '⚠️ PhishShield: This link appears suspicious — hover carefully before clicking.';
      el.setAttribute('data-phishshield-flagged', '1');
    }
  });

  // Add tooltip style if not already present
  if (!document.getElementById('phishshield-link-style')) {
    const style = document.createElement('style');
    style.id = 'phishshield-link-style';
    style.textContent = `
      a[data-phishshield-flagged]::after {
        content: ' ⚠️';
        font-size: 10px;
        vertical-align: super;
      }
    `;
    document.head.appendChild(style);
  }
}

function isSuspiciousLink(href, displayText) {
  if (!href) return false;

  let domain = '';
  try {
    domain = new URL(href).hostname.toLowerCase();
  } catch {
    return false;
  }

  // Shortened URLs
  if (SHORTENERS.has(domain)) return true;

  // IP address URL
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return true;

  // Suspicious keywords in URL or display text
  if (SUSPICIOUS_KW.test(href) || SUSPICIOUS_KW.test(displayText)) return true;

  // Subdomain depth > 3 (e.g., login.secure.bank.evil.com)
  if (domain.split('.').length > 4) return true;

  // Display text looks like a URL but doesn't match actual URL domain
  if (displayText.startsWith('http') && !displayText.includes(domain)) return true;

  return false;
}

// ── Boot ──────────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
