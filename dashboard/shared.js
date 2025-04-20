/**
 * PhishShield Dashboard — Shared Utilities
 * Called by every page via: initShared()
 */

window.PHISHSHIELD_API = 'http://localhost:8000';

async function initShared() {
  await checkAPIStatus();
  setupTabs();
}

function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.getAttribute('data-tab');

      // Deactivate all tabs
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      // Activate clicked tab
      btn.classList.add('active');
      const targetTab = document.getElementById(`tab-${tabName}`);
      if (targetTab) {
        targetTab.classList.add('active');
      }

      // If VT tab is activated, start polling
      if (tabName === 'virustotal') {
        pollVTResults();
      }
    });
  });
}

async function pollVTResults() {
  // Poll for VT results and update UI
  const scanId = document.getElementById('vt-scan-id')?.textContent;
  if (!scanId) return;

  try {
    const res = await fetch(`${window.PHISHSHIELD_API}/external/virustotal/scan/${scanId}`);
    if (!res.ok) return;

    const data = await res.json();
    updateVTResults(data);

    // Continue polling if not all completed
    if (data.queued > 0) {
      setTimeout(pollVTResults, 5000);
    }
  } catch (e) {
    console.log('VT poll error:', e);
  }
}

function updateVTResults(data) {
  // Update summary cards
  document.getElementById('vt-total-urls').textContent = data.urls.length;
  document.getElementById('vt-completed').textContent = data.completed;

  // Count detections
  let maliciousTotal = 0, suspiciousTotal = 0;

  const container = document.querySelector('.vt-results-container');
  if (!container) return;

  container.innerHTML = '';

  data.results.forEach(result => {
    maliciousTotal += result.stats?.malicious || 0;
    suspiciousTotal += result.stats?.suspicious || 0;

    const card = createVTCard(result);
    container.appendChild(card);
  });

  document.getElementById('vt-malicious-count').textContent = maliciousTotal;
  document.getElementById('vt-suspicious-count').textContent = suspiciousTotal;
}

function createVTCard(result) {
  const card = document.createElement('div');
  card.className = 'vt-report-card';

  const stats = result.stats || {};
  const status = result.status || 'unknown';

  card.innerHTML = `
    <div class="report-header">
      <div class="report-url">${escapeHtml(result.url)}</div>
      <span class="report-status-pill">${escapeHtml(status)}</span>
    </div>
    <div class="report-stats">
      <div class="stat-label">Detections</div>
      <span class="stat-badge danger">${stats.malicious || 0} Malicious</span>
      <span class="stat-badge warning">${stats.suspicious || 0} Suspicious</span>
    </div>
    ${result.flagged_engines && result.flagged_engines.length > 0 ? `
      <div class="report-engines">
        ${result.flagged_engines.map(e => `<div class="engine-item ${e.category}">${escapeHtml(e.engine_name)}: ${escapeHtml(e.result)}</div>`).join('')}
      </div>
    ` : ''}
    <div class="report-footer">
      <div class="report-timing">Queue: ${result.queue_time_ms || 0}ms</div>
      <a href="${escapeHtml(result.permalink)}" target="_blank" class="btn-link">VirusTotal ↗</a>
    </div>
  `;

  return card;
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

async function checkAPIStatus() {
  const dot   = document.getElementById('api-status-dot');
  const label = document.getElementById('api-status-text');

  try {
    const res  = await fetch(`${window.PHISHSHIELD_API}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    if (dot)   { dot.className = 'status-dot online'; }
    if (label) { label.textContent = `Online · v${data.version || '2.0'}`; }
  } catch {
    if (dot)   { dot.className = 'status-dot offline'; }
    if (label) { label.textContent = 'Offline (demo mode)'; }
  }
}
