/**
 * PhishShield Dashboard - Professional ML-Powered Email Analysis
 * Integrates DistilBERT + XGBoost with professional auto-extraction & forensics
 */

const API_URL = "http://127.0.0.1:8000";
const extractor = new EmailContentExtractor();

// Professional form submission handler
document.getElementById('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const btn = document.getElementById('btn-scan');
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  
  // Start analysis
  btn.innerHTML = '<span>🧬 Running DistilBERT Analysis...</span>';
  
  // Collect form data
  const emailData = {
    subject: document.getElementById('inp-subject').value.trim(),
    body: document.getElementById('inp-body').value.trim(),
    sender: document.getElementById('inp-sender').value.trim(),
    replyTo: document.getElementById('inp-reply').value.trim(),
    urls: document.getElementById('inp-urls').value
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  };

  // Validate input
  const validationErrors = validateEmailInput(emailData);
  if (validationErrors.length > 0) {
    alert('❌ Validation Error:\n' + validationErrors.join('\n'));
    btn.disabled = false;
    btn.innerHTML = originalHtml;
    return;
  }

  try {
    // Phase 1: Send to backend for ML prediction
    btn.innerHTML = '<span>🤖 Analyzing with ML Model...</span>';
    const predictionResponse = await fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subject: emailData.subject,
        body: emailData.body,
        from_email: emailData.sender,
        reply_to: emailData.replyTo,
        urls: emailData.urls
      })
    });

    if (!predictionResponse.ok) {
      throw new Error(`Backend failed: ${predictionResponse.statusText}`);
    }

    const prediction = await predictionResponse.json();

    // Phase 2: Extract content in parallel (client-side) - with fallback if it fails
    btn.innerHTML = '<span>🔍 Extracting Features...</span>';
    let extraction = null;
    try {
      extraction = await extractor.extractComplete(emailData);
    } catch (extractErr) {
      console.warn('Feature extraction failed, using minimal data:', extractErr);
      extraction = {
        urls: { count: emailData.urls.length, urls: emailData.urls },
        emails: { count: 0, emails: [] },
        ips: { count: 0, ips: [] },
        metadata: { extractionTimestamp: new Date().toISOString() }
      };
    }

    // Phase 3: Prepare comprehensive report data
    const reportData = {
      emailData: emailData,
      result: prediction,
      extraction: extraction,
      timestamp: new Date().toISOString()
    };

    // Render quick results on dashboard
    renderResults(prediction);

    // Create report URL with encoded data
    const reportUrl = createReportURL(reportData);

    // Add report link to UI
    showReportLink(reportUrl, prediction);

  } catch (err) {
    console.error('[PhishShield] Error:', err);
    alert("❌ Analysis Failed:\n\n" + err.message + "\n\n✓ Ensure the FastAPI backend is running:\n   python scripts/run_api.py");
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
});

/**
 * Validate email input fields
 */
function validateEmailInput(data) {
  const errors = [];
  if (!data.subject || data.subject.length < 1) {
    errors.push('Subject line is required');
  }
  if (!data.body || data.body.length < 10) {
    errors.push('Email body must be at least 10 characters');
  }
  if (data.subject.length > 500) {
    errors.push('Subject line is too long (max 500 chars)');
  }
  if (data.body.length > 50000) {
    errors.push('Email body is too long (max 50000 chars)');
  }
  return errors;
}

/**
 * Create report URL by encoding data in base64
 */
function createReportURL(reportData) {
  try {
    const jsonStr = JSON.stringify(reportData);
    // Encode as base64 for URL safety
    const encoded = btoa(
      unescape(
        encodeURIComponent(jsonStr)
      )
    );
    return `report.html?data=${encoded}`;
  } catch (error) {
    console.error('Error creating report URL:', error);
    return null;
  }
}

/**
 * Show report link after analysis
 */
function showReportLink(reportUrl, prediction) {
  if (!reportUrl) return;

  const panel = document.getElementById('results-panel');
  
  // Create report button container if not exists
  let reportContainer = document.getElementById('report-container');
  if (!reportContainer) {
    reportContainer = document.createElement('div');
    reportContainer.id = 'report-container';
    reportContainer.style.cssText = `
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      display: flex;
      gap: 12px;
    `;
    panel.appendChild(reportContainer);
  }

  reportContainer.innerHTML = `
    <a href="${reportUrl}" target="_blank" style="
      background: var(--primary);
      color: white;
      padding: 10px 20px;
      border-radius: 6px;
      text-decoration: none;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      transition: background 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    " onmouseover="this.style.background='#1f6feb'" onmouseout="this.style.background='var(--primary)'">
      📊 View Full Forensic Report
    </a>
    <div style="
      padding: 10px 16px;
      background: rgba(47, 129, 247, 0.1);
      border: 1px solid rgba(47, 129, 247, 0.3);
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    ">
      ✓ Comprehensive analysis available
    </div>
  `;
}


/**
 * Render quick summary results on dashboard
 */
function renderResults(data) {
  const panel = document.getElementById('results-panel');
  panel.style.display = 'block';

  // Verdict Banner
  const banner = document.getElementById('verdict-banner');
  const txtVerdict = document.getElementById('res-verdict');
  const verdict = data.phishing ? 'PHISHING' : 'LEGITIMATE';
  txtVerdict.textContent = verdict;
  
  banner.className = 'verdict-header ';
  if (data.risk_level === 'CRITICAL') banner.classList.add('verdict-critical');
  else if (data.risk_level === 'MEDIUM') banner.classList.add('verdict-medium');
  else banner.classList.add('verdict-safe');

  // Metrics
  document.getElementById('res-score').textContent = data.safety_score;
  document.getElementById('res-conf').textContent = ((data.confidence || 0.5) * 100).toFixed(1) + '%';
  document.getElementById('res-action').textContent = data.recommended_action;

  // Reasons List
  const reasonsList = document.getElementById('res-reasons');
  reasonsList.innerHTML = '';
  data.reasoning.forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  // Structural Indicators
  const indContainer = document.getElementById('res-indicators');
  indContainer.innerHTML = '';
  
  const indicators = data.structural_indicators;
  for (const [key, val] of Object.entries(indicators)) {
    if (val > 0) {
      const span = document.createElement('span');
      span.className = 'indicator-pill ' + (key.includes('detected') || key.includes('mismatch') ? 'indicator-red' : '');
      const readableKey = key.replace(/_/g, ' ').toUpperCase();
      span.textContent = `${readableKey} (${parseFloat(val).toFixed(1)})`;
      indContainer.appendChild(span);
    }
  }

  // Scroll to results
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-Load from Chrome/Edge Extension
// ─────────────────────────────────────────────────────────────────────────────

// Initial Backend Health Check
fetch(`${API_URL}/health`)
  .then(res => res.json())
  .then(data => {
    if(data.status === "online") {
      document.querySelector('.status-dot').style.background = 'var(--success)';
    }
  })
  .catch(() => {
    document.querySelector('.status-dot').style.background = 'var(--danger)';
    console.warn("[PhishShield] Backend offline. Some features may be unavailable.");
  });

const params = new URLSearchParams(window.location.search);
const dataParam = params.get('data');

if (dataParam) {
  try {
    // Robustly decode base64 UTF-8 JSON payload sent by popup.js
    const decodedStr = decodeURIComponent(atob(dataParam).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    const payload = JSON.parse(decodedStr);
    
    // 1. Auto-fill the form fields
    if (payload.emailData) {
      document.getElementById('inp-subject').value = payload.emailData.subject || '';
      document.getElementById('inp-sender').value  = payload.emailData.from_email || '';
      document.getElementById('inp-reply').value   = payload.emailData.replyTo || '';
      document.getElementById('inp-body').value    = payload.emailData.body || '';
      
      if (payload.emailData.urls && payload.emailData.urls.length > 0) {
        document.getElementById('inp-urls').value = payload.emailData.urls.join(', ');
      }
    }

    // 2. Instantly render the results without hitting the API again
    if (payload.result) {
      renderResults(payload.result);
      
      // Show report link if available
      if (payload.reportUrl) {
        showReportLink(payload.reportUrl, payload.result);
      }
      
      // Let the user know it was auto-loaded
      const btn = document.getElementById('btn-scan');
      btn.innerHTML = '<span>✨ Auto-Loaded from Extension</span>';
      setTimeout(() => {
        btn.innerHTML = '<span>🔬 Analyze Email</span>';
      }, 3000);
    }

  } catch (err) {
    console.error("[PhishShield] Failed to parse auto-load data from URL:", err);
  }
}

