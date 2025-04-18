/**
 * PhishShield Report Generator & Renderer
 * Professional VirusTotal-style report rendering with interactive tabs
 */

class ReportRenderer {
  constructor() {
    this.extractor = new EmailContentExtractor();
    this.analysis = null;
    this.prediction = null;
    this.emailData = null;
    this.init();
  }

  /**
   * Initialize report with data from URL parameters
   */
  init() {
    // Set up tab switching
    this.setupTabs();
    
    // Get data from URL
    this.loadDataFromURL();
  }

  /**
   * Setup tab switching functionality
   */
  setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tabName = e.target.dataset.tab;
        
        // Update active states
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        tabContents.forEach(c => c.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');
      });
    });
  }

  /**
   * Load email data from URL parameters — scan_id preferred, base64 fallback
   */
  async loadDataFromURL() {
    try {
      const params = new URLSearchParams(window.location.search);
      const scanId = params.get('scan_id');
      const dataParam = params.get('data');
      const apiParam = params.get('api');
      
      // Determine API base URL
      const apiBase = apiParam ? decodeURIComponent(apiParam) : 'http://127.0.0.1:8000';

      // Method 1: Fetch from backend by scan_id (clean, preferred)
      if (scanId) {
        try {
          console.log('[Report] Fetching scan data for:', scanId);
          const resp = await fetch(`${apiBase}/scan/${scanId}`);
          if (resp.ok) {
            const scanData = await resp.json();
            console.log('[Report] Scan data received:', scanData);
            this.prediction = scanData;
            
            // Map email_meta to emailData format expected by renderer
            // email_meta now includes: subject, sender, reply_to, url_count, urls, body
            this.emailData = {
              subject: scanData.email_meta?.subject || '',
              sender: scanData.email_meta?.sender || '',
              from_email: scanData.email_meta?.sender || '',
              replyTo: scanData.email_meta?.reply_to || '',
              reply_to: scanData.email_meta?.reply_to || '',
              body: scanData.email_meta?.body || '',
              urls: scanData.email_meta?.urls || [],
              url_count: scanData.email_meta?.url_count || 0,
            };
            
            this.generateReport();
            return;
          } else {
            console.warn('[Report] scan_id fetch failed (status', resp.status, '), trying data param fallback');
          }
        } catch (err) {
          console.warn('[Report] scan_id fetch error:', err);
        }
      }

      // Method 2: Decode base64 payload from URL (fallback)
      if (!dataParam) {
        this.showError('No analysis data provided. Scan an email from the extension or dashboard first.');
        return;
      }

      const decodedStr = decodeURIComponent(
        atob(dataParam)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );

      const payload = JSON.parse(decodedStr);
      this.emailData = payload.emailData || {};
      this.prediction = payload.result || {};
      this.generateReport();
    } catch (error) {
      console.error('Error loading data:', error);
      this.showError('Failed to load analysis data: ' + error.message);
    }
  }

  /**
   * Generate comprehensive report
   */
  async generateReport() {
    try {
      // Show loading state
      const verdict = document.getElementById('verdict-title');
      if (verdict) {
        verdict.textContent = '🔄 Analyzing email...';
      }

      // Perform content extraction
      this.analysis = await this.extractor.extractComplete(this.emailData);

      // Verify we got valid data
      if (!this.analysis || typeof this.analysis !== 'object' || this.analysis.error) {
        throw new Error('Invalid extraction result: ' + JSON.stringify(this.analysis));
      }

      // Update UI sections
      this.renderOverview();
      this.renderURLs();
      this.renderHeaders();
      this.renderContent();
      this.renderInfrastructure();
      this.renderForensics();
      this.renderDNSResults();
      this.renderTrustAnalysis();

      // Update metadata
      this.updateMetadata();
    } catch (error) {
      console.error('Report generation error:', error);
      const verdict = document.getElementById('verdict-title');
      if (verdict) {
        verdict.textContent = '⚠️ Analysis Error';
      }
      this.showError('Error generating report: ' + (error.message || String(error)));
    }
  }

  /**
   * Render Overview Tab
   */
  renderOverview() {
    // Update verdict section
    const isPhishing = this.prediction.phishing;
    const score = this.prediction.safety_score || 0;
    const riskLevel = this.prediction.risk_level || 'MEDIUM';

    const verdictTitle = document.getElementById('verdict-title');
    const verdictDesc = document.getElementById('verdict-description');
    const verdictScore = document.getElementById('verdict-score');
    
    verdictTitle.textContent = !isPhishing ? '✓ Email Appears Safe' : '⚠️ Potential Phishing Email';
    verdictDesc.textContent = this.getPredictionDescription(!isPhishing ? 'LEGITIMATE' : 'PHISHING', riskLevel);
    verdictScore.textContent = score;
    
    // Update verdict box styling
    const box = document.getElementById('verdict-section');
    box.style.borderColor = this.getRiskColor(riskLevel);
    if (riskLevel === 'CRITICAL') box.style.borderColor = '#ff7b72';
    else if (riskLevel === 'MEDIUM') box.style.borderColor = '#e3b341';
    else box.style.borderColor = '#3fb950';

    // Render email summary
    this.renderEmailSummary();

    // Render risk factors
    this.renderRiskFactors();

    // Update metrics
    this.updateMetrics();
  }

  /**
   * Render Email Summary Card
   */
  renderEmailSummary() {
    const subjectEl = document.getElementById('email-subject');
    const senderEl = document.getElementById('email-sender');
    const replyToEl = document.getElementById('email-reply-to');
    const urlCountEl = document.getElementById('email-url-count');
    const bodyPreviewEl = document.getElementById('email-body-preview');
    const bodyPreviewRow = document.getElementById('body-preview-row');

    // Subject
    if (subjectEl) {
      subjectEl.textContent = this.emailData.subject || '(No subject)';
    }

    // Sender
    if (senderEl) {
      const sender = this.emailData.sender || this.emailData.from_email || '';
      senderEl.textContent = sender || '(Unknown sender)';
      
      // Highlight if potentially suspicious (freemail or mismatch)
      if (sender && this.analysis?.headerIntelligence?.sender_analysis?.hasHomograph) {
        senderEl.style.color = '#ff7b72';
        senderEl.textContent += ' ⚠️ (Possible homograph attack)';
      }
    }

    // Reply-To
    if (replyToEl) {
      const replyTo = this.emailData.replyTo || this.emailData.reply_to || '';
      const sender = this.emailData.sender || this.emailData.from_email || '';
      
      if (replyTo) {
        replyToEl.textContent = replyTo;
        // Check for mismatch
        if (sender && replyTo !== sender) {
          const senderDomain = sender.split('@')[1];
          const replyToDomain = replyTo.split('@')[1];
          if (senderDomain !== replyToDomain) {
            replyToEl.style.color = '#e3b341';
            replyToEl.textContent += ' ⚠️ (Different domain from sender)';
          }
        }
      } else {
        replyToEl.textContent = '(Not specified)';
      }
    }

    // URL Count
    if (urlCountEl) {
      const urls = this.emailData.urls || [];
      const urlCount = Array.isArray(urls) ? urls.length : (this.emailData.url_count || 0);
      urlCountEl.textContent = `${urlCount} URL(s) extracted`;
      
      if (urlCount > 0 && Array.isArray(urls)) {
        // Show first few URLs
        const preview = urls.slice(0, 3).map(u => `• ${this.truncateUrl(u)}`).join('\n');
        urlCountEl.textContent = `${urlCount} URL(s) extracted:\n${preview}`;
        if (urlCount > 3) {
          urlCountEl.textContent += `\n• ... and ${urlCount - 3} more`;
        }
        urlCountEl.style.whiteSpace = 'pre-wrap';
      }
    }

    // Body Preview
    if (bodyPreviewEl && bodyPreviewRow) {
      const body = this.emailData.body || '';
      if (body) {
        bodyPreviewRow.style.display = 'flex';
        // Show first 500 chars
        const preview = body.length > 500 ? body.substring(0, 500) + '...' : body;
        bodyPreviewEl.textContent = preview;
      } else {
        bodyPreviewRow.style.display = 'none';
      }
    }
  }

  /**
   * Truncate URL for display
   */
  truncateUrl(url) {
    if (url.length > 60) {
      return url.substring(0, 57) + '...';
    }
    return url;
  }

  /**
   * Render Risk Factors
   */
  renderRiskFactors() {
    const container = document.getElementById('risk-list');
    const factors = this.analysis.riskFactors || [];

    if (factors.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">✓</div>
          <p>No significant risk factors detected</p>
        </div>
      `;
      document.getElementById('risk-count').textContent = '0 detected';
      return;
    }

    // Sort by severity
    const sorted = factors.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    let html = '';
    sorted.forEach((factor, idx) => {
      const badgeClass = `badge-${factor.severity}`;
      html += `
        <div class="list-item">
          <div class="list-item-icon">${this.getRiskIcon(factor.severity)}</div>
          <div class="list-item-content">
            <div class="list-item-label">
              <span class="badge ${badgeClass}">${factor.severity}</span>
              ${factor.category}
            </div>
            <div class="list-item-details">${factor.description}</div>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
    document.getElementById('risk-count').textContent = `${factors.length} detected`;
  }

  /**
   * Update metrics display
   */
  updateMetrics() {
    document.getElementById('metric-urls').textContent = 
      this.analysis.urls?.unique_domains || 0;
    document.getElementById('metric-emails').textContent = 
      this.analysis.emails?.count || 0;
    document.getElementById('metric-ips').textContent = 
      this.analysis.ips?.count || 0;
    document.getElementById('metric-flags').textContent = 
      Object.values(this.analysis.headerIntelligence?.authentication_issues || {})
        .filter(v => v === true).length;
  }

  /**
   * Render URLs Tab
   */
  renderURLs() {
    const container = document.getElementById('urls-list');
    const urls = this.analysis.urls?.urls || [];
    const totalCount = urls.length;

    document.getElementById('urls-count').textContent = totalCount;

    if (totalCount === 0) {
      container.innerHTML = `
        <div class="card">
          <div class="card-content">
            <div class="empty-state">
              <div class="empty-state-icon">🔗</div>
              <p>No URLs extracted from email</p>
            </div>
          </div>
        </div>
      `;
      return;
    }

    // Group URLs by domain
    const grouped = {};
    urls.forEach(url => {
      if (!grouped[url.domain]) grouped[url.domain] = [];
      grouped[url.domain].push(url);
    });

    let html = '';
    for (const [domain, domainUrls] of Object.entries(grouped)) {
      const suspicious = domainUrls.some(u => u.isSuspicious);
      html += `
        <div class="card" style="border-left: 4px solid ${suspicious ? '#ff7b72' : '#3fb950'}">
          <div class="card-header">
            <div>
              <strong>${domain}</strong>
              <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                ${domainUrls.length} URL(s)
              </div>
            </div>
            <span class="badge ${suspicious ? 'badge-high' : 'badge-safe'}">
              ${suspicious ? 'SUSPICIOUS' : 'SAFE'}
            </span>
          </div>
          <div class="card-content">
            <table class="table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Type</th>
                  <th>Protocol</th>
                  <th style="width: 100px;">Action</th>
                </tr>
              </thead>
              <tbody>
                ${domainUrls.map(url => `
                  <tr>
                    <td>
                      <code style="font-size: 11px; color: var(--text-muted); word-break: break-all;">
                        ${this.truncate(url.url, 60)}
                      </code>
                    </td>
                    <td>
                      <span class="badge ${this.getTypeColor(url.extractionMethod)}">
                        ${url.extractionMethod.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>${url.protocol || 'N/A'}</td>
                    <td>
                      <button class="copy-btn" onclick="navigator.clipboard.writeText('${url.url}')">
                        Copy URL
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  }

  /**
   * Render Headers Tab
   */
  renderHeaders() {
    const container = document.getElementById('headers-content');
    const headers = this.analysis.headerIntelligence || {};

    let html = `
      <!-- Subject Analysis -->
      <div class="card">
        <div class="card-header">👁️ Subject Line Analysis</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">📌</div>
            <div class="list-item-content">
              <div class="list-item-label">Subject Text</div>
              <div class="list-item-details">${this.emailData.subject || 'N/A'}</div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.subject_analysis?.hasUrgency ? '⚡' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Urgency Detected</div>
              <div class="list-item-details">
                ${headers.subject_analysis?.hasUrgency ? 'Yes - High pressure tactics' : 'No'}
              </div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.subject_analysis?.hasExecutive ? '👔' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Executive Impersonation</div>
              <div class="list-item-details">
                ${headers.subject_analysis?.hasExecutive ? 'Possible - Chief/Director keywords' : 'No'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Sender Analysis -->
      <div class="card">
        <div class="card-header">📬 Sender Analysis</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">✉️</div>
            <div class="list-item-content">
              <div class="list-item-label">From Address</div>
              <div class="list-item-details">${this.emailData.sender || 'N/A'}</div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.sender_analysis?.isFreeMail ? '⚠️' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Freemail Provider</div>
              <div class="list-item-details">
                ${headers.sender_analysis?.isFreeMail ? 'Yes - Often abused for phishing' : 'No - Corporate/Business domain'}
              </div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.sender_analysis?.hasHomograph ? '🎭' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Homograph Attack</div>
              <div class="list-item-details">
                ${headers.sender_analysis?.hasHomograph ? 'DETECTED - Domain looks like legitimate brand' : 'Not detected'}
              </div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.sender_analysis?.domainMismatchReplyTo ? '❌' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Domain Mismatch (Sender ≠ Reply-To)</div>
              <div class="list-item-details">
                ${headers.sender_analysis?.domainMismatchReplyTo ? 'MISMATCH - Different domains' : 'No mismatch'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Reply-To Analysis -->
      <div class="card">
        <div class="card-header">↩️ Reply-To Analysis</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">✉️</div>
            <div class="list-item-content">
              <div class="list-item-label">Reply-To Address</div>
              <div class="list-item-details">${this.emailData.replyTo || '(Not specified)'}</div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">${headers.reply_to_analysis?.isDifferentFromSender ? '⚠️' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Different From Sender</div>
              <div class="list-item-details">
                ${headers.reply_to_analysis?.isDifferentFromSender ? 'Yes - Possible redirection attack' : 'No - Matches sender'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Authentication Issues -->
      <div class="card">
        <div class="card-header">🔐 Authentication Issues</div>
        <div class="card-content">
          ${Object.entries(headers.authentication_issues || {}).map(([issue, detected]) => `
            <div class="list-item">
              <div class="list-item-icon">${detected ? '❌' : '✓'}</div>
              <div class="list-item-content">
                <div class="list-item-label">${this.formatIssueLabel(issue)}</div>
                <div class="list-item-details">${detected ? 'Detected - Check SPF/DKIM/DMARC' : 'No issues detected'}</div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- SPF/DKIM/DMARC Alignment -->
      <div class="card">
        <div class="card-header">📋 Email Authentication Alignment</div>
        <div class="card-content">
          <div style="margin-bottom: 16px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Alignment Status</div>
            <div class="risk-bar">
              <div class="risk-fill" style="width: ${headers.alignment_issues?.authentication_score || 0}%">
                ${headers.alignment_issues?.authentication_score || 0}%
              </div>
            </div>
          </div>
          <div>
            <div style="font-weight: 600; margin-bottom: 8px;">Issues Found</div>
            ${headers.alignment_issues?.issues && headers.alignment_issues.issues.length > 0 
              ? headers.alignment_issues.issues.map(issue => `
                  <div class="list-item" style="padding: 6px 0;">
                    <div style="color: #ff7b72;">⚠️</div>
                    <div>${issue}</div>
                  </div>
                `).join('')
              : '<p style="color: var(--text-muted); font-size: 13px;">✓ All authentication checks passed</p>'
            }
          </div>
        </div>
      </div>
    `;

    container.innerHTML = html;
  }

  /**
   * Render Content Analysis Tab
   */
  renderContent() {
    const container = document.getElementById('content-analysis');
    const suspicious = this.analysis.suspiciousContent || {};

    let html = `
      <!-- Suspicious Patterns -->
      <div class="card">
        <div class="card-header">🔴 Suspicious Content Patterns</div>
        <div class="card-content">
    `;

    const patterns = [
      { key: 'passwords', label: 'Password Requests', icon: '🔑' },
      { key: 'creditCards', label: 'Credit Card Requests', icon: '💳' },
      { key: 'securityQuestions', label: 'Security Questions', icon: '❓' },
      { key: 'accountActivation', label: 'Account Activation Scams', icon: '🔓' },
      { key: 'paymentRequests', label: 'Payment Requests', icon: '💰' },
      { key: 'urgencyLanguage', label: 'Urgency/Pressure Tactics', icon: '⚡' }
    ];

    patterns.forEach(({ key, label, icon }) => {
      const count = suspicious.patterns?.[key] || 0;
      html += `
        <div class="list-item">
          <div class="list-item-icon">${count > 0 ? '⚠️' : '✓'}</div>
          <div class="list-item-content">
            <div class="list-item-label">${icon} ${label}</div>
            <div class="list-item-details">${count > 0 ? `${count} instance(s) detected` : 'Not detected'}</div>
          </div>
        </div>
      `;
    });

    html += `
        </div>
      </div>

      <!-- Risk Assessment -->
      <div class="card">
        <div class="card-header">⚠️ Content Risk Assessment</div>
        <div class="card-content">
          <div style="margin-bottom: 16px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Risk Level: <span class="badge ${`badge-${suspicious.risk_level}`}">${suspicious.risk_level}</span></div>
            <div class="risk-bar">
              <div class="risk-fill" style="width: ${suspicious.risk_score || 0}%">
                ${suspicious.risk_score || 0}%
              </div>
            </div>
          </div>
          <div>
            <div style="font-weight: 600; margin-bottom: 8px;">Red Flags</div>
            ${suspicious.red_flags && suspicious.red_flags.length > 0
              ? suspicious.red_flags.map(flag => `
                  <div class="list-item" style="padding: 6px 0;">
                    <div style="color: #da3633;">🚩</div>
                    <div>${flag}</div>
                  </div>
                `).join('')
              : '<p style="color: var(--text-muted); font-size: 13px;">✓ No major red flags detected</p>'
            }
          </div>
        </div>
      </div>

      <!-- Extracted Emails -->
      <div class="card">
        <div class="card-header">📧 Email Addresses in Content</div>
        <div class="card-content">
          ${this.analysis.emails?.count > 0 ? `
            <table class="table">
              <thead>
                <tr>
                  <th>Email Address</th>
                  <th>Domain</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${this.analysis.emails.emails.map(e => `
                  <tr>
                    <td><code style="font-size: 11px;">${e.email}</code></td>
                    <td>${e.domain}</td>
                    <td><span class="badge ${e.isSuspicious ? 'badge-high' : 'badge-safe'}">${e.isSuspicious ? 'SUSPICIOUS' : 'OK'}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : '<p style="color: var(--text-muted);">No email addresses extracted</p>'}
        </div>
      </div>
    `;

    container.innerHTML = html;
  }

  /**
   * Render Infrastructure Tab
   */
  renderInfrastructure() {
    const container = document.getElementById('infrastructure-content');
    const infra = this.analysis.infrastructure || {};
    const ips = this.analysis.ips || {};

    let html = `
      <!-- Server Information -->
      <div class="card">
        <div class="card-header">🖥️ Server Information</div>
        <div class="card-content">
          <div class="indicators-grid">
            <div class="indicator">
              <div class="indicator-value">${infra.dns_records || 0}</div>
              <div class="indicator-label">DNS Records</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${infra.ipv6_addresses || 0}</div>
              <div class="indicator-label">IPv6 Addresses</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${infra.mac_addresses || 0}</div>
              <div class="indicator-label">MAC Addresses</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${infra.ports_detected || 0}</div>
              <div class="indicator-label">Ports Detected</div>
            </div>
          </div>
        </div>
      </div>

      <!-- IP Intelligence -->
      <div class="card">
        <div class="card-header">🌐 IP Intelligence</div>
        <div class="card-content">
          ${ips.count > 0 ? `
            <table class="table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${ips.ips.map(ip => `
                  <tr>
                    <td><code style="font-size: 11px; font-weight: 600;">${ip.ip}</code></td>
                    <td><span class="badge badge-low">${ip.type.replace(/_/g, ' ')}</span></td>
                    <td><span class="badge ${ip.isSuspicious ? 'badge-high' : 'badge-safe'}">${ip.isSuspicious ? 'SUSPICIOUS' : 'OK'}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : '<p style="color: var(--text-muted);">No public IP addresses detected</p>'}
        </div>
      </div>

      <!-- Port Analysis -->
      ${infra.ports_detected > 0 ? `
        <div class="card">
          <div class="card-header">🔌 Port Analysis</div>
          <div class="card-content">
            ${infra.data?.ports && infra.data.ports.length > 0
              ? `<p style="color: var(--text-muted); font-size: 13px;">
                  Ports detected: ${infra.data.ports.join(', ')}
                </p>`
              : '<p style="color: var(--text-muted);">No specific ports identified</p>'
            }
          </div>
        </div>
      ` : ''}
    `;

    container.innerHTML = html;
  }

  /**
   * Render Forensics Tab
   */
  renderForensics() {
    const container = document.getElementById('forensics-content');
    const forensics = this.analysis.forensics || {};

    let html = `
      <!-- Risk Indicators Summary -->
      <div class="card">
        <div class="card-header">📊 Risk Indicators Summary</div>
        <div class="card-content">
          <div class="indicators-grid">
            <div class="indicator">
              <div class="indicator-value">${forensics.domains_count || 0}</div>
              <div class="indicator-label">Unique Domains</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${forensics.risk_indicators?.credential_harvesting || 0}</div>
              <div class="indicator-label">Credential Harvest Attempts</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${forensics.risk_indicators?.urgent_language || 0}</div>
              <div class="indicator-label">Urgency Indicators</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${forensics.risk_indicators?.brand_impersonation?.length || 0}</div>
              <div class="indicator-label">Brand Impersonations</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Brand Impersonation Detection -->
      ${forensics.risk_indicators?.brand_impersonation && forensics.risk_indicators.brand_impersonation.length > 0 ? `
        <div class="card" style="border-left-color: #ff7b72;">
          <div class="card-header">🎭 Brand Impersonation Detected</div>
          <div class="card-content">
            <p style="margin-bottom: 12px; color: var(--text-muted); font-size: 13px;">
              The email attempts to impersonate the following brands:
            </p>
            <div>
              ${forensics.risk_indicators.brand_impersonation.map(brand => `
                <span class="badge badge-critical" style="margin-right: 8px; margin-bottom: 8px;">
                  ${brand.toUpperCase()}
                </span>
              `).join('')}
            </div>
          </div>
        </div>
      ` : ''}

      <!-- Infrastructure Insights -->
      <div class="card">
        <div class="card-header">🔍 Infrastructure Insights</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">${forensics.infrastructure_insight?.uses_ip_addresses ? '⚠️' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Uses IP Addresses Instead of Domains</div>
              <div class="list-item-details">
                ${forensics.infrastructure_insight?.uses_ip_addresses ? 'Yes - Common in phishing attacks' : 'No'}
              </div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">🏢</div>
            <div class="list-item-content">
              <div class="list-item-label">Hosting Provider Risk</div>
              <div class="list-item-details">${forensics.infrastructure_insight?.hosting_provider_risk || 'Medium'}</div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">📅</div>
            <div class="list-item-content">
              <div class="list-item-label">Domain Age Risk</div>
              <div class="list-item-details">${forensics.infrastructure_insight?.domain_age_risk || 'Unknown'}</div>
            </div>
          </div>
          <div class="list-item">
            <div class="list-item-icon">🌳</div>
            <div class="list-item-content">
              <div class="list-item-label">Subdomain Abuse Detected</div>
              <div class="list-item-details">
                ${forensics.infrastructure_insight?.subdomain_abuse > 0 ? `Yes - ${forensics.infrastructure_insight.subdomain_abuse} found` : 'No'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Authentication Abuse -->
      <div class="card">
        <div class="card-header">🔐 Email Authentication Abuse</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">${forensics.risk_indicators?.authentication_abuse > 0 ? '⚠️' : '✓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Authentication Issues</div>
              <div class="list-item-details">
                ${forensics.risk_indicators?.authentication_abuse > 0 
                  ? `${forensics.risk_indicators.authentication_abuse} issue(s) detected` 
                  : 'No issues detected'}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Payment Request Abuse -->
      ${forensics.risk_indicators?.payment_requests > 0 ? `
        <div class="card" style="border-left-color: #ff7b72;">
          <div class="card-header">💰 Unauthorized Payment Request</div>
          <div class="card-content">
            <p style="color: var(--text-muted); font-size: 13px;">
              Email contains ${forensics.risk_indicators.payment_requests} payment-related request(s).
              This is a common phishing tactic.
            </p>
          </div>
        </div>
      ` : ''}
    `;

    container.innerHTML = html;
  }

  /**
   * Update metadata display
   */
  updateMetadata() {
    document.getElementById('scan-id').textContent = 
      this.prediction.scan_id || 'N/A';
    document.getElementById('scan-timestamp').textContent = 
      this.analysis.metadata?.extractionTimestamp?.split('T')[0] || 'N/A';
    document.getElementById('scan-processing').textContent = 
      (this.analysis.metadata?.processingTimeMs || 0).toFixed(0) + 'ms';
  }

  /**
   * Helper: Get prediction description
   */
  getPredictionDescription(verdict, riskLevel) {
    if (verdict === 'LEGITIMATE') {
      return 'This email appears to be legitimate based on our analysis.';
    }
    const riskDescriptions = {
      CRITICAL: 'HIGH RISK - Multiple indicators suggest this is a phishing attempt. Do not interact with links or attachments.',
      MEDIUM: 'MEDIUM RISK - This email has some suspicious characteristics. Verify sender identity before taking any action.',
      LOW: 'LOW RISK - Some minor concerns detected. Proceed with caution.'
    };
    return riskDescriptions[riskLevel] || 'Analysis complete. Review details below.';
  }

  /**
   * Helper: Get risk color
   */
  getRiskColor(riskLevel) {
    const colors = {
      CRITICAL: '#ff7b72',
      HIGH: '#e3b341',
      MEDIUM: '#e3b341',
      LOW: '#3fb950'
    };
    return colors[riskLevel] || '#3fb950';
  }

  /**
   * Helper: Get risk icon
   */
  getRiskIcon(severity) {
    const icons = {
      critical: '🚨',
      high: '⚠️',
      medium: '⚡',
      low: 'ℹ️'
    };
    return icons[severity] || 'ℹ️';
  }

  /**
   * Helper: Get type color
   */
  getTypeColor(type) {
    if (type.includes('ip')) return 'badge-critical';
    if (type.includes('shortened')) return 'badge-high';
    if (type.includes('encoded')) return 'badge-medium';
    return 'badge-low';
  }

  /**
   * Helper: Format issue label
   */
  formatIssueLabel(issue) {
    return issue
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  /**
   * Helper: Truncate text
   */
  truncate(text, len) {
    return text.length > len ? text.substring(0, len) + '...' : text;
  }

  /**
   * Show error message
   */
  showError(message) {
    document.body.innerHTML = `
      <div style="max-width: 800px; margin: 50px auto; text-align: center; color: #ff7b72; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial;">
        <h1 style="font-size: 32px; margin-bottom: 16px;">⚠️ Error</h1>
        <p style="font-size: 16px; color: #8b949e; margin-bottom: 20px;">${message}</p>
        <button onclick="history.back()" style="padding: 10px 20px; background: #2f81f7; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">
          Go Back
        </button>
      </div>
    `;
  }

  // ─── DNS Results Rendering ───────────────────────────────────────────────────

  renderDNSResults() {
    const dnsResults = this.prediction.dns_results || [];
    const dnsSummary = this.prediction.dns_summary || {};

    // Create DNS tab content area if not exists
    let container = document.getElementById('dns-content');
    if (!container) {
      // Dynamically add DNS tab
      const tabs = document.querySelector('.tabs');
      if (tabs) {
        const btn = document.createElement('button');
        btn.className = 'tab-btn';
        btn.dataset.tab = 'dns';
        btn.textContent = '🌐 DNS Verification';
        btn.addEventListener('click', (e) => {
          document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          btn.classList.add('active');
          document.getElementById('dns').classList.add('active');
        });
        tabs.appendChild(btn);
      }

      const tabContent = document.createElement('div');
      tabContent.id = 'dns';
      tabContent.className = 'tab-content';
      tabContent.innerHTML = `
        <div class="section">
          <div class="section-header">
            <span class="section-icon">🌐</span>
            <span class="section-title">Live DNS Verification</span>
            <span class="section-count" id="dns-count">0</span>
          </div>
          <div id="dns-content"></div>
        </div>
      `;
      document.querySelector('.container').appendChild(tabContent);
      container = document.getElementById('dns-content');
    }

    if (dnsResults.length === 0) {
      container.innerHTML = `
        <div class="card"><div class="card-content">
          <div class="empty-state">
            <div class="empty-state-icon">🌐</div>
            <p>No domains to verify</p>
          </div>
        </div></div>
      `;
      return;
    }

    document.getElementById('dns-count').textContent = `${dnsResults.length} domain(s)`;

    let html = `
      <div class="card">
        <div class="card-header">📊 DNS Summary</div>
        <div class="card-content">
          <div class="indicators-grid">
            <div class="indicator">
              <div class="indicator-value">${dnsSummary.total_domains || 0}</div>
              <div class="indicator-label">Total Domains</div>
            </div>
            <div class="indicator">
              <div class="indicator-value" style="color: #3fb950;">${dnsSummary.resolved || 0}</div>
              <div class="indicator-label">Resolved</div>
            </div>
            <div class="indicator">
              <div class="indicator-value" style="color: #ff7b72;">${dnsSummary.unresolved || 0}</div>
              <div class="indicator-label">Unresolved</div>
            </div>
            <div class="indicator">
              <div class="indicator-value">${dnsSummary.timed_out || 0}</div>
              <div class="indicator-label">Timed Out</div>
            </div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">🔍 Per-Domain Results</div>
        <div class="card-content">
          <table class="table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>IP Address</th>
                <th>Response Time</th>
              </tr>
            </thead>
            <tbody>
              ${dnsResults.map(r => `
                <tr>
                  <td><code style="font-size: 12px;">${r.domain}</code></td>
                  <td>
                    <span class="badge ${r.resolves ? 'badge-safe' : 'badge-critical'}">
                      ${r.dns_status.toUpperCase()}
                    </span>
                  </td>
                  <td>${r.ip || '—'}</td>
                  <td>${r.response_time_ms}ms</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
          <p style="margin-top: 12px; font-size: 12px; color: var(--text-muted);">
            ⚠️ DNS resolution alone does NOT prove a domain is safe. Phishing domains often resolve successfully.
          </p>
        </div>
      </div>
    `;

    container.innerHTML = html;
  }

  // ─── Trust Analysis Rendering ────────────────────────────────────────────────

  renderTrustAnalysis() {
    const trust = this.prediction.trust_analysis || {};
    if (!trust.trust_score && trust.trust_score !== 0) return;

    // Dynamically add Trust tab
    let container = document.getElementById('trust-content');
    if (!container) {
      const tabs = document.querySelector('.tabs');
      if (tabs) {
        const btn = document.createElement('button');
        btn.className = 'tab-btn';
        btn.dataset.tab = 'trust';
        btn.textContent = '🛡️ Trust Analysis';
        btn.addEventListener('click', (e) => {
          document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          btn.classList.add('active');
          document.getElementById('trust').classList.add('active');
        });
        tabs.appendChild(btn);
      }

      const tabContent = document.createElement('div');
      tabContent.id = 'trust';
      tabContent.className = 'tab-content';
      tabContent.innerHTML = `
        <div class="section">
          <div class="section-header">
            <span class="section-icon">🛡️</span>
            <span class="section-title">Sender Trust & Verification</span>
          </div>
          <div id="trust-content"></div>
        </div>
      `;
      document.querySelector('.container').appendChild(tabContent);
      container = document.getElementById('trust-content');
    }

    const trustPct = Math.round(trust.trust_score * 100);
    const senderTrust = trust.sender_trust || {};
    const impersonations = trust.brand_impersonation || [];
    const crossCheck = trust.cross_check || {};
    const signals = trust.trust_signals || [];
    const warnings = trust.warnings || [];

    let html = `
      <!-- Trust Score -->
      <div class="card">
        <div class="card-header">📊 Trust Score</div>
        <div class="card-content">
          <div style="margin-bottom: 16px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Overall Trust: ${trustPct}%</div>
            <div class="risk-bar">
              <div class="risk-fill" style="width: ${trustPct}%; background: ${trustPct > 30 ? '#3fb950' : '#ff7b72'};">
                ${trustPct}%
              </div>
            </div>
            <p style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">Trust is one signal among many. A high trust score does NOT guarantee safety.</p>
          </div>
        </div>
      </div>

      <!-- Sender Verification -->
      <div class="card">
        <div class="card-header">✉️ Sender Verification</div>
        <div class="card-content">
          <div class="list-item">
            <div class="list-item-icon">${senderTrust.trusted ? '✅' : '❓'}</div>
            <div class="list-item-content">
              <div class="list-item-label">Domain: ${senderTrust.base_domain || 'Unknown'}</div>
              <div class="list-item-details">
                ${senderTrust.trusted 
                  ? 'Verified ' + (senderTrust.category || '') + ' domain (match type: ' + senderTrust.match_type + ')'
                  : 'Not in verified domain registry'}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Trust Signals
    if (signals.length > 0) {
      html += `
        <div class="card">
          <div class="card-header">✅ Trust Signals</div>
          <div class="card-content">
            ${signals.map(s => `
              <div class="list-item">
                <div class="list-item-icon">✓</div>
                <div class="list-item-content">
                  <div class="list-item-details">${s}</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // Warnings
    if (warnings.length > 0) {
      html += `
        <div class="card" style="border-left: 4px solid #ff7b72;">
          <div class="card-header">⚠️ Trust Warnings</div>
          <div class="card-content">
            ${warnings.map(w => `
              <div class="list-item">
                <div class="list-item-icon">⚠️</div>
                <div class="list-item-content">
                  <div class="list-item-details">${w}</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // Brand Impersonation
    if (impersonations.length > 0) {
      html += `
        <div class="card" style="border-left: 4px solid #da3633;">
          <div class="card-header">🎭 Brand Impersonation Detected</div>
          <div class="card-content">
            ${impersonations.map(imp => `
              <div class="list-item">
                <div class="list-item-icon">🚨</div>
                <div class="list-item-content">
                  <div class="list-item-label">
                    <span class="badge badge-critical">${imp.severity.toUpperCase()}</span>
                    ${imp.brand.toUpperCase()}
                  </div>
                  <div class="list-item-details">Domain '${imp.domain}' appears to impersonate ${imp.brand} (${imp.pattern})</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // Cross-Check
    if (crossCheck.sender_reply_to_mismatch || crossCheck.sender_url_mismatch) {
      html += `
        <div class="card">
          <div class="card-header">🔗 Cross-Domain Verification</div>
          <div class="card-content">
            <div class="list-item">
              <div class="list-item-icon">${crossCheck.sender_reply_to_mismatch ? '❌' : '✓'}</div>
              <div class="list-item-content">
                <div class="list-item-label">Sender ↔ Reply-To</div>
                <div class="list-item-details">${crossCheck.sender_reply_to_mismatch ? 'MISMATCH' : 'Match'}</div>
              </div>
            </div>
            <div class="list-item">
              <div class="list-item-icon">${crossCheck.sender_url_mismatch ? '⚠️' : '✓'}</div>
              <div class="list-item-content">
                <div class="list-item-label">Sender ↔ URL Domains</div>
                <div class="list-item-details">${crossCheck.sender_url_mismatch ? 'Mismatched: ' + (crossCheck.mismatched_url_domains || []).join(', ') : 'Consistent'}</div>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  }
}

// Initialize report on page load
window.addEventListener('load', () => {
  new ReportRenderer();
});
