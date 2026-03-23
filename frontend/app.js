/* ============================================================
   PhishGuard — Application Logic
   ============================================================ */

const API = ''; // Empty string so it automatically detects localhost OR the live Render URL
const GAUGE_CIRCUMFERENCE = 251.2; // half-circle path length

// ── API Key Management ─────────────────────────────────────────
async function getApiKey() {
  let key = localStorage.getItem('phishguard_api_key');
  if (!key) {
    try {
      const res = await fetch(`${API}/api/keys/generate`, { method: 'POST', credentials: 'include' });
      const data = await res.json();
      key = data.api_key;
      localStorage.setItem('phishguard_api_key', key);
      console.log('[PhishGuard] API key generated and stored.');
    } catch (e) {
      console.warn('[PhishGuard] Could not generate API key:', e);
      return null;
    }
  }
  return key;
}

// Authenticated fetch wrapper — adds X-API-Key header automatically
async function _apiFetch(path, opts = {}) {
  const key = await getApiKey();
  const headers = { ...(opts.headers || {}) };
  if (key) headers['X-API-Key'] = key;
  return fetch(`${API}${path}`, { ...opts, headers, credentials: 'include' });
}

// ── Utility: score → colour class ────────────────────────────
function riskClass(score) {
  if (score < 35)  return 'safe';
  if (score < 65)  return 'warning';
  return 'danger';
}

function riskLabel(score, label) {
  if (label === 'phishing') return score >= 65 ? '⚠ Phishing Detected' : '⚡ Suspicious';
  return '✓ Looks Safe';
}

function riskColor(cls) {
  return { safe: 'var(--safe)', warning: 'var(--warn)', danger: 'var(--danger)' }[cls];
}

// ── Custom Cursor ────────────────────────────────────────────
(function initCursor() {
  const dot  = document.getElementById('cursor-dot');
  const ring = document.getElementById('cursor-ring');
  if (!dot || !ring) return;

  let mouseX = 0, mouseY = 0;
  let ringX  = 0, ringY  = 0;
  let rafId;

  // Dot follows mouse instantly
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    dot.style.left = mouseX + 'px';
    dot.style.top  = mouseY + 'px';
  });

  // Ring lags behind the dot with lerp
  function animateRing() {
    ringX += (mouseX - ringX) * 0.14;
    ringY += (mouseY - ringY) * 0.14;
    ring.style.left = ringX + 'px';
    ring.style.top  = ringY + 'px';
    rafId = requestAnimationFrame(animateRing);
  }
  animateRing();

  // Hover state on interactive elements
  const hoverTargets = 'a, button, input, textarea, select, label, [data-tilt], .tab-btn, .history-item, .extracted-link-btn';
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest(hoverTargets)) {
      document.body.classList.add('cursor-hover');
    }
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest(hoverTargets)) {
      document.body.classList.remove('cursor-hover');
    }
  });

  // Click flash
  document.addEventListener('mousedown', () => document.body.classList.add('cursor-clicking'));
  document.addEventListener('mouseup',   () => document.body.classList.remove('cursor-clicking'));

  // Hide cursor when it leaves the window
  document.addEventListener('mouseleave', () => { dot.style.opacity = '0'; ring.style.opacity = '0'; });
  document.addEventListener('mouseenter', () => { dot.style.opacity = '1'; ring.style.opacity = '1'; });
})();

// ── Tab switching ─────────────────────────────────────────────
function switchTab(tab) {
  ['url', 'email', 'pdf'].forEach(t => {
    document.getElementById(`tab-${t}`).classList.toggle('active', t === tab);
    const btn = document.getElementById(`tab-${t}-btn`);
    btn.classList.toggle('active', t === tab);
    btn.setAttribute('aria-selected', t === tab ? 'true' : 'false');
  });
}

// ── Gauge animation ───────────────────────────────────────────
function animateGauge(prefix, score) {
  const fill  = document.getElementById(`${prefix}-gauge-fill`);
  const scoreEl = document.getElementById(`${prefix}-gauge-score`);
  const badge = document.getElementById(`${prefix}-risk-badge`);
  const cls   = riskClass(score);
  const color = riskColor(cls);

  // Animate the arc: offset goes from full (hidden) to (1 - score/100) * circumference
  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  fill.style.strokeDashoffset = offset;
  fill.style.stroke = color;

  // Animate the number counter
  const start = parseInt(scoreEl.textContent) || 0;
  const duration = 1200;
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    scoreEl.textContent = Math.round(start + (score - start) * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);

  // Update badge
  badge.className = `risk-badge ${cls}`;
  setTimeout(() => {}, 0); // flush
}

// ── Render reasons list ────────────────────────────────────────
function renderReasons(containerId, reasons, score) {
  const el = document.getElementById(containerId);
  el.innerHTML = '';

  if (!reasons || reasons.length === 0) {
    const cls = riskClass(score);
    if (cls === 'safe') {
      el.innerHTML = `
        <div class="clean-message">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" width="20" height="20">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          No suspicious signals detected. This looks legitimate.
        </div>`;
    }
    return;
  }

  reasons.forEach((reason, i) => {
    const item = document.createElement('div');
    item.className = 'reason-item';
    item.style.animationDelay = `${i * 0.05}s`;
    item.innerHTML = `
      <svg class="reason-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
      <span>${escHtml(reason)}</span>`;
    el.appendChild(item);
  });
}

// ── Render feature chips ───────────────────────────────────────
function renderFeatures(gridId, sectionId, features) {
  const grid    = document.getElementById(gridId);
  const section = document.getElementById(sectionId);
  if (!features || Object.keys(features).length === 0) {
    section.style.display = 'none';
    return;
  }
  section.style.display = 'block';
  grid.innerHTML = '';
  Object.entries(features).forEach(([k, v]) => {
    const chip = document.createElement('div');
    chip.className = 'feature-chip';
    const displayVal = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : v;
    chip.innerHTML = `<span class="feature-key">${escHtml(k)}</span><span class="feature-val">${escHtml(String(displayVal))}</span>`;
    grid.appendChild(chip);
  });
}

// ── Render email links ─────────────────────────────────────────
function renderEmailLinks(links, parentScore) {
  const section = document.getElementById('email-links-section');
  const list = document.getElementById('email-links-list');
  
  if (!links || links.length === 0) {
    if(section) section.style.display = 'none';
    return;
  }
  
  section.style.display = 'block';
  list.innerHTML = '';
  
  links.forEach(link => {
    const btn = document.createElement('button');
    btn.className = 'extracted-link-btn';
    btn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
      </svg>
      <span>${escHtml(link)}</span>
    `;
    btn.onclick = () => {
      if (parentScore >= 65) {
        // High risk email -> assume links are extremely suspicious and warn
        showWarningModal(link, "This link was extracted from a high-risk phishing email. It is likely malicious.");
      } else {
        // Load it into the URL checker
        switchTab('url');
        document.getElementById('url-input').value = link;
        checkURL();
      }
    };
    list.appendChild(btn);
  });
}

// ── Loading state helpers ─────────────────────────────────────
function setLoading(prefix, loading) {
  const btn     = document.getElementById(`${prefix}-btn`);
  const btnText = document.getElementById(`${prefix}-btn-text`);
  const btnIcon = document.getElementById(`${prefix}-btn-icon`);

  btn.disabled = loading;
  if (loading) {
    btnText.textContent = 'Analysing…';
    btnIcon.outerHTML = `<span id="${prefix}-btn-icon" class="spinner"></span>`;
  } else {
    btnText.textContent = prefix === 'url' ? 'Analyse' : 'Analyse Email';
    const spinner = document.getElementById(`${prefix}-btn-icon`);
    if (spinner) {
      spinner.outerHTML = `<svg id="${prefix}-btn-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" /></svg>`;
    }
  }
}

function showError(prefix, msg) {
  const el = document.getElementById(`${prefix}-error`);
  document.getElementById(`${prefix}-error-msg`).textContent = msg;
  el.style.display = 'flex';
}

function clearError(prefix) {
  document.getElementById(`${prefix}-error`).style.display = 'none';
}

function showResult(prefix) {
  const el = document.getElementById(`${prefix}-result`);
  el.classList.add('visible');
}

// ── Modals ────────────────────────────────────────────────────
function showWarningModal(url, customMsg) {
  const modal = document.getElementById('warning-modal');
  const textEl = document.getElementById('warning-modal-text');
  
  if (customMsg) {
    textEl.textContent = customMsg;
  } else {
    textEl.textContent = `The link "${escHtml(url)}" has been identified as highly malicious. You should not visit it.`;
  }
  
  modal.style.display = 'flex';
  
  const proceedBtn = document.getElementById('proceed-btn');
  // Avoid duplicate listeners by cloning
  const newProceedBtn = proceedBtn.cloneNode(true);
  proceedBtn.parentNode.replaceChild(newProceedBtn, proceedBtn);
  
  newProceedBtn.onclick = () => {
    let targetUrl = url;
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'http://' + targetUrl;
    }
    window.open(targetUrl, '_blank');
    closeWarningModal();
  };
}

function closeWarningModal() {
  document.getElementById('warning-modal').style.display = 'none';
}

// ── Escape HTML ───────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── History ───────────────────────────────────────────────────
const MAX_HISTORY = 8;

function loadHistory() {
  try { return JSON.parse(localStorage.getItem('phish_history') || '[]'); }
  catch { return []; }
}

function saveHistory(items) {
  localStorage.setItem('phish_history', JSON.stringify(items));
}

function pushHistory(entry) {
  const items = loadHistory();
  items.unshift(entry);
  if (items.length > MAX_HISTORY) items.length = MAX_HISTORY;
  saveHistory(items);
  renderHistory();
}

function clearHistory() {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  localStorage.removeItem('phish_history');
  renderHistory();
}

function renderHistory() {
  const list  = document.getElementById('history-list');
  const items = loadHistory();
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-history">No checks yet — paste a URL or email above to get started.</div>';
    return;
  }
  list.innerHTML = items.map(item => {
    const cls   = riskClass(item.score);
    const time  = new Date(item.ts).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
    const type  = item.type === 'url' ? '🔗 URL' : '✉ Email';
    return `
      <div class="history-item" title="${escHtml(item.text)}" onclick="reloadCheck('${item.type}', ${JSON.stringify(escHtml(item.text))})">
        <div class="history-score ${cls}">${Math.round(item.score)}</div>
        <div class="history-text">
          <div class="history-url">${escHtml(item.text)}</div>
          <div class="history-meta">${type} · ${time}</div>
        </div>
        <div class="history-label ${item.label}">${item.label}</div>
      </div>`;
  }).join('');
}

function reloadCheck(type, text) {
  if (type === 'url') {
    switchTab('url');
    document.getElementById('url-input').value = text;
    checkURL();
  } else {
    switchTab('email');
    document.getElementById('email-input').value = text;
    checkEmail();
  }
}

// ── Export PDF ───────────────────────────────────────────────
async function exportPDF() {
  const btn = document.getElementById('export-pdf-btn');
  const originalHtml = btn.innerHTML;
  btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;display:inline-block;vertical-align:middle;margin-right:4px;border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff;"></span> Exporting...';
  btn.disabled = true;

  try {
    const res = await _apiFetch('/api/export/history/pdf', { method: 'GET' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = 'PhishGuard_Report.pdf';
    document.body.appendChild(a);
    a.click();
    
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (err) {
    alert('Failed to export PDF: ' + err.message);
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

// ── Stats ────────────────────────────────────────────────────
async function refreshStats() {
  try {
    const res = await fetch(`${API}/api/stats`, { credentials: 'include' });
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('stat-total-urls').textContent   = data.total_url_checks   || 0;
    document.getElementById('stat-total-emails').textContent = data.total_email_checks || 0;
    
    const phishingCount = (data.phishing_url_caught || 0) + (data.phishing_email_caught || 0);
    document.getElementById('stat-phishing-caught').textContent = phishingCount;
    if (phishingCount > 0) {
      document.getElementById('stat-phishing-caught').parentElement.classList.add('alert-state');
    }

    const uptime = data.uptime_s || 0;
    const m = Math.floor(uptime / 60), s = uptime % 60;
    document.getElementById('stat-uptime').textContent =
      m > 0 ? `${m}m ${s}s` : `${s}s`;
  } catch { /* server not yet up */ }
}

// ─────────────────────────────────────────────────────────────
// URL Checker
// ─────────────────────────────────────────────────────────────
async function checkURL() {
  const input = document.getElementById('url-input');
  const url   = input.value.trim();
  clearError('url');

  if (!url) {
    showError('url', 'Please enter a URL to analyse.');
    return;
  }
  const deepScan = document.getElementById('url-deep-scan').checked;

  setLoading('url', true);
  document.getElementById('url-result').classList.remove('visible');

  try {
    let finalUrl = url;
    let extraFeatures = {};
    
    // Optional Deep Scan
    if (deepScan) {
      try {
        const traceRes = await fetch(`${API}/api/trace?url=${encodeURIComponent(url)}`);
        const traceData = await traceRes.json();
        if (traceData.success) finalUrl = traceData.final_url;
        
        const whoisRes = await fetch(`${API}/api/whois?domain=${encodeURIComponent(finalUrl)}`);
        const whoisData = await whoisRes.json();
        if (whoisData.success) {
          extraFeatures['WHOIS_Age_Days'] = whoisData.age_days || 'Unknown';
          extraFeatures['WHOIS_Is_New'] = whoisData.is_new ? 'Yes (High Risk)' : 'No';
        }
      } catch (e) { console.log('Deep scan warning:', e); }
    }

    const res = await _apiFetch(`/api/check-url`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: finalUrl }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const score = data.risk_score;
    const cls   = riskClass(score);
    const badge = document.getElementById('url-risk-badge');

    showResult('url');
    animateGauge('url', score);

    setTimeout(() => {
      badge.className  = `risk-badge ${cls}`;
      badge.textContent = riskLabel(score, data.label);

      // Report Button
      const reportBtn = document.getElementById('url-report-btn');
      if (cls === 'danger') {
        reportBtn.style.display = 'flex';
        reportBtn.onclick = () => window.open(`https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(data.url)}`, '_blank');
      } else {
        reportBtn.style.display = 'none';
      }

      if (score >= 65) {
        showWarningModal(url);
      }
    }, 200);

    // Merge deep scan features
    if (deepScan) {
      data.features = { ...data.features, ...extraFeatures };
      if (extraFeatures['WHOIS_Is_New'] && extraFeatures['WHOIS_Is_New'].includes('Yes')) {
        score = Math.min(100, score + 25);
        if (score >= 65) data.label = 'phishing';
        data.reasons.push("Domain is extremely new (< 30 days old). High risk.");
      }
    }

    // Confidence row
    const confEl = document.getElementById('url-confidence-row');
    if (data.confidence != null) {
      confEl.textContent = `Confidence: ${(data.confidence * 100).toFixed(1)}% · via ${data.model_source === 'ml_model' ? 'ML Model' : 'Heuristics'}`;
    } else {
      confEl.textContent = '';
    }

    renderReasons('url-reasons-list', data.reasons, score);
    renderFeatures('url-feature-grid', 'url-features-section', data.features);

    pushHistory({ type: 'url', text: url, score, label: data.label, ts: Date.now() });
    refreshStats();

    // ── Gemini AI Explanation ────────────────────────
    fetchAIExplanation('url', url, score, data.label, data.reasons, 'url-ai-explanation');

  } catch (err) {
    showError('url', `Error: ${err.message}. Is the backend running on port 8000?`);
  } finally {
    setLoading('url', false);
  }
}

// ─────────────────────────────────────────────────────────────
// Email Checker
// ─────────────────────────────────────────────────────────────
async function checkEmail() {
  const content = document.getElementById('email-input').value.trim();
  clearError('email');

  if (content.length < 10) {
    showError('email', 'Please paste some email content (at least 10 characters).');
    return;
  }

  setLoading('email', true);
  document.getElementById('email-result').classList.remove('visible');

  try {
    const res = await _apiFetch(`/api/check-email`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ content }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const score = data.risk_score;
    const cls   = riskClass(score);
    const badge = document.getElementById('email-risk-badge');

    showResult('email');
    animateGauge('email', score);

    setTimeout(() => {
      badge.className  = `risk-badge ${cls}`;
      badge.textContent = riskLabel(score, data.label);

      // Report Button
      const reportBtn = document.getElementById('email-report-btn');
      if (cls === 'danger') {
        reportBtn.style.display = 'flex';
        // Mock a URL for report if none found, or just open generic form
        reportBtn.onclick = () => window.open(`https://safebrowsing.google.com/safebrowsing/report_phish/`, '_blank');
      } else {
        reportBtn.style.display = 'none';
      }
    }, 200);

    document.getElementById('email-confidence-row').textContent =
      `Heuristic analysis · ${data.features?.word_count || 0} words`;

    renderReasons('email-reasons-list', data.reasons, score);
    renderEmailLinks(data.links_found, score);
    renderFeatures('email-feature-grid', 'email-features-section', data.features);

    const preview = content.slice(0, 60).replace(/\n/g, ' ') + (content.length > 60 ? '…' : '');
    pushHistory({ type: 'email', text: preview, score, label: data.label, ts: Date.now() });
    refreshStats();

    // ── Gemini AI Explanation ────────────────────────
    fetchAIExplanation('email', content, score, data.label, data.reasons, 'email-ai-explanation');

  } catch (err) {
    showError('email', `Error: ${err.message}. Is the backend running on port 8000?`);
  } finally {
    setLoading('email', false);
  }
}

// ── Init ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  renderHistory();
  refreshStats();
  setInterval(refreshStats, 10000); // refresh stats every 10s
  setupFileDropZone();
  // Ensure API key exists on page load (sets session cookie too)
  await getApiKey();
});

// ── Gemini AI Explanation ──────────────────────────────────
async function fetchAIExplanation(type, content, score, label, reasons, targetId) {
  const container = document.getElementById(targetId);
  if (!container) return;

  // Show a loading shimmer
  container.style.display = 'block';
  container.innerHTML = `
    <div class="ai-explanation-card loading">
      <div class="ai-exp-header">
        <span class="ai-exp-icon">🤖</span>
        <span class="ai-exp-title">Gemini AI is analysing…</span>
        <span class="ai-exp-badge">AI</span>
      </div>
      <div class="ai-exp-shimmer"></div>
    </div>`;

  try {
    const res = await _apiFetch(`/api/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content_type: type, content, risk_score: score, label, reasons }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    // Render the explanation as styled bullet points
    const lines = data.explanation.split('\n').filter(l => l.trim());
    const html = lines.map(line => {
      const clean = escHtml(line.trim());
      return `<div class="ai-exp-line">${clean}</div>`;
    }).join('');

    container.innerHTML = `
      <div class="ai-explanation-card">
        <div class="ai-exp-header">
          <span class="ai-exp-icon">🤖</span>
          <span class="ai-exp-title">Gemini AI Explanation</span>
          <span class="ai-exp-badge">AI</span>
        </div>
        <div class="ai-exp-body">${html}</div>
      </div>`;
  } catch (err) {
    container.innerHTML = `
      <div class="ai-explanation-card error">
        <div class="ai-exp-header">
          <span class="ai-exp-icon">⚠️</span>
          <span class="ai-exp-title">AI explanation unavailable: ${escHtml(err.message)}</span>
        </div>
      </div>`;
  }
}

// ── FIle Drop logic ────────────────────────────────────────
function setupFileDropZone() {
  const dropZone = document.getElementById('file-drop-zone');
  const fileInput = document.getElementById('file-input');
  if(!dropZone) return;

  dropZone.addEventListener('click', () => fileInput.click());
  
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault(); dropZone.style.background = 'rgba(124, 58, 237, 0.1)'; dropZone.style.borderColor = 'rgba(124, 58, 237, 0.5)';
  });
  dropZone.addEventListener('dragleave', () => { 
    dropZone.style.background = 'rgba(0,0,0,0.1)'; dropZone.style.borderColor = 'rgba(255,255,255,0.2)';
  });
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault(); 
    dropZone.style.background = 'rgba(0,0,0,0.1)'; dropZone.style.borderColor = 'rgba(255,255,255,0.2)';
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  });
}

async function handleFileUpload(file) {
  clearError('email');
  setLoading('email', true);
  document.getElementById('email-result').classList.remove('visible');

  try {
    const formData = new FormData();
    formData.append('file', file);
    
    const endpoint = file.type === 'application/pdf' ? '/api/analyze-document' : '/api/analyze-vision';
    const res = await _apiFetch(endpoint, {
      method: 'POST',
      body: formData
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (!data.success) throw new Error(data.error || "Analysis failed");

    const isThreat = data.analysis.toLowerCase().includes('phish') || data.analysis.toLowerCase().includes('suspicious');
    const score = isThreat ? 85 : 15;
    
    const mappedData = {
      risk_score: score,
      label: isThreat ? 'phishing' : 'legitimate',
      reasons: [data.analysis],
      features: { "File Type": file.type, "Extracted Details": "See AI analysis" },
      links_found: []
    };
    
    showResult('email');
    animateGauge('email', score);

    setTimeout(() => {
      const cls = riskClass(score);
      const badge = document.getElementById('email-risk-badge');
      badge.className  = `risk-badge ${cls}`;
      badge.textContent = riskLabel(score, mappedData.label);

      const reportBtn = document.getElementById('email-report-btn');
      if (cls === 'danger') {
        reportBtn.style.display = 'flex';
        reportBtn.onclick = () => window.open(`https://safebrowsing.google.com/safebrowsing/report_phish/`, '_blank');
      } else {
        reportBtn.style.display = 'none';
      }
    }, 200);

    document.getElementById('email-confidence-row').textContent = `AI Vision / Document Processing`;
    renderReasons('email-reasons-list', mappedData.reasons, score);
    renderEmailLinks(mappedData.links_found, score);
    renderFeatures('email-feature-grid', 'email-features-section', mappedData.features);
    pushHistory({ type: 'file', text: file.name, score, label: mappedData.label, ts: Date.now() });
    refreshStats();
  } catch (err) {
    showError('email', `Upload Error: ${err.message}. Is the backend fully configured?`);
  } finally {
    setLoading('email', false);
  }
}

// ── PDF Checker ───────────────────────────────────────────────
let selectedPdfFile = null;

function setupPdfDropZone() {
  const dropZone  = document.getElementById('pdf-drop-zone');
  const fileInput = document.getElementById('pdf-input');
  const browseBtn = document.getElementById('pdf-browse-btn');
  const clearBtn  = document.getElementById('pdf-clear-btn');

  browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) setPdfFile(file);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files[0]) setPdfFile(e.target.files[0]);
  });
  clearBtn.addEventListener('click', clearPdfFile);
}

function setPdfFile(file) {
  if (!file.name.endsWith('.pdf') && file.type !== 'application/pdf') {
    showError('pdf', 'Only PDF files are supported. Please select a .pdf file.');
    return;
  }
  selectedPdfFile = file;
  document.getElementById('pdf-file-name').textContent = file.name;
  document.getElementById('pdf-file-size').textContent = `(${(file.size / 1024).toFixed(1)} KB)`;
  document.getElementById('pdf-file-info').style.display = 'flex';
  document.getElementById('pdf-drop-zone').style.display = 'none';
  document.getElementById('pdf-btn').disabled = false;
  document.getElementById('pdf-error').style.display = 'none';
  document.getElementById('pdf-result').style.display = 'none';
}

function clearPdfFile() {
  selectedPdfFile = null;
  document.getElementById('pdf-file-info').style.display = 'none';
  document.getElementById('pdf-drop-zone').style.display = 'block';
  document.getElementById('pdf-btn').disabled = true;
  document.getElementById('pdf-input').value = '';
  document.getElementById('pdf-result').style.display = 'none';
  document.getElementById('pdf-error').style.display = 'none';
}

async function checkPDF() {
  if (!selectedPdfFile) return;
  const errorEl = document.getElementById('pdf-error');
  errorEl.style.display = 'none';

  // Button loading state
  const btn     = document.getElementById('pdf-btn');
  const btnText = document.getElementById('pdf-btn-text');
  const btnIcon = document.getElementById('pdf-btn-icon');
  btn.disabled = true;
  btnText.textContent = 'Analysing…';
  btnIcon.innerHTML = '<span class="spinner"></span>';
  document.getElementById('pdf-result').style.display = 'none';

  try {
    const formData = new FormData();
    formData.append('file', selectedPdfFile);

    const res = await _apiFetch('/api/analyze-document', { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (!data.success) throw new Error(data.error || 'Could not analyse the PDF.');

    // Score based on keywords in the AI analysis
    const analysis = data.analysis || '';
    const lc = analysis.toLowerCase();
    const isPhishing = lc.includes('phish') || lc.includes('malicious') || lc.includes('suspicious') || lc.includes('scam') || lc.includes('fraud');
    const isSafe = lc.includes('safe') || lc.includes('legitimate') || lc.includes('no threat') || lc.includes('no phishing');
    const score = isPhishing ? (lc.includes('high') ? 88 : 68) : isSafe ? 12 : 45;
    const label = score >= 35 ? 'phishing' : 'legitimate';
    const cls   = riskClass(score);

    // Show result
    document.getElementById('pdf-result').style.display = 'block';

    // Animate gauge
    animateGauge('pdf', score);
    setTimeout(() => {
      const badge = document.getElementById('pdf-risk-badge');
      badge.className = `risk-badge ${cls}`;
      badge.textContent = riskLabel(score, label);

      // Render AI analysis as a reason card
      const reasonsList = document.getElementById('pdf-reasons-list');
      reasonsList.innerHTML = `
        <div class="reason-item" style="display:block; line-height:1.7; font-size:0.875rem; color:var(--text-secondary);">${analysis.replace(/\n/g, '<br>')}</div>
      `;

      // Extracted text preview
      if (data.extracted_text_preview) {
        document.getElementById('pdf-text-preview').style.display = 'block';
        document.getElementById('pdf-text-content').textContent = data.extracted_text_preview;
      }

      // Report button
      const reportBtn = document.getElementById('pdf-report-btn');
      if (cls === 'danger') {
        reportBtn.style.display = 'flex';
        reportBtn.onclick = () => window.open('https://safebrowsing.google.com/safebrowsing/report_phish/', '_blank');
      } else {
        reportBtn.style.display = 'none';
      }

      document.getElementById('pdf-confidence-row').textContent = 'Gemini AI Document Analysis';
    }, 200);

    pushHistory({ type: 'pdf', text: selectedPdfFile.name, score, label, ts: Date.now() });
    refreshStats();
  } catch (err) {
    showError('pdf', `⚠ ${err.message}`);
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Analyse PDF';
    btnIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" width="16" height="16"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>`;
  }
}

function showError(prefix, message) {
  const el  = document.getElementById(`${prefix}-error`);
  const msg = document.getElementById(`${prefix}-error-msg`);
  if (!el || !msg) return;
  msg.textContent = message;
  el.style.display = 'flex';
}

// Init PDF drop zone on load
document.addEventListener('DOMContentLoaded', setupPdfDropZone);

// ═══════════════════════════════════════════════════════════
// AI Chatbot
// ═══════════════════════════════════════════════════════════
let chatOpen = false;
let chatHistory = [];   // [{role: 'user'|'assistant', content: '...'}]

function toggleChat() {
  chatOpen = !chatOpen;
  const panel = document.getElementById('chatbot-panel');
  const fab   = document.getElementById('chatbot-fab');
  panel.classList.toggle('open', chatOpen);
  fab.classList.toggle('active', chatOpen);
  if (chatOpen) {
    document.getElementById('chatbot-input').focus();
    scrollChatToBottom();
  }
}

function scrollChatToBottom() {
  const el = document.getElementById('chatbot-messages');
  el.scrollTop = el.scrollHeight;
}

function formatTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function appendMessage(role, text) {
  const container = document.getElementById('chatbot-messages');
  const div = document.createElement('div');
  div.className = `chat-msg ${role === 'user' ? 'user-msg' : 'bot-msg'}`;

  // Simple markdown-like rendering
  const formatted = escHtml(text)
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>');

  div.innerHTML = `
    <div class="chat-bubble">${formatted}</div>
    <div class="chat-time">${formatTime()}</div>`;
  container.appendChild(div);
  scrollChatToBottom();
}

function showTyping() {
  const container = document.getElementById('chatbot-messages');
  const div = document.createElement('div');
  div.id = 'chat-typing';
  div.className = 'chat-msg bot-msg';
  div.innerHTML = `<div class="chat-bubble typing-bubble"><span></span><span></span><span></span></div>`;
  container.appendChild(div);
  scrollChatToBottom();
}

function hideTyping() {
  document.getElementById('chat-typing')?.remove();
}

function sendSuggestion(btn) {
  document.getElementById('chatbot-input').value = btn.textContent;
  document.getElementById('chat-suggestions').style.display = 'none';
  sendChat();
}

async function sendChat() {
  const input = document.getElementById('chatbot-input');
  const message = input.value.trim();
  if (!message) return;
  input.value = '';

  // Hide suggestions after first message
  document.getElementById('chat-suggestions').style.display = 'none';

  appendMessage('user', message);
  chatHistory.push({ role: 'user', content: message });

  const sendBtn = document.getElementById('chatbot-send-btn');
  sendBtn.disabled = true;
  showTyping();

  try {
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        email_context: '',
        history: chatHistory.slice(-10).map(m => ({
          role: m.role === 'user' ? 'user' : 'model',
          content: m.content,
        })),
      }),
    });
    const data = await res.json();
    hideTyping();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    const reply = data.response || 'Sorry, I could not generate a response.';
    appendMessage('bot', reply);
    chatHistory.push({ role: 'assistant', content: reply });
    // Keep history manageable
    if (chatHistory.length > 20) chatHistory = chatHistory.slice(-20);
  } catch (err) {
    hideTyping();
    appendMessage('bot', `⚠️ ${err.message.includes('429') ? 'Rate limit reached — please wait a moment.' : err.message}`);
  } finally {
    sendBtn.disabled = false;
    input.focus();
  }
}

function clearChat() {
  chatHistory = [];
  const container = document.getElementById('chatbot-messages');
  container.innerHTML = `
    <div class="chat-msg bot-msg">
      <div class="chat-bubble">
        👋 Chat cleared! How can I help you with cybersecurity today?
      </div>
      <div class="chat-time">${formatTime()}</div>
    </div>
    <div class="chat-suggestions" id="chat-suggestions">
      <button class="chat-suggestion-btn" onclick="sendSuggestion(this)">Is this email a scam?</button>
      <button class="chat-suggestion-btn" onclick="sendSuggestion(this)">How do I spot phishing?</button>
      <button class="chat-suggestion-btn" onclick="sendSuggestion(this)">What are red flags in URLs?</button>
      <button class="chat-suggestion-btn" onclick="sendSuggestion(this)">How to stay safe online?</button>
    </div>`;
}

// ── Particles Initialization ─────────────────────────────────
window.addEventListener('load', () => {
  // Init VanillaTilt on all tilt-enabled elements (in case library loaded after DOMContentLoaded)
  if (typeof VanillaTilt !== 'undefined') {
    VanillaTilt.init(document.querySelectorAll('[data-tilt]'));
  }

  // Init tsParticles cyber-network background
  if (typeof tsParticles !== 'undefined') {
    tsParticles.load("tsparticles", {
      fpsLimit: 60,
      particles: {
        number: { value: 35, density: { enable: true, value_area: 800 } },
        color: { value: ["#6c63ff", "#f43f5e", "#22d3a5"] },
        links: { enable: true, color: "#6c63ff", distance: 150, opacity: 0.15, width: 1 },
        move: { enable: true, speed: 0.8, direction: "none", random: true, straight: false, outModes: "out" },
        size: { value: { min: 1, max: 3 } },
        opacity: { value: { min: 0.1, max: 0.5 } }
      },
      interactivity: {
        events: { onHover: { enable: true, mode: "grab" } },
        modes: { grab: { distance: 160, links: { opacity: 0.35 } } }
      },
      detectRetina: true
    });
  }
});

