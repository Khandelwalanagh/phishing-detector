/* ============================================================
   PhishGuard — Popup Logic
   ============================================================ */

const API_DEFAULT    = 'http://localhost:8000';
const GAUGE_CIRC     = 194.8;

let API = API_DEFAULT;

// ── Boot: load settings + init ─────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  refreshStats();
  renderHistory();
  initSettingsUI();
  autoScanCurrentTab();
  setInterval(refreshStats, 12000);
  
  // Attach event listeners
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  
  document.getElementById('url-btn').addEventListener('click', checkURL);
  document.getElementById('url-input').addEventListener('keydown', (e) => {
    if(e.key === 'Enter') checkURL();
  });
  
  document.getElementById('email-btn').addEventListener('click', checkEmail);
  document.getElementById('clear-history-btn').addEventListener('click', clearHistory);
  document.getElementById('save-settings-btn').addEventListener('click', saveSettings);
  document.getElementById('open-docs-btn').addEventListener('click', openDocs);
  
  // Event delegation for history items
  document.getElementById('history-list').addEventListener('click', (e) => {
    const item = e.target.closest('.history-item');
    if (item) {
      reloadCheck(item.dataset.type, item.dataset.text);
    }
  });

  // File Drop Zone setup
  setupFileDropZone();
  
  // Report button setup
  document.getElementById('report-threat-btn').addEventListener('click', reportThreat);
});

// ── Helpers ────────────────────────────────────────────────
function escH(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function riskCls(score) {
  if (score < 35)  return 'safe';
  if (score < 65)  return 'warning';
  return 'danger';
}

function riskColor(cls) {
  return { safe:'var(--safe)', warning:'var(--warn)', danger:'var(--danger)' }[cls];
}

function riskLabel(score, label) {
  if (label === 'phishing') return score >= 65 ? '⚠ Phishing Detected' : '⚡ Suspicious';
  return '✓ Looks Safe';
}

// ── Settings ───────────────────────────────────────────────
async function loadSettings() {
  const res = await chrome.storage.local.get(['pg_api','pg_auto_scan','pg_tooltips','pg_intercept','pg_notifications']);
  API = res.pg_api ?? API_DEFAULT;
}

function initSettingsUI() {
  chrome.storage.local.get(['pg_api','pg_auto_scan','pg_tooltips','pg_intercept','pg_notifications'], res => {
    document.getElementById('setting-api-url').value           = res.pg_api           ?? API_DEFAULT;
    document.getElementById('setting-auto-scan').checked       = res.pg_auto_scan     ?? true;
    document.getElementById('setting-tooltips').checked        = res.pg_tooltips      ?? true;
    document.getElementById('setting-intercept').checked       = res.pg_intercept     ?? true;
    document.getElementById('setting-notifications').checked   = res.pg_notifications ?? true;
  });
}

function saveSettings() {
  const api = document.getElementById('setting-api-url').value.trim() || API_DEFAULT;
  chrome.storage.local.set({
    pg_api:           api,
    pg_auto_scan:     document.getElementById('setting-auto-scan').checked,
    pg_tooltips:      document.getElementById('setting-tooltips').checked,
    pg_intercept:     document.getElementById('setting-intercept').checked,
    pg_notifications: document.getElementById('setting-notifications').checked,
  });
  API = api;
  const msg = document.getElementById('settings-msg');
  msg.textContent = '✓ Settings saved!';
  msg.style.display = 'block';
  setTimeout(() => { msg.style.display = 'none'; }, 2000);
}

// ── Stats ──────────────────────────────────────────────────
async function refreshStats() {
  // Try live backend stats first
  try {
    const res = await fetch(`${API}/api/stats`);
    if (res.ok) {
      const d = await res.json();
      document.getElementById('ms-urls').textContent   = d.total_url_checks   || 0;
      document.getElementById('ms-emails').textContent = d.total_email_checks || 0;
      const threats = (d.phishing_url_caught||0) + (d.phishing_email_caught||0);
      setThreats(threats);
      const uptime = d.uptime_s || 0;
      const m = Math.floor(uptime/60), s = uptime%60;
      document.getElementById('ms-uptime').textContent = m > 0 ? `${m}m` : `${s}s`;
      setHeaderStatus('ok');
      return;
    }
  } catch {}
  setHeaderStatus('offline');

  // Fallback to local storage counts
  const stored = await chrome.storage.local.get(['pg_url_count','pg_email_count','pg_threat_count','pg_started_at']);
  document.getElementById('ms-urls').textContent   = stored.pg_url_count   || 0;
  document.getElementById('ms-emails').textContent = stored.pg_email_count || 0;
  setThreats(stored.pg_threat_count || 0);
  const uptime = Math.round((Date.now() - (stored.pg_started_at||Date.now())) / 1000);
  const m = Math.floor(uptime/60), s = uptime%60;
  document.getElementById('ms-uptime').textContent = m > 0 ? `${m}m` : `${s}s`;
}

function setThreats(count) {
  document.getElementById('ms-threats').textContent = count;
  const card = document.getElementById('ms-threats-card');
  if (count > 0) card.classList.add('alert');
  else           card.classList.remove('alert');
}

function setHeaderStatus(state) {
  const dot    = document.getElementById('header-dot');
  const status = document.getElementById('header-status');
  if (state === 'ok') {
    dot.className = 'dot';
    dot.style.background = 'var(--safe)';
    status.textContent = 'AI Ready';
  } else {
    dot.className = 'dot warning';
    status.textContent = 'Offline';
  }
}

// ── Auto-scan current tab ──────────────────────────────────
async function autoScanCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || !tab.url.startsWith('http')) return;

    const url = tab.url;
    const short = url.length > 45 ? url.slice(0, 45) + '…' : url;
    document.getElementById('page-url-label').textContent = short;

    const autoScanEnabled = await getStorageVal('pg_auto_scan', true);
    if (!autoScanEnabled) return;

    const data = await callApi('/api/check-url', { url });
    const score = data.risk_score;
    const cls   = riskCls(score);

    // Flash the page banner to reflect threat status
    const banner = document.getElementById('page-banner');
    banner.style.background = cls === 'danger' ? 'rgba(244,63,94,0.12)'
      : cls === 'warning' ? 'rgba(245,158,11,0.1)' : 'var(--card)';
    banner.style.borderColor = cls === 'danger' ? 'rgba(244,63,94,0.3)'
      : cls === 'warning' ? 'rgba(245,158,11,0.25)' : 'var(--border)';

    document.getElementById('page-url-label').style.color =
      cls === 'danger' ? 'var(--danger)' : cls === 'warning' ? 'var(--warn)' : 'var(--text-2)';

    // Show in the URL tab automatically if dangerous
    if (score >= 35) {
      document.getElementById('url-input').value = url;
      renderResult('url', data);
    }
  } catch {}
}

// ── Tab switching ──────────────────────────────────────────
function switchTab(tab) {
  ['url','email','history','settings'].forEach(t => {
    document.getElementById(`tab-${t}`).classList.toggle('active', t === tab);
    document.getElementById(`tab-${t}-btn`).classList.toggle('active', t === tab);
    document.getElementById(`tab-${t}-btn`).setAttribute('aria-selected', t === tab ? 'true' : 'false');
  });
}

// ── API calls ──────────────────────────────────────────────
async function callApi(path, body, method='POST') {
  const opts = { method, headers: {} };
  if (body && method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${API}${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

function getStorageVal(key, def) {
  return new Promise(r => chrome.storage.local.get([key], res => r(res[key] ?? def)));
}

// ── Gauge ──────────────────────────────────────────────────
function animateGauge(prefix, score) {
  const fill    = document.getElementById(`${prefix}-gauge-fill`);
  const scoreEl = document.getElementById(`${prefix}-score`);
  const cls     = riskCls(score);
  const color   = riskColor(cls);

  const offset = GAUGE_CIRC * (1 - score / 100);
  fill.style.strokeDashoffset = offset;
  fill.style.stroke = color;

  const start = parseInt(scoreEl.textContent) || 0;
  const t0 = performance.now();
  const dur = 1100;
  function step(now) {
    const p = Math.min((now - t0) / dur, 1);
    const e = 1 - Math.pow(1 - p, 3);
    scoreEl.textContent = Math.round(start + (score - start) * e);
    scoreEl.style.color = color;
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Render result panel ────────────────────────────────────
function renderResult(prefix, data) {
  const score = data.risk_score;
  const cls   = riskCls(score);
  const panel = document.getElementById(`${prefix}-result`);
  const badge = document.getElementById(`${prefix}-badge`);

  panel.style.display = 'block';
  animateGauge(prefix, score);

  setTimeout(() => {
    badge.className   = `risk-badge ${cls}`;
    badge.textContent = riskLabel(score, data.label);
  }, 200);

  if (prefix === 'url') {
    document.getElementById('url-conf').textContent =
      data.confidence != null ? `Confidence: ${(data.confidence*100).toFixed(1)}%` : '';
    document.getElementById('url-source').textContent =
      data.model_source === 'ml_model' ? 'Source: ML + Heuristics' : 'Source: Heuristics only';
  } else {
    document.getElementById('email-conf').textContent =
      `Heuristic analysis · ${data.features?.word_count || 0} words`;
  }

  renderReasons(`${prefix}-reasons`, data.reasons, score);

  if (prefix === 'url') {
    const rawSec = document.getElementById('url-raw');
    if (data.features && Object.keys(data.features).length) {
      rawSec.style.display = 'block';
      renderFeatures('url-features', data.features);
    }
    
    // Show report button if dangerous
    const reportBtn = document.getElementById('report-threat-btn');
    if (cls === 'danger') {
      reportBtn.style.display = 'flex';
      reportBtn.dataset.url = data.url;
    } else {
      reportBtn.style.display = 'none';
    }
  }

  if (prefix === 'email') {
    renderEmailLinks(data.links_found, score);
  }
}

function reportThreat() {
  const url = document.getElementById('report-threat-btn').dataset.url;
  if (url) {
    chrome.tabs.create({ url: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}` });
  }
}

function renderReasons(id, reasons, score) {
  const el = document.getElementById(id);
  el.innerHTML = '';
  if (!reasons || reasons.length === 0) {
    el.innerHTML = `
      <div class="clean-msg">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        No suspicious signals — looks legitimate.
      </div>`;
    return;
  }
  reasons.forEach((r, i) => {
    const div = document.createElement('div');
    div.className = 'reason-item';
    div.style.animationDelay = `${i * 0.04}s`;
    div.innerHTML = `
      <svg class="reason-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
      </svg>
      <span>${escH(r)}</span>`;
    el.appendChild(div);
  });
}

function renderFeatures(id, features) {
  const grid = document.getElementById(id);
  grid.innerHTML = '';
  Object.entries(features).forEach(([k, v]) => {
    const c = document.createElement('div');
    c.className = 'feat-chip';
    const dv = typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : v;
    c.innerHTML = `<span class="feat-k">${escH(k)}</span><span class="feat-v">${escH(String(dv))}</span>`;
    grid.appendChild(c);
  });
}

function renderEmailLinks(links, parentScore) {
  const sec  = document.getElementById('email-links-section');
  const list = document.getElementById('email-links-list');
  if (!links || links.length === 0) { sec.style.display = 'none'; return; }
  sec.style.display = 'block';
  list.innerHTML = '';
  links.forEach(link => {
    const btn = document.createElement('button');
    btn.className = 'link-btn';
    btn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"/>
      </svg>
      <span>${escH(link.length > 60 ? link.slice(0,60)+'…' : link)}</span>`;
    btn.title = link;
    btn.onclick = () => {
      switchTab('url');
      document.getElementById('url-input').value = link;
      checkURL();
    };
    list.appendChild(btn);
  });
}

// ── Loading helpers ────────────────────────────────────────
function setLoading(prefix, on) {
  const btn  = document.getElementById(`${prefix}-btn`);
  const text = document.getElementById(`${prefix}-btn-text`);
  const icon = document.getElementById(`${prefix}-btn-icon`);
  btn.disabled = on;
  if (on) {
    text.textContent = 'Scanning…';
    icon.innerHTML = '<span class="spinner"></span>';
  } else {
    text.textContent = prefix === 'url' ? 'Scan' : 'Analyse Email';
    icon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>`;
  }
}

// ── URL Checker ────────────────────────────────────────────
async function checkURL() {
  const url = document.getElementById('url-input').value.trim();
  const err = document.getElementById('url-error');
  const deepScan = document.getElementById('url-deep-scan').checked;
  err.style.display = 'none';
  if (!url) { err.textContent = 'Please enter a URL.'; err.style.display = 'block'; return; }

  setLoading('url', true);
  document.getElementById('url-result').style.display = 'none';

  try {
    let finalUrl = url;
    let extraFeatures = {};
    
    // Optional Deep Scan (Redirect Trace & WHOIS)
    if (deepScan) {
      try {
        const traceData = await callApi(`/api/trace?url=${encodeURIComponent(url)}`, null, 'GET');
        if (traceData.success) finalUrl = traceData.final_url;
        
        const whoisData = await callApi(`/api/whois?domain=${encodeURIComponent(finalUrl)}`, null, 'GET');
        if (whoisData.success) {
          extraFeatures['WHOIS_Age_Days'] = whoisData.age_days || 'Unknown';
          extraFeatures['WHOIS_Is_New'] = whoisData.is_new ? 'Yes (High Risk)' : 'No';
        }
      } catch(e) { console.log('Deep scan warning:', e); }
    }

    const data = await callApi('/api/check-url', { url: finalUrl });
    
    // Merge deep scan features
    if (deepScan) {
      data.features = { ...data.features, ...extraFeatures };
      if (extraFeatures['WHOIS_Is_New'] && extraFeatures['WHOIS_Is_New'].includes('Yes')) {
        data.risk_score = Math.min(100, data.risk_score + 25);
        if (data.risk_score >= 65) data.label = 'phishing';
        data.reasons.push("Domain is extremely new (< 30 days old). High risk.");
      }
    }
    
    renderResult('url', data);
    pushHistory({ type:'url', text: url, score: data.risk_score, label: data.label, ts: Date.now() });
    refreshStats();
  } catch (e) {
    err.textContent = `⚠ ${e.message}. Is the backend running on port 8000?`;
    err.style.display = 'block';
  } finally {
    setLoading('url', false);
  }
}

// ── FIle Drop logic ────────────────────────────────────────
function setupFileDropZone() {
  const dropZone = document.getElementById('file-drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('click', () => fileInput.click());
  
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault(); dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault(); dropZone.classList.remove('dragover');
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
  const err = document.getElementById('email-error');
  err.style.display = 'none';
  setLoading('email', true);
  document.getElementById('email-result').style.display = 'none';

  try {
    const formData = new FormData();
    formData.append('file', file);
    
    const endpoint = file.type === 'application/pdf' ? '/api/analyze-document' : '/api/analyze-vision';
    const res = await fetch(`${API}${endpoint}`, {
      method: 'POST',
      body: formData
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    if (!data.success) throw new Error(data.error || "Analysis failed");

    // Stubbing the result array format to use existing UI
    const isThreat = data.analysis.toLowerCase().includes('phish') || data.analysis.toLowerCase().includes('suspicious');
    const score = isThreat ? 85 : 15;
    
    const mappedData = {
      risk_score: score,
      label: isThreat ? 'phishing' : 'legitimate',
      reasons: [data.analysis],
      features: { "File Type": file.type, "Extracted Details": "See analysis" },
      links_found: []
    };
    
    renderResult('email', mappedData);
    pushHistory({ type:'file', text: file.name, score: score, label: mappedData.label, ts: Date.now() });
    refreshStats();
  } catch (e) {
    err.textContent = `Upload Error: ${e.message}`;
    err.style.display = 'block';
  } finally {
    setLoading('email', false);
  }
}

// ── Email Checker ──────────────────────────────────────────
async function checkEmail() {
  const content = document.getElementById('email-input').value.trim();
  const err     = document.getElementById('email-error');
  err.style.display = 'none';
  if (content.length < 10) {
    err.textContent = 'Please paste email content (min 10 chars).';
    err.style.display = 'block';
    return;
  }

  setLoading('email', true);
  document.getElementById('email-result').style.display = 'none';

  try {
    const data = await callApi('/api/check-email', { content });
    renderResult('email', data);
    const preview = content.slice(0,55).replace(/\n/g,' ') + (content.length>55?'…':'');
    pushHistory({ type:'email', text: preview, score: data.risk_score, label: data.label, ts: Date.now() });
    refreshStats();
  } catch (e) {
    err.textContent = `Error: ${e.message}. Is the backend running?`;
    err.style.display = 'block';
  } finally {
    setLoading('email', false);
  }
}

// ── Scan current page btn ──────────────────────────────────
document.getElementById('scan-current-btn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  switchTab('url');
  document.getElementById('url-input').value = tab.url;
  checkURL();
});

// ── History ────────────────────────────────────────────────
function pushHistory(entry) {
  chrome.storage.local.get(['pg_history'], res => {
    const h = res.pg_history || [];
    h.unshift(entry);
    if (h.length > 30) h.length = 30;
    chrome.storage.local.set({ pg_history: h });
    renderHistory();
  });
}

function clearHistory() {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  chrome.storage.local.set({ pg_history: [] });
  renderHistory();
}

function renderHistory() {
  chrome.storage.local.get(['pg_history'], res => {
    const list  = document.getElementById('history-list');
    const items = res.pg_history || [];
    if (items.length === 0) {
      list.innerHTML = '<div class="empty-state">No scans yet.</div>';
      return;
    }
    list.innerHTML = items.map(item => {
      const cls  = riskCls(item.score);
      const type = item.type === 'url' ? '🔗 URL' : item.type === 'file' ? '📄 File' : '✉ Email';
      const time = new Date(item.ts).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
      return `
        <div class="history-item" data-type="${escH(item.type)}" data-text="${escH(item.text)}">
          <div class="h-score ${cls}">${Math.round(item.score)}</div>
          <div class="h-text">
            <div class="h-url">${escH(item.text)}</div>
            <div class="h-meta">${type} · ${time}</div>
          </div>
          <div class="h-label ${item.label}">${item.label}</div>
        </div>`;
    }).join('');
  });
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

function openDocs() {
  chrome.tabs.create({ url: `${API}/api/docs` });
}

document.getElementById('open-about-btn').addEventListener('click', () => {
  chrome.tabs.create({ url: `${API}/about.html` });
});
