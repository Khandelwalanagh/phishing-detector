/* ============================================================
   PhishGuard — Content Script
   Runs on every webpage. Two features:
   1. Link hover tooltips showing risk summary
   2. Click interception: for high-risk links, shows a warning overlay
   ============================================================ */

const API_DEFAULT = 'http://localhost:8000';
const GAUGE_CIRC  = 194.8;
const INTERCEPT_THRESHOLD = 65; // score >= this triggers block
const TOOLTIP_THRESHOLD   = 35; // score >= this shows warning badge

let settings = {
  api:       API_DEFAULT,
  tooltips:  true,
  intercept: true,
};

// ── Load settings from chrome.storage ─────────────────────
function loadSettings(cb) {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['pg_api', 'pg_tooltips', 'pg_intercept'], (res) => {
      settings.api       = res.pg_api       ?? API_DEFAULT;
      settings.tooltips  = res.pg_tooltips  ?? true;
      settings.intercept = res.pg_intercept ?? true;
      cb();
    });
  } else {
    cb();
  }
}

// ── Scan URL via backend ───────────────────────────────────
async function scanUrl(url) {
  const res  = await fetch(`${settings.api}/api/check-url`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Risk colours ───────────────────────────────────────────
function riskCls(score) {
  if (score < 35)  return 'safe';
  if (score < 65)  return 'warning';
  return 'danger';
}
function riskColor(cls) {
  return { safe: '#22d3a5', warning: '#f59e0b', danger: '#f43f5e' }[cls];
}
function riskLabel(score, label) {
  if (label === 'phishing') return score >= 65 ? '⚠ Phishing' : '⚡ Suspicious';
  return '✓ Safe';
}

// ──────────────────────────────────────────────────────────
// 1. TOOLTIP SYSTEM
// ──────────────────────────────────────────────────────────

let tooltip       = null;
let tooltipTimer  = null;
let pendingLink   = null;
let scanCache     = {};   // url → result

function createTooltip() {
  const el = document.createElement('div');
  el.id = '__pg_tooltip__';
  el.style.cssText = `
    position: fixed;
    z-index: 2147483647;
    background: #0f0f23;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    padding: 10px 13px;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
    font-size: 12px;
    color: #f0f0ff;
    box-shadow: 0 8px 30px rgba(0,0,0,0.5);
    pointer-events: none;
    min-width: 180px;
    max-width: 280px;
    animation: __pg_fade_in .15s ease both;
    line-height: 1.5;
  `;
  // inject animation
  if (!document.getElementById('__pg_styles__')) {
    const s = document.createElement('style');
    s.id = '__pg_styles__';
    s.textContent = `
      @keyframes __pg_fade_in { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }
    `;
    document.head.appendChild(s);
  }
  document.body.appendChild(el);
  return el;
}

function showTooltip(x, y, html) {
  if (!tooltip) tooltip = createTooltip();
  tooltip.innerHTML = html;
  tooltip.style.display = 'block';
  // Position
  const vw = window.innerWidth, vh = window.innerHeight;
  let left = x + 14, top = y + 14;
  setTimeout(() => {
    const r = tooltip.getBoundingClientRect();
    if (left + r.width  > vw) left = x - r.width - 14;
    if (top  + r.height > vh) top  = y - r.height - 14;
    tooltip.style.left = `${Math.max(4, left)}px`;
    tooltip.style.top  = `${Math.max(4, top)}px`;
  }, 0);
}

function hideTooltip() {
  if (tooltip) tooltip.style.display = 'none';
}

function buildTooltipHtml(data) {
  const cls   = riskCls(data.risk_score);
  const color = riskColor(cls);
  const label = riskLabel(data.risk_score, data.label);
  const reasons = (data.reasons || []).slice(0, 3).map(r =>
    `<div style="font-size:10.5px;color:#9898b8;margin-top:3px">⚑ ${r}</div>`
  ).join('');
  return `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:${reasons ? 7 : 0}px">
      <div style="
        width:40px;height:40px;border-radius:50%;
        background:${color}22;border:2px solid ${color}55;
        display:flex;align-items:center;justify-content:center;
        font-size:14px;font-weight:800;color:${color};flex-shrink:0
      ">${Math.round(data.risk_score)}</div>
      <div>
        <div style="font-weight:700;color:${color};font-size:12px">${label}</div>
        <div style="font-size:10px;color:#5a5a7a">Risk Score · PhishGuard</div>
      </div>
    </div>
    ${reasons}
  `;
}

async function handleLinkHover(e) {
  if (!settings.tooltips) return;
  const a = e.target.closest('a[href]');
  if (!a) return;
  const url = a.href;
  if (!url || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) return;
  pendingLink = url;

  tooltipTimer = setTimeout(async () => {
    if (pendingLink !== url) return;
    showTooltip(e.clientX, e.clientY, `
      <div style="color:#9898b8;font-size:11px;display:flex;align-items:center;gap:6px">
        <span style="display:inline-block;width:10px;height:10px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:__pg_spin .6s linear infinite"></span>
        Scanning…
      </div>
    `);
    if (!document.getElementById('__pg_styles__').textContent.includes('__pg_spin')) {
      document.getElementById('__pg_styles__').textContent += `@keyframes __pg_spin{to{transform:rotate(360deg)}}`;
    }

    try {
      let data;
      if (scanCache[url]) {
        data = scanCache[url];
      } else {
        data = await scanUrl(url);
        scanCache[url] = data;
      }
      if (pendingLink === url) showTooltip(e.clientX, e.clientY, buildTooltipHtml(data));
    } catch {
      hideTooltip();
    }
  }, 500);
}

function handleLinkLeave() {
  clearTimeout(tooltipTimer);
  pendingLink = null;
  hideTooltip();
}

// ──────────────────────────────────────────────────────────
// 2. CLICK INTERCEPTION OVERLAY
// ──────────────────────────────────────────────────────────

function buildInterstitial(data, href) {
  const overlay = document.createElement('div');
  overlay.id = '__pg_overlay__';
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    z-index: 2147483646;
    background: rgba(0,0,0,0.85);
    backdrop-filter: blur(14px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
    animation: __pg_fade_in .25s ease both;
  `;
  const cls = riskCls(data.risk_score);
  const color = riskColor(cls);
  const title  = data.label === 'phishing' && data.risk_score >= 65
    ? '⚠️ Malicious Link Blocked!'
    : '⚡ Suspicious Link';
  const subtitle = data.label === 'phishing'
    ? 'This link has been identified as a phishing attack. Visiting it may expose your passwords, personal details, or install malware.'
    : 'This link looks suspicious. Proceed with caution.';

  const reasons = (data.reasons || []).slice(0, 4).map(r =>
    `<div style="display:flex;gap:8px;padding:7px 10px;background:rgba(255,255,255,0.04);border-radius:6px;font-size:12px;color:#9898b8"><span style="color:${color};flex-shrink:0">⚑</span>${r}</div>`
  ).join('');

  overlay.innerHTML = `
    <div style="background:#0f0f23;border:1px solid rgba(244,63,94,0.4);border-radius:20px;padding:36px;max-width:460px;width:100%;box-shadow:0 0 80px rgba(244,63,94,0.2);text-align:center">
      <div style="width:72px;height:72px;margin:0 auto 20px;background:rgba(244,63,94,0.1);color:#f43f5e;border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid rgba(244,63,94,0.35);box-shadow:0 0 30px rgba(244,63,94,0.3)">
        <svg width="36" height="36" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        </svg>
      </div>
      <h2 style="font-size:22px;font-weight:800;color:#fff;margin-bottom:10px">${title}</h2>
      <p style="font-size:13px;color:#9898b8;margin-bottom:18px;line-height:1.6">${subtitle}</p>

      <div style="text-align:left;display:flex;flex-direction:column;gap:5px;margin-bottom:20px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#5a5a7a;margin-bottom:2px">Detection Signals</div>
        ${reasons || `<div style="font-size:12px;color:#5a5a7a;padding:6px">No specific signals provided.</div>`}
      </div>

      <div style="font-size:10.5px;color:#5a5a7a;background:rgba(255,255,255,0.03);border-radius:6px;padding:8px 12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:22px" title="${href}">
        🔗 ${href.length > 55 ? href.slice(0,55)+'…' : href}
      </div>

      <div style="display:flex;flex-direction:column;gap:10px">
        <button id="__pg_go_back__" style="background:linear-gradient(135deg,#f43f5e,#e11d48);color:#fff;border:none;padding:14px;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;box-shadow:0 4px 20px rgba(244,63,94,0.4)">
          ← Go Back to Safety
        </button>
        <button id="__pg_proceed__" style="background:transparent;color:#5a5a7a;border:none;padding:10px;font-size:12px;cursor:pointer;text-decoration:underline">
          Proceed anyway (unsafe)
        </button>
      </div>
    </div>
  `;

  overlay.querySelector('#__pg_go_back__').addEventListener('click', () => {
    overlay.remove();
  });
  overlay.querySelector('#__pg_proceed__').addEventListener('click', () => {
    overlay.remove();
    window.location.href = href;
  });

  document.body.appendChild(overlay);
}

async function handleLinkClick(e) {
  if (!settings.intercept) return;
  const a = e.target.closest('a[href]');
  if (!a) return;
  const url = a.href;
  if (!url || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) return;
  // same-origin: don't intercept
  if (new URL(url, location.href).origin === location.origin) return;

  // already have a cached result
  const cached = scanCache[url];
  if (cached) {
    if (cached.risk_score >= INTERCEPT_THRESHOLD) {
      e.preventDefault();
      e.stopImmediatePropagation();
      buildInterstitial(cached, url);
    }
    return;
  }

  // Intercept immediately and scan asynchronously
  e.preventDefault();
  e.stopImmediatePropagation();

  // Show quick scanning overlay
  const loader = document.createElement('div');
  loader.id = '__pg_loader__';
  loader.style.cssText = `
    position:fixed;inset:0;z-index:2147483646;
    background:rgba(0,0,0,0.7);backdrop-filter:blur(10px);
    display:flex;align-items:center;justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,"Inter",sans-serif;
  `;
  loader.innerHTML = `
    <div style="text-align:center;color:#f0f0ff">
      <div style="width:40px;height:40px;border:3px solid rgba(255,255,255,0.15);border-top-color:#6c63ff;border-radius:50%;animation:__pg_spin .6s linear infinite;margin:0 auto 14px"></div>
      <div style="font-size:14px;font-weight:600">Scanning link…</div>
      <div style="font-size:11px;color:#9898b8;margin-top:4px">PhishGuard AI</div>
    </div>
  `;
  document.body.appendChild(loader);

  try {
    const data = await scanUrl(url);
    scanCache[url] = data;
    loader.remove();
    if (data.risk_score >= INTERCEPT_THRESHOLD) {
      buildInterstitial(data, url);
    } else {
      // safe — navigate normally
      window.location.href = url;
    }
  } catch {
    loader.remove();
    window.location.href = url; // fail open
  }
}

// ── Boot ───────────────────────────────────────────────────
loadSettings(() => {
  document.addEventListener('mouseover',  handleLinkHover,  { passive: true });
  document.addEventListener('mouseout',   handleLinkLeave,  { passive: true });
  document.addEventListener('click',      handleLinkClick,  { capture: true });
});
