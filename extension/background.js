/* ============================================================
   PhishGuard — Background Service Worker (Manifest V3)
   - Listens for tab URL updates and auto-scans them
   - Sends Chrome notifications for high-risk pages
   - Updates the extension action icon + badge
   ============================================================ */

const API_DEFAULT = 'http://localhost:8000';

// ── Load settings ──────────────────────────────────────────
async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get(['pg_api', 'pg_auto_scan', 'pg_notifications', 'phishguard_api_key'], res => {
      resolve({
        api:           res.pg_api           ?? API_DEFAULT,
        auto_scan:     res.pg_auto_scan     ?? true,
        notifications: res.pg_notifications ?? true,
        api_key:       res.phishguard_api_key ?? null,
      });
    });
  });
}

// ── Get or generate API key ─────────────────────────────────
async function getOrFetchApiKey(api) {
  return new Promise(resolve => {
    chrome.storage.local.get(['phishguard_api_key'], async res => {
      if (res.phishguard_api_key) return resolve(res.phishguard_api_key);
      try {
        const r = await fetch(`${api}/api/keys/generate`, { method: 'POST' });
        const data = await r.json();
        const key = data.api_key;
        chrome.storage.local.set({ phishguard_api_key: key });
        resolve(key);
      } catch { resolve(null); }
    });
  });
}

// ── Scan a URL via backend ─────────────────────────────────
async function scanUrl(url, api, apiKey) {
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(`${api}/api/check-url`, {
    method:  'POST',
    headers,
    body:    JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Update icon + badge ────────────────────────────────────
function setBadge(score, tabId) {
  let color, text;
  if (score < 35) {
    color = '#22d3a5'; text = '';
  } else if (score < 65) {
    color = '#f59e0b'; text = '!';
  } else {
    color = '#f43f5e'; text = '!!';
  }
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ text: '', tabId });
}

// ── Save scan to history ───────────────────────────────────
async function pushHistory(entry) {
  const { pg_history = [] } = await new Promise(r => chrome.storage.local.get(['pg_history'], r));
  pg_history.unshift(entry);
  if (pg_history.length > 50) pg_history.length = 50;
  chrome.storage.local.set({ pg_history });
}

// ── Update global stats ────────────────────────────────────
async function incrementStats(type, isPhishing) {
  const stored = await new Promise(r =>
    chrome.storage.local.get(['pg_url_count', 'pg_email_count', 'pg_threat_count'], r)
  );
  const update = {};
  if (type === 'url')   update.pg_url_count   = (stored.pg_url_count   || 0) + 1;
  if (type === 'email') update.pg_email_count = (stored.pg_email_count || 0) + 1;
  if (isPhishing)       update.pg_threat_count = (stored.pg_threat_count || 0) + 1;
  chrome.storage.local.set(update);
}

// ── Get the extension's block page URL ────────────────────
const BLOCK_PAGE = chrome.runtime.getURL('block.html');

// ── Block a tab by redirecting to block.html ───────────────
function blockTab(tabId, url, score) {
  const blockUrl = `${BLOCK_PAGE}?url=${encodeURIComponent(url)}&score=${encodeURIComponent(score)}`;
  chrome.tabs.update(tabId, { url: blockUrl });
}

// ── Anonymous / URL-shortener domain blocklist ─────────────
const ANONYMOUS_DOMAINS = new Set([
  // URL Shorteners
  'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'is.gd', 'buff.ly',
  'adf.ly', 'shorte.st', 'ouo.io', 'sh.st', 'bc.vc',
  'linkbucks.com', 'adfly.com', 'shrinkme.io', 'cutt.ly',
  'rebrand.ly', 'bl.ink', 'tiny.cc', 'clck.ru', 'v.gd',
  't2m.io', 'short.io', 'zws.im', 'qr.ae', 'soo.gd',
  'yourls.org', 's.id', 'rb.gy', 'shorturl.at', 'tny.im',
  'urlzs.com', 'go2l.ink', 'x.co', 'po.st', 'vzturl.com',
  // Anonymizing proxies / privacy relays
  'anonymouse.org', 'hidemyass.com', 'hide.me', 'kproxy.com',
  'proxysite.com', 'whoer.net', 'zendproxy.com', 'proxfree.com',
  'vpnbook.com', 'surfshark.com', 'privateinternetaccess.com',
  'spysthis.com', 'youtubeunblocked.live', 'unblocksite.co',
  // Suspicious redirect / tracking services
  'redirect.me', 'go.redirectingat.com', 'click.linksynergy.com',
  'track.adform.net', 'clkmon.com', 'go.ad2ups.com',
  'exit.sc', 'cloaking.me', 'linkprotect.cudasvc.com',
  'spam.ly', 'spamurl.net', 'safelinking.net',
  // Known phishing redirect gates
  'iplogger.org', 'grabify.link', 'blasze.com', 'bmwforum.co',
  'geocities.ws', '000webhostapp.com', 'weebly.com',
]);

function getHostname(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}

// ── Redirect Interceptor ───────────────────────────────────
// Catches server-side and client-side redirects to anonymous domains
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only handle main frame navigations
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith('http')) return;
  if (url.startsWith(BLOCK_PAGE)) return;

  const { pg_intercept = true } = await new Promise(r =>
    chrome.storage.local.get(['pg_intercept'], r)
  );
  if (!pg_intercept) return;

  const isRedirect = details.transitionQualifiers?.includes('server_redirect') ||
                     details.transitionQualifiers?.includes('client_redirect');

  const host = getHostname(url);
  const isAnonymous = ANONYMOUS_DOMAINS.has(host);

  if (isAnonymous) {
    const reason = isRedirect ? 'Anonymous redirect intercepted' : 'Anonymous/tracking site blocked';
    console.log(`[PhishGuard] Blocking: ${url} — ${reason}`);
    chrome.action.setBadgeBackgroundColor({ color: '#f43f5e', tabId: details.tabId });
    chrome.action.setBadgeText({ text: '!!', tabId: details.tabId });
    blockTab(details.tabId, url, 75);

    await pushHistory({ type: 'redirect', text: url, score: 75, label: 'phishing', ts: Date.now() });
    await incrementStats('url', true);
  }
});

// ── Auto-scan + block handler ──────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const url = tab.url;
  if (!url || !url.startsWith('http')) return;
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

  // Don't re-scan our own block page
  if (url.startsWith(BLOCK_PAGE)) return;

  const settings = await getSettings();
  if (!settings.auto_scan) { clearBadge(tabId); return; }
  const apiKey = await getOrFetchApiKey(settings.api);

  // Fast blocklist: sites already confirmed as phishing this session
  const { pg_blocklist = [] } = await new Promise(r => chrome.storage.local.get(['pg_blocklist'], r));
  if (settings.intercept && pg_blocklist.includes(url)) {
    blockTab(tabId, url, 80);
    return;
  }

  try {
    const data = await scanUrl(url, settings.api, apiKey);
    const score = data.risk_score;
    setBadge(score, tabId);

    await pushHistory({ type: 'url', text: url, score, label: data.label, ts: Date.now() });
    await incrementStats('url', data.label === 'phishing');

    if (data.label === 'phishing' && score >= 50) {
      // Cache in fast blocklist for instant future blocking
      if (!pg_blocklist.includes(url)) {
        pg_blocklist.unshift(url);
        if (pg_blocklist.length > 200) pg_blocklist.length = 200;
        chrome.storage.local.set({ pg_blocklist });
      }

      if (settings.intercept) {
        // ── BLOCK: redirect to warning page ──────────────
        blockTab(tabId, url, score);
        return;
      }
    }

    // Notify for high-risk or suspicious pages (when blocking is off)
    if (score >= 50 && settings.notifications) {
      chrome.notifications.create(`pg_alert_${Date.now()}`, {
        type:    'basic',
        iconUrl: 'icons/icon128.png',
        title:   '⚠️ PhishGuard: Phishing Detected!',
        message: `Score ${Math.round(score)}/100 — ${url.length > 80 ? url.slice(0, 80) + '…' : url}`,
        priority: 2,
      });
    } else if (score >= 35 && score < 65 && settings.notifications) {
      chrome.notifications.create(`pg_warn_${Date.now()}`, {
        type:    'basic',
        iconUrl: 'icons/icon128.png',
        title:   '⚡ PhishGuard: Suspicious Site',
        message: `Score ${Math.round(score)}/100 — proceed with caution.`,
      });
    }
  } catch {
    clearBadge(tabId);
  }
});

// ── Context menu: "Scan this link with PhishGuard" ────────
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.create({
    id:       'scan-link',
    title:    '🛡️ Scan link with PhishGuard',
    contexts: ['link'],
  });
  chrome.storage.local.set({
    pg_api:           API_DEFAULT,
    pg_auto_scan:     true,
    pg_tooltips:      true,
    pg_intercept:     true,
    pg_notifications: true,
    pg_started_at:    Date.now(),
  });
  // Generate and store API key on install
  await getOrFetchApiKey(API_DEFAULT);
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== 'scan-link') return;
  const url = info.linkUrl;
  if (!url) return;
  const { api } = await getSettings();
  const apiKey = await getOrFetchApiKey(api);
  try {
    const data = await scanUrl(url, api, apiKey);
    const label = data.label === 'phishing' ? '⚠ Phishing' : '✓ Safe';
    const score = Math.round(data.risk_score);
    chrome.notifications.create(`pg_ctx_${Date.now()}`, {
      type:    'basic',
      iconUrl: 'icons/icon128.png',
      title:   `PhishGuard: ${label} (${score}/100)`,
      message: url.length > 100 ? url.slice(0,100)+'…' : url,
    });
  } catch {
    chrome.notifications.create(`pg_err_${Date.now()}`, {
      type:    'basic',
      iconUrl: 'icons/icon128.png',
      title:   'PhishGuard: Scan failed',
      message: 'Could not reach backend. Make sure it is running on port 8000.',
    });
  }
});
