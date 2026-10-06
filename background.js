// SentinelQA v0.3.0 - security header checks + per-tab result storage

const SECURITY_HEADERS = [
  "x-frame-options",
  "content-security-policy",
  "x-content-type-options",
  "strict-transport-security"
];

function isLocalHost(h) {
  return h === "localhost" || h.endsWith(".localhost") || h === "127.0.0.1" || h === "[::1]";
}

// Results are stored PER TAB (keyed by tab id) so pages never see each other's data.
async function updateTab(tabId, patch, replace) {
  const key = "tab_" + tabId;
  const data = await chrome.storage.session.get(key);
  const record = replace ? patch : Object.assign({}, data[key] || {}, patch);
  await chrome.storage.session.set({ [key]: record });
}

// 1) Server response headers. Fires on every page load, so it also resets that tab's record.
chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    if (details.type !== "main_frame" || details.tabId < 0) return;

    const url = new URL(details.url);
    const found = {};
    (details.responseHeaders || []).forEach(function (h) {
      found[h.name.toLowerCase()] = true;
    });

    // HSTS only makes sense over HTTPS, and is irrelevant for local dev servers.
    const expected = SECURITY_HEADERS.filter(function (h) {
      if (h === "strict-transport-security") {
        return url.protocol === "https:" && !isLocalHost(url.hostname);
      }
      return true;
    });
    const missing = expected.filter(function (h) { return !found[h]; });

    updateTab(details.tabId, {
      url: details.url,
      hostname: url.hostname,
      headersMissing: missing,
      pageFindings: []
    }, true);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders"]
);

// 2) Findings sent by content.js; sender.tab tells us which tab they belong to.
chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (msg && msg.type === "PAGE_FINDINGS" && sender.tab) {
    updateTab(sender.tab.id, { pageFindings: msg.findings, pageHostname: msg.hostname });
  }
});

// 3) Clean up when a tab closes.
chrome.tabs.onRemoved.addListener(function (tabId) {
  chrome.storage.session.remove("tab_" + tabId);
});