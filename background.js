// SentinelQA service worker - security headers, TLS errors, redirect chains, server IP,
// all stored per tab for the popup to read.

importScripts("lib/rules.js", "lib/core.js");

const SECURITY_HEADERS = [
  "x-frame-options",
  "content-security-policy",
  "x-content-type-options",
  "strict-transport-security"
];

// Results are stored PER TAB (keyed by tab id) so pages never see each other's data.
// Updates for one tab are chained so concurrent listeners cannot overwrite each other.
const queues = {};
function updateTab(tabId, updater) {
  const key = "tab_" + tabId;
  queues[tabId] = (queues[tabId] || Promise.resolve()).then(async function () {
    const data = await chrome.storage.session.get(key);
    await chrome.storage.session.set({ [key]: updater(data[key]) });
  }).catch(function () {});
  return queues[tabId];
}

// Redirect hops per request id; a redirected navigation keeps the same request id.
const redirectChains = {};

chrome.webRequest.onBeforeRedirect.addListener(
  function (details) {
    if (details.type !== "main_frame" || details.tabId < 0) return;
    (redirectChains[details.requestId] = redirectChains[details.requestId] || []).push(details.url);
  },
  { urls: ["http://*/*", "https://*/*"] }
);

// 1) Server response headers. Fires on every page load, so it also resets that tab's record.
chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    if (details.type !== "main_frame" || details.tabId < 0) return;
    if (details.statusCode >= 300 && details.statusCode < 400) return; // intermediate redirect hop

    const url = new URL(details.url);
    const found = {};
    (details.responseHeaders || []).forEach(function (h) {
      found[h.name.toLowerCase()] = true;
    });

    // HSTS only makes sense over HTTPS, and is irrelevant for local dev servers.
    const expected = SECURITY_HEADERS.filter(function (h) {
      if (h === "strict-transport-security") {
        return url.protocol === "https:" && !SentinelCore.isLocalHost(url.hostname);
      }
      return true;
    });
    const missing = expected.filter(function (h) { return !found[h]; });
    const redirects = redirectChains[details.requestId] || [];
    delete redirectChains[details.requestId];

    updateTab(details.tabId, function (prev) {
      // If the user clicked through a certificate warning, keep that warning on the report.
      const tlsError = prev && prev.hostname === url.hostname ? prev.tlsError : undefined;
      return {
        url: details.url,
        hostname: url.hostname,
        headersMissing: missing,
        redirects: redirects,
        tlsError: tlsError,
        pageFindings: []
      };
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders"]
);

// 2) The IP the browser actually connected to, for the DNS-over-HTTPS cross-check.
chrome.webRequest.onResponseStarted.addListener(
  function (details) {
    if (details.type !== "main_frame" || details.tabId < 0 || !details.ip) return;
    updateTab(details.tabId, function (prev) {
      return Object.assign({}, prev, { serverIp: details.ip });
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

// 3) Certificate / TLS failures - what an evil-twin hotspot or intercepting proxy typically triggers.
chrome.webRequest.onErrorOccurred.addListener(
  function (details) {
    delete redirectChains[details.requestId];
    if (details.type !== "main_frame" || details.tabId < 0) return;
    if (!/ERR_CERT_|ERR_SSL_|ERR_BAD_SSL/.test(details.error)) return;
    const url = new URL(details.url);
    updateTab(details.tabId, function () {
      return { url: details.url, hostname: url.hostname, tlsError: details.error.replace(/^net::/, ""),
               headersMissing: [], redirects: [], pageFindings: [] };
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

// 4) Findings sent by content.js; sender.tab tells us which tab they belong to.
chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (msg && msg.type === "PAGE_FINDINGS" && sender.tab) {
    updateTab(sender.tab.id, function (prev) {
      return Object.assign({}, prev, { pageFindings: msg.findings, pageHostname: msg.hostname });
    });
  }
});

// 5) Clean up when a tab closes.
chrome.tabs.onRemoved.addListener(function (tabId) {
  delete queues[tabId];
  chrome.storage.session.remove(["tab_" + tabId, "rescan_" + tabId]);
});

// 6) A (re)load collects fresh results, so the popup's re-scan allowance starts over.
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo) {
  if (changeInfo.status === "loading") chrome.storage.session.remove("rescan_" + tabId);
});
