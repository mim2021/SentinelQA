// SentinelQA popup - combines URL, page, header and online checks into one report card.
// Detection logic lives in lib/core.js (SentinelCore); this file only gathers inputs and renders.

function render(result, status) {
  const gradeEl = document.getElementById("grade");
  gradeEl.textContent = result.grade;
  gradeEl.className = result.grade;
  document.getElementById("label").textContent = result.label;
  document.getElementById("score").textContent = "Risk score: " + result.score + "/100" + (status ? " - " + status : "");
  document.getElementById("site").textContent = result.hostname;
  const list = document.getElementById("findings");
  list.textContent = "";
  const items = result.findings.length > 0
    ? result.findings.map(f => "⚠️ " + f)
    : ["✔️ No issues found at URL or page level."];
  items.forEach(text => {
    const li = document.createElement("li");
    li.textContent = text;
    list.appendChild(li);
  });
}

function renderUnscannable() {
  const gradeEl = document.getElementById("grade");
  gradeEl.textContent = "?";
  gradeEl.className = "none";
  document.getElementById("label").textContent = "Open a normal webpage first.";
  document.getElementById("score").textContent = "Browser pages (new tab, settings) cannot be scanned.";
  document.getElementById("site").textContent = "";
  document.getElementById("findings").textContent = "";
  document.getElementById("online-status").textContent = "";
  // Nothing to re-scan on browser pages, so the button would only do nothing
  document.getElementById("rescan").hidden = true;
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scan() {
  const tab = await activeTab();
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    renderUnscannable();
    return;
  }

  // Per-tab record written by background.js (headers, TLS, redirects) and content.js (page checks)
  const key = "tab_" + tab.id;
  const record = (await chrome.storage.session.get(key))[key];
  const result = SentinelCore.mergeRecord(SentinelCore.checkUrl(tab.url), record);

  const { online } = await NetChecks.settings();
  render(result, online ? "running online checks..." : "");

  const net = await NetChecks.run(tab.url, record);
  render(SentinelCore.applySignals(result, net.signals));
  document.getElementById("online-status").textContent = net.summary;
}

// Re-scan re-reads what was collected when the page loaded (headers, page checks), so repeating it
// soon stops adding anything. After MAX_RESCANS the button offers a page refresh instead, which
// collects everything again. background.js resets the count whenever the tab loads a page.
const MAX_RESCANS = 3;
const rescanKey = tabId => "rescan_" + tabId;

async function rescansUsed(tabId) {
  return (await chrome.storage.session.get(rescanKey(tabId)))[rescanKey(tabId)] || 0;
}

function showRefreshMode() {
  const button = document.getElementById("rescan");
  button.textContent = "Refresh page";
  button.dataset.mode = "refresh";
  document.getElementById("rescan-status").textContent =
    "Re-scanned " + MAX_RESCANS + " times. Refresh the page to collect fresh results.";
}

async function onRescanClick() {
  const button = document.getElementById("rescan");
  const tab = await activeTab();
  if (!tab) return;

  if (button.dataset.mode === "refresh") {
    // The reloaded page gets a fresh set of re-scans (background.js also clears this on any load).
    await chrome.storage.session.remove(rescanKey(tab.id));
    await chrome.tabs.reload(tab.id);
    window.close();
    return;
  }

  const used = await rescansUsed(tab.id);
  if (used >= MAX_RESCANS) {
    showRefreshMode();
    return;
  }

  await chrome.storage.session.set({ [rescanKey(tab.id)]: used + 1 });
  button.disabled = true;
  button.textContent = "Scanning...";
  try {
    await scan();
  } finally {
    button.disabled = false;
    button.textContent = "Re-scan this page";
  }
  document.getElementById("rescan-status").textContent =
    "Re-scanned (" + (used + 1) + "/" + MAX_RESCANS + ") at " + new Date().toLocaleTimeString();
}

async function init() {
  const tab = await activeTab();
  if (tab && (await rescansUsed(tab.id)) >= MAX_RESCANS) showRefreshMode();
  await scan();
}

document.getElementById("version").textContent = "v" + chrome.runtime.getManifest().version;
document.addEventListener("DOMContentLoaded", init);
document.getElementById("rescan").addEventListener("click", onRescanClick);
document.getElementById("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
