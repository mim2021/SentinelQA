// SentinelQA options page - online-check toggle and optional Safe Browsing key.

async function load() {
  const s = (await chrome.storage.local.get("settings")).settings || {};
  document.getElementById("online").checked = s.online !== false;
  document.getElementById("sbkey").value = s.safeBrowsingKey || "";
}

document.getElementById("save").addEventListener("click", async () => {
  await chrome.storage.local.set({
    settings: {
      online: document.getElementById("online").checked,
      safeBrowsingKey: document.getElementById("sbkey").value.trim()
    }
  });
  document.getElementById("saved").textContent = "Saved";
});

load();
