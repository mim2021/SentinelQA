// SentinelQA online checks: domain age (RDAP), DNS-over-HTTPS cross-check, Google Safe Browsing.
// Runs only from the popup, i.e. only for the site the user explicitly scans, never on every
// navigation. Each lookup sends that hostname (or URL, for Safe Browsing) to the third party named
// below, which is why they can be switched off on the options page.

const NetChecks = (function () {
  const TTL = { rdap: 24 * 3600 * 1000, doh: 5 * 60 * 1000, sb: 30 * 60 * 1000 };

  async function cached(kind, key, fetcher) {
    const id = "net_" + kind + ":" + key;
    const stored = (await chrome.storage.local.get(id))[id];
    if (stored && Date.now() - stored.at < TTL[kind]) return stored.value;
    const value = await fetcher();
    await chrome.storage.local.set({ [id]: { at: Date.now(), value: value } });
    return value;
  }

  async function fetchJson(url, options) {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, 5000);
    try {
      const res = await fetch(url, Object.assign({ signal: ctrl.signal, credentials: "omit" }, options || {}));
      if (!res.ok) return null;
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  // rdap.org redirects to the authoritative registry's RDAP server.
  function registrationDate(domain) {
    return cached("rdap", domain, async function () {
      const data = await fetchJson("https://rdap.org/domain/" + encodeURIComponent(domain));
      const ev = data && (data.events || []).find(function (e) { return e.eventAction === "registration"; });
      return ev ? ev.eventDate : null;
    });
  }

  function resolveDoh(hostname) {
    return cached("doh", hostname, async function () {
      const ips = [];
      for (const type of ["A", "AAAA"]) {
        const data = await fetchJson("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(hostname) + "&type=" + type,
                                     { headers: { accept: "application/dns-json" } });
        ((data && data.Answer) || []).forEach(function (a) {
          if (a.type === 1 || a.type === 28) ips.push(a.data);
        });
      }
      return ips;
    });
  }

  function safeBrowsing(url, apiKey) {
    return cached("sb", url, async function () {
      const data = await fetchJson("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(apiKey), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "sentinelqa", clientVersion: chrome.runtime.getManifest().version },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
          }
        })
      });
      // null = lookup failed (reported as unavailable), [] = checked and not listed
      return data ? (data.matches || []) : null;
    });
  }

  async function settings() {
    const s = (await chrome.storage.local.get("settings")).settings || {};
    return { online: s.online !== false, safeBrowsingKey: s.safeBrowsingKey || "" };
  }

  // Returns { signals, summary }: signal objects for SentinelCore.applySignals, plus a one-line
  // summary so the popup always shows that the checks ran (or why not), even when nothing was found.
  // Failed lookups are skipped, never fatal.
  async function run(url, record) {
    const opts = await settings();
    if (!opts.online) return { signals: [], summary: SentinelCore.onlineSummary(null) };
    const hostname = new URL(url).hostname;
    if (SentinelCore.isLocalHost(hostname) || SentinelCore.isIpHost(hostname)) {
      return { signals: [], summary: SentinelCore.onlineSummary({ skipped: true }) };
    }

    const observedIp = record && record.hostname === hostname ? record.serverIp : null;
    const info = { observedIp: observedIp, safeBrowsingChecked: !!opts.safeBrowsingKey };
    const jobs = [
      registrationDate(SentinelCore.registrableDomain(hostname))
        .then(function (d) { info.registered = d; return SentinelCore.domainAgeSignal(d); }),
      resolveDoh(hostname)
        .then(function (ips) { info.resolvedIps = ips; return SentinelCore.dohSignal(observedIp, ips); })
    ];
    if (opts.safeBrowsingKey) {
      jobs.push(safeBrowsing(url, opts.safeBrowsingKey)
        .then(function (m) { info.safeBrowsingMatches = m; return SentinelCore.safeBrowsingSignal(m); }));
    }
    const settled = await Promise.allSettled(jobs);
    const signals = settled.filter(function (s) { return s.status === "fulfilled"; }).map(function (s) { return s.value; });
    return { signals: signals, summary: SentinelCore.onlineSummary(info) };
  }

  return { run: run, settings: settings };
})();
