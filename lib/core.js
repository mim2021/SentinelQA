// SentinelQA shared detection core.
// Pure logic only (no chrome.* calls), so the same file is loaded as a classic script by the
// popup, the content script and the service worker, and via require() by the Node tests.
// Brand, TLD and look-alike data come from lib/rules.js, generated from shared/rules.json so the
// extension and the TrustGuard bot score with identical data. Load lib/rules.js first.

(function (root) {
  const RULES = typeof module !== "undefined" && module.exports ? require("./rules.js") : root.SentinelRules;
  const SUSPICIOUS_TLDS = RULES.suspiciousTlds;
  const KEYWORDS = ["login", "signin", "verify", "verification", "account", "update", "secure",
                    "confirm", "password", "banking", "wallet", "unlock", "suspended", "invoice", "webscr"];
  const LURE_WORDS = ["gift", "giftcard", "gift-card", "free", "nitro", "reward", "prize", "giveaway", "airdrop", "claim"];

  // Brands most often impersonated in credential phishing, with their official registrable domains.
  const BRANDS = RULES.brands;

  // Second-level suffixes where the registrable domain has three labels (example.co.uk).
  const MULTI_PART_SUFFIXES = RULES.multiPartSuffixes;

  // Characters attackers swap in to imitate letters (paypa1, disc0rd, stearn).
  const LOOKALIKE_MAP = RULES.lookalikeMap;

  const HEADER_NAMES = {
    "x-frame-options": "X-Frame-Options (clickjacking protection)",
    "content-security-policy": "Content-Security-Policy (injection protection)",
    "x-content-type-options": "X-Content-Type-Options (MIME-sniffing protection)",
    "strict-transport-security": "Strict-Transport-Security (forces HTTPS)"
  };

  function isLocalHost(h) {
    return h === "localhost" || h.endsWith(".localhost") || h === "127.0.0.1" || h === "[::1]";
  }

  function isIpHost(h) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[");
  }

  function registrableDomain(hostname) {
    const h = hostname.toLowerCase().replace(/\.$/, "");
    if (isIpHost(h)) return h;
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const lastTwo = parts.slice(-2).join(".");
    return parts.slice(MULTI_PART_SUFFIXES.includes(lastTwo) ? -3 : -2).join(".");
  }

  function normalizeLookalikes(s) {
    let out = s.toLowerCase();
    LOOKALIKE_MAP.forEach(function (pair) { out = out.split(pair[0]).join(pair[1]); });
    return out;
  }

  function editDistance(a, b) {
    const dp = Array.from({ length: a.length + 1 }, function (_, i) { return [i]; });
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                            dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
    }
    return dp[a.length][b.length];
  }

  function isOfficialDomain(hostname, brandKey) {
    return BRANDS[brandKey].domains.includes(registrableDomain(hostname));
  }

  // Returns { brand, name, kind } when a hostname imitates a known brand, else null.
  //   kind "lookalike": the domain is a near-copy of an official one (steamcommunnity.com, paypa1.com)
  //   kind "contains":  the brand name appears in a domain the brand does not own (steam-gift.xyz)
  function checkBrandImpersonation(hostname) {
    const host = hostname.toLowerCase();
    if (isIpHost(host)) return null;
    const reg = registrableDomain(host);
    const regLabel = reg.split(".")[0];
    const regNorm = normalizeLookalikes(regLabel);

    for (const key of Object.keys(BRANDS)) {
      if (isOfficialDomain(host, key)) return null;
    }

    for (const key of Object.keys(BRANDS)) {
      for (const official of BRANDS[key].domains) {
        const officialLabel = official.split(".")[0];
        if (officialLabel.length < 5 || regLabel === officialLabel) continue;
        // Short names only match through character swaps; longer ones also tolerate typos.
        const allowed = officialLabel.length >= 8 ? 2 : officialLabel.length >= 6 ? 1 : 0;
        const d = Math.min(editDistance(regNorm, officialLabel), editDistance(regLabel, officialLabel));
        if (d <= allowed) {
          return { brand: key, name: BRANDS[key].name, kind: "lookalike", official: official };
        }
      }
    }

    const parts = host.split(/[.-]/).map(normalizeLookalikes);
    for (const key of Object.keys(BRANDS)) {
      if (parts.some(function (p) { return p === key || p.startsWith(key); })) {
        return { brand: key, name: BRANDS[key].name, kind: "contains", official: BRANDS[key].domains[0] };
      }
    }
    return null;
  }

  // Brand keys whose display name appears as a whole word in free text (page title, headings, logo alt).
  function brandsMentionedIn(text) {
    const lower = (text || "").toLowerCase();
    return Object.keys(BRANDS).filter(function (key) {
      const name = BRANDS[key].name.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp("(^|[^a-z])" + name + "([^a-z]|$)").test(lower);
    });
  }

  function gradeOf(score) {
    if (score < 10)      return ["A", "Looks secure"];
    if (score < 30)      return ["B", "Minor concerns"];
    if (score < 50)      return ["C", "Be careful"];
    if (score < 70)      return ["D", "Suspicious"];
    return ["F", "High risk - phishing indicators"];
  }

  function applyGrade(result) {
    result.score = Math.min(result.score, 100);
    const [g, l] = gradeOf(result.score);
    result.grade = g;
    result.label = l;
    return result;
  }

  function checkUrl(urlString) {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const full = urlString.toLowerCase();
    const local = isLocalHost(hostname);
    let score = 0;
    const findings = [];

    // Local dev servers (localhost / 127.0.0.1) are exempt from the transport/IP checks.
    if (url.protocol !== "https:" && !local) {
      score += 25;
      findings.push("No HTTPS - the connection to this site is not encrypted. Anyone on the network can read what you send.");
    }
    if (!local && /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 30;
      findings.push("The site uses a raw IP address instead of a domain name. Legitimate services almost never do this.");
    }
    if (full.includes("@")) {
      score += 20;
      findings.push("The URL contains '@'. Everything before the @ is decoration - the real destination comes after it.");
    }
    if (hostname.includes("xn--")) {
      score += 25;
      findings.push("The domain uses punycode (xn--), which can hide look-alike characters (homoglyph attack).");
    }
    const tld = hostname.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 15;
      findings.push("The ." + tld + " domain extension is free/cheap and is abused in a large share of phishing sites.");
    }
    if (!local && !isIpHost(hostname) && /\d/.test(hostname.replace(/\./g, ""))) {
      score += 5;
      findings.push("Digits in the domain name (e.g. 'paypa1') - sometimes used to imitate real brands.");
    }
    const hits = KEYWORDS.filter(function (k) { return full.includes(k); });
    if (hits.length > 0) {
      score += Math.min(hits.length * 10, 20);
      findings.push("URL contains pressure/security words: " + hits.join(", ") + ". Phishing pages use these to rush you.");
    }
    if (urlString.length > 75) {
      score += 10;
      findings.push("Very long URL (" + urlString.length + " characters). Long URLs are often used to hide the real domain.");
    }

    const brand = local ? null : checkBrandImpersonation(hostname);
    if (brand && brand.kind === "lookalike") {
      score += 55;
      findings.push("CRITICAL: '" + registrableDomain(hostname) + "' is a look-alike of " + brand.name + "'s real domain (" +
                    brand.official + "). This is how fake login pages are disguised.");
    } else if (brand) {
      score += 35;
      findings.push("The domain uses the name '" + brand.name + "' but is not owned by " + brand.name +
                    " (official: " + brand.official + "). Brand names in unrelated domains are a classic phishing trick.");
    }
    const lures = LURE_WORDS.filter(function (w) { return full.includes(w); });
    if (brand && lures.length > 0) {
      score += 15;
      findings.push("The link combines a brand name with a reward lure (" + lures.join(", ") + ") - the pattern of fake gift-card scams.");
    }

    const result = { score: score, findings: findings, hostname: hostname };
    return applyGrade(result);
  }

  // Merges the per-tab record written by background.js and content.js into a URL result.
  function mergeRecord(result, record) {
    if (!record || record.hostname !== result.hostname) return result;

    if (record.tlsError) {
      result.score += 70;   // critical on its own: a rejected certificate always grades F
      result.findings.push("CRITICAL: the browser rejected this site's certificate (" + record.tlsError + "). " +
                           "On public Wi-Fi this is a typical sign of an interception (evil-twin / MITM) attempt.");
    }

    const pageFindings = record.pageFindings || [];
    if (pageFindings.length > 0) {
      result.findings.push.apply(result.findings, pageFindings);
      result.score += 35 * pageFindings.length;
    }

    const missing = record.headersMissing || [];
    if (missing.length > 0) {
      const pretty = missing.map(function (h) { return HEADER_NAMES[h] || h; }).join(", ");
      result.findings.push("Missing security headers: " + pretty + ".");
      result.score += 8 * missing.length;
    }

    const redirects = record.redirects || [];
    if (redirects.length > 0) {
      const domains = [];
      redirects.concat([record.url]).forEach(function (u) {
        try {
          const d = registrableDomain(new URL(u).hostname);
          if (!domains.includes(d)) domains.push(d);
        } catch (e) {}
      });
      if (redirects.length >= 3 || domains.length >= 3) {
        result.score += 10;
        result.findings.push("Reached through " + redirects.length + " redirect(s) across " + domains.length +
                             " domain(s): " + domains.join(" -> ") + ". Redirect chains are used to hide the real destination.");
      }
    }
    return applyGrade(result);
  }

  // --- Online-check signals (the network lookups live in netchecks.js; scoring stays pure here) ---

  function domainAgeSignal(registeredIso, now) {
    if (!registeredIso) return null;
    const days = Math.floor(((now || Date.now()) - Date.parse(registeredIso)) / 86400000);
    if (isNaN(days)) return null;
    if (days < 30)  return { points: 30, days: days, text: "The domain was registered only " + days + " day(s) ago. Most phishing domains are used within their first weeks." };
    if (days < 180) return { points: 10, days: days, text: "The domain is young (" + days + " days old). Treat login or payment requests with care." };
    return null;
  }

  function dohSignal(observedIp, resolvedIps) {
    if (!observedIp || !resolvedIps || resolvedIps.length === 0) return null;
    if (resolvedIps.includes(observedIp)) return null;
    // CDNs and geo-DNS legitimately return different addresses, so this is a weak signal on its own.
    return { points: 10, text: "The server address your browser connected to (" + observedIp + ") is not among the addresses a " +
                               "trusted DNS-over-HTTPS resolver returns (" + resolvedIps.slice(0, 3).join(", ") + "). " +
                               "This can mean DNS tampering on the local network - or just a CDN." };
  }

  function safeBrowsingSignal(matches) {
    if (!matches || matches.length === 0) return null;
    const types = matches.map(function (m) { return m.threatType; }).filter(function (t, i, a) { return a.indexOf(t) === i; });
    return { points: 100, text: "CRITICAL: Google Safe Browsing lists this URL as " + types.join(", ") + "." };
  }

  // One status line for the popup, so the user can see the online checks ran even when they found
  // nothing. info: null = switched off; { skipped } = local/IP host; otherwise what each lookup got
  // (a missing field means that lookup failed or was not run).
  function onlineSummary(info, now) {
    if (!info) return "Online checks: off (turn on in Settings)";
    if (info.skipped) return "Online checks: not used for local or IP addresses";
    const parts = [];

    const days = info.registered ? Math.floor(((now || Date.now()) - Date.parse(info.registered)) / 86400000) : NaN;
    if (isNaN(days)) parts.push("domain age unknown");
    else if (days >= 365) parts.push("domain " + Math.floor(days / 365) + " year(s) old ✔");
    else parts.push("domain " + days + " day(s) old " + (days >= 180 ? "✔" : "⚠"));

    if (!info.observedIp || !info.resolvedIps || info.resolvedIps.length === 0) parts.push("DNS not compared");
    else if (info.resolvedIps.includes(info.observedIp)) parts.push("DNS matches ✔");
    else parts.push("DNS differs ⚠");

    if (info.safeBrowsingChecked) {
      if (!info.safeBrowsingMatches) parts.push("Safe Browsing unavailable");
      else if (info.safeBrowsingMatches.length === 0) parts.push("not on Safe Browsing list ✔");
      else parts.push("listed by Safe Browsing ⚠");
    }
    return "Online checks: " + parts.join(" · ");
  }

  function applySignals(result, signals) {
    signals.filter(Boolean).forEach(function (s) {
      result.score += s.points;
      result.findings.push(s.text);
    });
    return applyGrade(result);
  }

  const api = {
    SUSPICIOUS_TLDS: SUSPICIOUS_TLDS, KEYWORDS: KEYWORDS, BRANDS: BRANDS, HEADER_NAMES: HEADER_NAMES,
    isLocalHost: isLocalHost, isIpHost: isIpHost, registrableDomain: registrableDomain,
    normalizeLookalikes: normalizeLookalikes, editDistance: editDistance, isOfficialDomain: isOfficialDomain,
    checkBrandImpersonation: checkBrandImpersonation, brandsMentionedIn: brandsMentionedIn,
    gradeOf: gradeOf, applyGrade: applyGrade, checkUrl: checkUrl, mergeRecord: mergeRecord,
    domainAgeSignal: domainAgeSignal, dohSignal: dohSignal, safeBrowsingSignal: safeBrowsingSignal,
    onlineSummary: onlineSummary, applySignals: applySignals
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.SentinelCore = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
