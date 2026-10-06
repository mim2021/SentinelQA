// SentinelQA v0.3.0 - URL-level + page-level + security header checks

const SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "loan", "icu", "cam"];
const KEYWORDS = ["login", "signin", "verify", "verification", "account", "update", "secure",
                  "confirm", "password", "banking", "wallet", "unlock", "suspended", "invoice", "webscr"];

function isLocalHost(h) {
  return h === "localhost" || h.endsWith(".localhost") || h === "127.0.0.1" || h === "[::1]";
}

function gradeOf(score) {
  if (score < 10)      return ["A", "Looks secure"];
  if (score < 30)      return ["B", "Minor concerns"];
  if (score < 50)      return ["C", "Be careful"];
  if (score < 70)      return ["D", "Suspicious"];
  return ["F", "High risk - phishing indicators"];
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
  if (!local && /\d/.test(hostname.replace(/\./g, ""))) {
    score += 5;
    findings.push("Digits in the domain name (e.g. 'paypa1') - sometimes used to imitate real brands.");
  }
  const hits = KEYWORDS.filter(k => full.includes(k));
  if (hits.length > 0) {
    score += Math.min(hits.length * 10, 20);
    findings.push("URL contains pressure/security words: " + hits.join(", ") + ". Phishing pages use these to rush you.");
  }
  if (urlString.length > 75) {
    score += 10;
    findings.push("Very long URL (" + urlString.length + " characters). Long URLs are often used to hide the real domain.");
  }

  score = Math.min(score, 100);
  const [grade, label] = gradeOf(score);
  return { score, grade, label, findings, hostname };
}

function applyGrade(result) {
  const [g, l] = gradeOf(result.score);
  result.grade = g;
  result.label = l;
}

function render(result) {
  const gradeEl = document.getElementById("grade");
  gradeEl.textContent = result.grade;
  gradeEl.className = result.grade;
  document.getElementById("label").textContent = result.label;
  document.getElementById("score").textContent = "Risk score: " + result.score + "/100";
  document.getElementById("site").textContent = result.hostname;
  document.getElementById("findings").innerHTML =
    result.findings.map(f => "<li>&#9888;&#65039; " + f + "</li>").join("") ||
    "<li>&#10004;&#65039; No issues found at URL or page level.</li>";
}

const HEADER_NAMES = {
  "x-frame-options": "X-Frame-Options (clickjacking protection)",
  "content-security-policy": "Content-Security-Policy (injection protection)",
  "x-content-type-options": "X-Content-Type-Options (MIME-sniffing protection)",
  "strict-transport-security": "Strict-Transport-Security (forces HTTPS)"
};

async function scan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    document.getElementById("label").textContent = "Open a normal webpage first.";
    return;
  }

  const result = checkUrl(tab.url);

  // Per-tab record written by background.js (headers) and content.js (page checks)
  const key = "tab_" + tab.id;
  const stored = await chrome.storage.session.get(key);
  const record = stored[key];

  if (record && record.hostname === result.hostname) {
    const pageFindings = record.pageFindings || [];
    if (pageFindings.length > 0) {
      result.findings.push(...pageFindings);
      result.score = Math.min(result.score + 35 * pageFindings.length, 100);
    }

    const missing = record.headersMissing || [];
    if (missing.length > 0) {
      const pretty = missing.map(h => HEADER_NAMES[h]).join(", ");
      result.findings.push("Missing security headers: " + pretty + ".");
      result.score = Math.min(result.score + 8 * missing.length, 100);
    }
    applyGrade(result);
  }

  render(result);
}

document.addEventListener("DOMContentLoaded", scan);
document.getElementById("rescan").addEventListener("click", scan);