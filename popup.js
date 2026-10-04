// SentinelQA v0.2.0 - URL-level security checks
// These checks run entirely on the page's web address (URL).

const SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "loan", "icu", "cam"];
const KEYWORDS = ["login", "signin", "verify", "verification", "account", "update", "secure",
                  "confirm", "password", "banking", "wallet", "unlock", "suspended", "invoice", "webscr"];

function checkUrl(urlString) {
  const url = new URL(urlString);
  const hostname = url.hostname.toLowerCase();
  const full = urlString.toLowerCase();
  let score = 0;
  const findings = [];

  // Check 1: Encryption
  if (url.protocol !== "https:") {
    score += 25;
    findings.push("No HTTPS - the connection to this site is not encrypted. Anyone on the network can read what you send.");
  }

  // Check 2: IP address instead of domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    findings.push("The site uses a raw IP address instead of a domain name. Legitimate services almost never do this.");
  }

  // Check 3: '@' symbol in URL (hides the real destination)
  if (full.includes("@")) {
    score += 20;
    findings.push("The URL contains '@'. Everything before the @ is decoration - the real destination comes after it.");
  }

  // Check 4: Punycode look-alike domains
  if (hostname.includes("xn--")) {
    score += 25;
    findings.push("The domain uses punycode (xn--), which can hide look-alike characters (homoglyph attack).");
  }

  // Check 5: Suspicious TLD
  const tld = hostname.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 15;
    findings.push("The ." + tld + " domain extension is free/cheap and is abused in a large share of phishing sites.");
  }

  // Check 6: Digits in domain
  if (/\d/.test(hostname.replace(/\./g, ""))) {
    score += 5;
    findings.push("Digits in the domain name (e.g. 'paypa1') - sometimes used to imitate real brands.");
  }

  // Check 7: Suspicious keywords
  const hits = KEYWORDS.filter(k => full.includes(k));
  if (hits.length > 0) {
    score += Math.min(hits.length * 10, 20);
    findings.push("URL contains pressure/security words: " + hits.join(", ") + ". Phishing pages use these to rush you.");
  }

  // Check 8: Very long URL
  if (urlString.length > 75) {
    score += 10;
    findings.push("Very long URL (" + urlString.length + " characters). Long URLs are often used to hide the real domain.");
  }

  score = Math.min(score, 100);

  // Convert score to letter grade (like a QA test report)
  let grade, label;
  if (score < 10)      { grade = "A"; label = "Looks secure"; }
  else if (score < 30) { grade = "B"; label = "Minor concerns"; }
  else if (score < 50) { grade = "C"; label = "Be careful"; }
  else if (score < 70) { grade = "D"; label = "Suspicious"; }
  else                 { grade = "F"; label = "High risk - phishing indicators"; }

  return { score, grade, label, findings, hostname };
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
    "<li>&#10004;&#65039; No URL-level issues found. Page-level checks come in the next version.</li>";
}

async function scan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    document.getElementById("label").textContent = "Open a normal webpage first.";
    return;
  }
  render(checkUrl(tab.url));
}

document.addEventListener("DOMContentLoaded", scan);
document.getElementById("rescan").addEventListener("click", scan);
