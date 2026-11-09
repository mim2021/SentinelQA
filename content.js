// SentinelQA page-level checks.
// This script runs INSIDE every webpage you visit (after lib/core.js, see manifest.json).

(function () {
  const findings = [];
  const core = globalThis.SentinelCore;

  // Check 9: Password field sending data over HTTP
  const passwordFields = document.querySelectorAll("input[type='password']");
  passwordFields.forEach(function (field) {
    const form = field.closest("form");
    const action = form ? form.action : location.href;
    let local = false;
    try { local = core.isLocalHost(new URL(action).hostname); } catch (e) {}
    if (action.startsWith("http://") && !local) {
      findings.push("CRITICAL: this page has a PASSWORD field that submits over unencrypted HTTP. Anyone on the network can read the password.");
    }
  });

  // Check 10: Mixed content on an HTTPS page
  if (location.protocol === "https:") {
    const mixed = document.querySelectorAll('img[src^="http://"], script[src^="http://"], link[href^="http://"], iframe[src^="http://"]');
    if (mixed.length > 0) {
      findings.push("This secure (HTTPS) page loads " + mixed.length + " resource(s) over unencrypted HTTP (mixed content). Browsers may block or warn about these.");
    }
  }

  // Check 11: Fake login page - a password form presenting itself as a brand the domain does not belong to.
  if (passwordFields.length > 0 && !core.isLocalHost(location.hostname)) {
    const ogSite = document.querySelector('meta[property="og:site_name"]');
    // Only the page's own identity (title, site name, main heading): "Sign in with Google" buttons
    // and partner logos elsewhere on legitimate pages would otherwise trigger false alarms.
    const h1 = document.querySelector("h1");
    const identity = [document.title, ogSite ? ogSite.content : "", h1 ? h1.textContent : ""].join(" ");
    core.brandsMentionedIn(identity)
      .filter(function (key) { return !core.isOfficialDomain(location.hostname, key); })
      .slice(0, 1)
      .forEach(function (key) {
        findings.push("CRITICAL: this page asks for a password while presenting itself as " + core.BRANDS[key].name +
                      ", but " + location.hostname + " is not a " + core.BRANDS[key].name + " domain. Likely a fake login page.");
      });
  }

  // Hand the results to the background script, which stores them for THIS tab
  chrome.runtime.sendMessage({ type: "PAGE_FINDINGS", hostname: location.hostname, findings: findings });
})();
