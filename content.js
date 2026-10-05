// SentinelQA v0.3.0 - page-level checks
// This script runs INSIDE every webpage you visit.

(function () {
  const findings = [];

  // Check 9: Password field sending data over HTTP
  const passwordFields = document.querySelectorAll("input[type='password']");
  passwordFields.forEach(function (field) {
    const form = field.closest("form");
    const action = form ? form.action : location.href;
    if (action.startsWith("http://")) {
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

  // Save the results where the popup can find them
  chrome.storage.local.set({ pageFindings: findings, pageChecked: location.hostname });
})();