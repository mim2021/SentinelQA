// Unit tests for lib/core.js. Run with: npm test  (Node 18+, no dependencies)

const test = require("node:test");
const assert = require("node:assert/strict");
const core = require("../lib/core.js");

const has = (result, text) => result.findings.some(f => f.includes(text));

test("clean, well-known site gets an A", () => {
  const r = core.checkUrl("https://www.google.com/");
  assert.equal(r.grade, "A");
  assert.equal(r.findings.length, 0);
});

test("official brand subdomains are not flagged", () => {
  for (const u of ["https://store.steampowered.com/", "https://steamcommunity.com/id/someone",
                   "https://discord.com/channels/@me", "https://www.amazon.co.uk/"]) {
    assert.equal(core.checkBrandImpersonation(new URL(u).hostname), null, u);
  }
});

test("plain HTTP adds 25 points", () => {
  const r = core.checkUrl("http://example.com/");
  assert.equal(r.score, 25);
  assert.ok(has(r, "No HTTPS"));
});

test("localhost is exempt from HTTPS and IP checks", () => {
  assert.equal(core.checkUrl("http://localhost:8000/").score, 0);
  assert.equal(core.checkUrl("http://127.0.0.1:8000/").score, 0);
});

test("raw IP host is flagged", () => {
  const r = core.checkUrl("https://203.0.113.7/");
  assert.ok(has(r, "raw IP address"));
  assert.ok(!has(r, "Digits in the domain"));
});

test("'@' trick is flagged", () => {
  assert.ok(has(core.checkUrl("https://example.com@evil.example/"), "contains '@'"));
});

test("punycode homoglyph domain is flagged", () => {
  assert.ok(has(core.checkUrl("https://xn--pypal-4ve.com/"), "punycode"));
});

test("suspicious TLD is flagged", () => {
  assert.ok(has(core.checkUrl("https://free-prizes.tk/"), ".tk domain"));
});

test("pressure keywords are capped at 20 points", () => {
  const r = core.checkUrl("https://example.com/login/verify/account/update");
  assert.equal(r.score, 20);
});

test("very long URL is flagged", () => {
  assert.ok(has(core.checkUrl("https://example.com/" + "a".repeat(80)), "Very long URL"));
});

test("incident pattern: look-alike Steam gift-card link scores F", () => {
  const r = core.checkUrl("https://steamcommunnity.com/gift-card/pay/50");
  assert.ok(has(r, "look-alike of Steam"));
  assert.ok(has(r, "reward lure"));
  assert.equal(r.grade, "F");
});

test("brand name inside an unrelated domain is flagged", () => {
  const b = core.checkBrandImpersonation("steam-gift-claim.xyz");
  assert.equal(b.brand, "steam");
  assert.equal(b.kind, "contains");
  assert.equal(core.checkBrandImpersonation("paypal.com.secure-check.top").brand, "paypal");
});

test("digit substitutions are normalised (paypa1, disc0rd)", () => {
  assert.equal(core.checkBrandImpersonation("paypa1.com").kind, "lookalike");
  assert.equal(core.checkBrandImpersonation("disc0rd.com").brand, "discord");
  assert.equal(core.checkBrandImpersonation("dlscord.gift").brand, "discord");
});

test("short dictionary words are not mistaken for brands", () => {
  assert.equal(core.checkBrandImpersonation("stream.com"), null);
  assert.equal(core.checkBrandImpersonation("example.org"), null);
});

test("registrableDomain handles multi-part suffixes", () => {
  assert.equal(core.registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(core.registrableDomain("login.example.com"), "example.com");
});

test("brandsMentionedIn matches whole words only", () => {
  assert.deepEqual(core.brandsMentionedIn("Sign In - Steam Community"), ["steam"]);
  assert.deepEqual(core.brandsMentionedIn("Steamboat tours"), []);
});

test("grade boundaries", () => {
  assert.deepEqual([9, 10, 29, 30, 49, 50, 69, 70].map(s => core.gradeOf(s)[0]),
                   ["A", "B", "B", "C", "C", "D", "D", "F"]);
});

test("mergeRecord ignores records for another hostname", () => {
  const r = core.mergeRecord(core.checkUrl("https://example.com/"), { hostname: "other.com", headersMissing: ["x-frame-options"] });
  assert.equal(r.score, 0);
});

test("mergeRecord adds headers, page findings, TLS errors and redirect chains", () => {
  const r = core.mergeRecord(core.checkUrl("https://example.com/"), {
    hostname: "example.com",
    url: "https://example.com/",
    headersMissing: ["x-frame-options", "content-security-policy"],
    pageFindings: ["CRITICAL: fake login"],
    tlsError: "ERR_CERT_AUTHORITY_INVALID",
    redirects: ["https://t.example.net/a", "https://bit.example.org/b"]
  });
  assert.ok(has(r, "certificate"));
  assert.ok(has(r, "fake login"));
  assert.ok(has(r, "X-Frame-Options"));
  assert.ok(has(r, "redirect(s) across 3 domain(s)"));
  assert.equal(r.score, 100);
  assert.equal(r.grade, "F");
});

test("domain age signal", () => {
  const now = Date.parse("2026-10-07T00:00:00Z");
  assert.equal(core.domainAgeSignal("2026-10-01T00:00:00Z", now).points, 30);
  assert.equal(core.domainAgeSignal("2026-06-01T00:00:00Z", now).points, 10);
  assert.equal(core.domainAgeSignal("2010-01-01T00:00:00Z", now), null);
  assert.equal(core.domainAgeSignal(null, now), null);
});

test("DoH signal fires only on a mismatch", () => {
  assert.equal(core.dohSignal("198.51.100.1", ["198.51.100.1"]), null);
  assert.equal(core.dohSignal(null, ["198.51.100.1"]), null);
  assert.equal(core.dohSignal("10.0.0.5", ["198.51.100.1"]).points, 10);
});

test("online summary shows the checks ran even when nothing was found", () => {
  const now = Date.parse("2026-11-01T00:00:00Z");
  assert.match(core.onlineSummary(null), /off/);
  assert.match(core.onlineSummary({ skipped: true }), /local or IP/);
  const clean = core.onlineSummary({ registered: "2010-01-01T00:00:00Z", observedIp: "198.51.100.1",
                                     resolvedIps: ["198.51.100.1"] }, now);
  assert.match(clean, /domain 16 year\(s\) old ✔/);
  assert.match(clean, /DNS matches ✔/);
  assert.doesNotMatch(clean, /Safe Browsing/);
  const young = core.onlineSummary({ registered: "2026-10-20T00:00:00Z", observedIp: "10.0.0.5",
                                     resolvedIps: ["198.51.100.1"], safeBrowsingChecked: true }, now);
  assert.match(young, /domain 12 day\(s\) old ⚠/);
  assert.match(young, /DNS differs ⚠/);
  assert.match(young, /Safe Browsing unavailable/);
  assert.match(core.onlineSummary({}, now), /domain age unknown .* DNS not compared/);
});

test("Safe Browsing match forces F", () => {
  const r = core.applySignals(core.checkUrl("https://example.com/"),
                              [core.safeBrowsingSignal([{ threatType: "SOCIAL_ENGINEERING" }])]);
  assert.equal(r.grade, "F");
});

test("a rejected certificate alone grades F", () => {
  const r = core.mergeRecord(core.checkUrl("https://self-signed.badssl.com/"),
                             { hostname: "self-signed.badssl.com", tlsError: "ERR_CERT_AUTHORITY_INVALID" });
  assert.equal(r.grade, "F");
});
