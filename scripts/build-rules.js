// Generates the per-layer copies of shared/rules.json. Run: npm run build:rules
// `render()` is also used by tests/rules.test.js to check the committed copies are current.

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SOURCE = path.join(ROOT, "shared", "rules.json");
const TARGETS = {
  js: path.join(ROOT, "lib", "rules.js"),
  py: path.join(ROOT, "trustguard", "trustguard", "core", "shared_rules.json")
};

function render() {
  const rules = JSON.parse(fs.readFileSync(SOURCE, "utf8"));
  delete rules._about;
  const json = JSON.stringify(rules, null, 2);
  return {
    js: "// GENERATED from shared/rules.json by scripts/build-rules.js - do not edit by hand.\n" +
        "(function (root, rules) {\n" +
        "  if (typeof module !== \"undefined\" && module.exports) module.exports = rules;\n" +
        "  else root.SentinelRules = rules;\n" +
        "})(typeof globalThis !== \"undefined\" ? globalThis : this, " + json + ");\n",
    py: json + "\n"
  };
}

if (require.main === module) {
  const out = render();
  for (const key of Object.keys(TARGETS)) {
    fs.writeFileSync(TARGETS[key], out[key]);
    console.log("wrote " + path.relative(ROOT, TARGETS[key]));
  }
}

module.exports = { render, TARGETS };
