// The extension and the bot must score with the same data. Fails when shared/rules.json was
// edited without running `npm run build:rules`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const { render, TARGETS } = require("../scripts/build-rules.js");

test("generated rule copies match shared/rules.json", () => {
  const expected = render();
  for (const key of Object.keys(TARGETS)) {
    assert.equal(fs.readFileSync(TARGETS[key], "utf8").replace(/\r\n/g, "\n"), expected[key],
                 TARGETS[key] + " is stale - run npm run build:rules");
  }
});

test("core uses the shared rules", () => {
  const core = require("../lib/core.js");
  const rules = require("../lib/rules.js");
  assert.deepEqual(core.BRANDS, rules.brands);
  assert.deepEqual(core.SUSPICIOUS_TLDS, rules.suspiciousTlds);
});
