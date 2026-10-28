"use strict";

// The dashboard script used to write into tiles the page no longer has. A cached copy of that
// script throws "Cannot set properties of null (setting 'textContent')" on every refresh.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");

test("every dashboard element the script updates is present on the page", () => {
  const script = fs.readFileSync(path.join(root, "public/js/index.js"), "utf8");
  const page = fs.readFileSync(path.join(root, "views/index.ejs"), "utf8");
  const ids = new Set();
  for (const match of script.matchAll(/"(stat[A-Za-z]+|hint[A-Za-z]+|agentsBody|lastUpdated)"/g)) {
    ids.add(match[1]);
  }
  assert.ok(ids.has("statReconnecting") && ids.has("statStale") && ids.has("agentsBody"));
  for (const id of ids) {
    assert.match(page, new RegExp('id="' + id + '"'), id + " is on the dashboard");
  }
  assert.doesNotMatch(page, /id="statActive"/);
  assert.doesNotMatch(page, /id="statOffline"/);
  assert.doesNotMatch(script, /statActive|statOffline/);
});
