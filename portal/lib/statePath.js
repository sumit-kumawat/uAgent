"use strict";

const fs = require("fs");
const path = require("path");

function stateFile(name) {
  if (process.env.PORTAL_STATE_DIR) {
    return path.join(process.env.PORTAL_STATE_DIR, name);
  }
  const systemDir = "/var/lib/uagent";
  if (canWrite(systemDir)) {
    return path.join(systemDir, name);
  }
  return path.join(__dirname, "..", "data", name);
}

function canWrite(directory) {
  try {
    fs.mkdirSync(directory, { recursive: true });
    fs.accessSync(directory, fs.constants.W_OK);
    return true;
  } catch (error) {
    return false;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    return null;
  }
}

module.exports = { stateFile, writeJson, readJson };
