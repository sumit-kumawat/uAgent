"use strict";

// Server-side package checks: Authenticode validation with osslsigncode and malware scanning with
// ClamAV, when those tools are installed. Agents repeat the signature check with WinVerifyTrust and can
// scan with Microsoft Defender before installing, so a missing server tool never weakens the endpoint.
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

const SEARCH_DIRS = ["/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"];

function findTool(name) {
  const dirs = (process.env.PATH || "").split(path.delimiter).concat(SEARCH_DIRS);
  for (const dir of dirs) {
    if (!dir) {
      continue;
    }
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // Try the next directory.
    }
  }
  return null;
}

function run(file, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => {
      const code = error ? (typeof error.code === "number" ? error.code : -1) : 0;
      resolve({ code, timedOut: Boolean(error && error.killed), output: `${stdout || ""}${stderr || ""}` });
    });
  });
}

function commonName(subject) {
  const match = /CN=([^,/]+)/.exec(subject || "");
  return match ? match[1].trim() : (subject || "").trim();
}

function createPackageScanner(config, logger) {
  const signTool = findTool("osslsigncode");
  const clamd = findTool("clamdscan");
  const clam = findTool("clamscan");
  const mode = config.packageScanMode;
  const scanEngine = mode === "off" ? null : clamd ? "clamdscan" : clam ? "clamscan" : null;

  async function verifySignature(file, hasSignature) {
    if (!signTool) {
      return hasSignature
        ? { status: "Present", subject: "", detail: "The file carries a digital signature. This server cannot validate it because osslsigncode is not installed; agents validate it before installing." }
        : { status: "Unsigned", subject: "", detail: "The file is not digitally signed." };
    }
    const result = await run(signTool, ["verify", "-in", file], 120000);
    const subjectLine = /Signer's certificate:[\s\S]*?Subject:\s*(.+)/.exec(result.output);
    const subject = subjectLine ? commonName(subjectLine[1]) : "";
    if (result.code === 0 && /Signature verification: ok/.test(result.output)) {
      return { status: "Valid", subject, detail: `Signed by ${subject || "an unknown publisher"}; the signature and certificate chain are valid.` };
    }
    if (/has no signature|No signature found|Unable to extract existing signature/i.test(result.output) && !hasSignature) {
      return { status: "Unsigned", subject: "", detail: "The file is not digitally signed." };
    }
    if (result.timedOut) {
      return { status: "Present", subject, detail: "Signature validation timed out on the server; agents validate the signature before installing." };
    }
    const reason = (/Signature verification: (.+)/.exec(result.output) || [])[1] || "the signature or its certificate chain did not validate";
    return { status: "Invalid", subject, detail: `The digital signature is not valid: ${reason.trim()}.` };
  }

  async function scan(file) {
    if (mode === "off") {
      return { status: "NotScanned", engine: "", detail: "Server-side malware scanning is turned off.", scannedUtc: null };
    }
    if (!scanEngine) {
      return { status: "NotScanned", engine: "", detail: "No malware scanner (ClamAV) is installed on this server.", scannedUtc: null };
    }
    const args = scanEngine === "clamdscan" ? ["--no-summary", "--fdpass", file] : ["--no-summary", file];
    const result = await run(scanEngine === "clamdscan" ? clamd : clam, args, 30 * 60 * 1000);
    const scannedUtc = new Date().toISOString();
    if (result.code === 0) {
      return { status: "Clean", engine: scanEngine, detail: "No threats were found.", scannedUtc };
    }
    if (result.code === 1) {
      const found = (/: (.+) FOUND/.exec(result.output) || [])[1] || "a threat";
      logger(`Malware scan found ${found} in an uploaded package.`);
      return { status: "Infected", engine: scanEngine, detail: `The scanner reported ${found}.`, scannedUtc };
    }
    return { status: "Error", engine: scanEngine, detail: result.timedOut ? "The malware scan timed out." : `The malware scanner failed: ${result.output.trim().split("\n").pop() || `exit code ${result.code}`}`, scannedUtc };
  }

  return {
    verifySignature,
    scan,
    describe: () => ({ available: Boolean(scanEngine), engine: scanEngine || "", mode, signatureTool: Boolean(signTool) })
  };
}

module.exports = { createPackageScanner };
