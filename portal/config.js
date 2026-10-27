"use strict";

// Central configuration for the uAgent portal. Every value can be overridden with an environment variable.
const crypto = require("crypto");
const path = require("path");

function intFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function boolFromEnv(name, fallback) {
  const raw = (process.env[name] || "").trim().toLowerCase();
  if (raw === "") {
    return fallback;
  }
  return raw === "1" || raw === "true" || raw === "yes";
}

const validRoles = new Set(["Administrator", "Operator", "Monitor"]);

// PORTAL_USERS takes a JSON array: [{"username":"ops","password":"...","role":"Operator"}].
// Without it, a single Administrator signs in with PORTAL_USER / PORTAL_PASS. When PORTAL_PASS is empty the
// first start generates a one-time password and prints it to the service log.
function loadUsers() {
  const raw = process.env.PORTAL_USERS;
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`PORTAL_USERS is not valid JSON: ${error.message}`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error("PORTAL_USERS must be a non-empty JSON array.");
    }
    return parsed.map((u, index) => {
      if (!u || !u.username || typeof u.password !== "string" || !validRoles.has(u.role)) {
        throw new Error(`PORTAL_USERS entry ${index} needs username, password and role (Administrator, Operator or Monitor).`);
      }
      return { username: String(u.username), password: u.password, role: u.role };
    });
  }
  return [{
    username: process.env.PORTAL_USER || "admin",
    password: process.env.PORTAL_PASS || "",
    role: "Administrator"
  }];
}

const httpPort = intFromEnv("PORTAL_HTTP_PORT", 80);
const httpsPort = intFromEnv("PORTAL_HTTPS_PORT", 443);

const config = {
  // Canonical public host name of the portal. Both http:// and https:// are served for it.
  publicHost: (process.env.PUBLIC_HOST || "uagent.example.com").trim().toLowerCase(),
  // Optional extra address to put on the TLS certificate. Empty uses the machine's own IPv4 address.
  publicIp: (process.env.PUBLIC_IP || "").trim(),
  // Ports clients use to reach the portal. Differ from the listen ports only behind a reverse proxy or NAT.
  publicHttpPort: intFromEnv("PUBLIC_HTTP_PORT", httpPort),
  publicHttpsPort: intFromEnv("PUBLIC_HTTPS_PORT", httpsPort),

  // Listen ports. HTTP always listens; HTTPS listens when a certificate is available.
  httpPort,
  httpsPort,

  // Redirect browser page requests that arrive on an unrecognised host name to the public host.
  // Localhost, IP addresses and the agent API are never redirected.
  canonicalRedirect: boolFromEnv("CANONICAL_REDIRECT", true),

  // Redirect every plain-HTTP request to HTTPS whenever a certificate is available. On by default so the
  // portal and agents always use TLS. Set FORCE_HTTPS=false only when terminating TLS at a proxy.
  forceHttps: boolFromEnv("FORCE_HTTPS", true),

  users: loadUsers(),

  // Enrollment key: embedded in the downloadable installer and used only to register. Each agent then
  // receives its own unique credential, so this key is not a permanent shared secret. Rotate it anytime;
  // already-registered agents keep working with their own keys.
  enrollmentKey: process.env.ENROLLMENT_KEY || process.env.AGENT_API_KEY || "change-me-enroll",

  // When true, a newly enrolled agent stays in PendingApproval (no actions delivered) until an
  // administrator approves it in the portal. Off by default for one-click onboarding.
  requireApproval: boolFromEnv("AGENT_REQUIRE_APPROVAL", false),

  // Directory holding the built installer (uAgent-Setup.exe) and its manifest.json. Produced by
  // scripts/build-agent.sh. Served read-only; never writable through the portal.
  installerDir: process.env.INSTALLER_DIR || path.join(__dirname, "agent-dist"),

  // With a self-signed certificate, embed its public-key hash so agents can connect. Ignored for public and
  // private-CA certificates, which agents validate normally. Set EMBED_CERT_PIN=false to omit it.
  embedCertPin: boolFromEnv("EMBED_CERT_PIN", true),

  // Private CA root (PEM) that signed the portal certificate. Embedded in installers so agents validate the
  // chain and host name against it; browsers need the same root deployed by GPO or Intune.
  caFile: process.env.TLS_CA_FILE || "",
  // Key of that private CA. When present the portal issues and renews its own leaf certificate.
  caKeyFile: process.env.TLS_CA_KEY_FILE || "",
  // Let the portal reissue its own self-signed certificate when the host changes or it nears expiry.
  manageSelfSigned: boolFromEnv("TLS_MANAGE_SELF_SIGNED", true),

  // Secret used to sign the session cookie. Sessions are held in memory and end on restart anyway, so a
  // random per-process secret is used when none is configured.
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),

  // An agent is online when it contacted the portal within this window (ms).
  onlineWindowMs: intFromEnv("ONLINE_WINDOW_MS", 60 * 1000),

  certFile: process.env.TLS_CERT_FILE || path.join(__dirname, "certs", "portal.crt"),
  keyFile: process.env.TLS_KEY_FILE || path.join(__dirname, "certs", "portal.key"),

  // Software deployment. Server-side malware scanning with ClamAV: "off" skips it, "on" scans when a
  // scanner is installed, "required" quarantines any package that is not confirmed clean.
  packageScanMode: ["off", "on", "required"].includes((process.env.PACKAGE_SCAN_MODE || "").trim().toLowerCase())
    ? (process.env.PACKAGE_SCAN_MODE || "").trim().toLowerCase()
    : "on",
  // Largest single installer accepted into the software library, and the total library storage budget.
  maxPackageBytes: intFromEnv("MAX_PACKAGE_MB", 2048) * 1024 * 1024,
  maxStorageBytes: intFromEnv("MAX_LIBRARY_STORAGE_MB", 51200) * 1024 * 1024,
  // Key file that seals vault secrets (AES-256-GCM). Keep it backed up and readable only by the service.
  vaultKeyFile: process.env.VAULT_KEY_FILE || ""
};

module.exports = config;
