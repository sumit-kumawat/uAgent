"use strict";

// uAgent portal — Node.js/Express application for managing uAgent Windows agents.
// It renders the operator UI (EJS), exposes the operator JSON API (session cookie + roles), and hosts the
// agent-facing API (X-Api-Key). Agents auto-register on their first heartbeat (Wazuh-style).
// The portal is published at http://uagent.corp.helixops.ai and https://uagent.corp.helixops.ai by default.
const express = require("express");
const session = require("express-session");
const path = require("path");
const http = require("http");
const https = require("https");
const fs = require("fs");
const os = require("os");
const net = require("net");
const crypto = require("crypto");

const config = require("./config");
const Store = require("./lib/store");
const InstallerPackage = require("./lib/installerPackage");
const { createAuth } = require("./lib/auth");
const pagesRouter = require("./routes/pages");
const agentApiRouter = require("./routes/agentApi");
const portalApiRouter = require("./routes/portalApi");
const downloadRouter = require("./routes/download");
const { createHostSettings } = require("./lib/hostSettings");

function log(message) {
  process.stdout.write(`[${new Date().toISOString()}] ${message}\n`);
}

// First non-internal IPv4 address, so the portal can advertise a LAN URL agents can reach.
function localIpv4() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const entry of ifaces[name] || []) {
      if (entry.family === "IPv4" && !entry.internal) {
        return entry.address;
      }
    }
  }
  return null;
}

function withPort(protocol, host, port) {
  const standard = (protocol === "http" && port === 80) || (protocol === "https" && port === 443);
  return `${protocol}://${host}${standard ? "" : `:${port}`}`;
}

function buildUrlCatalog(httpsEnabled) {
  const ip = localIpv4();
  const urls = [config.publicHttpUrl];
  if (httpsEnabled) {
    urls.push(config.publicHttpsUrl);
  }
  urls.push(withPort("http", "localhost", config.httpPort));
  const staticIp = config.publicIp && config.publicIp !== ip ? config.publicIp : null;
  if (ip) {
    urls.push(withPort("http", ip, config.httpPort));
  }
  if (staticIp) {
    urls.push(withPort("http", staticIp, config.httpPort));
  }
  if (httpsEnabled) {
    urls.push(withPort("https", "localhost", config.httpsPort));
    if (ip) {
      urls.push(withPort("https", ip, config.httpsPort));
    }
    if (staticIp) {
      urls.push(withPort("https", staticIp, config.httpsPort));
    }
  }
  return { urls, localIp: ip || config.publicIp || null };
}

function loadTls() {
  try {
    if (!fs.existsSync(config.certFile) || !fs.existsSync(config.keyFile)) {
      return null;
    }
    const cert = fs.readFileSync(config.certFile);
    const key = fs.readFileSync(config.keyFile);
    const x509 = new crypto.X509Certificate(cert);
    return {
      cert,
      key,
      fingerprint: x509.fingerprint256,
      subject: x509.subject.replace(/\n/g, ", "),
      validTo: x509.validTo,
      coversPublicHost: Boolean(x509.checkHost(config.publicHost))
    };
  } catch (error) {
    log(`Could not read TLS certificate: ${error.message}`);
    return null;
  }
}

function isLocalOrIp(host) {
  return !host || host === "localhost" || host.endsWith(".localhost") || net.isIP(host) !== 0;
}

const store = new Store(config.onlineWindowMs, { requireApproval: config.requireApproval });
const auth = createAuth(config);
const tls = loadTls();
const urlCatalog = buildUrlCatalog(Boolean(tls));
const installer = new InstallerPackage(config.installerDir);

// Public base URL agents and installers use (HTTPS when available). Drives installer embedding and links.
config.httpsEnabled = Boolean(tls);
config.installerManagerUrl = tls ? config.publicHttpsUrl : config.publicHttpUrl;
config.installerCertPin = tls && config.embedCertPin ? tls.fingerprint : "";
config.publicDashboardUrl = config.installerManagerUrl;
config.publicDownloadUrl = config.installerManagerUrl;
const hostSettings = createHostSettings(config);

const app = express();
app.disable("x-powered-by");
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
// Only trust X-Forwarded-* from a local reverse proxy, so clients cannot spoof their IP or protocol.
app.set("trust proxy", process.env.TRUST_PROXY || "loopback");

app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "DENY");
  res.set("Referrer-Policy", "same-origin");
  next();
});

// Force TLS: any plain-HTTP request is redirected to the same host over HTTPS (308 preserves the method
// and body, so agent POSTs survive). The health probe is left on HTTP for simple load-balancer checks.
app.use((req, res, next) => {
  if (!config.forceHttps || !tls || req.secure || req.path === "/healthz") {
    return next();
  }
  const host = (req.hostname || config.publicHost);
  const target = withPort("https", host, config.publicHttpsPort) + req.originalUrl;
  return res.redirect(308, target);
});

// Send browsers that reach the portal through another host name to the canonical public host,
// keeping the protocol they used. Agents, health checks, localhost and IP access are left alone.
app.use((req, res, next) => {
  if (!config.canonicalRedirect || (req.method !== "GET" && req.method !== "HEAD")) {
    return next();
  }
  if (req.path.startsWith("/api/") || req.path.startsWith("/download") || req.path === "/healthz") {
    return next();
  }
  const configured = hostSettings.configuredHost();
  if (!configured || net.isIP(configured) !== 0) {
    return next();
  }
  const host = (req.hostname || "").toLowerCase();
  if (host === configured || isLocalOrIp(host)) {
    return next();
  }
  const port = req.protocol === "https" ? config.publicHttpsPort : config.publicHttpPort;
  return res.redirect(302, withPort(req.protocol, configured, port) + req.originalUrl);
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

app.use(session({
  name: "uagent.sid",
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: "auto", // Secure flag on HTTPS requests, plain cookie on HTTP
    maxAge: 8 * 60 * 60 * 1000 // 8-hour sliding window
  }
}));

// Unauthenticated liveness probe (handy for load balancers and quick checks).
app.get("/healthz", (req, res) => res.json({ status: "ok", host: config.publicHost, time: new Date().toISOString() }));

// Unauthenticated installer download, kept separate from management operations.
app.use("/download", downloadRouter(installer, config, log, store, hostSettings));

// Agent API first so its paths are claimed before the operator API catch-alls.
app.use("/api/agents", agentApiRouter(store, auth, config, installer, log));
app.use("/api", portalApiRouter(store, auth, config, urlCatalog, log, installer, hostSettings));
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use("/", pagesRouter(store, auth, config, urlCatalog, tls, installer, log, hostSettings));
app.use((req, res) => res.status(404).render("notFound", { message: "The page you requested does not exist." }));

// Fallback error handler so a thrown route error returns JSON rather than crashing.
app.use((err, req, res, next) => {
  log(`Unhandled error on ${req.method} ${req.originalUrl}: ${err.message}`);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: "Internal server error." });
});

function listen(server, port, label) {
  return new Promise((resolve) => {
    server.once("error", (error) => {
      if (error.code === "EACCES") {
        log(`${label} could not listen on port ${port}: permission denied. Run with privileges or set ${label === "HTTP" ? "PORTAL_HTTP_PORT" : "PORTAL_HTTPS_PORT"}.`);
      } else if (error.code === "EADDRINUSE") {
        log(`${label} could not listen on port ${port}: the port is already in use.`);
      } else {
        log(`${label} could not listen on port ${port}: ${error.message}`);
      }
      resolve(false);
    });
    server.listen(port, () => resolve(true));
  });
}

async function start() {
  const httpOk = await listen(http.createServer(app), config.httpPort, "HTTP");
  const httpsOk = tls ? await listen(https.createServer({ cert: tls.cert, key: tls.key }, app), config.httpsPort, "HTTPS") : false;
  if (!httpOk && !httpsOk) {
    log("No listener could be started. Exiting.");
    process.exit(1);
  }

  log(`uAgent portal started for ${config.publicHost}. Reachable URLs:`);
  urlCatalog.urls.forEach((url) => log(`  ${url}`));
  log(`Portal accounts: ${config.users.map((u) => `${u.username} (${u.role})`).join(", ")}`);
  if (tls) {
    log(`TLS certificate SHA-256: ${tls.fingerprint}${tls.coversPublicHost ? "" : `  (does NOT cover ${config.publicHost})`}`);
  } else {
    log("HTTPS disabled (no certificate). Run 'npm run gencert' or set TLS_CERT_FILE / TLS_KEY_FILE.");
  }
  const manifest = installer.manifest();
  if (manifest) {
    log(`Agent installer: ${installer.fileName} v${manifest.version} (${(manifest.size / 1048576).toFixed(1)} MB, ${manifest.signed ? "signed" : "unsigned"}) at /download/agent`);
  } else {
    log(`Agent installer not built yet. Run scripts/build-agent.sh; the Download button is disabled until then.`);
  }
  log(`Agent onboarding: ${config.requireApproval ? "new agents require approval" : "new agents appear immediately"}.`);
  if (config.enrollmentKey === "change-me-enroll") {
    log("WARNING: ENROLLMENT_KEY is the default. Set a strong enrollment key before production.");
  }
}

start();
