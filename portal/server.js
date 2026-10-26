"use strict";

// uAgent portal — Node.js/Express application for managing uAgent Windows agents.
// It renders the operator UI (EJS), exposes the operator JSON API (session cookie + roles), and hosts the
// agent-facing API (X-Api-Key). Agents auto-register on their first heartbeat (Wazuh-style).
// The portal is published on this machine's IP until an administrator saves a DNS name in Settings.
// Documentation uses the dummy name uagent.example.com.
const express = require("express");
const session = require("express-session");
const compression = require("compression");
const path = require("path");
const http = require("http");
const https = require("https");
const os = require("os");
const net = require("net");

const config = require("./config");
const Store = require("./lib/store");
const InstallerPackage = require("./lib/installerPackage");
const { createAuth } = require("./lib/auth");
const pagesRouter = require("./routes/pages");
const agentApiRouter = require("./routes/agentApi");
const portalApiRouter = require("./routes/portalApi");
const downloadRouter = require("./routes/download");
const { createHostSettings } = require("./lib/hostSettings");
const { createTlsManager } = require("./lib/tlsManager");
const { createHostChange } = require("./lib/hostChange");
const { createOperators } = require("./lib/operators");
const { stateFile } = require("./lib/statePath");

function log(message) {
  process.stdout.write(`[${new Date().toISOString()}] ${message}\n`);
}

// First non-internal IPv4 address, so the portal can advertise a LAN URL agents can reach.
function localIpv4Addresses() {
  const found = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const entry of ifaces[name] || []) {
      const ipv4 = entry.family === 4 || entry.family === "IPv4";
      if (ipv4 && !entry.internal && !found.includes(entry.address)) {
        found.push(entry.address);
      }
    }
  }
  return found;
}

function withPort(protocol, host, port) {
  const standard = (protocol === "http" && port === 80) || (protocol === "https" && port === 443);
  return `${protocol}://${host}${standard ? "" : `:${port}`}`;
}

function buildUrlCatalog(httpsEnabled) {
  const ips = localIpv4Addresses();
  if (config.publicIp && net.isIP(config.publicIp) === 4 && !ips.includes(config.publicIp)) {
    ips.push(config.publicIp);
  }
  const urls = [];
  const add = (protocol, host) => {
    const url = withPort(protocol, host, protocol === "https" ? config.httpsPort : config.httpPort);
    if (!urls.includes(url)) {
      urls.push(url);
    }
  };
  add("http", "localhost");
  ips.forEach((ip) => add("http", ip));
  if (httpsEnabled) {
    add("https", "localhost");
    ips.forEach((ip) => add("https", ip));
  }
  if (config.publicHost && config.publicHost !== "uagent.example.com" && net.isIP(config.publicHost) === 0) {
    add("http", config.publicHost);
    if (httpsEnabled) {
      add("https", config.publicHost);
    }
  }
  return { urls, localIp: ips[0] || null };
}

function isLocalOrIp(host) {
  return !host || host === "localhost" || host.endsWith(".localhost") || net.isIP(host) !== 0;
}

const store = new Store(config.onlineWindowMs, { requireApproval: config.requireApproval });
store.attachPersistence(stateFile("portal-store.json"));
const operators = createOperators(config);
const auth = createAuth(config, operators);
const tlsManager = createTlsManager(config, log);
const tls = tlsManager.current;
const urlCatalog = buildUrlCatalog(Boolean(tls));
const installer = new InstallerPackage(config.installerDir);

config.httpsEnabled = Boolean(tls);
const hostSettings = createHostSettings(config);
const hostChange = createHostChange({ hostSettings, tlsManager, store, logger: log, config });

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

// Live event streams must not be buffered by compression.
app.use(compression({ filter: (req, res) => req.path !== "/api/events" && compression.filter(req, res) }));
// Inventory uploads (processes, services, applications) are larger than operator requests.
app.use("/api/agents", express.json({ limit: "16mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
// Asset URLs carry the build version and start time, so browsers cache them but pick up every deployment.
const assetVersion = `${require("./package.json").version}-${Date.now().toString(36)}`;
app.use((req, res, next) => {
  res.locals.assetVersion = assetVersion;
  next();
});
app.use(express.static(path.join(__dirname, "public"), { maxAge: "7d" }));

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

app.use((req, res, next) => {
  if (req.session && req.session.user && operators.mustChange(req.session.user.name)) {
    req.session.user.mustChangePassword = true;
  }
  next();
});

// Unauthenticated liveness probe (handy for load balancers and quick checks).
app.get("/healthz", (req, res) => {
  const access = hostSettings.describe();
  res.json({ status: "ok", host: access.host, agentUrl: access.managerUrl, needsDns: access.needsDns, time: new Date().toISOString() });
});

// Unauthenticated installer download, kept separate from management operations.
app.use("/download", downloadRouter(installer, config, log, store, hostSettings, tlsManager));

// Agent API first so its paths are claimed before the operator API catch-alls.
app.use("/api/agents", agentApiRouter(store, auth, config, installer, log, hostSettings));
app.use("/api", portalApiRouter(store, auth, config, urlCatalog, log, installer, hostSettings, operators, tlsManager, hostChange));
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use("/", pagesRouter(store, auth, config, urlCatalog, tlsManager, installer, log, hostSettings, operators, hostChange));
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
    // Agents hold a long poll open for up to 55 s; keep idle sockets longer than that.
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
    server.listen(port, () => resolve(true));
  });
}

async function start() {
  const httpOk = await listen(http.createServer(app), config.httpPort, "HTTP");
  let httpsOk = false;
  if (tls) {
    const server = https.createServer({ cert: tls.cert, key: tls.key }, app);
    tlsManager.attach(server);
    httpsOk = await listen(server, config.httpsPort, "HTTPS");
    const hostProvider = () => hostSettings.effectiveHost();
    hostProvider.ips = () => hostSettings.addresses();
    tlsManager.start(hostProvider);
  }
  if (!httpOk && !httpsOk) {
    log("No listener could be started. Exiting.");
    process.exit(1);
  }

  const contact = hostSettings.describe();
  log(`Agents are downloaded bound to ${contact.managerUrl}${contact.needsDns ? ". Set a DNS name or FQDN in Settings." : "."}`);
  log(`Portal state is saved in ${path.dirname(stateFile("portal-store.json"))}.`);
  log(`uAgent portal started for ${contact.host}. Reachable URLs:`);
  urlCatalog.urls.forEach((url) => log(`  ${url}`));
  log(`Portal accounts: ${config.users.map((u) => `${u.username} (${u.role})`).join(", ")}`);
  const cert = tlsManager.describe();
  if (cert) {
    log(`TLS certificate: ${cert.subject} (${cert.mode}${cert.healthy ? "" : ", has problems"}), valid to ${cert.validTo}, SHA-256 ${cert.fingerprint}.`);
    if (!tlsManager.covers(contact.host)) {
      log(`WARNING: the TLS certificate does not cover ${contact.host}. Agents will refuse to connect until it does.`);
    }
    if (cert.mode === "self-signed") {
      log("WARNING: the certificate is self-signed. Browsers will show ERR_CERT_AUTHORITY_INVALID. Use a public or private CA certificate for production.");
    }
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

const presenceTimer = setInterval(() => store.sweepPresence(), 5000);
presenceTimer.unref();

function shutdown() {
  store.flush();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

start();
