"use strict";

// uAgent portal — Node.js/Express application for managing uAgent Windows agents.
// It renders the operator UI (EJS), exposes the operator JSON API (session cookie + roles), and hosts the
// agent-facing API (X-Api-Key). Agents enroll with the enrollment key and then use their own credential.
// The portal is published on this machine's IP until an administrator saves a DNS name in Settings.
const express = require("express");
const session = require("express-session");
const compression = require("compression");
const path = require("path");
const http = require("http");
const https = require("https");
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
const deployApiRouter = require("./routes/deployApi");
const downloadRouter = require("./routes/download");
const maintenanceApiRouter = require("./routes/maintenanceApi");
const setupApiRouter = require("./routes/maintenanceApi").setupApi;
const connectivity = require("./lib/connectivity");
const { createMaintenance } = require("./lib/maintenance");
const { createHostSettings } = require("./lib/hostSettings");
const { createTlsManager } = require("./lib/tlsManager");
const { createHostChange } = require("./lib/hostChange");
const { createOperators } = require("./lib/operators");
const { createReauth } = require("./lib/reauth");
const { createUninstallKeys } = require("./lib/uninstallKey");
const { createPackageScanner } = require("./lib/packageScanner");
const { createSecretVault } = require("./lib/secretVault");
const { createUploads } = require("./lib/uploads");
const { createSoftwareLibrary } = require("./lib/softwareLibrary");
const { createDeployTargets } = require("./lib/deployTargets");
const { createDeploymentEngine } = require("./lib/deploymentEngine");
const { createAgentReleases } = require("./lib/agentReleases");
const { createAgentDeployment } = require("./lib/agentDeployment");
const { createTargetValidation } = require("./lib/targetValidation");
const { stateFile } = require("./lib/statePath");

function log(message) {
  process.stdout.write(`[${new Date().toISOString()}] ${message}\n`);
}

// Non-internal IPv4 addresses, so the portal can advertise LAN URLs agents can reach.
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

const store = new Store(config.onlineWindowMs, { requireApproval: config.requireApproval, logger: log, staleAfterMs: config.staleAfterMs });
store.attachPersistence(stateFile("portal-store.json"));
const operators = createOperators(config, log);
if (operators.setupPending()) {
  operators.setupCode();
}
const auth = createAuth(operators);
const tlsManager = createTlsManager(config, log);
const tls = tlsManager.current;
const urlCatalog = buildUrlCatalog(Boolean(tls));
const installer = new InstallerPackage(config.installerDir);

config.httpsEnabled = Boolean(tls);
const hostSettings = createHostSettings(config);
const hostChange = createHostChange({ hostSettings, tlsManager, store, logger: log, config });
const reauth = createReauth(auth, store, log);
const uninstallKeys = createUninstallKeys({ store, logger: log });
const maintenance = createMaintenance({ store, tlsManager, hostSettings, config, operators, logger: log });

// --- Software and agent deployment platform -------------------------------------------------------
const stateDir = path.dirname(stateFile("deployments.json"));
const scanner = createPackageScanner(config, log);
const vault = createSecretVault(stateFile("vault-secrets.json"), config.vaultKeyFile || path.join(stateDir, "vault.key"), store);
const storageLimits = {
  _used: () => 0,
  maxPackageBytes: () => config.maxPackageBytes,
  ensureCapacity(bytes) {
    if (storageLimits._used() + bytes > config.maxStorageBytes) {
      const error = new Error(`Adding this package would exceed the ${Math.floor(config.maxStorageBytes / 1048576)} MB library storage limit.`);
      error.status = 413;
      error.code = "storage_full";
      throw error;
    }
  },
  describe: () => ({ maxPackageBytes: config.maxPackageBytes, maxStorageBytes: config.maxStorageBytes, usedBytes: storageLimits._used() })
};
const library = createSoftwareLibrary({ dir: path.join(stateDir, "software"), stateFileName: stateFile("software-library.json"), scanner, vault, store, logger: log, limits: storageLimits });
storageLimits._used = () => library.usedBytes();
const uploads = createUploads(path.join(stateDir, "uploads"), storageLimits);
const targets = createDeployTargets(store, stateFile("deploy-targets.json"), config.agentHeartbeatSeconds);

// Bridges the engine to the agent command channel: a job dispatches one command per system.
const onDispatch = {
  software(agentId, spec) {
    const command = { commandId: crypto.randomUUID(), samAccountName: "", commandType: "InstallSoftware", newPassword: null, createdUtc: new Date().toISOString(), accountSource: null, deployment: spec };
    store.enqueueDeploymentCommand(agentId, command);
    return command;
  },
  agentAction(agentId, action) {
    const command = { commandId: crypto.randomUUID(), samAccountName: "", commandType: action === "repair" ? "RepairAgent" : "UpdateAgent", newPassword: null, createdUtc: new Date().toISOString(), accountSource: null, deployment: null };
    store.enqueueDeploymentCommand(agentId, command);
    return command;
  }
};
const engine = createDeploymentEngine({
  store, targets, library, vault, logger: log, stateFileName: stateFile("deployments.json"), onDispatch,
  agentVersion: () => {
    const manifest = installer.manifest();
    return manifest ? manifest.version : "";
  }
});
library.setUsage(engine.usageForPackage);
store.setDeploymentHandler({ onResult: engine.onResult });
const agentReleases = createAgentReleases({ dir: path.join(stateDir, "agent-releases"), installerDir: config.installerDir, stateFileName: stateFile("agent-releases.json"), scanner, store, installer, logger: log });
const agentDeployment = createAgentDeployment({ store, installer, engine, targets, logger: log, stateFileName: stateFile("agent-imports.json") });
const targetValidation = createTargetValidation({ store, targets, agentDeployment, logger: log });
targets.setValidationResolver(targetValidation.agentIds);
const deployContext = { store, auth, logger: log, config, uploads, library, targets, engine, vault, agentDeployment, agentReleases, targetValidation, scanner, reauth, limits: storageLimits };

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
  if (!config.forceHttps || !config.httpsEnabled || req.secure || req.path === "/healthz") {
    return next();
  }
  const host = req.hostname || config.publicHost;
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
// System lists (pasted or CSV/Excel up to 10 MB, sent base64) are larger than other operator requests.
app.use(["/api/deploy/targets/validate", "/api/agent-deployment/imports"], express.json({ limit: "15mb" }));
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

// A reset that clears accounts signs everyone out, including sessions that are open right now.
app.use((req, res, next) => {
  if (req.session && req.session.user && req.session.epoch !== operators.sessionEpoch()) {
    delete req.session.user;
  }
  next();
});

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

// API responses are never stored by browsers or proxies unless a route opts into revalidation.
app.use("/api", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

// Agent API first so its paths are claimed before the operator API catch-alls.
app.use("/api/agents", agentApiRouter(store, auth, config, installer, log, hostSettings, { engine, library, targets, tlsManager }));
// Setup needs no session, but only answers while the portal has no account at all.
app.use("/api", setupApiRouter({ operators, maintenance, store, auth, logger: log }));
app.use("/api", maintenanceApiRouter({ store, auth, maintenance, reauth, uninstallKeys, connectivity, tlsManager, hostSettings, config, logger: log }));
app.use("/api", portalApiRouter(store, auth, config, urlCatalog, log, installer, hostSettings, operators, tlsManager, hostChange, reauth, uninstallKeys));
app.use("/api", deployApiRouter(deployContext));
app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));
app.use("/", pagesRouter(store, auth, config, urlCatalog, tlsManager, installer, log, hostSettings, operators, hostChange));
app.use((req, res) => res.status(404).render("notFound", { message: "The page you requested does not exist." }));

// Fallback error handler: request-parsing failures keep their 4xx status; anything else is logged and
// answered with a generic 500 so internal details never reach the client.
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  const status = Number(err.status || err.statusCode) || 500;
  if (status >= 400 && status < 500) {
    let message = "The request could not be processed.";
    if (err.type === "entity.parse.failed") {
      message = "The request body is not valid JSON.";
    } else if (err.type === "entity.too.large") {
      message = "The request body is too large.";
    }
    return res.status(status).json({ error: message, code: "invalid" });
  }
  log(`Unhandled error on ${req.method} ${req.originalUrl}: ${err.message}`);
  return res.status(500).json({ error: "The portal could not complete the request.", code: "server_error" });
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
    if (!httpsOk) {
      config.httpsEnabled = false;
      log("HTTPS is unavailable, so requests are served over HTTP and agents are given an http:// address.");
    }
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

// Connectivity changes reach dashboards within about a second.
const presenceTimer = setInterval(() => store.sweepPresence(), 1000);
presenceTimer.unref();

// Each save is attempted on its own, so one failing does not lose the other.
function saveAll() {
  for (const save of [() => engine.flush(), () => store.flush(true)]) {
    try {
      save();
    } catch (error) {
      log(`Could not save state while stopping: ${error.message}`);
    }
  }
}

function shutdown() {
  saveAll();
  process.exit(0);
}

// After a backup restore the files on disk are the truth: stop saving and let systemd restart the portal.
maintenance.setRuntime({
  save: saveAll,
  freeze: () => {
    engine.detach();
    store.detachPersistence();
  },
  restart: () => {
    log("Restarting to load the restored state.");
    process.exit(0);
  }
});
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("unhandledRejection", (reason) => {
  log(`Unhandled promise rejection: ${reason && reason.message ? reason.message : reason}`);
});
// Save what is in memory before exiting; systemd restarts the service and agents reconnect by themselves.
process.on("uncaughtException", (error) => {
  log(`Unexpected error, restarting: ${error && error.stack ? error.stack : error}`);
  saveAll();
  process.exit(1);
});

start().catch((error) => {
  log(`The portal failed to start: ${error.message}`);
  store.flush();
  process.exit(1);
});
