"use strict";

// Public download of the Windows installer. Intentionally unauthenticated so an administrator can grab or
// share the installer before signing in, matching the agent enrollment model (the embedded enrollment key
// only registers an agent; each agent then gets its own credential). No management data is exposed here,
// and the installer files are served read-only — the portal never writes to the installer directory.
const express = require("express");

module.exports = function download(installer, config, logger, store, hostSettings) {
  const router = express.Router();

  // Lightweight metadata for the dashboard's download card (also unauthenticated).
  router.get("/agent/info", (req, res) => {
    const manifest = installer.manifest();
    res.json({
      available: Boolean(manifest),
      fileName: installer.fileName,
      version: manifest ? manifest.version : null,
      size: manifest ? manifest.size : null,
      signed: manifest ? manifest.signed : false,
      sha256: manifest ? manifest.sha256 : null,
      downloadUrl: `${hostSettings.managerUrl(req)}/download/agent`,
      downloadPath: "/download/agent"
    });
  });

  // The one-click installer: base build + embedded manager connection, so no manual entry is needed.
  router.get("/agent", (req, res) => {
    if (!installer.isAvailable()) {
      const detail = "The agent installer has not been built yet. Run scripts/build-agent.sh on a machine with the .NET SDK.";
      if (store) {
        store.recordDownload({ result: "Failed", remoteIp: req.ip, detail, fileName: installer.fileName });
      }
      return res.status(503).type("text/plain").send(detail);
    }

    const configBlock = {
      managerUrl: hostSettings.managerUrl(req),
      enrollmentKey: config.enrollmentKey,
      certificatePin: config.installerCertPin || "",
      issuedUtc: new Date().toISOString()
    };
    const payload = installer.personalized(configBlock);
    if (!payload) {
      const detail = "The installer could not be prepared.";
      if (store) {
        store.recordDownload({ result: "Failed", remoteIp: req.ip, detail, fileName: installer.fileName });
      }
      return res.status(503).type("text/plain").send(detail);
    }

    const manifest = installer.manifest();
    if (store) {
      store.recordDownload({
        result: "Success",
        remoteIp: req.ip,
        version: manifest ? manifest.version : "",
        fileName: installer.fileName,
        size: payload.length
      });
    }
    logger(`Installer downloaded from ${req.ip} (version ${manifest ? manifest.version : "unknown"}).`);
    res.setHeader("Content-Type", "application/vnd.microsoft.portable-executable");
    res.setHeader("Content-Disposition", `attachment; filename="${installer.fileName}"`);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Agent-Version", manifest ? manifest.version : "unknown");
    res.send(payload);
  });

  return router;
};
