"use strict";

// Portal page routes (server-rendered EJS). All pages except /login require a session.
// Redirects are relative so they keep the host name and protocol (http or https) the browser used.
const express = require("express");
const { Roles, roleAllows } = require("../lib/commandTypes");

function safeReturnUrl(value) {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//") ? value : "/";
}

function loginView(installer, downloadUrl, overrides) {
  const manifest = installer.manifest();
  return Object.assign({
    error: null,
    returnUrl: "/",
    installerAvailable: Boolean(manifest),
    installerVersion: manifest ? manifest.version : null,
    installerFileName: manifest ? installer.fileName : "",
    downloadUrl
  }, overrides);
}

module.exports = function pages(store, auth, config, urlCatalog, tlsInfo, installer, logger, hostSettings, operators) {
  const router = express.Router();

  router.use((req, res, next) => {
    const user = req.session && req.session.user ? req.session.user : null;
    res.locals.user = user ? user.name : "";
    res.locals.role = user ? user.role : "";
    res.locals.publicHost = hostSettings.effectiveHost();
    res.locals.needsDns = hostSettings.needsDns();
    res.locals.agentContactUrl = hostSettings.managerUrl();
    res.locals.mustChangePassword = Boolean(user && (user.mustChangePassword || (operators && operators.mustChange(user.name))));
    res.locals.secure = req.secure;
    next();
  });

  router.get("/login", (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect("/");
    }
    res.render("login", loginView(installer, `${hostSettings.managerUrl(req)}/download/agent`, { returnUrl: safeReturnUrl(req.query.returnUrl) }));
  });

  router.post("/login", (req, res) => {
    const ip = req.ip || "unknown";
    const returnUrl = safeReturnUrl(req.body.returnUrl);
    const username = String(req.body.username || "").trim();

    const remaining = auth.throttle.lockoutRemaining(ip);
    if (remaining > 0) {
      return res.status(429).render("login", loginView(installer, `${hostSettings.managerUrl(req)}/download/agent`, {
        error: `Too many failed attempts. Try again in ${Math.ceil(remaining / 1000)} seconds.`,
        returnUrl
      }));
    }

    const result = auth.validate(username, req.body.password);
    if (!result) {
      auth.throttle.registerFailure(ip);
      store.addAudit({ user: username || "(blank)", action: "SignIn", result: "Failed", details: "Invalid username or password.", remoteIp: ip });
      logger(`Failed login attempt from ${ip}`);
      return res.status(401).render("login", loginView(installer, `${hostSettings.managerUrl(req)}/download/agent`, { error: "Invalid username or password.", returnUrl }));
    }

    auth.throttle.reset(ip);
    req.session.regenerate((err) => {
      if (err) {
        logger(`Session regeneration failed: ${err.message}`);
        return res.status(500).render("login", loginView(installer, `${hostSettings.managerUrl(req)}/download/agent`, { error: "Could not start a session. Try again.", returnUrl }));
      }
      req.session.user = result;
      store.addAudit({ user: result.name, action: "SignIn", result: "Success", details: `Signed in as ${result.role} over ${req.protocol.toUpperCase()}.`, remoteIp: ip });
      logger(`${result.name} signed in with role ${result.role}`);
      if (result.mustChangePassword) {
        return res.redirect("/account/password");
      }
      res.redirect(returnUrl);
    });
  });

  router.get("/logout", (req, res) => {
    const user = req.session && req.session.user;
    if (user) {
      store.addAudit({ user: user.name, action: "SignOut", result: "Success", details: "Signed out.", remoteIp: req.ip });
    }
    req.session.destroy(() => {
      res.clearCookie("uagent.sid");
      res.redirect("/login");
    });
  });

  router.use(auth.requirePage);
  router.use((req, res, next) => {
    const pending = req.session.user && (req.session.user.mustChangePassword || (operators && operators.mustChange(req.session.user.name)));
    if (pending && req.path !== "/account/password") {
      return res.redirect("/account/password");
    }
    return next();
  });

  router.get("/account/password", (req, res) => {
    res.render("password", { error: "" });
  });

  router.post("/account/password", (req, res) => {
    const nextPassword = String(req.body.newPassword || "");
    const confirm = String(req.body.confirmPassword || "");
    if (nextPassword !== confirm) {
      return res.status(400).render("password", { error: "The new password and confirmation do not match." });
    }
    try {
      operators.changePassword(req.session.user.name, req.body.currentPassword, nextPassword);
      req.session.user.mustChangePassword = false;
      store.addAudit({ user: req.session.user.name, action: "ChangePassword", result: "Success", details: "Replaced the initial password.", remoteIp: req.ip });
      logger(`${req.session.user.name} changed the initial portal password.`);
      return res.redirect("/");
    } catch (error) {
      return res.status(400).render("password", { error: error.message });
    }
  });

  router.get("/", (req, res) => {
    res.render("index");
  });

  router.get("/agents", (req, res) => {
    res.render("agents");
  });

  router.get("/downloads", (req, res) => {
    res.render("downloads");
  });

  router.get("/agents/details/:agentId", (req, res) => {
    const agentId = store.resolveAgentId(req.params.agentId);
    res.redirect(agentId ? `/agents/${store.getDisplayId(agentId)}` : "/agents");
  });

  router.get("/agents/:key", (req, res) => {
    const agentId = store.resolveAgentId(req.params.key);
    if (!agentId) {
      return res.status(404).render("notFound", {
        message: `No agent with id ${req.params.key} has enrolled with this portal.`
      });
    }
    res.render("agentDetails", {
      agentKey: store.getDisplayId(agentId),
      machineName: store.getMachineName(agentId)
    });
  });

  router.get("/accounts", (req, res) => {
    res.render("accounts", { readOnly: !roleAllows(req.session.user.role, Roles.Operator) });
  });

  router.get("/commands", (req, res) => {
    res.render("commands");
  });

  router.get("/audit", (req, res) => {
    res.render("audit");
  });

  function noticeText(code, access) {
    if (code === "saved") {
      return `Downloaded agents now contact ${access.host}.`;
    }
    if (code === "detected") {
      return "The saved DNS name was cleared. New downloads use this server's IP address again.";
    }
    if (code === "reissued") {
      return `Downloaded agents now contact ${access.host}. A new certificate was written. Restart the portal service before agents use it.`;
    }
    return "";
  }

  function settingsView(req, extras) {
    const access = hostSettings.describe(req);
    const httpsEnabled = Boolean(tlsInfo);
    const managerUrl = access.managerUrl;
    let certSubject = tlsInfo ? tlsInfo.subject : "";
    let certValidTo = tlsInfo ? tlsInfo.validTo : "";
    let certFingerprint = tlsInfo ? tlsInfo.fingerprint : "";
    if (access.certificateReissued) {
      try {
        const crypto = require("crypto");
        const fs = require("fs");
        const certificate = new crypto.X509Certificate(fs.readFileSync(config.certFile));
        certSubject = certificate.subject.replace(/\n/g, ", ");
        certValidTo = certificate.validTo;
        certFingerprint = certificate.fingerprint256;
      } catch (error) {
        logger(`Could not read the reissued certificate: ${error.message}`);
      }
    }
    return Object.assign({
      publicHttpUrl: managerUrl.replace(/^https:/, "http:"),
      publicHttpsUrl: httpsEnabled ? managerUrl.replace(/^http:/, "https:") : "",
      httpsEnabled,
      certFingerprint,
      certSubject,
      certValidTo,
      certCoversHost: httpsEnabled ? hostSettings.covers(access.host) : false,
      users: config.users.map((u) => ({ username: u.username, role: u.role })),
      enrollmentKeyIsDefault: config.enrollmentKey === "change-me-enroll",
      requireApproval: config.requireApproval,
      onlineWindowSeconds: Math.round(config.onlineWindowMs / 1000),
      urls: urlCatalog.urls,
      installer: installer.manifest(),
      installerFileName: installer.fileName,
      downloadPath: "/download/agent",
      downloadUrl: `${managerUrl}/download/agent`,
      access,
      canConfigureHost: roleAllows(req.session.user.role, Roles.Administrator),
      hostValue: "",
      hostError: "",
      hostNotice: noticeText(req.query.notice, access),
      certificateReissued: access.certificateReissued
    }, extras);
  }

  router.get("/settings", (req, res) => {
    res.render("settings", settingsView(req));
  });

  router.post("/settings/host", (req, res) => {
    const user = req.session.user;
    if (!roleAllows(user.role, Roles.Administrator)) {
      return res.status(403).render("settings", settingsView(req, { hostError: "Only an Administrator can change the host agents contact." }));
    }
    try {
      if (req.body.action === "detect") {
        hostSettings.clearHost(user.name);
        store.addAudit({
          user: user.name,
          action: "SetAgentHost",
          result: "Success",
          details: "Cleared the configured host. New downloads use the address opened in the browser.",
          remoteIp: req.ip
        });
        logger(`Agent host cleared by ${user.name}. Downloads use this server: ${hostSettings.managerUrl()}`);
        return res.redirect("/settings?notice=detected");
      }
      const saved = hostSettings.setHost(req.body.host, user.name);
      let reissued = false;
      if (req.body.reissue === "1") {
        hostSettings.reissueCertificate(saved.host);
        reissued = true;
      }
      store.addAudit({
        user: user.name,
        action: "SetAgentHost",
        result: "Success",
        details: `Agents downloaded from this portal contact ${saved.host}.${reissued ? " A new self-signed certificate was written and needs a portal restart." : ""}`,
        remoteIp: req.ip
      });
        logger(`Agents downloaded from this portal now contact ${hostSettings.managerUrl()}.`);
      return res.redirect(`/settings?notice=${reissued ? "reissued" : "saved"}`);
    } catch (error) {
      return res.status(400).render("settings", settingsView(req, { hostError: error.message, hostValue: String(req.body.host || "") }));
    }
  });

  return router;
};
