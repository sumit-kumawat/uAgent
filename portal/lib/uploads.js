"use strict";

// Chunked, resumable uploads from the browser. Each chunk is a separate short request, so large
// installers survive proxies, request timeouts and brief network drops, and an interrupted upload
// continues from the bytes already received.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CHUNK_SIZE = 8 * 1024 * 1024;
const IDLE_EXPIRY_MS = 24 * 60 * 60 * 1000;
const PURPOSES = new Set(["software", "agent-release"]);

class UploadError extends Error {
  constructor(message, status, code, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra || {};
  }
}

function safeFileName(name) {
  const base = path.basename(String(name || "")).replace(/[^\w.\- ()+]/g, "_").trim();
  return base.slice(0, 200);
}

function createUploads(dir, limits) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sessions = new Map();

  function sweep() {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (now - session.touched > IDLE_EXPIRY_MS) {
        discard(id);
      }
    }
  }

  function maxBytesFor(purpose) {
    return purpose === "agent-release" ? 512 * 1024 * 1024 : limits.maxPackageBytes();
  }

  function start({ fileName, size, purpose }, user) {
    sweep();
    const name = safeFileName(fileName);
    const total = Number(size);
    if (!PURPOSES.has(purpose)) {
      throw new UploadError("Unknown upload purpose.", 400, "invalid");
    }
    if (!name) {
      throw new UploadError("A file name is required.", 400, "invalid", { field: "fileName" });
    }
    const extension = path.extname(name).toLowerCase();
    if (purpose === "software" && extension !== ".msi" && extension !== ".exe") {
      throw new UploadError("Only .msi and .exe installers can be uploaded.", 400, "invalid", { field: "fileName" });
    }
    if (purpose === "agent-release" && extension !== ".exe") {
      throw new UploadError("Agent releases must be the uAgent .exe installer.", 400, "invalid", { field: "fileName" });
    }
    const maxBytes = maxBytesFor(purpose);
    if (!Number.isSafeInteger(total) || total <= 0) {
      throw new UploadError("The file size is missing or invalid.", 400, "invalid", { field: "size" });
    }
    if (total > maxBytes) {
      throw new UploadError(`The file is larger than the ${Math.floor(maxBytes / 1048576)} MB limit.`, 413, "too_large");
    }
    limits.ensureCapacity(total);
    const id = crypto.randomUUID();
    const file = path.join(dir, `${id}.part`);
    fs.writeFileSync(file, Buffer.alloc(0), { mode: 0o600 });
    const session = { id, fileName: name, size: total, received: 0, purpose, file, user: user.name, touched: Date.now(), writing: false };
    sessions.set(id, session);
    return { uploadId: id, chunkSize: CHUNK_SIZE, maxBytes };
  }

  function get(id, user) {
    const session = sessions.get(id);
    if (!session || session.user !== user.name) {
      throw new UploadError("The upload was not found or has expired. Start it again.", 404, "not_found");
    }
    session.touched = Date.now();
    return session;
  }

  function describe(id, user) {
    const s = get(id, user);
    return { uploadId: s.id, fileName: s.fileName, size: s.size, received: s.received, purpose: s.purpose };
  }

  // Streams one chunk to disk. The offset must match the bytes received so far, which makes
  // retries idempotent and rejects out-of-order chunks.
  function writeChunk(id, user, offset, req) {
    const session = get(id, user);
    return new Promise((resolve, reject) => {
      if (session.writing) {
        return reject(new UploadError("Another chunk for this upload is still being written.", 409, "busy", { received: session.received }));
      }
      if (Number(offset) !== session.received) {
        return reject(new UploadError("The chunk offset does not match the bytes received.", 409, "offset_mismatch", { received: session.received }));
      }
      session.writing = true;
      const out = fs.createWriteStream(session.file, { flags: "a" });
      let written = 0;
      let failed = false;
      const fail = (error) => {
        if (failed) {
          return;
        }
        failed = true;
        req.unpipe(out);
        out.destroy();
        req.resume();
        try {
          fs.truncateSync(session.file, session.received);
        } catch {
          // The next chunk will be rejected with offset_mismatch and the browser resumes.
        }
        session.writing = false;
        reject(error);
      };
      req.on("data", (chunk) => {
        written += chunk.length;
        if (written > CHUNK_SIZE || session.received + written > session.size) {
          fail(new UploadError("The chunk is larger than allowed.", 413, "too_large"));
        }
      });
      req.on("aborted", () => fail(new UploadError("The chunk upload was interrupted.", 400, "aborted", { received: session.received })));
      out.on("error", (error) => fail(new UploadError(`The chunk could not be stored: ${error.message}`, 500, "storage")));
      out.on("finish", () => {
        if (failed) {
          return;
        }
        session.received += written;
        session.writing = false;
        session.touched = Date.now();
        resolve({ received: session.received });
      });
      req.pipe(out);
    });
  }

  // Hands the finished file to the caller, which moves it into its own storage.
  function take(id, user, purpose) {
    const session = get(id, user);
    if (session.purpose !== purpose) {
      throw new UploadError("The upload was started for a different purpose.", 400, "invalid");
    }
    if (session.received !== session.size) {
      throw new UploadError(`The upload is incomplete (${session.received} of ${session.size} bytes).`, 409, "incomplete", { received: session.received });
    }
    sessions.delete(id);
    return { file: session.file, fileName: session.fileName, size: session.size };
  }

  function discard(id, user) {
    const session = sessions.get(id);
    if (!session || (user && session.user !== user.name)) {
      return false;
    }
    sessions.delete(id);
    fs.rm(session.file, { force: true }, () => {});
    return true;
  }

  // Leftover partial files from a previous run cannot be resumed (sessions are in memory).
  for (const entry of fs.readdirSync(dir)) {
    if (entry.endsWith(".part")) {
      fs.rmSync(path.join(dir, entry), { force: true });
    }
  }
  const timer = setInterval(sweep, 60 * 60 * 1000);
  timer.unref();

  return { start, describe, writeChunk, take, discard, CHUNK_SIZE };
}

module.exports = { createUploads, UploadError, safeFileName };
