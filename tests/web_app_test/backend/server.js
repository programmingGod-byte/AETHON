// Minimal "real" web app backend for testing Aethon end to end (no npm dependencies).
// Runs behind nginx: client -> Aethon (veth0) -> nginx 127.0.0.1:8080 -> this app 127.0.0.1:3000
//
// Endpoints:
//   GET    /api/health              liveness
//   GET    /api/notes               list notes (in-memory)
//   POST   /api/notes   {text}      create a note
//   DELETE /api/notes/:id           delete a note
//   POST   /api/upload              streams the body, replies {bytes, sha256}
//   GET    /api/file/:name          streams a generated file (e.g. 5mb.bin) through node -> nginx -> Aethon
//   GET    /api/slow?ms=1500        delayed response (slow backend)
//   GET    /api/echo                echoes method, path and headers

"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || "/tmp/aethon_web_app_test/files";

const MAX_NOTES = 1000;
const MAX_NOTE_LEN = 500;
const MAX_JSON_BODY = 16 * 1024;

const notes = new Map();
let nextId = 1;

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readJson(req, res, cb) {
  let size = 0;
  const chunks = [];
  req.on("data", (c) => {
    size += c.length;
    if (size > MAX_JSON_BODY) {
      sendJson(res, 413, { error: "body too large" });
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on("end", () => {
    if (res.writableEnded) return;
    try {
      cb(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
    } catch {
      sendJson(res, 400, { error: "invalid JSON" });
    }
  });
}

function handleUpload(req, res) {
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  req.on("data", (c) => {
    bytes += c.length;
    hash.update(c);
  });
  req.on("end", () => sendJson(res, 200, { bytes, sha256: hash.digest("hex") }));
  req.on("error", () => res.destroy());
}

function handleFile(res, name) {
  // Only generated test files, never arbitrary paths
  if (!/^[0-9]+mb\.bin$/.test(name)) return sendJson(res, 404, { error: "not found" });
  const file = path.join(DATA_DIR, name);
  fs.stat(file, (err, st) => {
    if (err) return sendJson(res, 404, { error: "not found" });
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": st.size });
    const stream = fs.createReadStream(file);
    stream.on("error", () => res.destroy());
    stream.pipe(res);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;

  if (req.method === "GET" && p === "/api/health") {
    return sendJson(res, 200, { ok: true, uptime_s: Math.round(process.uptime()) });
  }

  if (p === "/api/notes" && req.method === "GET") {
    return sendJson(res, 200, { notes: [...notes.values()] });
  }

  if (p === "/api/notes" && req.method === "POST") {
    return readJson(req, res, (body) => {
      const text = typeof body.text === "string" ? body.text.trim() : "";
      if (!text || text.length > MAX_NOTE_LEN) {
        return sendJson(res, 400, { error: `text must be 1-${MAX_NOTE_LEN} characters` });
      }
      if (notes.size >= MAX_NOTES) return sendJson(res, 507, { error: "note limit reached" });
      const note = { id: nextId++, text, created_at: new Date().toISOString() };
      notes.set(note.id, note);
      sendJson(res, 201, note);
    });
  }

  const del = p.match(/^\/api\/notes\/(\d+)$/);
  if (del && req.method === "DELETE") {
    const ok = notes.delete(Number(del[1]));
    return sendJson(res, ok ? 200 : 404, ok ? { deleted: true } : { error: "not found" });
  }

  if (p === "/api/upload" && req.method === "POST") return handleUpload(req, res);

  const file = p.match(/^\/api\/file\/([^/]+)$/);
  if (file && req.method === "GET") return handleFile(res, file[1]);

  if (p === "/api/slow" && req.method === "GET") {
    const ms = Math.min(Math.max(Number(url.searchParams.get("ms")) || 1000, 0), 30000);
    return setTimeout(() => sendJson(res, 200, { slept_ms: ms }), ms);
  }

  if (p === "/api/echo") {
    return sendJson(res, 200, { method: req.method, path: req.url, headers: req.headers });
  }

  sendJson(res, 404, { error: "not found" });
});

server.keepAliveTimeout = 65000;
server.listen(PORT, HOST, () => {
  console.log(`[web_app_test] backend listening on http://${HOST}:${PORT} (DATA_DIR=${DATA_DIR})`);
});
