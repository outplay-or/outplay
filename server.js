"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");

// In-memory key-value store. Simple and enough for ephemeral training-session rooms.
// Resets if the server restarts — that's fine, rooms are meant to be short-lived.
const store = new Map();

// Basic cleanup: drop keys older than 6 hours so memory doesn't grow forever on a long-running server.
const createdAt = new Map();
setInterval(() => {
  const cutoff = Date.now() - 6 * 60 * 60 * 1000;
  for (const [k, t] of createdAt) {
    if (t < cutoff) { store.delete(k); createdAt.delete(k); }
  }
}, 30 * 60 * 1000);

const INDEX_HTML = fs.readFileSync(path.join(__dirname, "index.html"));

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 1_000_000) { req.destroy(); reject(new Error("body too large")); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");

    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    if (url.pathname === "/api/kv/get" && req.method === "GET") {
      const key = url.searchParams.get("key") || "";
      if (!key || key.length > 200) return sendJSON(res, 400, { ok: false, error: "bad key" });
      const value = store.has(key) ? store.get(key) : null;
      return sendJSON(res, 200, { ok: true, value });
    }

    if (url.pathname === "/api/kv/set" && req.method === "POST") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch { return sendJSON(res, 400, { ok: false, error: "bad json" }); }
      const { key, value } = body || {};
      if (!key || typeof key !== "string" || key.length > 200) return sendJSON(res, 400, { ok: false, error: "bad key" });
      if (typeof value !== "string" || value.length > 500_000) return sendJSON(res, 400, { ok: false, error: "bad value" });
      store.set(key, value);
      createdAt.set(key, Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    if (url.pathname === "/api/health") {
      return sendJSON(res, 200, { ok: true, keys: store.size });
    }

    // everything else: serve the single-page app
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(INDEX_HTML);
  } catch (e) {
    sendJSON(res, 500, { ok: false, error: String((e && e.message) || e) });
  }
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log("OUTPLAY server listening on " + PORT));
