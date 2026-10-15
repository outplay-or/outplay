"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* =====================================================================
   OUTPLAY server
   - tiny in-memory KV used by the rooms (host browser = game engine)
   - per-room access control: host token, per-seat tokens (no impersonation,
     joiners cannot read other players' cards or write the table state)
   - rejoin flow (coach approval for a seat taken from a new device)
   - optional coach licensing: set env COACH_CODES="CODE1:Coach Name,CODE2:Other"
     When set, only holders of a code can open the app / create rooms. Players
     join with a room code (cookie issued after the room is verified).
   ===================================================================== */

const PORT = process.env.PORT || 8080;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString("hex");
const COACHES = new Map(); // code -> name
String(process.env.COACH_CODES || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((x) => {
  const i = x.indexOf(":");
  const code = (i < 0 ? x : x.slice(0, i)).trim().toUpperCase();
  COACHES.set(code, i < 0 ? code : x.slice(i + 1).trim());
});
const LICENSED = COACHES.size > 0;
const MAX_ROOMS_PER_COACH = +process.env.MAX_ROOMS_PER_COACH || 5;

const store = new Map();
const createdAt = new Map();
const rooms = new Map(); // code -> { hostToken, coach, seatTokens:[], reqs:{}, created }

setInterval(() => {
  const cutoff = Date.now() - 6 * 60 * 60 * 1000;
  for (const [k, t] of createdAt) if (t < cutoff) { store.delete(k); createdAt.delete(k); }
  for (const [c, r] of rooms) if (r.created < cutoff) rooms.delete(c);
}, 30 * 60 * 1000);

const INDEX_HTML = fs.readFileSync(path.join(__dirname, "index.html"));

/* ---------- helpers ---------- */
function sendJSON(res, status, obj, extra) {
  res.writeHead(status, Object.assign({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  }, extra || {}));
  res.end(JSON.stringify(obj));
}
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on("data", (c) => { size += c.length; if (size > (max || 3_000_000)) { req.destroy(); reject(new Error("body too large")); return; } chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
async function jsonBody(req, res, max) {
  let body;
  try { body = JSON.parse(await readBody(req, max)); } catch { sendJSON(res, 400, { ok: false, error: "bad json" }); return null; }
  return body || {};
}
const tokEq = (a, b) => typeof a === "string" && typeof b === "string" && a.length === b.length && a.length > 0 && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const newToken = () => crypto.randomBytes(18).toString("base64url");
const clientIp = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

// naive rate limit for guesses: max N per window per ip+bucket
const hits = new Map();
function limited(req, bucket, max, windowMs) {
  const k = bucket + "|" + clientIp(req), now = Date.now();
  const arr = (hits.get(k) || []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(k, arr);
  return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some((t) => now - t < 120000)) hits.delete(k); }, 60000);

/* ---------- signed access cookie (only used when licensing is on) ---------- */
function sign(payload) { return payload + "." + crypto.createHmac("sha256", SECRET).update(payload).digest("base64url"); }
function verify(tok) {
  if (!tok || typeof tok !== "string") return null;
  const i = tok.lastIndexOf("."); if (i < 0) return null;
  const p = tok.slice(0, i); if (!tokEq(sign(p), tok)) return null;
  const [kind, val, exp] = p.split("|"); if (+exp < Date.now()) return null;
  return { kind, val };
}
function cookieOf(req, name) {
  const m = String(req.headers.cookie || "").split(/;\s*/).map((c) => c.split("=")).find((c) => c[0] === name);
  return m ? decodeURIComponent(m.slice(1).join("=")) : null;
}
function setAccess(kind, val, days) {
  const tok = sign(`${kind}|${val}|${Date.now() + days * 86400000}`);
  return { "Set-Cookie": `op_access=${encodeURIComponent(tok)}; Path=/; Max-Age=${days * 86400}; HttpOnly; SameSite=Lax${process.env.NODE_ENV === "production" || process.env.RENDER ? "; Secure" : ""}` };
}
function hasAccess(req) { return !LICENSED || !!verify(cookieOf(req, "op_access")); }
function coachFromReq(req) {
  const c = verify(cookieOf(req, "op_access"));
  if (c && c.kind === "coach" && COACHES.has(c.val)) return c.val;
  const hdr = String(req.headers["x-coach-code"] || "").trim().toUpperCase();
  return COACHES.has(hdr) ? hdr : null;
}

/* ---------- per-room authorization ---------- */
function who(req, room) {
  if (!room) return { role: null };
  if (tokEq(String(req.headers["x-host-token"] || ""), room.hostToken)) return { role: "host" };
  const seat = parseInt(req.headers["x-seat"], 10);
  if (Number.isInteger(seat) && seat >= 0 && tokEq(String(req.headers["x-seat-token"] || ""), room.seatTokens[seat])) return { role: "seat", seat };
  return { role: null };
}
// returns null if allowed, otherwise [status, error]
function keyPolicy(method, key, req, itemSeat) {
  const m = /^room_([A-Z0-9]{4,8})_(.+)$/.exec(key);
  if (!m) return null; // non-room keys (diagnostics) stay open
  const room = rooms.get(m[1]), suf = m[2], me = who(req, room);
  if (suf === "meta") {
    if (method === "GET") return null;
    if (!room) return null; // creation is handled in the set handler
    return me.role === "host" ? null : [403, "host only"];
  }
  if (!room) return [404, "room not found"];
  if (suf === "queue") {
    if (method === "APPEND") return (me.role === "host" || (me.role === "seat" && me.seat === itemSeat)) ? null : [403, "bad seat token"];
    return me.role === "host" ? null : [403, "host only"];
  }
  const sm = /^(state|hist)_s(\d+)$/.exec(suf);
  if (sm && method === "GET") return (me.role === "host" || (me.role === "seat" && me.seat === +sm[2])) ? null : [403, "not your seat"];
  return me.role === "host" ? null : [403, "host only"];
}

/* ---------- HTTP ---------- */
const GATE = (msg) => `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OUTPLAY</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#05080c;color:#eef3f7;font-family:system-ui,Arial}
.b{width:min(380px,92vw);background:#121b24;border:1px solid #2c4054;border-radius:16px;padding:26px;text-align:center}
h1{margin:0 0 4px;font-size:26px}h1 b{color:#f2b84b}p{color:#8da0b1;font-size:14px;line-height:1.5}
input{width:100%;box-sizing:border-box;margin:8px 0;padding:13px;border-radius:10px;border:1px solid #2c4054;background:#0a1016;color:#fff;font-size:18px;text-align:center;letter-spacing:.2em;text-transform:uppercase}
button{width:100%;padding:13px;border:0;border-radius:10px;background:linear-gradient(#ffd36e,#e0a23a);font-weight:800;font-size:16px;cursor:pointer}
.e{color:#ff7b80;min-height:20px;font-size:14px}</style></head><body><div class="b"><h1>OUT<b>PLAY</b></h1>
<p>הכניסה למאמנים בעלי רישיון, או לשחקנים עם קוד חדר.</p><input id="c" placeholder="קוד מאמן / קוד חדר" autocomplete="off"><button onclick="go()">כניסה</button><div class="e" id="e">${msg || ""}</div></div>
<script>
const q=new URLSearchParams(location.search).get('join');if(q){document.getElementById('c').value=q}
async function go(){const code=document.getElementById('c').value.trim();if(!code)return;
const r=await fetch('/api/access',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});const d=await r.json().catch(()=>({}));
if(d.ok){location.href=d.room?('/?join='+d.room):'/'}else document.getElementById('e').textContent=d.error||'קוד לא תקין'}
document.getElementById('c').addEventListener('keydown',e=>{if(e.key==='Enter')go()});if(q)go();
</script></body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

    /* ---- public config + access ---- */
    if (p === "/api/config") {
      const coach = LICENSED ? coachFromReq(req) : null;
      return sendJSON(res, 200, { ok: true, licensed: LICENSED, coach: coach ? COACHES.get(coach) : null, isCoach: !LICENSED || !!coach });
    }
    if (p === "/api/access" && req.method === "POST") {
      if (limited(req, "access", 12, 60000)) return sendJSON(res, 429, { ok: false, error: "יותר מדי ניסיונות, נסו שוב בעוד דקה" });
      const b = await jsonBody(req, res, 2000); if (!b) return;
      const code = String(b.code || "").trim().toUpperCase();
      if (COACHES.has(code)) return sendJSON(res, 200, { ok: true, kind: "coach" }, setAccess("coach", code, 30));
      if (rooms.has(code) && store.has(`room_${code}_meta`)) return sendJSON(res, 200, { ok: true, kind: "player", room: code }, setAccess("player", code, 1));
      return sendJSON(res, 403, { ok: false, error: "קוד לא תקין או שהחדר לא קיים" });
    }

    /* ---- KV ---- */
    if (p === "/api/kv/health") return sendJSON(res, 200, { ok: true });
    if (p === "/api/health") return sendJSON(res, 200, { ok: true, keys: store.size, rooms: rooms.size });

    if (p.startsWith("/api/") && !hasAccess(req)) return sendJSON(res, 401, { ok: false, error: "no access" });

    if (p === "/api/kv/get" && req.method === "GET") {
      const key = url.searchParams.get("key") || "";
      if (!key || key.length > 200) return sendJSON(res, 400, { ok: false, error: "bad key" });
      const deny = keyPolicy("GET", key, req); if (deny) return sendJSON(res, deny[0], { ok: false, error: deny[1] });
      return sendJSON(res, 200, { ok: true, value: store.has(key) ? store.get(key) : null });
    }

    if (p === "/api/kv/set" && req.method === "POST") {
      const body = await jsonBody(req, res); if (!body) return;
      const { key, value } = body;
      if (!key || typeof key !== "string" || key.length > 200) return sendJSON(res, 400, { ok: false, error: "bad key" });
      const big = /_hist_(s\d+|full)$/.test(key);
      if (typeof value !== "string" || value.length > (big ? 2_500_000 : 500_000)) return sendJSON(res, 400, { ok: false, error: "bad value" });
      const m = /^room_([A-Z0-9]{4,8})_meta$/.exec(key);
      if (m && !rooms.has(m[1])) {
        // room creation
        let coach = null;
        if (LICENSED) {
          coach = coachFromReq(req);
          if (!coach) return sendJSON(res, 403, { ok: false, error: "נדרש קוד מאמן תקף ליצירת חדר" });
          let active = 0; for (const r of rooms.values()) if (r.coach === coach) active++;
          if (active >= MAX_ROOMS_PER_COACH) return sendJSON(res, 429, { ok: false, error: "הגעת למספר החדרים המקסימלי הפעיל" });
        }
        const ht = String(req.headers["x-host-token"] || "");
        if (ht.length < 16) return sendJSON(res, 400, { ok: false, error: "missing host token" });
        rooms.set(m[1], { hostToken: ht, coach, seatTokens: [], reqs: {}, created: Date.now() });
      } else {
        const deny = keyPolicy("SET", key, req); if (deny) return sendJSON(res, deny[0], { ok: false, error: deny[1] });
      }
      store.set(key, value); createdAt.set(key, Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    if (p === "/api/kv/append" && req.method === "POST") {
      const body = await jsonBody(req, res); if (!body) return;
      const { key, item } = body;
      if (!key || typeof key !== "string" || key.length > 200) return sendJSON(res, 400, { ok: false, error: "bad key" });
      if (item === undefined) return sendJSON(res, 400, { ok: false, error: "missing item" });
      const deny = keyPolicy("APPEND", key, req, item && item.seat); if (deny) return sendJSON(res, deny[0], { ok: false, error: deny[1] });
      let arr = [];
      const existing = store.has(key) ? store.get(key) : null;
      if (existing) { try { arr = JSON.parse(existing); if (!Array.isArray(arr)) arr = []; } catch { arr = []; } }
      if (arr.length > 200) arr = arr.slice(-100);
      arr.push(item);
      const s = JSON.stringify(arr);
      if (s.length > 500_000) return sendJSON(res, 400, { ok: false, error: "queue too large" });
      store.set(key, s); createdAt.set(key, Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    // atomic read-and-clear of a queue (host only) - no action can be lost between read and clear
    if (p === "/api/kv/drain" && req.method === "POST") {
      const body = await jsonBody(req, res); if (!body) return;
      const key = body.key;
      if (!key || typeof key !== "string" || !/_queue$/.test(key)) return sendJSON(res, 400, { ok: false, error: "bad key" });
      const deny = keyPolicy("DRAIN", key, req); if (deny) return sendJSON(res, deny[0], { ok: false, error: deny[1] });
      let arr = []; try { arr = JSON.parse(store.get(key) || "[]"); } catch {}
      store.set(key, "[]");
      return sendJSON(res, 200, { ok: true, items: Array.isArray(arr) ? arr : [] });
    }

    /* ---- seats ---- */
    if (p === "/api/kv/claim-seat" && req.method === "POST") {
      const body = await jsonBody(req, res); if (!body) return;
      const { key, name } = body;
      const m = /^room_([A-Z0-9]{4,8})_meta$/.exec(String(key || ""));
      if (!m) return sendJSON(res, 400, { ok: false, error: "bad key" });
      if (typeof name !== "string" || !name.trim() || name.length > 40) return sendJSON(res, 400, { ok: false, error: "bad name" });
      const room = rooms.get(m[1]), raw = store.get(key);
      if (!room || !raw) return sendJSON(res, 404, { ok: false, error: "room not found" });
      let meta; try { meta = JSON.parse(raw); } catch { return sendJSON(res, 500, { ok: false, error: "corrupt room state" }); }
      if (meta.ended) return sendJSON(res, 200, { ok: true, seat: -1, reason: "ended" });
      const nm = name.trim();
      if (meta.seats.some((s) => s && s.toLowerCase() === nm.toLowerCase())) return sendJSON(res, 200, { ok: true, seat: -1, reason: "exists" });
      if (meta.started) return sendJSON(res, 200, { ok: true, seat: -1, reason: "started" });
      const seat = meta.seats.findIndex((s) => s === null);
      if (seat < 0) return sendJSON(res, 200, { ok: true, seat: -1, reason: "full" });
      meta.seats[seat] = nm;
      room.seatTokens[seat] = newToken();
      const s = JSON.stringify(meta);
      store.set(key, s); createdAt.set(key, Date.now());
      return sendJSON(res, 200, { ok: true, seat, token: room.seatTokens[seat], value: s });
    }

    // Coming back after refresh / dropped connection. Same device (valid token) -> straight in.
    // Otherwise the coach has to approve before the seat is handed over.
    if (p === "/api/room/rejoin" && req.method === "POST") {
      if (limited(req, "rejoin", 20, 60000)) return sendJSON(res, 429, { ok: false, error: "יותר מדי ניסיונות" });
      const b = await jsonBody(req, res, 4000); if (!b) return;
      const code = String(b.code || "").toUpperCase(), nm = String(b.name || "").trim().toLowerCase();
      const room = rooms.get(code), raw = store.get(`room_${code}_meta`);
      if (!room || !raw) return sendJSON(res, 404, { ok: false, error: "room not found" });
      const meta = JSON.parse(raw); if (meta.ended) return sendJSON(res, 200, { ok: false, error: "החדר נסגר" });
      const seat = meta.seats.findIndex((s) => s && s.trim().toLowerCase() === nm);
      if (seat < 0) return sendJSON(res, 404, { ok: false, error: "לא נמצא שחקן בשם הזה בחדר" });
      if (seat === 0) return sendJSON(res, 403, { ok: false, error: "מושב המארח אפשרי רק מהמכשיר של המאמן" });
      if (tokEq(String(b.token || ""), room.seatTokens[seat])) return sendJSON(res, 200, { ok: true, seat, token: room.seatTokens[seat], name: meta.seats[seat], value: JSON.stringify(meta) });
      const old = room.reqs[seat];
      if (old && old.status === "pending" && Date.now() - old.ts < 300000) return sendJSON(res, 200, { ok: true, pending: true, reqId: old.id });
      const id = newToken().slice(0, 10);
      room.reqs[seat] = { id, seat, name: meta.seats[seat], ts: Date.now(), status: "pending" };
      return sendJSON(res, 200, { ok: true, pending: true, reqId: id });
    }
    if (p === "/api/room/rejoin-status" && req.method === "GET") {
      const code = String(url.searchParams.get("code") || "").toUpperCase(), id = url.searchParams.get("req");
      const room = rooms.get(code); if (!room) return sendJSON(res, 404, { ok: false, error: "room not found" });
      const r = Object.values(room.reqs).find((x) => x.id === id);
      if (!r) return sendJSON(res, 200, { ok: true, status: "none" });
      if (r.status === "approved" && !r.delivered) {
        r.delivered = true; room.seatTokens[r.seat] = newToken(); // old device loses the seat
        return sendJSON(res, 200, { ok: true, status: "approved", seat: r.seat, token: room.seatTokens[r.seat], name: r.name });
      }
      return sendJSON(res, 200, { ok: true, status: r.delivered ? "used" : (Date.now() - r.ts > 300000 && r.status === "pending" ? "expired" : r.status) });
    }
    if (p === "/api/room/requests" && req.method === "GET") {
      const code = String(url.searchParams.get("code") || "").toUpperCase(), room = rooms.get(code);
      if (!room || who(req, room).role !== "host") return sendJSON(res, 403, { ok: false, error: "host only" });
      const list = Object.values(room.reqs).filter((r) => r.status === "pending" && Date.now() - r.ts < 300000).map((r) => ({ id: r.id, seat: r.seat, name: r.name }));
      return sendJSON(res, 200, { ok: true, list });
    }
    if (p === "/api/room/decide" && req.method === "POST") {
      const b = await jsonBody(req, res, 2000); if (!b) return;
      const code = String(b.code || "").toUpperCase(), room = rooms.get(code);
      if (!room || who(req, room).role !== "host") return sendJSON(res, 403, { ok: false, error: "host only" });
      const r = Object.values(room.reqs).find((x) => x.id === b.id);
      if (!r || r.status !== "pending") return sendJSON(res, 404, { ok: false, error: "no such request" });
      r.status = b.approve ? "approved" : "denied";
      return sendJSON(res, 200, { ok: true });
    }
    // coach removes a player's access (e.g. kicked / lost device)
    if (p === "/api/room/revoke" && req.method === "POST") {
      const b = await jsonBody(req, res, 2000); if (!b) return;
      const code = String(b.code || "").toUpperCase(), room = rooms.get(code);
      if (!room || who(req, room).role !== "host") return sendJSON(res, 403, { ok: false, error: "host only" });
      if (Number.isInteger(b.seat) && b.seat > 0) room.seatTokens[b.seat] = newToken();
      return sendJSON(res, 200, { ok: true });
    }

    /* ---- app ---- */
    if (!hasAccess(req)) { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }); res.end(GATE("")); return; }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN" });
    res.end(INDEX_HTML);
  } catch (e) {
    sendJSON(res, 500, { ok: false, error: String((e && e.message) || e) });
  }
});

server.listen(PORT, () => console.log("OUTPLAY server listening on " + PORT + (LICENSED ? " (licensed mode, " + COACHES.size + " coach codes)" : " (open mode)")));
