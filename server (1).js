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
const LICENSED = COACHES.size > 0 || !!process.env.ADMIN_PASSWORD;
const MAX_ROOMS_PER_COACH = +process.env.MAX_ROOMS_PER_COACH || 5;

/* ---------- coach accounts (username + password, created only by the admin) ----------
   Storage: Upstash Redis (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN) so accounts survive
   restarts on free hosting; falls back to a local JSON file (DATA_FILE) otherwise.
   Admin: set ADMIN_PASSWORD; open /admin. */
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const UP_URL = String(process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, ""), UP_TOK = String(process.env.UPSTASH_REDIS_REST_TOKEN || "");
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "accounts.json");
const ACCOUNTS_ON = !!ADMIN_PASSWORD;
let ACCTS = {}; // username -> { user, name, salt, hash, expires(ms, 0 = none), maxRooms, disabled, created }
async function dbLoad() {
  try {
    if (UP_URL) {
      const r = await fetch(UP_URL, { method: "POST", headers: { Authorization: "Bearer " + UP_TOK }, body: JSON.stringify(["GET", "outplay_accounts"]) });
      const d = await r.json(); ACCTS = d && d.result ? JSON.parse(d.result) : {};
    } else if (fs.existsSync(DATA_FILE)) ACCTS = JSON.parse(fs.readFileSync(DATA_FILE, "utf8") || "{}");
  } catch (e) { console.error("accounts load failed:", e.message); }
}
async function dbSave() {
  const v = JSON.stringify(ACCTS);
  if (UP_URL) {
    const r = await fetch(UP_URL, { method: "POST", headers: { Authorization: "Bearer " + UP_TOK }, body: JSON.stringify(["SET", "outplay_accounts", v]) });
    const d = await r.json(); if (!d || d.error) throw new Error((d && d.error) || "db write failed");
  } else fs.writeFileSync(DATA_FILE, v);
}
const READY = ACCOUNTS_ON ? dbLoad() : Promise.resolve();
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString("base64url"); }
function normUser(u) { return String(u || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32); }
function acctActive(a) { return !!a && !a.disabled && (!a.expires || a.expires > Date.now()); }
function acctStatus(a) { return a.disabled ? "נעצר" : (a.expires && a.expires <= Date.now() ? "פג תוקף" : "פעיל"); }

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
function hasAccess(req) {
  if (!LICENSED) return true;
  const c = verify(cookieOf(req, "op_access"));
  if (!c) return false;
  if (c.kind === "coach" && c.val.startsWith("u:")) return acctActive(ACCTS[c.val.slice(2)]);
  return true;
}
const isAdmin = (req) => { const c = verify(cookieOf(req, "op_admin")); return !!(c && c.kind === "admin" && ACCOUNTS_ON); };
const adminCookie = () => ({ "Set-Cookie": `op_admin=${encodeURIComponent(sign(`admin|1|${Date.now() + 8 * 3600000}`))}; Path=/; Max-Age=${8 * 3600}; HttpOnly; SameSite=Strict${process.env.NODE_ENV === "production" || process.env.RENDER ? "; Secure" : ""}` });
const coachName = (c) => c.startsWith("u:") ? ((ACCTS[c.slice(2)] || {}).name || c.slice(2)) : COACHES.get(c);
const coachMaxRooms = (c) => c.startsWith("u:") ? ((ACCTS[c.slice(2)] || {}).maxRooms || MAX_ROOMS_PER_COACH) : MAX_ROOMS_PER_COACH;
function coachFromReq(req) {
  const c = verify(cookieOf(req, "op_access"));
  if (c && c.kind === "coach" && COACHES.has(c.val)) return c.val;
  if (c && c.kind === "coach" && c.val.startsWith("u:") && acctActive(ACCTS[c.val.slice(2)])) return c.val;
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
<link href="https://fonts.googleapis.com/css2?family=Frank+Ruhl+Libre:wght@900&family=Rubik:wght@400;600;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(900px 500px at 50% -10%,#1a232b,#0b0d10);color:#f1ede3;font-family:Rubik,system-ui,Arial}
.b{width:min(400px,92vw);background:#151a20;border:1px solid #2a313a;border-radius:20px;padding:28px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
h1{margin:0 0 4px;font-family:"Frank Ruhl Libre",serif;font-size:34px;font-weight:900;text-align:center}h1 b{color:#f0c878}
p{color:#9aa3ad;font-size:14px;line-height:1.5;text-align:center;margin:0 0 14px}
.tabs{display:flex;gap:6px;background:#0f1318;border-radius:12px;padding:4px;margin-bottom:16px}.tabs button{flex:1;background:none;border:0;color:#9aa3ad;padding:9px;border-radius:9px;font-weight:600;font-size:14px;cursor:pointer}.tabs button.on{background:#232a33;color:#f1ede3}
label{display:block;font-size:13px;color:#9aa3ad;margin:10px 0 4px}
input{width:100%;padding:13px;border-radius:10px;border:1px solid #39424d;background:#0d1014;color:#fff;font-size:17px;font-family:inherit}input:focus{outline:2px solid #d9a84e;outline-offset:1px}
.code{text-align:center;letter-spacing:.2em;text-transform:uppercase;font-size:20px}
.go{width:100%;margin-top:16px;padding:14px;border:0;border-radius:12px;background:linear-gradient(#f0c878,#d9a84e);color:#2a1c06;font-weight:800;font-size:16px;cursor:pointer;font-family:inherit}
.e{color:#ff8a78;min-height:22px;font-size:14px;margin-top:10px;text-align:center}.pane{display:none}.pane.on{display:block}</style></head><body><div class="b"><h1>OUT<b>PLAY</b></h1>
<p>מעבדת אימון פוקר</p>
<div class="tabs"><button id="t1" class="on" onclick="tab(1)">כניסת מאמן</button><button id="t2" onclick="tab(2)">קוד חדר / קוד מאמן</button></div>
<div class="pane on" id="p1"><label for="u">שם משתמש</label><input id="u" autocomplete="username" dir="ltr"><label for="pw">סיסמה</label><input id="pw" type="password" autocomplete="current-password" dir="ltr"><button class="go" onclick="login()">כניסה</button></div>
<div class="pane" id="p2"><label for="c">קוד חדר</label><input id="c" class="code" placeholder="ABCD" autocomplete="off"><button class="go" onclick="go()">הצטרפות</button></div>
<div class="e" id="e">${msg || ""}</div></div>
<script>
const $=id=>document.getElementById(id),q=new URLSearchParams(location.search).get('join');
function tab(n){$('t1').classList.toggle('on',n===1);$('t2').classList.toggle('on',n===2);$('p1').classList.toggle('on',n===1);$('p2').classList.toggle('on',n===2);$('e').textContent='';(n===1?$('u'):$('c')).focus()}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json().catch(()=>({}))}
async function login(){const user=$('u').value.trim(),password=$('pw').value;if(!user||!password){$('e').textContent='נא למלא שם משתמש וסיסמה';return}
const d=await post('/api/login',{user,password});if(d.ok)location.href='/';else $('e').textContent=d.error||'הכניסה נכשלה'}
async function go(){const code=$('c').value.trim();if(!code)return;const d=await post('/api/access',{code});
if(d.ok){location.href=d.room?('/?join='+d.room):'/'}else $('e').textContent=d.error||'קוד לא תקין'}
$('c').addEventListener('keydown',e=>{if(e.key==='Enter')go()});$('pw').addEventListener('keydown',e=>{if(e.key==='Enter')login()});$('u').addEventListener('keydown',e=>{if(e.key==='Enter')$('pw').focus()});
if(q){tab(2);$('c').value=q;go()}
</script></body></html>`;

const ADMIN_PAGE = (on) => `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OUTPLAY · ניהול מאמנים</title>
<link href="https://fonts.googleapis.com/css2?family=Frank+Ruhl+Libre:wght@900&family=Rubik:wght@400;600;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box}body{margin:0;background:#0b0d10;color:#f1ede3;font-family:Rubik,system-ui,Arial;padding:24px 16px}
.w{max-width:980px;margin:0 auto}h1{font-family:"Frank Ruhl Libre",serif;font-weight:900;font-size:30px;margin:0 0 4px}h1 b{color:#f0c878}h2{font-size:17px;margin:26px 0 10px}
.card{background:#151a20;border:1px solid #2a313a;border-radius:16px;padding:18px}
input,select{padding:10px 12px;border-radius:9px;border:1px solid #39424d;background:#0d1014;color:#fff;font-size:15px;font-family:inherit;min-width:0}
button{padding:9px 14px;border-radius:9px;border:1px solid #39424d;background:#232a33;color:#f1ede3;font-weight:600;cursor:pointer;font-family:inherit;font-size:14px}button.g{background:linear-gradient(#f0c878,#d9a84e);color:#2a1c06;border-color:#f6d99b}button.r{border-color:#7a3a33;color:#ffb3a6}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}.f{display:flex;flex-direction:column;gap:4px;font-size:13px;color:#9aa3ad}
table{width:100%;border-collapse:collapse;margin-top:6px}th{font-size:12px;color:#9aa3ad;text-align:start;padding:8px 6px;font-weight:600}td{padding:10px 6px;border-top:1px solid #2a313a;vertical-align:middle}
.st{padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600}.st.a{background:#12382c;color:#6fe0b0}.st.x{background:#40201c;color:#ff9a88}
.acts{display:flex;gap:5px;flex-wrap:wrap}.e{color:#ff8a78;min-height:20px;margin-top:8px}.note{color:#9aa3ad;font-size:13px;margin-top:8px}.warn{background:#3a2d12;border:1px solid #6b5420;color:#f0c878;padding:10px 14px;border-radius:12px;margin-top:12px;font-size:14px}
</style></head><body><div class="w"><h1>OUT<b>PLAY</b> · ניהול מאמנים</h1><div class="note">רק אתה רואה את העמוד הזה.</div>
<div id="login" class="card" style="margin-top:18px;max-width:380px"><div class="f">סיסמת מנהל<input id="ap" type="password" dir="ltr"></div><div style="margin-top:12px"><button class="g" onclick="alogin()">כניסה</button></div><div class="e" id="le">${on ? "" : "ADMIN_PASSWORD לא הוגדר בשרת. הגדר אותו ב-Render כדי להפעיל חשבונות."}</div></div>
<div id="main" style="display:none"><div id="warn"></div>
<h2>מאמן חדש</h2><div class="card"><div class="row"><div class="f">שם משתמש (אנגלית)<input id="nu" dir="ltr"></div><div class="f">שם להצגה<input id="nn"></div><div class="f">סיסמה<input id="np" dir="ltr"></div><div class="f">מנוי (ימים, 0 = ללא הגבלה)<input id="nd" type="number" value="30" style="width:130px"></div><div class="f">חדרים פעילים<input id="nr" type="number" value="3" style="width:90px"></div><button class="g" onclick="create()">צור חשבון</button></div><div class="e" id="ce"></div></div>
<h2>מאמנים</h2><div class="card"><table><thead><tr><th>שם</th><th>משתמש</th><th>סטטוס</th><th>תוקף עד</th><th>חדרים</th><th></th></tr></thead><tbody id="rows"></tbody></table><div class="e" id="te"></div></div></div>
<script>
const $=id=>document.getElementById(id);
async function api(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json().catch(()=>({ok:false,error:'שגיאת רשת'}))}
async function alogin(){const d=await api('/api/admin/login',{password:$('ap').value});if(d.ok){$('login').style.display='none';$('main').style.display='block';load()}else $('le').textContent=d.error||'שגיאה'}
$('ap').addEventListener('keydown',e=>{if(e.key==='Enter')alogin()});
const fd=t=>t?new Date(t).toLocaleDateString('he-IL'):'ללא הגבלה';
async function load(){const r=await fetch('/api/admin/list');const d=await r.json();if(!d.ok){$('te').textContent=d.error;return}
$('warn').innerHTML=d.persistent?'':'<div class="warn">אין חיבור ל-Upstash: החשבונות נשמרים בקובץ על השרת ועלולים להימחק כשהשרת מתחדש. הגדר UPSTASH_REDIS_REST_URL ו-UPSTASH_REDIS_REST_TOKEN.</div>';
$('rows').innerHTML=d.list.map(a=>'<tr><td>'+esc(a.name)+'</td><td dir="ltr">'+esc(a.user)+'</td><td><span class="st '+(a.status==='פעיל'?'a':'x')+'">'+a.status+'</span></td><td>'+fd(a.expires)+'</td><td dir="ltr" style="text-align:right">'+a.rooms+' / '+a.maxRooms+'</td><td class="acts"><button onclick="ext(\\''+a.user+'\\',30)">+30 יום</button><button onclick="ext(\\''+a.user+'\\',365)">+שנה</button><button onclick="tog(\\''+a.user+'\\')">'+(a.disabled?'הפעל':'עצור')+'</button><button onclick="pw(\\''+a.user+'\\')">סיסמה חדשה</button><button onclick="rooms(\\''+a.user+'\\','+a.maxRooms+')">חדרים</button><button class="r" onclick="del(\\''+a.user+'\\')">מחק</button></td></tr>').join('')||'<tr><td colspan="6" style="color:#9aa3ad">עדיין אין מאמנים. צור את הראשון למעלה.</td></tr>'}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function run(u,b){const d=await api(u,b);$('te').textContent=d.ok?'':(d.error||'שגיאה');load()}
async function create(){const d=await api('/api/admin/create',{user:$('nu').value,name:$('nn').value,password:$('np').value,days:$('nd').value,maxRooms:$('nr').value});$('ce').textContent=d.ok?'':(d.error||'שגיאה');if(d.ok){$('nu').value=$('nn').value=$('np').value='';load()}}
const ext=(u,days)=>run('/api/admin/extend',{user:u,days}),tog=u=>run('/api/admin/toggle',{user:u});
function pw(u){const p=prompt('סיסמה חדשה ל-'+u+' (לפחות 6 תווים)');if(p)run('/api/admin/password',{user:u,password:p})}
function rooms(u,n){const p=prompt('כמה חדרים פעילים מותר?',n);if(p)run('/api/admin/rooms',{user:u,maxRooms:p})}
function del(u){if(confirm('למחוק את '+u+' לצמיתות?'))run('/api/admin/delete',{user:u})}
</script></div></body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
    await READY;

    /* ---- admin (you only) ---- */
    if (p === "/admin") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY" }); res.end(ADMIN_PAGE(ACCOUNTS_ON)); return; }
    if (p === "/api/admin/login" && req.method === "POST") {
      if (!ACCOUNTS_ON) return sendJSON(res, 404, { ok: false, error: "ADMIN_PASSWORD לא הוגדר בשרת" });
      if (limited(req, "adminlogin", 6, 300000)) return sendJSON(res, 429, { ok: false, error: "יותר מדי ניסיונות, נסו שוב בעוד כמה דקות" });
      const b = await jsonBody(req, res, 2000); if (!b) return;
      if (!tokEq(String(b.password || ""), ADMIN_PASSWORD)) return sendJSON(res, 403, { ok: false, error: "סיסמה שגויה" });
      return sendJSON(res, 200, { ok: true }, adminCookie());
    }
    if (p.startsWith("/api/admin/")) {
      if (!isAdmin(req)) return sendJSON(res, 401, { ok: false, error: "לא מחובר" });
      if (p === "/api/admin/list") {
        const list = Object.values(ACCTS).map((a) => ({ user: a.user, name: a.name, expires: a.expires || 0, maxRooms: a.maxRooms, disabled: !!a.disabled, status: acctStatus(a), created: a.created }));
        let active = {}; for (const r of rooms.values()) if (r.coach) active[r.coach] = (active[r.coach] || 0) + 1;
        return sendJSON(res, 200, { ok: true, list: list.map((a) => Object.assign(a, { rooms: active["u:" + a.user] || 0 })), persistent: !!UP_URL });
      }
      const b = await jsonBody(req, res, 4000); if (!b) return;
      const user = normUser(b.user);
      if (p === "/api/admin/create") {
        const pw = String(b.password || "");
        if (!user || user.length < 3) return sendJSON(res, 400, { ok: false, error: "שם משתמש: לפחות 3 תווים באנגלית/ספרות" });
        if (pw.length < 6) return sendJSON(res, 400, { ok: false, error: "סיסמה: לפחות 6 תווים" });
        if (ACCTS[user]) return sendJSON(res, 409, { ok: false, error: "שם המשתמש תפוס" });
        const days = Math.max(0, Math.round(+b.days || 0)), salt = crypto.randomBytes(12).toString("base64url");
        ACCTS[user] = { user, name: String(b.name || user).slice(0, 60), salt, hash: hashPw(pw, salt), expires: days ? Date.now() + days * 86400000 : 0, maxRooms: Math.max(1, Math.min(50, Math.round(+b.maxRooms || MAX_ROOMS_PER_COACH))), disabled: false, created: Date.now() };
      } else {
        const a = ACCTS[user]; if (!a) return sendJSON(res, 404, { ok: false, error: "משתמש לא נמצא" });
        if (p === "/api/admin/extend") { const base = Math.max(a.expires || 0, Date.now()); a.expires = base + Math.max(1, Math.round(+b.days || 30)) * 86400000; a.disabled = false; }
        else if (p === "/api/admin/setexpiry") { a.expires = b.date ? new Date(b.date + "T23:59:59").getTime() : 0; }
        else if (p === "/api/admin/toggle") a.disabled = !a.disabled;
        else if (p === "/api/admin/password") { const pw = String(b.password || ""); if (pw.length < 6) return sendJSON(res, 400, { ok: false, error: "סיסמה: לפחות 6 תווים" }); a.salt = crypto.randomBytes(12).toString("base64url"); a.hash = hashPw(pw, a.salt); }
        else if (p === "/api/admin/rooms") a.maxRooms = Math.max(1, Math.min(50, Math.round(+b.maxRooms || 1)));
        else if (p === "/api/admin/delete") delete ACCTS[user];
        else return sendJSON(res, 404, { ok: false, error: "unknown" });
      }
      try { await dbSave(); } catch (e) { return sendJSON(res, 500, { ok: false, error: "שמירה נכשלה: " + e.message }); }
      return sendJSON(res, 200, { ok: true });
    }
    if (p === "/api/login" && req.method === "POST") {
      if (limited(req, "login", 8, 60000)) return sendJSON(res, 429, { ok: false, error: "יותר מדי ניסיונות, נסו שוב בעוד דקה" });
      const b = await jsonBody(req, res, 2000); if (!b) return;
      const a = ACCTS[normUser(b.user)];
      const good = a && tokEq(hashPw(String(b.password || ""), a.salt), a.hash);
      if (!good) return sendJSON(res, 403, { ok: false, error: "שם משתמש או סיסמה שגויים" });
      if (a.disabled) return sendJSON(res, 403, { ok: false, error: "החשבון הושהה. פנו אל הספק." });
      if (!acctActive(a)) return sendJSON(res, 403, { ok: false, error: "המנוי הסתיים. פנו אל הספק לחידוש." });
      return sendJSON(res, 200, { ok: true, kind: "coach", name: a.name }, setAccess("coach", "u:" + a.user, 7));
    }
    if (p === "/api/logout") return sendJSON(res, 200, { ok: true }, { "Set-Cookie": "op_access=; Path=/; Max-Age=0; HttpOnly" });

    /* ---- public config + access ---- */
    if (p === "/api/config") {
      const coach = LICENSED ? coachFromReq(req) : null;
      return sendJSON(res, 200, { ok: true, licensed: LICENSED, coach: coach ? coachName(coach) : null, isCoach: !LICENSED || !!coach });
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
          if (active >= coachMaxRooms(coach)) return sendJSON(res, 429, { ok: false, error: "הגעת למספר החדרים המקסימלי הפעיל" });
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

server.listen(PORT, () => console.log("OUTPLAY server listening on " + PORT + (LICENSED ? " (licensed mode, " + COACHES.size + " coach codes" + (ACCOUNTS_ON ? ", accounts " + (UP_URL ? "upstash" : "file") : "") + ")" : " (open mode)")));
