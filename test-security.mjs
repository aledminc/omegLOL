// Security test harness. Pure unit checks (validation, rate limiting, origin/CSP helpers) plus
// live integration against startServer with an in-memory DB (no auth env, no Postgres).
// Run: node test-security.mjs
//
// These are set BEFORE startServer is called (startServer reads them at boot), so they take effect
// even though ES imports evaluate first. The origin allowlist and a low per-IP cap make those
// paths testable.
process.env.NODE_ENV = "test";                 // not production (keep http, no HSTS redirect)
process.env.ALLOWED_ORIGINS = "http://good.example";
process.env.WS_MAX_CONNS_PER_IP = "3";
delete process.env.BETTER_AUTH_SECRET;         // guest/token-only; /api/auth has a limiter but no handler
for (const k of ["CLOUDFLARE_TURN_TOKEN_ID", "CLOUDFLARE_TURN_API_TOKEN", "TURN_URLS", "TURN_SECRET", "TURN_USERNAME", "TURN_PASSWORD"])
  delete process.env[k];                       // /api/ice must serve STUN-only in tests (no network calls)
delete process.env.ADMIN_EMAILS; delete process.env.ADMIN_USER_IDS;   // no admins -> admin routes fail closed
delete process.env.SENTRY_DSN;                                         // error tracking stays off in tests

import assert from "node:assert/strict";
import { once } from "node:events";
import WebSocket from "ws";
import { startServer } from "./server.mjs";
import { validateMessage, cleanText, escapeHtml } from "./validate.mjs";
import { makeLimiter } from "./ratelimit.mjs";
import { normalizeOrigin, isOriginAllowed, allowedOrigins, clientIp, cspDirectives } from "./security.mjs";
import { coturnCredentials, iceFromEnv, cloudflareIce } from "./ice.mjs";

let passed = 0;
const ok = name => { passed++; console.log("  ok -", name); };
const delay = ms => new Promise(r => setTimeout(r, ms));

// ---------------- minimal in-memory DB (only what these tests touch) ----------------
function memDb() {
  let uid = 0;
  const mk = ({ name, token }) => ({ id: ++uid, name: cleanText(name, 24) || "Anon", token: token || ("tok-" + uid),
    friend_code: "AAA-" + uid, auth_id: null, rating: 1000, wins: 0, losses: 0, draws: 0, games: 0, trust_score: 50 });
  const users = [];
  return {
    async initSchema() {},
    async getOrCreateUser({ token, name }) { if (token) { const u = users.find(x => x.token === token); if (u) return u; } const u = mk({ name }); users.push(u); return u; },
    async createGuestUser({ name }) { const u = mk({ name }); users.push(u); return u; },
    async isNameTaken(name, exceptId = null) { return users.some(u => u.name.toLowerCase() === String(name).toLowerCase() && u.id !== exceptId); },
    async logModeration() {},
    async getUserByToken(t) { return users.find(u => u.token === t) || null; },
    async recentMatches() { return []; },
    async topPlayers() { return []; },
    async friendsLeaderboard(userId) { return users.filter(u => u.id === userId); },
    async listFriends() { return []; },
    async listFriendRequests() { return []; },
    async requestFriend() { return { ok: false, reason: "not_found" }; },
    async acceptFriendRequest() { return { ok: false, reason: "not_found" }; },
    async declineFriendRequest() { return { ok: true }; },
    async getActiveBan() { return null; },
  };
}

// ---------------- tiny WS client with close-code tracking ----------------
function client(url, opts = {}) {
  const ws = new WebSocket(url, opts);
  const all = [], waiters = [];
  let closeCode = null;
  ws.on("message", d => { const m = JSON.parse(d); all.push(m); for (const w of [...waiters]) if (w.pred(m)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(m); } });
  ws.on("close", c => { closeCode = c; });
  ws.on("error", () => {});
  return {
    ws,
    open() { return ws.readyState === ws.OPEN ? Promise.resolve() : once(ws, "open"); },
    send(m) { ws.send(typeof m === "string" ? m : JSON.stringify(m)); },
    get closeCode() { return closeCode; },
    waitFor(pred, timeout = 4000) {
      const p = typeof pred === "string" ? (m => m.type === pred) : pred;
      const i = all.findIndex(p); if (i >= 0) return Promise.resolve(all[i]);
      return new Promise((res, rej) => { const w = { pred: p, resolve: res }; waiters.push(w); setTimeout(() => { const j = waiters.indexOf(w); if (j >= 0) { waiters.splice(j, 1); rej(new Error("timeout " + pred)); } }, timeout); });
    },
    waitClose(timeout = 4000) { if (closeCode != null) return Promise.resolve(closeCode); return new Promise(res => { ws.on("close", c => res(c)); setTimeout(() => res(closeCode), timeout); }); },
    close() { try { ws.close(); } catch {} },
  };
}
// Connect and report only whether the socket stayed open (used for the origin allowlist test).
function tryConnect(url, origin) {
  return new Promise(res => {
    const ws = new WebSocket(url, origin ? { headers: { origin } } : {});
    let done = false; const finish = v => { if (done) return; done = true; try { ws.close(); } catch {} res(v); };
    ws.on("open", () => finish(true));
    ws.on("error", () => finish(false));
    ws.on("unexpected-response", () => finish(false));
    setTimeout(() => finish(false), 3000);
  });
}

// ==================== pure unit tests (no server) ====================
function unitTests() {
  console.log("pure units");
  // validation
  assert.equal(validateMessage({ type: "find" }), "find");
  assert.equal(validateMessage({ type: "leaveMatch" }), "leaveMatch");
  assert.equal(validateMessage({ type: "nope" }), null);
  assert.equal(validateMessage("hello"), null);
  assert.equal(validateMessage({ type: "report", target: 3, reason: "cheating" }), "report");
  assert.equal(validateMessage({ type: "report", target: 3, reason: "banana" }), null);
  assert.equal(validateMessage({ type: "reaction", delta: 999, tier: "nuke" }), null);
  assert.equal(validateMessage({ type: "reaction", delta: 2.5, tier: "laugh", silent: true }), "reaction");
  assert.equal(validateMessage({ type: "reaction", delta: 2.5, silent: "yes" }), null);
  assert.equal(validateMessage({ type: "rematchRequest" }), "rematchRequest");
  assert.equal(validateMessage({ type: "rematchResponse", accept: true }), "rematchResponse");
  assert.equal(validateMessage({ type: "rematchResponse", accept: "yes" }), null);
  assert.equal(validateMessage({ type: "addMatchFriend" }), "addMatchFriend");
  assert.equal(validateMessage({ type: "faceCue", tracked: true, active: false,
    points: [[61, 500], [200, 400], [500, 350], [800, 400], [939, 500], [500, 650]] }), "faceCue");
  assert.equal(validateMessage({ type: "faceCue", tracked: true, active: true, points: [[1, 2]] }), null);
  assert.equal(validateMessage({ type: "faceCue", tracked: false, active: false, points: [] }), "faceCue");
  assert.equal(validateMessage({ type: "offer", target: 2, sdp: { type: "offer", sdp: "v=0" } }), "offer");
  assert.equal(validateMessage({ type: "offer", target: 2, sdp: { x: "a".repeat(40000) } }), null); // oversized blob
  assert.equal(validateMessage({ type: "rtcStat", ok: false }), "rtcStat");
  assert.equal(validateMessage({ type: "rtcStat", ok: "yes" }), null);
  ok("validateMessage accepts good / rejects malformed, unknown, out-of-range, oversized");

  assert.equal(cleanText("  a\t\n  b  ", 50), "a b");
  assert.equal(cleanText("<3 hi", 24), "<3 hi");                 // keeps angle brackets (escaped at render)
  assert.equal(escapeHtml('<img src=x onerror="a">'), "&lt;img src=x onerror=&quot;a&quot;&gt;");
  ok("text gate: cleanText normalizes/caps, escapeHtml neutralizes markup");

  // rate limiter: per-type budget + abuse disconnect (injected clock, no time passes)
  let t = 0; const clock = () => t;
  const lim = makeLimiter(clock);
  let allowed = 0; for (let i = 0; i < 8; i++) if (lim.check("chat").allow) allowed++;
  assert.equal(allowed, 8);                                       // chat cap is 8
  assert.equal(lim.check("chat").allow, false);                  // 9th (same instant) dropped
  ok("ratelimit: per-type token bucket drops the burst overflow");

  const lim2 = makeLimiter(() => 0);
  let disconnect = false; for (let i = 0; i < 200; i++) if (lim2.check("report").disconnect) { disconnect = true; break; }
  assert.ok(disconnect);                                          // sustained drops trip the abuse cap
  ok("ratelimit: sustained abuse signals disconnect");

  // origin / ip / csp helpers
  assert.equal(normalizeOrigin("HTTP://Example.com/"), "http://example.com");
  const set = allowedOrigins({ ALLOWED_ORIGINS: "http://a.com, https://b.com/" });
  assert.deepEqual([...set], ["http://a.com", "https://b.com"]);
  assert.ok(isOriginAllowed("http://a.com", set));
  assert.ok(!isOriginAllowed("http://evil.com", set));
  assert.ok(!isOriginAllowed("", set));                          // missing origin is not "allowed" by the helper
  assert.equal(clientIp({ headers: { "cf-connecting-ip": "1.2.3.4" } }), "1.2.3.4");
  assert.equal(clientIp({ headers: { "x-forwarded-for": "9.9.9.9, 10.0.0.1" } }), "9.9.9.9");
  const csp = cspDirectives({ production: true });
  assert.deepEqual(csp.frameAncestors, ["'none'"]);
  assert.deepEqual(csp.objectSrc, ["'none'"]);
  assert.ok(csp.scriptSrc.includes("'wasm-unsafe-eval'"));
  assert.ok("upgradeInsecureRequests" in csp);
  assert.ok(!("upgradeInsecureRequests" in cspDirectives({ production: false })));
  ok("security helpers: origin normalize/allow, client IP, CSP shape");

  // ICE sourcing (ice.mjs)
  const cc = coturnCredentials("sekret", { ttl: 600, now: 1_000_000_000_000 });
  assert.equal(cc.username, "1000000600:omeglol");                  // "<expiry>:<label>"
  assert.ok(cc.credential.length > 0 && cc.credential === coturnCredentials("sekret", { ttl: 600, now: 1_000_000_000_000 }).credential); // deterministic
  assert.deepEqual(iceFromEnv({}).config.iceServers.length, 1);    // STUN only when no TURN env
  assert.ok(/stun:/.test(String(iceFromEnv({}).config.iceServers[0].urls)));
  const staticIce = iceFromEnv({ TURN_URLS: "turn:t.example:3478", TURN_USERNAME: "u", TURN_PASSWORD: "p" }).config;
  assert.equal(staticIce.iceServers.length, 2);
  assert.equal(staticIce.iceServers[1].username, "u");
  const coturnIce = iceFromEnv({ TURN_URLS: "turn:t:3478", TURN_SECRET: "s", TURN_TTL: "600" }, { now: 1_000_000_000_000 }).config;
  assert.ok(coturnIce.iceServers[1].username.endsWith(":omeglol") && coturnIce.iceServers[1].credential.length > 0);
  ok("ice: coturn creds deterministic; env builds STUN / static / coturn configs");
}

// async ICE test (injected fetch — no real network)
async function iceCloudflareTest() {
  let calledUrl = null, calledAuth = null;
  const fakeFetch = async (url, opts) => {
    calledUrl = url; calledAuth = opts.headers.authorization;
    return { ok: true, json: async () => ({ iceServers: { urls: ["stun:stun.cloudflare.com:3478", "turn:turn.cloudflare.com:3478?transport=udp"], username: "cfu", credential: "cfc" } }) };
  };
  assert.equal(await cloudflareIce({}, { fetchImpl: fakeFetch }), null);   // no env -> null
  const out = await cloudflareIce({ CLOUDFLARE_TURN_TOKEN_ID: "key123", CLOUDFLARE_TURN_API_TOKEN: "tok456" }, { ttl: 3600, fetchImpl: fakeFetch });
  assert.ok(calledUrl.includes("/turn/keys/key123/credentials/generate"));
  assert.equal(calledAuth, "Bearer tok456");
  assert.equal(out.config.iceServers[0].username, "cfu");
  assert.equal(out.config.iceServers[0].credential, "cfc");
  ok("ice: Cloudflare TURN mints ephemeral creds via API (token stays server-side)");
}

// ==================== integration tests (live server) ====================
async function main() {
  unitTests();
  await iceCloudflareTest();

  const { server } = await startServer({ db: memDb(), pool: null, port: 0 });
  const port = server.address().port;
  const base = "http://127.0.0.1:" + port;
  const wsUrl = "ws://127.0.0.1:" + port;
  console.log("http/ws integration (port " + port + ")");

  // ---- HTTP security headers ----
  {
    const res = await fetch(base + "/");
    const h = res.headers, csp = h.get("content-security-policy") || "";
    assert.ok(/frame-ancestors 'none'/.test(csp), "CSP frame-ancestors none");
    assert.ok(/object-src 'none'/.test(csp), "CSP object-src none");
    assert.equal(h.get("x-frame-options"), "DENY");
    assert.equal(h.get("x-content-type-options"), "nosniff");
    assert.ok(h.get("referrer-policy"));
    assert.ok(/camera=\(self\)/.test(h.get("permissions-policy") || ""));
    assert.equal(h.get("x-powered-by"), null);
    ok("HTTP: security headers present, x-powered-by hidden, page cannot be framed");
  }

  // ---- /api/ice serves ICE config (STUN-only when no TURN env, no secrets) ----
  {
    const res = await fetch(base + "/api/ice");
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.ok(Array.isArray(j.iceServers) && j.iceServers.length >= 1, "iceServers array present");
    assert.ok(j.iceServers.some(s => /stun:/.test(String(s.urls))), "STUN entry present");
    assert.ok(!/TURN_|CLOUDFLARE|Bearer|credential.*secret/i.test(JSON.stringify(j)), "no secret leaked");
    ok("HTTP: /api/ice serves ICE config (STUN-only with no TURN env)");
  }

  // ---- /healthz: 200 when up (no pool = liveness only); 503 when the DB check fails; leaks nothing ----
  {
    const res = await fetch(base + "/healthz");
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });

    const failPool = { query: async () => { throw new Error("db down"); } };
    const { server: s2 } = await startServer({ db: memDb(), pool: failPool, port: 0 });
    const dead = await fetch("http://127.0.0.1:" + s2.address().port + "/healthz");
    assert.equal(dead.status, 503, "503 when DB unreachable");
    assert.deepEqual(await dead.json(), { ok: false });
    await new Promise(r => s2.close(r));
    ok("HTTP: /healthz 200 healthy, 503 on DB failure, reveals nothing");
  }

  // ---- admin surface is fail-closed (no auth + no admin env -> 403 everywhere) ----
  {
    for (const p of ["/api/admin/reports", "/api/admin/mod-events", "/api/admin/active-bans", "/api/admin/stats", "/api/admin/user/1", "/admin"])
      assert.equal((await fetch(base + p)).status, 403, p + " must 403");
    const post = await fetch(base + "/api/admin/ban", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ userId: 1, tier: "day" }) });
    assert.equal(post.status, 403, "admin ban must 403 for non-admin");
    ok("HTTP: /api/admin/* and /admin are fail-closed (403 without an admin session)");
  }

  // ---- consent endpoint gating + legal pages (crawlable for Google OAuth) ----
  {
    assert.equal((await fetch(base + "/api/consent", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ agree: false }) })).status, 400, "agree:true required");
    assert.equal((await fetch(base + "/api/consent", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ agree: true }) })).status, 401, "needs a resolved user");
    for (const p of ["/terms", "/privacy", "/about", "/agree", "/age"]) assert.equal((await fetch(base + p)).status, 200, p + " renders");
    const terms = await (await fetch(base + "/terms")).text();
    assert.ok(/peer-to-peer/i.test(terms) && /\b18\b/.test(terms), "/terms states 18+ and P2P risk");
    ok("HTTP: /api/consent gated (400/401); /terms /privacy /about /agree /age render");
  }

  // ---- HTTP body cap (413) ----
  {
    const big = JSON.stringify({ x: "a".repeat(20000) });         // > 16kb limit
    const res = await fetch(base + "/", { method: "POST", headers: { "content-type": "application/json" }, body: big });
    assert.equal(res.status, 413);
    const body = await res.json().catch(() => ({}));
    assert.ok(!/stack|Error:/i.test(JSON.stringify(body)));        // no internal detail leaked
    ok("HTTP: oversized JSON body rejected (413), no stack leaked");
  }

  // ---- HTTP auth rate limit (strict) ----
  {
    const codes = await Promise.all(Array.from({ length: 45 }, () => fetch(base + "/api/auth/ping").then(r => r.status)));
    assert.ok(codes.includes(429), "auth endpoint rate-limited after the strict cap");
    ok("HTTP: /api/auth/* is rate-limited (credential-stuffing backstop)");
  }

  // ---- WS per-IP connection cap (cap=3) — run first, count is clean ----
  {
    const a = client(wsUrl); const b = client(wsUrl); const c = client(wsUrl);
    await Promise.all([a.open(), b.open(), c.open()]);
    const extra = client(wsUrl);
    const code = await extra.waitClose(3000);
    assert.equal(code, 1013, "4th concurrent socket from one IP is refused (1013)");
    assert.equal(a.ws.readyState, a.ws.OPEN);                      // the first three survive
    a.close(); b.close(); c.close(); extra.close();
    await delay(200);
    ok("WS: concurrent connections per IP are capped");
  }

  // ---- WS malformed/unknown ignored; the socket keeps working ----
  {
    const cl = client(wsUrl); await cl.open();
    cl.send("{ not json");                                         // invalid JSON
    cl.send({ type: "totally-unknown", x: 1 });                   // unknown type
    cl.send({ type: "report", target: "abc", reason: "banana" }); // malformed report
    cl.send({ type: "auth", name: "tester" });                    // valid -> should still work
    const authed = await cl.waitFor("authed");
    assert.ok(authed.profile && authed.profile.id);
    cl.close(); await delay(150);
    ok("WS: malformed/unknown messages are ignored; the connection still serves valid ones");
  }

  // ---- WS oversized frame dropped (maxPayload) ----
  {
    const cl = client(wsUrl); await cl.open();
    cl.send("x".repeat(70 * 1024));                               // > 64KB maxPayload
    const code = await cl.waitClose(3000);
    assert.notEqual(code, null);                                  // server dropped the connection
    cl.close(); await delay(150);
    ok("WS: oversized frame is rejected and the socket is dropped");
  }

  // ---- WS sustained abuse -> disconnect ----
  {
    const cl = client(wsUrl); await cl.open();
    for (let i = 0; i < 400; i++) cl.send({ type: "leaderboard" }); // flood one type
    const code = await cl.waitClose(4000);
    assert.notEqual(code, null, "server closed the flooding socket");
    cl.close(); await delay(200);
    ok("WS: sustained message flooding disconnects the socket");
  }

  // ---- WS origin allowlist (ALLOWED_ORIGINS=http://good.example) ----
  {
    assert.equal(await tryConnect(wsUrl, "http://good.example"), true,  "allowed origin connects");
    assert.equal(await tryConnect(wsUrl, "http://evil.example"), false, "cross-site origin rejected");
    assert.equal(await tryConnect(wsUrl, null), true, "no-origin (non-browser) client allowed");
    ok("WS: Origin allowlist blocks cross-site WebSocket hijacking");
  }

  await new Promise(r => server.close(r));
  console.log(`\nAll ${passed} security tests passed.`);
}

main().then(() => process.exit(0)).catch(e => { console.error("\nFAILED:", e && e.stack || e); process.exit(1); });
