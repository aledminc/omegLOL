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

import assert from "node:assert/strict";
import { once } from "node:events";
import WebSocket from "ws";
import { startServer } from "./server.mjs";
import { validateMessage, cleanText, escapeHtml } from "./validate.mjs";
import { makeLimiter } from "./ratelimit.mjs";
import { normalizeOrigin, isOriginAllowed, allowedOrigins, clientIp, cspDirectives } from "./security.mjs";

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
    async getUserByToken(t) { return users.find(u => u.token === t) || null; },
    async recentMatches() { return []; },
    async topPlayers() { return []; },
    async listFriends() { return []; },
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
  assert.equal(validateMessage({ type: "nope" }), null);
  assert.equal(validateMessage("hello"), null);
  assert.equal(validateMessage({ type: "report", target: 3, reason: "cheating" }), "report");
  assert.equal(validateMessage({ type: "report", target: 3, reason: "banana" }), null);
  assert.equal(validateMessage({ type: "reaction", delta: 999, tier: "nuke" }), null);
  assert.equal(validateMessage({ type: "offer", target: 2, sdp: { type: "offer", sdp: "v=0" } }), "offer");
  assert.equal(validateMessage({ type: "offer", target: 2, sdp: { x: "a".repeat(40000) } }), null); // oversized blob
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
}

// ==================== integration tests (live server) ====================
async function main() {
  unitTests();

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
    cl.send({ type: "auth" });                                     // valid -> should still work
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
