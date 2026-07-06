// Integration test: drives the real WS protocol against startServer with an in-memory DB
// (no auth env, no Postgres). Cameras can't be tested, so we exercise the report/ban PROTOCOL.
// Run: node test-moderation-ws.mjs
//
// Phases sit in "countdown" indefinitely (durations pinned huge below) so a match stays live
// while we drive reports; we tear games down explicitly via `next`, disconnect, or a ban.
process.env.T_COUNTDOWN = "36000";
process.env.T_ROUND = "36000";
process.env.T_SWAP = "36000";
process.env.T_RESULT = "36000";
delete process.env.BETTER_AUTH_SECRET;           // force guest/token-only mode

import assert from "node:assert/strict";
import { once } from "node:events";
import WebSocket from "ws";
import { startServer } from "./server.mjs";
import { HEAT_AUTHED, TRUST_DEFAULT } from "./moderation.mjs";

// ---------------- in-memory DB (implements everything server.mjs calls) ----------------
function makeMemDb() {
  const users = [], reports = [], bans = [];
  let uid = 0, rid = 0, bid = 0;
  const now = () => new Date();

  function createUser({ name, token, authId = null }) {
    const u = { id: ++uid, name: name || "Anon", token: token || ("tok-" + uid), friend_code: "AAA-" + uid,
      auth_id: authId, rating: 1000, wins: 0, losses: 0, draws: 0, games: 0, trust_score: TRUST_DEFAULT };
    users.push(u); return u;
  }
  // pre-seed a real "account" (auth_id set -> server treats as logged-in, not guest)
  function seedAccount(name) { const u = createUser({ name, token: "acct-" + (uid + 1), authId: "auth-" + (uid + 1) }); return u.token; }

  const byId = id => users.find(u => u.id === id);

  return {
    _users: users, _reports: reports, _bans: bans, seedAccount,
    _clearBans(userId) { for (const b of bans) if (b.user_id === userId) b.cleared = true; },
    _ageReports(ms) { for (const r of reports) r.created_at = new Date(r.created_at.getTime() - ms); },

    async initSchema() {},
    async getOrCreateUser({ token, name }) {
      if (token) { const u = users.find(x => x.token === token); if (u) return u; }
      return createUser({ name, token: undefined });     // fresh guest (fresh token), auth_id null
    },
    async getUserByToken(token) { return users.find(u => u.token === token) || null; },
    async getUserByAuthId(authId) { return users.find(u => u.auth_id === authId) || null; },
    async createAuthedUser({ authId, name }) { return createUser({ name, authId }); },
    async recentMatches() { return []; },
    async topPlayers() { return []; },
    async recordMatch() { return null; },
    async recordDuosRatings() { return {}; },
    async getUserById(id) { return byId(id) || null; },
    async addFriendByCode() { return { ok: false, reason: "not_found" }; },
    async listFriends() { return []; },

    // ---- moderation ----
    async insertReport(r) {
      if (reports.some(x => x.reporter_id === r.reporter_id && x.reported_id === r.reported_id && x.game_id === r.game_id))
        return { inserted: false, duplicate: true };
      const row = { id: ++rid, created_at: now(), stale_checked: false, ...r, detail: r.detail ?? null,
        reporter_ip_hash: r.reporter_ip_hash ?? null, needs_review: r.needs_review ?? false };
      reports.push(row); return { inserted: true, id: row.id, duplicate: false };
    },
    async getReportCluster(reportedId, sinceTs) {
      return reports.filter(r => r.reported_id === reportedId && r.created_at >= sinceTs);
    },
    async getActiveBan(userId) {
      const active = bans.filter(b => b.user_id === userId && !b.cleared && b.expires_at > now())
        .sort((a, b) => b.expires_at - a.expires_at);
      return active[0] || null;
    },
    async countPriorBans(userId) { return bans.filter(b => b.user_id === userId).length; },
    async issueBan({ userId, tier, reason, isGuest, expiresAt }) {
      const b = { id: ++bid, user_id: userId, reason, tier, is_guest: isGuest, created_at: now(), expires_at: expiresAt, cleared: false };
      bans.push(b); return b;
    },
    async adjustTrust(userId, delta) {
      const u = byId(userId); if (!u) return null;
      const hi = u.auth_id == null ? 60 : 100;
      u.trust_score = Math.max(0, Math.min(hi, Math.round(u.trust_score + delta)));
      return u.trust_score;
    },
    async getTrust(userId) { return byId(userId)?.trust_score ?? TRUST_DEFAULT; },
    async recentReportsBy(reporterId, sinceTs) { return reports.filter(r => r.reporter_id === reporterId && r.created_at >= sinceTs); },
    async gamesPlayed(userId) { return byId(userId)?.games ?? 0; },
    async agingUncorroboratedReports(reporterId, beforeTs) {
      return reports.filter(r => r.reporter_id === reporterId && r.created_at < beforeTs && !r.stale_checked
        && !reports.some(o => o.reported_id === r.reported_id && o.reporter_id !== r.reporter_id));
    },
    async markStaleChecked(ids) { for (const r of reports) if (ids.includes(r.id)) r.stale_checked = true; },
  };
}

// ---------------- tiny WS client with a consuming waitFor ----------------
function makeClient(url) {
  const ws = new WebSocket(url);
  const all = [], queue = [], waiters = [];
  const pump = () => {
    for (const w of [...waiters]) {
      const i = queue.findIndex(w.pred);
      if (i >= 0) { const [m] = queue.splice(i, 1); waiters.splice(waiters.indexOf(w), 1); w.resolve(m); }
    }
  };
  ws.on("message", d => { const m = JSON.parse(d); all.push(m); queue.push(m); pump(); });
  return {
    ws, all,
    send: m => ws.send(JSON.stringify(m)),
    has: type => all.some(m => m.type === type),
    async open() { if (ws.readyState !== ws.OPEN) await once(ws, "open"); },
    close() { try { ws.close(); } catch {} },
    waitFor(pred, timeout = 4000) {
      const p = typeof pred === "string" ? (m => m.type === pred) : pred;
      const i = queue.findIndex(p);
      if (i >= 0) { const [m] = queue.splice(i, 1); return Promise.resolve(m); }
      return new Promise((resolve, reject) => {
        const w = { pred: p, resolve };
        waiters.push(w);
        setTimeout(() => { const j = waiters.indexOf(w); if (j >= 0) { waiters.splice(j, 1); reject(new Error("timeout waiting for " + (typeof pred === "string" ? pred : "predicate"))); } }, timeout);
      });
    },
  };
}

// ---------------- harness ----------------
let passed = 0;
const ok = name => { passed++; console.log("  ok -", name); };

async function main() {
  const db = makeMemDb();
  const { server, wss } = await startServer({ db, pool: null, port: 0 });
  if (!server.listening) await once(server, "listening");
  const url = "ws://127.0.0.1:" + server.address().port;

  const clients = [];
  async function connect() { const c = makeClient(url); await c.open(); clients.push(c); return c; }
  async function authGuest(c, name) { c.send({ type: "auth", name }); return c.waitFor("authed"); }
  async function authAccount(c, token) { c.send({ type: "auth", token }); return c.waitFor("authed"); }

  // pair `a` (sends find first, becomes the waiter) with `b`; returns b's `matched` (peers[0].id = a's conn)
  async function pair(a, b) {
    a.send({ type: "find" }); await a.waitFor("waiting");
    b.send({ type: "find" });
    const [, bm] = await Promise.all([a.waitFor("matched"), b.waitFor("matched")]);
    return bm;
  }
  // reporter R (fresh each round) reports persistent target T once; returns R's reportAck
  async function reportOnce(T, R, reason = "cheating", detail) {
    const bm = await pair(T, R);
    const targetConn = bm.peers[0].id;                 // the opponent (= T) connection id
    R.send({ type: "report", target: targetConn, reason, ...(detail ? { detail } : {}) });
    return R.waitFor("reportAck");
  }

  console.log("moderation WS protocol");

  // ---- T1: report handshake, dedup, persisted metadata ----
  {
    const T = await connect(), R = await connect();
    await authGuest(T, "victim1"); await authGuest(R, "reporter1");
    const bm = await pair(T, R);
    const targetConn = bm.peers[0].id;
    R.send({ type: "report", target: targetConn, reason: "cheating" });
    const ack1 = await R.waitFor("reportAck");
    assert.equal(ack1.ok, true); assert.ok(!ack1.already);
    R.send({ type: "report", target: targetConn, reason: "cheating" });   // same match -> dedup
    const ack2 = await R.waitFor("reportAck");
    assert.equal(ack2.ok, true); assert.equal(ack2.already, true);
    const rows = db._reports.filter(x => x.reason === "cheating");
    assert.equal(rows.length, 1, "dedup keeps exactly one row");
    const row = rows[0];
    assert.equal(row.reporter_guest, true);
    assert.equal(row.reported_guest, true);
    assert.equal(row.reporter_trusted, false);         // default trust 50 < 70
    assert.equal(typeof row.game_id, "string");
    T.close(); R.close();
    ok("report handshake + dedup + metadata snapshot persisted");
  }

  // ---- T2: "other" requires detail, sets needs_review, never auto-bans alone ----
  {
    const T = await connect(), R = await connect();
    await authGuest(T, "victim2"); await authGuest(R, "reporter2");
    const bm = await pair(T, R);
    const targetConn = bm.peers[0].id;
    R.send({ type: "report", target: targetConn, reason: "other" });      // no detail
    const bad = await R.waitFor("reportAck");
    assert.equal(bad.ok, false); assert.equal(bad.reason, "needdetail");
    R.send({ type: "report", target: targetConn, reason: "other", detail: "was very rude on cam" });
    const good = await R.waitFor("reportAck");
    assert.equal(good.ok, true);
    const row = db._reports.find(x => x.reason === "other");
    assert.equal(row.needs_review, true);
    assert.equal(await db.getActiveBan(row.reported_id), null, "'other' alone must not ban");
    T.close(); R.close();
    ok('"other" needs detail, flags needs_review, does not auto-ban');
  }

  // ---- T3: one reporter hammering across matches never bans the target ----
  {
    const T = await connect(), R = await connect();
    await authGuest(T, "victim3"); await authGuest(R, "spammer3");
    const Tid = db._users.find(u => u.name === "victim3").id;
    // 3 separate matches, same single reporter -> heat is ONE contribution, never crosses threshold
    let bm = await pair(T, R);
    for (let i = 0; i < 3; i++) {
      R.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      await R.waitFor("reportAck");
      if (i < 2) {                                     // requeue both into a fresh game (new game_id)
        T.send({ type: "next" }); R.send({ type: "next" });
        const [, rbm] = await Promise.all([T.waitFor("matched"), R.waitFor("matched")]);
        bm = rbm;
      }
    }
    assert.equal(await db.getActiveBan(Tid), null, "a lone reporter cannot manufacture a ban");
    assert.equal(db._reports.filter(x => x.reported_id === Tid).length, 3, "3 distinct-match reports recorded");
    T.close(); R.close();
    ok("single reporter across matches never bans (distinct-reporter rule)");
  }

  // ---- T4: distinct-reporter cluster bans an ACCOUNT at 1 day; a later cluster escalates to 1 week ----
  {
    const tokT = db.seedAccount("acctVictim");
    const Tid = db._users.find(u => u.name === "acctVictim").id;
    const T = await connect(); await authAccount(T, tokT);
    assert.equal(db._users.find(u => u.id === Tid).auth_id != null, true, "seeded target is an account");

    // three DISTINCT reporters, each their own match with T -> heat 3.0 == HEAT_AUTHED
    let bannedMsg = null;
    for (let i = 0; i < 3; i++) {
      const R = await connect(); await authGuest(R, "clusterR" + i);
      const bm = await pair(T, R);
      R.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      const ack = await R.waitFor("reportAck");
      assert.equal(ack.ok, true);
      if (i < 2) {
        // no ban yet; tear the match down so T is idle for the next distinct reporter
        R.send({ type: "next" }); R.close();
        await T.waitFor("partnerLeft");
      } else {
        bannedMsg = await T.waitFor("banned");         // 3rd distinct reporter tips it over
        await R.waitFor("partnerLeft");                // opponent sees the live game torn down
        R.close();
      }
    }
    assert.ok(bannedMsg, "account target got banned");
    assert.equal(bannedMsg.tier, "day", "first offense = 1 day");
    assert.equal(bannedMsg.guest, false);

    // escalation: clear the ban + age the old reports out of window, then a fresh distinct cluster
    db._clearBans(Tid);
    db._ageReports(5 * 24 * 3600e3);                   // > WINDOW_AUTHED so only the new cluster counts
    let banned2 = null;
    for (let i = 0; i < 3; i++) {
      const R = await connect(); await authGuest(R, "cluster2R" + i);
      const bm = await pair(T, R);
      R.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      await R.waitFor("reportAck");
      if (i < 2) { R.send({ type: "next" }); R.close(); await T.waitFor("partnerLeft"); }
      else { banned2 = await T.waitFor("banned"); await R.waitFor("partnerLeft"); R.close(); }
    }
    assert.equal(banned2.tier, "week", "second offense escalates to 1 week");
    T.close();
    ok("distinct cluster bans account at day; second cluster escalates to week");
  }

  // ---- T5: guest banned at a lower bar than an account at the same report count ----
  {
    // guest target: 2 distinct reporters (heat 2.0 == HEAT_GUEST) -> banned
    const Tg = await connect(); await authGuest(Tg, "guestVictim");
    let gBan = null;
    for (let i = 0; i < 2; i++) {
      const R = await connect(); await authGuest(R, "gR" + i);
      const bm = await pair(Tg, R);
      R.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      await R.waitFor("reportAck");
      if (i < 1) { R.send({ type: "next" }); R.close(); await Tg.waitFor("partnerLeft"); }
      else { gBan = await Tg.waitFor("banned"); await R.waitFor("partnerLeft"); R.close(); }
    }
    assert.equal(gBan.tier, "day"); assert.equal(gBan.guest, true);
    Tg.close();

    // account target: same 2-distinct-reporter count -> below HEAT_AUTHED(3.0) -> NOT banned
    const tokTa = db.seedAccount("acctSafe");
    const Taid = db._users.find(u => u.name === "acctSafe").id;
    const Ta = await connect(); await authAccount(Ta, tokTa);
    for (let i = 0; i < 2; i++) {
      const R = await connect(); await authGuest(R, "aR" + i);
      const bm = await pair(Ta, R);
      R.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      await R.waitFor("reportAck");                    // ack is sent AFTER the ban decision runs
      R.send({ type: "next" }); R.close();
      if (i < 1) await Ta.waitFor("partnerLeft");
    }
    assert.equal(await db.getActiveBan(Taid), null, "account not banned at the guest count");
    assert.equal(Ta.has("banned"), false);
    Ta.close();
    ok("guest bans at lower threshold; account at same count is not banned");
  }

  // ---- T6: a banned user cannot matchmake (auth + find both refuse with `banned`) ----
  {
    // reuse acctVictim from T4 (still banned: week). Reconnect fresh.
    const tokT = db._users.find(u => u.name === "acctVictim").token;
    const T = await connect();
    T.send({ type: "auth", token: tokT });
    await T.waitFor("authed");
    const onAuth = await T.waitFor("banned");           // banned screen appears on first load
    assert.equal(onAuth.tier, "week");
    T.send({ type: "find" });
    const onFind = await T.waitFor("banned");            // and find is refused
    assert.ok(onFind);
    assert.equal(T.has("waiting"), false, "banned user never enters the queue");
    T.close();
    ok("banned user is refused at auth and at find");
  }

  // ---- T7: spam — the excess report is rejected and the reporter's trust drops ----
  {
    const Rs = await connect(); await authGuest(Rs, "trigger-happy");
    const Rsid = db._users.find(u => u.name === "trigger-happy").id;
    // report 5 DISTINCT targets (each its own match) -> all accepted
    for (let i = 0; i < 5; i++) {
      const V = await connect(); await authGuest(V, "spamV" + i);
      const bm = await pair(V, Rs);                     // V waits, Rs joins -> Rs sees peers[0]=V
      Rs.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
      const ack = await Rs.waitFor("reportAck");
      assert.equal(ack.ok, true);
      Rs.send({ type: "next" }); V.close();
      await Rs.waitFor(m => m.type === "partnerLeft" || m.type === "waiting").catch(() => {});
      if (Rs.has("waiting")) { Rs.send({ type: "cancelSearch" }); await Rs.waitFor("searchCanceled"); }
    }
    // 6th within the window -> rejected as rate + trust penalty
    const V = await connect(); await authGuest(V, "spamV5");
    const bm = await pair(V, Rs);
    Rs.send({ type: "report", target: bm.peers[0].id, reason: "cheating" });
    const rej = await Rs.waitFor("reportAck");
    assert.equal(rej.ok, false); assert.equal(rej.reason, "rate");
    assert.ok(db._users.find(u => u.id === Rsid).trust_score < TRUST_DEFAULT, "spammer trust dropped");
    Rs.close(); V.close();
    ok("spam excess rejected + reporter trust drops; distinct targets never cluster-ban");
  }

  // ---- sanity: HEAT_AUTHED is the value the cluster test relied on ----
  assert.equal(HEAT_AUTHED, 3.0);

  for (const c of clients) c.close();
  wss.close(); server.close();
  console.log(`\nAll ${passed} moderation WS protocol tests passed.`);
}

main().then(() => process.exit(0)).catch(e => { console.error("\nFAILED:", e && e.stack || e); process.exit(1); });
