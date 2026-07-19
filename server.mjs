import express from "express";
import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { WebSocketServer } from "ws";
import pg from "pg";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { makeDb } from "./db.mjs";
import {
  decideBan, banExpiry, trustDelta, overReporting, moderateText, heatOf, TIERS,
  TRUSTED_THRESHOLD, SPAM_LIMIT, SPAM_WINDOW, CORROB_WINDOW, WINDOW_AUTHED, WINDOW_GUEST,
  CHAT_DUP_WINDOW, CHAT_MUTE_STRIKES, CHAT_MUTE_MS,
} from "./moderation.mjs";
import { validateMessage, cleanText, NAME_MAX } from "./validate.mjs";
import { makeLimiter } from "./ratelimit.mjs";
import { clientIp, allowedOrigins, isOriginAllowed, cspDirectives, RATE } from "./security.mjs";
import { iceFromEnv, cloudflareIce } from "./ice.mjs";
import { initSentry, captureError } from "./instrument.mjs";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;   // trailing window for the over-report rate

// ToS/Privacy version the user consents to. Bump when the legal terms change to force re-consent.
export const TOS_VERSION = process.env.TOS_VERSION || "2026-07-08";

// ---- structured security logging (one line, no secrets/PII; IPs are hashed, never raw) ----
const MOD_IP_SALT = process.env.MOD_IP_SALT || "";
const hashIp = ip => ip ? crypto.createHash("sha256").update(MOD_IP_SALT + "|" + ip).digest("hex").slice(0, 16) : null;
function logSec(event, fields = {}) {
  const safe = { ...fields };
  if (safe.ip) { safe.iph = hashIp(safe.ip); delete safe.ip; }   // never log a raw IP
  try { console.log("sec " + event + " " + JSON.stringify(safe)); } catch { console.log("sec " + event); }
}

const WS_MAX_PAYLOAD   = 64 * 1024;                              // drop oversized WS frames
const HEARTBEAT_MS     = 30 * 1000;                             // ping idle sockets; drop the dead

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, "public");
const PORT = +process.env.PORT || 3000;
const SEC = 1000;
const dur = {
  intro:     (+process.env.T_INTRO     || 5)  * SEC,   // VS screen + player-card reveal before the countdown
  countdown: (+process.env.T_COUNTDOWN || 5)  * SEC,
  round:     (+process.env.T_ROUND     || 30) * SEC,
  swap:      (+process.env.T_SWAP      || 3)  * SEC,
  result:    (+process.env.T_RESULT    || 8)  * SEC,
};

// startServer takes an injected db so the whole stack (HTTP + WS) is testable
// against an in-memory database without a real Postgres.
export async function startServer({ db, pool = null, port = PORT }) {
  // ---------- HTTP: static files, pretty page routes, a small JSON API ----------
  const app = express();
  const production = process.env.NODE_ENV === "production";
  const MAX_CONNS_PER_IP = +process.env.WS_MAX_CONNS_PER_IP || 20;   // concurrent sockets per IP (read at boot)

  // Lightweight launch counters (logged/inspected via /api/admin/stats; a metrics backend can come later).
  const stats = { matchesStarted: 0, rtcConnected: 0, rtcFailed: 0, bansIssued: 0, rateLimitTrips: 0, startedAt: Date.now() };

  // Health check for an uptime monitor / load balancer. Registered BEFORE the rate limiter and
  // hardening so it is never rate-limited. Cheap, unauthenticated, leaks nothing: 200 when the
  // process is up and the DB answers a fast `SELECT 1`, 503 if the DB check fails. No pool (guest/
  // test mode) => just report process liveness.
  app.get("/healthz", async (_req, res) => {
    if (!pool) return res.status(200).json({ ok: true });
    try {
      await Promise.race([
        pool.query("SELECT 1"),
        new Promise((_, rej) => setTimeout(() => rej(new Error("db timeout")), 2000)),
      ]);
      res.status(200).json({ ok: true });
    } catch { res.status(503).json({ ok: false }); }
  });

  // ---------- HTTP hardening: proxy, https, headers, rate limits (see security.mjs) ----------
  // Behind Cloudflare, trust a bounded number of proxy hops so req.ip / req.protocol reflect the
  // edge, not the socket. Default 1 (Cloudflare); raise TRUST_PROXY_HOPS if there are more.
  app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 1));
  app.disable("x-powered-by");

  if (production) {                         // force https at the app layer (Cloudflare does it too)
    app.use((req, res, next) => {
      if (req.secure || req.headers["x-forwarded-proto"] === "https") return next();
      res.redirect(308, "https://" + req.headers.host + req.originalUrl);
    });
  }

  app.use(helmet({
    contentSecurityPolicy: { useDefaults: false, directives: cspDirectives({ production }) },
    crossOriginEmbedderPolicy: false,       // MediaPipe loads cross-origin wasm/workers; COEP would block it
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    hsts: production ? { maxAge: 15552000, includeSubDomains: true, preload: true } : false,
  }));
  app.use((_req, res, next) => {            // camera/mic only for us; deny geolocation etc.
    res.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=(), browsing-topics=()");
    res.setHeader("X-Frame-Options", "DENY");   // belt-and-suspenders with CSP frame-ancestors 'none'
    next();
  });

  // Per-IP HTTP rate limiting, keyed off the real client IP (Cloudflare-aware). Strict on auth
  // (brute force / credential stuffing), looser on reads, a general backstop on everything else.
  const mkLimit = (cfg) => rateLimit({
    windowMs: cfg.windowMs, max: cfg.max, standardHeaders: true, legacyHeaders: false,
    validate: false, keyGenerator: clientIp,
    handler: (req, res) => { stats.rateLimitTrips++; logSec("http_rate_limited", { ip: clientIp(req), path: req.path }); res.status(429).json({ error: "rate_limited" }); },
  });
  app.use(mkLimit(RATE.general));
  app.use("/api/auth", mkLimit(RATE.auth));
  app.use("/api/me", mkLimit(RATE.read));
  app.use("/api/leaderboard", mkLimit(RATE.read));

  // ---------- optional real accounts (better-auth) ----------
  // Auth is wired ONLY when a secret + a pg pool are available. Absent either, the server
  // runs exactly as before (guests + anonymous tokens), so nothing external is needed to boot.
  let auth = null, fromHeaders = null;
  if (process.env.BETTER_AUTH_SECRET && pool) {
    const [{ makeAuth }, nodeHandler, { getMigrations }] = await Promise.all([
      import("./auth.mjs"),
      import("better-auth/node"),
      import("better-auth/db/migration"),   // 1.6.x path; on <1.5 it was "better-auth/db"
    ]);
    auth = makeAuth(pool);
    fromHeaders = nodeHandler.fromNodeHeaders;
    // Ensure better-auth's own tables (user/session/account/verification) exist. This replaces the
    // manual `npx @better-auth/cli migrate` step: Railway (and any host) only runs `npm start`, so
    // we apply any missing tables/columns programmatically on boot. Idempotent — a no-op once the
    // schema is current — and transactional inside runMigrations().
    try {
      const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(auth.options);
      if (toBeCreated.length || toBeAdded.length) {
        await runMigrations();
        console.log("auth: better-auth schema migrated (%d table(s) created, %d altered)",
          toBeCreated.length, toBeAdded.length);
      } else {
        console.log("auth: better-auth schema up to date");
      }
    } catch (e) {
      // Don't take the whole server down over auth-schema issues — guests, /healthz and the game
      // stay up; auth endpoints will surface the error. Loud in logs + Sentry so it isn't missed.
      logSec("auth_migrate_failed", { msg: e && e.message });
      captureError(e, { where: "auth_migrate" });
    }
    // better-auth reads the raw request body itself; mount before any json parser (there are none).
    app.all("/api/auth/{*any}", nodeHandler.toNodeHandler(auth));
    console.log("auth: better-auth mounted (email/password)");
  } else {
    console.log("auth: disabled — guest/token only (set BETTER_AUTH_SECRET + DATABASE_URL to enable)");
  }

  // A signalling value for "authenticated, but this brand-new account still needs to pick
  // a screenname" — the client answers by re-sending auth with a name (the name gate).
  const NEED_NAME = Symbol("needName");

  const isUniqueViolation = e => !!e && (e.code === "23505" || /unique|duplicate/i.test(e.message || ""));

  // Up to 3 available, moderation-clean alternatives for a taken name (base + a small number).
  async function suggestNames(base) {
    const root = base.replace(/\d+$/, "").slice(0, 16) || "player";
    const out = [];
    for (let n = 2; out.length < 3 && n < 60; n++) {
      const cand = root + n;
      if (moderateText(cand, { context: "username" }).ok && !(await db.isNameTaken(cand))) out.push(cand);
    }
    return out;
  }

  // Create a user with a NEW display name: moderate it, enforce case-insensitive uniqueness, and
  // survive the signup race (catch the UNIQUE violation). Returns the user row, or a rejection
  // { rejected, reason, suggestions } the caller turns into a `nameError` for the client.
  async function createNamedUser({ authId = null, name }) {
    const verdict = moderateText(name, { context: "username" });
    if (!verdict.ok) {
      if (verdict.rule) db.logModeration({ userId: null, context: "username", rule: verdict.rule });
      return { rejected: true, reason: verdict.reason, suggestions: [] };
    }
    const cleaned = verdict.cleaned;
    if (await db.isNameTaken(cleaned)) return { rejected: true, reason: "taken", suggestions: await suggestNames(cleaned) };
    try {
      return authId ? await db.createAuthedUser({ authId, name: cleaned }) : await db.createGuestUser({ name: cleaned });
    } catch (e) {
      if (isUniqueViolation(e)) return { rejected: true, reason: "taken", suggestions: await suggestNames(cleaned) };
      throw e;
    }
  }

  // Map a request to its game `users` row. A valid session cookie (a real account) always
  // wins and any client-supplied token is ignored (can't impersonate an account). With no
  // session we fall back to the guest token. A NEW name (guest create or first account login)
  // is moderated + uniqueness-checked here; a returning user keeps their existing name.
  async function resolveGameUser({ headers, guestToken, name }) {
    if (auth) {
      try {
        const session = await auth.api.getSession({ headers: fromHeaders(headers) });
        if (session?.user) {
          const existing = await db.getUserByAuthId(session.user.id);
          if (existing) return existing;
          if (!cleanText(name, NAME_MAX)) return NEED_NAME;      // first login: prompt for a screenname
          return await createNamedUser({ authId: session.user.id, name });
        }
      } catch (e) { console.error("session resolve failed:", e.message); }
    }
    if (guestToken) {                                            // returning guest keeps their row + name
      const existing = await db.getUserByToken(guestToken);
      if (existing) return existing;
    }
    if (!cleanText(name, NAME_MAX)) return NEED_NAME;            // new guest must pick a name at the gate
    return await createNamedUser({ name });
  }

  // Body cap: mounted AFTER the better-auth handler (which reads its own raw body). Oversized or
  // malformed JSON bodies are rejected here (413) rather than buffered. Our own routes are GET-only.
  app.use(express.json({ limit: "16kb" }));

  // no-cache = "revalidate every time", NOT "don't cache": unchanged files still answer 304.
  // Without an explicit Cache-Control, browsers heuristically cache css/js/html off Last-Modified
  // and can serve stale assets for hours after a deploy (fresh profiles get new files, returning
  // ones keep old — which looks like a per-user bug, e.g. a theme toggle with no CSS behind it).
  app.use(express.static(PUBLIC, {                         // landing, css, js, *.html
    setHeaders: res => res.setHeader("Cache-Control", "no-cache"),
  }));
  const page = f => (_req, res) =>
    res.sendFile(path.join(PUBLIC, f), { headers: { "Cache-Control": "no-cache" } });
  app.get("/login",  page("login.html"));
  app.get("/play",   page("play.html"));
  app.get("/ranked", page("ranked.html"));
  app.get("/terms",  page("terms.html"));
  app.get("/privacy", page("privacy.html"));
  app.get("/about",  page("about.html"));
  app.get("/agree",  page("agree.html"));    // consent step 1: read + agree to Terms/Privacy
  app.get("/age",    page("age.html"));       // consent step 2: 18+ / peer-to-peer risk warning
  app.get("/api/leaderboard", async (_req, res) => {       // request/response data -> HTTP, not WS
    try { res.json(await db.topPlayers(10)); }
    catch { res.status(500).json({ error: "unavailable" }); }
  });
  // Global presence: just the aggregate count of players online right now (no ids, no names).
  app.get("/api/online", mkLimit(RATE.read), (_req, res) => res.json({ online: online.size }));

  // WebRTC ICE config (STUN always; TURN when configured). Credentials are short-lived, so we cache
  // one shared set server-side until just before expiry rather than minting per request. Cloudflare
  // Realtime TURN is preferred (network mint); then coturn/static from env; else STUN-only for dev.
  let iceCache = null;   // { config, expiresAt }
  async function getIce() {
    const now = Date.now();
    if (iceCache && now < iceCache.expiresAt) return iceCache.config;
    const ttl = Math.max(60, +process.env.TURN_TTL || 3600);
    try {
      const cf = await cloudflareIce(process.env, { ttl });   // null when Cloudflare env absent
      if (cf) { iceCache = { config: cf.config, expiresAt: now + Math.max(30, cf.ttl - 300) * 1000 }; return cf.config; }
    } catch (e) { logSec("ice_cloudflare_failed", { msg: e.message }); }
    const { config, ttl: envTtl } = iceFromEnv(process.env, { now });   // coturn/static/STUN (no network)
    iceCache = { config, expiresAt: now + Math.min(300, Math.max(30, envTtl - 60)) * 1000 };
    return config;
  }
  app.get("/api/ice", mkLimit(RATE.read), async (_req, res) => {
    try { res.json(await getIce()); }
    catch { res.json(iceFromEnv(process.env).config); }    // last-resort STUN/static, never 500
  });
  app.get("/api/me", async (req, res) => {                  // the signed-in player's profile + history
    try {
      let user = null;
      if (auth) {                                           // session cookie identifies a real account
        const session = await auth.api.getSession({ headers: fromHeaders(req.headers) });
        if (session?.user) user = await db.getUserByAuthId(session.user.id);
      }
      if (!user) {                                          // guest fallback: the anonymous token
        const token = req.get("x-token");
        if (token) user = await db.getUserByToken(token);
      }
      if (!user) return res.status(401).json({ error: "no session" });
      const matches = await db.recentMatches(user.id, 10);
      res.json({
        profile: { name: user.name, rating: user.rating, wins: user.wins, losses: user.losses, draws: user.draws, games: user.games },
        matches,
      });
    } catch { res.status(500).json({ error: "unavailable" }); }
  });

  // Consent capture (18+ & ToS/Privacy) — the legal paper trail. Records age_confirmed_at +
  // tos_version_accepted on the user's row (server-authoritative). Matchmaking is hard-gated on this
  // record server-side (see requireConsent), so it cannot be bypassed by a raw WebSocket.
  app.post("/api/consent", async (req, res) => {
    if (req.body?.agree !== true) return res.status(400).json({ error: "must_agree" });
    try {
      const { user } = await resolveRequester(req);       // session (account) or guest token
      if (!user) return res.status(401).json({ error: "no_user" });
      const rec = await db.setConsent(user.id, TOS_VERSION);
      logSec("consent", { user: user.id, tos: TOS_VERSION });
      res.json({ ok: true, tosVersion: rec?.tos_version_accepted || TOS_VERSION });
    } catch (e) { logSec("consent_failed", { msg: e.message }); res.status(500).json({ error: "unavailable" }); }
  });

  // ---------- moderation admin (minimal, access-controlled; §7) ----------
  // Admins are identified SERVER-SIDE only: a session email in ADMIN_EMAILS (recommended) or the
  // resolved game-user id in ADMIN_USER_IDS. Never a client flag. If neither env is set there are no
  // admins and every /api/admin/* + /admin returns 403 (fail closed). Actions reuse the existing
  // issueBan/enforceBan path — there is no second ban path.
  const adminEmails = () => (process.env.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const adminIds    = () => (process.env.ADMIN_USER_IDS || "").split(",").map(s => s.trim()).filter(Boolean);
  const posInt = v => (Number.isInteger(+v) && +v > 0 ? +v : null);

  // Resolve the requester like /api/me: session (account) first, then guest token. Both are
  // server-verified credentials; a client can't self-declare admin.
  async function resolveRequester(req) {
    if (auth) {
      try { const s = await auth.api.getSession({ headers: fromHeaders(req.headers) });
            if (s?.user) return { session: s, user: await db.getUserByAuthId(s.user.id) }; } catch {}
    }
    const token = req.get("x-token");
    if (token) { const u = await db.getUserByToken(token); if (u) return { session: null, user: u }; }
    return { session: null, user: null };
  }
  function isAdmin({ session, user }) {
    const email = session?.user?.email && String(session.user.email).toLowerCase();
    if (email && adminEmails().includes(email)) return true;
    if (user && adminIds().includes(String(user.id))) return true;
    return false;
  }
  async function requireAdmin(req, res, next) {
    let who; try { who = await resolveRequester(req); } catch { who = { session: null, user: null }; }
    if (!isAdmin(who)) { logSec("admin_denied", { ip: clientIp(req), path: req.path }); return res.status(403).json({ error: "forbidden" }); }
    req.admin = who; next();
  }
  const adminActor = req => (req.admin?.user?.id ?? req.admin?.session?.user?.id ?? "?");

  // Gated admin page (kept OUT of /public so express.static can never serve it ungated).
  app.get("/admin", requireAdmin, (_req, res) => res.sendFile(path.join(__dirname, "admin.html")));

  app.get("/api/admin/reports", requireAdmin, async (req, res) => {
    try {
      const status = req.query.status === "reviewed" ? "reviewed" : "open";
      const rows = await db.listReports({ status, limit: +req.query.limit || 50 });
      const seen = new Map();                                  // annotate each distinct target once
      for (const r of rows) {
        const key = String(r.reported_id);
        if (!seen.has(key)) {
          const window = r.reported_guest ? WINDOW_GUEST : WINDOW_AUTHED;
          const cluster = (await db.getReportCluster(r.reported_id, new Date(Date.now() - window)))
            .map(x => ({ reporterId: x.reporter_id, trust: x.reporter_trust, guest: x.reporter_guest, reason: x.reason }));
          const ban = await db.getActiveBan(r.reported_id);
          seen.set(key, { heat: Math.round(heatOf(cluster) * 100) / 100, active_ban: ban ? { tier: ban.tier, expires_at: ban.expires_at } : null });
        }
        Object.assign(r, seen.get(key));
      }
      res.json({ reports: rows });
    } catch (e) { logSec("admin_reports_failed", { msg: e.message }); res.status(500).json({ error: "unavailable" }); }
  });

  app.get("/api/admin/mod-events", requireAdmin, async (req, res) => {
    try { res.json({ events: await db.listModEvents({ limit: +req.query.limit || 50 }) }); }
    catch { res.status(500).json({ error: "unavailable" }); }
  });

  app.get("/api/admin/active-bans", requireAdmin, async (_req, res) => {
    try { res.json({ bans: await db.listActiveBans(100) }); }
    catch { res.status(500).json({ error: "unavailable" }); }
  });

  // At-a-glance launch stats (admin-only). Counters are since process start; live figures are current.
  app.get("/api/admin/stats", requireAdmin, (_req, res) => {
    const rtcTotal = stats.rtcConnected + stats.rtcFailed;
    res.json({
      uptimeSec: Math.round((Date.now() - stats.startedAt) / 1000),
      online: online.size, liveSockets: clients.size, inQueue: (waiting !== null ? 1 : 0) + (duosWaiting !== null ? 2 : 0),
      matchesStarted: stats.matchesStarted, bansIssued: stats.bansIssued, rateLimitTrips: stats.rateLimitTrips,
      rtcConnected: stats.rtcConnected, rtcFailed: stats.rtcFailed,
      rtcFailRate: rtcTotal ? Math.round((stats.rtcFailed / rtcTotal) * 100) / 100 : 0,
      sentry: !!process.env.SENTRY_DSN,
    });
  });

  app.get("/api/admin/user/:id", requireAdmin, async (req, res) => {
    const id = posInt(req.params.id);
    if (!id) return res.status(400).json({ error: "bad_id" });
    try {
      const u = await db.getUserById(id);
      if (!u) return res.status(404).json({ error: "not_found" });
      const [bans, against, by, ban] = await Promise.all([db.listBans(id), db.reportsAgainst(id), db.reportsBy(id), db.getActiveBan(id)]);
      res.json({
        user: { id: u.id, name: u.name, guest: u.auth_id == null, trust: u.trust_score, rating: u.rating, games: u.games },
        active_ban: ban ? { tier: ban.tier, reason: ban.reason, expires_at: ban.expires_at } : null,
        bans, reports_against: against, reports_by: by,
      });
    } catch (e) { logSec("admin_user_failed", { msg: e.message }); res.status(500).json({ error: "unavailable" }); }
  });

  // Ban: accepts a tier ('day'|'week'|'month'|'year') OR durationHours. Reuses issueBan + enforceBan.
  app.post("/api/admin/ban", requireAdmin, async (req, res) => {
    const userId = posInt(req.body?.userId);
    const reason = cleanText(req.body?.reason, 200) || "admin action";
    const hours = req.body?.durationHours != null ? +req.body.durationHours : null;
    const tier = typeof req.body?.tier === "string" ? req.body.tier : null;
    if (!userId) return res.status(400).json({ error: "bad_user" });
    let tierLabel, expiresAt;
    if (hours != null) {
      if (!(hours > 0 && hours <= 24 * 366)) return res.status(400).json({ error: "bad_duration" });
      tierLabel = hours + "h"; expiresAt = new Date(Date.now() + hours * 3600 * 1000);
    } else if (tier && TIERS.includes(tier)) {
      tierLabel = tier; expiresAt = banExpiry(tier);
    } else return res.status(400).json({ error: "bad_tier" });
    try {
      const target = await db.getUserById(userId);
      if (!target) return res.status(404).json({ error: "not_found" });
      const ban = await db.issueBan({ userId, tier: tierLabel, reason, isGuest: target.auth_id == null, expiresAt });
      stats.bansIssued++;
      enforceBan(userId, ban);                                 // if live: tears the game down + sends `banned`
      logSec("admin_ban", { by: adminActor(req), target: userId, tier: tierLabel });
      res.json({ ok: true, ban: { tier: tierLabel, expires_at: expiresAt } });
    } catch (e) { logSec("admin_ban_failed", { msg: e.message }); res.status(500).json({ error: "unavailable" }); }
  });

  app.post("/api/admin/unban", requireAdmin, async (req, res) => {
    const userId = posInt(req.body?.userId);
    if (!userId) return res.status(400).json({ error: "bad_user" });
    try {
      const cleared = await db.clearActiveBans(userId);
      logSec("admin_unban", { by: adminActor(req), target: userId, cleared });
      res.json({ ok: true, cleared });
    } catch { res.status(500).json({ error: "unavailable" }); }
  });

  app.post("/api/admin/clear-report", requireAdmin, async (req, res) => {
    const reportId = posInt(req.body?.reportId);
    if (!reportId) return res.status(400).json({ error: "bad_report" });
    try {
      const ok = await db.clearReport(reportId);
      logSec("admin_clear_report", { by: adminActor(req), report: reportId });
      res.json({ ok });
    } catch { res.status(500).json({ error: "unavailable" }); }
  });

  // Generic error handler: log the detail server-side, return no stack/internal detail to the
  // client. 413 = body over the cap; everything else is an opaque 500.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err && (err.status || err.statusCode) === 413 ? 413 : 500;
    logSec("http_error", { status, msg: err && err.message });
    if (status >= 500) captureError(err, { where: "http", path: req.path });   // report 5xx (no PII)
    res.status(status).json({ error: status === 413 ? "too_large" : "server_error" });
  });

  // ---------- one HTTP server; the WebSocket shares it (upgrade on the same port) ----------
  const server = http.createServer(app);
  // maxPayload drops oversized WS frames before they buffer. verifyClient enforces the Origin
  // allowlist on the upgrade (browsers always send Origin — this blocks cross-site WS hijacking;
  // a missing Origin is a non-browser client, which can't mount that attack and still must auth).
  const originSet = allowedOrigins();
  const enforceOrigin = originSet.size > 0;
  if (!enforceOrigin) console.warn("ws: origin allowlist empty — set ALLOWED_ORIGINS or BETTER_AUTH_URL to enforce (dev only)");
  const wss = new WebSocketServer({
    server,
    maxPayload: WS_MAX_PAYLOAD,
    verifyClient: ({ origin, req }, done) => {
      if (enforceOrigin && origin && !isOriginAllowed(origin, originSet)) {
        logSec("ws_origin_rejected", { ip: clientIp(req), origin });
        return done(false, 403, "forbidden origin");
      }
      done(true);
    },
  });

  // Heartbeat: ping every socket on an interval; a socket that missed the last pong is dead
  // (half-open TCP, dropped client) and gets terminated so it can't leak memory/state.
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }, HEARTBEAT_MS);
  heartbeat.unref?.();
  wss.on("close", () => clearInterval(heartbeat));

  // ===================== game (per-server state) =====================
  const clients = new Map();   // id -> { ws, state, partner, game, userId, name, rating }
  const connsByIp = new Map(); // ipKey -> live connection count (in-memory; caps sockets per IP)
  let waiting = null, nextId = 1, nextGameId = 1;

  // presence + duo lobbies (all in-memory; identity lives in the DB, liveness lives here)
  const online = new Map();      // userId(str) -> connId  (latest connection wins)
  const lobbies = new Map();     // lobbyId -> { id, members:[userId,...], leader }
  const userLobby = new Map();   // userId(str) -> lobbyId
  let duosWaiting = null, nextLobby = 1;
  const connOfUser = uid => clients.get(online.get(String(uid)));

  const send = (id, msg) => { const c = clients.get(id); if (c && c.ws.readyState === c.ws.OPEN) c.ws.send(JSON.stringify(msg)); };
  const teamOf = (game, id) => game.teams.findIndex(team => team.includes(id));
  const otherTeamOf = (game, id) => 1 - teamOf(game, id);
  const scoreView = (game, id) => {
    const mine = teamOf(game, id);
    const theirs = 1 - mine;
    return { you: game.scores[mine], them: game.scores[theirs] };
  };

  // Consent hard-gate: a socket must have a server-logged 18+/ToS consent (age_confirmed_at) before it
  // can enter the camera/matchmaking path. No consent -> tell the client and KILL the socket instantly,
  // so raw WebSocket manipulation can't bypass the /login gate. Returns true if it blocked (+closed).
  function requireConsent(id) {
    const c = clients.get(id);
    if (!c) return true;
    if (c.consented) return false;
    logSec("consent_block", { user: c.userId });
    send(id, { type: "consentRequired" });
    try { c.ws.close(1008, "consent required"); } catch {}
    return true;
  }

  async function findMatch(id) {
    const c = clients.get(id);
    if (!c || !c.userId || c.state !== "idle") return;
    if (requireConsent(id)) return;                          // 18+/ToS consent required to matchmake
    if (await isBanned(c.userId, id)) return;                 // banned users can't queue (belt-and-suspenders)
    if (waiting !== null && waiting !== id && clients.get(waiting)?.state === "waiting") {
      const partnerId = waiting; waiting = null; await pair(id, partnerId);
    } else { c.state = "waiting"; waiting = id; send(id, { type: "waiting" }); }
  }
  function cancelSearch(id) {
    const c = clients.get(id);
    if (!c || c.state !== "waiting") return;
    if (waiting === id) waiting = null;
    c.state = "idle";
    send(id, { type: "searchCanceled" });
  }
  async function playerCard(id) {
    const c = clients.get(id);
    let form = [];
    if (c?.userId) {
      try { form = (await db.recentMatches(c.userId, 5)).map(m => m.outcome); }
      catch (e) { console.error("recentMatches (card) failed:", e.message); }
    }
    return { id, name: c?.name || "?", rating: c?.rating || 1000, form };
  }

  async function pair(a, b) {
    const ca = clients.get(a), cb = clients.get(b);
    ca.partner = b; ca.state = "paired"; cb.partner = a; cb.state = "paired";
    const game = {
      id: nextGameId++,
      mode: "solo",
      players: [a, b],
      teams: [[a], [b]],
      scores: [0, 0],
      performerTeam: null,
      watcherTeam: null,
      phase: null,
      timer: null,
    };
    ca.game = game; cb.game = game;
    await announceMatch(game);
    startIntro(game);
  }

  function setPhase(game, phase, ms, next) { clearTimeout(game.timer); game.phase = phase; game.timer = setTimeout(() => next(game), ms); }
  function setRoles(game, teamIdx) { game.performerTeam = teamIdx; game.watcherTeam = 1 - teamIdx; }
  function broadcast(game, phase, seconds) {
    for (const id of game.players)
      send(id, { type: "gameState", phase, seconds,
        role: teamOf(game, id) === game.performerTeam ? "performer" : teamOf(game, id) === game.watcherTeam ? "watcher" : null,
        scores: scoreView(game, id) });
  }
  function broadcastScores(game) {
    for (const id of game.players)
      send(id, { type: "score", scores: scoreView(game, id) });
  }
  // Match opener: a client-rendered VS screen + player-card reveal (intro), then the countdown.
  function startIntro(game)     { stats.matchesStarted++; setRoles(game, 0); setPhase(game, "intro", dur.intro, startCountdown); broadcast(game, "intro", dur.intro / SEC); }
  function startCountdown(game) {                    setRoles(game, 0); setPhase(game, "countdown", dur.countdown, startRound1); broadcast(game, "countdown", dur.countdown / SEC); }
  function startRound1(game)    { setRoles(game, 0); setPhase(game, "round1",    dur.round,     startSwap);   broadcast(game, "round1",    dur.round / SEC); }
  function startSwap(game)      {                    setPhase(game, "swap",      dur.swap,      startRound2); broadcast(game, "swap",      dur.swap / SEC); }
  function startRound2(game)    { setRoles(game, 1); setPhase(game, "round2",    dur.round,     endGame);     broadcast(game, "round2",    dur.round / SEC); }

  async function endGame(game) {
    setPhase(game, "result", dur.result, resetGame);
    for (const id of game.players) {
      const mine = game.scores[teamOf(game, id)], theirs = game.scores[otherTeamOf(game, id)];
      send(id, { type: "gameState", phase: "result", seconds: dur.result / SEC, role: null,
        scores: { you: mine, them: theirs }, outcome: mine > theirs ? "win" : mine < theirs ? "lose" : "draw" });
    }
    if (game.mode === "solo") {
      const c0 = clients.get(game.teams[0][0]), c1 = clients.get(game.teams[1][0]);
      if (c0?.userId && c1?.userId) {
        try {
          const res = await db.recordMatch(c0.userId, c1.userId, game.scores[0], game.scores[1]);
          c0.rating = res.a.after; c1.rating = res.b.after;
          send(game.teams[0][0], { type: "ranked", delta: res.a.delta, rating: res.a.after });
          send(game.teams[1][0], { type: "ranked", delta: res.b.delta, rating: res.b.after });
        } catch (e) { console.error("recordMatch failed:", e.message); }
      }
    } else if (game.mode === "duos") {
      const idsOf = team => team.map(cid => clients.get(cid)?.userId).filter(u => u != null);
      const teamA = idsOf(game.teams[0]), teamB = idsOf(game.teams[1]);
      if (teamA.length === 2 && teamB.length === 2) {
        try {
          const res = await db.recordDuosRatings(teamA, teamB, game.scores[0], game.scores[1]);
          for (const id of game.players) {               // each player gets their own delta
            const c = clients.get(id);
            const r = c?.userId != null ? res[String(c.userId)] : null;
            if (r) { c.rating = r.after; send(id, { type: "ranked", delta: r.delta, rating: r.after }); }
          }
        } catch (e) { console.error("recordDuosRatings failed:", e.message); }
      }
    }
  }
  function resetGame(game) {
    for (const id of game.players) {
      const c = clients.get(id);
      if (c) { c.state = "idle"; c.partner = null; c.game = null; }
      send(id, { type: "gameReset" });
    }
  }

  function handleReaction(id, msg) {
    const game = clients.get(id)?.game;
    if (!game || (game.phase !== "round1" && game.phase !== "round2")) return;
    if (teamOf(game, id) !== game.watcherTeam) return;                  // only watchers react
    const delta = Math.max(0, Math.min(50, +msg.delta || 0));
    const tier = msg.tier === "laugh" ? "laugh" : msg.tier === "big" ? "big" : "small";
    game.scores[game.performerTeam] += delta;       // the number: continuous + authoritative
    broadcastScores(game);                       // meters, to both players
    for (const performer of game.teams[game.performerTeam]) send(performer, { type: "reaction", tier, delta });
  }

  // Who can hear a chat message: everyone in the sender's live game, or — before a game
  // exists — their duo lobby mates. Returns connection ids (including the sender's own).
  function chatPeers(id) {
    const c = clients.get(id);
    if (!c) return [];
    if (c.game) return c.game.players;
    const lid = c.userId != null ? userLobby.get(String(c.userId)) : null;
    const lobby = lid != null ? lobbies.get(lid) : null;
    if (lobby) return lobby.members.map(uid => online.get(String(uid))).filter(cid => clients.has(cid));
    return [];
  }

  async function announceMatch(game) {
    const cards = new Map();
    await Promise.all(game.players.map(async pid => cards.set(pid, await playerCard(pid))));
    const roster = team => team.map(pid => cards.get(pid));
    for (const id of game.players) {
      const mine = teamOf(game, id);
      const peers = game.players
        .filter(pid => pid !== id)
        .map(pid => ({ ...cards.get(pid), team: teamOf(game, pid) === mine ? "ally" : "enemy", initiator: id < pid }));
      send(id, {
        type: "matched",
        mode: game.mode,
        peerId: id,
        peers,
        yourTeam: roster(game.teams[mine]),
        enemyTeam: roster(game.teams[1 - mine]),
        opponent: cards.get(game.teams[1 - mine][0]),
      });
    }
  }

  function leaveGame(id) {
    const c = clients.get(id);
    if (!c?.game) return;
    const game = c.game;
    clearTimeout(game.timer);
    for (const pid of game.players) {
      const p = clients.get(pid);
      if (p) { p.partner = null; p.state = "idle"; p.game = null; }
      if (pid !== id) send(pid, { type: "partnerLeft", name: c.name });
    }
  }

  // ---------- friends + presence ----------
  async function friendsPayload(userId) {
    const list = await db.listFriends(userId);
    return list.map(f => ({ id: f.id, name: f.name, rating: f.rating, code: f.friend_code, online: online.has(String(f.id)) }));
  }
  async function sendFriends(userId) {
    const connId = online.get(String(userId));
    if (connId == null) return;
    try { send(connId, { type: "friends", list: await friendsPayload(userId) }); } catch {}
  }
  // Push a user's INCOMING friend requests (live: the badge lights up the moment someone adds you).
  async function sendFriendRequests(userId) {
    const connId = online.get(String(userId));
    if (connId == null) return;
    try {
      const list = (await db.listFriendRequests(userId)).map(r => ({ id: r.id, name: r.name, rating: r.rating }));
      send(connId, { type: "friendRequests", list });
    } catch {}
  }
  async function refreshFriendsOf(userId) {     // my online flag flipped -> push fresh lists to my online friends
    try { for (const f of await db.listFriends(userId)) if (online.has(String(f.id))) await sendFriends(f.id); } catch {}
  }

  // ---------- duo lobbies ----------
  const sendToUser = (uid, msg) => { const cn = online.get(String(uid)); if (cn != null) send(cn, msg); };
  // Two connections are lobby-mates if their users share a lobby. Used to allow WebRTC
  // signaling BEFORE a game exists, so duo partners can see each other on cam in the lobby.
  function inSameLobby(connA, connB) {
    const ua = clients.get(connA)?.userId, ub = clients.get(connB)?.userId;
    if (ua == null || ub == null) return false;
    const la = userLobby.get(String(ua)), lb = userLobby.get(String(ub));
    return la != null && la === lb;
  }
  // peerId = the member's live connection id, so the client can open a P2P call to them.
  // Includes each member's rating + recent form so the lobby cam cards match a real match's cards.
  const lobbyPayload = async lobby => ({
    id: lobby.id, leader: lobby.leader,
    members: await Promise.all(lobby.members.map(async uid => {
      const connId = online.get(String(uid));
      const card = connId != null ? await playerCard(connId) : { name: "?", rating: 1000, form: [] };
      return { id: uid, name: card.name, rating: card.rating, form: card.form, peerId: connId };
    })),
  });
  async function createLobby(uidA, uidB) {      // inviter (A) is the leader
    const lid = nextLobby++;
    const lobby = { id: lid, members: [uidA, uidB], leader: uidA };
    lobbies.set(lid, lobby);
    userLobby.set(String(uidA), lid); userLobby.set(String(uidB), lid);
    const payload = await lobbyPayload(lobby);
    for (const u of lobby.members) sendToUser(u, { type: "lobby", lobby: payload });
  }
  function leaveLobby(connId) {                 // a duo needs both, so leaving disbands it
    const c = clients.get(connId);
    if (!c || c.userId == null) return;
    const lid = userLobby.get(String(c.userId));
    if (lid == null) return;
    userLobby.delete(String(c.userId));
    if (duosWaiting === lid) duosWaiting = null;
    const lobby = lobbies.get(lid);
    if (lobby) {
      for (const u of lobby.members) if (String(u) !== String(c.userId)) { userLobby.delete(String(u)); sendToUser(u, { type: "lobbyClosed" }); }
      lobbies.delete(lid);
    }
  }
  async function queueDuos(uid) {                // only the leader queues the duo
    const lid = userLobby.get(String(uid));
    if (lid == null) return;
    const lobby = lobbies.get(lid);
    if (!lobby || String(lobby.leader) !== String(uid) || lobby.members.length < 2) return;
    const leaderConn = online.get(String(uid));
    if (leaderConn != null && requireConsent(leaderConn)) return;   // leader must have consented
    for (const m of lobby.members) {             // a banned OR non-consented member blocks the whole duo
      const cn = online.get(String(m));
      if (cn == null) continue;
      if (await isBanned(m, cn)) return;
      if (!clients.get(cn)?.consented) { sendToUser(uid, { type: "friendError", reason: "unavailable" }); return; }
    }
    if (duosWaiting !== null && duosWaiting !== lid && lobbies.has(duosWaiting)) {
      const otherLobby = lobbies.get(duosWaiting); duosWaiting = null;
      await matchDuos(lobby, otherLobby);
    } else {
      duosWaiting = lid;
      for (const u of lobby.members) sendToUser(u, { type: "duosWaiting" });
    }
  }
  function cancelDuos(uid) {                     // leader pulls the duo out of queue but keeps the lobby
    const lid = userLobby.get(String(uid));
    if (lid == null) return;
    const lobby = lobbies.get(lid);
    if (!lobby || String(lobby.leader) !== String(uid)) return;
    if (duosWaiting === lid) duosWaiting = null;
    for (const u of lobby.members) sendToUser(u, { type: "duosCanceled" });
  }
  async function matchDuos(l1, l2) {
    const team1 = l1.members.map(uid => online.get(String(uid))).filter(id => clients.has(id));
    const team2 = l2.members.map(uid => online.get(String(uid))).filter(id => clients.has(id));
    const ready = id => clients.get(id)?.state === "idle";
    if (team1.length !== 2 || team2.length !== 2 || !team1.every(ready) || !team2.every(ready)) {
      for (const u of [...l1.members, ...l2.members]) sendToUser(u, { type: "friendError", reason: "unavailable" });
      return;
    }

    for (const u of [...l1.members, ...l2.members]) userLobby.delete(String(u));
    lobbies.delete(l1.id); lobbies.delete(l2.id);

    const players = [...team1, ...team2];
    const game = {
      id: nextGameId++,
      mode: "duos",
      players,
      teams: [team1, team2],
      scores: [0, 0],
      performerTeam: null,
      watcherTeam: null,
      phase: null,
      timer: null,
    };
    for (const id of players) {
      const c = clients.get(id);
      c.state = "paired";
      c.partner = null;
      c.game = game;
    }
    await announceMatch(game);
    startIntro(game);
  }

  // ---------- moderation: reports, reporter trust, progressive bans ----------
  // Policy math lives in moderation.mjs; this just orchestrates DB + sockets. Reports are SILENT:
  // the reported player is never told. Everything degrades cleanly when moderation is "cold".

  // If a user has an active ban, tell that socket and report true (so callers refuse matchmaking).
  async function isBanned(userId, connId) {
    try {
      const ban = await db.getActiveBan(userId);
      if (!ban) return false;
      send(connId, { type: "banned", until: new Date(ban.expires_at).getTime(),
        tier: ban.tier, reason: ban.reason, guest: ban.is_guest });
      return true;
    } catch (e) { console.error("ban check failed:", e.message); return false; }
  }

  // Reward/penalize the REPORTER's trust for this report event (rate-based, emergent).
  async function applyReporterTrust(reporterId, reportedId) {
    // corroboration: a second distinct reporter on the same target within the window lifts both.
    try {
      const cluster = await db.getReportCluster(reportedId, new Date(Date.now() - CORROB_WINDOW));
      const reporters = new Set(cluster.map(r => String(r.reporter_id)));
      if (reporters.size >= 2) {
        await db.adjustTrust(reporterId, trustDelta("corroborate"));
        if (reporters.size === 2) {                        // first corroborating pair: reward the earlier reporter too
          const other = [...reporters].find(rid => rid !== String(reporterId));
          if (other) await db.adjustTrust(other, trustDelta("corroborate"));
        }
      }
    } catch (e) { console.error("corroboration trust failed:", e.message); }
    // over-reporting: trigger-happy relative to games played.
    try {
      const recent = await db.recentReportsBy(reporterId, new Date(Date.now() - WEEK_MS));
      const games = await db.gamesPlayed(reporterId);
      if (overReporting(recent.length, games)) await db.adjustTrust(reporterId, trustDelta("overreport"));
    } catch (e) { console.error("overreport trust failed:", e.message); }
    // stale: aged, never-corroborated reports charged lazily (capped at one per new report, no cron).
    try {
      const aged = await db.agingUncorroboratedReports(reporterId, new Date(Date.now() - CORROB_WINDOW));
      if (aged.length) { await db.adjustTrust(reporterId, trustDelta("stale")); await db.markStaleChecked(aged.map(r => r.id)); }
    } catch (e) { console.error("stale trust failed:", e.message); }
  }

  // Recompute a target's heat over its window and, if it crosses a tier, issue + enforce a ban.
  async function evaluateTarget(reportedId, reportedGuest) {
    try {
      const window = reportedGuest ? WINDOW_GUEST : WINDOW_AUTHED;
      const rows = await db.getReportCluster(reportedId, new Date(Date.now() - window));
      const cluster = rows.map(r => ({ reporterId: r.reporter_id, trust: r.reporter_trust, guest: r.reporter_guest, reason: r.reason }));
      const priorBans = await db.countPriorBans(reportedId);
      const decision = decideBan({ reportedGuest, priorBans, cluster });
      if (!decision.ban) return;
      if (await db.getActiveBan(reportedId)) return;        // already serving a ban — don't stack
      const ban = await db.issueBan({ userId: reportedId, tier: decision.tier, reason: decision.reason, isGuest: reportedGuest, expiresAt: banExpiry(decision.tier) });
      stats.bansIssued++;
      // reward the distinct STRUCTURED reporters whose reports built this ban.
      const assisted = [...new Set(cluster.filter(r => r.reason !== "other").map(r => String(r.reporterId)))];
      for (const rid of assisted) await db.adjustTrust(rid, trustDelta("ban_assist"));
      await db.adjustTrust(reportedId, trustDelta("reported"));   // bad actors make bad reporters
      enforceBan(reportedId, ban);
    } catch (e) { console.error("ban evaluation failed:", e.message); }
  }

  // Boot a freshly-banned live user: tear down their game (opponents get the normal partnerLeft),
  // pull them from any queue/lobby, and hand them the banned screen.
  function enforceBan(userId, ban) {
    const connId = online.get(String(userId));
    if (connId == null) return;                             // offline — they'll get it on next auth
    const c = clients.get(connId);
    if (c?.game) leaveGame(connId);
    if (waiting === connId) waiting = null;
    leaveLobby(connId);
    send(connId, { type: "banned", until: new Date(ban.expires_at).getTime(),
      tier: ban.tier, reason: ban.reason, guest: ban.is_guest });
  }

  // WS `report`: reporter must be in a live game; target another participant in that same game.
  async function handleReport(id, msg) {
    const c = clients.get(id);
    const game = c?.game;
    if (!game) return send(id, { type: "reportAck", ok: false, reason: "nogame" });
    const target = +msg.target;
    if (!Number.isFinite(target) || target === id || !game.players.includes(target))
      return send(id, { type: "reportAck", ok: false, reason: "badtarget" });
    const tc = clients.get(target);
    if (!tc || tc.userId == null) return send(id, { type: "reportAck", ok: false, reason: "badtarget" });

    const reason = ["cheating", "harassment", "other"].includes(msg.reason) ? msg.reason : null;
    if (!reason) return send(id, { type: "reportAck", ok: false, reason: "badreason" });
    let detail = null;
    if (reason === "other") {                                    // moderate freetail (normalize/cap; quoting allowed)
      const v = moderateText(msg.detail, { context: "report_detail" });
      if (!v.ok) return send(id, { type: "reportAck", ok: false, reason: "needdetail" });
      detail = v.cleaned;
    }

    const reporterId = c.userId, reportedId = tc.userId;
    const reporterGuest = !!c.isGuest, reportedGuest = !!tc.isGuest;

    // spam / rate-limit: reject the excess and dock the reporter's trust.
    try {
      const recent = await db.recentReportsBy(reporterId, new Date(Date.now() - SPAM_WINDOW));
      if (recent.length >= SPAM_LIMIT) {
        await db.adjustTrust(reporterId, trustDelta("spam"));
        return send(id, { type: "reportAck", ok: false, reason: "rate" });
      }
    } catch (e) { console.error("spam check failed:", e.message); }

    let reporterTrust = 50;
    try { reporterTrust = await db.getTrust(reporterId); } catch {}

    let result;
    try {
      result = await db.insertReport({
        reporter_id: reporterId, reported_id: reportedId, game_id: String(game.id),
        reason, detail, reporter_trusted: reporterTrust >= TRUSTED_THRESHOLD, reporter_trust: reporterTrust,
        reporter_guest: reporterGuest, reported_guest: reportedGuest,
        reporter_ip_hash: c.ipHash || null, needs_review: reason === "other",
      });
    } catch (e) { console.error("insertReport failed:", e.message); return send(id, { type: "reportAck", ok: false, reason: "error" }); }
    if (result.duplicate) return send(id, { type: "reportAck", ok: true, already: true });

    await applyReporterTrust(reporterId, reportedId);
    await evaluateTarget(reportedId, reportedGuest);
    send(id, { type: "reportAck", ok: true });
  }

  wss.on("connection", (ws, req) => {
    const id = nextId++;
    // req.headers carry same-origin cookies from the WS upgrade — that's how a socket
    // authenticates from a session. Captured once; the session is fixed for the socket's life.
    // ipHash: a SALTED hash of the remote IP for guest-cluster DETECTION only (never a raw IP,
    // never a matchmaking gate — see moderation §5). Salt from env; empty salt still avoids storing IPs.
    const rawIp = clientIp(req);
    const ipHash = rawIp ? crypto.createHash("sha256").update(MOD_IP_SALT + "|" + rawIp).digest("hex") : null;

    // Cap concurrent sockets per IP (the in-memory key is the salted hash, never a raw IP).
    const ipKey = ipHash || rawIp || "";
    if (ipKey) {
      const n = (connsByIp.get(ipKey) || 0) + 1;
      if (n > MAX_CONNS_PER_IP) { logSec("ws_conn_capped", { ip: rawIp }); try { ws.close(1013, "too many connections"); } catch {} return; }
      connsByIp.set(ipKey, n);
    }

    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });
    // A socket-level error (e.g. an oversized/ malformed frame past maxPayload) emits 'error'.
    // Without a listener Node throws it as an unhandled event and crashes the process — swallow it.
    ws.on("error", (err) => logSec("ws_socket_error", { msg: err && err.message }));
    const limiter = makeLimiter();     // per-connection rate limiter (global + per-type budgets)

    clients.set(id, { ws, reqHeaders: req.headers, ipHash, isGuest: true, state: "idle", partner: null, game: null, userId: null, name: null, rating: null });

    ws.on("message", async (data) => {
     let msg = null;
     try {
      // Validate BEFORE dispatch, then rate-limit. A hand-crafted socket can't reach a handler
      // with a wrong-shaped payload; malformed/unknown messages still count toward the limiter.
      try { msg = JSON.parse(data); } catch { limiter.check("_bad"); return; }
      const type = validateMessage(msg);
      const gate = limiter.check(type || "_bad");
      if (gate.disconnect) { stats.rateLimitTrips++; logSec("ws_abuse_disconnect", { ip: rawIp }); try { ws.close(1008, "rate"); } catch {} return; }
      if (!gate.allow || !type) return;              // over budget, or malformed/unknown -> ignore

      const c = clients.get(id); if (!c) return;

      if (msg.type === "auth") {
        const user = await resolveGameUser({ headers: c.reqHeaders, guestToken: msg.token, name: msg.name });
        if (user === NEED_NAME) { send(id, { type: "needName" }); return; }   // first login: pick a screenname
        if (user && user.rejected) {                                          // name blocked/taken -> reprompt
          send(id, { type: "nameError", reason: user.reason, suggestions: user.suggestions || [] });
          return;
        }
        c.userId = user.id; c.name = user.name; c.rating = user.rating;
        c.isGuest = user.auth_id == null;         // guest vs account, used everywhere moderation branches
        c.consented = user.age_confirmed_at != null;   // 18+ & ToS/Privacy consent logged? gates matchmaking
        let form = [];
        try { form = (await db.recentMatches(user.id, 5)).map(m => m.outcome); }
        catch (e) { console.error("recentMatches (auth) failed:", e.message); }
        send(id, { type: "authed", token: user.token, profile: {
          id: user.id, name: user.name, rating: user.rating, wins: user.wins, losses: user.losses,
          draws: user.draws, games: user.games, form, friendCode: user.friend_code,
          consented: c.consented, tosVersion: TOS_VERSION } });
        online.set(String(user.id), id);          // this connection is now the user's live socket
        sendFriends(user.id);                     // hand them their friends list (with online flags)
        sendFriendRequests(user.id);              // ...and any friend requests waiting on them
        refreshFriendsOf(user.id);                // tell their online friends they just came online
        await isBanned(user.id, id);              // banned accounts see the suspension screen on first load
      } else if (msg.type === "leaderboard") {
        send(id, { type: "leaderboard", top: await db.topPlayers(10) });
      } else if (msg.type === "find") {
        await findMatch(id);
      } else if (msg.type === "cancelSearch") {
        cancelSearch(id);
      } else if (msg.type === "next") {
        const wasDuos = c.game?.mode === "duos";
        leaveGame(id);
        if (!wasDuos) await findMatch(id);
      } else if (msg.type === "reaction") {
        handleReaction(id, msg);
      } else if (msg.type === "chat" && c.userId) {
        const now = Date.now();
        if (c.chatMutedUntil && now < c.chatMutedUntil) { send(id, { type: "chatBlocked", reason: "muted" }); return; }
        const verdict = moderateText(msg.text, { context: "chat" });   // slur->block, profanity->redact, url->block
        if (!verdict.ok) {
          // Hard block (slur/link): tell only the sender, broadcast nothing. Slurs cost trust,
          // are logged (rule id, never the raw text), and repeat offenders get a short mute.
          if (verdict.rule === "slur") {
            c.chatStrikes = (c.chatStrikes || 0) + 1;
            db.logModeration({ userId: c.userId, context: "chat", rule: verdict.rule });
            db.adjustTrust(c.userId, trustDelta("chat_violation")).catch(() => {});
            if (c.chatStrikes >= CHAT_MUTE_STRIKES) { c.chatMutedUntil = now + CHAT_MUTE_MS; c.chatStrikes = 0; }
          }
          send(id, { type: "chatBlocked", reason: verdict.reason });
          return;
        }
        const text = verdict.cleaned;
        if (c.lastChat === text && (now - (c.lastChatAt || 0)) < CHAT_DUP_WINDOW) { send(id, { type: "chatBlocked", reason: "dup" }); return; }
        c.lastChat = text; c.lastChatAt = now;
        for (const pid of chatPeers(id)) send(pid, { type: "chat", from: c.name, fromId: id, text, self: pid === id });
      } else if (msg.type === "addFriend" && c.userId) {
        // Sends a friend REQUEST; the friendship only forms when the other side accepts.
        // (Crossed requests auto-accept in db.requestFriend — both sides already said yes.)
        const r = await db.requestFriend(c.userId, msg.code);
        if (!r.ok) send(id, { type: "friendError", reason: r.reason });
        else if (r.accepted) {                                     // they had already asked us
          send(id, { type: "friendRequestSent", to: r.friend.name, accepted: true });
          sendFriends(c.userId); sendFriends(r.friend.id); sendFriendRequests(c.userId);
        } else {
          send(id, { type: "friendRequestSent", to: r.friend.name });
          sendFriendRequests(r.friend.id);                         // light their badge up live
        }
      } else if (msg.type === "acceptFriend" && c.userId) {
        const r = await db.acceptFriendRequest(c.userId, msg.fromId);
        if (!r.ok) { send(id, { type: "friendError", reason: r.reason }); sendFriendRequests(c.userId); }
        else { sendFriends(c.userId); sendFriends(r.friend.id); sendFriendRequests(c.userId); }
      } else if (msg.type === "declineFriend" && c.userId) {
        await db.declineFriendRequest(c.userId, msg.fromId);
        sendFriendRequests(c.userId);
      } else if (msg.type === "removeFriend" && c.userId) {
        await db.removeFriend(c.userId, msg.friendId);
        sendFriends(c.userId);
        sendFriends(msg.friendId);                             // no-op if they're offline; live update if not
      } else if (msg.type === "friendRequests" && c.userId) {
        sendFriendRequests(c.userId);
      } else if (msg.type === "friends" && c.userId) {
        sendFriends(c.userId);
      } else if (msg.type === "invite" && c.userId) {
        if (requireConsent(id)) return;                       // lobby cam needs consent too
        if (c.state !== "idle" || userLobby.get(String(c.userId)) != null) { send(id, { type: "friendError", reason: "unavailable" }); return; }
        const friend = connOfUser(msg.friendId);
        if (!friend) send(id, { type: "friendError", reason: "offline" });
        else if (friend.state !== "idle") send(id, { type: "friendError", reason: "unavailable" });
        else sendToUser(msg.friendId, { type: "invited", from: { id: c.userId, name: c.name } });
      } else if (msg.type === "acceptInvite" && c.userId) {
        if (requireConsent(id)) return;                       // joining a lobby opens the cam
        const free = uid => userLobby.get(String(uid)) == null && connOfUser(uid)?.state === "idle";
        if (connOfUser(msg.fromId) && free(msg.fromId) && free(c.userId)) createLobby(msg.fromId, c.userId);
        else send(id, { type: "friendError", reason: "unavailable" });
      } else if (msg.type === "declineInvite" && c.userId) {
        sendToUser(msg.fromId, { type: "inviteDeclined", by: c.name });
      } else if (msg.type === "leaveLobby" && c.userId) {
        leaveLobby(id);
      } else if (msg.type === "queueDuos" && c.userId) {
        await queueDuos(c.userId);
      } else if (msg.type === "cancelDuos" && c.userId) {
        cancelDuos(c.userId);
      } else if (msg.type === "report" && c.userId) {
        await handleReport(id, msg);
      } else if (msg.type === "rtcStat") {                    // client reports peer-connection outcome (observability)
        if (msg.ok) stats.rtcConnected++;
        else { stats.rtcFailed++; logSec("rtc_connect_failed", {}); }
      } else if ((msg.type === "offer" || msg.type === "answer" || msg.type === "candidate") && msg.target != null) {
        const target = +msg.target;
        const sameGame = c.game && c.game.players.includes(target) && clients.get(target)?.game === c.game;
        const sameLobby = inSameLobby(id, target);     // pre-game lobby cam between duo partners
        if (sameGame || sameLobby) send(target, { ...msg, from: id });
      } else if (c.state === "paired" && c.partner != null) {
        send(c.partner, { ...msg, from: id });
      }
     } catch (err) {
      // One thrown handler must never take down the process (§7.2). Log, report, keep the socket alive.
      logSec("ws_handler_error", { msg: err && err.message });
      captureError(err, { where: "ws_handler", type: msg && msg.type });
     }
    });

    ws.on("close", () => {
      if (ipKey) { const n = (connsByIp.get(ipKey) || 1) - 1; if (n > 0) connsByIp.set(ipKey, n); else connsByIp.delete(ipKey); }
      if (waiting === id) waiting = null;
      leaveGame(id);
      leaveLobby(id);
      const c = clients.get(id);
      if (c?.userId != null && online.get(String(c.userId)) === id) {   // only if this was their live socket
        const uid = c.userId; online.delete(String(uid)); refreshFriendsOf(uid);
      }
      clients.delete(id);
    });
  });

  server.listen(PORT, () => {
    console.log(`omegLOL running on port ${PORT}`);
  });
  return { server, wss };
}

// run directly (not when imported by a test)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.DATABASE_URL) { console.error("Set DATABASE_URL (see run notes)."); process.exit(1); }

  await initSentry();   // error tracking (no-op unless SENTRY_DSN is set)

  // Last-resort guards: a stray async error must not take the whole process (and every live game)
  // down. Per-message handlers already try/catch (§7.2); this catches anything that escapes.
  // Run under a supervisor (pm2/systemd/container) so a truly wedged process gets restarted.
  process.on("unhandledRejection", (reason) => {
    logSec("unhandled_rejection", { msg: reason && (reason.message || String(reason)) });
    captureError(reason, { where: "unhandledRejection" });
  });
  process.on("uncaughtException", (err) => {
    logSec("uncaught_exception", { msg: err && err.message });
    captureError(err, { where: "uncaughtException" });
  });

  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const db = makeDb(pool);
  await db.initSchema();
  const { server } = await startServer({ db, pool });   // pool is handed to better-auth when its env is set

  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => {   // clean shutdown for restarts
    logSec("shutdown", { sig });
    server.close(() => pool.end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(0), 10000).unref();   // don't hang on lingering sockets
  });
}
