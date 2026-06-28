import express from "express";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { WebSocketServer } from "ws";
import pg from "pg";
import { makeDb } from "./db.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, "public");
const PORT = +process.env.PORT || 8080;
const SEC = 1000;
const dur = {
  countdown: (+process.env.T_COUNTDOWN || 3)  * SEC,
  round:     (+process.env.T_ROUND     || 30) * SEC,
  swap:      (+process.env.T_SWAP      || 3)  * SEC,
  result:    (+process.env.T_RESULT    || 8)  * SEC,
};

// startServer takes an injected db so the whole stack (HTTP + WS) is testable
// against an in-memory database without a real Postgres.
export function startServer({ db, port = PORT }) {
  // ---------- HTTP: static files, pretty page routes, a small JSON API ----------
  const app = express();
  app.use(express.static(PUBLIC));                         // landing, css, js, *.html
  const page = f => (_req, res) => res.sendFile(path.join(PUBLIC, f));
  app.get("/login",  page("login.html"));
  app.get("/play",   page("play.html"));
  app.get("/ranked", page("ranked.html"));
  app.get("/api/leaderboard", async (_req, res) => {       // request/response data -> HTTP, not WS
    try { res.json(await db.topPlayers(10)); }
    catch { res.status(500).json({ error: "unavailable" }); }
  });

  // ---------- one HTTP server; the WebSocket shares it (upgrade on the same port) ----------
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server });

  // ===================== game (per-server state) =====================
  const clients = new Map();   // id -> { ws, state, partner, game, userId, name, rating }
  let waiting = null, nextId = 1;

  const send = (id, msg) => { const c = clients.get(id); if (c && c.ws.readyState === c.ws.OPEN) c.ws.send(JSON.stringify(msg)); };
  const other = (game, id) => game.players.find(p => p !== id);

  function findMatch(id) {
    const c = clients.get(id);
    if (!c || !c.userId || c.state !== "idle") return;
    if (waiting !== null && waiting !== id && clients.get(waiting)?.state === "waiting") {
      const partnerId = waiting; waiting = null; pair(id, partnerId);
    } else { c.state = "waiting"; waiting = id; send(id, { type: "waiting" }); }
  }
  function pair(a, b) {
    const ca = clients.get(a), cb = clients.get(b);
    ca.partner = b; ca.state = "paired"; cb.partner = a; cb.state = "paired";
    send(a, { type: "matched", initiator: true });
    send(b, { type: "matched", initiator: false });
    const game = { players: [a, b], scores: { [a]: 0, [b]: 0 }, performer: null, watcher: null, phase: null, timer: null };
    ca.game = game; cb.game = game;
    startCountdown(game);
  }

  function setPhase(game, phase, ms, next) { clearTimeout(game.timer); game.phase = phase; game.timer = setTimeout(() => next(game), ms); }
  function setRoles(game, pIdx) { game.performer = game.players[pIdx]; game.watcher = game.players[1 - pIdx]; }
  function broadcast(game, phase, seconds) {
    for (const id of game.players)
      send(id, { type: "gameState", phase, seconds,
        role: id === game.performer ? "performer" : id === game.watcher ? "watcher" : null,
        scores: { you: game.scores[id], them: game.scores[other(game, id)] } });
  }
  function broadcastScores(game) {
    for (const id of game.players)
      send(id, { type: "score", scores: { you: game.scores[id], them: game.scores[other(game, id)] } });
  }
  function startCountdown(game) { setRoles(game, 0); setPhase(game, "countdown", dur.countdown, startRound1); broadcast(game, "countdown", dur.countdown / SEC); }
  function startRound1(game)    { setRoles(game, 0); setPhase(game, "round1",    dur.round,     startSwap);   broadcast(game, "round1",    dur.round / SEC); }
  function startSwap(game)      {                    setPhase(game, "swap",      dur.swap,      startRound2); broadcast(game, "swap",      dur.swap / SEC); }
  function startRound2(game)    { setRoles(game, 1); setPhase(game, "round2",    dur.round,     endGame);     broadcast(game, "round2",    dur.round / SEC); }

  async function endGame(game) {
    setPhase(game, "result", dur.result, resetGame);
    for (const id of game.players) {
      const mine = game.scores[id], theirs = game.scores[other(game, id)];
      send(id, { type: "gameState", phase: "result", seconds: dur.result / SEC, role: null,
        scores: { you: mine, them: theirs }, outcome: mine > theirs ? "win" : mine < theirs ? "lose" : "draw" });
    }
    const c0 = clients.get(game.players[0]), c1 = clients.get(game.players[1]);
    if (c0?.userId && c1?.userId) {
      try {
        const res = await db.recordMatch(c0.userId, c1.userId, game.scores[game.players[0]], game.scores[game.players[1]]);
        c0.rating = res.a.after; c1.rating = res.b.after;
        send(game.players[0], { type: "ranked", delta: res.a.delta, rating: res.a.after });
        send(game.players[1], { type: "ranked", delta: res.b.delta, rating: res.b.after });
      } catch (e) { console.error("recordMatch failed:", e.message); }
    }
  }
  function resetGame(game) {
    for (const id of game.players) {
      const c = clients.get(id);
      if (c) { c.state = "idle"; c.partner = null; c.game = null; }
      send(id, { type: "gameReset" });
    }
  }

  function handleScore(id, msg) {
    const game = clients.get(id)?.game;
    if (!game || (game.phase !== "round1" && game.phase !== "round2")) return;
    if (id !== game.watcher) return;
    const delta = Math.max(0, Math.min(50, +msg.delta || 0));
    game.scores[game.performer] += delta;
    broadcastScores(game);
  }

  function leavePartner(id) {
    const c = clients.get(id);
    if (!c || c.state !== "paired") return;
    const partnerId = c.partner;
    if (c.game) clearTimeout(c.game.timer);
    c.partner = null; c.state = "idle"; c.game = null;
    const p = clients.get(partnerId);
    if (p) { p.partner = null; p.state = "idle"; p.game = null; send(partnerId, { type: "partnerLeft" }); }
  }

  wss.on("connection", (ws) => {
    const id = nextId++;
    clients.set(id, { ws, state: "idle", partner: null, game: null, userId: null, name: null, rating: null });

    ws.on("message", async (data) => {
      let msg; try { msg = JSON.parse(data); } catch { return; }
      const c = clients.get(id); if (!c) return;

      if (msg.type === "auth") {
        const user = await db.getOrCreateUser({ token: msg.token, name: msg.name });
        c.userId = user.id; c.name = user.name; c.rating = user.rating;
        send(id, { type: "authed", token: user.token, profile: {
          name: user.name, rating: user.rating, wins: user.wins, losses: user.losses, draws: user.draws, games: user.games } });
      } else if (msg.type === "leaderboard") {
        send(id, { type: "leaderboard", top: await db.topPlayers(10) });
      } else if (msg.type === "find") {
        findMatch(id);
      } else if (msg.type === "next") {
        leavePartner(id); findMatch(id);
      } else if (msg.type === "score") {
        handleScore(id, msg);
      } else if (c.state === "paired") {
        send(c.partner, msg);
      }
    });

    ws.on("close", () => { if (waiting === id) waiting = null; leavePartner(id); clients.delete(id); });
  });

  server.listen(port, () => console.log(`omegLOL on http://localhost:${port}`));
  return { server, wss };
}

// run directly (not when imported by a test)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.DATABASE_URL) { console.error("Set DATABASE_URL (see run notes)."); process.exit(1); }
  const db = makeDb(new pg.Pool({ connectionString: process.env.DATABASE_URL }));
  await db.initSchema();
  startServer({ db });
}
