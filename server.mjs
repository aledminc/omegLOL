import { WebSocketServer } from "ws";

const PORT = 8080;
const SEC = 1000;
const dur = {
  countdown: (+process.env.T_COUNTDOWN || 3)  * SEC,
  round:     (+process.env.T_ROUND     || 30) * SEC,
  swap:      (+process.env.T_SWAP      || 3)  * SEC,
  result:    (+process.env.T_RESULT    || 8)  * SEC,
};

const wss = new WebSocketServer({ port: PORT });
const clients = new Map();   // id -> { ws, state, partner, game }
let waiting = null;
let nextId = 1;

function send(id, msg) {
  const c = clients.get(id);
  if (c && c.ws.readyState === c.ws.OPEN) c.ws.send(JSON.stringify(msg));
}
const other = (game, id) => game.players.find(p => p !== id);

// ---- matchmaking ----
function findMatch(id) {
  const c = clients.get(id);
  if (!c || c.state !== "idle") return;
  if (waiting !== null && waiting !== id && clients.get(waiting)?.state === "waiting") {
    const partnerId = waiting; waiting = null; pair(id, partnerId);
  } else {
    c.state = "waiting"; waiting = id; send(id, { type: "waiting" });
  }
}

function pair(a, b) {
  const ca = clients.get(a), cb = clients.get(b);
  ca.partner = b; ca.state = "paired";
  cb.partner = a; cb.state = "paired";
  send(a, { type: "matched", initiator: true });
  send(b, { type: "matched", initiator: false });

  const game = { players: [a, b], scores: { [a]: 0, [b]: 0 }, performer: null, watcher: null, phase: null, timer: null };
  ca.game = game; cb.game = game;
  startCountdown(game);
}

// ---- phase engine ----
function setPhase(game, phase, ms, next) {
  clearTimeout(game.timer);
  game.phase = phase;
  game.timer = setTimeout(() => next(game), ms);
}
function setRoles(game, performerIdx) {
  game.performer = game.players[performerIdx];
  game.watcher   = game.players[1 - performerIdx];
}
function broadcast(game, phase, seconds) {
  for (const id of game.players) {
    send(id, {
      type: "gameState", phase, seconds,
      role: id === game.performer ? "performer" : id === game.watcher ? "watcher" : null,
      scores: { you: game.scores[id], them: game.scores[other(game, id)] },
    });
  }
}
function broadcastScores(game) {
  for (const id of game.players)
    send(id, { type: "score", scores: { you: game.scores[id], them: game.scores[other(game, id)] } });
}

function startCountdown(game) { setRoles(game, 0); setPhase(game, "countdown", dur.countdown, startRound1); broadcast(game, "countdown", dur.countdown / SEC); }
function startRound1(game)    { setRoles(game, 0); setPhase(game, "round1",    dur.round,     startSwap);   broadcast(game, "round1",    dur.round / SEC); }
function startSwap(game)      {                    setPhase(game, "swap",      dur.swap,      startRound2); broadcast(game, "swap",      dur.swap / SEC); }
function startRound2(game)    { setRoles(game, 1); setPhase(game, "round2",    dur.round,     endGame);     broadcast(game, "round2",    dur.round / SEC); }

function endGame(game) {
  setPhase(game, "result", dur.result, resetGame);
  for (const id of game.players) {
    const mine = game.scores[id], theirs = game.scores[other(game, id)];
    send(id, { type: "gameState", phase: "result", seconds: dur.result / SEC, role: null,
      scores: { you: mine, them: theirs },
      outcome: mine > theirs ? "win" : mine < theirs ? "lose" : "draw" });
  }
}
function resetGame(game) {
  for (const id of game.players) {
    const c = clients.get(id);
    if (c) { c.state = "idle"; c.partner = null; c.game = null; }
    send(id, { type: "gameReset" });
  }
}

// ---- scoring ----
function handleScore(id, msg) {
  const game = clients.get(id)?.game;
  if (!game || (game.phase !== "round1" && game.phase !== "round2")) return;
  if (id !== game.watcher) return;                              // only the watcher can score
  const delta = Math.max(0, Math.min(50, +msg.delta || 0));
  game.scores[game.performer] += delta;                        // credit the performer
  broadcastScores(game);
}

// ---- teardown ----
function leavePartner(id) {
  const c = clients.get(id);
  if (!c || c.state !== "paired") return;
  const partnerId = c.partner;
  if (c.game) clearTimeout(c.game.timer);                      // kill the pending phase timer
  c.partner = null; c.state = "idle"; c.game = null;
  const p = clients.get(partnerId);
  if (p) { p.partner = null; p.state = "idle"; p.game = null; send(partnerId, { type: "partnerLeft" }); }
}

// ---- lifecycle ----
wss.on("connection", (ws) => {
  const id = nextId++;
  clients.set(id, { ws, state: "idle", partner: null, game: null });

  ws.on("message", (data) => {
    let msg; try { msg = JSON.parse(data); } catch { return; }
    const c = clients.get(id); if (!c) return;

    if (msg.type === "find") findMatch(id);
    else if (msg.type === "next") { leavePartner(id); findMatch(id); }
    else if (msg.type === "score") handleScore(id, msg);
    else if (c.state === "paired") send(c.partner, msg);       // chat / offer / answer / candidate
  });

  ws.on("close", () => {
    if (waiting === id) waiting = null;
    leavePartner(id);
    clients.delete(id);
  });
});

console.log(`game server on ws://localhost:${PORT}`);
