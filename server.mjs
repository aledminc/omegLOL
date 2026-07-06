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
export async function startServer({ db, pool = null, port = PORT }) {
  // ---------- HTTP: static files, pretty page routes, a small JSON API ----------
  const app = express();

  // ---------- optional real accounts (better-auth) ----------
  // Auth is wired ONLY when a secret + a pg pool are available. Absent either, the server
  // runs exactly as before (guests + anonymous tokens), so nothing external is needed to boot.
  let auth = null, fromHeaders = null;
  if (process.env.BETTER_AUTH_SECRET && pool) {
    const [{ makeAuth }, nodeHandler] = await Promise.all([
      import("./auth.mjs"),
      import("better-auth/node"),
    ]);
    auth = makeAuth(pool);
    fromHeaders = nodeHandler.fromNodeHeaders;
    // better-auth reads the raw request body itself; mount before any json parser (there are none).
    app.all("/api/auth/{*any}", nodeHandler.toNodeHandler(auth));
    console.log("auth: better-auth mounted (email/password)");
  } else {
    console.log("auth: disabled — guest/token only (set BETTER_AUTH_SECRET + DATABASE_URL to enable)");
  }

  // A signalling value for "authenticated, but this brand-new account still needs to pick
  // a screenname" — the client answers by re-sending auth with a name (the name gate).
  const NEED_NAME = Symbol("needName");

  // Map a request to its game `users` row. A valid session cookie (a real account) always
  // wins and any client-supplied token is ignored (can't impersonate an account). With no
  // session we fall back to the guest token exactly as before. New accounts start clean.
  async function resolveGameUser({ headers, guestToken, name }) {
    if (auth) {
      try {
        const session = await auth.api.getSession({ headers: fromHeaders(headers) });
        if (session?.user) {
          const existing = await db.getUserByAuthId(session.user.id);
          if (existing) return existing;
          const screen = (name || "").trim();
          if (!screen) return NEED_NAME;            // first login: prompt for a screenname
          return await db.createAuthedUser({ authId: session.user.id, name: screen });
        }
      } catch (e) { console.error("session resolve failed:", e.message); }
    }
    return await db.getOrCreateUser({ token: guestToken, name });   // guest path (unchanged)
  }

  app.use(express.static(PUBLIC));                         // landing, css, js, *.html
  const page = f => (_req, res) => res.sendFile(path.join(PUBLIC, f));
  app.get("/login",  page("login.html"));
  app.get("/play",   page("play.html"));
  app.get("/ranked", page("ranked.html"));
  app.get("/api/leaderboard", async (_req, res) => {       // request/response data -> HTTP, not WS
    try { res.json(await db.topPlayers(10)); }
    catch { res.status(500).json({ error: "unavailable" }); }
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

  // ---------- one HTTP server; the WebSocket shares it (upgrade on the same port) ----------
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server });

  // ===================== game (per-server state) =====================
  const clients = new Map();   // id -> { ws, state, partner, game, userId, name, rating }
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

  async function findMatch(id) {
    const c = clients.get(id);
    if (!c || !c.userId || c.state !== "idle") return;
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
    startCountdown(game);
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
  function startCountdown(game) { setRoles(game, 0); setPhase(game, "countdown", dur.countdown, startRound1); broadcast(game, "countdown", dur.countdown / SEC); }
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
  const lobbyPayload = lobby => ({
    id: lobby.id, leader: lobby.leader,
    members: lobby.members.map(uid => ({ id: uid, name: connOfUser(uid)?.name || "?", peerId: online.get(String(uid)) })),
  });
  function createLobby(uidA, uidB) {            // inviter (A) is the leader
    const lid = nextLobby++;
    const lobby = { id: lid, members: [uidA, uidB], leader: uidA };
    lobbies.set(lid, lobby);
    userLobby.set(String(uidA), lid); userLobby.set(String(uidB), lid);
    for (const u of lobby.members) sendToUser(u, { type: "lobby", lobby: lobbyPayload(lobby) });
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
    startCountdown(game);
  }

  wss.on("connection", (ws, req) => {
    const id = nextId++;
    // req.headers carry same-origin cookies from the WS upgrade — that's how a socket
    // authenticates from a session. Captured once; the session is fixed for the socket's life.
    clients.set(id, { ws, reqHeaders: req.headers, state: "idle", partner: null, game: null, userId: null, name: null, rating: null });

    ws.on("message", async (data) => {
      let msg; try { msg = JSON.parse(data); } catch { return; }
      const c = clients.get(id); if (!c) return;

      if (msg.type === "auth") {
        const user = await resolveGameUser({ headers: c.reqHeaders, guestToken: msg.token, name: msg.name });
        if (user === NEED_NAME) { send(id, { type: "needName" }); return; }   // first login: pick a screenname
        c.userId = user.id; c.name = user.name; c.rating = user.rating;
        let form = [];
        try { form = (await db.recentMatches(user.id, 5)).map(m => m.outcome); }
        catch (e) { console.error("recentMatches (auth) failed:", e.message); }
        send(id, { type: "authed", token: user.token, profile: {
          id: user.id, name: user.name, rating: user.rating, wins: user.wins, losses: user.losses,
          draws: user.draws, games: user.games, form, friendCode: user.friend_code } });
        online.set(String(user.id), id);          // this connection is now the user's live socket
        sendFriends(user.id);                     // hand them their friends list (with online flags)
        refreshFriendsOf(user.id);                // tell their online friends they just came online
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
        const text = String(msg.text ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
        if (!text) return;
        for (const pid of chatPeers(id)) send(pid, { type: "chat", from: c.name, fromId: id, text, self: pid === id });
      } else if (msg.type === "addFriend" && c.userId) {
        const r = await db.addFriendByCode(c.userId, msg.code);
        if (r.ok) { sendFriends(c.userId); sendFriends(r.friend.id); }   // refresh both sides
        else send(id, { type: "friendError", reason: r.reason });
      } else if (msg.type === "friends" && c.userId) {
        sendFriends(c.userId);
      } else if (msg.type === "invite" && c.userId) {
        if (c.state !== "idle" || userLobby.get(String(c.userId)) != null) { send(id, { type: "friendError", reason: "unavailable" }); return; }
        const friend = connOfUser(msg.friendId);
        if (!friend) send(id, { type: "friendError", reason: "offline" });
        else if (friend.state !== "idle") send(id, { type: "friendError", reason: "unavailable" });
        else sendToUser(msg.friendId, { type: "invited", from: { id: c.userId, name: c.name } });
      } else if (msg.type === "acceptInvite" && c.userId) {
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
      } else if ((msg.type === "offer" || msg.type === "answer" || msg.type === "candidate") && msg.target != null) {
        const target = +msg.target;
        const sameGame = c.game && c.game.players.includes(target) && clients.get(target)?.game === c.game;
        const sameLobby = inSameLobby(id, target);     // pre-game lobby cam between duo partners
        if (sameGame || sameLobby) send(target, { ...msg, from: id });
      } else if (c.state === "paired" && c.partner != null) {
        send(c.partner, { ...msg, from: id });
      }
    });

    ws.on("close", () => {
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

  server.listen(port, () => console.log(`omegLOL on http://localhost:${port}`));
  return { server, wss };
}

// run directly (not when imported by a test)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.DATABASE_URL) { console.error("Set DATABASE_URL (see run notes)."); process.exit(1); }
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const db = makeDb(pool);
  await db.initSchema();
  await startServer({ db, pool });   // pool is handed to better-auth when its env is set
}
