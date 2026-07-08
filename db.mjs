import crypto from "node:crypto";
import { resultFromScores, updatedRatings } from "./elo.mjs";
import { TRUST_MIN, TRUST_MAX, TRUST_MAX_GUEST } from "./moderation.mjs";
import { cleanText, NAME_MAX } from "./validate.mjs";

// Screennames pass through the shared text gate (strip control/zero-width chars, collapse
// whitespace, cap length). Output is still HTML-escaped at render time — this is defense in depth.
const safeName = n => cleanText(n, NAME_MAX) || "Anon";

// Short, shareable, non-secret handle. No ambiguous chars (0/O, 1/I/L). e.g. "K7M-3PQ".
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genCode() {
  let s = "";
  for (let i = 0; i < 6; i++) s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  return s.slice(0, 3) + "-" + s.slice(3);
}

// makeDb takes a connection pool (real pg, or pg-mem in tests) and returns the
// data-access functions. Keeping the pool injected means this file never imports
// pg directly, so the same code is testable in-memory.
export function makeDb(pool) {
  async function initSchema() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id          BIGSERIAL PRIMARY KEY,
        name        TEXT NOT NULL,
        token       TEXT NOT NULL UNIQUE,
        friend_code TEXT,
        rating  INTEGER NOT NULL DEFAULT 1000,
        wins    INTEGER NOT NULL DEFAULT 0,
        losses  INTEGER NOT NULL DEFAULT 0,
        draws   INTEGER NOT NULL DEFAULT 0,
        games   INTEGER NOT NULL DEFAULT 0
      );`);
    // migrate user tables that predate friend codes, then backfill + enforce uniqueness
    try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS friend_code TEXT`); } catch {}
    const missing = await pool.query(`SELECT id FROM users WHERE friend_code IS NULL`);
    for (const r of missing.rows) await pool.query(`UPDATE users SET friend_code = $1 WHERE id = $2`, [genCode(), r.id]);
    try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_friend_code_idx ON users (friend_code)`); } catch {}

    // link a game user to a better-auth account (nullable: guests never get one). Same
    // migrate-then-index pattern as friend_code. A plain unique index treats NULLs as
    // distinct in Postgres, so many guest rows keep auth_id NULL while accounts stay unique.
    try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_id TEXT`); } catch {}
    try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_auth_id_idx ON users (auth_id)`); } catch {}

    // ---- moderation: reporter trust, reports, progressive bans (same idempotent pattern) ----
    try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_score INTEGER NOT NULL DEFAULT 50`); } catch {}
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id               BIGSERIAL PRIMARY KEY,
        reporter_id      BIGINT  NOT NULL,
        reported_id      BIGINT  NOT NULL,
        game_id          TEXT    NOT NULL,
        reason           TEXT    NOT NULL,           -- 'cheating' | 'harassment' | 'other'
        detail           TEXT,                       -- freetext, only for 'other'
        reporter_trusted BOOLEAN NOT NULL,           -- snapshot: trust >= TRUSTED_THRESHOLD at report time
        reporter_trust   INTEGER NOT NULL,           -- snapshot score
        reporter_guest   BOOLEAN NOT NULL,
        reported_guest   BOOLEAN NOT NULL,
        reporter_ip_hash TEXT,                       -- salted, detection-only guest clustering
        needs_review     BOOLEAN NOT NULL DEFAULT FALSE,
        stale_checked    BOOLEAN NOT NULL DEFAULT FALSE,  -- lazy stale-trust eval marker (no cron)
        created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
      );`);
    // one reporter can report a given target at most once per match
    try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS reports_dedup_idx ON reports (reporter_id, reported_id, game_id)`); } catch {}
    try { await pool.query(`CREATE INDEX IF NOT EXISTS reports_reported_idx ON reports (reported_id, created_at)`); } catch {}
    try { await pool.query(`CREATE INDEX IF NOT EXISTS reports_reporter_idx ON reports (reporter_id, created_at)`); } catch {}
    // stale_checked may be missing on tables that predate it
    try { await pool.query(`ALTER TABLE reports ADD COLUMN IF NOT EXISTS stale_checked BOOLEAN NOT NULL DEFAULT FALSE`); } catch {}
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bans (
        id         BIGSERIAL PRIMARY KEY,
        user_id    BIGINT  NOT NULL,
        reason     TEXT    NOT NULL,
        tier       TEXT    NOT NULL,                 -- 'day' | 'week' | 'month' | 'year'
        is_guest   BOOLEAN NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL,
        cleared    BOOLEAN NOT NULL DEFAULT FALSE    -- manual unban flag
      );`);
    try { await pool.query(`CREATE INDEX IF NOT EXISTS bans_active_idx ON bans (user_id, expires_at)`); } catch {}

    await pool.query(`
      CREATE TABLE IF NOT EXISTS matches (
        id              BIGSERIAL PRIMARY KEY,
        player_a        BIGINT NOT NULL,
        player_b        BIGINT NOT NULL,
        score_a         INTEGER NOT NULL,
        score_b         INTEGER NOT NULL,
        outcome_a       TEXT NOT NULL,
        rating_a_before INTEGER NOT NULL,
        rating_a_after  INTEGER NOT NULL,
        rating_b_before INTEGER NOT NULL,
        rating_b_after  INTEGER NOT NULL
      );`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS friends (
        user_id   BIGINT NOT NULL,
        friend_id BIGINT NOT NULL,
        UNIQUE (user_id, friend_id)
      );`);
  }

  // Resolve a browser to an account. Known token -> that user. Otherwise mint a
  // fresh account + token (the client adopts whatever token we return).
  async function getOrCreateUser({ token, name }) {
    if (token) {
      const { rows } = await pool.query("SELECT * FROM users WHERE token = $1", [token]);
      if (rows.length) return rows[0];
    }
    const newToken = crypto.randomUUID();
    const { rows } = await pool.query(
      "INSERT INTO users (name, token, friend_code) VALUES ($1, $2, $3) RETURNING *",
      [safeName(name), newToken, genCode()]
    );
    return rows[0];
  }

  // ---- account linking (better-auth) ----
  // The game keeps its own users table as the source of truth for rating/friends/etc.;
  // auth_id is the only bridge to a better-auth account. Guests never touch these.
  async function getUserByAuthId(authId) {
    if (!authId) return null;
    const { rows } = await pool.query("SELECT * FROM users WHERE auth_id = $1", [authId]);
    return rows[0] || null;
  }

  // Create the game user for a freshly signed-in account. Called only once we have the
  // screenname the player chose (accounts start clean — no guest rating is carried over).
  // ON CONFLICT makes it race-safe if two sockets authenticate the new account at once.
  async function createAuthedUser({ authId, name }) {
    const token = crypto.randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO users (name, token, friend_code, auth_id) VALUES ($1, $2, $3, $4)
         ON CONFLICT (auth_id) DO UPDATE SET name = users.name
       RETURNING *`,
      [safeName(name), token, genCode(), authId]
    );
    return rows[0];
  }

  // ---- moderation persistence (policy math lives in moderation.mjs) ----

  // Record a report. Dedup index makes a second report of the same target in the same match
  // a no-op, so heat can't be double-counted. -> { inserted, duplicate }.
  async function insertReport(r) {
    const { rows } = await pool.query(
      `INSERT INTO reports
         (reporter_id, reported_id, game_id, reason, detail, reporter_trusted,
          reporter_trust, reporter_guest, reported_guest, reporter_ip_hash, needs_review)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (reporter_id, reported_id, game_id) DO NOTHING
       RETURNING id`,
      [r.reporter_id, r.reported_id, r.game_id, r.reason, r.detail ?? null,
       r.reporter_trusted, r.reporter_trust, r.reporter_guest, r.reported_guest,
       r.reporter_ip_hash ?? null, r.needs_review ?? false]);
    return rows.length ? { inserted: true, id: rows[0].id, duplicate: false }
                       : { inserted: false, duplicate: true };
  }

  // Reports against a target since a cutoff — the raw material for heat.
  async function getReportCluster(reportedId, sinceTs) {
    const { rows } = await pool.query(
      `SELECT reporter_id, reason, reporter_trust, reporter_guest, needs_review, created_at
         FROM reports WHERE reported_id = $1 AND created_at >= $2`,
      [reportedId, sinceTs]);
    return rows;
  }

  async function getActiveBan(userId) {
    const { rows } = await pool.query(
      `SELECT * FROM bans WHERE user_id = $1 AND cleared = FALSE AND expires_at > now()
        ORDER BY expires_at DESC LIMIT 1`, [userId]);
    return rows[0] || null;
  }

  async function countPriorBans(userId) {
    const { rows } = await pool.query(`SELECT count(*)::int AS n FROM bans WHERE user_id = $1`, [userId]);
    return rows[0]?.n || 0;
  }

  async function issueBan({ userId, tier, reason, isGuest, expiresAt }) {
    const { rows } = await pool.query(
      `INSERT INTO bans (user_id, reason, tier, is_guest, expires_at)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [userId, reason, tier, isGuest, expiresAt]);
    return rows[0];
  }

  // Atomic clamp in SQL so concurrent adjustments can't drift past bounds. The guest ceiling
  // (auth_id IS NULL) is tighter than the account ceiling.
  async function adjustTrust(userId, delta) {
    const { rows } = await pool.query(
      `UPDATE users SET trust_score = LEAST(
           CASE WHEN auth_id IS NULL THEN $2 ELSE $3 END,
           GREATEST($4, trust_score + $1))
        WHERE id = $5 RETURNING trust_score`,
      [delta, TRUST_MAX_GUEST, TRUST_MAX, TRUST_MIN, userId]);
    return rows[0]?.trust_score ?? null;
  }

  async function getTrust(userId) {
    const { rows } = await pool.query(`SELECT trust_score FROM users WHERE id = $1`, [userId]);
    return rows[0]?.trust_score ?? 50;
  }

  async function recentReportsBy(reporterId, sinceTs) {
    const { rows } = await pool.query(
      `SELECT id, reported_id, reason, created_at FROM reports
        WHERE reporter_id = $1 AND created_at >= $2 ORDER BY created_at DESC`,
      [reporterId, sinceTs]);
    return rows;
  }

  async function gamesPlayed(userId) {
    const { rows } = await pool.query(`SELECT games FROM users WHERE id = $1`, [userId]);
    return rows[0]?.games ?? 0;
  }

  // A reporter's own aged reports that no other distinct reporter ever backed up and that we
  // haven't charged for staleness yet. Evaluated lazily on the reporter's next report (no cron).
  async function agingUncorroboratedReports(reporterId, beforeTs) {
    const { rows } = await pool.query(
      `SELECT r.id, r.reported_id FROM reports r
        WHERE r.reporter_id = $1 AND r.created_at < $2 AND r.stale_checked = FALSE
          AND NOT EXISTS (
            SELECT 1 FROM reports o
             WHERE o.reported_id = r.reported_id AND o.reporter_id <> r.reporter_id)`,
      [reporterId, beforeTs]);
    return rows;
  }
  async function markStaleChecked(ids) {
    if (!ids || !ids.length) return;
    await pool.query(`UPDATE reports SET stale_checked = TRUE WHERE id = ANY($1)`, [ids]);
  }

  // The whole rating update in one transaction: read both ratings, compute Elo,
  // update both users, insert the match record. All or nothing.
  async function recordMatch(aId, bId, rawScoreA, rawScoreB) {
    // Laugh points come in fractional (the amusement integral); the columns are INTEGER.
    const scoreA = Math.round(rawScoreA);
    const scoreB = Math.round(rawScoreB);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const a = (await client.query("SELECT * FROM users WHERE id = $1", [aId])).rows[0];
      const b = (await client.query("SELECT * FROM users WHERE id = $1", [bId])).rows[0];

      const resultA = resultFromScores(scoreA, scoreB);
      const { a: newA, b: newB } = updatedRatings(a.rating, b.rating, resultA);
      const outA = resultA === 1 ? "win" : resultA === 0 ? "lose" : "draw";

      const bump = (id, rating, r) => client.query(
        `UPDATE users SET rating = $1, games = games + 1,
           wins = wins + $2, losses = losses + $3, draws = draws + $4 WHERE id = $5`,
        [rating, r === 1 ? 1 : 0, r === 0 ? 1 : 0, r === 0.5 ? 1 : 0, id]
      );
      await bump(aId, newA, resultA);
      await bump(bId, newB, 1 - resultA);

      await client.query(
        `INSERT INTO matches
           (player_a, player_b, score_a, score_b, outcome_a,
            rating_a_before, rating_a_after, rating_b_before, rating_b_after)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [aId, bId, scoreA, scoreB, outA, a.rating, newA, b.rating, newB]
      );

      await client.query("COMMIT");
      return {
        a: { before: a.rating, after: newA, delta: newA - a.rating, outcome: outA },
        b: { before: b.rating, after: newB, delta: newB - b.rating,
             outcome: outA === "win" ? "lose" : outA === "lose" ? "win" : "draw" },
      };
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }

  // Duos rating: each of the 4 players is updated INDIVIDUALLY, as if they'd played a solo
  // game against the average rating of the opposing team. Both teammates share an outcome
  // (their team won/lost/drew) but get different deltas based on their own rating. No 2v2
  // match row is written (the matches table is 1v1-shaped); only ratings + W/L/D/games move.
  // teamA / teamB are arrays of two user ids; scores are the team scores.
  async function recordDuosRatings(teamA, teamB, rawScoreA, rawScoreB) {
    const scoreA = Math.round(rawScoreA), scoreB = Math.round(rawScoreB);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const load = async ids => {
        const out = [];
        for (const id of ids) out.push((await client.query("SELECT * FROM users WHERE id = $1", [id])).rows[0]);
        return out;
      };
      const a = await load(teamA), b = await load(teamB);
      const resultA = resultFromScores(scoreA, scoreB);          // 1 / 0.5 / 0 for team A
      const avg = arr => arr.reduce((s, u) => s + u.rating, 0) / arr.length;
      const avgA = avg(a), avgB = avg(b);
      const results = {};
      const apply = async (players, oppAvg, result) => {
        const outcome = result === 1 ? "win" : result === 0 ? "lose" : "draw";
        for (const u of players) {
          const { a: after } = updatedRatings(u.rating, oppAvg, result);   // .a = this player's new rating
          await client.query(
            `UPDATE users SET rating = $1, games = games + 1,
               wins = wins + $2, losses = losses + $3, draws = draws + $4 WHERE id = $5`,
            [after, result === 1 ? 1 : 0, result === 0 ? 1 : 0, result === 0.5 ? 1 : 0, u.id]
          );
          results[String(u.id)] = { before: u.rating, after, delta: after - u.rating, outcome };
        }
      };
      await apply(a, avgB, resultA);
      await apply(b, avgA, 1 - resultA);
      await client.query("COMMIT");
      return results;                                            // { userId(str) -> {before, after, delta, outcome} }
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }

  async function topPlayers(n = 10) {
    const { rows } = await pool.query(
      "SELECT name, rating, wins, losses FROM users ORDER BY rating DESC, games DESC LIMIT $1",
      [n]
    );
    return rows;
  }

  async function getUserByToken(token) {
    if (!token) return null;
    const { rows } = await pool.query("SELECT * FROM users WHERE token = $1", [token]);
    return rows[0] || null;
  }

  // a player's recent matches, each normalized to THAT player's point of view
  async function recentMatches(userId, n = 10) {
    const { rows } = await pool.query(
      `SELECT m.*, ua.name AS name_a, ub.name AS name_b
         FROM matches m
         JOIN users ua ON ua.id = m.player_a
         JOIN users ub ON ub.id = m.player_b
        WHERE m.player_a = $1 OR m.player_b = $1
        ORDER BY m.id DESC LIMIT $2`,
      [userId, n]
    );
    return rows.map(r => {
      const meA = String(r.player_a) === String(userId);
      const before = meA ? r.rating_a_before : r.rating_b_before;
      const after  = meA ? r.rating_a_after  : r.rating_b_after;
      let outcome = r.outcome_a;                                   // stored from A's view
      if (!meA) outcome = outcome === "win" ? "lose" : outcome === "lose" ? "win" : "draw";
      return {
        opponent: meA ? r.name_b : r.name_a,
        outcome, before, after, delta: after - before,
        scoreMe:   meA ? r.score_a : r.score_b,
        scoreThem: meA ? r.score_b : r.score_a,
      };
    });
  }

  async function getUserById(id) {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    return rows[0] || null;
  }

  // Add a friend by their shareable code. Mutual + idempotent (two directed rows).
  async function addFriendByCode(userId, code) {
    let norm = (code || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (norm.length === 6) norm = norm.slice(0, 3) + "-" + norm.slice(3);
    if (!norm) return { ok: false, reason: "empty" };
    const { rows } = await pool.query("SELECT * FROM users WHERE friend_code = $1", [norm]);
    const friend = rows[0];
    if (!friend) return { ok: false, reason: "not_found" };
    if (String(friend.id) === String(userId)) return { ok: false, reason: "self" };
    const link = async (a, b) => {
      const { rows: ex } = await pool.query("SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2", [a, b]);
      if (!ex.length) await pool.query("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)", [a, b]);
    };
    await link(userId, friend.id);
    await link(friend.id, userId);
    return { ok: true, friend: { id: friend.id, name: friend.name, rating: friend.rating } };
  }

  async function listFriends(userId) {
    const { rows } = await pool.query(
      `SELECT u.id, u.name, u.rating, u.friend_code
         FROM friends f JOIN users u ON u.id = f.friend_id
        WHERE f.user_id = $1
        ORDER BY u.name ASC`,
      [userId]
    );
    return rows;
  }

  return { initSchema, getOrCreateUser, getUserByAuthId, createAuthedUser, recordMatch, recordDuosRatings, topPlayers, getUserByToken, recentMatches, getUserById, addFriendByCode, listFriends,
    insertReport, getReportCluster, getActiveBan, countPriorBans, issueBan, adjustTrust, getTrust, recentReportsBy, gamesPlayed, agingUncorroboratedReports, markStaleChecked };
}
