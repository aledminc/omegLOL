import crypto from "node:crypto";
import { resultFromScores, updatedRatings } from "./elo.mjs";

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
    const safeName = (name || "Anon").trim().slice(0, 24) || "Anon";
    const { rows } = await pool.query(
      "INSERT INTO users (name, token, friend_code) VALUES ($1, $2, $3) RETURNING *",
      [safeName, newToken, genCode()]
    );
    return rows[0];
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

  return { initSchema, getOrCreateUser, recordMatch, topPlayers, getUserByToken, recentMatches, getUserById, addFriendByCode, listFriends };
}
