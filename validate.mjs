// Central input validation + the ONE text gate for user-authored strings.
//
// Every inbound WebSocket message passes through validateMessage() BEFORE dispatch, so a
// hand-crafted socket can't reach a handler with a wrong-shaped payload. Everything here is
// pure (no I/O), so it's unit-testable and shared by the server and db layers.
//
// Rule of thumb: assume the client is hostile. Unknown type, wrong value type, out-of-range
// number, oversized string, or non-enum reason => reject. We never trust JSON.parse output.

// ---- length caps (named, so the DB, server, and client agree on one set of limits) ----
export const NAME_MAX   = 24;    // screennames (matches the users table slice)
export const CHAT_MAX   = 200;   // one chat line
export const DETAIL_MAX = 500;   // report freetext ('other')
export const CODE_MAX   = 16;    // friend code input ("K7M-3PQ" + slack)
export const TOKEN_MAX  = 200;   // guest/game token (a UUID is ~36)
export const SDP_MAX    = 32 * 1024;  // a serialized SDP/candidate blob we only relay

export const REPORT_REASONS = ["cheating", "harassment", "other"];
export const REACTION_TIERS = ["small", "big", "laugh"];

// Control chars (C0 + DEL) and zero-width / BOM code points, stripped from all user text.
// Built from an ASCII escape string so this source file contains no literal control characters.
const STRIP_RE = new RegExp("[\\u0000-\\u001F\\u007F\\u200B-\\u200D\\uFEFF]", "g");

// Canonical HTML escaper. Output encoding is the real XSS defense — user text is escaped or
// set via textContent at render time, never interpolated raw into innerHTML.
export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// The single text gate. Coerce to string, strip control/zero-width characters, collapse runs of
// whitespace, trim, and hard-cap the length. Used for names, chat, and report detail so there is
// exactly one place that decides what "clean text" means. It does NOT strip angle brackets — a
// name like "<3" is legitimate; the DOM layer escapes on output instead.
export function cleanText(s, max) {
  return String(s ?? "")
    .replace(STRIP_RE, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, Math.max(0, max | 0));
}

const isObj  = v => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr  = v => typeof v === "string";
// A non-negative safe integer id (connection ids are small; user ids are BIGINT but bounded).
const isId   = v => (typeof v === "number" || typeof v === "string") &&
                    Number.isInteger(+v) && +v >= 0 && +v <= Number.MAX_SAFE_INTEGER;
const strOk  = (v, max) => isStr(v) && v.length <= max;
// A signaling blob (SDP/candidate) we only relay: must be a smallish object, never interpreted.
const blobOk = v => isObj(v) && JSON.stringify(v).length <= SDP_MAX;
const cuePointsOk = v => Array.isArray(v) && (v.length === 0 || v.length === 6) &&
  v.every(p => Array.isArray(p) && p.length === 2 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 1000));

// Per-type shape guards. Each returns true iff the message body is acceptable. Missing entry =>
// unknown type => rejected. Optional fields are only checked when present.
const SCHEMA = {
  auth:          m => (m.token === undefined || strOk(m.token, TOKEN_MAX)) &&
                      (m.name  === undefined || m.name === null || strOk(m.name, NAME_MAX * 4)),
  leaderboard:   () => true,
  find:          () => true,
  cancelSearch:  () => true,
  next:          () => true,
  leaveMatch:    () => true,
  friends:       () => true,
  leaveLobby:    () => true,
  queueDuos:     () => true,
  cancelDuos:    () => true,
  reaction:      m => (m.delta === undefined || (typeof m.delta === "number" && Number.isFinite(m.delta))) &&
                      (m.tier  === undefined || REACTION_TIERS.includes(m.tier)),
  faceCue:       m => typeof m.tracked === "boolean" && typeof m.active === "boolean" &&
                      cuePointsOk(m.points) && (m.tracked ? m.points.length === 6 : m.points.length === 0),
  chat:          m => strOk(m.text ?? "", CHAT_MAX * 4),   // generous pre-clean cap; cleanText trims to CHAT_MAX
  rtcStat:       m => typeof m.ok === "boolean",           // peer-connection outcome (observability counter)
  sound:         m => strOk(m.id ?? "", 64),               // soundboard trigger: catalog id only, no audio
  clipPref:      m => typeof m.enabled === "boolean",      // client's clip-consent state (match gating)
  addFriend:     m => strOk(m.code ?? "", CODE_MAX * 2),   // sends a friend REQUEST (accepted via acceptFriend)
  friendRequests: () => true,
  acceptFriend:  m => isId(m.fromId),
  declineFriend: m => isId(m.fromId),
  removeFriend:  m => isId(m.friendId),
  invite:        m => isId(m.friendId),
  acceptInvite:  m => isId(m.fromId),
  declineInvite: m => isId(m.fromId),
  report:        m => isId(m.target) && REPORT_REASONS.includes(m.reason) &&
                      (m.detail === undefined || m.detail === null || strOk(m.detail, DETAIL_MAX * 4)),
  offer:         m => isId(m.target) && blobOk(m.sdp),
  answer:        m => isId(m.target) && blobOk(m.sdp),
  candidate:     m => isId(m.target) && blobOk(m.candidate),
};

export const MSG_TYPES = new Set(Object.keys(SCHEMA));

// Validate a parsed message. Returns the type string when valid, or null (caller ignores/limits).
export function validateMessage(msg) {
  if (!isObj(msg) || !isStr(msg.type)) return null;
  const check = SCHEMA[msg.type];
  if (!check) return null;
  try { return check(msg) ? msg.type : null; }
  catch { return null; }
}
