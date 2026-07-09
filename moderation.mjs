// Pure moderation policy: reporter trust math, cluster "heat", ban tiers, and the shared
// text-moderation chokepoint (usernames / chat / report detail).
// No database, no network — values in, decisions out (mirrors elo.mjs).
// EVERY tunable lives here as a named constant so Xander can retune in one place.
import { SLURS, PROFANITY, RESERVED } from "./blocklist.mjs";

// ---- time units (ms) ----
const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;

// ---- reporter trust (0..100) ----
export const TRUST_MIN = 0;
export const TRUST_MAX = 100;
export const TRUST_DEFAULT = 50;            // matches the users.trust_score column default
export const TRUST_DEFAULT_GUEST = 40;      // guests are less accountable, so they start lower
export const TRUST_MAX_GUEST = 60;          // ...and can never climb as high as an account
export const TRUSTED_THRESHOLD = 70;        // >= this -> a report's reporter_trusted snapshot is true

// ---- trust deltas (applied on named events) ----
export const CORROB_WINDOW = 72 * HOUR;     // window in which a second distinct reporter "corroborates"
export const CORROB_BONUS = 5;              // + to each corroborating reporter
export const BAN_ASSIST_BONUS = 10;         // + when your report contributed to a confirmed ban
export const SPAM_LIMIT = 5;                // more than this many reports...
export const SPAM_WINDOW = 30 * MIN;        // ...within this window is spam
export const SPAM_PENALTY = 10;             // - and the excess report is rejected
export const OVERREPORT_RATE = 0.5;         // reports/games over 7d above this = trigger-happy
export const OVERREPORT_PENALTY = 3;        // - on each further report while over the rate
export const STALE_PENALTY = 3;             // - for a report that never got corroborated (lazy, capped)
export const REPORTED_PENALTY = 8;          // - to a user's OWN trust when they get banned (bad actors report badly)
export const CHAT_VIOLATION_PENALTY = 4;    // - to a user's trust for each hard-blocked (slur) chat line

// ---- ban thresholds (weighted, distinct-reporter "heat") ----
// Windows differ: logged-in offenses accumulate over 3 days; guests only over a day/session.
export const WINDOW_AUTHED = 72 * HOUR;
export const WINDOW_GUEST = 24 * HOUR;
export const HEAT_AUTHED = 3.0;             // logged-in ban threshold
export const HEAT_AUTHED_SEVERE = 6.0;      // a big, high-trust cluster bumps the tier up one
export const HEAT_GUEST = 2.0;              // guests ban at a LOWER bar (fewer reporters needed)

// Progressive tiers, low -> high. Logged-in escalation walks this by prior-ban count.
export const TIERS = ["day", "week", "month", "year"];
const TIER_MS = { day: DAY, week: 7 * DAY, month: 30 * DAY, year: 365 * DAY };

// Guest IP clustering is DETECTION-ONLY. Never gate matchmaking on an IP hash (CGNAT / campus /
// shared IPs would sweep up innocents). Left OFF as a constant so it's a one-line future toggle.
export const AUTO_IP_BAN = false;

// severity of the report reason toward heat. "other" is freetext -> low weight + manual review.
export function severityWeight(reason) {
  if (reason === "harassment") return 1.5;
  if (reason === "cheating") return 1.0;
  return 0.6;                                // "other"
}

// how much a reporter's word counts, by their trust. Guests are capped at 1.0 (no trusted bonus).
export function trustWeight(trust, guest = false) {
  let w = trust >= TRUSTED_THRESHOLD ? 1.5 : trust < 30 ? 0.4 : 1.0;
  if (guest) w = Math.min(w, 1.0);
  return w;
}

// Heat = sum over DISTINCT reporters of that reporter's single MAX weighted contribution.
// Distinct-reporter is the anti-abuse core: one person can't manufacture a ban by spamming —
// it takes a cluster of different people. cluster = [{ reporterId, trust, guest, reason }, ...].
export function heatOf(cluster = []) {
  const best = new Map();                    // reporterId -> their max single weight
  for (const r of cluster) {
    const w = trustWeight(r.trust, r.guest) * severityWeight(r.reason);
    const key = String(r.reporterId);
    if (!best.has(key) || w > best.get(key)) best.set(key, w);
  }
  let sum = 0;
  for (const w of best.values()) sum += w;
  return sum;
}

// dominant reason among a set of reports, weighted by severity (ties -> the more severe reason).
function dominantReason(reports = []) {
  const acc = new Map();
  for (const r of reports) acc.set(r.reason, (acc.get(r.reason) || 0) + severityWeight(r.reason));
  let best = null, bestScore = -1;
  for (const [reason, score] of acc) {
    if (score > bestScore || (score === bestScore && severityWeight(reason) > severityWeight(best))) {
      best = reason; bestScore = score;
    }
  }
  return best;
}

// The one ban decision. Server just persists whatever this returns.
//   cluster: [{ reporterId, trust, guest, reason }] already narrowed to the target's window.
// Manual-review guard: only STRUCTURED (cheating/harassment) heat can auto-ban; "other" freetext
// merely flags needs_review. So a wall of vague "other" reports never bans on its own.
export function decideBan({ reportedGuest = false, priorBans = 0, cluster = [] } = {}) {
  const structured = cluster.filter(r => r.reason === "cheating" || r.reason === "harassment");
  const heat = heatOf(structured);
  const needsReview = cluster.some(r => r.reason === "other");
  const reason = dominantReason(structured) || "cluster";

  if (reportedGuest) {
    if (heat >= HEAT_GUEST) {
      const tier = priorBans >= 1 ? "week" : "day";   // 1 day first time, 1 week if the same guest re-offends
      return { ban: true, tier, reason, needsReview };
    }
    return { ban: false, tier: null, reason, needsReview };
  }

  // logged-in: progressive by prior bans, with a severity/size bump for large high-trust clusters.
  if (heat >= HEAT_AUTHED) {
    let idx = priorBans <= 0 ? 0 : priorBans === 1 ? 1 : priorBans === 2 ? 2 : 3;
    if (heat >= HEAT_AUTHED_SEVERE) idx = Math.min(idx + 1, TIERS.length - 1);
    return { ban: true, tier: TIERS[idx], reason, needsReview };
  }
  return { ban: false, tier: null, reason, needsReview };
}

// signed trust delta for a named event (see constants above).
export function trustDelta(event) {
  switch (event) {
    case "corroborate": return CORROB_BONUS;
    case "ban_assist":  return BAN_ASSIST_BONUS;
    case "spam":        return -SPAM_PENALTY;
    case "overreport":  return -OVERREPORT_PENALTY;
    case "stale":       return -STALE_PENALTY;
    case "reported":    return -REPORTED_PENALTY;
    case "chat_violation": return -CHAT_VIOLATION_PENALTY;
    default:            return 0;
  }
}

// when a ban of `tier` issued at `now` expires.
export function banExpiry(tier, now = Date.now()) {
  return new Date(now + (TIER_MS[tier] ?? TIER_MS.day));
}

// clamp a trust score into range, applying the tighter guest ceiling when relevant.
export function clampTrust(score, isGuest = false) {
  const hi = isGuest ? TRUST_MAX_GUEST : TRUST_MAX;
  return Math.max(TRUST_MIN, Math.min(hi, Math.round(score)));
}

// is a reporter trigger-happy? reports-per-game over the trailing window above the allowed rate.
export function overReporting(reportCount, games) {
  return reportCount / Math.max(1, games) > OVERREPORT_RATE;
}

// ============================================================================
// Shared text-moderation chokepoint. ALL user-authored text (usernames, chat, report detail)
// goes through moderateText on the server before it is stored or shown to anyone. Pure + tunable.
// ============================================================================

// ---- per-context length bounds ----
export const USERNAME_MIN = 3, USERNAME_MAX = 20;
export const CHAT_MIN = 1, CHAT_MAX = 200;
export const DETAIL_MIN = 1, DETAIL_MAX = 500;

// ---- chat behavior tunables (flood/dup/mute; the transport rate limit lives in ratelimit.mjs) ----
export const ALLOW_CHAT_LINKS = false;      // URLs in chat are a scam/grooming vector — blocked by default
export const CHAT_DUP_WINDOW = 4000;        // identical back-to-back message within this (ms) = spam
export const CHAT_MUTE_STRIKES = 3;         // hard-blocked lines before a short auto-mute
export const CHAT_MUTE_MS = 60_000;         // how long that mute lasts

// Usernames: letters, digits, and a short set of safe separators. HTML metacharacters
// (< > & " ' /) and everything else are rejected — the first layer of the anti-XSS defense.
const USERNAME_RE = /^[A-Za-z0-9 _.\-]+$/;

// Control chars (C0 + DEL), zero-width, BOM, word-joiner — evasion/homoglyph tools. Built from an
// ASCII escape string so this file contains no literal control characters.
const STRIP_RE = new RegExp("[\\u0000-\\u001F\\u007F\\u200B-\\u200D\\u2060\\uFEFF]", "g");

// Leet folding so "h4te"/"sh1t" normalize to letters before blocklist matching.
const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i", "|": "i" };
const LEET_RE = /[0134578@$!|]/g;
const leetFold = s => s.toLowerCase().replace(LEET_RE, c => LEET[c] || c);

const SLUR_SET = new Set(SLURS.map(s => s.toLowerCase()));
const PROFANITY_SET = new Set(PROFANITY.map(s => s.toLowerCase()));
const RESERVED_SET = new Set(RESERVED.map(s => s.toLowerCase()));
// Bare-domain / URL sniff for chat (kept deliberately broad; tune the TLD tail as needed).
const URL_RE = /(https?:\/\/|www\.|\b[a-z0-9-]+\.(?:com|net|org|io|gg|xyz|co|me|tv|ru|link|to|app|dev|info|biz|live|online|site|club|shop)\b)/i;

// Normalize once: NFC (fold composed forms), strip control/zero-width, collapse whitespace, trim.
function normalize(raw) {
  return String(raw ?? "").normalize("NFC").replace(STRIP_RE, "").replace(/\s+/g, " ").trim();
}

// Slur present? word-boundary match on the leet-folded text, plus a separator-stripped pass so
// "n-i-g..." style spacing is caught. Returns boolean only (callers log a rule id, never the term).
function hasSlur(text) {
  const folded = leetFold(text);
  const words = folded.split(/[^a-z0-9]+/).filter(Boolean);
  if (words.some(w => SLUR_SET.has(w))) return true;
  const collapsed = folded.replace(/[^a-z]/g, "");
  for (const s of SLUR_SET) if (s.length >= 4 && collapsed.includes(s)) return true;
  return false;
}
// Whole-word profanity only (no substrings -> no Scunthorpe problem).
function hasProfanityWord(text) {
  const words = new Set(leetFold(text).split(/[^a-z0-9]+/).filter(Boolean));
  for (const p of PROFANITY_SET) if (words.has(p)) return true;
  return false;
}
// Replace whole-word profanity (incl. simple leet spellings) with same-length asterisks.
function redactProfanity(text) {
  return text.replace(/[A-Za-z0-9@$!|]+/g, tok => (PROFANITY_SET.has(leetFold(tok)) ? "*".repeat(tok.length) : tok));
}
// Reserved / impersonation name? Check two cores so both "adm1n" (leet in the middle) and
// "admin1"/"admin_" (trailing digits/separators) are caught: one leet-folded, one raw-with-trailing-
// digits-stripped (folding a trailing digit would otherwise turn "admin1" into "admini").
function isReserved(name) {
  const rawCore = name.toLowerCase().replace(/[^a-z0-9]/g, "").replace(/[0-9]+$/, "");
  const foldCore = leetFold(name).replace(/[^a-z0-9]/g, "").replace(/[0-9]+$/, "");
  return RESERVED_SET.has(rawCore) || RESERVED_SET.has(foldCore);
}

const fail = (reason) => ({ ok: false, cleaned: null, reason });

// moderateText(raw, { context }) -> { ok, cleaned, reason } (+ `rule` on a hard block, for logging).
//   context: 'username' | 'chat' | 'report_detail'
// Server is authoritative — never trust the client to have filtered. `cleaned` is the value to
// store/broadcast. Reasons: 'empty' | 'too_short' | 'too_long' | 'charset' | 'reserved' |
// 'blocked' | 'nolinks'.
export function moderateText(raw, { context } = {}) {
  const cleaned = normalize(raw);

  if (context === "username") {
    if (cleaned.length < USERNAME_MIN) return fail(cleaned ? "too_short" : "empty");
    if (cleaned.length > USERNAME_MAX) return fail("too_long");
    if (!USERNAME_RE.test(cleaned)) return fail("charset");
    if (!/[a-z0-9]/i.test(cleaned)) return fail("charset");       // must have an alphanumeric (no separator/emoji-only)
    if (isReserved(cleaned)) return fail("reserved");
    if (hasSlur(cleaned)) return { ok: false, cleaned: null, reason: "blocked", rule: "slur" };
    if (hasProfanityWord(cleaned)) return { ok: false, cleaned: null, reason: "blocked", rule: "profanity" };
    return { ok: true, cleaned, reason: null };
  }

  if (context === "chat") {
    if (cleaned.length < CHAT_MIN) return fail("empty");
    let text = cleaned.slice(0, CHAT_MAX);
    if (!ALLOW_CHAT_LINKS && URL_RE.test(text)) return fail("nolinks");
    if (hasSlur(text)) return { ok: false, cleaned: null, reason: "blocked", rule: "slur" };
    return { ok: true, cleaned: redactProfanity(text), reason: null };   // profanity is redacted, not blocked
  }

  if (context === "report_detail") {
    // A reporter may legitimately quote the abuse they're reporting, so no blocklist here — just
    // normalize, require some content, and cap. (No links check: quoting a link can be evidence.)
    if (cleaned.length < DETAIL_MIN) return fail("empty");
    return { ok: true, cleaned: cleaned.slice(0, DETAIL_MAX), reason: null };
  }

  // unknown context: safest default — plain, normalized, capped.
  return { ok: true, cleaned: cleaned.slice(0, CHAT_MAX), reason: null };
}
