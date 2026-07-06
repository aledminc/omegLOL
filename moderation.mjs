// Pure moderation policy: reporter trust math, cluster "heat", and ban tiers.
// No database, no network — numbers/objects in, decisions out (mirrors elo.mjs).
// EVERY tunable lives here as a named constant so Xander can retune in one place.

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
