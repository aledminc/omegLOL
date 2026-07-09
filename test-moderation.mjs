// Unit tests for the pure moderation policy (moderation.mjs). No DB, no server.
// Run: node test-moderation.mjs
import assert from "node:assert/strict";
import {
  trustWeight, severityWeight, heatOf, decideBan, trustDelta, banExpiry, clampTrust, overReporting, moderateText,
  TRUSTED_THRESHOLD, HEAT_AUTHED, HEAT_GUEST, HEAT_AUTHED_SEVERE,
  CORROB_BONUS, BAN_ASSIST_BONUS, SPAM_PENALTY, REPORTED_PENALTY, OVERREPORT_PENALTY, STALE_PENALTY,
  TRUST_MAX, TRUST_MIN, TRUST_MAX_GUEST, CHAT_VIOLATION_PENALTY,
} from "./moderation.mjs";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log("  ok -", name); };

console.log("moderation.mjs pure policy");

// ---- weights ----
t("trustWeight tiers", () => {
  assert.equal(trustWeight(80), 1.5);            // trusted
  assert.equal(trustWeight(TRUSTED_THRESHOLD), 1.5);
  assert.equal(trustWeight(50), 1.0);            // normal
  assert.equal(trustWeight(30), 1.0);
  assert.equal(trustWeight(29), 0.4);            // low
});
t("trustWeight caps guests at 1.0 (no trusted bonus)", () => {
  assert.equal(trustWeight(90, true), 1.0);
  assert.equal(trustWeight(50, true), 1.0);
  assert.equal(trustWeight(10, true), 0.4);      // low still applies
});
t("severityWeight", () => {
  assert.equal(severityWeight("harassment"), 1.5);
  assert.equal(severityWeight("cheating"), 1.0);
  assert.equal(severityWeight("other"), 0.6);
});

// ---- heat: distinct-reporter, max-per-reporter ----
t("heatOf sums distinct reporters' max single weight", () => {
  // two distinct normal reporters, cheating -> 1.0 + 1.0 = 2.0
  assert.equal(heatOf([
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
  ]), 2.0);
});
t("heatOf collapses one reporter's many reports to their max", () => {
  // same reporter twice: max(cheating 1.0, harassment 1.5) = 1.5, not 2.5
  assert.equal(heatOf([
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 1, trust: 50, guest: false, reason: "harassment" },
  ]), 1.5);
});
t("heatOf: a lone spammer cannot build heat", () => {
  const spam = Array.from({ length: 20 }, () => ({ reporterId: 7, trust: 90, guest: false, reason: "harassment" }));
  assert.equal(heatOf(spam), 2.25);              // 20 reports collapse to ONE contribution (1.5*1.5)
  assert.ok(heatOf(spam) < HEAT_AUTHED);         // ...and one person still can't reach the ban bar
});

// ---- decideBan: logged-in ----
t("authed: a distinct-reporter cluster crossing HEAT_AUTHED bans at 1 day (prior=0)", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 3, trust: 50, guest: false, reason: "cheating" },
  ]; // heat 3.0 == HEAT_AUTHED
  const d = decideBan({ reportedGuest: false, priorBans: 0, cluster });
  assert.equal(d.ban, true);
  assert.equal(d.tier, "day");
});
t("authed: below threshold does not ban", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
  ]; // heat 2.0 < 3.0
  assert.equal(decideBan({ reportedGuest: false, priorBans: 0, cluster }).ban, false);
});
t("authed: progressive tiers by prior bans", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 3, trust: 50, guest: false, reason: "cheating" },
  ];
  assert.equal(decideBan({ reportedGuest: false, priorBans: 0, cluster }).tier, "day");
  assert.equal(decideBan({ reportedGuest: false, priorBans: 1, cluster }).tier, "week");
  assert.equal(decideBan({ reportedGuest: false, priorBans: 2, cluster }).tier, "month");
  assert.equal(decideBan({ reportedGuest: false, priorBans: 3, cluster }).tier, "year");
  assert.equal(decideBan({ reportedGuest: false, priorBans: 9, cluster }).tier, "year");
});
t("authed: severe cluster bumps one tier up", () => {
  // 4 trusted reporters harassment: 4 * 1.5 * 1.5 = 9.0 >= HEAT_AUTHED_SEVERE(6)
  const cluster = [1, 2, 3, 4].map(id => ({ reporterId: id, trust: 90, guest: false, reason: "harassment" }));
  assert.ok(heatOf(cluster) >= HEAT_AUTHED_SEVERE);
  assert.equal(decideBan({ reportedGuest: false, priorBans: 0, cluster }).tier, "week");   // day -> week
  assert.equal(decideBan({ reportedGuest: false, priorBans: 3, cluster }).tier, "year");   // already max, stays
});

// ---- decideBan: guests ----
t("guest: lower threshold bans where the same count would NOT ban an account", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
  ]; // heat 2.0
  assert.equal(decideBan({ reportedGuest: true,  priorBans: 0, cluster }).ban, true);   // guest bar 2.0
  assert.equal(decideBan({ reportedGuest: false, priorBans: 0, cluster }).ban, false);  // authed bar 3.0
});
t("guest: 1 day first, 1 week on re-offense", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
  ];
  assert.equal(decideBan({ reportedGuest: true, priorBans: 0, cluster }).tier, "day");
  assert.equal(decideBan({ reportedGuest: true, priorBans: 1, cluster }).tier, "week");
  assert.equal(decideBan({ reportedGuest: true, priorBans: 5, cluster }).tier, "week");
});

// ---- manual-review guard: "other" never auto-bans, only flags ----
t('"other" freetext flags needs_review and never auto-bans alone', () => {
  const cluster = [1, 2, 3, 4, 5].map(id => ({ reporterId: id, trust: 90, guest: false, reason: "other" }));
  const d = decideBan({ reportedGuest: false, priorBans: 0, cluster });
  assert.equal(d.ban, false);
  assert.equal(d.needsReview, true);
});
t("structured heat bans; a trailing 'other' just sets needsReview", () => {
  const cluster = [
    { reporterId: 1, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 2, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 3, trust: 50, guest: false, reason: "cheating" },
    { reporterId: 4, trust: 50, guest: false, reason: "other" },
  ];
  const d = decideBan({ reportedGuest: false, priorBans: 0, cluster });
  assert.equal(d.ban, true);
  assert.equal(d.needsReview, true);
});

// ---- trust deltas / clamp / rate ----
t("trustDelta signs", () => {
  assert.equal(trustDelta("corroborate"), CORROB_BONUS);
  assert.equal(trustDelta("ban_assist"), BAN_ASSIST_BONUS);
  assert.equal(trustDelta("spam"), -SPAM_PENALTY);
  assert.equal(trustDelta("overreport"), -OVERREPORT_PENALTY);
  assert.equal(trustDelta("stale"), -STALE_PENALTY);
  assert.equal(trustDelta("reported"), -REPORTED_PENALTY);
  assert.equal(trustDelta("nope"), 0);
});
t("clampTrust bounds + guest ceiling", () => {
  assert.equal(clampTrust(150), TRUST_MAX);
  assert.equal(clampTrust(-9), TRUST_MIN);
  assert.equal(clampTrust(80, true), TRUST_MAX_GUEST);   // guest capped at 60
  assert.equal(clampTrust(55, true), 55);
});
t("overReporting rate", () => {
  assert.equal(overReporting(6, 10), true);   // 0.6 > 0.5
  assert.equal(overReporting(5, 10), false);  // 0.5 not > 0.5
  assert.equal(overReporting(1, 0), true);    // guards div-by-zero
});
t("banExpiry maps tier -> future date", () => {
  const now = Date.now();
  assert.equal(banExpiry("day", now).getTime(), now + 24 * 3600e3);
  assert.equal(banExpiry("week", now).getTime(), now + 7 * 24 * 3600e3);
  assert.ok(banExpiry("bogus", now).getTime() === now + 24 * 3600e3);   // defaults to day
});

// ---- text moderation chokepoint ----
const uname = s => moderateText(s, { context: "username" });
const chat  = s => moderateText(s, { context: "chat" });
const detail = s => moderateText(s, { context: "report_detail" });

t("username: accepts a clean name, normalizes whitespace", () => {
  assert.deepEqual(uname("  Cool_Guy-7  "), { ok: true, cleaned: "Cool_Guy-7", reason: null });
});
t("username: length bounds", () => {
  assert.equal(uname("ab").reason, "too_short");
  assert.equal(uname("a".repeat(21)).reason, "too_long");
});
t("username: rejects HTML metacharacters (anti-XSS layer 1)", () => {
  assert.equal(uname("hi<b>").reason, "charset");
  assert.equal(uname('a"b').reason, "charset");
  assert.equal(uname("a/b").reason, "charset");
  assert.equal(uname("<img src=x onerror=alert(1)>").ok, false);   // never accepted (too long here, charset if short)
});
t("username: rejects emoji-only / separator-only", () => {
  assert.equal(uname("😀😀😀").ok, false);
  assert.equal(uname("___").reason, "charset");
});
t("username: reserved names + close variants rejected", () => {
  assert.equal(uname("admin").reason, "reserved");
  assert.equal(uname("adm1n").reason, "reserved");
  assert.equal(uname("admin1").reason, "reserved");
  assert.equal(uname("omeglol").reason, "reserved");
});
t("username: slurs and profanity rejected (leet-folded, word-boundary)", () => {
  assert.equal(uname("f4ggot").reason, "blocked");     // slur, whole token (leet-folded)
  assert.equal(uname("fuck_you").reason, "blocked");   // profanity token; word-boundary avoids Scunthorpe
});
t("username: no Scunthorpe false-positives", () => {
  for (const good of ["Scunthorpe", "assassin", "classic", "Dickinson", "shitake_no"]) assert.equal(uname(good).ok, true, good);
});
t("chat: profanity is redacted (not blocked), slurs are blocked", () => {
  assert.equal(chat("you are shit").cleaned, "you are ****");
  assert.equal(chat("sh1t man").cleaned.startsWith("****"), true);
  assert.equal(chat("you nigger").reason, "blocked");
  assert.equal(chat("n i g g e r").ok, false);        // spaced-out evasion caught
});
t("chat: links blocked, zero-width stripped, empty rejected", () => {
  assert.equal(chat("dm me at evil.com").reason, "nolinks");
  assert.equal(chat("http://x.io/p").reason, "nolinks");
  assert.equal(chat("he​llo").cleaned, "hello");
  assert.equal(chat("   ").reason, "empty");
});
t("report_detail: allows quoting abuse, still caps + normalizes", () => {
  assert.equal(detail("he called me a slur (nigger) on cam").ok, true);
  assert.equal(detail("").reason, "empty");
});
t("chat_violation trust delta is negative", () => {
  assert.equal(trustDelta("chat_violation"), -CHAT_VIOLATION_PENALTY);
});

console.log(`\nAll ${n} moderation policy tests passed.`);
