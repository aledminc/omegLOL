// Per-connection WebSocket rate limiting (pure + injectable clock, so it unit-tests).
//
// Each socket gets its own set of token buckets: one GLOBAL bucket that caps total
// messages/second, plus one bucket per message CATEGORY so a client can't, say, flood
// `report`/`chat` even while under the global cap. Signaling (offer/answer/candidate) is
// deliberately loose because a single WebRTC negotiation emits many ICE candidates fast.
//
// A separate "abuse" bucket accumulates a penalty on every dropped message and leaks over
// time; when it overflows we tell the caller to disconnect the socket (sustained abuse, not a
// brief burst). HTTP rate limiting is handled separately by express-rate-limit (see server.mjs).

// bucket = { cap, refill/sec }. tokens are consumed one per message and refill continuously.
const GLOBAL = { cap: 40, refill: 20 };

// Caps are burst tolerances, generous enough that a human playing fast is never clipped and that
// the POLICY layers stay authoritative: report flooding is really governed by moderation's
// SPAM_LIMIT (server-side, trust-docking), so the transport `report` budget only stops a DB-
// hammering flood. The real backstop for sustained abuse of ANY type is the abuse bucket below,
// which closes the socket after ~40 drops.
const LIMITS = {
  signaling:   { cap: 80, refill: 40 },  // WebRTC ICE bursts — loose
  matchmaking: { cap: 20, refill: 4  },  // find / next / queueDuos ...
  social:      { cap: 12, refill: 2  },  // addFriend / invite / accept / decline
  chat:        { cap: 8,  refill: 2  },  // ~8 burst then 2/sec
  report:      { cap: 12, refill: 0.5 }, // above SPAM_LIMIT so the policy gate decides; caps floods
  light:       { cap: 24, refill: 4  },  // auth / leaderboard / friends
};

// Which category each message type draws from. Types absent here fall back to "light".
const CATEGORY = {
  offer: "signaling", answer: "signaling", candidate: "signaling",
  find: "matchmaking", cancelSearch: "matchmaking", next: "matchmaking", leaveMatch: "matchmaking",
  queueDuos: "matchmaking", cancelDuos: "matchmaking",
  addFriend: "social", invite: "social", acceptInvite: "social", declineInvite: "social",
  leaveLobby: "social",
  chat: "chat",
  report: "report",
  reaction: "signaling",  // watchers emit many small reactions during a round — treat like signaling
  faceCue: "signaling",   // quantized mouth landmarks, throttled client-side to about 12/sec
  auth: "light", leaderboard: "light", friends: "light",
};

// Penalty bucket for sustained abuse: each dropped message adds ABUSE_HIT; it leaks ABUSE_LEAK/sec.
// Cross ABUSE_CAP and the socket should be closed.
const ABUSE_CAP  = 40;
const ABUSE_HIT  = 1;
const ABUSE_LEAK = 2;

function newBucket({ cap }, at) { return { tokens: cap, last: at }; }

// Refill by elapsed time, then try to spend one token. Returns true if allowed.
function spend(b, { cap, refill }, at) {
  b.tokens = Math.min(cap, b.tokens + ((at - b.last) / 1000) * refill);
  b.last = at;
  if (b.tokens >= 1) { b.tokens -= 1; return true; }
  return false;
}

// Create a limiter for one connection. `now` is injectable (defaults to Date.now) for tests.
export function makeLimiter(now = Date.now) {
  const at0 = now();
  const global = newBucket(GLOBAL, at0);
  const cats = {};
  for (const [name, cfg] of Object.entries(LIMITS)) cats[name] = { cfg, b: newBucket(cfg, at0) };
  const abuse = { level: 0, last: at0 };

  // check(type) -> { allow, disconnect }. Called once per inbound (validated OR not) message.
  function check(type) {
    const at = now();
    const catName = CATEGORY[type] || "light";
    const cat = cats[catName];
    const okGlobal = spend(global, GLOBAL, at);
    const okCat = spend(cat.b, cat.cfg, at);
    const allow = okGlobal && okCat;

    // leak the abuse level, then add a hit if we just dropped a message
    abuse.level = Math.max(0, abuse.level - ((at - abuse.last) / 1000) * ABUSE_LEAK);
    abuse.last = at;
    if (!allow) abuse.level += ABUSE_HIT;

    return { allow, disconnect: abuse.level >= ABUSE_CAP };
  }

  return { check };
}

export const _internals = { GLOBAL, LIMITS, CATEGORY, ABUSE_CAP };
