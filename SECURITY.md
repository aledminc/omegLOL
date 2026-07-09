# omegLOL — Security

Pre-launch security posture and the human launch checklist. App-level controls live in the code;
infrastructure items (Cloudflare, DB, secret manager, error tracker) are flagged for a human.

## What the app enforces (implemented)

**Rate limiting**
- HTTP: per-IP limits via `express-rate-limit`, keyed off the real client IP (`CF-Connecting-IP`,
  then trusted `X-Forwarded-For`). Strict on `/api/auth/*` (brute force / credential stuffing),
  looser on reads, a general backstop on everything else. Tunings in `security.mjs` (`RATE`).
- WebSocket: per-connection token buckets — a global messages/sec cap plus per-type budgets
  (tight on `report`/`chat`/`social`, loose on signaling). Sustained abuse closes the socket.
  See `ratelimit.mjs`. `express.json({ limit: "16kb" })` caps HTTP bodies; `maxPayload` (64 KB)
  drops oversized WS frames. Max concurrent WS connections per IP is capped (`WS_MAX_CONNS_PER_IP`).
- better-auth's own limiter runs in production as an inner layer (tight custom rules on
  sign-in/sign-up), keyed off `cf-connecting-ip`. Off in dev (no forwarded IP header there; the
  express-rate-limit layer still guards `/api/auth`).

**Input validation & sanitization**
- Every WS message is validated centrally *before* dispatch (`validate.mjs`): known type, correct
  shape/value types, length caps, enum membership (report reason, reaction tier), numeric bounds.
  Malformed/unknown messages are ignored and count toward the rate limiter. JSON.parse output is
  never trusted.
- One text gate: `validate.mjs::cleanText` for transport-level normalization, and the content-policy
  chokepoint `moderation.mjs::moderateText(raw, {context})` (`username` | `chat` | `report_detail`)
  for everything user-authored. It NFC-normalizes, strips control/zero-width chars, enforces
  per-context length, applies a username charset (rejecting HTML metacharacters), and matches a
  leet-folded, word-boundary blocklist (`blocklist.mjs`) that avoids the Scunthorpe problem.
- Usernames: case-insensitively **unique** (dedup migration + `users_name_lower_idx`, race-safe on
  the UNIQUE violation), reserved/impersonation names blocked, collisions re-prompt with suggestions.
- Chat: server-authoritative moderation before broadcast — slurs are hard-blocked (sender-only
  feedback, trust penalty, short mute on repeats), profanity is redacted, links are blocked,
  duplicates suppressed; delivered only to the match/lobby participants. Violations are logged to
  `mod_events` by **rule id, never the raw text**.
- SQL: every query in `db.mjs` is parameterized (`$1,$2,…`); no user input is interpolated into SQL.
- Signaling: `offer`/`answer`/`candidate` are relayed only to a participant of the sender's own
  match/lobby, and SDP/candidate blobs are relayed verbatim, never interpreted.
- XSS: user strings are escaped or set via `textContent`. The known leaderboard/history sinks in
  `ranked.html` are now escaped.

**Headers / transport** (`helmet` + `security.mjs::cspDirectives`)
- CSP locked to `'self'` + the exact CDNs used (jsdelivr for MediaPipe, Google Fonts, the MediaPipe
  model host). `frame-ancestors 'none'` + `X-Frame-Options: DENY` (clickjacking — critical for a
  camera app), `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`. `nosniff`,
  `Referrer-Policy`, and `Permissions-Policy: camera=(self), microphone=(self), geolocation=()`.
- Production: HSTS, `NODE_ENV=production`, http→https redirect, `upgrade-insecure-requests`,
  `x-powered-by` disabled.

**Origin / cross-site**
- WS upgrade enforces an `Origin` allowlist (`ALLOWED_ORIGINS`; blocks cross-site WS hijacking).
  A missing Origin (non-browser client, which can't mount CSWSH) is allowed but still must
  authenticate. The socket authenticates from the session cookie; it can never act for a user it
  didn't authenticate as, and a client-supplied token can never override a real session.

**Auth / session** (`auth.mjs`)
- Password min length 10 (max 128 to avoid slow-hash DoS). Sessions expire in 7 days and roll
  daily. Cookies are httpOnly + SameSite=Lax, Secure in production. `trustedOrigins` (CSRF/redirect)
  reuses the same allowlist. Ban checks gate matchmaking in `findMatch`/`queueDuos` **and** can't be
  bypassed by talking to the WS directly (the gate is server-side, keyed to the authenticated user).

**Resilience**
- Every WS message handler is wrapped so one thrown error can't crash the process; process-level
  `unhandledRejection`/`uncaughtException` guards log and stay up. Heartbeat ping/pong drops dead
  sockets. Graceful shutdown on SIGTERM/SIGINT.

**Secrets / logging**
- All secrets are server-side env only (`.env`, git-ignored; `.env.example` documents every key).
  History scanned — no secret was ever committed. Structured security logging (`logSec`) records
  rate-limit hits, origin rejections, abuse disconnects, and errors **with IPs hashed, never raw**,
  and never logs secrets/session objects/SDP.

### Accepted relaxation (follow-up)
- CSP `script-src`/`style-src` keep `'unsafe-inline'` because the static HTML carries inline
  `<script>`/`<style>` blocks and many `style=""` attributes (no templating layer). There are **no
  inline event handlers**, and output-encoding is the primary XSS defense, so residual risk is low.
  Follow-up: move inline scripts to external files (or nonce them) and drop `'unsafe-inline'` from
  `script-src`. `script-src` also allows `'wasm-unsafe-eval'` (MediaPipe compiles WebAssembly).

## Human launch checklist (infrastructure — not code)

- [ ] **Cloudflare**: proxy on; SSL/TLS mode **Full (Strict)**; WAF + Bot Fight; rate-limiting rules
      as an outer layer; **lock the origin to Cloudflare IP ranges** so `CF-Connecting-IP` can be
      trusted (otherwise it is spoofable). Confirm `TRUST_PROXY_HOPS` matches the real hop count.
- [ ] **Turnstile / CAPTCHA** on sign-in/sign-up if brute-force pressure appears (decision).
- [ ] **Database**: TLS (`sslmode=require`); a least-privilege app role (no superuser, only DML on
      the app tables); encrypted, tested backups. Confirm no raw IP is persisted (only salted hashes).
- [ ] **Secrets**: load from the host's secret manager in prod (not a file on disk where possible).
      Rotate `BETTER_AUTH_SECRET`, `GOOGLE_CLIENT_SECRET`, `MOD_IP_SALT`, `DATABASE_URL` on any leak.
- [ ] **Error tracking**: wire Sentry (or similar) via a prod-only DSN; forward the `logSec` channel.
- [ ] **Dependencies**: `npm audit` clean; lockfile committed; enable Dependabot/renovate; pin versions.
- [ ] **Process supervisor**: run under pm2/systemd/container orchestration so a wedged process
      restarts. Consider switching `uncaughtException` to log-and-exit once a supervisor is in place.
- [ ] **Email verification** (§6.2 decision): currently OFF. For a public 18+ service, turning it on
      (or gating some actions behind it) reduces throwaway/abuse accounts. Flip
      `emailAndPassword.requireEmailVerification` in `auth.mjs` when an email provider is wired.

## Env reference
See `.env.example` for every key. Secrets (`BETTER_AUTH_SECRET`, `GOOGLE_CLIENT_SECRET`,
`DATABASE_URL`, `MOD_IP_SALT`) are server-only. The Google **client ID** is public; the **client
secret** is not.
