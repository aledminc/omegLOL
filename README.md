# omegLOL

A competitive **try-not-to-laugh** webcam game. You're matched live with a stranger (1v1 or 2v2);
one side performs, the other tries to keep a straight face while an on-device camera signal keeps
score. Node ESM + Express + `ws` + Postgres, better-auth for accounts, WebRTC (P2P) for video.

## Stack
- **Server:** `server.mjs` (one HTTP server shared with the WebSocket). Pure logic in small modules:
  `elo.mjs`, `moderation.mjs` (+ `blocklist.mjs`), `validate.mjs`, `ratelimit.mjs`, `security.mjs`,
  `ice.mjs`, `instrument.mjs`. Data access in `db.mjs` (`makeDb(pool)`). Auth in `auth.mjs`.
- **Client:** static multi-page app in `public/` (vanilla JS, retro CSS). Face scoring via MediaPipe.
- **Media:** peer-to-peer WebRTC — video/audio never touch the server (STUN/TURN via `/api/ice`).

## Run locally
```bash
npm install
cp .env.example .env      # then fill in DATABASE_URL (+ optional keys)
npm start                 # -> http://localhost:8080
```
The game tables auto-migrate on boot. For real accounts, also run the better-auth migration once:
```bash
npx @better-auth/cli migrate
```
Without `BETTER_AUTH_SECRET` + `DATABASE_URL` the server still runs in guest/token-only mode.

## Test
```bash
npm test    # moderation policy, moderation WS protocol, and security suites (no DB needed)
```

## Deploy (Railway)
1. Connect this repo (already done). Railway/Nixpacks runs `npm start` (see `package.json`).
2. Add the **PostgreSQL** plugin — it provides `DATABASE_URL` automatically.
3. Set env vars (see `.env.example` for the full list). Minimum for a real deploy:
   - `NODE_ENV=production`, `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL` (your public URL),
     `ALLOWED_ORIGINS`, `MOD_IP_SALT`.
   - Optional: `GOOGLE_CLIENT_ID`/`SECRET`, Cloudflare TURN keys, `SENTRY_DSN`, `ADMIN_EMAILS`.
4. Health check / uptime monitor: point it at `GET /healthz` (200 healthy, 503 if DB is down).
5. Run the better-auth migration against the deployed database once (see above).

`PORT` is provided by Railway and read automatically. Set `TRUST_PROXY_HOPS` to match the number of
proxies in front (Railway edge = 1; add 1 more if you also front it with Cloudflare).

## Security & launch
See **`SECURITY.md`** for the hardening posture and the remaining human launch checklist
(Cloudflare Full-Strict TLS, DB least-privilege, age-assurance provider, NCMEC registration, etc.).
Secrets live only in env (`.env` is git-ignored); never commit real secrets.
