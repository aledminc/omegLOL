// better-auth configuration. This module is imported ONLY when auth env is present
// (see server.mjs), so guest/test runs never load better-auth at all.
//
// better-auth owns its own tables (user, session, account, verification) in the SAME
// Postgres database as the game. The game's `users` table stays the source of truth for
// rating/friends/etc.; the two are bridged by users.auth_id (see db.mjs). Generate the
// better-auth tables once with:  npx @better-auth/cli migrate   (needs the same DATABASE_URL)
import { betterAuth } from "better-auth";
import { allowedOrigins } from "./security.mjs";

// The minimum env for real auth to run. Without a secret we stay guest/token-only.
export function authEnvReady() {
  return Boolean(process.env.BETTER_AUTH_SECRET);
}

export function makeAuth(pool) {
  const production = process.env.NODE_ENV === "production";
  const baseURL = process.env.BETTER_AUTH_URL || "http://localhost:8080";

  // Google drops in automatically the day its creds exist — no code change needed.
  const socialProviders = {};
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    socialProviders.google = {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    };
  }

  // CSRF/redirect allowlist: better-auth validates the request Origin and only redirects to
  // trusted origins. Reuse the same allowlist as the WS/CORS layer so there is one source of truth.
  const trusted = [...allowedOrigins()];
  if (!trusted.length) trusted.push(baseURL);

  return betterAuth({
    database: pool,                                   // reuse the game's pg Pool
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL,
    trustedOrigins: trusted,
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,                // v1: no verification (see SECURITY.md decision)
      minPasswordLength: 10,                           // blunt weak-password / credential-stuffing reuse
      maxPasswordLength: 128,                          // cap: hashing very long inputs is a DoS vector
    },
    session: {
      expiresIn: 60 * 60 * 24 * 7,                     // 7-day sessions
      updateAge: 60 * 60 * 24,                         // roll the expiry once a day of activity
    },
    // Session cookies: httpOnly + SameSite=Lax always; Secure only over HTTPS (production), else
    // local dev over http would drop the cookie. Lax (not Strict) so the Google OAuth top-level
    // redirect still carries the cookie back.
    advanced: {
      useSecureCookies: production,
      defaultCookieAttributes: { httpOnly: true, sameSite: "lax" },
      // Which header carries the real client IP (Cloudflare first). Without this, better-auth's
      // limiter can't resolve an IP and warns; behind the edge these headers are present.
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip", "x-forwarded-for"] },
    },
    // better-auth's own per-endpoint limiter (inner layer). Only ON in production — locally there
    // is no forwarded IP header (so it would warn + fall back to one shared bucket), and the
    // express-rate-limit layer on /api/auth already guards dev. Tight on sign-in/up to blunt brute force.
    rateLimit: {
      enabled: production,
      window: 60,
      max: 60,
      customRules: {
        "/sign-in/email": { window: 60, max: 10 },
        "/sign-up/email": { window: 60, max: 6 },
      },
    },
    ...(Object.keys(socialProviders).length ? { socialProviders } : {}),
  });
}
