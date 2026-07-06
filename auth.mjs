// better-auth configuration. This module is imported ONLY when auth env is present
// (see server.mjs), so guest/test runs never load better-auth at all.
//
// better-auth owns its own tables (user, session, account, verification) in the SAME
// Postgres database as the game. The game's `users` table stays the source of truth for
// rating/friends/etc.; the two are bridged by users.auth_id (see db.mjs). Generate the
// better-auth tables once with:  npx @better-auth/cli migrate   (needs the same DATABASE_URL)
import { betterAuth } from "better-auth";

// The minimum env for real auth to run. Without a secret we stay guest/token-only.
export function authEnvReady() {
  return Boolean(process.env.BETTER_AUTH_SECRET);
}

export function makeAuth(pool) {
  // Google drops in automatically the day its creds exist — no code change needed.
  const socialProviders = {};
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    socialProviders.google = {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    };
  }

  return betterAuth({
    database: pool,                                   // reuse the game's pg Pool
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: process.env.BETTER_AUTH_URL || "http://localhost:8080",
    emailAndPassword: { enabled: true, requireEmailVerification: false }, // v1: no verification
    ...(Object.keys(socialProviders).length ? { socialProviders } : {}),
  });
}
