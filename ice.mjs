// WebRTC ICE server sourcing. STUN is always present; TURN is added when configured so users on
// symmetric-NAT / restrictive networks can still connect (direct P2P fails for a meaningful share
// of them). TURN secrets stay server-side — the client only ever receives short-lived credentials.
//
// Three providers, tried in order by server.mjs:
//   1. Cloudflare Realtime TURN  (network call, ephemeral creds)  <- cloudflareIce()
//   2. generic coturn REST       (HMAC ephemeral, no network)     <- iceFromEnv() + TURN_SECRET
//   3. static TURN creds         (no network)                     <- iceFromEnv() + TURN_USERNAME/PASSWORD
// If none are configured, STUN-only (dev/local still works).
import crypto from "node:crypto";

export const DEFAULT_STUN = { urls: ["stun:stun.l.google.com:19302"] };

// coturn REST scheme: username = "<expiry-unix>:<label>", credential = base64(HMAC-SHA1(username, secret)).
// Pure + deterministic (inject `now` for tests).
export function coturnCredentials(secret, { ttl = 600, label = "omeglol", now = Date.now() } = {}) {
  const expiry = Math.floor(now / 1000) + ttl;
  const username = `${expiry}:${label}`;
  const credential = crypto.createHmac("sha1", secret).update(username).digest("base64");
  return { username, credential, expiry };
}

// Build ICE config from env WITHOUT any network I/O (STUN + optional coturn-HMAC or static TURN).
// Pure + testable. `ttlSeconds` is how long the returned coturn creds are valid (also its cache life).
export function iceFromEnv(env = process.env, { now = Date.now() } = {}) {
  const iceServers = [DEFAULT_STUN];
  const urls = (env.TURN_URLS || "").split(",").map(s => s.trim()).filter(Boolean);
  const ttl = Math.max(60, +env.TURN_TTL || 3600);
  if (urls.length) {
    if (env.TURN_SECRET) {
      const { username, credential } = coturnCredentials(env.TURN_SECRET, { ttl, now });
      iceServers.push({ urls, username, credential });
    } else if (env.TURN_USERNAME && env.TURN_PASSWORD) {
      iceServers.push({ urls, username: env.TURN_USERNAME, credential: env.TURN_PASSWORD });
    }
  }
  return { config: { iceServers }, ttl };
}

// Cloudflare Realtime TURN: POST to their API to mint short-lived credentials. Returns
// { config: { iceServers: [...] }, ttl } or null if the Cloudflare env isn't set. `fetchImpl`
// is injectable for tests; secrets are read from env and never returned to the caller's client.
export async function cloudflareIce(env = process.env, { ttl = 3600, fetchImpl = fetch } = {}) {
  const keyId = env.CLOUDFLARE_TURN_TOKEN_ID, token = env.CLOUDFLARE_TURN_API_TOKEN;
  if (!keyId || !token) return null;
  const res = await fetchImpl(
    `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate`,
    { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ ttl }) });
  if (!res.ok) throw new Error("cloudflare turn: HTTP " + res.status);
  const data = await res.json();
  // Cloudflare returns { iceServers: { urls:[...], username, credential } } — a single entry with a
  // urls array. RTCPeerConnection wants an array of entries, so wrap it (STUN urls in it ignore creds).
  const entry = data && data.iceServers;
  if (!entry || !entry.urls) throw new Error("cloudflare turn: unexpected response shape");
  return { config: { iceServers: [entry] }, ttl };
}
