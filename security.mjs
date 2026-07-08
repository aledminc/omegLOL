// HTTP/transport security helpers. Pure where possible so the tricky bits (client IP behind
// Cloudflare, origin allowlisting, CSP shape) are unit-testable without booting a server.
//
// Deployment note: Cloudflare sits in front. `CF-Connecting-IP` is the real client IP and CF
// strips any client-supplied copy — but ONLY if the origin server is locked to Cloudflare's IP
// ranges at the edge (human launch task), otherwise an attacker who reaches the origin directly
// could spoof that header. Everything here is the app-level backstop; the edge is the front line.

// Lowercase, trim, drop a trailing slash so origins compare stably.
export function normalizeOrigin(o) {
  return String(o || "").trim().toLowerCase().replace(/\/+$/, "");
}

// The real client IP, working for both an Express req and a raw WS-upgrade req.
export function clientIp(req) {
  const h = (req && req.headers) || {};
  const cf = h["cf-connecting-ip"];
  if (cf) return String(cf).trim();
  if (req && req.ip) return req.ip;                       // Express, trust-proxy aware
  const xff = h["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req && req.socket && req.socket.remoteAddress) || "";
}

// Build the WebSocket/CORS origin allowlist. Explicit ALLOWED_ORIGINS wins; otherwise derive
// from the app's canonical URL, plus localhost in non-production for dev/tests.
export function allowedOrigins(env = process.env) {
  const raw = env.ALLOWED_ORIGINS;
  if (raw) return new Set(raw.split(",").map(normalizeOrigin).filter(Boolean));
  const set = new Set();
  if (env.BETTER_AUTH_URL) set.add(normalizeOrigin(env.BETTER_AUTH_URL));
  if (env.NODE_ENV !== "production") {
    set.add("http://localhost:8080");
    set.add("http://127.0.0.1:8080");
  }
  return set;
}

// Strict membership test. A MISSING origin returns false; the caller decides whether to allow
// non-browser clients (which have no Origin and can't mount a cross-site WS hijack anyway).
export function isOriginAllowed(origin, set) {
  if (!origin) return false;
  return set.has(normalizeOrigin(origin));
}

// Content-Security-Policy directives (helmet shape). Locked everywhere the app doesn't need an
// exception. Known, intentional relaxations:
//   script-src 'unsafe-inline'  -> the pages carry inline <script> blocks (static HTML, no
//                                  templating). No inline event handlers exist, so injected
//                                  markup still can't run handlers; output-encoding is the
//                                  primary XSS defense. Follow-up: move to nonces/external JS.
//   script-src 'wasm-unsafe-eval' -> MediaPipe compiles WebAssembly for face landmarks.
//   style-src  'unsafe-inline'  -> inline <style> blocks + many style="" attributes.
// Frames are denied outright (clickjacking matters for a camera app).
export function cspDirectives({ production = false } = {}) {
  const self = "'self'";
  const dirs = {
    defaultSrc:  [self],
    baseUri:     [self],
    scriptSrc:   [self, "https://cdn.jsdelivr.net", "'unsafe-inline'", "'wasm-unsafe-eval'"],
    styleSrc:    [self, "https://fonts.googleapis.com", "'unsafe-inline'"],
    fontSrc:     [self, "https://fonts.gstatic.com", "data:"],
    imgSrc:      [self, "data:", "blob:"],
    mediaSrc:    [self, "blob:", "mediastream:"],
    connectSrc:  [self, "https://cdn.jsdelivr.net", "https://storage.googleapis.com"],
    workerSrc:   [self, "blob:"],
    objectSrc:   ["'none'"],
    frameSrc:    ["'none'"],
    frameAncestors: ["'none'"],
    formAction:  [self],
  };
  if (production) dirs.upgradeInsecureRequests = [];
  return dirs;
}

// HTTP rate-limit tunings (express-rate-limit). Auth is strict (credential stuffing / brute
// force); reads are looser; a general cap backstops everything else incl. static assets.
export const RATE = {
  auth:    { windowMs: 15 * 60 * 1000, max: 40  },   // /api/auth/* per IP / 15 min
  read:    { windowMs: 60 * 1000,      max: 120 },   // /api/me, /api/leaderboard per IP / min
  general: { windowMs: 60 * 1000,      max: 300 },   // everything else per IP / min
};
