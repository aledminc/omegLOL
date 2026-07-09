// Error tracking (Sentry), fully OPTIONAL and env-gated. When SENTRY_DSN is unset — dev, tests, and
// any run without it — nothing here loads @sentry/node or sends anything, so the app and the test
// suites are untouched. When it's set, we capture three things MANUALLY (no auto HTTP/OTEL
// instrumentation, to avoid overhead/interference in a real-time WS app): unhandled exceptions/
// rejections, errors thrown inside WS handlers, and 5xx HTTP errors.
//
// PII scrub: sendDefaultPii is off and beforeSend strips request data (headers/cookies/body/IP),
// user, and hostname. Callers only ever pass small, non-PII context (no tokens/chat/raw IPs).

let _sentry = null;

// Strip anything identifying before an event leaves the process (belt-and-suspenders; we don't
// attach request/user data in the first place since we capture manually).
function beforeSend(event) {
  try {
    delete event.request;        // headers, cookies, body, ip
    delete event.user;           // id, email, ip
    delete event.server_name;    // hostname
    if (event.contexts) { delete event.contexts.device; delete event.contexts.culture; }
  } catch {}
  return event;
}

// Initialize once, only if SENTRY_DSN is present. Returns true if enabled. Safe to call more than
// once. Never throws (a broken tracker must not take down the server).
export async function initSentry() {
  if (_sentry || !process.env.SENTRY_DSN) return false;
  try {
    const Sentry = await import("@sentry/node");
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || "development",
      tracesSampleRate: 0,                 // errors only — no performance tracing
      sendDefaultPii: false,               // never attach IP/cookies/user
      defaultIntegrations: false,          // no auto HTTP/express/pg instrumentation; we capture manually
      beforeSend,
    });
    _sentry = Sentry;
    console.log("sentry: error tracking enabled");
    return true;
  } catch (e) {
    console.error("sentry init failed (continuing without error tracking):", e && e.message);
    return false;
  }
}

export function sentryEnabled() { return !!_sentry; }

// Report an error. `context` is a small plain object (e.g. { where:"ws_handler" }) — callers must
// NOT put PII/secrets in it. No-op when Sentry is disabled.
export function captureError(err, context) {
  if (!_sentry) return;
  try {
    const e = err instanceof Error ? err : new Error(typeof err === "string" ? err : "non-error thrown");
    _sentry.captureException(e, context ? { extra: context } : undefined);
  } catch {}
}
