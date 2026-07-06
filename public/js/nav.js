// Shared nav, injected into every page. Single source of truth, highlights the active link.
// The last slot is auth-aware: "Log in" for guests, or the signed-in name + "Log out".
const here = location.pathname;
const el = document.getElementById("site-nav");

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function render(authSlot) {
  if (!el) return;
  const links = [
    { href: "/play", label: "Play" },
    { href: "/ranked", label: "Ranked" },
  ];
  el.innerHTML =
    `<a class="brand" href="/"><span class="dot"></span>omeg<span class="lol">LOL</span></a>` +
    `<nav>` +
    links.map(l => `<a class="${here === l.href ? "active" : ""}" href="${l.href}">${l.label}</a>`).join("") +
    authSlot +
    `</nav>`;
}

// Render the logged-out nav immediately (no flash of empty bar), then upgrade if a session exists.
render(`<a class="${here === "/login" ? "active" : ""}" href="/login">Log in</a>`);

(async () => {
  try {
    const r = await fetch("/api/auth/get-session", { credentials: "same-origin" });
    if (!r.ok) return;                                  // auth disabled / error → keep "Log in"
    const s = await r.json().catch(() => null);
    if (!s || !s.user) return;                          // not signed in → keep "Log in"

    // Prefer the in-game screenname (from /api/me) over the account name.
    let name = s.user.name || "account";
    try {
      const me = await fetch("/api/me", { credentials: "same-origin" });
      if (me.ok) { const d = await me.json(); if (d.profile && d.profile.name) name = d.profile.name; }
    } catch { /* fall back to account name */ }

    render(
      `<span class="nav-user" title="signed in">${escapeHtml(name)}</span>` +
      `<a href="#" id="logoutLink">Log out</a>`
    );
    const out = document.getElementById("logoutLink");
    if (out) out.addEventListener("click", async e => {
      e.preventDefault();
      try {
        await fetch("/api/auth/sign-out", {
          method: "POST", credentials: "same-origin",
          headers: { "content-type": "application/json" }, body: "{}",
        });
      } catch { /* ignore; reload anyway */ }
      location.reload();
    });
  } catch { /* keep the logged-out nav */ }
})();
