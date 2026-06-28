// Shared nav, injected into every page. Single source of truth, highlights the active link.
const here = location.pathname;
const links = [
  { href: "/play",   label: "Play" },
  { href: "/ranked", label: "Ranked" },
  { href: "/login",  label: "Log in" },
];
const el = document.getElementById("site-nav");
if (el) {
  el.innerHTML =
    `<a class="brand" href="/"><span class="dot"></span>omeg<span class="lol">LOL</span></a>` +
    `<nav>` +
    links.map(l => `<a class="${here === l.href ? "active" : ""}" href="${l.href}">${l.label}</a>`).join("") +
    `</nav>`;
}
