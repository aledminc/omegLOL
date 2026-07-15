# UI Changelog — Design System v2 "Broadcast"

Full visual re-skin per `design.txt`. **Visuals only** — no gameplay, matchmaking,
WebRTC, auth, moderation, or server logic was touched. Every DOM id, data attribute,
and JS-queried class is unchanged; only CSS (and a handful of static markup class
swaps with no JS references) changed.

## CSP / fonts

**No security.mjs change was needed.** The existing CSP already allowlists
`fonts.googleapis.com` (style-src) and `fonts.gstatic.com` (font-src), and permits
inline `<style>` (`style-src 'unsafe-inline'` is a documented, intentional
relaxation). Space Grotesk (500/700), Inter (400/500/600), and IBM Plex Mono (500)
are loaded via `<link rel="preconnect">` + one Google Fonts stylesheet `<link>` in
every page head. The old `@import` (Press Start 2P / VT323) was removed from base.css.

## Per-file

### css/base.css (rewritten)
- Token block at the top: full palette, semantic colors, tint/glow/scrim variants,
  three font stacks, radius scale (8/12/16), spacing scale (`--s1..--s9`), easing +
  duration tokens, and the single float shadow. **Zero hardcoded hex below :root.**
- **Legacy alias block**: old token names (`--ink`, `--panel`, `--accent`, `--gold`,
  `--grad-*`, `--bevel-*`, `--scanlines`, …) resolve to new tokens so untouched
  consumers (e.g. the root-level admin.html console) keep working.
- Primitives rebuilt: body defaults, global `:focus-visible` gold ring, `.panel`
  (surface + hairline, no shadow), buttons (`.btn` = secondary outline, `.btn.gold` =
  primary, `.btn.ghost`), inputs, `.gate` (full-screen surface overlay), `.modal .box`
  (raised surface + float shadow), ranked table/toggle/history styles, tier `.ladder`
  cards (mono numeral chip + tier-color top edge), scorebar, juice popup typography,
  gamebar buttons.
- Nav: slim sticky 64px bar, backdrop-blur, Display-700 wordmark ("omeg" white +
  "LOL" gold via `.lol`), static gold brand dot, active link = 2px gold underline
  offset 6px. **js/nav.js needed no code change** — its existing template
  (`.brand`/`.dot`/`.lol`/`.nav-user`) was restyled purely in CSS.
- Landing/about shells: `.crt` is now a dark stage panel carrying the signature
  spotlight (radial gold at ~5%, breathing 6s); `.band`/`.marquee` restyled into the
  slim broadcast ticker; footer, sections, how-steps re-skinned.
- Leaderboard: top-3 rows get the 3px Spotlight-Dim left edge; rank/Elo in Mono
  tabular.

### public/index.html
- Hero markup simplified: logo + tagline + one gold "Play free" + two secondary CTAs
  + 18+ micro-label + ghost social icon buttons (brand-color hovers replaced with the
  system hover — one accent only).
- Page-load sequence (nav → headline → tag → CTA pop + single gold pulse ring,
  ~880ms total, transform/opacity only, reduced-motion guarded).
- Star marquee replaced with ONE slim ticker (2 sets, `·` separators, same copy).
- Removed the old glow/shine/blink animations and the inline `style=` on the footer
  brand (now `.lol`).

### public/play.html (inline `<style>` rewritten; markup + all JS untouched)
- All layout mechanics preserved byte-for-byte: `.play-shell` grid, phase-driven
  show/hide, `data-cams` 1/2/3/4 aspect grids, `.stage.split` columns, cqw container
  scaling, drawer transform, media queries.
- Camera tiles: 16px radius, hairline border, `#000` fill; CRT frames, scanline
  overlays, and REC badges removed.
- **Performer spotlight**: during round1/round2 the performing side's tile(s) get the
  gold border + soft glow, crossfading 400ms on swap — driven purely by the existing
  `body[data-phase]`/`[data-role]` + `data-team` attributes (no new JS).
- Nameplates (`.cam-card`): dark scrim chips moved to bottom-left, backdrop-blur on
  chips only; W/L/D form cells as quiet outline cells.
- Searching state: spinner replaced by three gold dots doing a slow wave (pure CSS on
  the existing `.ring` div) + elapsed clock in Mono.
- Match intro: VS slam re-set in Space Grotesk (white V / gold S, dark bolt with gold
  glow); intro reveal cards use Display names + mono tier-numeral chips in tier color.
- Countdown: Mono numerals with a per-second heartbeat (scale 1.15→1 + fade), role
  hint in gold below.
- Juice popups: Display 700, tier-scaled 1.25/2/3rem, scold = danger, reward = gold,
  "+X.X" floats in Mono gold, snappy pop-in then float-fade. Reduced-motion swaps to
  an opacity-only fade **that still fires `animationend`** so popup nodes self-remove.
- Edge flash: re-implemented as a 3px/25%-opacity inner vignette pulse on each cam
  tile's (previously scanline) `::after` overlay — felt, not blinding, and now visible
  in the split layout.
- Find a match: the page's one gold element (solid fill, cqw-scaled); cancel state is
  a quiet danger-text secondary. "Next" turns gold when it becomes actionable.
- Friends drawer: raised surface + float shadow; requests badge kept red (semantic).
  Mode toggles, chat, lobby chip, invite toast, report modal, ban gate all re-skinned
  on tokens.
- Split-stage backdrop carries the second sanctioned spotlight glow.

### public/login.html
- CTA hierarchy: **Continue with Google = gold primary**, email "Sign in" = secondary,
  guest link = quiet text. (`// DESIGN-NOTE:` the spec lists both auth actions as
  gold; one solid gold per view won, Google on top.) Inline `style="width:100%"`
  removed in favor of CSS. Retro cam graphic simplified to a dark tile + gold dot.

### public/agree.html, public/age.html (not in the listed 7, but they share base.css)
- Compatibility re-skin so the consent flow isn't a light-theme orphan: dark doc
  scroller, danger-tinted risk box, gold unlock buttons. **All legal copy untouched.**

### public/ranked.html
- Page header row with the spec's "Jump back in" gold button top-right; segmented
  toggle, history rows, board rows on tokens; numbers in Mono. Tier modal reuses the
  restyled `.ladder`.
- `// DESIGN-NOTE:` own-row highlight on the leaderboard needs the client to know
  "which row is me" — that's a JS change, so it was skipped (top-3 gold edge shipped).

### public/about.html, terms.html, privacy.html
- Typographic pass only: ~70ch measure, Micro-label section headings (gold eyebrow on
  legal h2s), Mono doc-meta, no copy changes.

## DESIGN-NOTE summary
1. login.html — one gold (Google) instead of two.
2. ranked.html — no own-row highlight (would require JS).
3. play.html — the drawer's "Accept" request button is created by JS with
   `btn gold fr-invite`; left as-is (JS untouched), so an open drawer with pending
   requests can show a second gold element.
4. Landing scroll-reveals: the landing page has no below-fold sections anymore
   (hero + ticker + footer), so there was nothing to reveal.
5. Countdown heartbeat is a 1s CSS loop during the countdown phase (approximates
   per-tick animation without touching the timer JS).

## Verification
- `node --check` ✓ on js/nav.js and both extracted play.html inline scripts.
- Grep sweep ✓: zero old-palette hex codes, zero Press Start 2P / VT323 references,
  every `animation:` name has a matching `@keyframes`, no removed ids/classes that
  the inline JS references (play.html markup untouched).
- Test suites: moderation (29) ✓, moderation-WS (11) ✓; test-security.mjs fails with
  a **pre-existing** `port` TypeError (confirmed unrelated to UI work — it predates
  this change and stems from a server PORT default edit).
- All animations are transform/opacity only; every loop is inside
  `prefers-reduced-motion: no-preference`; one-shots have opacity-only fallbacks.
- data-cams 1/2/4 grids: rules preserved verbatim — recommend one manual visual pass
  in the browser (set the attribute by hand) since no browser was available here.
