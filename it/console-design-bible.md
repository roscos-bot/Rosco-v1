# Console Design Bible

**Owner:** Rosco's IT department (Cortex / the Warrant seat).
**Governs:** every captain console — SteelHaven (Bessemer), RUM (Morgan), and every
console that comes after. They diverge in code and content; they must **not** diverge in
the invariants below.
**Status:** living document. When a UI/UX decision is made once, it is recorded here and
checked against every console — not left to be re-fixed console by console.

> Why this exists: RUM once shipped the *old* API-keys layout (a non-wrapping row that
> clipped the **Save** button off-screen) while SteelHaven already had the fixed version.
> A fix landed on one console and never reached the other. This document — and the rule
> that shared UI lives in one place — is how that stops happening.

---

## 0. The Prime Directive

**Fix it once, in the shared layer, and every console inherits it.**

The monorepo (`C:\Users\Ross\captain-consoles`) already has the shared layers. Use them.

| Layer | Path | What belongs here |
|---|---|---|
| **Design tokens + global CSS** | `packages/ui/src/styles.css` | colors, scrollbars, focus, selection, motion, fonts |
| **Shared components** | `packages/ui/src/**` | anything two consoles render the same way (primitives, `ApiKeys`, `Sidebar`, `TopBar`, `AppShell`, `FleetGraph`, module panels) |
| **Shared behavior** | `packages/lib/src/**` | auth/session, API clients, hooks, roles |
| **Per-app (allowed to differ)** | `apps/<console>/src/**` | brand name/copy, which modules mount, the provider/model list, accent choice, routes |

**The test before you write UI in an `apps/` folder:** *"Would the other console want this exact
thing?"* If yes → it goes in `packages/ui` (or `packages/lib`), parameterized by props.
Only genuinely per-business content (the word "Besse" vs "Morgan", `@steelhaven.homes`
vs `@rumachines.com`, the model list) lives per-app.

Duplicating a component across `apps/steelhaven` and `apps/rum` is a **defect**, not a
shortcut — it is a future drift bug already written. The API-keys panel is the cautionary
tale: it is now one shared `packages/ui/src/components/ApiKeys.tsx` that both apps feed a
provider list. That is the pattern for everything shared.

---

## 1. Color — tokens only, never a raw hex

Every color is a semantic CSS variable defined in `packages/ui/src/styles.css` and exposed
as a Tailwind utility (`bg-surface`, `text-muted`, `border-line`, `bg-brand`, `text-bad`…).
They flip automatically between light and dark — **there are no `dark:` variants and there
must be none.**

- **Never** write a literal hex (`#1a1e27`) or a Tailwind palette color (`bg-slate-800`) in a
  component. If a shade is missing, add a token to `styles.css`; don't inline it.
- The token set: `bg, sidebar, surface, surface-2, surface-3, line, line-2, text, muted,
  faint, brand, brand-ink, brand-tint, brand-soft, good, warn, bad, info` (+ each status has a
  `-tint`). Use the semantic one that matches *intent* (a destructive action is `bad`, not "red").
- **Per-captain accent:** the brand hue is overridden by `[data-captain="rum"]` (steel-blue)
  — same shell, different accent. A new console adds one `[data-captain="x"]` block; it does
  **not** restyle components. Never hardcode the SteelHaven amber.
- **Three theme states, all handled by the tokens:** explicit `[data-theme=light|dark]`, and
  the un-stamped system default via `@media (prefers-color-scheme: dark)`. Because components
  only ever reference tokens, they are correct in all three for free.

## 2. Fixed global invariants (in `styles.css`, already applied to all consoles)

These are done. Do not re-implement them per app; extend them here if needed.

- **Scrollbars** are thin and theme-reactive (`::-webkit-scrollbar` + `scrollbar-color`).
  Never ship a raw browser scrollbar. If a scroll area needs a custom look, it still inherits
  these — don't override per component without a reason recorded here.
- **Keyboard focus** shows a 2px `--brand` ring via `:focus-visible` (keyboard only; mouse
  clicks stay clean). Every interactive element must be reachable and show this ring — never
  `outline: none` without an equivalent visible replacement.
- **Text selection** uses `--brand-tint`.
- **Reduced motion:** `@media (prefers-reduced-motion: reduce)` neutralizes animation and
  transition. Any new animation must survive this (it will, if it's a CSS transition/anim).

## 3. Layout & responsive — wrap, don't clip (the API-keys lesson)

- A row of controls that can outgrow its container must **wrap** (`flex-wrap`) or the
  secondary content must be allowed to drop — never let a primary action (Save/Submit) slide
  off the right edge. The canonical fixed pattern: a flexing label block
  (`min-w-0 flex-1 basis-[…]`) + an action group that stays whole (`shrink-0 ml-auto`), with
  the row `flex-wrap`. See `packages/ui/src/components/ApiKeys.tsx`.
- Wide content (tables, code, diagrams, long rows) lives in its own `overflow-x-auto`
  container. **The page body never scrolls sideways.**
- Content columns use a sensible `max-w-[…]` (settings/readers ≈ `820px`) so text doesn't run
  edge-to-edge on wide screens.
- Inputs are `w-full` inside their cell and shrink on narrow viewports
  (`w-[170px] max-[520px]:w-[130px]`), not fixed widths that force horizontal scroll.

## 4. Components — reach for the shared primitives first

`packages/ui/src/components/primitives.tsx` provides `Card`, `Badge`, `Button`,
`SectionTitle`, etc. Compose these; don't hand-roll a card or a button.

- **Button** has `variant` (`primary`/default) and a real `disabled` state
  (`disabled:opacity-50 disabled:cursor-not-allowed`). A submit button is disabled while the
  field is empty or the request is in flight, and shows an in-flight label ("Saving…").
- **Badge** carries a `tone` (`good`/`muted`/`brand`/…) — status is a tone, not a color.
- Shared multi-console panels (`ApiKeys`, and future ones) take their differences as **props**
  (provider list, intro copy, feed keys), never as forked copies.

## 5. States — every surface handles all four

Anything that fetches or acts must define, visibly:
1. **Loading** — a real loading state, not a blank flash.
2. **Empty** — a helpful line ("No one enrolled yet — invite a teammate below."), not a bare void.
3. **Error** — a plain, human message in `text-bad`; for an authed call that 401s, the app
   drops the dead session and re-gates to sign-in (see `packages/lib/src/auth.tsx` +
   `api.ts` `noteAuth`) — it never leaves you in a dead console.
4. **Success/disabled** — confirm actions (`text-good` "Saved."), disable controls that can't act.

## 6. Typography & spacing

- Fonts come from tokens (`--font-sans`, `--font-mono`); code/IDs/env-names are `font-mono`.
- Stay on the existing type rhythm (labels ≈ `text-[10px]` uppercase mono muted; body
  ≈ `text-[12.5px]`–`text-[13px]`; numbers use `.tabular` / `tabular-nums`).
- Space with fl/grid `gap`, not ad-hoc margins that collapse or double.

## 7. Accessibility (non-negotiable)

- Keyboard reachable + visible focus (see §2). Don't remove the ring.
- Color is never the *only* signal — pair it with text/icon (a "not set" badge says the words).
- Respect reduced motion (§2). Maintain legible contrast in **both** themes — verify dark, not
  just light.

---

## 8. The cross-console check (how IT enforces this)

Run this whenever a console UI changes, a new console is stood up, or a UI/UX fix lands on one:

1. **Did the fix land in a shared layer?** If it was made in an `apps/` folder and the other
   console would want it, move it to `packages/ui`/`packages/lib` and delete the duplicate.
2. **Diff the consoles for forked components.** Anything that exists in both
   `apps/steelhaven/src` and `apps/rum/src` with near-identical code is a drift risk — extract it.
   Quick scan: compare `apps/*/src/modules/*` file lists and sizes; near-twins are candidates.
3. **Token sweep:** `grep` the apps for raw hex (`#[0-9a-f]{3,6}`) and Tailwind palette colors
   (`bg-(slate|zinc|gray|red|green|amber)-`) — there should be none; replace with tokens.
4. **Invariant sweep:** confirm no app re-styles scrollbars/focus/selection locally
   (they belong in `styles.css`).
5. **Responsive pass:** shrink each changed view to ~380px wide — nothing clips, no primary
   action leaves the viewport, body doesn't scroll sideways.
6. **Both themes:** toggle light/dark — every color still resolves from a token and reads.
7. **A11y pass:** tab through new controls — all reachable, focus ring visible.

When a rule here is added or changed, note it in the changelog below and open the fix on
**every** live console in the same pass — not "next time we touch that console."

---

## Changelog
- **2026-08-20** — Bible created. Established the Prime Directive (shared-layer-first) after
  the RUM API-keys clip bug. Landed the global invariants (scrollbars, focus-visible,
  selection, reduced-motion) in `packages/ui/src/styles.css`, and extracted the shared
  `<ApiKeys>` so the panel can't diverge again.
