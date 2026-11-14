# Decisions

Dated decisions for this repo, newest last.

- 2026-11-10: created from the ops starter kit, area `plugins`.
- 2026-11-10: Plugin Security leads this repo (assigned by Helm). Platform wires it into the first site and does the independent pre-publish security read. It goes public from the first push after that audit, with MIT.
- 2026-11-10: design proposed in docs/adr/0001-design.md, before any code (rules/build-it-right.md).
- 2026-11-10: ADR 0001 updated for Platform's pre-publish read (every Must and Should taken; see its last section).
- 2026-11-10: 0.1.0 built to ADR 0001, with 19 tests; four protections checked to fail their tests when removed.
- 2026-11-10: after Platform's code read, state moved to its own collection (with a one-time move from the account), the limiter records before counting, and the key comes from the raw app secret. See ADR 0001's last section.
- 2026-11-10: **Name.** The owner, verbatim (Helm's chat, about 8:30 PM MST, relayed by Helm): "MFA — payload-plugin-mfa (Recommended)". The repo and package are `payload-plugin-mfa`, with 2fa, two-factor and two-step in its keywords; the site's own wording stays "two-step". Public names follow it (`mfa()`, `MfaError`, `MFA_*`, `mfa-state`, `mfa-attempts`, the `payload-mfa` cookie) while nothing is released yet.
- 2026-11-10: after Platform's final read, the legacy move is an explicit `moveLegacyState` script, not a startup step (cold starts, two instances at once), and accounts with unmoved state can't sign in; old tries are deleted; clock skew is noted in the README.

## From the decision feed (ops/decisions/all.md and the area feed), applied 2026-11-10

- D1 decision feeds: this repo's lead reads the feed at startup and after a context summary.
- D2 build it right: the plugin stands alone. It depends on no other plugin; other plugins reach it only through optional adapters.
- D3 owner items: steps and tests for the owner go to ops/inbox/ (rules/owner-items.md).
- D4 priority order, D7 timeline order: work follows the ops timeline; nothing here is dated.
- D5 no private repos because of CI: public since 2026-11-10.
- D6 names: the name is on ops/plugin-names.md (owner, 2026-11-10).
- D8 Seed World: the collections this plugin adds were sent to Seed World ahead of the site wiring (2026-11-10). Platform's wiring PR sends the at-merge notice.
- D12 no family tags yet: the keywords carry no family word (`identity` isn't one of them); the category stays `authentication`.
- D9, D10, D11, D13, D14, D15, D16: don't apply to this repo.

- 2026-11-10 (Plugins Lead, K25): added `statusFor` and `resetFor` for wiring it into the first site, as Web Platform asked through Plugin Security, so the site stops reading `mfa-state` directly. Server-only, with no endpoint. The reset goes through the version-checked write, and clears the account's own limiter tries but not per-address ones, which other accounts share. Built on the `status-and-reset` branch. It merges to main after its own security read, so the owner's first publish (N99) includes it only once it's been read.

- 2026-11-10 (K29 self-audit): events carry a request copy with nothing secret: no code or remember value in its context, no headers, no body. It keeps the user, the transaction and the rest of the context, which is what an audit trail needs.
- 2026-11-13: moved to the ExtantApe GitHub organization and the `@extantape` npm scope at the same version. EXTANT APE owns its reusable tools and licenses them to the platform. The earlier package name is deprecated with a pointer here, and GitHub redirects the old repository address.
