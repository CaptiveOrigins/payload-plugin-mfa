# Decisions

Dated decisions for this repo, newest last.

- 2026-11-10: created from the standard repo starter kit.
- 2026-11-10: the first site wires it in, and an independent pre-publish security read comes first. It goes public from the first push after that audit, with MIT.
- 2026-11-10: design proposed in docs/adr/0001-design.md, before any code.
- 2026-11-10: ADR 0001 updated for the pre-publish security read (every Must and Should taken; see its last section).
- 2026-11-10: 0.1.0 built to ADR 0001, with 19 tests; four protections checked to fail their tests when removed.
- 2026-11-10: after the reviewer's code read, state moved to its own collection (with a one-time move from the account), the limiter records before counting, and the key comes from the raw app secret. See ADR 0001's last section.
- 2026-11-10: **Name.** The owner chose MFA, `payload-plugin-mfa`. The repo and package are `payload-plugin-mfa`, with 2fa, two-factor and two-step in its keywords; the site's own wording stays "two-step". Public names follow it (`mfa()`, `MfaError`, `MFA_*`, `mfa-state`, `mfa-attempts`, the `payload-mfa` cookie) while nothing is released yet.
- 2026-11-10: after the reviewer's final read, the legacy move is an explicit `moveLegacyState` script, not a startup step (cold starts, two instances at once), and accounts with unmoved state can't sign in; old tries are deleted; clock skew is noted in the README.

## Standing rules, applied 2026-11-10

- The plugin stands alone. It depends on no other plugin; other plugins reach it only through optional adapters.
- Public since 2026-11-10.
- No family tags yet: the keywords carry no family word (`identity` isn't one of them); the category stays `authentication`.

- 2026-11-10: added `statusFor` and `resetFor` for wiring it into the first site, as the site asked, so the site stops reading `mfa-state` directly. Server-only, with no endpoint. The reset goes through the version-checked write, and clears the account's own limiter tries but not per-address ones, which other accounts share. Built on the `status-and-reset` branch. It merges to main after its own security read, so the owner's first publish includes it only once it's been read.

- 2026-11-10 (self-audit): events carry a request copy with nothing secret: no code or remember value in its context, no headers, no body. It keeps the user, the transaction and the rest of the context, which is what an audit trail needs.
- 2026-11-13: moved to the ExtantApe GitHub organization and the `@extantape` npm scope at the same version. EXTANT APE owns its reusable tools and licenses them to the platform. The earlier package name is deprecated with a pointer here, and GitHub redirects the old repository address.
