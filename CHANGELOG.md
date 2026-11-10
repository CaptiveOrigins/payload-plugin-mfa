# Changelog

## 0.1.1 (unreleased)

- `statusFor(payload, userId)`: `{ on, since, recoveryLeft }` for the person's security page, so a site doesn't read the state collection itself.
- `resetFor(payload, userId, { enrollHours, actor })`: a maintainer's reset without a code. It goes through the version-checked write, clears the account's limiter tries, opens an enrollment window and sends a `reset` event naming the actor. Both are server-only, with no endpoint. Asked for by the Captive Origins site wiring.

Tested: 3 new tests (27 in all), including a reset racing a sign-in. A mutation check shows each part of the reset (the cleared secret and recovery codes, the cleared tries, the window bounds) fails a test when removed. Not yet used on a site.

## 0.1.0 (unreleased)

First version, as `@captiveorigins/payload-plugin-mfa` (renamed from payload-plugin-two-step by the owner, 2026-11-10), extracted from Captive Origins' own two-step sign-in, with the decisions in `docs/adr/0001-design.md` (including Platform's pre-publish read): factors, use-once codes with a race guard, per-account limits with keys built inside, the required rule at sign-in, refresh and every request, per-session expiry, remembered browsers, email codes blocked after a reset, step-up `verify`, and the login endpoint.

- The state lives in its own `two-step-state` collection, not on the account, so Payload's sign-in can't write old state back (found by Platform's read). `moveLegacyState` moves state kept on the account, run once as a script; until then those accounts can't sign in.
- The built-in limiter records each try before counting it, so tries at once can't outrun it.
- The key comes from the raw app secret, as Captive Origins derives it.
- Tries older than the window are deleted as new ones arrive.

Tested: 24 tests. Replay, the race guard, per-account limiting, the failing rule and the limiter under 40 tries at once were each checked to fail when the protection is removed. Not yet used on a site, and no screens of its own.
