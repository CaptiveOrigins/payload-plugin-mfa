# Changelog

## 0.1.0 (unreleased)

First version, extracted from Captive Origins' own two-step sign-in, with the decisions in `docs/adr/0001-design.md` (including Platform's pre-publish read): factors, use-once codes with a race guard, per-account limits with keys built inside, the required rule at sign-in, refresh and every request, per-session expiry, remembered browsers, email codes blocked after a reset, step-up `verify`, and the login endpoint.

- The state lives in its own `two-step-state` collection, not on the account, so Payload's sign-in can't write old state back (found by Platform's read). `legacyUserField` moves state kept on the account, once, at startup.
- The built-in limiter records each try before counting it, so tries at once can't outrun it.
- The key comes from the raw app secret, as Captive Origins derives it.

Tested: 23 tests. Replay, the race guard, per-account limiting, the failing rule and the limiter under 40 tries at once were each checked to fail when the protection is removed. Not yet used on a site, and no screens of its own.
