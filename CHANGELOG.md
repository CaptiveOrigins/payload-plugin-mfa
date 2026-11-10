# Changelog

## 0.1.0 (unreleased)

First version, extracted from Captive Origins' own two-step sign-in, with the decisions in `docs/adr/0001-design.md` (including Platform's pre-publish read): factors, use-once codes with a race guard, per-account limits with keys built inside, the required rule at sign-in, refresh and every request, per-session expiry, remembered browsers, email codes blocked after a reset, step-up `verify`, and the login endpoint.

Tested: 19 tests. Four of them (replay, races, per-account limiting, a failing rule) were checked to fail when the protection is removed. Not yet used on a site, and no screens of its own.
