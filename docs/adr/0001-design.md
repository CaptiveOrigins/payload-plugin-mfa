# ADR 0001: Two-step sign-in for Payload, the design

Status: proposed, 2026-11-10. Lead: Plugin Security. Independent pre-publish security read: Platform. Approved as an agnostic plugin by the owner, 2026-11-10 (relayed by Helm).

## Context

Payload has no second factor. The first site built one itself (`src/lib/security/twoStep.ts`, the Users hooks and the My Information actions), and the owner wants staff to need it (N62) on a site with kids. Hats asks for a second factor before switching into a sensitive hat, through its `stepUp` option. Under `rules/build-it-right.md`, this becomes its own plugin: it works on any Payload site, and other plugins reach it through small adapters, never imports.

The site's version has been audited and works. This ADR keeps its behavior and fixes what an extraction would otherwise carry over.

## Decisions

1. **Factors.** An authenticator app code (TOTP, SHA-1, 6 digits, 30 s, ±1 step) is the main one. The backups are an emailed code (8 digits, so it can't be mistaken for an app code; used once; 10 minutes) and recovery codes (10, 80 bits each, shown once). No text messages, ever (cost and SIM-swap). Passkeys are a possible 0.2, not part of 0.1.

2. **Storage.** A hidden `twoStep` group on the auth collection, with field access false for read, create and update, so only the plugin's own server code touches it.
   - The app secret is sealed with AES-256-GCM. The key is derived by HKDF-SHA256 from the app's secret, with `salt` and `info` options (defaults `payload-plugin-two-step` and `two-step-secret`). The site passes its current values (its own salt and `two-step-secret`) so existing secrets keep working, with **no database migration**. Field names stay as the site has them.
   - Recovery codes are stored as SHA-256 hashes, and email codes as HMACs under the derived key, so a copy of the database alone gives none of them.
   - If the app's secret changes, app codes stop working and recovery codes still do. This is documented.

3. **Where the code is checked.** In the auth collection's `beforeLogin`, which Payload runs after the password matched, on sign-in **and** password reset (checked: `resetPassword` runs `beforeLogin` before it issues a token).
   - The code, the remembered-browser value and the trusted flag arrive only in `req.context`, which HTTP requests can't set. So an enrolled account can't sign in through bare REST or GraphQL `login`: there's no way to send the code.
   - The plugin offers the ways in: `signIn(payload, { email, password, code?, remember? })` for server code (Next server actions and similar), and an optional endpoint `POST /api/<users>/two-step/login { email, password, code }` (`endpoint: true`) for sites without server actions. Both put the code in context and call Payload's `login`.
   - `TRUSTED` stays: a server-only context flag for code that has already vouched for this sign-in, or throws its token away (for example, checking a password). It's documented as server-only and never read from a request body.

4. **Who must use it.** `requiredFor({ user, req }) => boolean | Promise<boolean>` (default: nobody required).
   - It's checked at sign-in **and** on every session refresh, so switching the requirement on catches sessions that are already open.
   - It fails closed: if it throws, the account counts as required.
   - A required account that hasn't enrolled is refused at sign-in with `enroll`, so a stolen password can't enroll its own phone at first sign-in. A site lets someone enroll through a short window, `allowEnrollment(payload, userId, hours)` (default 24 hours, logged), set by staff.
   - Exemptions such as an automation account are the site's `requiredFor`, never built into the plugin.

5. **Remembered browser, per session.** After a good code the site may set the remember cookie (HttpOnly, SameSite=Lax, Secure outside dev). Its value is an HMAC over the account id, the expiry, the sealed secret and the password hash, so a new password or a new secret ends it.
   - It lasts `rememberHours` (default 24).
   - A session can't outlive it: refresh is refused once `now − verifiedAt > remember − tokenExpiration`, using the collection's own `tokenExpiration`, not a hard-coded two hours as in the site today.
   - **`verifiedAt` is kept per session**, keyed by Payload's session id (`sid`), not per account, so a code given on one device doesn't extend another. Entries for expired sessions are dropped when a session is added.

6. **After a password reset.** Whoever holds the mailbox has just proved that, so the mailbox can't also be the second step: email codes are off for `emailBlockHours` (default 24) and any outstanding one is cleared.
   - **The plugin enforces it** in an `afterOperation` hook on `resetPassword`, and through `afterPasswordSet(payload, userId)` for a site's own invitation flow. The site no longer has to remember to call it.

7. **Rate limits, built in and keyed inside.** Every code check (sign-in, `verify`, enrol, disable, new recovery codes) and every email-code send goes through the limiter.
   - **The key is built inside the plugin** from the account id, never passed in by a caller, so a caller can't change it to dodge the limit.
   - **The per-account limit never includes the address**, so rotating addresses gives no fresh tries. A per-address limit can be added on top when the site gives `clientAddress`.
   - Wrong codes count toward this per-account limit, which works as the code's own lockout (Payload's 5-failure lock counts only wrong passwords).
   - The limiter is an adapter, `limit({ kind: 'code' | 'emailCode', key, req }) => boolean`; the Guardrails plugin will provide one later. Without it, a built-in fixed window with hashed keys (defaults: 5 codes and 3 email codes per 15 minutes per account).
   - A limiter that throws refuses. A refused code reads exactly like a wrong one.

8. **No double use under concurrency.** Checking a code and saving the result are one step: the update only applies if the state hasn't changed since it was read (a `version` counter in the group, with `updateOne` matched on `id` and `version`). If two requests race with the same app code, recovery code or email code, only one wins; the other is "wrong".

9. **Step-up for other plugins.** `verify(payload, { user, code, req })` returns true only for a good code. It applies the same limiter, use-once rules and concurrency guard, and records `verifiedAt`.
   - `isOn(user)` says whether an account has two-step.
   - Hats' `stepUp` becomes `{ available: (u) => isOn(u), verify: ({ user, code, req }) => verify(payload, { user, code, req }) }`.

10. **Managing it.** Server functions for a site's own pages:
    - `start(userId, { code? })`, after the site has checked the password: returns the QR link and manual key, and keeps the secret pending. **If two-step is already on, it refuses unless a current app or recovery code comes with it**, so a session plus a password (or a site bug that skips the password check) can't move the factor to another phone.
    - `confirm(userId, code)`: turns it on and returns the recovery codes once.
    - `turnOff(userId, code)` and `newRecoveryCodes(userId, code)`, after the site has checked the password.
    - `sendEmailCode(email)`: the same answer whether or not the address exists or has two-step.

    The issuer name in the authenticator app is an option (`issuer`, default the site's `meta.titleSuffix` or "Payload"). An accessible default React panel is a possible 0.2. In 0.1 the site keeps its own panel.

11. **Events.** `onEvent` for enrolled, confirmed, turned off, recovery codes renewed, a recovery code used, an email code sent, email codes blocked after a reset, an enrolment window set, and refused for too many tries (at most once per window). Each event carries the account id and never a code, secret or address. It's meant for the audit-trail plugin's sink.

12. **Failing closed, everywhere.**
    - A `requiredFor` that throws counts as required.
    - A limiter that throws refuses.
    - A secret that can't be opened means app codes are refused, while recovery codes still work.
    - A malformed state is treated as on, and a code is needed.
    - The plugin won't start without the app's secret (at least 32 characters) or an auth collection.

## What stays in the site

The sign-in, My Information and reset pages and their wording (the plugin returns `needed | wrong | enroll` and stable reasons). Who must use it (`STAFF_TWO_STEP_REQUIRED` becomes the site's `requiredFor`). The test-account exemption. The email text.

## Tests, before 0.1

- Every factor: accepted once, refused when reused, expired or wrong.
- Clock drift of ±1 step.
- A recovery code is used up.
- An email code is blocked after a reset, through both the reset hook and `afterPasswordSet`.
- REST and GraphQL `login` are refused for an enrolled account.
- A required account that hasn't enrolled is refused; a `requiredFor` that throws refuses; a refresh past the remembered window is refused.
- A remembered cookie: works within the window; is refused once edited, once the password changes or once the secret changes.
- The limiter key can't be chosen by the caller; a limiter that throws refuses.
- Concurrency: two simultaneous uses of one code, and only one succeeds.
- `verify` for step-up.
- `sendEmailCode` answers the same for an unknown address.
- Events carry no secrets.
- Compatibility: a secret sealed with the site's current settings opens.

## Open

- The default React panel and passkeys are left for 0.2. Nothing is promised in 0.1.

## Changes after Platform's pre-publish read (2026-11-10)

Platform read this ADR at `87d92cd`. Each point, and what changed:

1. **Must: the per-account limit must not include the address.** Done in decision 7: always per account, with an optional per-address limit on top. Test: 5 wrong codes from address A, then the 6th from B is still refused.
2. **Must: `start()` on an account already on.** Done in decision 10: it needs a current app or recovery code.
3. **Must: API keys and custom strategies skip `beforeLogin`.** The plugin **refuses to start if the auth collection has `useAPIKey` on**. Custom auth strategies are documented as the site's job, with `isOn(user)` and `requiredFor` exported for the site to use. The first site has no API keys.
4. **Should: `verifiedAt` per session.** Done in decision 5, keyed by `sid`. Test: a code on device A doesn't extend device B.
5. **Should: last TOTP step.** Every accepted app code stores its step, and any step ≤ the last is refused; the `version` guard covers races. Test: the same code is refused even after waiting one step, while still in the drift window.
6. **Should: requirement on sessions that never refresh.** The plugin wraps the auth strategies of the users collection (as Hats does): a session whose account is now required but hasn't enrolled is signed out on its next request. The README says what this costs (one `requiredFor` call per authenticated request).
7. **Should: the login endpoint.** `/two-step/login` calls Payload's `login` (its lockout, CSRF and cookie rules apply). Wrong codes count toward decision 7's per-account limit. An unknown email answers exactly like a wrong password.
8. **Should: the enrolment window ends at the first successful confirm.** Done.
9. **Should: constant-time comparisons.** The email-code HMAC, the recovery hash and the remember HMAC all use `timingSafeEqual` (recovery is checked against every stored hash, not with `includes`).
10. **Note.** The README says the plugin's own state writes use `updateOne` (so they skip audit hooks), and that `onEvent` is the record.

Not changed: `TRUSTED` through `req.context`, and unsalted SHA-256 for 80-bit recovery codes. Platform agreed both are fine.

## Changes after Platform's read of the code (2026-11-10, at `44f484f`)

Platform reproduced three problems against Payload 3.92's real `login`. All are fixed, and Platform's repro tests are in the suite, adapted.

1. **Blocker: Payload wrote old two-step state back over new.** `login` reads the account before its transaction, then `addSessionToUser` writes that whole stale copy back, so a sign-in that began earlier could turn two-step off again or bring a used code back, version included. **Decision 2 is replaced:** the state lives in the plugin's own `two-step-state` collection, one document per account (unique `user`, access false), which nothing in Payload's sign-in, refresh or logout touches. The version guard works as designed there.
   - This **replaces "no migration"**. With `legacyUserField: 'twoStep'`, the plugin moves state kept on the account into its collection once at startup (copying only where the account has none yet), then removes it from the account. It refuses to start while the auth collection still declares that field.
   - Tests: a sign-in begun before confirm doesn't turn two-step off; one recovery code signs in once when the second sign-in began first; the move runs once and two-step stays on.
2. **Blocker: the built-in limiter could be outrun in parallel.** It now records the try first, then allows it only if it's among the window's first five (ordered by time then id, the same for every request), outside the request's transaction. Under a race some tries are refused that might have fitted, never the other way. Test: of 40 tries at once, at most 5 get through (it fails with the old count-then-record limiter).
3. **Should: per-session records and `lastStep`** stopped being lost once the state moved; the refresh tests pass on the new collection.
4. **Smaller: a remembered sign-in whose session record loses a race** now reads the state again and tries once more, and logs if that fails too.

Found while doing this: **the key must come from the raw app secret** (`payload.config.secret`), as the first site derives it. `payload.secret` is Payload's own hash of it and gives a different key, which would have left the site's stored authenticator secrets unreadable. The move test proves a secret sealed the site's way opens and signs in.

## Renamed, and Platform's final read (2026-11-10)

- **Renamed** to `payload-plugin-mfa` by the owner (see `docs/decisions.md`). The text above keeps its original names (two-step, `twoStep()`, `two-step-state`); in the code they're now `mfa()`, `MfaError`, `MFA_*`, `mfa-state` and `mfa-attempts`.
- **Attempt records expire.** Every try writes a record, refused ones included. Tries older than the window are now deleted as new ones arrive, with a test.
- **The legacy move is explicit.** It runs as `moveLegacyState(payload)`, a script the site runs once after a backup, not at every cold start where two instances could race. An account whose old state hasn't moved can't sign in, so nothing runs half-moved. An existing new state counts as moved; a setup never confirmed is dropped and counted.
- **Clock skew** between servers is documented as a limit of the try order.
