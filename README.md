# payload-plugin-mfa

MFA for Payload (two-step sign-in): an authenticator code after the password, with emailed and recovery codes as backups, each used once, limited per account, and required by a rule you set.

**Status:** early, 0.1.0, not on npm yet. 29 tests pass against a real Payload 3.92 with an in-memory MongoDB, covering every factor, replays, the limits (including 40 tries at once), remembered browsers, per-session expiry, the required rule, the login endpoint, and races with Payload's own sign-in (a sign-in begun earlier can't undo two-step or reuse a code). It's extracted from the version Captive Origins runs, but this package itself isn't in use on any site yet, and it has no screens of its own: your site builds the sign-in and settings pages.

## What it does

- **After the password, a code.** From an authenticator app (6 digits, one 30-second step of clock drift allowed), or as backups an emailed code (8 digits, 10 minutes) or one of 10 recovery codes. No text messages.
- **Each code works once.** An app code can't be replayed, even within its drift window. An emailed or recovery code is used up. Two requests racing with the same code can't both win.
- **Limited per account, never by address.** 5 code tries and 3 emailed codes per 15 minutes per account, so changing address gives no fresh tries. An optional per-address limit sits on top. Bring your own limiter with `limit`; the plugin builds the key itself.
- **Required by your rule.** `requiredFor` decides who must have it. It's checked at sign-in, on every refresh, and on every request for open sessions, and if it throws the account counts as required. A required account that hasn't enrolled can't sign in, so a stolen password can't enrol its own phone. Staff can open a short window with `allowEnrollment`.
- **Remembered browsers.** After a code, the site can set a cookie so the password alone works for 24 hours. A new password or a new app ends it. A session can't outlive the code it came from, counted per session, so one device's code never extends another.
- **After a password reset,** emailed codes are off for 24 hours, since the mailbox has just proved itself. The plugin does this by itself after Payload's `resetPassword`.
- **Nothing readable.** The secret is sealed with AES-256-GCM, using a key derived from your app secret. Codes are stored hashed. The state lives in its own `mfa-state` collection (one document per account), hidden from every API read and never written by Payload's sign-in.

## Install

```bash
npm install @captiveorigins/payload-plugin-mfa
```

```ts
import { mfa } from '@captiveorigins/payload-plugin-mfa'

export default buildConfig({
  plugins: [
    mfa({
      requiredFor: ({ user }) => user.roles?.includes('admin') ?? false,
      issuer: 'My site',
      onEvent: (event) => auditLog(event), // never contains a code, secret or address
    }),
  ],
})
```

## Using it

HTTP can't carry the code: it travels in `req.context`, which only your server code can set. So:

- **Sign in** from a server action with `signIn(payload, { email, password, code })`, or with `remember` (the cookie's value) instead of `code`. Errors are Payload's usual ones; an `MfaError` has `mfa: 'needed' | 'wrong' | 'enroll'`. After a good code, set the `REMEMBER_COOKIE` cookie (HttpOnly) to `await rememberValue(payload, { userId })`. Sites without server actions can turn on `endpoint: true` for `POST /api/users/mfa/login { email, password, code }`, which sets both cookies.
- **Set up** with `start(payload, { userId })`, which returns `{ uri, key }` for a QR code, and then `confirm(payload, { userId, code })`, which returns the recovery codes once. Check the person's password before `start`. If two-step is already on, `start` needs a current app or recovery code.
- **Turn off or renew codes** with `turnOff` and `newRecoveryCodesFor`. Check the password first; both need an app or recovery code (an emailed code only proves the mailbox).
- **Emailed codes:** `sendEmailCode(payload, { email })`. It answers the same whatever the address, so say "if that account uses two-step, we've sent a code".
- **Step-up** before a sensitive action: `verify(payload, { user, code, req })`. For Hats: `stepUp: { available: (u) => isOnFor(payload, u.id), verify: ({ user, code, req }) => verify(payload, { user, code, req }) }`.
- **Your own vouching:** pass `context: { [MFA_TRUSTED]: true }` to `payload.login` only from server code that has checked the person another way, or that throws the token away (for example, checking a password).
- **Invitations:** after a password set through an emailed link, call `afterPasswordSet(payload, { userId })`.
- **Status** for the person's own security page: `statusFor(payload, userId)` gives `{ on, since, recoveryLeft }`, and nothing about the secret or the codes. Pass the signed-in person's own id; it trusts the id it's given.
- **A maintainer's reset**, for someone who lost their app and their recovery codes: `resetFor(payload, userId, { enrollHours, actor })`.
  - It needs no code, so check the maintainer, and confirm who you're resetting another way, in your own code first.
  - It clears the app, the recovery codes, any emailed code and the per-session records. Remembered browsers stop working.
  - It signs the account out everywhere, because a stolen phone may have a session open. Pass `endSessions: false` to keep them. It also records when the reset happened, and any session made before then is refused at every request and refresh. That holds even if a sign-in racing the reset wrote the old sessions back, so each signed-in request reads the account's two-step state once (one small query). This needs Payload's sessions (`auth.useSessions`, on by default). With sessions off there's nothing to end, and old tokens keep working until they expire.
  - It opens an enrollment window: default 24 hours, at most 14 days. During it, anyone who knows the password can set up a phone. Keep it short, and reset the password too if it may be known.
  - It clears the account's built-in limiter tries. A limiter of your own isn't cleared.
  - It sends a `reset` event with `by`: pass the maintainer's id as `actor`, never an email address. If your `onEvent` throws, the reset has still happened.
  - A block on emailed codes after a password reset stays.
  - Neither function has an endpoint.

## Moving from state kept on the account

If your site kept two-step state in a group on the account (Captive Origins did, as `twoStep`):
1. Back up the database. On Captive Origins this needs the owner's yes before it runs on prod.
2. Remove that field from the auth collection and pass `legacyUserField: 'twoStep'`, plus the `keyDerivation` values you used. The plugin refuses to start while the field is still declared.
3. Run `await moveLegacyState(payload)` once, as a script. It copies each account's old state where the account has none yet (one that already exists counts as moved), removes the old field, and returns what it did. A setup that was never confirmed is dropped and counted. It's safe to run again. MongoDB only.

Until an account's old state is moved, that account can't sign in, so nothing runs half-moved with weaker sign-in.

## Limits

- **API keys aren't supported** on the same collection: they sign in without a password or code, so the plugin refuses to start with `useAPIKey` on. Keep API keys on another collection. A custom auth strategy is your code's job: check `isOnFor` and your rule there.
- **Payload's own reset page can't collect a code.** For an enrolled account, reset the password through your own form, with a code (or `MFA_TRUSTED` once you've checked one).
- **The per-request check** for open sessions looks the account up once per authenticated request, and only when you set `requiredFor`.
- **Changing the app secret** (or the `keyDerivation` values) makes stored authenticator secrets unreadable. People then sign in with a recovery code and set up again.
- **The plugin's own state writes go straight to the database,** so collection hooks (an audit trail's included) don't see them; `onEvent` is the record.
- **The try limit orders tries by each server's clock.** If your servers' clocks disagree, a burst could get a few extra tries through. Keep clocks in sync (they are on any managed host).
- **Old tries are deleted** as new ones arrive, so the try table stays small.
- **The emailed code's default wording is English.** Pass `sendEmailCode` for your own.

## Commands

```bash
npm test          # Vitest, in-memory MongoDB
npm run typecheck
npm run build
```

## License

MIT
