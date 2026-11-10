# payload-plugin-two-step

Two-step sign-in for Payload: an authenticator code after the password, with emailed and recovery codes as backups, each used once, limited per account, and required by a rule you set.

**Status:** early, 0.1.0, not on npm yet. 23 tests pass against a real Payload 3.92 with an in-memory MongoDB, covering every factor, replays, the limits (including 40 tries at once), remembered browsers, per-session expiry, the required rule, the login endpoint, and races with Payload's own sign-in (a sign-in begun earlier can't undo two-step or reuse a code). It's extracted from the version Captive Origins runs, but this package itself isn't in use on any site yet, and it has no screens of its own: your site builds the sign-in and settings pages.

## What it does

- **After the password, a code.** From an authenticator app (6 digits, one 30-second step of clock drift allowed), or as backups an emailed code (8 digits, 10 minutes) or one of 10 recovery codes. No text messages.
- **Each code works once.** An app code can't be replayed, even within its drift window. An emailed or recovery code is used up. Two requests racing with the same code can't both win.
- **Limited per account, never by address.** 5 code tries and 3 emailed codes per 15 minutes per account, so changing address gives no fresh tries. An optional per-address limit sits on top. Bring your own limiter with `limit`; the plugin builds the key itself.
- **Required by your rule.** `requiredFor` decides who must have it. It's checked at sign-in, on every refresh, and on every request for open sessions, and if it throws the account counts as required. A required account that hasn't enrolled can't sign in, so a stolen password can't enrol its own phone. Staff can open a short window with `allowEnrollment`.
- **Remembered browsers.** After a code, the site can set a cookie so the password alone works for 24 hours. A new password or a new app ends it. A session can't outlive the code it came from, counted per session, so one device's code never extends another.
- **After a password reset,** emailed codes are off for 24 hours, since the mailbox has just proved itself. The plugin does this by itself after Payload's `resetPassword`.
- **Nothing readable.** The secret is sealed with AES-256-GCM, using a key derived from your app secret. Codes are stored hashed. The state lives in its own `two-step-state` collection (one document per account), hidden from every API read and never written by Payload's sign-in.

## Install

```bash
npm install @captiveorigins/payload-plugin-two-step
```

```ts
import { twoStep } from '@captiveorigins/payload-plugin-two-step'

export default buildConfig({
  plugins: [
    twoStep({
      requiredFor: ({ user }) => user.roles?.includes('admin') ?? false,
      issuer: 'My site',
      onEvent: (event) => auditLog(event), // never contains a code, secret or address
    }),
  ],
})
```

## Using it

HTTP can't carry the code: it travels in `req.context`, which only your server code can set. So:

- **Sign in** from a server action with `signIn(payload, { email, password, code })`, or with `remember` (the cookie's value) instead of `code`. Errors are Payload's usual ones; a `TwoStepError` has `twoStep: 'needed' | 'wrong' | 'enroll'`. After a good code, set the `REMEMBER_COOKIE` cookie (HttpOnly) to `await rememberValue(payload, { userId })`. Sites without server actions can turn on `endpoint: true` for `POST /api/users/two-step/login { email, password, code }`, which sets both cookies.
- **Set up** with `start(payload, { userId })`, which returns `{ uri, key }` for a QR code, and then `confirm(payload, { userId, code })`, which returns the recovery codes once. Check the person's password before `start`. If two-step is already on, `start` needs a current app or recovery code.
- **Turn off or renew codes** with `turnOff` and `newRecoveryCodesFor`. Check the password first; both need an app or recovery code (an emailed code only proves the mailbox).
- **Emailed codes:** `sendEmailCode(payload, { email })`. It answers the same whatever the address, so say "if that account uses two-step, we've sent a code".
- **Step-up** before a sensitive action: `verify(payload, { user, code, req })`. For Hats: `stepUp: { available: (u) => isOnFor(payload, u.id), verify: ({ user, code, req }) => verify(payload, { user, code, req }) }`.
- **Your own vouching:** pass `context: { [TWO_STEP_TRUSTED]: true }` to `payload.login` only from server code that has checked the person another way, or that throws the token away (for example, checking a password).
- **Invitations:** after a password set through an emailed link, call `afterPasswordSet(payload, { userId })`.

## Moving from state kept on the account

If your site kept two-step state in a group on the account (Captive Origins did, as `twoStep`), remove that field from the auth collection and pass `legacyUserField: 'twoStep'` (plus the `keyDerivation` values you used). At startup the plugin copies each account's old state into its collection, where it has none yet, then removes it from the account. MongoDB only. Back up first; on Captive Origins, this needs the owner's yes before it runs on prod.

## Limits

- **API keys aren't supported** on the same collection: they sign in without a password or code, so the plugin refuses to start with `useAPIKey` on. Keep API keys on another collection. A custom auth strategy is your code's job: check `isOnFor` and your rule there.
- **Payload's own reset page can't collect a code.** For an enrolled account, reset the password through your own form, with a code (or `TWO_STEP_TRUSTED` once you've checked one).
- **The per-request check** for open sessions looks the account up once per authenticated request, and only when you set `requiredFor`.
- **Changing the app secret** (or the `keyDerivation` values) makes stored authenticator secrets unreadable. People then sign in with a recovery code and set up again.
- **The plugin's own state writes go straight to the database,** so collection hooks (an audit trail's included) don't see them; `onEvent` is the record.
- **The emailed code's default wording is English.** Pass `sendEmailCode` for your own.

## Commands

```bash
npm test          # Vitest, in-memory MongoDB
npm run typecheck
npm run build
```

## License

MIT
