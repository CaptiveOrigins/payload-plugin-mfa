# Test audit

## 2026-11-10: full self-audit (K29)

Read the README, `docs/decisions.md`, ADR 0001 and `src/`, and mapped each promise to `test/mfa.test.ts`. The baseline was 29 tests. It's now 44. Every test runs against a real Payload 3.92 with an in-memory MongoDB. Nothing here is mocked except the limiter in the key test and the clock (backdated state).

| Promise | Test |
| --- | --- |
| A code after the password once it's on; REST and GraphQL login can't carry one | `signing in > needs nothing extra…` |
| An app code works once, even inside its drift window | `signing in > uses each app code once…` |
| The code that confirmed setup can't sign in again | `fail-closed… > confirms only a pending app…` (new) |
| `confirm` needs a pending app and its right code | `fail-closed… > confirms only a pending app…` (new) |
| A recovery code is used up | `signing in > uses a recovery code once` |
| An emailed code works once | `signing in > takes an emailed code once…` |
| An emailed code expires | `fail-closed… > refuses an emailed code once it has expired` (new) |
| 3 emailed codes per window per account | `fail-closed… > sends at most three emailed codes…` (new) |
| After a new password, emailed codes are off and an outstanding one is cleared | `signing in > takes an emailed code once…`, `fail-closed… > refuses an emailed code sent before a new password…` (new) |
| The plugin blocks emailed codes by itself after Payload's `resetPassword` | `signing in > blocks emailed codes by itself…` |
| A secret that can't be opened refuses app codes; recovery codes still work; odd state counts as on | `fail-closed… > refuses app codes when the secret can't be opened…` (new) |
| `requiredFor` at sign-in; a throwing rule counts as required; the staff window ends at confirm | `who must use it > refuses a required account…` |
| `requiredFor` on every request for open sessions | `who must use it > signs out, on its next request…` |
| `requiredFor` on every refresh, including a throwing rule | `fail-closed… > refuses a refresh for an account that must have two-step…` (new) |
| Per-session expiry; one device's code doesn't extend another | `sessions… > counts a code per session…` |
| Remembered browser; an edited cookie or a new password ends it | `sessions… > a remembered browser…` |
| A new app ends a remembered browser; a value claiming more than the window is refused | `fail-closed… > ends a remembered browser when a new app is set up…` (new) |
| A remembered sign-in's session counts from the code, not from now | `fail-closed… > a remembered sign-in counts from when the code was given…` (new) |
| 5 code tries per window per account, never by address | `limits > limits per account…` |
| A per-address limit on top, shared across accounts | `fail-closed… > limits per address on top…` (new) |
| The limiter key is built inside; a throwing limiter refuses | `limits > builds the limiter's key itself…` |
| The built-in limit holds under 40 tries at once; old tries are deleted | `races… > the built-in limit…`, `races… > deletes tries older…` |
| A sign-in begun earlier can't undo two-step or reuse a code | `races… > a sign-in that began before…`, `races… > one recovery code signs in once…` |
| Moving the factor needs an app or recovery code, never an emailed one | `changing the factor > won't move two-step…` |
| Turning off with a current code | `changing the factor > turns off…` |
| `turnOff` and `newRecoveryCodesFor` refuse without two-step, refuse a wrong code, and are limited | `fail-closed… > turnOff and newRecoveryCodesFor refuse…` (new) |
| `verify` takes a good code once; one winner under concurrency | `step-up > verify() takes a good code once…` |
| `verify` refuses an account without two-step, and is limited | `fail-closed… > verify() refuses an account without two-step…` (new) |
| `statusFor`, `resetFor` | the K25 section below |
| `sendEmailCode` answers the same for an unknown address | `telling nothing… > sends nothing…` |
| Events carry no code, secret, email or client address in their fields | `telling nothing… > never puts a code or secret…`, `fail-closed… > never puts an email or client address…` (new) |
| The state is hidden from API reads | `telling nothing… > never puts a code or secret…` |
| Both collections are closed to every API read and write | `fail-closed… > keeps both of its collections closed…` (new) |
| The endpoint answers an unknown email like a wrong password, needs a code, sets the cookies | `the login endpoint > answers an unknown email…` |
| The endpoint ignores a trusted flag in the body, refuses a wrong code, sets the remember cookie HttpOnly and SameSite=Lax, and takes it back | `fail-closed… > the login endpoint ignores a trusted flag…` (new) |
| Secrets sealed the way the first site seals them open | `telling nothing… > opens an app secret sealed…` |
| Unmoved legacy state can't sign in; the move is explicit and repeatable | `moving state… > refuses an account with unmoved state…` |
| Refuses to start: short secret, no auth collection, API keys, legacy field declared | `refusing to start > …`, `moving state…` |
| Refuses to start: `rememberHours` not longer than the token, or a clashing collection | `fail-closed… > refuses to start when rememberHours…` (new) |

### Gaps added

The 15 tests in `fail-closed cases and refusals (audit K29)`, listed as "(new)" above. Most are fail-closed checks or refusals that were promised but only exercised on the happy path, or not at all: an expired emailed code, the emailed-code send limit, the per-address limit, the refresh check for required accounts, the remember window's upper bound, a remembered session dated from its code, the limiter on `verify`, `turnOff` and `newRecoveryCodesFor`, write and delete access on both collections, and the endpoint ignoring a trusted flag in its body.

### Mutation check

Each guard was broken in `src/` (a Python string replace, `src/` copied first and restored after), and the suite run.

24 of 26 caught. The two not caught are guards that a stronger one already covers:

| Guard broken | Result |
| --- | --- |
| Emailed code expiry | caught |
| Emailed-code send limit | caught |
| Emailed codes refused while blocked (`acceptCode`) | caught (by the new direct check) |
| `afterPasswordSet` clears an outstanding emailed code | not caught: the block refuses the code anyway |
| Both of the two above at once | caught |
| App codes refused when the secret can't be opened | caught |
| `confirm` stores the step it used | caught |
| `confirm` refuses a wrong code | caught |
| `confirm` needs a pending app | caught |
| Remember value can't claim more than the window | caught |
| Remember value tied to the secret | caught |
| Remembered session dated from the code | caught |
| Refresh refused for a required account without two-step | caught |
| A throwing `requiredFor` counts as required | caught |
| Limiter on `verify` | caught |
| `verify` needs two-step on | not caught: with no secret, no recovery codes and no emailed code, `acceptCode` refuses every code anyway |
| Limiter on `turnOff` and `newRecoveryCodesFor` | caught |
| `turnOff` and `newRecoveryCodesFor` need two-step on | caught |
| Per-address limit | caught |
| `mfa-state` update closed | caught |
| `mfa-state` delete closed | caught |
| `mfa-attempts` read closed | caught |
| The endpoint keeps its body out of `req.context` | caught |
| Remember cookie is HttpOnly | caught |
| Startup: `rememberHours` longer than the token | caught |
| Startup: refuses a clashing collection | caught |

### Gaps skipped, and why

- **The built-in limiter's window rollover.** Plain count-since-time code; the per-account test shows the refusal, and the delete test shows the window edge.
- **Recovery codes typed in lower case or without dashes.** Convenience, not safety.
- **The per-request check runs only when `requiredFor` is set.** Cost, not safety; the reset check runs either way and is tested.
- **The issuer and label in the app link, `isOnFor`, `statusFor`'s plain reads.** Trivial, or covered by stronger tests.
- **The default email text through `payload.sendEmail`.** Framework plumbing; every test uses `sendEmailCode`.
- **Payload's own lockout, CSRF and cookie rules on the endpoint.** Payload internals.
- **Real HTTP requests to REST, GraphQL and the endpoint.** The tests call `payload.login` with no context, which is the same path. A real browser test belongs with the site wiring.

### Found, not fixed (for the lead)

- **Events carry the request, and the request carries the code and the address.** `onEvent` gets `{ type, user, req, detail }`. `detail` is clean, but `req.context.mfaCode` holds the code just entered, and `req.headers` holds the client address. Checked: after a sign-in with a recovery code, the `recovery-used` event's `req.context` was `{ mfaCode: <that code> }`. On `too-many-tries` that can be a right code that was refused, so still unused. The README says the event "never contains a code, secret or address", which is true of `detail` only. The existing test strips `req` before checking. Not fixed: the fix is either to drop `req` from events or to say plainly that `req` carries both, and that's a design call.
- **`too-many-tries` isn't sent "at most once per window"**, as ADR 0001 decision 11 says. It's sent on every refused sign-in and `verify`, and not at all from `start`, `confirm`, `turnOff` or `newRecoveryCodesFor`. The code and the ADR disagree; one should change.
- **`allowEnrollment` has no upper bound on `hours`.** The README calls it "a short window", and `resetFor` caps its window at 14 days, but `allowEnrollment` takes any number. A promise only written down.
- **`verify` accepts an emailed code.** `start`, `turnOff` and `newRecoveryCodesFor` refuse one, because it only proves the mailbox. For step-up before a sensitive action, that may be too weak. Nothing promises either way; worth deciding.
- **For the lead, bigger:** a test through real HTTP (REST login, GraphQL login and the endpoint behind the site's server) belongs with the site wiring.

## 2026-11-10 (0.1.0)

Each promise in the README and ADR 0001, and the test that proves it (`test/mfa.test.ts`):

| Promise | Test |
| --- | --- |
| A code after the password once on; REST and GraphQL can't carry one | "needs nothing extra until two-step is on…" |
| App codes used once, including within drift | "uses each app code once…" (fails without the step check) |
| Recovery codes used once; events record it without the code | "uses a recovery code once" |
| Emailed codes once; none after a new password | "takes an emailed code once…" |
| Blocked after Payload's own reset, by the plugin | "blocks emailed codes by itself…" |
| Required accounts refused; a throwing rule counts as required; the window ends at confirm | "refuses a required account…" (fails when a throw counts as not required) |
| Open sessions of newly required accounts are signed out | "signs out, on its next request…" |
| Per-session expiry; one device's code doesn't extend another | "counts a code per session…" |
| Remembered browser; edited cookie and new password end it | "a remembered browser…" |
| Per-account limit, never by address | "limits per account…" (fails with the address in the key) |
| Limiter key built inside; a throwing limiter refuses | "builds the limiter's key itself…" |
| Moving the factor needs an app or recovery code, not email | "won't move two-step…" |
| Turning off | "turns off with a current code…" |
| Step-up `verify`; one winner under concurrency | "verify() takes a good code once…" (fails without the version guard) |
| Same answer for unknown addresses | "sends nothing, and says nothing different…" |
| No codes or secrets in events; state hidden from API reads | "never puts a code or secret…" |
| Secrets sealed by the first site today open | "opens an app secret sealed the way…" |
| Endpoint: unknown email like a wrong password; needs a code; sets cookies | "answers an unknown email like a wrong password…" |
| Startup refusals (short secret, no auth collection, API keys) | "with a short app secret…" |
| A sign-in begun earlier can't turn two-step off | "a sign-in that began before two-step was confirmed…" (Platform's repro) |
| A recovery code signs in once against an earlier-begun sign-in | "one recovery code signs in once…" (Platform's repro) |
| The limiter holds under 40 tries at once | "the built-in limit lets at most five…" (fails with count-then-record) |
| Old state: refused until moved, moved by an explicit run (repeatable), then signs in | "refuses an account with unmoved state…" (also proves the raw-secret key) |
| Old tries are deleted | "deletes tries older than the window…" |

Gaps, skipped with reason: the built-in limiter's window rollover (simple count-since-time code, covered by the per-account test's refusal); `rememberHours` versus `tokenExpiration` at startup (a config check, low risk). Bigger: a test against a real browser flow belongs to the site's wiring.

## 2026-11-10: statusFor and resetFor (K25)

| Promise | Test |
| --- | --- |
| statusFor gives on, since and recovery left, and nothing else; recovery counts down | `status and a maintainer's reset > reports on…` |
| resetFor clears the secret, recovery codes, emailed code and sessions; the old code, recovery codes and remembered browsers stop working; a required account must enrol once the window ends; `reset` event with the actor; bad window and unknown account refused | `status and a maintainer's reset > resets without a code…` |
| resetFor clears the account's limiter tries, and wins or retries against a racing sign-in | `status and a maintainer's reset > clears the account's limiter tries…` |

| resetFor signs the account out everywhere (unless `endSessions: false`) and keeps the email-code block | `status and a maintainer's reset > signs the account out…` |
| Sessions made before a reset stay refused at request and refresh even when written back by a racing sign-in; `endSessions: false` keeps them | `status and a maintainer's reset > signs the account out…` |
| turnOff keeps the reset time; an undated session is refused, a later one isn't, no reset means no check | `status and a maintainer's reset > signs the account out…` |
| resetFor wins against a racing write that would keep the old secret | `status and a maintainer's reset > wins against a racing write…` |

Gaps added: the five tests above; the last two after the security read (a subagent, Plugin Security's checklist) found the version guard, the upper bound and the kept email block caught only elsewhere or not at all. A mutation check now catches 9 of 9 guards in these tests, after one assertion was added: kept recovery codes weren't caught at first, because a required account is refused for enrollment before any code is checked. Gaps skipped: a site's own limiter isn't cleared by resetFor (said in the README).
