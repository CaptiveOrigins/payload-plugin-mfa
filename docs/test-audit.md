# Test audit

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
| Secrets sealed by Captive Origins today open | "opens an app secret sealed the way…" |
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
