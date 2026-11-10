# Test audit

## 2026-11-10 (0.1.0)

Each promise in the README and ADR 0001, and the test that proves it (`test/two-step.test.ts`):

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
| Old state moves once from the account and signs in | "moves it once at startup…" (also proves the raw-secret key) |

Gaps, skipped with reason: the built-in limiter's window rollover (simple count-since-time code, covered by the per-account test's refusal); `rememberHours` versus `tokenExpiration` at startup (a config check, low risk). Bigger: a test against a real browser flow belongs to the site's wiring.
