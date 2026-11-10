import type { Payload, PayloadRequest, RequestContext } from 'payload'

import { appLink, newEmailCode, newRecoveryCodes, newSecret, seal, emailCodeHash } from './crypto.js'
import {
  acceptCode,
  acceptPending,
  allowed,
  clearAccountTries,
  emailBlocked,
  emit,
  isOnState,
  keysOf,
  loadState,
  loadUser,
  optionsOf,
  rememberValueFor,
  saveIfUnchanged,
  MFA_CODE,
  MFA_REMEMBER,
  withSession,
} from './core.js'
import type { MfaState, MfaUser } from './types.js'

const HOUR = 60 * 60_000

/** A refusal a site can show, with a stable reason. */
export class MfaRefused extends Error {
  constructor(
    readonly reason: 'notFound' | 'notOn' | 'alreadyOn' | 'needsCode' | 'wrongCode' | 'tooMany' | 'noPending' | 'busy',
    message: string,
  ) {
    super(message)
    this.name = 'MfaRefused'
  }
}

const refuse = (reason: MfaRefused['reason'], message: string): never => {
  throw new MfaRefused(reason, message)
}

async function load(payload: Payload, userId: string | number, req?: PayloadRequest) {
  const user = await loadUser(payload, userId, req)
  if (!user) refuse('notFound', 'That account wasn’t found.')
  const loaded = await loadState(payload, user!.id, req)
  return { user: user!, loaded, state: loaded.state }
}

/** Whether an account has two-step on. For step-up checks: `stepUp.available` in Hats. */
export async function isOnFor(payload: Payload, userId: string | number, req?: PayloadRequest) {
  return isOnState((await loadState(payload, userId, req)).state)
}

/**
 * Checks a code for an account that's already signed in, e.g. before a sensitive action (Hats' step-up). Limited
 * per account, each code used once, safe under concurrency. Records the code against the request's session.
 */
export async function verify(payload: Payload, args: { user: { id: string | number } & Record<string, unknown>; code: unknown; req?: PayloadRequest }): Promise<boolean> {
  const user = await loadUser(payload, args.user.id, args.req)
  if (!user) return false
  const loaded = await loadState(payload, user.id, args.req)
  const state = loaded.state
  if (!isOnState(state)) return false
  if (!(await allowed(payload, 'code', user.id, args.req))) {
    await emit(payload, { type: 'too-many-tries', user: String(user.id), req: args.req })
    return false
  }
  const accepted = acceptCode(keysOf(payload), state, args.code)
  if (!accepted) return false
  const sid = (args.req?.user as { _sid?: string } | null | undefined)?._sid
  const next = withSession(accepted.next, user, sid, new Date().toISOString())
  if (!(await saveIfUnchanged(payload, user.id, loaded, next, args.req))) return false
  if (accepted.used === 'recovery') await emit(payload, { type: 'recovery-used', user: String(user.id), req: args.req, detail: { left: next.recovery?.length ?? 0 } })
  return true
}

/**
 * Signs in for server code (a Next server action, say): Payload's own login with the code or the remembered value
 * in context, where HTTP can't put them. Throws Payload's usual error; a `MfaError` says `needed`, `wrong` or `enroll`.
 */
export async function signIn(payload: Payload, args: { email: string; password: string; code?: string; remember?: string; req?: PayloadRequest; context?: RequestContext }) {
  const o = optionsOf(payload)
  const context: RequestContext = { ...(args.context ?? {}), ...(args.code ? { [MFA_CODE]: args.code } : args.remember ? { [MFA_REMEMBER]: args.remember } : {}) }
  return payload.login({ collection: o.users as never, data: { email: args.email, password: args.password }, context, ...(args.req ? { req: args.req } : {}) })
}

/** The remember cookie's value for an account that has just given a code. The site sets the cookie (HttpOnly). */
export async function rememberValue(payload: Payload, args: { userId: string | number; req?: PayloadRequest }) {
  const user = await loadUser(payload, args.userId, args.req)
  return user ? rememberValueFor(payload, user, (await loadState(payload, user.id, args.req)).state) : ''
}

/**
 * Begins setting up an app. The site checks the password first. If two-step is already on, a current app code or
 * a recovery code must come with it, so a signed-in session can't move the factor to another phone.
 */
export async function start(payload: Payload, args: { userId: string | number; code?: unknown; req?: PayloadRequest }): Promise<{ uri: string; key: string }> {
  const o = optionsOf(payload)
  const { user, loaded, state } = await load(payload, args.userId, args.req)
  let base: MfaState = state
  if (isOnState(state)) {
    if (typeof args.code !== 'string' || !args.code.trim()) refuse('needsCode', 'Enter a code from your current app, or a recovery code, to set up a new one.')
    if (!(await allowed(payload, 'code', user.id, args.req))) refuse('tooMany', 'Too many tries. Please wait a few minutes.')
    const accepted = acceptCode(keysOf(payload), state, args.code)
    if (!accepted || accepted.used === 'email') refuse('wrongCode', 'That code didn’t work.')
    base = accepted!.next
  }
  const secret = newSecret()
  if (!(await saveIfUnchanged(payload, user.id, loaded, { ...base, pending: seal(keysOf(payload), secret) }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'started', user: String(user.id), req: args.req })
  return { uri: appLink(secret, o.issuer, String(user.email ?? user.id)), key: secret }
}

/** The first code from the app proves it works: two-step goes on, and the recovery codes are returned once. */
export async function confirm(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }): Promise<{ recoveryCodes: string[] }> {
  const { user, loaded, state } = await load(payload, args.userId, args.req)
  if (!state.pending) refuse('noPending', 'Start again: there’s no app waiting to be confirmed.')
  if (!(await allowed(payload, 'code', user.id, args.req))) refuse('tooMany', 'Too many tries. Please wait a few minutes.')
  const step = acceptPending(keysOf(payload), state, args.code)
  if (step === null) refuse('wrongCode', 'That code didn’t work. Check the time on your phone and try the next code.')
  const { codes, hashes } = newRecoveryCodes()
  const now = new Date().toISOString()
  const sid = (args.req?.user as { _sid?: string } | null | undefined)?._sid
  const next = withSession(
    { ...state, secret: state.pending, pending: null, enabledAt: now, lastStep: step, recovery: hashes, enrollUntil: null, emailCode: null, emailCodeExpires: null },
    user,
    sid,
    now,
  )
  if (!(await saveIfUnchanged(payload, user.id, loaded, next, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'confirmed', user: String(user.id), req: args.req })
  return { recoveryCodes: codes }
}

async function withCode(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }) {
  const { user, loaded, state } = await load(payload, args.userId, args.req)
  if (!isOnState(state)) refuse('notOn', 'Two-step isn’t on for this account.')
  if (!(await allowed(payload, 'code', user.id, args.req))) refuse('tooMany', 'Too many tries. Please wait a few minutes.')
  const accepted = acceptCode(keysOf(payload), state, args.code)
  // Changing the factor itself needs the app or a recovery code: an emailed code only proves the mailbox.
  if (!accepted || accepted.used === 'email') refuse('wrongCode', 'Enter a code from your app, or a recovery code.')
  return { user, loaded, state, accepted: accepted! }
}

/** Turns two-step off. The site checks the password first; a current code (or recovery code) is needed too. */
export async function turnOff(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }) {
  const { user, loaded, state } = await withCode(payload, args)
  const cleared: MfaState = { secret: null, pending: null, enabledAt: null, lastStep: null, recovery: [], verifiedAt: null, sessions: {}, emailCode: null, emailCodeExpires: null, emailBlockedUntil: state.emailBlockedUntil ?? null, enrollUntil: null }
  if (!(await saveIfUnchanged(payload, user.id, loaded, cleared, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'turned-off', user: String(user.id), req: args.req })
}

/** New recovery codes, returned once; the old ones stop working. The site checks the password first; a current code is needed too. */
export async function newRecoveryCodesFor(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }): Promise<{ recoveryCodes: string[] }> {
  const { user, loaded, accepted } = await withCode(payload, args)
  const { codes, hashes } = newRecoveryCodes()
  if (!(await saveIfUnchanged(payload, user.id, loaded, { ...accepted.next, recovery: hashes }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'recovery-renewed', user: String(user.id), req: args.req })
  return { recoveryCodes: codes }
}

/**
 * Emails a code to an account that has two-step on. Answers the same whether or not the address exists, has
 * two-step, is blocked after a reset or has had too many: the caller always says "if that account uses two-step,
 * we've sent a code".
 */
export async function sendEmailCode(payload: Payload, args: { email: string; req?: PayloadRequest }): Promise<void> {
  const o = optionsOf(payload)
  const email = String(args.email ?? '').trim().toLowerCase()
  if (!email) return
  const found = (await payload.find({ collection: o.users as never, where: { email: { equals: email } }, limit: 1, depth: 0, overrideAccess: true, showHiddenFields: true, ...(args.req ? { req: args.req } : {}) })).docs[0] as unknown as MfaUser | undefined
  if (!found) return
  const loaded = await loadState(payload, found.id, args.req)
  const state = loaded.state
  if (!isOnState(state) || emailBlocked(state)) return
  if (!(await allowed(payload, 'emailCode', found.id, args.req))) return
  const code = newEmailCode()
  const saved = await saveIfUnchanged(payload, found.id, loaded, { ...state, emailCode: emailCodeHash(keysOf(payload), code), emailCodeExpires: new Date(Date.now() + o.emailCodeMinutes * 60_000).toISOString() }, args.req)
  if (!saved) return
  const send = o.sendEmailCode ?? (({ payload: p, to, code: c, minutes }) => p.sendEmail({ to, subject: 'Your sign-in code', text: `Your sign-in code is ${c}. It works once, for ${minutes} minutes.\n\nIf you didn't try to sign in, someone may know your password: change it.` }))
  try {
    await send({ payload, to: email, code, minutes: o.emailCodeMinutes, req: args.req })
    await emit(payload, { type: 'email-code-sent', user: String(found.id), req: args.req })
  } catch (error) {
    payload.logger.error({ err: error, msg: 'mfa: an email code was not sent' })
  }
}

/** Lets an account that must have two-step sign in to set it up, for a while (staff, for one person). Ends at the first confirm. */
export async function allowEnrollment(payload: Payload, args: { userId: string | number; hours?: number; req?: PayloadRequest }) {
  const { user, loaded, state } = await load(payload, args.userId, args.req)
  const until = new Date(Date.now() + (args.hours ?? 24) * HOUR).toISOString()
  if (!(await saveIfUnchanged(payload, user.id, loaded, { ...state, enrollUntil: until }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'enrollment-window', user: String(user.id), req: args.req, detail: { hours: args.hours ?? 24 } })
}

/**
 * After a new password set through the mailbox (a reset, an invitation link): emailed codes are off for a while
 * and any outstanding one is cleared. The plugin runs this itself after Payload's `resetPassword`.
 */
export async function afterPasswordSet(payload: Payload, args: { userId: string | number; req?: PayloadRequest }) {
  const o = optionsOf(payload)
  for (let i = 0; i < 3; i++) {
    const loaded = await loadState(payload, args.userId, args.req)
    const state = loaded.state
    const next = { ...state, emailCode: null, emailCodeExpires: null, emailBlockedUntil: new Date(Date.now() + o.emailBlockHours * HOUR).toISOString() }
    if (await saveIfUnchanged(payload, args.userId, loaded, next, args.req)) {
      await emit(payload, { type: 'email-codes-blocked', user: String(args.userId), req: args.req, detail: { hours: o.emailBlockHours } })
      return
    }
  }
  throw new Error('mfa: could not block email codes after the new password; try again.')
}

/**
 * For the account's own security page: whether two-step is on, since when, and how many recovery codes are left.
 * Server-only: there's no endpoint for it. Says nothing about the secret or the codes themselves.
 */
export async function statusFor(payload: Payload, userId: string | number, req?: PayloadRequest): Promise<{ on: boolean; since: string | null; recoveryLeft: number }> {
  const { state } = await loadState(payload, userId, req)
  const on = isOnState(state)
  return { on, since: on ? (state.enabledAt ?? null) : null, recoveryLeft: on ? (state.recovery ?? []).length : 0 }
}

/**
 * A maintainer's reset, without a code, for someone who lost their app and their recovery codes. Clears the
 * app, recovery codes, emailed code and per-session records through the version-checked write, so a sign-in
 * racing it can't keep the old state; remembered browsers stop working because they're tied to the secret.
 * Opens an enrollment window (default 24 hours) so a required account can sign in to set up again, clears the
 * account's limiter tries, signs the account out everywhere (`endSessions`, default true: a stolen phone may
 * have a session open), and records a `reset` event with who did it (an id, never an address). A block on emailed
 * codes after a password reset is kept. Server-only: the site checks the maintainer and confirms who they're
 * resetting. The window lets whoever knows the password set up a phone, so keep it short, and reset the
 * password too if it may be known.
 */
export async function resetFor(payload: Payload, userId: string | number, args: { enrollHours?: number; actor?: string | number | null; endSessions?: boolean; req?: PayloadRequest } = {}) {
  const hours = args.enrollHours ?? 24
  if (!(hours > 0 && hours <= 24 * 14)) throw new Error('mfa: enrollHours must be more than 0 and at most 336 (14 days).')
  const user = await loadUser(payload, userId, args.req)
  if (!user) refuse('notFound', 'That account wasn’t found.')
  for (let i = 0; i < 3; i++) {
    const loaded = await loadState(payload, user!.id, args.req)
    const cleared: MfaState = {
      secret: null,
      pending: null,
      enabledAt: null,
      lastStep: null,
      recovery: [],
      verifiedAt: null,
      sessions: {},
      emailCode: null,
      emailCodeExpires: null,
      emailBlockedUntil: loaded.state.emailBlockedUntil ?? null,
      enrollUntil: new Date(Date.now() + hours * HOUR).toISOString(),
    }
    if (await saveIfUnchanged(payload, user!.id, loaded, cleared, args.req)) {
      await clearAccountTries(payload, user!.id, args.req)
      // Payload keeps the account's open sessions on the account itself: emptying them signs it out everywhere.
      if (args.endSessions !== false) await payload.db.updateOne({ collection: optionsOf(payload).users, where: { id: { equals: user!.id } } as never, data: { sessions: [] }, ...(args.req ? { req: args.req } : {}) })
      await emit(payload, { type: 'reset', user: String(user!.id), req: args.req, detail: { by: args.actor === undefined || args.actor === null ? null : String(args.actor), hours } })
      return
    }
  }
  refuse('busy', 'Something changed at the same moment. Please try again.')
}
