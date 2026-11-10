import type { Payload, PayloadRequest, RequestContext } from 'payload'

import { appLink, newEmailCode, newRecoveryCodes, newSecret, seal, emailCodeHash } from './crypto.js'
import {
  acceptCode,
  acceptPending,
  allowed,
  emailBlocked,
  emit,
  isOnState,
  keysOf,
  loadUser,
  optionsOf,
  rememberValueFor,
  saveIfUnchanged,
  stateOf,
  TWO_STEP_CODE,
  TWO_STEP_REMEMBER,
  withSession,
} from './core.js'
import type { TwoStepState, TwoStepUser } from './types.js'

const HOUR = 60 * 60_000

/** A refusal a site can show, with a stable reason. */
export class TwoStepRefused extends Error {
  constructor(
    readonly reason: 'notFound' | 'notOn' | 'alreadyOn' | 'needsCode' | 'wrongCode' | 'tooMany' | 'noPending' | 'busy',
    message: string,
  ) {
    super(message)
    this.name = 'TwoStepRefused'
  }
}

const refuse = (reason: TwoStepRefused['reason'], message: string): never => {
  throw new TwoStepRefused(reason, message)
}

async function load(payload: Payload, userId: string | number, req?: PayloadRequest) {
  const user = await loadUser(payload, userId, req)
  if (!user) refuse('notFound', 'That account wasn’t found.')
  return { user: user!, state: stateOf(payload, user) }
}

/** Whether this account has two-step on. For step-up checks: `stepUp.available` in Hats. */
export const isOn = (payload: Payload, user: Record<string, unknown> | null | undefined) => isOnState(stateOf(payload, user))

/** Whether an account (by id) has two-step on, looking up its hidden state. */
export async function isOnFor(payload: Payload, userId: string | number, req?: PayloadRequest) {
  const user = await loadUser(payload, userId, req)
  return Boolean(user && isOnState(stateOf(payload, user)))
}

/**
 * Checks a code for an account that's already signed in, e.g. before a sensitive action (Hats' step-up). Limited
 * per account, each code used once, safe under concurrency. Records the code against the request's session.
 */
export async function verify(payload: Payload, args: { user: { id: string | number } & Record<string, unknown>; code: unknown; req?: PayloadRequest }): Promise<boolean> {
  const loaded = await loadUser(payload, args.user.id, args.req)
  if (!loaded) return false
  const state = stateOf(payload, loaded)
  if (!isOnState(state)) return false
  if (!(await allowed(payload, 'code', loaded.id, args.req))) {
    await emit(payload, { type: 'too-many-tries', user: String(loaded.id), req: args.req })
    return false
  }
  const accepted = acceptCode(keysOf(payload), state, args.code)
  if (!accepted) return false
  const sid = (args.req?.user as { _sid?: string } | null | undefined)?._sid
  const next = withSession(accepted.next, loaded, sid, new Date().toISOString())
  if (!(await saveIfUnchanged(payload, loaded, state, next, args.req))) return false
  if (accepted.used === 'recovery') await emit(payload, { type: 'recovery-used', user: String(loaded.id), req: args.req, detail: { left: next.recovery?.length ?? 0 } })
  return true
}

/**
 * Signs in for server code (a Next server action, say): Payload's own login with the code or the remembered value
 * in context, where HTTP can't put them. Throws Payload's usual error; a `TwoStepError` says `needed`, `wrong` or `enroll`.
 */
export async function signIn(payload: Payload, args: { email: string; password: string; code?: string; remember?: string; req?: PayloadRequest; context?: RequestContext }) {
  const o = optionsOf(payload)
  const context: RequestContext = { ...(args.context ?? {}), ...(args.code ? { [TWO_STEP_CODE]: args.code } : args.remember ? { [TWO_STEP_REMEMBER]: args.remember } : {}) }
  return payload.login({ collection: o.users as never, data: { email: args.email, password: args.password }, context, ...(args.req ? { req: args.req } : {}) })
}

/** The remember cookie's value for an account that has just given a code. The site sets the cookie (HttpOnly). */
export async function rememberValue(payload: Payload, args: { userId: string | number; req?: PayloadRequest }) {
  const user = await loadUser(payload, args.userId, args.req)
  return user ? rememberValueFor(payload, user) : ''
}

/**
 * Begins setting up an app. The site checks the password first. If two-step is already on, a current app code or
 * a recovery code must come with it, so a signed-in session can't move the factor to another phone.
 */
export async function start(payload: Payload, args: { userId: string | number; code?: unknown; req?: PayloadRequest }): Promise<{ uri: string; key: string }> {
  const o = optionsOf(payload)
  const { user, state } = await load(payload, args.userId, args.req)
  let base: TwoStepState = state
  if (isOnState(state)) {
    if (typeof args.code !== 'string' || !args.code.trim()) refuse('needsCode', 'Enter a code from your current app, or a recovery code, to set up a new one.')
    if (!(await allowed(payload, 'code', user.id, args.req))) refuse('tooMany', 'Too many tries. Please wait a few minutes.')
    const accepted = acceptCode(keysOf(payload), state, args.code)
    if (!accepted || accepted.used === 'email') refuse('wrongCode', 'That code didn’t work.')
    base = accepted!.next
  }
  const secret = newSecret()
  if (!(await saveIfUnchanged(payload, user, state, { ...base, pending: seal(keysOf(payload), secret) }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'started', user: String(user.id), req: args.req })
  return { uri: appLink(secret, o.issuer, String(user.email ?? user.id)), key: secret }
}

/** The first code from the app proves it works: two-step goes on, and the recovery codes are returned once. */
export async function confirm(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }): Promise<{ recoveryCodes: string[] }> {
  const { user, state } = await load(payload, args.userId, args.req)
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
  if (!(await saveIfUnchanged(payload, user, state, next, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'confirmed', user: String(user.id), req: args.req })
  return { recoveryCodes: codes }
}

async function withCode(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }) {
  const { user, state } = await load(payload, args.userId, args.req)
  if (!isOnState(state)) refuse('notOn', 'Two-step isn’t on for this account.')
  if (!(await allowed(payload, 'code', user.id, args.req))) refuse('tooMany', 'Too many tries. Please wait a few minutes.')
  const accepted = acceptCode(keysOf(payload), state, args.code)
  // Changing the factor itself needs the app or a recovery code: an emailed code only proves the mailbox.
  if (!accepted || accepted.used === 'email') refuse('wrongCode', 'Enter a code from your app, or a recovery code.')
  return { user, state, accepted: accepted! }
}

/** Turns two-step off. The site checks the password first; a current code (or recovery code) is needed too. */
export async function turnOff(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }) {
  const { user, state } = await withCode(payload, args)
  const cleared: TwoStepState = { secret: null, pending: null, enabledAt: null, lastStep: null, recovery: [], verifiedAt: null, sessions: {}, emailCode: null, emailCodeExpires: null, emailBlockedUntil: state.emailBlockedUntil ?? null, enrollUntil: null }
  if (!(await saveIfUnchanged(payload, user, state, cleared, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'turned-off', user: String(user.id), req: args.req })
}

/** New recovery codes, returned once; the old ones stop working. The site checks the password first; a current code is needed too. */
export async function newRecoveryCodesFor(payload: Payload, args: { userId: string | number; code: unknown; req?: PayloadRequest }): Promise<{ recoveryCodes: string[] }> {
  const { user, state, accepted } = await withCode(payload, args)
  const { codes, hashes } = newRecoveryCodes()
  if (!(await saveIfUnchanged(payload, user, state, { ...accepted.next, recovery: hashes }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
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
  const found = (await payload.find({ collection: o.users as never, where: { email: { equals: email } }, limit: 1, depth: 0, overrideAccess: true, showHiddenFields: true, ...(args.req ? { req: args.req } : {}) })).docs[0] as unknown as TwoStepUser | undefined
  if (!found) return
  const state = stateOf(payload, found)
  if (!isOnState(state) || emailBlocked(state)) return
  if (!(await allowed(payload, 'emailCode', found.id, args.req))) return
  const code = newEmailCode()
  const saved = await saveIfUnchanged(payload, found, state, { ...state, emailCode: emailCodeHash(keysOf(payload), code), emailCodeExpires: new Date(Date.now() + o.emailCodeMinutes * 60_000).toISOString() }, args.req)
  if (!saved) return
  const send = o.sendEmailCode ?? (({ payload: p, to, code: c, minutes }) => p.sendEmail({ to, subject: 'Your sign-in code', text: `Your sign-in code is ${c}. It works once, for ${minutes} minutes.\n\nIf you didn't try to sign in, someone may know your password: change it.` }))
  try {
    await send({ payload, to: email, code, minutes: o.emailCodeMinutes, req: args.req })
    await emit(payload, { type: 'email-code-sent', user: String(found.id), req: args.req })
  } catch (error) {
    payload.logger.error({ err: error, msg: 'two-step: an email code was not sent' })
  }
}

/** Lets an account that must have two-step sign in to set it up, for a while (staff, for one person). Ends at the first confirm. */
export async function allowEnrollment(payload: Payload, args: { userId: string | number; hours?: number; req?: PayloadRequest }) {
  const { user, state } = await load(payload, args.userId, args.req)
  const until = new Date(Date.now() + (args.hours ?? 24) * HOUR).toISOString()
  if (!(await saveIfUnchanged(payload, user, state, { ...state, enrollUntil: until }, args.req))) refuse('busy', 'Something changed at the same moment. Please try again.')
  await emit(payload, { type: 'enrollment-window', user: String(user.id), req: args.req, detail: { hours: args.hours ?? 24 } })
}

/**
 * After a new password set through the mailbox (a reset, an invitation link): emailed codes are off for a while
 * and any outstanding one is cleared. The plugin runs this itself after Payload's `resetPassword`.
 */
export async function afterPasswordSet(payload: Payload, args: { userId: string | number; req?: PayloadRequest }) {
  const o = optionsOf(payload)
  for (let i = 0; i < 3; i++) {
    const user = await loadUser(payload, args.userId, args.req)
    if (!user) return
    const state = stateOf(payload, user)
    const next = { ...state, emailCode: null, emailCodeExpires: null, emailBlockedUntil: new Date(Date.now() + o.emailBlockHours * HOUR).toISOString() }
    if (await saveIfUnchanged(payload, user, state, next, args.req)) {
      await emit(payload, { type: 'email-codes-blocked', user: String(user.id), req: args.req, detail: { hours: o.emailBlockHours } })
      return
    }
  }
  throw new Error('two-step: could not block email codes after the new password; try again.')
}
