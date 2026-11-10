import { createHash } from 'node:crypto'

import type { Payload, PayloadRequest } from 'payload'

import { appCodeStep, deriveKey, emailCodeHash, hashRecovery, mac, open, same, type Keys } from './crypto.js'
import type { LimitKind, Resolved, TwoStepEvent, TwoStepState, TwoStepUser } from './types.js'

/** Server-only `req.context` keys. HTTP requests can't set context, so only the site's own code can. */
export const TWO_STEP_CODE = 'twoStepCode'
/** The remember cookie's value, as the site read it from the browser. */
export const TWO_STEP_REMEMBER = 'twoStepRemember'
/** The site's own code vouches for this sign-in (or throws its token away), e.g. checking a password. */
export const TWO_STEP_TRUSTED = 'twoStepTrusted'
export const REMEMBER_COOKIE = 'payload-two-step'

const HOUR = 60 * 60_000

export const optionsOf = (payload: Payload): Resolved => {
  const o = payload.config.custom?.twoStep as Resolved | undefined
  if (!o) throw new Error('two-step: the plugin is not configured on this site.')
  return o
}

const keyCache = new WeakMap<Payload, Keys>()
export const keysOf = (payload: Payload): Keys => {
  let k = keyCache.get(payload)
  if (!k) {
    const o = optionsOf(payload)
    k = deriveKey(payload.secret, o.keyDerivation.salt, o.keyDerivation.info)
    keyCache.set(payload, k)
  }
  return k
}

export const stateOf = (payload: Payload, user: Record<string, unknown> | null | undefined): TwoStepState => ((user?.[optionsOf(payload).field] as TwoStepState | null | undefined) ?? {}) as TwoStepState

/** On whenever there's a secret: it's only ever set with `enabledAt`, and turning off clears it. Anything odd counts as on. */
export const isOnState = (s: TwoStepState) => Boolean(s.secret)

export async function emit(payload: Payload, event: TwoStepEvent) {
  await optionsOf(payload).onEvent?.(event)
}

/** Loads an account with its hidden fields. */
export async function loadUser(payload: Payload, id: string | number, req?: PayloadRequest): Promise<TwoStepUser | null> {
  const o = optionsOf(payload)
  return (await payload.findByID({ collection: o.users as never, id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true, ...(req ? { req } : {}) })) as unknown as TwoStepUser | null
}

/**
 * Saves the state only if nobody changed it since it was read (its `version`), in one database step. Returns
 * false when another request got there first: the caller treats its code as wrong. These writes go straight to
 * the database, so they skip collection hooks (audit hooks included); `onEvent` is the record.
 */
export async function saveIfUnchanged(payload: Payload, user: TwoStepUser, before: TwoStepState, next: TwoStepState, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  const version = before.version ?? 0
  const where = {
    and: [{ id: { equals: user.id } }, version ? { [`${o.field}.version`]: { equals: version } } : { or: [{ [`${o.field}.version`]: { exists: false } }, { [`${o.field}.version`]: { equals: null } }, { [`${o.field}.version`]: { equals: 0 } }] }],
  }
  const done = await payload.db.updateOne({ collection: o.users, where: where as never, data: { [o.field]: { ...next, version: version + 1 } }, ...(req ? { req } : {}) })
  return Boolean(done)
}

// ------------------------------------------------------------------------------------------------
// The limiter: per account always (never including the address, so changing address gives no new tries),
// plus per address on top when the site gives `clientAddress`. Keys are built here, never passed in.

async function builtIn(payload: Payload, kind: LimitKind, key: string): Promise<boolean> {
  const o = optionsOf(payload)
  const max = kind.startsWith('emailCode') ? o.limits.emailCode : o.limits.code
  const keyHash = createHash('sha256').update(`${payload.secret}|two-step|${kind}|${key}`).digest('hex')
  const since = new Date(Date.now() - o.limits.windowMinutes * 60_000).toISOString()
  const { totalDocs } = await payload.count({ collection: o.attempts as never, where: { and: [{ keyHash: { equals: keyHash } }, { at: { greater_than: since } }] } as never, overrideAccess: true })
  if (totalDocs >= max) return false
  await payload.create({ collection: o.attempts as never, data: { keyHash, at: new Date().toISOString() } as never, overrideAccess: true })
  return true
}

/** True to allow. Refuses on any error (fails closed). */
export async function allowed(payload: Payload, kind: 'code' | 'emailCode', userId: string | number, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  const check = async (k: LimitKind, key: string) => (o.limit ? (await o.limit({ kind: k, key, req })) === true : builtIn(payload, k, key))
  try {
    if (!(await check(kind, `account:${String(userId)}`))) return false
    const address = req && o.clientAddress ? o.clientAddress(req) : null
    if (address && !(await check(`${kind}-address` as LimitKind, `address:${address}`))) return false
    return true
  } catch (error) {
    payload.logger.error({ err: error, msg: 'two-step: the limiter failed, so the try was refused' })
    return false
  }
}

// ------------------------------------------------------------------------------------------------
// Codes

export type Accepted = { next: TwoStepState; used: 'app' | 'email' | 'recovery' }

/**
 * Checks a code: an app code (one step of drift either way; a step at or before the last one used is refused), an
 * emailed code (used once, before it expires, and not while blocked after a reset), or a recovery code (used up).
 * Returns the state to save, or null for a wrong code. Never throws.
 */
export function acceptCode(keys: Keys, state: TwoStepState, code: unknown, now = Date.now()): Accepted | null {
  if (typeof code !== 'string') return null
  const entered = code.trim()
  if (/^\d{8}$/.test(entered)) {
    if (!state.emailCode || !state.emailCodeExpires || new Date(state.emailCodeExpires).getTime() <= now || emailBlocked(state, now)) return null
    return same(state.emailCode, emailCodeHash(keys, entered)) ? { next: { ...state, emailCode: null, emailCodeExpires: null }, used: 'email' } : null
  }
  if (/^\d{3}\s?\d{3}$/.test(entered)) {
    const secret = open(keys, state.secret)
    if (!secret) return null // the app's secret changed: only recovery codes still work
    const step = appCodeStep(secret, entered, now)
    if (step === null || step <= (state.lastStep ?? 0)) return null
    return { next: { ...state, lastStep: step }, used: 'app' }
  }
  if (entered.length < 8 || entered.length > 40) return null
  const hash = hashRecovery(entered)
  let hit = -1
  // Every stored hash is compared in constant time, and all of them are checked.
  ;(state.recovery ?? []).forEach((h, i) => {
    if (same(h, hash) && hit < 0) hit = i
  })
  if (hit < 0) return null
  return { next: { ...state, recovery: (state.recovery ?? []).filter((_, i) => i !== hit) }, used: 'recovery' }
}

/** An app code against a pending (not yet confirmed) secret. */
export function acceptPending(keys: Keys, state: TwoStepState, code: unknown, now = Date.now()): number | null {
  if (typeof code !== 'string' || !/^\d{3}\s?\d{3}$/.test(code.trim())) return null
  const secret = open(keys, state.pending)
  return secret ? appCodeStep(secret, code.trim(), now) : null
}

export const emailBlocked = (s: TwoStepState, now = Date.now()) => Boolean(s.emailBlockedUntil && new Date(s.emailBlockedUntil).getTime() > now)

// ------------------------------------------------------------------------------------------------
// Remembered browsers: tied to the account, the secret and the password hash, so changing either ends it.

const rememberMac = (keys: Keys, user: TwoStepUser, state: TwoStepState, expires: number) => mac(keys, `remember|${String(user.id)}|${expires}|${state.secret ?? ''}|${String(user.hash ?? '')}`)

export function rememberValueFor(payload: Payload, user: TwoStepUser, now = Date.now()): string {
  const o = optionsOf(payload)
  const expires = now + o.rememberHours * HOUR
  return `${expires}.${rememberMac(keysOf(payload), user, stateOf(payload, user), expires)}`
}

/** The moment the code behind a remembered browser was given, or null when the value isn't valid now. */
export function rememberedSince(payload: Payload, user: TwoStepUser, value: unknown, now = Date.now()): number | null {
  if (typeof value !== 'string') return null
  const o = optionsOf(payload)
  const [expires, given] = value.split('.')
  const until = Number(expires)
  const span = o.rememberHours * HOUR
  if (!given || !Number.isFinite(until) || until <= now || until > now + span) return null
  return same(given, rememberMac(keysOf(payload), user, stateOf(payload, user), until)) ? until - span : null
}

/** Keeps the per-session record small: only sessions the account still has. */
export function withSession(state: TwoStepState, user: TwoStepUser, sid: string | undefined, at: string): TwoStepState {
  const live = new Set((user.sessions ?? []).map((s) => s.id))
  const sessions: Record<string, string> = {}
  for (const [k, v] of Object.entries(state.sessions ?? {})) if (live.has(k)) sessions[k] = v
  if (sid) sessions[sid] = at
  return { ...state, sessions, verifiedAt: at }
}

/** When this session last gave a code. A session the record doesn't know falls back to nothing (not verified). */
export const sessionVerifiedAt = (state: TwoStepState, sid: string | undefined) => (sid && state.sessions?.[sid] ? new Date(state.sessions[sid]!).getTime() : null)

export async function isRequired(payload: Payload, user: TwoStepUser, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  if (!o.requiredFor) return false
  try {
    return (await o.requiredFor({ user, req })) !== false
  } catch (error) {
    payload.logger.error({ err: error, msg: 'two-step: requiredFor failed, so the account counts as required' })
    return true
  }
}

export const inEnrollWindow = (s: TwoStepState, now = Date.now()) => Boolean(s.enrollUntil && new Date(s.enrollUntil).getTime() > now)
