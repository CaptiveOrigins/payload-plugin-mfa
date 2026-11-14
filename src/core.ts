import { createHash } from 'node:crypto'

import type { Payload, PayloadRequest } from 'payload'

import { appCodeStep, deriveKey, emailCodeHash, hashRecovery, mac, open, same, type Keys } from './crypto.js'
import type { LimitKind, Resolved, MfaEvent, MfaState, MfaUser } from './types.js'

/** Server-only `req.context` keys. HTTP requests can't set context, so only the site's own code can. */
export const MFA_CODE = 'mfaCode'
/** The remember cookie's value, as the site read it from the browser. */
export const MFA_REMEMBER = 'mfaRemember'
/** The site's own code vouches for this sign-in (or throws its token away), e.g. checking a password. */
export const MFA_TRUSTED = 'mfaTrusted'
export const REMEMBER_COOKIE = 'payload-mfa'

const HOUR = 60 * 60_000

export const optionsOf = (payload: Payload): Resolved => {
  const o = payload.config.custom?.mfa as Resolved | undefined
  if (!o) throw new Error('mfa: the plugin is not configured on this site.')
  return o
}

const keyCache = new WeakMap<Payload, Keys>()
export const keysOf = (payload: Payload): Keys => {
  let k = keyCache.get(payload)
  if (!k) {
    const o = optionsOf(payload)
    // The raw app secret, as the first site derives it: `payload.secret` is Payload's own hash of it, which would give another key.
    k = deriveKey(payload.config.secret, o.keyDerivation.salt, o.keyDerivation.info)
    keyCache.set(payload, k)
  }
  return k
}

/**
 * An account's two-step state lives in its own collection, one document per account, never on the account: Payload's
 * sign-in reads the account before its transaction and writes that whole copy back when it adds a session, which
 * would put old two-step state back over new. Here, only this plugin writes.
 */
export type Loaded = { docId: string | number | null; state: MfaState }

const STATE_FIELDS = ['secret', 'pending', 'enabledAt', 'lastStep', 'recovery', 'verifiedAt', 'sessions', 'emailCode', 'emailCodeExpires', 'emailBlockedUntil', 'enrollUntil', 'resetAt', 'version'] as const

export async function loadState(payload: Payload, userId: string | number, req?: PayloadRequest): Promise<Loaded> {
  const o = optionsOf(payload)
  const doc = (await payload.find({ collection: o.stateSlug as never, where: { user: { equals: String(userId) } }, limit: 1, depth: 0, overrideAccess: true, pagination: false, ...(req ? { req } : {}) })).docs[0] as Record<string, unknown> | undefined
  if (!doc) return { docId: null, state: {} }
  const state: MfaState = {}
  for (const k of STATE_FIELDS) (state as Record<string, unknown>)[k] = doc[k] ?? null
  return { docId: doc.id as string, state }
}

/** On whenever there's a secret: it's only ever set with `enabledAt`, and turning off clears it. Anything odd counts as on. */
export const isOnState = (s: MfaState) => Boolean(s.secret)

/**
 * Events get a copy of the request without anything secret: no entered code or remember value in its context, no
 * headers (they hold cookies, tokens and the client address) and no body. `payload` and the translation helpers stay
 * usable but aren't enumerable, so walking the object never reaches the app's secret. The transaction and the rest
 * of the context stay, so an audit trail keeps its write in the same transaction. The actor is `event.user`:
 * during a sign-in, `req.user` is whoever the request already had, not the person signing in.
 */
export function safeReq(req: PayloadRequest | undefined): PayloadRequest | undefined {
  if (!req) return undefined
  const { [MFA_CODE]: _code, [MFA_REMEMBER]: _remember, ...context } = (req.context ?? {}) as Record<string, unknown>
  const copy = { ...req, context, headers: new Headers(), data: undefined, body: undefined, json: undefined, text: undefined, formData: undefined } as Record<string, unknown>
  // These hold the app's config (its secret and database address). They stay usable, but a logger that walks the
  // object (JSON.stringify, pino) skips them.
  for (const k of ['payload', 'i18n', 'payloadDataLoader', 't']) if (k in copy) Object.defineProperty(copy, k, { value: copy[k], enumerable: false, writable: true, configurable: true })
  return copy as unknown as PayloadRequest
}

export async function emit(payload: Payload, event: MfaEvent) {
  await optionsOf(payload).onEvent?.({ ...event, req: safeReq(event.req) })
}

/** Loads an account with its hidden fields. */
export async function loadUser(payload: Payload, id: string | number, req?: PayloadRequest): Promise<MfaUser | null> {
  const o = optionsOf(payload)
  return (await payload.findByID({ collection: o.users as never, id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true, ...(req ? { req } : {}) })) as unknown as MfaUser | null
}

/**
 * Saves the state only if nobody changed it since it was read (its `version`), in one database step. Returns
 * false when another request got there first: the caller treats its code as wrong. These writes go straight to
 * the database, so they skip collection hooks (audit hooks included); `onEvent` is the record.
 */
export async function saveIfUnchanged(payload: Payload, userId: string | number, loaded: Loaded, next: MfaState, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  const version = loaded.state.version ?? 0
  const data: Record<string, unknown> = {}
  for (const k of STATE_FIELDS) if (k !== 'version') data[k] = (next as Record<string, unknown>)[k] ?? null
  data.version = version + 1
  try {
    if (loaded.docId === null) {
      // The first state for this account; a unique index on `user` stops two being made at once.
      await payload.db.create({ collection: o.stateSlug, data: { ...data, user: String(userId) }, ...(req ? { req } : {}) })
      return true
    }
    const done = await payload.db.updateOne({ collection: o.stateSlug, where: { and: [{ id: { equals: loaded.docId } }, { version: { equals: version } }] } as never, data, ...(req ? { req } : {}) })
    return Boolean(done)
  } catch (error) {
    // A duplicate first state, or a write conflict inside a transaction: someone else got there first.
    payload.logger.warn({ err: error, msg: 'mfa: a state write lost a race, so it was refused' })
    return false
  }
}

// ------------------------------------------------------------------------------------------------
// The limiter: per account always (never including the address, so changing address gives no new tries),
// plus per address on top when the site gives `clientAddress`. Keys are built here, never passed in.

/**
 * Records the try first, then counts the window including it, so tries arriving together can't all see room:
 * under a race some are refused that might have fitted (fails closed), never the other way. Written outside the
 * request's transaction, so a refused sign-in rolling back doesn't erase its try.
 */
async function builtIn(payload: Payload, kind: LimitKind, key: string): Promise<boolean> {
  const o = optionsOf(payload)
  const max = kind.startsWith('emailCode') ? o.limits.emailCode : o.limits.code
  const keyHash = createHash('sha256').update(`${payload.secret}|mfa|${kind}|${key}`).digest('hex')
  const now = Date.now()
  const at = new Date(now).toISOString()
  const mine = (await payload.create({ collection: o.attempts as never, data: { keyHash, at } as never, overrideAccess: true })) as unknown as { id: string | number }
  const since = new Date(now - o.limits.windowMinutes * 60_000).toISOString()
  // Allowed only if this try is among the window's first `max`, ordered by time then id, the same for every request.
  const { docs } = await payload.find({ collection: o.attempts as never, where: { and: [{ keyHash: { equals: keyHash } }, { at: { greater_than: since } }] } as never, sort: ['at', 'id'], limit: max, depth: 0, overrideAccess: true, pagination: false })
  // Tries older than the window can't count any more: delete them, so refused tries can't grow the table without end.
  await payload.db.deleteMany({ collection: o.attempts, where: { at: { less_than: since } } as never }).catch((err: unknown) => payload.logger.warn({ err, msg: 'mfa: old tries weren’t cleared; they will be next time' }))
  return (docs as unknown as { id: string | number }[]).some((d) => String(d.id) === String(mine.id))
}

/**
 * Clears the built-in limiter's tries for one account (not for its addresses, which other accounts share). A site
 * with its own limiter clears its own.
 */
export async function clearAccountTries(payload: Payload, userId: string | number, req?: PayloadRequest) {
  const o = optionsOf(payload)
  if (o.limit) return
  const hashes = (['code', 'emailCode'] as const).map((kind) => createHash('sha256').update(`${payload.secret}|mfa|${kind}|account:${String(userId)}`).digest('hex'))
  await payload.db.deleteMany({ collection: o.attempts, where: { keyHash: { in: hashes } } as never, ...(req ? { req } : {}) })
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
    payload.logger.error({ err: error, msg: 'mfa: the limiter failed, so the try was refused' })
    return false
  }
}

// ------------------------------------------------------------------------------------------------
// Codes

export type Accepted = { next: MfaState; used: 'app' | 'email' | 'recovery' }

/**
 * Checks a code: an app code (one step of drift either way; a step at or before the last one used is refused), an
 * emailed code (used once, before it expires, and not while blocked after a reset), or a recovery code (used up).
 * Returns the state to save, or null for a wrong code. Never throws.
 */
export function acceptCode(keys: Keys, state: MfaState, code: unknown, now = Date.now()): Accepted | null {
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
export function acceptPending(keys: Keys, state: MfaState, code: unknown, now = Date.now()): number | null {
  if (typeof code !== 'string' || !/^\d{3}\s?\d{3}$/.test(code.trim())) return null
  const secret = open(keys, state.pending)
  return secret ? appCodeStep(secret, code.trim(), now) : null
}

export const emailBlocked = (s: MfaState, now = Date.now()) => Boolean(s.emailBlockedUntil && new Date(s.emailBlockedUntil).getTime() > now)

// ------------------------------------------------------------------------------------------------
// Remembered browsers: tied to the account, the secret and the password hash, so changing either ends it.

const rememberMac = (keys: Keys, user: MfaUser, state: MfaState, expires: number) => mac(keys, `remember|${String(user.id)}|${expires}|${state.secret ?? ''}|${String(user.hash ?? '')}`)

export function rememberValueFor(payload: Payload, user: MfaUser, state: MfaState, now = Date.now()): string {
  const o = optionsOf(payload)
  const expires = now + o.rememberHours * HOUR
  return `${expires}.${rememberMac(keysOf(payload), user, state, expires)}`
}

/** The moment the code behind a remembered browser was given, or null when the value isn't valid now. */
export function rememberedSince(payload: Payload, user: MfaUser, state: MfaState, value: unknown, now = Date.now()): number | null {
  if (typeof value !== 'string') return null
  const o = optionsOf(payload)
  const [expires, given] = value.split('.')
  const until = Number(expires)
  const span = o.rememberHours * HOUR
  if (!given || !Number.isFinite(until) || until <= now || until > now + span) return null
  return same(given, rememberMac(keysOf(payload), user, state, until)) ? until - span : null
}

/** Keeps the per-session record small: only sessions the account still has. */
export function withSession(state: MfaState, user: MfaUser, sid: string | undefined, at: string): MfaState {
  const live = new Set((user.sessions ?? []).map((s) => s.id))
  const sessions: Record<string, string> = {}
  for (const [k, v] of Object.entries(state.sessions ?? {})) if (live.has(k)) sessions[k] = v
  if (sid) sessions[sid] = at
  return { ...state, sessions, verifiedAt: at }
}

/** When this session last gave a code. A session the record doesn't know falls back to nothing (not verified). */
export const sessionVerifiedAt = (state: MfaState, sid: string | undefined) => (sid && state.sessions?.[sid] ? new Date(state.sessions[sid]!).getTime() : null)

export async function isRequired(payload: Payload, user: MfaUser, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  if (!o.requiredFor) return false
  try {
    return (await o.requiredFor({ user, req })) !== false
  } catch (error) {
    payload.logger.error({ err: error, msg: 'mfa: requiredFor failed, so the account counts as required' })
    return true
  }
}

/**
 * True when this session was made before the account's last reset, or can't be dated while a reset exists: it's
 * refused. Payload's sign-in and refresh write the whole account back, so a sign-in racing the reset can restore
 * the sessions it emptied; this check stops them working anyway.
 */
export function sessionBeforeReset(state: MfaState, user: MfaUser): boolean {
  if (!state.resetAt) return false
  const sid = user._sid
  if (!sid) return false // not a session sign-in (an API key, say): the reset doesn't cover those
  const session = (user.sessions ?? []).find((s) => s.id === sid)
  const made = session?.createdAt ? new Date(session.createdAt).getTime() : NaN
  return !Number.isFinite(made) || made < new Date(state.resetAt).getTime()
}

export const inEnrollWindow = (s: MfaState, now = Date.now()) => Boolean(s.enrollUntil && new Date(s.enrollUntil).getTime() > now)
