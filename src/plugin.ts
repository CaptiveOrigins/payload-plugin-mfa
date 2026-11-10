import { AuthenticationError, Forbidden, generatePayloadCookie, type AuthStrategy, type CollectionAfterOperationHook, type CollectionBeforeLoginHook, type CollectionBeforeOperationHook, type CollectionConfig, type Config, type Endpoint, type Payload, type Plugin } from 'payload'

import { afterPasswordSet, rememberValue } from './api.js'
import {
  acceptCode,
  allowed,
  emit,
  inEnrollWindow,
  isOnState,
  isRequired,
  keysOf,
  loadState,
  optionsOf,
  REMEMBER_COOKIE,
  rememberedSince,
  saveIfUnchanged,
  sessionBeforeReset,
  sessionVerifiedAt,
  MFA_CODE,
  MFA_REMEMBER,
  MFA_TRUSTED,
  withSession,
} from './core.js'
import type { Resolved, MfaOptions, MfaUser } from './types.js'

/** Same answer as a wrong password to anyone reading the API; the site's own form reads `mfa`. */
export class MfaError extends AuthenticationError {
  mfa: 'needed' | 'wrong' | 'enroll'
  constructor(t: ConstructorParameters<typeof AuthenticationError>[0], mfa: 'needed' | 'wrong' | 'enroll') {
    super(t)
    this.mfa = mfa
  }
}

const HOUR = 60 * 60_000
const never = () => false

/** One document per account, written only by this plugin; nothing in Payload's sign-in touches it. */
function stateCollection(o: Resolved): CollectionConfig {
  return {
    slug: o.stateSlug,
    admin: { hidden: true },
    access: { read: never, create: never, update: never, delete: never },
    fields: [
      { name: 'user', type: 'text', required: true, unique: true, index: true },
      { name: 'secret', type: 'text' },
      { name: 'pending', type: 'text' },
      { name: 'enabledAt', type: 'date' },
      { name: 'lastStep', type: 'number' },
      { name: 'recovery', type: 'text', hasMany: true },
      { name: 'verifiedAt', type: 'date' },
      { name: 'sessions', type: 'json' },
      { name: 'emailCode', type: 'text' },
      { name: 'emailCodeExpires', type: 'date' },
      { name: 'emailBlockedUntil', type: 'date' },
      { name: 'enrollUntil', type: 'date' },
      { name: 'resetAt', type: 'date' },
      { name: 'version', type: 'number', index: true },
    ],
  }
}

function attemptsCollection(o: Resolved): CollectionConfig {
  return {
    slug: o.attempts,
    admin: { hidden: true },
    access: { read: never, create: never, update: never, delete: never },
    fields: [
      { name: 'keyHash', type: 'text', required: true, index: true },
      { name: 'at', type: 'date', required: true, index: true },
    ],
  }
}

/** The sign-in this request belongs to: Payload adds the new session to this login's own copy of the account just before `beforeLogin`. */
const newestSid = (user: MfaUser) => user.sessions?.at(-1)?.id

const beforeLogin: CollectionBeforeLoginHook = async ({ req, user: u }) => {
  const payload = req.payload
  const user = u as MfaUser
  if (req.context?.[MFA_TRUSTED] === true) return u
  const o = optionsOf(payload)
  if (o.legacyUserField && (await hasUnmovedState(payload, o, user.id))) throw new MfaError(req.t, 'needed')
  const loaded = await loadState(payload, user.id, req)
  const state = loaded.state
  if (!isOnState(state)) {
    if ((await isRequired(payload, user, req)) && !inEnrollWindow(state)) throw new MfaError(req.t, 'enroll')
    return u
  }
  const sid = newestSid(user)
  // A browser that gave a code recently: the session counts from when that code was given.
  const since = rememberedSince(payload, user, state, req.context?.[MFA_REMEMBER])
  if (since !== null) {
    const at = new Date(since).toISOString()
    if (!(await saveIfUnchanged(payload, user.id, loaded, withSession(state, user, sid, at), req))) {
      // Someone else wrote the state at the same moment: read it again and try once more, or the session can't refresh.
      const again = await loadState(payload, user.id, req)
      if (!(await saveIfUnchanged(payload, user.id, again, withSession(again.state, user, sid, at), req)))
        payload.logger.warn({ msg: 'mfa: a remembered sign-in’s session wasn’t recorded; it will need a code at its next refresh' })
    }
    return u
  }
  const code = req.context?.[MFA_CODE]
  if (typeof code !== 'string' || !code.trim()) throw new MfaError(req.t, 'needed')
  // Payload's lockout counts wrong passwords only; codes have their own per-account limit.
  if (!(await allowed(payload, 'code', user.id, req))) {
    await emit(payload, { type: 'too-many-tries', user: String(user.id), req })
    throw new MfaError(req.t, 'wrong')
  }
  const accepted = acceptCode(keysOf(payload), state, code)
  if (!accepted) throw new MfaError(req.t, 'wrong')
  const next = withSession(accepted.next, user, sid, new Date().toISOString())
  if (!(await saveIfUnchanged(payload, user.id, loaded, next, req))) throw new MfaError(req.t, 'wrong')
  if (accepted.used === 'recovery') await emit(payload, { type: 'recovery-used', user: String(user.id), req, detail: { left: next.recovery?.length ?? 0 } })
  return u
}

/** A session can't outlive the remembered window, and an account that must have two-step but doesn't can't refresh. */
const beforeOperation: CollectionBeforeOperationHook = async ({ operation, req }) => {
  if (operation !== 'refresh' || !req.user) return
  const payload = req.payload
  const o = optionsOf(payload)
  const user = req.user as unknown as MfaUser
  const { state } = await loadState(payload, user.id, req)
  if (sessionBeforeReset(state, user)) throw new Forbidden(req.t)
  if (!isOnState(state)) {
    if ((await isRequired(payload, user, req)) && !inEnrollWindow(state)) throw new Forbidden(req.t)
    return
  }
  const verified = sessionVerifiedAt(state, user._sid)
  const tokenMs = (payload.collections[o.users as never]?.config.auth as { tokenExpiration?: number } | undefined)?.tokenExpiration ?? 7200
  if (verified === null || Date.now() - verified > o.rememberHours * HOUR - tokenMs * 1000) throw new Forbidden(req.t)
}

/** A password reset by email: the mailbox just proved itself, so it can't be the second step for a while. */
const afterOperation: CollectionAfterOperationHook = async ({ operation, req, result }) => {
  if (operation !== 'resetPassword') return result
  const id = (result as { user?: { id?: string | number } } | undefined)?.user?.id
  if (id !== undefined) await afterPasswordSet(req.payload, { userId: id, req })
  return result
}

/** Signs out, on its next request, a session made before a reset, and one whose account must now have two-step and doesn't. */
function wrapStrategies(payload: Payload, o: Resolved) {
  payload.authStrategies = payload.authStrategies.map(
    (strategy): AuthStrategy => ({
      ...strategy,
      authenticate: async (args) => {
        const result = await strategy.authenticate(args)
        const user = result.user as MfaUser | null
        if (!user || user.collection !== o.users) return result
        // One small read per signed-in request: needed so a reset ends sessions even when a sign-in raced it.
        const { state } = await loadState(payload, user.id)
        if (sessionBeforeReset(state, user)) return { ...result, user: null }
        if (!o.requiredFor) return result
        if (!isOnState(state) && (await isRequired(payload, user)) && !inEnrollWindow(state)) return { ...result, user: null }
        return result
      },
    }),
  )
}

type RawUsers = {
  base?: { Types?: { ObjectId?: new (s: string) => unknown } }
  collection: { find: (q: object, opts?: object) => { toArray: () => Promise<Record<string, unknown>[]> }; updateOne: (q: object, u: object) => Promise<unknown>; countDocuments: (q: object) => Promise<number> }
}
const rawUsers = (payload: Payload, o: Resolved): RawUsers => {
  const users = (payload.db as unknown as { collections?: Record<string, RawUsers> }).collections?.[o.users]
  if (!users) throw new Error('mfa: `legacyUserField` needs the MongoDB adapter.')
  return users
}

/** While an account still has state in the old field, it can't sign in: it can't run half-moved and weaker. */
async function hasUnmovedState(payload: Payload, o: Resolved, userId: string | number) {
  const users = rawUsers(payload, o)
  const ObjectId = users.base?.Types?.ObjectId
  const id = ObjectId && /^[a-f0-9]{24}$/i.test(String(userId)) ? new ObjectId(String(userId)) : userId
  return (await users.collection.countDocuments({ _id: id, [o.legacyUserField!]: { $exists: true, $ne: null } })) > 0
}

/**
 * Moves state Captive Origins kept on the account (`legacyUserField`, e.g. `twoStep`) into the plugin's collection.
 * Run it once, as a script, after a backup (on Captive Origins, with the owner's yes). For each account with old
 * state: copy it if the account has no new state yet (an existing one counts as moved), then remove the old field.
 * A setup that was never confirmed (a pending app, no secret) is dropped, and counted in the log. Safe to run again.
 */
export async function moveLegacyState(payload: Payload, args: { field?: string } = {}) {
  const o = optionsOf(payload)
  const field = args.field ?? o.legacyUserField
  if (!field) throw new Error('mfa: name the old field (`field`, or the plugin\'s `legacyUserField`).')
  const users = rawUsers(payload, { ...o, legacyUserField: field })
  const old = await users.collection.find({ [field]: { $exists: true, $ne: null } }, { projection: { _id: 1, [field]: 1 } }).toArray()
  let moved = 0
  let alreadyMoved = 0
  let unfinished = 0
  for (const row of old) {
    const id = String(row._id)
    const legacy = (row[field] ?? {}) as Record<string, unknown>
    const existing = await loadState(payload, id)
    if (existing.docId !== null) alreadyMoved++
    else if (legacy.secret) {
      if (!(await saveIfUnchanged(payload, id, existing, { ...(legacy as object), sessions: {}, version: 0 })) && (await loadState(payload, id)).docId === null)
        throw new Error(`mfa: couldn’t move the old state of account ${id}; nothing was removed from it.`)
      moved++
    } else if (legacy.pending) unfinished++
    await users.collection.updateOne({ _id: row._id }, { $unset: { [field]: '' } })
  }
  payload.logger.info({ msg: `mfa: moved ${moved}, already moved ${alreadyMoved}, dropped ${unfinished} unfinished setup(s); cleared ${old.length} account(s).` })
  return { moved, alreadyMoved, unfinished, cleared: old.length }
}

function loginEndpoint(o: Resolved): Endpoint {
  return {
    path: '/mfa/login',
    method: 'post',
    handler: async (req) => {
      const payload = req.payload
      const body = ((await req.json?.().catch(() => null)) ?? {}) as { email?: unknown; password?: unknown; code?: unknown }
      const cookie = new RegExp(`(?:^|;\\s*)${REMEMBER_COOKIE}=([^;]+)`).exec(req.headers.get('cookie') ?? '')?.[1]
      const code = typeof body.code === 'string' && body.code.trim() ? body.code : undefined
      try {
        // Payload's own login: its lockout, its CSRF and cookie rules, and the same answer for an unknown email.
        const result = await payload.login({
          collection: o.users as never,
          data: { email: String(body.email ?? ''), password: String(body.password ?? '') },
          req,
          context: { ...(code ? { [MFA_CODE]: code } : cookie ? { [MFA_REMEMBER]: decodeURIComponent(cookie) } : {}) },
        })
        const auth = payload.collections[o.users as never]!.config.auth
        const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
        headers.append('Set-Cookie', generatePayloadCookie({ collectionAuthConfig: auth, cookiePrefix: payload.config.cookiePrefix, token: result.token! }) as string)
        if (code && result.user) {
          const secure = auth.cookies.secure ? '; Secure' : ''
          headers.append('Set-Cookie', `${REMEMBER_COOKIE}=${encodeURIComponent(await rememberValue(payload, { userId: result.user.id as string }))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${o.rememberHours * 3600}${secure}`)
        }
        return new Response(JSON.stringify({ ok: true, user: { id: result.user?.id } }), { status: 200, headers })
      } catch (error) {
        if (error instanceof MfaError) return Response.json({ ok: false, mfa: error.mfa }, { status: 401, headers: { 'Cache-Control': 'no-store' } })
        return Response.json({ ok: false, errors: [{ message: 'The email or password provided is incorrect.' }] }, { status: 401, headers: { 'Cache-Control': 'no-store' } })
      }
    },
  }
}

/**
 * Two-step sign-in for Payload: an authenticator code after the password, with emailed and recovery codes as
 * backups, each used once, limited per account, and required by the site's own rule.
 */
export const mfa =
  (options: MfaOptions = {}): Plugin =>
  (config: Config): Config => {
    const o: Resolved = {
      users: options.users ?? 'users',
      issuer: options.issuer ?? 'Payload',
      rememberHours: options.rememberHours ?? 24,
      emailBlockHours: options.emailBlockHours ?? 24,
      emailCodeMinutes: options.emailCodeMinutes ?? 10,
      endpoint: options.endpoint ?? false,
      requiredFor: options.requiredFor,
      limit: options.limit,
      clientAddress: options.clientAddress,
      sendEmailCode: options.sendEmailCode,
      onEvent: options.onEvent,
      legacyUserField: options.legacyUserField,
      keyDerivation: { salt: options.keyDerivation?.salt ?? 'payload-plugin-mfa', info: options.keyDerivation?.info ?? 'two-step-secret' },
      limits: { code: options.limits?.code ?? 5, emailCode: options.limits?.emailCode ?? 3, windowMinutes: options.limits?.windowMinutes ?? 15 },
      attempts: 'mfa-attempts',
      stateSlug: 'mfa-state',
    }
    if (!config.secret || config.secret.length < 32) throw new Error('mfa: the app secret must be at least 32 characters (it seals the authenticator secrets).')
    const users = (config.collections ?? []).find((c) => c.slug === o.users)
    if (!users?.auth) throw new Error(`mfa: no auth collection "${o.users}".`)
    if (typeof users.auth === 'object' && users.auth.useAPIKey)
      throw new Error('mfa: API keys sign in without a password or code, which would skip two-step. Turn off `auth.useAPIKey` on this collection, or put API keys on a separate collection.')
    for (const slug of [o.attempts, o.stateSlug]) if ((config.collections ?? []).some((c) => c.slug === slug)) throw new Error(`mfa: a collection "${slug}" already exists.`)
    if (o.rememberHours * 3600 <= ((typeof users.auth === 'object' && users.auth.tokenExpiration) || 7200))
      throw new Error('mfa: `rememberHours` must be longer than the collection’s `auth.tokenExpiration`.')
    if (o.legacyUserField && users.fields.some((f) => 'name' in f && f.name === o.legacyUserField))
      throw new Error(`mfa: remove the "${o.legacyUserField}" field from "${o.users}": Payload's sign-in would keep writing it. Run moveLegacyState once to move its data.`)

    const onInit = config.onInit
    return {
      ...config,
      collections: [
        ...(config.collections ?? []).map((c): CollectionConfig =>
          c.slug !== o.users
            ? c
            : {
                ...c,
                hooks: {
                  ...c.hooks,
                  beforeLogin: [...(c.hooks?.beforeLogin ?? []), beforeLogin],
                  beforeOperation: [...(c.hooks?.beforeOperation ?? []), beforeOperation],
                  afterOperation: [...(c.hooks?.afterOperation ?? []), afterOperation],
                },
                endpoints: [...(c.endpoints || []), ...(o.endpoint ? [loginEndpoint(o)] : [])],
              },
        ),
        stateCollection(o),
        attemptsCollection(o),
      ],
      custom: { ...config.custom, mfa: o },
      onInit: async (payload) => {
        await onInit?.(payload)
        wrapStrategies(payload, o)
      },
    }
  }
