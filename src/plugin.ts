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
  sessionVerifiedAt,
  TWO_STEP_CODE,
  TWO_STEP_REMEMBER,
  TWO_STEP_TRUSTED,
  withSession,
} from './core.js'
import type { Resolved, TwoStepOptions, TwoStepUser } from './types.js'

/** Same answer as a wrong password to anyone reading the API; the site's own form reads `twoStep`. */
export class TwoStepError extends AuthenticationError {
  twoStep: 'needed' | 'wrong' | 'enroll'
  constructor(t: ConstructorParameters<typeof AuthenticationError>[0], twoStep: 'needed' | 'wrong' | 'enroll') {
    super(t)
    this.twoStep = twoStep
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
const newestSid = (user: TwoStepUser) => user.sessions?.at(-1)?.id

const beforeLogin: CollectionBeforeLoginHook = async ({ req, user: u }) => {
  const payload = req.payload
  const user = u as TwoStepUser
  if (req.context?.[TWO_STEP_TRUSTED] === true) return u
  const loaded = await loadState(payload, user.id, req)
  const state = loaded.state
  if (!isOnState(state)) {
    if ((await isRequired(payload, user, req)) && !inEnrollWindow(state)) throw new TwoStepError(req.t, 'enroll')
    return u
  }
  const sid = newestSid(user)
  // A browser that gave a code recently: the session counts from when that code was given.
  const since = rememberedSince(payload, user, state, req.context?.[TWO_STEP_REMEMBER])
  if (since !== null) {
    const at = new Date(since).toISOString()
    if (!(await saveIfUnchanged(payload, user.id, loaded, withSession(state, user, sid, at), req))) {
      // Someone else wrote the state at the same moment: read it again and try once more, or the session can't refresh.
      const again = await loadState(payload, user.id, req)
      if (!(await saveIfUnchanged(payload, user.id, again, withSession(again.state, user, sid, at), req)))
        payload.logger.warn({ msg: 'two-step: a remembered sign-in’s session wasn’t recorded; it will need a code at its next refresh' })
    }
    return u
  }
  const code = req.context?.[TWO_STEP_CODE]
  if (typeof code !== 'string' || !code.trim()) throw new TwoStepError(req.t, 'needed')
  // Payload's lockout counts wrong passwords only; codes have their own per-account limit.
  if (!(await allowed(payload, 'code', user.id, req))) {
    await emit(payload, { type: 'too-many-tries', user: String(user.id), req })
    throw new TwoStepError(req.t, 'wrong')
  }
  const accepted = acceptCode(keysOf(payload), state, code)
  if (!accepted) throw new TwoStepError(req.t, 'wrong')
  const next = withSession(accepted.next, user, sid, new Date().toISOString())
  if (!(await saveIfUnchanged(payload, user.id, loaded, next, req))) throw new TwoStepError(req.t, 'wrong')
  if (accepted.used === 'recovery') await emit(payload, { type: 'recovery-used', user: String(user.id), req, detail: { left: next.recovery?.length ?? 0 } })
  return u
}

/** A session can't outlive the remembered window, and an account that must have two-step but doesn't can't refresh. */
const beforeOperation: CollectionBeforeOperationHook = async ({ operation, req }) => {
  if (operation !== 'refresh' || !req.user) return
  const payload = req.payload
  const o = optionsOf(payload)
  const user = req.user as unknown as TwoStepUser
  const { state } = await loadState(payload, user.id, req)
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

/** Signs out, on its next request, a session whose account must now have two-step and doesn't. Only with a rule. */
function wrapStrategies(payload: Payload, o: Resolved) {
  payload.authStrategies = payload.authStrategies.map(
    (strategy): AuthStrategy => ({
      ...strategy,
      authenticate: async (args) => {
        const result = await strategy.authenticate(args)
        const user = result.user as TwoStepUser | null
        if (!user || user.collection !== o.users || !o.requiredFor) return result
        const { state } = await loadState(payload, user.id)
        if (!isOnState(state) && (await isRequired(payload, user)) && !inEnrollWindow(state)) return { ...result, user: null }
        return result
      },
    }),
  )
}

/**
 * Moves state Captive Origins kept on the account (`legacyUserField`) into the plugin's collection, once: for each
 * account that has old state and no new state, copy it, then remove it from the account. Any failure stops startup.
 */
async function moveLegacyState(payload: Payload, o: Resolved) {
  const field = o.legacyUserField!
  const users = (payload.db as unknown as { collections?: Record<string, { collection: { find: (q: object, opts?: object) => { toArray: () => Promise<Record<string, unknown>[]> }; updateOne: (q: object, u: object) => Promise<unknown> } }> }).collections?.[o.users]
  if (!users) throw new Error('two-step: `legacyUserField` needs the MongoDB adapter.')
  const old = await users.collection.find({ [field]: { $exists: true, $ne: null } }, { projection: { _id: 1, [field]: 1 } }).toArray()
  let moved = 0
  for (const row of old) {
    const id = String(row._id)
    const legacy = (row[field] ?? {}) as Record<string, unknown>
    const existing = await loadState(payload, id)
    if (existing.docId === null && legacy.secret) {
      const ok = await saveIfUnchanged(payload, id, existing, { ...(legacy as object), sessions: {}, version: 0 })
      if (!ok) throw new Error(`two-step: couldn’t move the old two-step state of account ${id}; nothing was removed from it.`)
      moved++
    }
    await users.collection.updateOne({ _id: row._id }, { $unset: { [field]: '' } })
  }
  if (old.length) payload.logger.info({ msg: `two-step: moved the old state of ${moved} account(s) into ${o.stateSlug}; cleared ${old.length}.` })
}

function loginEndpoint(o: Resolved): Endpoint {
  return {
    path: '/two-step/login',
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
          context: { ...(code ? { [TWO_STEP_CODE]: code } : cookie ? { [TWO_STEP_REMEMBER]: decodeURIComponent(cookie) } : {}) },
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
        if (error instanceof TwoStepError) return Response.json({ ok: false, twoStep: error.twoStep }, { status: 401, headers: { 'Cache-Control': 'no-store' } })
        return Response.json({ ok: false, errors: [{ message: 'The email or password provided is incorrect.' }] }, { status: 401, headers: { 'Cache-Control': 'no-store' } })
      }
    },
  }
}

/**
 * Two-step sign-in for Payload: an authenticator code after the password, with emailed and recovery codes as
 * backups, each used once, limited per account, and required by the site's own rule.
 */
export const twoStep =
  (options: TwoStepOptions = {}): Plugin =>
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
      keyDerivation: { salt: options.keyDerivation?.salt ?? 'payload-plugin-two-step', info: options.keyDerivation?.info ?? 'two-step-secret' },
      limits: { code: options.limits?.code ?? 5, emailCode: options.limits?.emailCode ?? 3, windowMinutes: options.limits?.windowMinutes ?? 15 },
      attempts: 'two-step-attempts',
      stateSlug: 'two-step-state',
    }
    if (!config.secret || config.secret.length < 32) throw new Error('two-step: the app secret must be at least 32 characters (it seals the authenticator secrets).')
    const users = (config.collections ?? []).find((c) => c.slug === o.users)
    if (!users?.auth) throw new Error(`two-step: no auth collection "${o.users}".`)
    if (typeof users.auth === 'object' && users.auth.useAPIKey)
      throw new Error('two-step: API keys sign in without a password or code, which would skip two-step. Turn off `auth.useAPIKey` on this collection, or put API keys on a separate collection.')
    for (const slug of [o.attempts, o.stateSlug]) if ((config.collections ?? []).some((c) => c.slug === slug)) throw new Error(`two-step: a collection "${slug}" already exists.`)
    if (o.rememberHours * 3600 <= ((typeof users.auth === 'object' && users.auth.tokenExpiration) || 7200))
      throw new Error('two-step: `rememberHours` must be longer than the collection’s `auth.tokenExpiration`.')
    if (o.legacyUserField && users.fields.some((f) => 'name' in f && f.name === o.legacyUserField))
      throw new Error(`two-step: remove the "${o.legacyUserField}" field from "${o.users}": Payload's sign-in would keep writing it. The plugin moves its data at startup.`)

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
      custom: { ...config.custom, twoStep: o },
      onInit: async (payload) => {
        await onInit?.(payload)
        if (o.legacyUserField) await moveLegacyState(payload, o)
        wrapStrategies(payload, o)
      },
    }
  }
