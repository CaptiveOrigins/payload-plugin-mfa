import { AuthenticationError, Forbidden, generatePayloadCookie, type AuthStrategy, type CollectionAfterOperationHook, type CollectionBeforeLoginHook, type CollectionBeforeOperationHook, type CollectionConfig, type Config, type Endpoint, type Field, type Payload, type Plugin } from 'payload'

import { afterPasswordSet, rememberValue } from './api.js'
import {
  acceptCode,
  allowed,
  emit,
  inEnrollWindow,
  isOnState,
  isRequired,
  keysOf,
  optionsOf,
  REMEMBER_COOKIE,
  rememberedSince,
  saveIfUnchanged,
  sessionVerifiedAt,
  stateOf,
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

function stateField(o: Resolved): Field {
  return {
    name: o.field,
    type: 'group',
    // Only the plugin's own server code reads or writes it.
    access: { read: never, create: never, update: never },
    admin: { hidden: true },
    fields: [
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
  const o = optionsOf(payload)
  const user = u as TwoStepUser
  if (req.context?.[TWO_STEP_TRUSTED] === true) return u
  const state = stateOf(payload, user)
  const on = isOnState(state)
  if (!on) {
    if ((await isRequired(payload, user, req)) && !inEnrollWindow(state)) throw new TwoStepError(req.t, 'enroll')
    return u
  }
  const sid = newestSid(user)
  // A browser that gave a code recently: the session counts from when that code was given.
  const since = rememberedSince(payload, user, req.context?.[TWO_STEP_REMEMBER])
  if (since !== null) {
    await saveIfUnchanged(payload, user, state, withSession(state, user, sid, new Date(since).toISOString()), req)
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
  if (!(await saveIfUnchanged(payload, user, state, next, req))) throw new TwoStepError(req.t, 'wrong')
  if (accepted.used === 'recovery') await emit(payload, { type: 'recovery-used', user: String(user.id), req, detail: { left: next.recovery?.length ?? 0 } })
  return { ...u, [o.field]: next }
}

/** A session can't outlive the remembered window, and an account that must have two-step but doesn't can't refresh. */
const beforeOperation: CollectionBeforeOperationHook = async ({ operation, req }) => {
  if (operation !== 'refresh' || !req.user) return
  const payload = req.payload
  const o = optionsOf(payload)
  const user = req.user as unknown as TwoStepUser
  const full = (await payload.findByID({ collection: o.users as never, id: user.id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true, req })) as unknown as TwoStepUser | null
  if (!full) throw new Forbidden(req.t)
  const state = stateOf(payload, full)
  if (!isOnState(state)) {
    if ((await isRequired(payload, full, req)) && !inEnrollWindow(state)) throw new Forbidden(req.t)
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

/** Signs out, on its next request, a session whose account must now have two-step and doesn't. */
function wrapStrategies(payload: Payload, o: Resolved) {
  payload.authStrategies = payload.authStrategies.map(
    (strategy): AuthStrategy => ({
      ...strategy,
      authenticate: async (args) => {
        const result = await strategy.authenticate(args)
        const user = result.user as TwoStepUser | null
        // Only when the site has a rule: otherwise nothing here can change the answer.
        if (!user || user.collection !== o.users || !o.requiredFor) return result
        const full = (await payload.findByID({ collection: o.users as never, id: user.id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true })) as unknown as TwoStepUser | null
        if (!full) return { ...result, user: null }
        const state = stateOf(payload, full)
        if (!isOnState(state) && (await isRequired(payload, full)) && !inEnrollWindow(state)) return { ...result, user: null }
        return result
      },
    }),
  )
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
      field: options.field ?? 'twoStep',
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
      keyDerivation: { salt: options.keyDerivation?.salt ?? 'payload-plugin-two-step', info: options.keyDerivation?.info ?? 'two-step-secret' },
      limits: { code: options.limits?.code ?? 5, emailCode: options.limits?.emailCode ?? 3, windowMinutes: options.limits?.windowMinutes ?? 15 },
      attempts: 'two-step-attempts',
    }
    if (!config.secret || config.secret.length < 32) throw new Error('two-step: the app secret must be at least 32 characters (it seals the authenticator secrets).')
    const users = (config.collections ?? []).find((c) => c.slug === o.users)
    if (!users?.auth) throw new Error(`two-step: no auth collection "${o.users}".`)
    if (typeof users.auth === 'object' && users.auth.useAPIKey)
      throw new Error('two-step: API keys sign in without a password or code, which would skip two-step. Turn off `auth.useAPIKey` on this collection, or put API keys on a separate collection.')
    if ((config.collections ?? []).some((c) => c.slug === o.attempts)) throw new Error(`two-step: a collection "${o.attempts}" already exists.`)
    if (o.rememberHours * 3600 <= ((typeof users.auth === 'object' && users.auth.tokenExpiration) || 7200))
      throw new Error('two-step: `rememberHours` must be longer than the collection’s `auth.tokenExpiration`.')

    const onInit = config.onInit
    return {
      ...config,
      collections: [
        ...(config.collections ?? []).map((c): CollectionConfig =>
          c.slug !== o.users
            ? c
            : {
                ...c,
                fields: [...c.fields, stateField(o)],
                hooks: {
                  ...c.hooks,
                  beforeLogin: [...(c.hooks?.beforeLogin ?? []), beforeLogin],
                  beforeOperation: [...(c.hooks?.beforeOperation ?? []), beforeOperation],
                  afterOperation: [...(c.hooks?.afterOperation ?? []), afterOperation],
                },
                endpoints: [...(c.endpoints || []), ...(o.endpoint ? [loginEndpoint(o)] : [])],
              },
        ),
        attemptsCollection(o),
      ],
      custom: { ...config.custom, twoStep: o },
      onInit: async (payload) => {
        await onInit?.(payload)
        wrapStrategies(payload, o)
      },
    }
  }
