import { createCipheriv, hkdfSync, randomBytes } from 'node:crypto'

import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { BasePayload, buildConfig, createLocalReq, getPayload, type Endpoint, type Payload, type PayloadRequest, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { afterPasswordSet, allowEnrollment, codeFor, confirm, isOnFor, moveLegacyState, newRecoveryCodesFor, rememberValue, sendEmailCode, signIn, start, statusFor, resetFor, turnOff, mfa, MFA_TRUSTED, verify, type Limiter, type MfaEvent } from '../src/index.js'
import { deriveKey, open, seal } from '../src/crypto.js'
import { allowed, optionsOf } from '../src/core.js'

/** A made-up site: staff must use two-step, members may. Codes come from the secret `start` returns. */
type U = { id: string; email: string; role: string; sessions?: { id: string }[] }
const SECRET = 'a-made-up-app-secret-for-tests-only-0123456789'
const PW = 'correct-horse-battery'
let payload: Payload
let config: SanitizedConfig
let mongo: MongoMemoryReplSet
const mail: { to: string; text: string }[] = []
const events: MfaEvent[] = []
let n = 0
const email = (name: string) => `${name}-${++n}@example.invalid`

const make = async (role = 'member') => (await payload.create({ collection: 'users', data: { email: email(role), password: PW, role } as never })) as unknown as U
const reqWith = async (headers: Record<string, string> = {}, user?: U & { _sid?: string }) => {
  const req = (await createLocalReq({ ...(user ? { user: { ...user, collection: 'users' } as never } : {}) }, payload)) as PayloadRequest
  ;(req as { headers: Headers }).headers = new Headers(headers)
  return req
}
const reason = async (p: Promise<unknown>) => {
  try {
    await p
    return 'signed in'
  } catch (error) {
    return (error as { mfa?: string }).mfa ?? (error as Error).message
  }
}
/** Sets up an app for an account and returns its secret. */
const enrol = async (u: U) => {
  const { key } = await start(payload, { userId: u.id })
  const { recoveryCodes } = await confirm(payload, { userId: u.id, code: codeFor(key) })
  return { key, recoveryCodes }
}
/** The account (for its sessions) and its two-step state document. */
const state = async (u: U) => {
  const account = (await payload.findByID({ collection: 'users', id: u.id, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { sessions?: { id: string }[] }
  const doc = (await payload.find({ collection: 'mfa-state' as never, where: { user: { equals: String(u.id) } }, limit: 1, overrideAccess: true })).docs[0] as unknown as Record<string, any>
  return { sessions: account.sessions, twoStep: doc ?? {}, docId: doc?.id }
}
/** The next time step's code: accepted now (drift), and it moves `lastStep` past the current one. */
const nextStepCode = (key: string) => codeFor(key, Date.now() + 30_000)

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  config = await buildConfig({
    secret: SECRET,
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('twostep'), ensureIndexes: true }),
    collections: [{ slug: 'users', auth: true, access: { read: () => true, update: () => true }, fields: [{ name: 'role', type: 'text' }] }],
    plugins: [
      mfa({
        requiredFor: ({ user }) => {
          if ((user as unknown as U).role === 'broken') throw new Error('rule failed')
          return (user as unknown as U).role === 'staff'
        },
        issuer: 'Test site',
        clientAddress: (req) => req.headers?.get?.('x-test-ip') ?? null,
        sendEmailCode: async ({ to, code }) => void mail.push({ to, text: code }),
        onEvent: (e) => void events.push({ ...e, req: undefined }),
        endpoint: true,
      }),
    ],
  })
  payload = await getPayload({ config })
}, 120_000)

afterAll(async () => {
  await payload?.destroy?.()
  await mongo?.stop()
})

const login = (u: U, extra: { code?: string; remember?: string; req?: PayloadRequest; context?: Record<string, unknown> } = {}) => signIn(payload, { email: u.email, password: PW, ...extra })

describe('signing in', () => {
  it('needs nothing extra until two-step is on, then needs a code; REST and GraphQL can’t carry one', async () => {
    const u = await make()
    expect(await reason(login(u))).toBe('signed in')
    const { key } = await enrol(u)
    expect(await isOnFor(payload, u.id)).toBe(true)
    // Payload's own login with no code: what REST and GraphQL do.
    expect(await reason(payload.login({ collection: 'users', data: { email: u.email, password: PW } }))).toBe('needed')
    expect(await reason(login(u, { code: '000000' }))).toBe('wrong')
    expect(await reason(login(u, { code: nextStepCode(key) }))).toBe('signed in')
  })

  it('uses each app code once, even a code still inside the drift window', async () => {
    const u = await make()
    const { key } = await enrol(u)
    const later = nextStepCode(key)
    expect(await reason(login(u, { code: later }))).toBe('signed in')
    expect(await reason(login(u, { code: later }))).toBe('wrong') // the same code again
    expect(await reason(login(u, { code: codeFor(key) }))).toBe('wrong') // the step before the one used, still within drift
  })

  it('uses a recovery code once', async () => {
    const u = await make()
    const { recoveryCodes } = await enrol(u)
    expect(await reason(login(u, { code: recoveryCodes[0]! }))).toBe('signed in')
    expect(await reason(login(u, { code: recoveryCodes[0]! }))).toBe('wrong')
    expect((await state(u)).twoStep.recovery).toHaveLength(9)
    expect(events.some((e) => e.type === 'recovery-used' && e.user === String(u.id))).toBe(true)
  })

  it('takes an emailed code once, and none for a day after a new password set through the mailbox', async () => {
    const u = await make()
    await enrol(u)
    mail.length = 0
    await sendEmailCode(payload, { email: u.email })
    const code = mail.at(-1)!.text
    expect(code).toMatch(/^\d{8}$/)
    expect(await reason(login(u, { code }))).toBe('signed in')
    expect(await reason(login(u, { code }))).toBe('wrong')
    await afterPasswordSet(payload, { userId: u.id })
    mail.length = 0
    await sendEmailCode(payload, { email: u.email })
    expect(mail).toHaveLength(0) // blocked: the mailbox just proved itself
  })

  it('blocks emailed codes by itself after Payload’s own password reset', async () => {
    const u = await make()
    await enrol(u)
    const token = await payload.forgotPassword({ collection: 'users', data: { email: u.email }, disableEmail: true })
    const req = await reqWith()
    req.context = { [MFA_TRUSTED]: true }
    await payload.resetPassword({ collection: 'users', data: { token: token as string, password: 'a-new-password-1' }, overrideAccess: true, req })
    expect(new Date((await state(u)).twoStep.emailBlockedUntil).getTime()).toBeGreaterThan(Date.now())
  })
})

describe('who must use it', () => {
  it('refuses a required account that hasn’t enrolled, and one whose rule throws; a staff window lets them in to enrol, until they do', async () => {
    const staff = await make('staff')
    expect(await reason(login(staff))).toBe('enroll')
    expect(await reason(login(await make('broken')))).toBe('enroll') // fails closed
    await allowEnrollment(payload, { userId: staff.id, hours: 1 })
    expect(await reason(login(staff))).toBe('signed in')
    const { key } = await enrol(staff)
    expect((await state(staff)).twoStep.enrollUntil ?? null).toBeNull() // the window ends at the first confirm
    expect(await reason(login(staff, { code: nextStepCode(key) }))).toBe('signed in')
  })

  it('signs out, on its next request, a session whose account became required without two-step', async () => {
    const u = await make()
    const { token } = await login(u)
    const who = async () => (await payload.auth({ headers: new Headers({ Authorization: `JWT ${token}` }) })).user
    expect(await who()).toBeTruthy()
    await payload.update({ collection: 'users', id: u.id, data: { role: 'staff' } as never, overrideAccess: true })
    expect(await who()).toBeNull()
  })
})

describe('sessions and remembered browsers', () => {
  const refresh = async (user: U & { _sid?: string }) => {
    const hooks = payload.collections.users!.config.hooks.beforeOperation ?? []
    const req = await reqWith({}, user)
    for (const h of hooks) await h({ operation: 'refresh', req, args: {} as never, collection: payload.collections.users!.config, context: {} } as never)
  }
  const sidOf = async (u: U) => (await state(u)).sessions!.at(-1)!.id

  it('counts a code per session: one device’s code doesn’t extend another, and a session past the window can’t refresh', async () => {
    const u = await make()
    const { key } = await enrol(u)
    await login(u, { code: nextStepCode(key) })
    const a = await sidOf(u)
    // Another sign-in vouched for by the site's own code (no code given): not verified.
    const req = await reqWith()
    await login(u, { context: { [MFA_TRUSTED]: true }, req })
    const b = await sidOf(u)
    expect(a).not.toBe(b)
    await refresh({ ...u, _sid: a })
    await expect(refresh({ ...u, _sid: b })).rejects.toThrow()
    // Session A's code was given more than the window ago.
    const s = await state(u)
    await payload.db.updateOne({ collection: 'mfa-state', id: s.docId, data: { sessions: { [a]: new Date(Date.now() - 23 * 3_600_000).toISOString() } } })
    await expect(refresh({ ...u, _sid: a })).rejects.toThrow()
  })

  it('a remembered browser signs in without a code, until the cookie is edited or the password changes', async () => {
    const u = await make()
    const { key } = await enrol(u)
    await login(u, { code: nextStepCode(key) })
    const remember = await rememberValue(payload, { userId: u.id })
    expect(await reason(login(u, { remember }))).toBe('signed in')
    expect(await reason(login(u, { remember: remember.replace(/.$/, (c) => (c === 'a' ? 'b' : 'a')) }))).toBe('needed')
    await payload.update({ collection: 'users', id: u.id, data: { password: 'a-different-password' } as never, overrideAccess: true })
    expect(await reason(signIn(payload, { email: u.email, password: 'a-different-password', remember }))).toBe('needed')
  })
})

describe('limits', () => {
  it('limits per account, never by address: five wrong codes from one address, then the right one from another is refused', async () => {
    const u = await make()
    const { key } = await enrol(u)
    for (let i = 0; i < 5; i++) await reason(login(u, { code: '111111', req: await reqWith({ 'x-test-ip': '203.0.113.1' }) }))
    expect(await reason(login(u, { code: nextStepCode(key), req: await reqWith({ 'x-test-ip': '203.0.113.99' }) }))).toBe('wrong')
    expect(events.some((e) => e.type === 'too-many-tries' && e.user === String(u.id))).toBe(true)
  })

  it('builds the limiter’s key itself, and refuses when the limiter throws', async () => {
    const o = optionsOf(payload)
    const before = o.limit
    const seen: string[] = []
    try {
      o.limit = (({ kind, key }) => (seen.push(`${kind}|${key}`), true)) as Limiter
      const u = await make()
      const { key } = await enrol(u)
      await login(u, { code: nextStepCode(key), req: await reqWith({ 'x-test-ip': '198.51.100.7' }) })
      expect(seen).toEqual(expect.arrayContaining([`code|account:${u.id}`, 'code-address|address:198.51.100.7']))
      o.limit = (() => {
        throw new Error('limiter down')
      }) as Limiter
      const v = await make()
      const { key: k2 } = await (async () => {
        o.limit = (() => true) as Limiter
        const r = await enrol(v)
        o.limit = (() => {
          throw new Error('limiter down')
        }) as Limiter
        return r
      })()
      expect(await reason(login(v, { code: nextStepCode(k2) }))).toBe('wrong')
    } finally {
      o.limit = before
    }
  })
})

/** Holds Payload login's first read of the account (made before its transaction) until released. Platform's repro, adapted. */
function holdLoginRead() {
  let release!: () => void
  const gate = new Promise<void>((r) => (release = r))
  let readDone!: () => void
  const read = new Promise<void>((r) => (readDone = r))
  const original = payload.db.findOne.bind(payload.db)
  let held = false
  payload.db.findOne = (async (args: any) => {
    const result = await original(args)
    if (!held && args.collection === 'users' && !args.req?.transactionID) {
      held = true
      readDone()
      await gate
    }
    return result
  }) as typeof payload.db.findOne
  return { read, release, restore: () => (payload.db.findOne = original as never) }
}

describe('races with Payload’s own sign-in', () => {
  it('a sign-in that began before two-step was confirmed doesn’t turn it back off', async () => {
    const u = await make()
    const { key } = await start(payload, { userId: u.id })
    const hold = holdLoginRead()
    const pending = login(u).catch(() => undefined) // a second tab, or someone with the password
    await hold.read
    await confirm(payload, { userId: u.id, code: codeFor(key) })
    hold.release()
    await pending
    hold.restore()
    expect(await isOnFor(payload, u.id)).toBe(true)
  })

  it('one recovery code signs in once, even when the second sign-in began first', async () => {
    const u = await make()
    const { recoveryCodes } = await enrol(u)
    const code = recoveryCodes[0]!
    const hold = holdLoginRead()
    const second = reason(login(u, { code }))
    await hold.read
    hold.restore()
    const first = await reason(login(u, { code }))
    hold.release()
    expect([first, await second].sort()).toEqual(['signed in', 'wrong'])
  })

  it('deletes tries older than the window, so refused tries can’t pile up', async () => {
    const u = await make()
    await payload.db.create({ collection: 'mfa-attempts', data: { keyHash: 'old-try', at: new Date(Date.now() - 2 * 60 * 60_000).toISOString() } })
    await allowed(payload, 'code', u.id)
    expect((await payload.count({ collection: 'mfa-attempts' as never, where: { keyHash: { equals: 'old-try' } }, overrideAccess: true })).totalDocs).toBe(0)
  })

  it('the built-in limit lets at most five of forty tries at once through', async () => {
    const u = await make()
    const results = await Promise.all(Array.from({ length: 40 }, () => allowed(payload, 'code', u.id)))
    expect(results.filter(Boolean).length).toBeLessThanOrEqual(5)
    expect(results.filter(Boolean).length).toBeGreaterThan(0)
  })
})

describe('changing the factor', () => {
  it('won’t move two-step to another app without a current app or recovery code, and an emailed code isn’t enough', async () => {
    const u = await make()
    const { key, recoveryCodes } = await enrol(u)
    await expect(start(payload, { userId: u.id })).rejects.toMatchObject({ reason: 'needsCode' })
    mail.length = 0
    await sendEmailCode(payload, { email: u.email })
    await expect(start(payload, { userId: u.id, code: mail.at(-1)!.text })).rejects.toMatchObject({ reason: 'wrongCode' })
    await expect(turnOff(payload, { userId: u.id, code: mail.at(-1)!.text })).rejects.toMatchObject({ reason: 'wrongCode' })
    expect((await start(payload, { userId: u.id, code: recoveryCodes[1]! })).key).toBeTruthy()
    const renewed = await newRecoveryCodesFor(payload, { userId: u.id, code: nextStepCode(key) })
    expect(renewed.recoveryCodes).toHaveLength(10)
    expect(await reason(login(u, { code: recoveryCodes[2]! }))).toBe('wrong') // the old set is gone
  })

  it('turns off with a current code, after which signing in needs no code', async () => {
    const u = await make()
    const { key } = await enrol(u)
    await turnOff(payload, { userId: u.id, code: nextStepCode(key) })
    expect(await isOnFor(payload, u.id)).toBe(false)
    expect(await reason(login(u))).toBe('signed in')
  })
})

describe('status and a maintainer’s reset', () => {
  it('reports on, since when and recovery codes left, and nothing for an account without it', async () => {
    const u = await make()
    expect(await statusFor(payload, u.id)).toEqual({ on: false, since: null, recoveryLeft: 0 })
    const { recoveryCodes } = await enrol(u)
    const s = await statusFor(payload, u.id)
    expect(s.on).toBe(true)
    expect(s.since).toBe((await state(u)).twoStep.enabledAt)
    expect(s.recoveryLeft).toBe(recoveryCodes.length)
    expect(await reason(login(u, { code: recoveryCodes[0] }))).toBe('signed in')
    expect((await statusFor(payload, u.id)).recoveryLeft).toBe(recoveryCodes.length - 1)
    expect(Object.keys(s)).toEqual(['on', 'since', 'recoveryLeft'])
  })

  it('resets without a code: the old app, recovery codes and remembered browsers stop working, and a required account must enrol again', async () => {
    const staff = await make('staff')
    await allowEnrollment(payload, { userId: staff.id, hours: 1 })
    const { key, recoveryCodes } = await enrol(staff)
    const remembered = await rememberValue(payload, { userId: staff.id })
    expect(await reason(login(staff, { remember: remembered }))).toBe('signed in')
    events.length = 0
    await resetFor(payload, staff.id, { enrollHours: 2, actor: 'maintainer-1' })
    expect(await statusFor(payload, staff.id)).toEqual({ on: false, since: null, recoveryLeft: 0 })
    const after = (await state(staff)).twoStep
    expect([after.secret, after.pending, after.recovery, after.emailCode, after.sessions]).toEqual([null, null, [], null, {}])
    expect(new Date(after.enrollUntil).getTime() - Date.now()).toBeGreaterThan(1.9 * 60 * 60_000)
    expect(events.map((e) => [e.type, e.detail])).toEqual([['reset', { by: 'maintainer-1', hours: 2 }]])
    // The old code, a recovery code and the remembered browser give nothing: inside the window the account signs in
    // with its password, to set up again.
    await expect(login(staff, { code: nextStepCode(key) })).resolves.toBeTruthy()
    expect(await isOnFor(payload, staff.id)).toBe(false)
    await resetFor(payload, staff.id, { enrollHours: 1 })
    await payload.db.updateOne({ collection: 'mfa-state', where: { user: { equals: String(staff.id) } }, data: { enrollUntil: new Date(Date.now() - 1000).toISOString() } } as never)
    expect(await reason(login(staff, { code: recoveryCodes[1] }))).toBe('enroll')
    expect(await reason(login(staff, { remember: remembered }))).toBe('enroll')
    await expect(resetFor(payload, staff.id, { enrollHours: 0 })).rejects.toThrow(/enrollHours/)
    await expect(resetFor(payload, 'aaaaaaaaaaaaaaaaaaaaaaaa')).rejects.toMatchObject({ reason: 'notFound' })
  })

  it('clears the account’s limiter tries, and loses no write to a racing sign-in', async () => {
    const u = await make()
    const { key } = await enrol(u)
    for (let i = 0; i < 5; i++) await reason(login(u, { code: '000000' }))
    expect(await reason(login(u, { code: nextStepCode(key) }))).not.toBe('signed in') // limit reached
    await Promise.all([resetFor(payload, u.id), reason(login(u, { code: nextStepCode(key) }))])
    expect(await statusFor(payload, u.id)).toMatchObject({ on: false })
    expect(await allowed(payload, 'code', u.id)).toBe(true)
  })
})

describe('step-up for other plugins', () => {
  it('verify() takes a good code once, and only one of two at the same moment wins', async () => {
    const u = await make()
    const { key } = await enrol(u)
    const code = nextStepCode(key)
    const both = await Promise.all([verify(payload, { user: u as never, code }), verify(payload, { user: u as never, code })])
    expect(both.filter(Boolean)).toHaveLength(1)
    expect(await verify(payload, { user: u as never, code })).toBe(false)
    expect(await verify(payload, { user: u as never, code: '123456' })).toBe(false)
  })
})

describe('telling nothing, keeping nothing readable', () => {
  it('sends nothing, and says nothing different, for an unknown address or an account without two-step', async () => {
    mail.length = 0
    await sendEmailCode(payload, { email: 'nobody@example.invalid' })
    await sendEmailCode(payload, { email: (await make()).email })
    expect(mail).toHaveLength(0)
  })

  it('never puts a code or secret in an event, and keeps the state out of every API read', async () => {
    const u = await make()
    const { key, recoveryCodes } = await enrol(u)
    const text = JSON.stringify(events)
    expect(text).not.toContain(key)
    expect(text).not.toContain(recoveryCodes[0]!)
    const read = (await payload.findByID({ collection: 'users', id: u.id, overrideAccess: false, user: { ...u, collection: 'users' } as never })) as Record<string, unknown>
    expect(read.twoStep).toBeUndefined()
    await expect(payload.find({ collection: 'mfa-state' as never, overrideAccess: false, user: { ...u, collection: 'users' } as never })).rejects.toThrow()
  })

  it('opens an app secret sealed the way Captive Origins seals them today, with its key settings', () => {
    // The site's sealSecret (src/lib/security/twoStep.ts), copied as it is.
    const siteKey = Buffer.from(hkdfSync('sha256', SECRET, 'captive-origins', 'two-step-secret', 32))
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', siteKey, iv)
    const body = Buffer.concat([cipher.update('JBSWY3DPEHPK3PXP', 'utf8'), cipher.final()])
    const sealed = [iv, cipher.getAuthTag(), body].map((p) => p.toString('base64url')).join('.')
    expect(open(deriveKey(SECRET, 'captive-origins', 'two-step-secret'), sealed)).toBe('JBSWY3DPEHPK3PXP')
    expect(open(deriveKey(SECRET, 'payload-plugin-two-step', 'two-step-secret'), sealed)).toBeNull()
  })
})

describe('the login endpoint', () => {
  const post = async (body: unknown) => {
    const ep = (payload.collections.users!.config.endpoints as Endpoint[]).find((e) => e.path === '/mfa/login')!
    const req = await reqWith({ 'content-type': 'application/json' })
    ;(req as unknown as { json: () => Promise<unknown> }).json = async () => body
    return ep.handler(req)
  }
  it('answers an unknown email like a wrong password, asks for a code, and signs in with one', async () => {
    const unknown = await (await post({ email: 'nobody@example.invalid', password: PW })).json()
    const wrong = await (await post({ email: (await make()).email, password: 'not-it-at-all' })).json()
    expect(unknown).toEqual(wrong)
    const u = await make()
    const { key } = await enrol(u)
    expect(await (await post({ email: u.email, password: PW })).json()).toEqual({ ok: false, mfa: 'needed' })
    const ok = await post({ email: u.email, password: PW, code: nextStepCode(key) })
    expect(ok.status).toBe(200)
    expect(ok.headers.getSetCookie().some((c) => c.startsWith('payload-mfa='))).toBe(true)
  })
})

describe('moving state Captive Origins kept on the account', () => {
  it('refuses an account with unmoved state, moves it with an explicit run (safe to repeat), and keeps two-step on', async () => {
    const legacyCfg = (fields: any[] = []) =>
      buildConfig({ secret: SECRET, telemetry: false, typescript: { autoGenerate: false }, db: mongooseAdapter({ url: mongo.getUri('legacy'), ensureIndexes: true }), collections: [{ slug: 'users', auth: true, fields }], plugins: [mfa({ legacyUserField: 'twoStep', keyDerivation: { salt: 'captive-origins', info: 'two-step-secret' } })] })
    await expect(legacyCfg([{ name: 'twoStep', type: 'group', fields: [{ name: 'secret', type: 'text' }] }])).rejects.toThrow(/remove the "twoStep" field/)
    const first = await new BasePayload().init({ config: await legacyCfg() })
    const u = (await first.create({ collection: 'users', data: { email: 'legacy@example.invalid', password: PW } as never })) as unknown as U
    const secret = 'JBSWY3DPEHPK3PXP'
    const sealed = seal(deriveKey(SECRET, 'captive-origins', 'two-step-secret'), secret)
    // The account as Captive Origins stores it today: the group on the account, sealed with its key settings.
    await (first.db as any).collections.users.collection.updateOne({ email: 'legacy@example.invalid' }, { $set: { twoStep: { secret: sealed, enabledAt: new Date().toISOString(), recovery: [] } } })
    const half = (await first.create({ collection: 'users', data: { email: 'half@example.invalid', password: PW } as never })) as unknown as U
    await (first.db as any).collections.users.collection.updateOne({ email: 'half@example.invalid' }, { $set: { twoStep: { pending: sealed } } })
    await first.destroy()
    const second = await new BasePayload().init({ config: await legacyCfg() })
    // Not moved yet: refused even with a good code, so it can't run half-moved.
    expect(await signIn(second, { email: 'legacy@example.invalid', password: PW, code: codeFor(secret) }).then(() => 'signed in', (e) => e.mfa)).toBe('needed')
    expect(await moveLegacyState(second)).toEqual({ moved: 1, alreadyMoved: 0, unfinished: 1, cleared: 2 })
    expect(await moveLegacyState(second)).toEqual({ moved: 0, alreadyMoved: 0, unfinished: 0, cleared: 0 })
    void half
    expect(await (second.db as any).collections.users.collection.countDocuments({ twoStep: { $exists: true } })).toBe(0)
    const moved = (await second.find({ collection: 'mfa-state' as never, where: { user: { equals: String(u.id) } }, overrideAccess: true })).docs
    expect(moved).toHaveLength(1)
    expect(await isOnFor(second, u.id)).toBe(true)
    const why = await signIn(second, { email: 'legacy@example.invalid', password: PW }).then(() => 'signed in', (e) => e.mfa)
    expect(why).toBe('needed')
    expect(await signIn(second, { email: 'legacy@example.invalid', password: PW, code: codeFor(secret) }).then(() => 'signed in', (e) => e.mfa)).toBe('signed in')
    await second.destroy()
  })
})

describe('refusing to start', () => {
  const build = (over: Record<string, unknown>, opts = {}) =>
    buildConfig({ secret: SECRET, telemetry: false, typescript: { autoGenerate: false }, db: mongooseAdapter({ url: mongo.getUri('x') }), collections: [{ slug: 'users', auth: true, fields: [] }], ...over, plugins: [mfa(opts)] })
  it('with a short app secret, without the auth collection, or with API keys on it', async () => {
    await expect(build({ secret: 'short' })).rejects.toThrow(/at least 32/)
    await expect(build({ collections: [{ slug: 'people', auth: true, fields: [] }] })).rejects.toThrow(/no auth collection/)
    await expect(build({ collections: [{ slug: 'users', auth: { useAPIKey: true }, fields: [] }] })).rejects.toThrow(/API keys/)
  })
})
