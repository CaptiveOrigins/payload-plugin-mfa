import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'

import { Secret, TOTP } from 'otpauth'

export const STEP_SECONDS = 30
const RECOVERY_CODES = 10
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

export type Keys = { seal: Buffer }

/** The key that seals app secrets and signs everything else, from the app's own secret. */
export const deriveKey = (appSecret: string, salt: string, info: string): Keys => ({ seal: Buffer.from(hkdfSync('sha256', appSecret, salt, info, 32)) })

export function seal(keys: Keys, text: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', keys.seal, iv)
  const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
  return [iv, cipher.getAuthTag(), body].map((p) => p.toString('base64url')).join('.')
}

/** Null when it can't be opened (the app's secret changed, or the value isn't ours). */
export function open(keys: Keys, sealed: string | null | undefined): string | null {
  if (!sealed) return null
  try {
    const [iv, tag, body] = sealed.split('.').map((p) => Buffer.from(p, 'base64url'))
    if (!iv || !tag || !body) return null
    const decipher = createDecipheriv('aes-256-gcm', keys.seal, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
  } catch {
    return null
  }
}

export const mac = (keys: Keys, text: string) => createHmac('sha256', keys.seal).update(text).digest('hex')

/** Constant-time comparison of two strings of hex or similar. */
export const same = (a: string, b: string) => {
  const x = Buffer.from(a)
  const y = Buffer.from(b)
  return x.length === y.length && timingSafeEqual(x, y)
}

const totp = (secret: string, issuer = 'Payload', label = 'account') => new TOTP({ issuer, label, algorithm: 'SHA1', digits: 6, period: STEP_SECONDS, secret: Secret.fromBase32(secret) })

export const newSecret = () => new Secret({ size: 20 }).base32
/** What the authenticator app reads from the QR code. */
export const appLink = (secret: string, issuer: string, label: string) => totp(secret, issuer, label).toString()
/** The code an app shows at `timestamp`, for tests and tools. */
export const codeFor = (secret: string, timestamp = Date.now()) => totp(secret).generate({ timestamp })

/** The time step an app code belongs to, allowing one step of clock drift either way, or null when it's wrong. */
export function appCodeStep(secret: string, code: string, now: number): number | null {
  const delta = totp(secret).validate({ token: code.replace(/\s/g, ''), timestamp: now, window: 1 })
  return delta === null ? null : Math.floor(now / 1000 / STEP_SECONDS) + delta
}

export const hashRecovery = (code: string) => createHash('sha256').update(code.toUpperCase().replace(/[^A-Z0-9]/g, '')).digest('hex')

/** Ten single-use codes (80 bits each) and the hashes to keep. The codes are shown once. */
export function newRecoveryCodes(): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: RECOVERY_CODES }, () =>
    Array.from({ length: 4 }, () => Array.from({ length: 4 }, () => RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)]).join('')).join('-'),
  )
  return { codes, hashes: codes.map(hashRecovery) }
}

export const emailCodeHash = (keys: Keys, code: string) => mac(keys, `email-code|${code}`)

/** Eight digits, so it can't be mistaken for an app's six. */
export const newEmailCode = () => String(randomInt(10_000_000, 100_000_000))
