import type { Payload, PayloadRequest } from 'payload'

/** What the plugin keeps for each account, in its own `two-step-state` collection (one document per account). */
export type TwoStepState = {
  /** The app secret, sealed (AES-256-GCM). */
  secret?: string | null
  /** A secret waiting for its first code, sealed. */
  pending?: string | null
  enabledAt?: string | null
  /** The last app-code time step accepted: any step at or before it is refused, so a code works once. */
  lastStep?: number | null
  /** Recovery codes, hashed. */
  recovery?: string[] | null
  /** When a code was last accepted on any session (kept for sessions made before `sessions` existed). */
  verifiedAt?: string | null
  /** When a code was last accepted, per Payload session id: one device's code never extends another. */
  sessions?: Record<string, string> | null
  emailCode?: string | null
  emailCodeExpires?: string | null
  /** After a password reset: the mailbox just proved itself, so it can't also be the second step for a while. */
  emailBlockedUntil?: string | null
  /** A staff-given window to sign in and enrol while two-step is required. Ends at the first successful confirm. */
  enrollUntil?: string | null
  /** Bumped on every write, so two requests racing with the same code can't both win. */
  version?: number | null
}

export type TwoStepUser = { id: string | number; email?: string | null; collection?: string; hash?: string | null; sessions?: { id: string; expiresAt?: string | Date }[] | null; _sid?: string } & Record<string, unknown>

export type TwoStepEvent = {
  type: 'started' | 'confirmed' | 'turned-off' | 'recovery-renewed' | 'recovery-used' | 'email-code-sent' | 'email-codes-blocked' | 'enrollment-window' | 'too-many-tries'
  user: string
  req?: PayloadRequest
  /** Never a code, a secret or an address. */
  detail?: Record<string, string | number | boolean | null>
}

/** What the limiter counts. Keys are built by the plugin, never by a caller. */
export type LimitKind = 'code' | 'emailCode' | 'code-address' | 'emailCode-address'
/** Resolve true to allow. Anything else, or throwing, refuses. */
export type Limiter = (args: { kind: LimitKind; key: string; req?: PayloadRequest }) => boolean | Promise<boolean>

export type TwoStepOptions = {
  /** The auth collection. Default `users`. */
  users?: string
  /**
   * Captive Origins kept this state in a group on the account (default name `twoStep`). Name it here to move it,
   * once, into the plugin's own collection when the site starts: each account's old state is copied (where the account
   * has none yet) and removed from the account. The group must no longer be declared on the auth collection.
   */
  legacyUserField?: string
  /** Who must have two-step to sign in. Throwing counts as required. Default: nobody. */
  requiredFor?: (args: { user: TwoStepUser; req?: PayloadRequest }) => boolean | Promise<boolean>
  /** The name the authenticator app shows. Default `Payload`. */
  issuer?: string
  /** HKDF salt and info for the key that seals app secrets. Keep them once chosen: changing them makes stored secrets unreadable. */
  keyDerivation?: { salt?: string; info?: string }
  /** How long a browser that gave a code signs in with the password alone, and the most a session lives after a code. Default 24. */
  rememberHours?: number
  /** After a password reset, how long email codes are off. Default 24. */
  emailBlockHours?: number
  /** How long an emailed code works, in minutes. Default 10. */
  emailCodeMinutes?: number
  /** The site's limiter. Default: a built-in one with hashed keys. */
  limit?: Limiter
  /** Built-in limiter: tries per window, per account. Defaults: 5 codes and 3 email codes per 15 minutes. */
  limits?: { code?: number; emailCode?: number; windowMinutes?: number }
  /** The client's address, for an extra per-address limit on top of the per-account one. Optional. */
  clientAddress?: (req: PayloadRequest) => string | null
  /** Sends an emailed code. Default: `payload.sendEmail` with plain text. */
  sendEmailCode?: (args: { payload: Payload; to: string; code: string; minutes: number; req?: PayloadRequest }) => Promise<unknown>
  /** Every change and refusal worth recording, for an audit trail. */
  onEvent?: (event: TwoStepEvent) => void | Promise<void>
  /** Add `POST /api/<users>/two-step/login` for sites without server actions. Default false. */
  endpoint?: boolean
}

export type Resolved = Required<Pick<TwoStepOptions, 'users' | 'issuer' | 'rememberHours' | 'emailBlockHours' | 'emailCodeMinutes' | 'endpoint'>> &
  Pick<TwoStepOptions, 'requiredFor' | 'limit' | 'clientAddress' | 'sendEmailCode' | 'onEvent' | 'legacyUserField'> & {
    stateSlug: string
    keyDerivation: { salt: string; info: string }
    limits: { code: number; emailCode: number; windowMinutes: number }
    attempts: string
  }
