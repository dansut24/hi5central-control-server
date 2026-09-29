import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import { pool, withTransaction } from './db.js'
import { verifyPassword } from './password.js'
import { ensureRedisConnected } from './redis.js'
import {
  createSession,
  resolveSession,
  sessionPayload,
  setSessionCookie,
} from './session.js'
import { originMatchesTenant as deploymentOriginMatchesTenant } from './deploymentConfig.js'
import {
  mfaGraceEndsAt,
  mfaRequiredFor,
  securitySettings,
  sessionTtlSeconds,
} from './securityPolicy.js'

const TOTP_PERIOD_SECONDS = 30
const TOTP_DIGITS = 6
const CHALLENGE_SECONDS = 10 * 60
const MAX_CHALLENGE_ATTEMPTS = 8
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function normaliseEmail(value = '') {
  return String(value).trim().toLowerCase()
}

function normaliseSlug(value = '') {
  return String(value).trim().toLowerCase()
}

function validSlug(slug) {
  return /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(slug) && !slug.includes('--')
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254
}

function hashToken(value) {
  return createHash('sha256').update(String(value || '')).digest('hex')
}

function requestIp(c) {
  const forwarded = c.req.header('x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0].trim()
  return c.req.header('x-real-ip') || 'unknown'
}

async function rateLimit(key, max, seconds) {
  const redis = await ensureRedisConnected()
  const attempts = await redis.incr(key)
  if (attempts === 1) await redis.expire(key, seconds)
  return attempts <= max
}

function originMatchesTenant(c, slug) {
  return deploymentOriginMatchesTenant(c.req.header('origin'), slug)
}

function encryptionKey() {
  const raw = String(process.env.MFA_ENCRYPTION_KEY || '').trim()
  if (!raw) {
    const error = new Error('MFA encryption is not configured on this Hi5Central environment.')
    error.status = 503
    throw error
  }

  let key
  if (/^[0-9a-f]{64}$/i.test(raw)) {
    key = Buffer.from(raw, 'hex')
  } else {
    try {
      key = Buffer.from(raw, 'base64url')
    } catch {
      key = null
    }
  }

  if (!key || key.length !== 32) {
    const error = new Error('MFA_ENCRYPTION_KEY must contain exactly 32 bytes of key material.')
    error.status = 503
    throw error
  }
  return key
}

function encryptSecret(secret) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv)
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`
}

function decryptSecret(envelope) {
  const [version, ivValue, tagValue, ciphertextValue] = String(envelope || '').split('.')
  if (version !== 'v1' || !ivValue || !tagValue || !ciphertextValue) {
    throw new Error('Stored MFA secret is invalid.')
  }
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivValue, 'base64url'))
  decipher.setAuthTag(Buffer.from(tagValue, 'base64url'))
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextValue, 'base64url')),
    decipher.final(),
  ]).toString('utf8')
}

function base32Encode(buffer) {
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return output
}

function base32Decode(input) {
  const clean = String(input || '').toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '')
  let bits = 0
  let value = 0
  const bytes = []
  for (const character of clean) {
    const index = BASE32_ALPHABET.indexOf(character)
    if (index < 0) throw new Error('Invalid base32 MFA secret.')
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

function totpForStep(secret, step) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const digest = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary = (
    ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff)
  ) >>> 0
  return String(binary % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, '0')
}

function constantTimeCodeEqual(left, right) {
  const a = Buffer.from(String(left || ''))
  const b = Buffer.from(String(right || ''))
  return a.length === b.length && timingSafeEqual(a, b)
}

function verifyTotp(secret, code, lastUsedStep = null, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code || ''))) return null
  const currentStep = Math.floor(now / 1000 / TOTP_PERIOD_SECONDS)
  for (const drift of [-1, 0, 1]) {
    const step = currentStep + drift
    if (lastUsedStep !== null && lastUsedStep !== undefined && step <= Number(lastUsedStep)) continue
    if (constantTimeCodeEqual(totpForStep(secret, step), code)) return step
  }
  return null
}

function recoveryCode() {
  let raw = ''
  for (let index = 0; index < 12; index += 1) {
    raw += RECOVERY_ALPHABET[randomBytes(1)[0] % RECOVERY_ALPHABET.length]
  }
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`
}

function normaliseRecoveryCode(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '')
}

function recoveryHash(value) {
  return createHash('sha256').update(normaliseRecoveryCode(value)).digest('hex')
}

function createRecoveryCodes() {
  const codes = Array.from({ length: 10 }, () => recoveryCode())
  return { codes, hashes: codes.map(recoveryHash) }
}

function otpauthUri({ secret, companyName, email }) {
  const issuer = 'Hi5Central'
  const account = `${companyName || 'Hi5Central'}:${email}`
  return `otpauth://totp/${encodeURIComponent(account)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
}

async function accountByCredentials(tenantSlug, email) {
  const result = await pool.query(
    `SELECT
       t.id AS tenant_id,
       t.slug,
       t.company_name,
       t.status AS tenant_status,
       u.id AS user_id,
       u.email,
       u.name,
       u.password_hash,
       m.role AS tenant_role,
       m.status AS membership_status,
       ts.modules,
       ts.onboarding_step,
       ts.onboarding_completed_at,
       ts.onboarding_data,
       ts.configuration,
       ts.tenant_url,
       ts.portal_url,
       ts.rmm_url
     FROM tenants t
     JOIN tenant_memberships m ON m.tenant_id = t.id
     JOIN users u ON u.id = m.user_id
     JOIN tenant_settings ts ON ts.tenant_id = t.id
     WHERE t.slug = $1 AND u.email = $2
     LIMIT 1`,
    [tenantSlug, email],
  )
  return result.rows[0] || null
}

async function accountByIds(db, tenantId, userId) {
  const result = await db.query(
    `SELECT
       t.id AS tenant_id,
       t.slug,
       t.company_name,
       t.status AS tenant_status,
       u.id AS user_id,
       u.email,
       u.name,
       m.role AS tenant_role,
       m.status AS membership_status,
       ts.modules,
       ts.onboarding_step,
       ts.onboarding_completed_at,
       ts.onboarding_data,
       ts.configuration,
       ts.tenant_url,
       ts.portal_url,
       ts.rmm_url
     FROM tenants t
     JOIN tenant_memberships m ON m.tenant_id = t.id
     JOIN users u ON u.id = m.user_id
     JOIN tenant_settings ts ON ts.tenant_id = t.id
     WHERE t.id = $1 AND u.id = $2
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function enabledMethod(db, tenantId, userId) {
  const result = await db.query(
    `SELECT * FROM user_mfa_methods
     WHERE tenant_id = $1 AND user_id = $2 AND method = 'totp'
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function createChallenge(db, tenantId, userId, purpose) {
  await db.query(
    `UPDATE auth_mfa_challenges
     SET used_at = COALESCE(used_at, now())
     WHERE tenant_id = $1 AND user_id = $2 AND purpose = $3 AND used_at IS NULL`,
    [tenantId, userId, purpose],
  )
  const token = randomBytes(32).toString('base64url')
  await db.query(
    `INSERT INTO auth_mfa_challenges (tenant_id, user_id, token_hash, purpose, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::int))`,
    [tenantId, userId, hashToken(token), purpose, CHALLENGE_SECONDS],
  )
  return token
}

async function challengeAccount(db, token, expectedPurpose, lock = false) {
  const result = await db.query(
    `SELECT
       c.id AS challenge_id,
       c.purpose,
       c.expires_at AS challenge_expires_at,
       c.attempts AS challenge_attempts,
       t.id AS tenant_id,
       t.slug,
       t.company_name,
       t.status AS tenant_status,
       u.id AS user_id,
       u.email,
       u.name,
       m.role AS tenant_role,
       m.status AS membership_status,
       ts.modules,
       ts.onboarding_step,
       ts.onboarding_completed_at,
       ts.onboarding_data,
       ts.configuration,
       ts.tenant_url,
       ts.portal_url,
       ts.rmm_url
     FROM auth_mfa_challenges c
     JOIN tenants t ON t.id = c.tenant_id
     JOIN users u ON u.id = c.user_id
     JOIN tenant_memberships m ON m.tenant_id = c.tenant_id AND m.user_id = c.user_id
     JOIN tenant_settings ts ON ts.tenant_id = c.tenant_id
     WHERE c.token_hash = $1
       AND c.purpose = $2
       AND c.used_at IS NULL
       AND c.expires_at > now()
       AND c.attempts < $3
     LIMIT 1${lock ? ' FOR UPDATE OF c' : ''}`,
    [hashToken(token), expectedPurpose, MAX_CHALLENGE_ATTEMPTS],
  )
  return result.rows[0] || null
}

async function provisionSecret(db, tenantId, userId) {
  const existing = await enabledMethod(db, tenantId, userId)
  if (existing?.enabled) {
    const error = new Error('MFA is already enrolled for this account.')
    error.status = 409
    throw error
  }

  if (existing && !existing.enabled) {
    return decryptSecret(existing.secret_encrypted)
  }

  const secret = base32Encode(randomBytes(20))
  await db.query(
    `INSERT INTO user_mfa_methods (
       tenant_id, user_id, method, secret_encrypted, enabled, recovery_code_hashes, updated_at
     ) VALUES ($1, $2, 'totp', $3, false, '[]'::jsonb, now())
     ON CONFLICT (tenant_id, user_id, method) DO UPDATE SET
       secret_encrypted = EXCLUDED.secret_encrypted,
       enabled = false,
       verified_at = NULL,
       recovery_code_hashes = '[]'::jsonb,
       last_used_step = NULL,
       updated_at = now()`,
    [tenantId, userId, encryptSecret(secret)],
  )
  return secret
}

function verifyMethodCode(method, code, { allowRecovery = true } = {}) {
  const secret = decryptSecret(method.secret_encrypted)
  const totpStep = verifyTotp(secret, String(code || '').trim(), method.last_used_step)
  if (totpStep !== null) return { ok: true, type: 'totp', step: totpStep }

  if (allowRecovery) {
    const hashes = Array.isArray(method.recovery_code_hashes) ? method.recovery_code_hashes : []
    const candidate = recoveryHash(code)
    const index = hashes.findIndex((hash) => constantTimeCodeEqual(hash, candidate))
    if (index >= 0) {
      return {
        ok: true,
        type: 'recovery',
        remainingHashes: hashes.filter((_, hashIndex) => hashIndex !== index),
      }
    }
  }
  return { ok: false }
}

async function requireSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c, session.slug)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  return { session }
}

function methodStatus(session, method) {
  const graceEnds = mfaGraceEndsAt(session)
  return {
    requiredForCurrentUser: mfaRequiredFor(session),
    enrolled: Boolean(method?.enabled && method?.verified_at),
    verifiedAt: method?.verified_at || null,
    recoveryCodesRemaining: Array.isArray(method?.recovery_code_hashes) ? method.recovery_code_hashes.length : 0,
    sessionVerified: Boolean(session.mfa_verified_at),
    sessionHours: securitySettings(session).sessionHours,
    graceEndsAt: graceEnds ? graceEnds.toISOString() : null,
  }
}

export function registerMfaRoutes(app) {
  app.post('/api/v1/auth/login-secure', async (c) => {
    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const email = normaliseEmail(body?.email)
    const password = String(body?.password || '')
    if (!validSlug(tenantSlug) || !validEmail(email) || !password) {
      return c.json({ error: 'Enter a valid email address and password.' }, 400)
    }
    if (!originMatchesTenant(c, tenantSlug)) return c.json({ error: 'Tenant sign-in origin mismatch.' }, 403)

    const allowed = await rateLimit(`login-secure:${requestIp(c)}:${tenantSlug}:${email}`, 10, 900)
    if (!allowed) return c.json({ error: 'Too many sign-in attempts. Please try again later.' }, 429)

    const account = await accountByCredentials(tenantSlug, email)
    if (!account) return c.json({ error: 'Email address or password is incorrect.' }, 401)
    if (account.tenant_status === 'pending_verification' || account.membership_status === 'pending_verification') {
      return c.json({ error: 'Verify your email address before signing in.' }, 403)
    }
    if (account.tenant_status !== 'active' || account.membership_status !== 'active') {
      return c.json({ error: 'This Hi5Central account is not currently active.' }, 403)
    }

    const valid = await verifyPassword(password, account.password_hash)
    if (!valid) return c.json({ error: 'Email address or password is incorrect.' }, 401)

    const ttl = sessionTtlSeconds(account)
    if (!mfaRequiredFor(account)) {
      const token = await withTransaction((client) => createSession(client, {
        tenantId: account.tenant_id,
        userId: account.user_id,
        ttlSeconds: ttl,
      }))
      setSessionCookie(c, token, ttl)
      return c.json(sessionPayload(account))
    }

    const result = await withTransaction(async (client) => {
      const method = await enabledMethod(client, account.tenant_id, account.user_id)
      const challengeToken = await createChallenge(client, account.tenant_id, account.user_id, 'login')
      return {
        challengeToken,
        setupRequired: !method?.enabled,
      }
    })

    return c.json({
      authenticated: false,
      mfaRequired: true,
      setupRequired: result.setupRequired,
      challengeToken: result.challengeToken,
      expiresInSeconds: CHALLENGE_SECONDS,
      tenant: { slug: account.slug, companyName: account.company_name },
      user: { email: account.email, name: account.name, tenantRole: account.tenant_role },
    })
  })

  app.post('/api/v1/auth/mfa/setup', async (c) => {
    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const challengeToken = String(body?.challengeToken || '')
    if (!challengeToken) return c.json({ error: 'MFA challenge is required.' }, 400)

    try {
      const material = await withTransaction(async (client) => {
        const account = await challengeAccount(client, challengeToken, 'login', true)
        if (!account) {
          const error = new Error('This MFA challenge has expired. Sign in again.')
          error.status = 401
          throw error
        }
        if (!originMatchesTenant(c, account.slug)) {
          const error = new Error('Tenant sign-in origin mismatch.')
          error.status = 403
          throw error
        }
        const secret = await provisionSecret(client, account.tenant_id, account.user_id)
        return {
          secret,
          account,
          uri: otpauthUri({ secret, companyName: account.company_name, email: account.email }),
        }
      })
      return c.json({
        secret: material.secret,
        otpauthUri: material.uri,
        issuer: 'Hi5Central',
        account: `${material.account.company_name}:${material.account.email}`,
      })
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/auth/mfa/verify', async (c) => {
    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const challengeToken = String(body?.challengeToken || '')
    const code = text(body?.code, 64)
    if (!challengeToken || !code) return c.json({ error: 'Enter your authenticator or recovery code.' }, 400)

    const result = await withTransaction(async (client) => {
      const account = await challengeAccount(client, challengeToken, 'login', true)
      if (!account || !originMatchesTenant(c, account?.slug)) {
        return { ok: false, status: 401, error: 'This MFA challenge has expired. Sign in again.' }
      }
      const method = await enabledMethod(client, account.tenant_id, account.user_id)
      if (!method) return { ok: false, status: 409, error: 'Set up your authenticator before verifying.' }

      const verification = verifyMethodCode(method, code, { allowRecovery: Boolean(method.enabled) })
      if (!verification.ok) {
        await client.query(
          'UPDATE auth_mfa_challenges SET attempts = attempts + 1 WHERE id = $1',
          [account.challenge_id],
        )
        return { ok: false, status: 401, error: 'That MFA code is not valid.' }
      }

      let recoveryCodes = null
      let recoveryHashes = Array.isArray(method.recovery_code_hashes) ? method.recovery_code_hashes : []
      if (!method.enabled) {
        const generated = createRecoveryCodes()
        recoveryCodes = generated.codes
        recoveryHashes = generated.hashes
      } else if (verification.type === 'recovery') {
        recoveryHashes = verification.remainingHashes
      }

      await client.query(
        `UPDATE user_mfa_methods
         SET enabled = true,
             verified_at = COALESCE(verified_at, now()),
             recovery_code_hashes = $3::jsonb,
             last_used_step = CASE WHEN $4::bigint IS NULL THEN last_used_step ELSE $4::bigint END,
             updated_at = now()
         WHERE tenant_id = $1 AND user_id = $2 AND method = 'totp'`,
        [
          account.tenant_id,
          account.user_id,
          JSON.stringify(recoveryHashes),
          verification.type === 'totp' ? verification.step : null,
        ],
      )
      await client.query('UPDATE auth_mfa_challenges SET used_at = now() WHERE id = $1', [account.challenge_id])

      const ttl = sessionTtlSeconds(account)
      const token = await createSession(client, {
        tenantId: account.tenant_id,
        userId: account.user_id,
        mfaVerified: true,
        ttlSeconds: ttl,
      })
      return {
        ok: true,
        token,
        ttl,
        payload: sessionPayload({ ...account, mfa_verified_at: new Date().toISOString() }),
        recoveryCodes,
      }
    })

    if (!result.ok) return c.json({ error: result.error }, result.status)
    setSessionCookie(c, result.token, result.ttl)
    return c.json({ ...result.payload, recoveryCodes: result.recoveryCodes })
  })

  app.get('/api/v1/mfa/status', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const method = await enabledMethod(pool, auth.session.tenant_id, auth.session.user_id)
    return c.json(methodStatus(auth.session, method))
  })

  app.post('/api/v1/mfa/setup', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    try {
      const result = await withTransaction(async (client) => {
        const method = await enabledMethod(client, auth.session.tenant_id, auth.session.user_id)
        if (method?.enabled) {
          const error = new Error('MFA is already enrolled for this account.')
          error.status = 409
          throw error
        }
        const secret = await provisionSecret(client, auth.session.tenant_id, auth.session.user_id)
        const setupToken = await createChallenge(client, auth.session.tenant_id, auth.session.user_id, 'setup')
        return {
          secret,
          setupToken,
          uri: otpauthUri({ secret, companyName: auth.session.company_name, email: auth.session.email }),
        }
      })
      return c.json({
        secret: result.secret,
        setupToken: result.setupToken,
        otpauthUri: result.uri,
        issuer: 'Hi5Central',
        account: `${auth.session.company_name}:${auth.session.email}`,
      })
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/mfa/confirm', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const setupToken = String(body?.setupToken || '')
    const code = text(body?.code, 32)
    if (!setupToken || !code) return c.json({ error: 'Enter the six-digit authenticator code.' }, 400)

    const result = await withTransaction(async (client) => {
      const challenge = await challengeAccount(client, setupToken, 'setup', true)
      if (!challenge
        || challenge.tenant_id !== auth.session.tenant_id
        || challenge.user_id !== auth.session.user_id) {
        return { ok: false, status: 401, error: 'This MFA setup has expired. Start setup again.' }
      }
      const method = await enabledMethod(client, auth.session.tenant_id, auth.session.user_id)
      if (!method) return { ok: false, status: 409, error: 'Start MFA setup again.' }

      const verification = verifyMethodCode(method, code, { allowRecovery: false })
      if (!verification.ok || verification.type !== 'totp') {
        await client.query('UPDATE auth_mfa_challenges SET attempts = attempts + 1 WHERE id = $1', [challenge.challenge_id])
        return { ok: false, status: 401, error: 'That authenticator code is not valid.' }
      }

      const generated = createRecoveryCodes()
      await client.query(
        `UPDATE user_mfa_methods
         SET enabled = true,
             verified_at = now(),
             recovery_code_hashes = $3::jsonb,
             last_used_step = $4,
             updated_at = now()
         WHERE tenant_id = $1 AND user_id = $2 AND method = 'totp'`,
        [auth.session.tenant_id, auth.session.user_id, JSON.stringify(generated.hashes), verification.step],
      )
      await client.query('UPDATE auth_mfa_challenges SET used_at = now() WHERE id = $1', [challenge.challenge_id])
      await client.query('UPDATE auth_sessions SET mfa_verified_at = now() WHERE id = $1', [auth.session.session_id])
      return { ok: true, recoveryCodes: generated.codes }
    })

    if (!result.ok) return c.json({ error: result.error }, result.status)
    const refreshedMethod = await enabledMethod(pool, auth.session.tenant_id, auth.session.user_id)
    return c.json({
      ...methodStatus({ ...auth.session, mfa_verified_at: new Date().toISOString() }, refreshedMethod),
      recoveryCodes: result.recoveryCodes,
    })
  })

  app.post('/api/v1/mfa/recovery-codes', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const code = text(body?.code, 64)
    if (!code) return c.json({ error: 'Enter your current authenticator code.' }, 400)

    const result = await withTransaction(async (client) => {
      const method = await enabledMethod(client, auth.session.tenant_id, auth.session.user_id)
      if (!method?.enabled) return { ok: false, status: 409, error: 'MFA is not enrolled.' }
      const verification = verifyMethodCode(method, code, { allowRecovery: false })
      if (!verification.ok) return { ok: false, status: 401, error: 'That authenticator code is not valid.' }
      const generated = createRecoveryCodes()
      await client.query(
        `UPDATE user_mfa_methods
         SET recovery_code_hashes = $3::jsonb,
             last_used_step = $4,
             updated_at = now()
         WHERE tenant_id = $1 AND user_id = $2 AND method = 'totp'`,
        [auth.session.tenant_id, auth.session.user_id, JSON.stringify(generated.hashes), verification.step],
      )
      return { ok: true, recoveryCodes: generated.codes }
    })
    if (!result.ok) return c.json({ error: result.error }, result.status)
    return c.json({ recoveryCodes: result.recoveryCodes })
  })

  app.post('/api/v1/mfa/disable', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    if (mfaRequiredFor(auth.session)) {
      return c.json({ error: 'This tenant requires MFA for your role. Disable the tenant policy before removing your authenticator.' }, 409)
    }

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const code = text(body?.code, 64)
    if (!code) return c.json({ error: 'Enter your authenticator or recovery code.' }, 400)

    const result = await withTransaction(async (client) => {
      const method = await enabledMethod(client, auth.session.tenant_id, auth.session.user_id)
      if (!method?.enabled) return { ok: false, status: 409, error: 'MFA is not enrolled.' }
      const verification = verifyMethodCode(method, code)
      if (!verification.ok) return { ok: false, status: 401, error: 'That MFA code is not valid.' }
      await client.query(
        `DELETE FROM user_mfa_methods
         WHERE tenant_id = $1 AND user_id = $2 AND method = 'totp'`,
        [auth.session.tenant_id, auth.session.user_id],
      )
      await client.query('UPDATE auth_sessions SET mfa_verified_at = NULL WHERE id = $1', [auth.session.session_id])
      return { ok: true }
    })
    if (!result.ok) return c.json({ error: result.error }, result.status)
    return c.json({ disabled: true })
  })
}
