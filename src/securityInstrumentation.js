import { createHash } from 'node:crypto'
import { pool } from './db.js'
import {
  recordSecurityEvent,
  requestIp,
  requestUserAgent,
} from './securityAudit.js'
import { resolveSession } from './session.js'

function hashToken(value) {
  return createHash('sha256').update(String(value || '')).digest('hex')
}

async function clonedJsonRequest(c) {
  try {
    return await c.req.raw.clone().json()
  } catch {
    return {}
  }
}

async function clonedJsonResponse(c) {
  try {
    return await c.res.clone().json()
  } catch {
    return {}
  }
}

async function accountForLogin(slug, email) {
  if (!slug) return null
  const result = await pool.query(
    `SELECT t.id AS tenant_id, u.id AS user_id
     FROM tenants t
     LEFT JOIN tenant_memberships m ON m.tenant_id = t.id
     LEFT JOIN users u ON u.id = m.user_id AND lower(u.email) = lower($2)
     WHERE t.slug = $1
     ORDER BY CASE WHEN u.id IS NULL THEN 1 ELSE 0 END
     LIMIT 1`,
    [String(slug).toLowerCase(), String(email || '').toLowerCase()],
  )
  return result.rows[0] || null
}

async function challengeIdentity(token) {
  if (!token) return null
  const result = await pool.query(
    `SELECT tenant_id, user_id
     FROM auth_mfa_challenges
     WHERE token_hash = $1
     LIMIT 1`,
    [hashToken(token)],
  )
  return result.rows[0] || null
}

async function stampLatestSession(tenantId, userId, c) {
  if (!tenantId || !userId) return
  await pool.query(
    `UPDATE auth_sessions
     SET ip_address = $3, user_agent = $4
     WHERE id = (
       SELECT id FROM auth_sessions
       WHERE tenant_id = $1 AND user_id = $2
         AND revoked_at IS NULL AND expires_at > now()
       ORDER BY created_at DESC
       LIMIT 1
     )`,
    [tenantId, userId, requestIp(c), requestUserAgent(c)],
  )
}

export function registerSecurityInstrumentation(app) {
  app.use('/api/v1/auth/login-secure', async (c, next) => {
    const body = await clonedJsonRequest(c)
    const identity = await accountForLogin(body?.tenantSlug, body?.email).catch(() => null)
    await next()
    if (!identity?.tenant_id) return

    const payload = await clonedJsonResponse(c)
    const outcome = c.res.status >= 400 ? 'failure' : 'success'
    const eventType = payload?.mfaRequired
      ? 'login.mfa_required'
      : payload?.authenticated
        ? 'login.success'
        : 'login.failure'

    if (payload?.authenticated && identity.user_id) {
      await stampLatestSession(identity.tenant_id, identity.user_id, c).catch(() => {})
    }

    await recordSecurityEvent({
      tenantId: identity.tenant_id,
      actorUserId: identity.user_id || null,
      eventType,
      outcome,
      ipAddress: requestIp(c),
      userAgent: requestUserAgent(c),
      metadata: identity.user_id ? {} : { attemptedEmailHash: hashToken(String(body?.email || '').toLowerCase()) },
    }).catch(() => {})
  })

  app.use('/api/v1/auth/mfa/verify', async (c, next) => {
    const body = await clonedJsonRequest(c)
    const identity = await challengeIdentity(body?.challengeToken).catch(() => null)
    await next()
    if (!identity?.tenant_id) return

    const payload = await clonedJsonResponse(c)
    const success = c.res.status < 400 && payload?.authenticated
    const recovery = !/^\d{6}$/.test(String(body?.code || '').trim())

    if (success) {
      await stampLatestSession(identity.tenant_id, identity.user_id, c).catch(() => {})
    }

    await recordSecurityEvent({
      tenantId: identity.tenant_id,
      actorUserId: identity.user_id,
      eventType: success ? 'login.success' : 'mfa.challenge_failed',
      outcome: success ? 'success' : 'failure',
      ipAddress: requestIp(c),
      userAgent: requestUserAgent(c),
      metadata: success ? { factor: recovery ? 'recovery_code' : 'totp' } : {},
    }).catch(() => {})

    if (success && recovery) {
      await recordSecurityEvent({
        tenantId: identity.tenant_id,
        actorUserId: identity.user_id,
        eventType: 'mfa.recovery_code_used',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
      }).catch(() => {})
    }
  })

  app.use('/api/v1/mfa/confirm', async (c, next) => {
    const session = await resolveSession(c).catch(() => null)
    await next()
    if (!session || c.res.status >= 400) return
    await recordSecurityEvent({
      tenantId: session.tenant_id,
      actorUserId: session.user_id,
      sessionId: session.session_id,
      eventType: 'mfa.enrolled',
      ipAddress: requestIp(c),
      userAgent: requestUserAgent(c),
    }).catch(() => {})
  })

  app.use('/api/v1/mfa/recovery-codes', async (c, next) => {
    const session = await resolveSession(c).catch(() => null)
    await next()
    if (!session || c.res.status >= 400) return
    await recordSecurityEvent({
      tenantId: session.tenant_id,
      actorUserId: session.user_id,
      sessionId: session.session_id,
      eventType: 'mfa.recovery_codes_regenerated',
      ipAddress: requestIp(c),
      userAgent: requestUserAgent(c),
    }).catch(() => {})
  })
}
