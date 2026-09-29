import { hasPermission } from './access.js'
import { createHash, randomBytes } from 'node:crypto'
import { pool, withTransaction } from './db.js'
import { sendPasswordResetEmail } from './mailer.js'
import { hashPassword, passwordPolicyResult, verifyPassword } from './password.js'
import { ensureRedisConnected } from './redis.js'
import {
  pruneSecurityAuditForTenant,
  recordSecurityEvent,
  requestIp,
  requestUserAgent,
  startSecurityAuditMaintenance,
} from './securityAudit.js'
import { securitySettings } from './securityPolicy.js'
import { resolveSession } from './session.js'
import { originMatchesTenant as deploymentOriginMatchesTenant } from './deploymentConfig.js'

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

function originMatchesTenant(c, slug) {
  return deploymentOriginMatchesTenant(c.req.header('origin'), slug)
}

async function requireSession(c, permission = null) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c, session.slug)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (permission && !hasPermission(session.access, permission)) {
    return { error: c.json({ error: 'You do not have permission to view this tenant security information.', permission }, 403) }
  }
  return { session }
}

async function rateLimit(key, max, seconds) {
  const redis = await ensureRedisConnected()
  const count = await redis.incr(key)
  if (count === 1) await redis.expire(key, seconds)
  return count <= max
}

async function passwordRow(db, tenantId, userId) {
  const result = await db.query(
    `SELECT u.id, u.email, u.name, u.password_hash, u.password_changed_at,
            t.slug, t.company_name, t.status AS tenant_status,
            m.role AS tenant_role, m.status AS membership_status,
            ts.configuration, ts.onboarding_data, ts.tenant_url
     FROM users u
     JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = $1
     JOIN tenants t ON t.id = m.tenant_id
     JOIN tenant_settings ts ON ts.tenant_id = m.tenant_id
     WHERE u.id = $2
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

function sessionPayload(row, currentSessionId) {
  return {
    id: row.id,
    current: row.id === currentSessionId,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    mfaVerified: Boolean(row.mfa_verified_at),
    ipAddress: row.ip_address || null,
    userAgent: row.user_agent || null,
    revokedAt: row.revoked_at || null,
    revokedReason: row.revoked_reason || null,
  }
}

async function revokeOtherSessions(db, session, reason) {
  return db.query(
    `UPDATE auth_sessions
     SET revoked_at = COALESCE(revoked_at, now()),
         revoked_reason = COALESCE(revoked_reason, $3)
     WHERE tenant_id = $1
       AND user_id = $2
       AND id <> $4
       AND revoked_at IS NULL`,
    [session.tenant_id, session.user_id, reason, session.session_id],
  )
}

export function registerSecurityRoutes(app) {
  startSecurityAuditMaintenance()

  app.get('/api/v1/security/summary', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const account = await passwordRow(pool, auth.session.tenant_id, auth.session.user_id)
    const sessions = await pool.query(
      `SELECT count(*)::int AS count
       FROM auth_sessions
       WHERE tenant_id = $1 AND user_id = $2
         AND revoked_at IS NULL AND expires_at > now()`,
      [auth.session.tenant_id, auth.session.user_id],
    )
    return c.json({
      policy: securitySettings(auth.session),
      passwordChangedAt: account?.password_changed_at || null,
      activeSessions: sessions.rows[0]?.count || 0,
      currentSession: {
        id: auth.session.session_id,
        mfaVerified: Boolean(auth.session.mfa_verified_at),
        createdAt: auth.session.session_created_at,
        expiresAt: auth.session.expires_at,
      },
    })
  })

  app.get('/api/v1/security/sessions', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id, created_at, last_seen_at, expires_at, mfa_verified_at,
              ip_address, user_agent, revoked_at, revoked_reason
       FROM auth_sessions
       WHERE tenant_id = $1 AND user_id = $2
         AND (revoked_at IS NULL OR revoked_at > now() - interval '30 days')
       ORDER BY created_at DESC
       LIMIT 100`,
      [auth.session.tenant_id, auth.session.user_id],
    )
    return c.json({ items: result.rows.map((row) => sessionPayload(row, auth.session.session_id)) })
  })

  app.post('/api/v1/security/sessions/revoke-others', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const result = await withTransaction(async (client) => {
      const revoked = await revokeOtherSessions(client, auth.session, 'user_revoked_other_sessions')
      await recordSecurityEvent({
        db: client,
        tenantId: auth.session.tenant_id,
        actorUserId: auth.session.user_id,
        sessionId: auth.session.session_id,
        eventType: 'sessions.revoked_others',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
        metadata: { revokedCount: revoked.rowCount || 0 },
      })
      return revoked.rowCount || 0
    })
    return c.json({ revoked: result })
  })

  app.post('/api/v1/security/sessions/:sessionId/revoke', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const sessionId = text(c.req.param('sessionId'), 80)
    if (sessionId === auth.session.session_id) {
      return c.json({ error: 'Use Sign out to end the current session.' }, 409)
    }
    const result = await withTransaction(async (client) => {
      const revoked = await client.query(
        `UPDATE auth_sessions
         SET revoked_at = COALESCE(revoked_at, now()),
             revoked_reason = COALESCE(revoked_reason, 'user_revoked_session')
         WHERE id = $1 AND tenant_id = $2 AND user_id = $3
           AND revoked_at IS NULL
         RETURNING id`,
        [sessionId, auth.session.tenant_id, auth.session.user_id],
      )
      if (revoked.rowCount) {
        await recordSecurityEvent({
          db: client,
          tenantId: auth.session.tenant_id,
          actorUserId: auth.session.user_id,
          sessionId: auth.session.session_id,
          eventType: 'session.revoked',
          ipAddress: requestIp(c),
          userAgent: requestUserAgent(c),
          metadata: { revokedSessionId: sessionId },
        })
      }
      return Boolean(revoked.rowCount)
    })
    if (!result) return c.json({ error: 'Session not found or already ended.' }, 404)
    return c.json({ revoked: true })
  })

  app.post('/api/v1/security/password/change', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const currentPassword = String(body?.currentPassword || '')
    const newPassword = String(body?.newPassword || '')

    const account = await passwordRow(pool, auth.session.tenant_id, auth.session.user_id)
    if (!account) return c.json({ error: 'Account not found.' }, 404)
    if (!await verifyPassword(currentPassword, account.password_hash)) {
      await recordSecurityEvent({
        tenantId: auth.session.tenant_id,
        actorUserId: auth.session.user_id,
        sessionId: auth.session.session_id,
        eventType: 'password.change',
        outcome: 'failure',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
        metadata: { reason: 'current_password_invalid' },
      })
      return c.json({ error: 'Current password is incorrect.' }, 401)
    }
    if (await verifyPassword(newPassword, account.password_hash)) {
      return c.json({ error: 'Choose a password different from your current password.' }, 400)
    }

    const policy = securitySettings(auth.session).passwordPolicy
    const validation = passwordPolicyResult(newPassword, policy)
    if (!validation.ok) return c.json({ error: validation.message, policy }, 400)
    const newHash = await hashPassword(newPassword)

    await withTransaction(async (client) => {
      await client.query(
        `UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1`,
        [auth.session.user_id, newHash],
      )
      await revokeOtherSessions(client, auth.session, 'password_changed')
      await client.query(
        `UPDATE password_reset_tokens SET used_at = COALESCE(used_at, now())
         WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
        [auth.session.tenant_id, auth.session.user_id],
      )
      await recordSecurityEvent({
        db: client,
        tenantId: auth.session.tenant_id,
        actorUserId: auth.session.user_id,
        sessionId: auth.session.session_id,
        eventType: 'password.changed',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
        metadata: { policy },
      })
    })
    return c.json({ changed: true, otherSessionsRevoked: true })
  })

  app.post('/api/v1/security/mfa/remove', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const policy = securitySettings(auth.session)
    if (policy.requireMfa && ['owner', 'admin'].includes(auth.session.tenant_role)) {
      return c.json({ error: 'Disable the administrator MFA requirement before removing your authenticator.' }, 409)
    }
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const account = await passwordRow(pool, auth.session.tenant_id, auth.session.user_id)
    if (!account || !await verifyPassword(String(body?.password || ''), account.password_hash)) {
      return c.json({ error: 'Password confirmation is incorrect.' }, 401)
    }

    await withTransaction(async (client) => {
      await client.query('DELETE FROM user_mfa_methods WHERE tenant_id = $1 AND user_id = $2', [auth.session.tenant_id, auth.session.user_id])
      await client.query('DELETE FROM auth_mfa_challenges WHERE tenant_id = $1 AND user_id = $2', [auth.session.tenant_id, auth.session.user_id])
      await client.query('UPDATE auth_sessions SET mfa_verified_at = NULL WHERE id = $1', [auth.session.session_id])
      await revokeOtherSessions(client, auth.session, 'mfa_removed')
      await recordSecurityEvent({
        db: client,
        tenantId: auth.session.tenant_id,
        actorUserId: auth.session.user_id,
        sessionId: auth.session.session_id,
        eventType: 'mfa.removed',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
      })
    })
    return c.json({ removed: true })
  })

  app.get('/api/v1/security/audit', async (c) => {
    const auth = await requireSession(c, 'settings.security.manage')
    if (auth.error) return auth.error
    const limit = Math.max(20, Math.min(200, Number(c.req.query('limit') || 60)))
    await pruneSecurityAuditForTenant(auth.session.tenant_id, securitySettings(auth.session).auditRetention)
    const result = await pool.query(
      `SELECT e.id, e.event_type, e.outcome, e.ip_address, e.user_agent,
              e.metadata, e.created_at,
              u.name AS actor_name, u.email AS actor_email
       FROM security_audit_events e
       LEFT JOIN users u ON u.id = e.actor_user_id
       WHERE e.tenant_id = $1
       ORDER BY e.created_at DESC
       LIMIT $2`,
      [auth.session.tenant_id, limit],
    )
    return c.json({
      retentionDays: Number(securitySettings(auth.session).auditRetention),
      items: result.rows.map((row) => ({
        id: row.id,
        type: row.event_type,
        outcome: row.outcome,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        metadata: row.metadata || {},
        actor: row.actor_name || row.actor_email || 'System',
        actorEmail: row.actor_email || null,
        createdAt: row.created_at,
      })),
    })
  })

  app.post('/api/v1/auth/password/forgot', async (c) => {
    let body
    try { body = await c.req.json() } catch { return c.json({ status: 'accepted' }) }
    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const email = normaliseEmail(body?.email)
    const generic = { status: 'accepted', message: 'If that account exists, a password reset email has been sent.' }
    if (!validSlug(tenantSlug) || !validEmail(email) || !originMatchesTenant(c, tenantSlug)) return c.json(generic)
    const allowed = await rateLimit(`password-reset:${requestIp(c)}:${tenantSlug}:${email}`, 5, 900)
    if (!allowed) return c.json(generic)

    const result = await pool.query(
      `SELECT t.id AS tenant_id, t.slug, t.company_name, t.status AS tenant_status,
              u.id AS user_id, u.email, u.name,
              m.status AS membership_status, ts.tenant_url
       FROM tenants t
       JOIN tenant_memberships m ON m.tenant_id = t.id
       JOIN users u ON u.id = m.user_id
       JOIN tenant_settings ts ON ts.tenant_id = t.id
       WHERE t.slug = $1 AND u.email = $2
       LIMIT 1`,
      [tenantSlug, email],
    )
    const account = result.rows[0]
    if (!account || account.tenant_status !== 'active' || account.membership_status !== 'active') return c.json(generic)

    const token = randomBytes(32).toString('base64url')
    await withTransaction(async (client) => {
      await client.query(
        `UPDATE password_reset_tokens SET used_at = COALESCE(used_at, now())
         WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
        [account.tenant_id, account.user_id],
      )
      await client.query(
        `INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at)
         VALUES ($1,$2,$3,now() + interval '60 minutes')`,
        [account.tenant_id, account.user_id, hashToken(token)],
      )
      await recordSecurityEvent({
        db: client,
        tenantId: account.tenant_id,
        actorUserId: account.user_id,
        eventType: 'password.reset_requested',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
      })
    })

    try {
      await sendPasswordResetEmail({
        to: account.email,
        name: account.name,
        companyName: account.company_name,
        token,
        tenantUrl: account.tenant_url,
      })
    } catch (error) {
      console.error('Password reset email delivery failed', error)
    }
    return c.json(generic)
  })

  app.post('/api/v1/auth/password/reset', async (c) => {
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const token = String(body?.token || '')
    const newPassword = String(body?.newPassword || '')
    if (!validSlug(tenantSlug) || token.length < 20 || !originMatchesTenant(c, tenantSlug)) {
      return c.json({ error: 'This password reset link is invalid or has expired.' }, 400)
    }

    try {
      const result = await withTransaction(async (client) => {
        const resetResult = await client.query(
          `SELECT r.id AS reset_id, r.tenant_id, r.user_id,
                  t.slug, t.status AS tenant_status,
                  m.status AS membership_status,
                  ts.configuration, ts.onboarding_data
           FROM password_reset_tokens r
           JOIN tenants t ON t.id = r.tenant_id
           JOIN tenant_memberships m ON m.tenant_id = r.tenant_id AND m.user_id = r.user_id
           JOIN tenant_settings ts ON ts.tenant_id = r.tenant_id
           WHERE r.token_hash = $1 AND t.slug = $2
             AND r.used_at IS NULL AND r.expires_at > now()
           LIMIT 1 FOR UPDATE OF r`,
          [hashToken(token), tenantSlug],
        )
        const reset = resetResult.rows[0]
        if (!reset || reset.tenant_status !== 'active' || reset.membership_status !== 'active') {
          const error = new Error('This password reset link is invalid or has expired.')
          error.status = 400
          throw error
        }
        const policy = securitySettings(reset).passwordPolicy
        const validation = passwordPolicyResult(newPassword, policy)
        if (!validation.ok) {
          const error = new Error(validation.message)
          error.status = 400
          throw error
        }
        const newHash = await hashPassword(newPassword)
        await client.query(
          `UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1`,
          [reset.user_id, newHash],
        )
        await client.query('UPDATE password_reset_tokens SET used_at = now() WHERE id = $1', [reset.reset_id])
        await client.query(
          `UPDATE auth_sessions
           SET revoked_at = COALESCE(revoked_at, now()), revoked_reason = COALESCE(revoked_reason, 'password_reset')
           WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
          [reset.tenant_id, reset.user_id],
        )
        await recordSecurityEvent({
          db: client,
          tenantId: reset.tenant_id,
          actorUserId: reset.user_id,
          eventType: 'password.reset_completed',
          ipAddress: requestIp(c),
          userAgent: requestUserAgent(c),
          metadata: { policy },
        })
        return { policy }
      })
      return c.json({ changed: true, policy: result.policy })
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })
}
