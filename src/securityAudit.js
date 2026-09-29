import { pool } from './db.js'
import { securitySettings } from './securityPolicy.js'

function text(value, max = 500) {
  return String(value ?? '').trim().slice(0, max)
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

export function requestIp(c) {
  const forwarded = c?.req?.header?.('x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0].trim().slice(0, 120)
  return String(c?.req?.header?.('x-real-ip') || 'unknown').slice(0, 120)
}

export function requestUserAgent(c) {
  return String(c?.req?.header?.('user-agent') || 'unknown').slice(0, 1000)
}

export async function recordSecurityEvent({
  db = pool,
  tenantId,
  actorUserId = null,
  sessionId = null,
  eventType,
  outcome = 'success',
  ipAddress = null,
  userAgent = null,
  metadata = {},
}) {
  if (!tenantId || !eventType) return null
  const result = await db.query(
    `INSERT INTO security_audit_events (
       tenant_id, actor_user_id, session_id, event_type, outcome,
       ip_address, user_agent, metadata
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
     RETURNING id, created_at`,
    [
      tenantId,
      actorUserId,
      sessionId,
      text(eventType, 160),
      ['success', 'failure', 'blocked'].includes(outcome) ? outcome : 'success',
      ipAddress ? text(ipAddress, 120) : null,
      userAgent ? text(userAgent, 1000) : null,
      JSON.stringify(asObject(metadata)),
    ],
  )
  return result.rows[0] || null
}

export async function pruneSecurityAuditForTenant(tenantId, retentionDays = null, db = pool) {
  if (!tenantId) return 0
  let days = Number(retentionDays)
  if (![90, 365, 730].includes(days)) {
    const result = await db.query(
      `SELECT configuration, onboarding_data
       FROM tenant_settings
       WHERE tenant_id = $1
       LIMIT 1`,
      [tenantId],
    )
    days = Number(securitySettings(result.rows[0] || {}).auditRetention)
  }

  if (![90, 365, 730].includes(days)) days = 365
  const deleted = await db.query(
    `DELETE FROM security_audit_events
     WHERE tenant_id = $1
       AND created_at < now() - make_interval(days => $2::int)`,
    [tenantId, days],
  )
  return deleted.rowCount || 0
}

let maintenanceStarted = false

export function startSecurityAuditMaintenance() {
  if (maintenanceStarted) return
  maintenanceStarted = true

  const run = async () => {
    try {
      const tenants = await pool.query('SELECT tenant_id, configuration, onboarding_data FROM tenant_settings')
      for (const row of tenants.rows) {
        const days = Number(securitySettings(row).auditRetention)
        await pruneSecurityAuditForTenant(row.tenant_id, days)
      }
      await pool.query(`DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL OR expires_at < now() - interval '1 day'`)
      await pool.query(`DELETE FROM auth_mfa_challenges WHERE used_at IS NOT NULL OR expires_at < now() - interval '1 day'`)
    } catch (error) {
      console.error('Security retention maintenance failed', error)
    }
  }

  run().catch(() => {})
  const timer = setInterval(run, 6 * 60 * 60 * 1000)
  timer.unref?.()
}
