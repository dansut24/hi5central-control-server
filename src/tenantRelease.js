import { pool } from './db.js'
import { deployment, originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'
import { recordSecurityEvent, requestIp, requestUserAgent } from './securityAudit.js'

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function preferencePayload(row) {
  return {
    tenantId: row.tenant_id,
    updateMode: row.update_mode,
    managedByHi5Central: row.update_mode === 'hi5_managed',
    testAutoSync: Boolean(row.test_auto_sync),
    uatAutoStage: Boolean(row.uat_auto_stage),
    liveAutoPromote: Boolean(row.live_auto_promote),
    liveDelayHours: Number(row.live_delay_hours || 0),
    allowEmergencySecurityUpdates: Boolean(row.allow_emergency_security_updates),
    maintenanceWindow: object(row.maintenance_window),
    updatedAt: row.updated_at,
  }
}

function environmentPayload(row) {
  return {
    environment: row.environment,
    status: row.status,
    activeReleaseRef: row.active_release_ref || '',
    lastResetAt: row.last_reset_at,
    lastDeployedAt: row.last_deployed_at,
    updatedAt: row.updated_at,
  }
}

async function requireTenantAdmin(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!['owner','admin'].includes(session.tenant_role)) {
    return { error: c.json({ error: 'Organisation administrator access is required.' }, 403) }
  }
  return { session }
}

async function ensurePreference(tenantId) {
  await pool.query(
    `INSERT INTO tenant_release_preferences (tenant_id)
     VALUES ($1)
     ON CONFLICT (tenant_id) DO NOTHING`,
    [tenantId],
  )
  await pool.query(
    `INSERT INTO tenant_environment_state (tenant_id,environment,status)
     VALUES ($1,'test','available'),($1,'uat','available'),($1,'live','ready')
     ON CONFLICT (tenant_id,environment) DO NOTHING`,
    [tenantId],
  )
}

export async function tenantReleaseState(tenantId) {
  await ensurePreference(tenantId)
  const [preference, environments] = await Promise.all([
    pool.query('SELECT * FROM tenant_release_preferences WHERE tenant_id=$1', [tenantId]),
    pool.query(
      `SELECT * FROM tenant_environment_state
       WHERE tenant_id=$1
       ORDER BY CASE environment WHEN 'test' THEN 1 WHEN 'uat' THEN 2 ELSE 3 END`,
      [tenantId],
    ),
  ])
  return {
    preference: preferencePayload(preference.rows[0]),
    environments: environments.rows.map(environmentPayload),
  }
}

export function registerTenantReleaseRoutes(app) {
  app.get('/api/v1/release-management', async (c) => {
    const auth = await requireTenantAdmin(c)
    if (auth.error) return auth.error
    const state = await tenantReleaseState(auth.session.tenant_id)
    return c.json({
      deploymentMode: deployment.deploymentMode,
      edition: deployment.deploymentMode === 'managed' ? 'managed' : deployment.selfHostEdition,
      ...state,
    })
  })

  app.patch('/api/v1/release-management/preferences', async (c) => {
    const auth = await requireTenantAdmin(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const updateMode = String(body?.updateMode || '').trim().toLowerCase()
    if (!['admin_controlled','hi5_managed'].includes(updateMode)) {
      return c.json({ error: 'updateMode must be admin_controlled or hi5_managed.' }, 400)
    }

    const delay = body?.liveDelayHours == null ? 24 : Math.floor(Number(body.liveDelayHours))
    if (!Number.isFinite(delay) || delay < 0 || delay > 720) {
      return c.json({ error: 'liveDelayHours must be between 0 and 720.' }, 400)
    }

    const maintenanceWindow = object(body?.maintenanceWindow)
    const modeDefaults = updateMode === 'hi5_managed'
      ? { uatAutoStage: true, liveAutoPromote: true }
      : { uatAutoStage: false, liveAutoPromote: false }

    await ensurePreference(auth.session.tenant_id)
    const result = await pool.query(
      `UPDATE tenant_release_preferences SET
         update_mode=$2,
         test_auto_sync=true,
         uat_auto_stage=$3,
         live_auto_promote=$4,
         live_delay_hours=$5,
         allow_emergency_security_updates=$6,
         maintenance_window=CASE WHEN $7::jsonb='{}'::jsonb THEN maintenance_window ELSE $7::jsonb END,
         updated_by=$8,
         updated_at=now()
       WHERE tenant_id=$1
       RETURNING *`,
      [
        auth.session.tenant_id,
        updateMode,
        modeDefaults.uatAutoStage,
        modeDefaults.liveAutoPromote,
        delay,
        body?.allowEmergencySecurityUpdates !== false,
        JSON.stringify(maintenanceWindow),
        auth.session.user_id,
      ],
    )

    await recordSecurityEvent({
      tenantId: auth.session.tenant_id,
      actorUserId: auth.session.user_id,
      sessionId: auth.session.session_id || null,
      eventType: 'release.preferences_updated',
      ipAddress: requestIp(c),
      userAgent: requestUserAgent(c),
      metadata: {
        updateMode,
        liveDelayHours: delay,
        allowEmergencySecurityUpdates: body?.allowEmergencySecurityUpdates !== false,
      },
    })

    return c.json({ preference: preferencePayload(result.rows[0]) })
  })
}
