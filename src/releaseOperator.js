import { createHash, timingSafeEqual } from 'node:crypto'
import { pool, withTransaction } from './db.js'
import { deployment } from './deploymentConfig.js'

function configuredToken() {
  return String(process.env.RELEASE_OPERATOR_TOKEN || '').trim()
}

function authorised(c) {
  const expected = configuredToken()
  if (expected.length < 32) return false
  const header = String(c.req.header('authorization') || '')
  const supplied = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
  if (!supplied) return false
  const left = Buffer.from(createHash('sha256').update(supplied).digest('hex'))
  const right = Buffer.from(createHash('sha256').update(expected).digest('hex'))
  return left.length === right.length && timingSafeEqual(left, right)
}

function requireOperator(c) {
  if (configuredToken().length < 32) {
    return c.json({ error: 'Release operator is not configured.', code: 'RELEASE_OPERATOR_UNAVAILABLE' }, 503)
  }
  if (!authorised(c)) return c.json({ error: 'Release operator authentication required.' }, 401)
  return null
}



function localWindowParts(timeZone, date = new Date()) {
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    }).formatToParts(date)
    return Object.fromEntries(parts.map((part) => [part.type, part.value]))
  } catch {
    return localWindowParts('UTC', date)
  }
}

function minuteOfDay(value, fallback) {
  const match = String(value || '').match(/^(\d{2}):(\d{2})$/)
  if (!match) return fallback
  const hour = Number(match[1])
  const minute = Number(match[2])
  if (hour > 23 || minute > 59) return fallback
  return hour * 60 + minute
}

function withinMaintenanceWindow(windowValue, now = new Date()) {
  const window = windowValue && typeof windowValue === 'object' && !Array.isArray(windowValue) ? windowValue : {}
  const timeZone = String(window.timezone || 'UTC')
  const local = localWindowParts(timeZone, now)
  const weekday = String(local.weekday || '').toLowerCase().slice(0,3)
  const configuredDays = Array.isArray(window.days)
    ? window.days.map((day) => String(day).toLowerCase().slice(0,3)).filter(Boolean)
    : []
  if (configuredDays.length && !configuredDays.includes(weekday)) return false
  const current = Number(local.hour || 0) * 60 + Number(local.minute || 0)
  const start = minuteOfDay(window.start, 0)
  const end = minuteOfDay(window.end, 24 * 60 - 1)
  if (start === end) return true
  return start < end ? current >= start && current < end : current >= start || current < end
}

async function queueManagedPromotion(db, { fromEnvironment, toEnvironment, releaseRef, changeIds, notBefore = null }) {
  const existing = await db.query(
    `SELECT id FROM platform_release_promotions
      WHERE from_environment=$1 AND to_environment=$2 AND release_ref=$3
        AND status IN ('requested','running','succeeded')
      LIMIT 1`,
    [fromEnvironment,toEnvironment,releaseRef],
  )
  if (existing.rowCount) return existing.rows[0].id

  const promotion = await db.query(
    `INSERT INTO platform_release_promotions
      (from_environment,to_environment,status,release_ref)
     VALUES ($1,$2,'requested',$3)
     RETURNING id`,
    [fromEnvironment,toEnvironment,releaseRef],
  )
  for (const changeId of changeIds) {
    await db.query(
      'INSERT INTO platform_release_promotion_items (promotion_id,change_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [promotion.rows[0].id,changeId],
    )
  }
  await db.query(
    `INSERT INTO platform_environment_actions
      (environment,action,payload,not_before)
     VALUES ($1,'promote',$2::jsonb,COALESCE($3::timestamptz,now()))`,
    [
      toEnvironment,
      JSON.stringify({ promotionId: promotion.rows[0].id, changeIds, releaseRef, source: 'hi5-managed-policy' }),
      notBefore,
    ],
  )
  return promotion.rows[0].id
}

async function applyManagedTenantFeatureActivation(db, environment, changeIds) {
  if (!changeIds.length || !['uat','live'].includes(environment)) return
  const featureRows = await db.query(
    `SELECT feature_key FROM platform_release_changes
      WHERE id=ANY($1::uuid[]) AND feature_key IS NOT NULL`,
    [changeIds],
  )
  if (!featureRows.rowCount) return
  const tenants = await db.query(
    `SELECT tenant_id FROM tenant_release_preferences
      WHERE update_mode='hi5_managed'`,
  )
  for (const tenant of tenants.rows) {
    for (const change of featureRows.rows) {
      await db.query(
        `INSERT INTO tenant_environment_feature_overrides
          (tenant_id,environment,feature_key,enabled)
         VALUES ($1,$2,$3,true)
         ON CONFLICT (tenant_id,environment,feature_key) DO UPDATE
         SET enabled=true,updated_at=now()`,
        [tenant.tenant_id,environment,change.feature_key],
      )
    }
  }
}

async function continueManagedReleaseFlow(db, current, releaseRef, changeIds) {
  const preferenceResult = await db.query(
    `SELECT * FROM platform_release_preferences WHERE preference_key='deployment' LIMIT 1`,
  )
  const preference = preferenceResult.rows[0]
  if (!preference || preference.update_mode !== 'hi5_managed') return

  if (current.environment === 'test' && current.action === 'deploy') {
    if (changeIds.length) {
      await db.query(
        `INSERT INTO platform_release_test_results
          (change_id,environment,result,notes,evidence)
         SELECT id,'test','passed','Automated Hi5Central health gate passed.',
                jsonb_build_object('source','hi5-managed-policy','releaseRef',$2::text)
           FROM platform_release_changes
          WHERE id=ANY($1::uuid[])`,
        [changeIds,releaseRef],
      )
      await db.query(
        `UPDATE platform_release_changes
            SET state='ready_for_uat',updated_at=now()
          WHERE id=ANY($1::uuid[]) AND state<>'promoted'`,
        [changeIds],
      )
    }
    if (preference.uat_auto_stage) {
      await queueManagedPromotion(db, {
        fromEnvironment: 'test',
        toEnvironment: 'uat',
        releaseRef,
        changeIds,
      })
    }
    return
  }

  if (current.environment === 'uat' && current.action === 'promote') {
    if (changeIds.length) {
      await db.query(
        `INSERT INTO platform_release_test_results
          (change_id,environment,result,notes,evidence)
         SELECT id,'uat','passed','Automated Hi5Central UAT health gate passed.',
                jsonb_build_object('source','hi5-managed-policy','releaseRef',$2::text)
           FROM platform_release_changes
          WHERE id=ANY($1::uuid[])`,
        [changeIds,releaseRef],
      )
      await db.query(
        `UPDATE platform_release_changes
            SET state='selected_for_live',updated_at=now()
          WHERE id=ANY($1::uuid[]) AND state<>'promoted'`,
        [changeIds],
      )
    }
    if (preference.live_auto_promote) {
      const delayHours = Math.max(0, Math.min(720, Number(preference.live_delay_hours || 0)))
      const notBefore = new Date(Date.now() + delayHours * 60 * 60 * 1000).toISOString()
      await queueManagedPromotion(db, {
        fromEnvironment: 'uat',
        toEnvironment: 'live',
        releaseRef,
        changeIds,
        notBefore,
      })
    }
  }
}

function actionPayload(row) {
  if (!row) return null
  return {
    id: row.id,
    environment: row.environment,
    action: row.action,
    status: row.status,
    payload: row.payload || {},
    requestedAt: row.requested_at,
    notBefore: row.not_before,
    startedAt: row.started_at,
  }
}

export function registerReleaseOperatorRoutes(app) {
  app.get('/api/platform-operator/v1/health', (c) => {
    const denied = requireOperator(c)
    if (denied) return denied
    return c.json({
      ok: true,
      environment: deployment.runtimeEnvironment,
      operatorConfigured: true,
    })
  })

  app.post('/api/platform-operator/v1/actions/claim', async (c) => {
    const denied = requireOperator(c)
    if (denied) return denied
    const result = await withTransaction(async (db) => {
      const next = await db.query(
        `SELECT *
           FROM platform_environment_actions
          WHERE status='requested' AND not_before<=now()
          ORDER BY not_before,requested_at
          FOR UPDATE SKIP LOCKED
          LIMIT 1`,
      )
      const candidate = next.rows[0]
      if (!candidate) return null

      if (candidate.action === 'promote' && candidate.environment === 'live') {
        const preference = await db.query(
          `SELECT update_mode,maintenance_window
             FROM platform_release_preferences
            WHERE preference_key='deployment'
            LIMIT 1`,
        )
        const policy = preference.rows[0]
        if (policy?.update_mode === 'hi5_managed' && !withinMaintenanceWindow(policy.maintenance_window)) {
          return null
        }
      }

      const claimed = await db.query(
        `UPDATE platform_environment_actions
            SET status='running',started_at=now(),error_message=''
          WHERE id=$1 AND status='requested'
          RETURNING *`,
        [candidate.id],
      )
      const row = claimed.rows[0]
      if (!row) return null
      if (row.action === 'promote') {
        const promotionId = String(row.payload?.promotionId || '')
        if (promotionId) {
          await db.query(
            `UPDATE platform_release_promotions
                SET status='running',started_at=COALESCE(started_at,now()),error_message=''
              WHERE id=$1 AND status='requested'`,
            [promotionId],
          )
        }
      }
      return row
    })
    return c.json({ action: actionPayload(result) })
  })

  app.post('/api/platform-operator/v1/actions/:id/complete', async (c) => {
    const denied = requireOperator(c)
    if (denied) return denied
    const id = String(c.req.param('id') || '').trim()
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const status = String(body?.status || '').trim().toLowerCase()
    if (!['succeeded','failed'].includes(status)) {
      return c.json({ error: 'status must be succeeded or failed.' }, 400)
    }
    const errorMessage = String(body?.errorMessage || '').trim().slice(0, 4000)
    const details = body?.details && typeof body.details === 'object' && !Array.isArray(body.details) ? body.details : {}
    const releaseRef = String(body?.releaseRef || '').trim().slice(0, 300)

    const result = await withTransaction(async (db) => {
      const currentResult = await db.query(
        'SELECT * FROM platform_environment_actions WHERE id=$1 FOR UPDATE',
        [id],
      )
      if (!currentResult.rowCount) return { notFound: true }
      const current = currentResult.rows[0]
      if (current.status !== 'running') return { conflict: current.status }

      const mergedPayload = { ...(current.payload || {}), operatorResult: details }
      const updated = await db.query(
        `UPDATE platform_environment_actions
            SET status=$2,completed_at=now(),error_message=$3,payload=$4::jsonb
          WHERE id=$1
          RETURNING *`,
        [id,status,errorMessage,JSON.stringify(mergedPayload)],
      )

      const promotionId = String(current.payload?.promotionId || '')
      if (current.action === 'promote' && promotionId) {
        await db.query(
          `UPDATE platform_release_promotions
              SET status=$2,completed_at=now(),error_message=$3,
                  artifact_manifest=CASE WHEN $2='succeeded' THEN $4::jsonb ELSE artifact_manifest END
            WHERE id=$1`,
          [promotionId,status,errorMessage,JSON.stringify(details?.manifest || {})],
        )
      }

      if (status === 'succeeded') {
        if (current.environment === 'test' && ['reset','deploy'].includes(current.action)) {
          await db.query(
            `UPDATE platform_environment_state
                SET last_reset_at=CASE WHEN $2='reset' THEN now() ELSE last_reset_at END,
                    last_deployed_at=now(),
                    active_release_ref=COALESCE(NULLIF($1,''),active_release_ref),updated_at=now()
              WHERE environment='test'`,
            [releaseRef || String(current.payload?.releaseRef || ''),current.action],
          )
        }

        if (current.action === 'promote' && ['uat','live'].includes(current.environment)) {
          await db.query(
            `UPDATE platform_environment_state
                SET last_deployed_at=now(),
                    active_release_ref=COALESCE(NULLIF($2,''),active_release_ref),updated_at=now()
              WHERE environment=$1`,
            [current.environment,releaseRef || String(current.payload?.releaseRef || '')],
          )

          const changeIds = Array.isArray(current.payload?.changeIds)
            ? current.payload.changeIds.map(String).filter(Boolean)
            : []
          await applyManagedTenantFeatureActivation(db, current.environment, changeIds)
          if (changeIds.length && current.environment === 'live') {
            await db.query(
              `UPDATE platform_release_changes
                  SET state='promoted',promoted_at=now(),updated_at=now()
                WHERE id=ANY($1::uuid[]) AND state='selected_for_live'`,
              [changeIds],
            )
          }
        }

        const flowChangeIds = Array.isArray(current.payload?.changeIds)
          ? current.payload.changeIds.map(String).filter(Boolean)
          : []
        const flowReleaseRef = releaseRef || String(current.payload?.releaseRef || '')
        if ((current.action === 'deploy' && current.environment === 'test')
          || (current.action === 'promote' && current.environment === 'uat')) {
          await continueManagedReleaseFlow(db, current, flowReleaseRef, flowChangeIds)
        }
      }
      return { action: updated.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'Environment action not found.' }, 404)
    if (result.conflict) return c.json({ error: `Environment action is ${result.conflict}, not running.` }, 409)
    return c.json({ action: actionPayload(result.action) })
  })
}
