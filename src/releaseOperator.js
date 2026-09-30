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

function actionPayload(row) {
  if (!row) return null
  return {
    id: row.id,
    environment: row.environment,
    action: row.action,
    status: row.status,
    payload: row.payload || {},
    requestedAt: row.requested_at,
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
      const claimed = await db.query(
        `WITH next_action AS (
           SELECT id
             FROM platform_environment_actions
            WHERE status='requested'
            ORDER BY requested_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         UPDATE platform_environment_actions a
            SET status='running',started_at=now(),error_message=''
           FROM next_action n
          WHERE a.id=n.id
         RETURNING a.*`,
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
        if (current.action === 'reset' && current.environment === 'test') {
          await db.query(
            `UPDATE platform_environment_state
                SET last_reset_at=now(),last_deployed_at=now(),
                    active_release_ref=COALESCE(NULLIF($1,''),active_release_ref),updated_at=now()
              WHERE environment='test'`,
            [releaseRef],
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
          if (changeIds.length) {
            const featureRows = await db.query(
              `SELECT id,feature_key FROM platform_release_changes
                WHERE id=ANY($1::uuid[])`,
              [changeIds],
            )
            for (const change of featureRows.rows) {
              if (!change.feature_key) continue
              await db.query(
                `INSERT INTO platform_environment_feature_flags
                  (environment,feature_key,enabled,updated_by)
                 VALUES ($1,$2,true,$3)
                 ON CONFLICT (environment,feature_key) DO UPDATE
                 SET enabled=true,updated_by=EXCLUDED.updated_by,updated_at=now()`,
                [current.environment,change.feature_key,current.requested_by],
              )
            }
            if (current.environment === 'live') {
              await db.query(
                `UPDATE platform_release_changes
                    SET state='promoted',promoted_at=now(),updated_at=now()
                  WHERE id=ANY($1::uuid[]) AND state='selected_for_live'`,
                [changeIds],
              )
            }
          }
        }
      }
      return { action: updated.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'Environment action not found.' }, 404)
    if (result.conflict) return c.json({ error: `Environment action is ${result.conflict}, not running.` }, 409)
    return c.json({ action: actionPayload(result.action) })
  })
}
