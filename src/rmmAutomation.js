import { createHash, randomUUID } from 'node:crypto'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { recordRmmActivity } from './rmmActivity.js'
import { ensureBuiltinAutomations } from './rmmBuiltinAutomations.js'
import { agentSocketForDevice } from './rmmAgent.js'
import { resolveSession } from './session.js'

function clean(value = '') { return String(value ?? '').trim() }
function sha256(value = '') { return createHash('sha256').update(String(value)).digest('hex') }
function boundedInteger(value, min, max, fallback) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(number)))
}
function asObject(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function asArray(value) { return Array.isArray(value) ? value : [] }

async function requireAccess(c, permissions) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!permissions.some((permission) => hasPermission(session.access, permission))) {
    return { error: c.json({ error: 'You do not have permission to perform this RMM action.' }, 403) }
  }
  return { session }
}

async function authenticateAgent(deviceId, deviceSecret) {
  const id = clean(deviceId)
  const secret = clean(deviceSecret)
  if (!id || !secret) return null
  const result = await pool.query(
    `SELECT a.id,a.tenant_id,a.inventory_id,i.reference,i.name
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id
      WHERE a.id::text=$1 AND a.secret_hash=$2 AND a.disabled_at IS NULL
      LIMIT 1`,
    [id, sha256(secret)],
  )
  return result.rows[0] || null
}

async function automationRows(tenantId) {
  const result = await pool.query(
    `SELECT a.id,a.name,a.description,a.category,a.platform,a.language,a.status,a.published_version_id,
            a.created_at,a.updated_at,
            pv.version_number AS published_version_number,pv.content_sha256 AS published_sha256,
            pv.timeout_seconds AS published_timeout_seconds,pv.run_as AS published_run_as,pv.published_at,
            latest.id AS latest_version_id,latest.version_number AS latest_version_number,
            latest.state AS latest_version_state,latest.script_text AS latest_script_text,
            latest.content_sha256 AS latest_sha256,latest.timeout_seconds AS latest_timeout_seconds,
            latest.run_as AS latest_run_as,latest.release_notes AS latest_release_notes
       FROM rmm_automations a
       LEFT JOIN rmm_automation_versions pv ON pv.id=a.published_version_id
       LEFT JOIN LATERAL (
         SELECT v.id,v.version_number,v.state,v.script_text,v.content_sha256,v.timeout_seconds,v.run_as,v.release_notes
           FROM rmm_automation_versions v
          WHERE v.automation_id=a.id
          ORDER BY v.version_number DESC
          LIMIT 1
       ) latest ON true
      WHERE a.tenant_id=$1 AND a.status<>'archived'
      ORDER BY lower(a.name),a.created_at`,
    [tenantId],
  )
  return result.rows
}

async function trayPolicy(tenantId) {
  const policyResult = await pool.query(
    `SELECT id,name,enabled,scope_type,scope_id,priority,branding,support,created_at,updated_at
       FROM rmm_tray_policies
      WHERE tenant_id=$1 AND scope_type='tenant' AND scope_id=''
      LIMIT 1`,
    [tenantId],
  )
  const policy = policyResult.rows[0]
  if (!policy) return { enabled: false, name: 'Default tray policy', branding: {}, support: {}, actions: [] }
  const actionsResult = await pool.query(
    `SELECT ta.id,ta.automation_id,ta.automation_version_id,ta.label,ta.description,
            ta.enabled,ta.confirmation_required,ta.sort_order,a.name AS automation_name,
            v.version_number,v.content_sha256
       FROM rmm_tray_policy_actions ta
       JOIN rmm_automations a ON a.id=ta.automation_id
       JOIN rmm_automation_versions v ON v.id=ta.automation_version_id
      WHERE ta.policy_id=$1
      ORDER BY ta.sort_order,lower(ta.label)`,
    [policy.id],
  )
  return { ...policy, actions: actionsResult.rows }
}

export function registerRmmAutomationRoutes(app) {
  app.get('/api/v1/rmm/automations', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.view', 'rmm.automation.run', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    await ensureBuiltinAutomations(auth.session.tenant_id)
    return c.json({ automations: await automationRows(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/automations', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.manage'])
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    const scriptText = String(body.scriptText ?? '')
    if (name.length < 2) return c.json({ error: 'Automation name must be at least 2 characters.' }, 400)
    if (!scriptText.trim()) return c.json({ error: 'Automation script cannot be empty.' }, 400)
    if (Buffer.byteLength(scriptText, 'utf8') > 512 * 1024) return c.json({ error: 'Automation script is too large.' }, 413)
    const timeoutSeconds = boundedInteger(body.timeoutSeconds, 5, 3600, 120)
    const result = await withTransaction(async (client) => {
      const automation = await client.query(
        `INSERT INTO rmm_automations
          (tenant_id,name,description,category,platform,language,status,created_by_user_id,updated_by_user_id)
         VALUES ($1,$2,$3,$4,'windows','powershell','draft',$5,$5)
         RETURNING id`,
        [auth.session.tenant_id, name, clean(body.description).slice(0, 2000), clean(body.category).slice(0, 80) || 'General', auth.session.user_id],
      )
      const automationId = automation.rows[0].id
      await client.query(
        `INSERT INTO rmm_automation_versions
          (tenant_id,automation_id,version_number,state,script_text,content_sha256,timeout_seconds,run_as,release_notes,created_by_user_id)
         VALUES ($1,$2,1,'draft',$3,$4,$5,'system',$6,$7)`,
        [auth.session.tenant_id, automationId, scriptText, sha256(scriptText), timeoutSeconds, clean(body.releaseNotes).slice(0, 2000), auth.session.user_id],
      )
      return automationId
    })
    return c.json({ success: true, id: result }, 201)
  })

  app.patch('/api/v1/rmm/automations/:automationId', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.manage'])
    if (auth.error) return auth.error
    const automationId = clean(c.req.param('automationId'))
    const body = await c.req.json().catch(() => ({}))
    const updated = await withTransaction(async (client) => {
      const found = await client.query(
        `SELECT id,status FROM rmm_automations WHERE id=$1 AND tenant_id=$2 AND status<>'archived' FOR UPDATE`,
        [automationId, auth.session.tenant_id],
      )
      if (!found.rowCount) return false
      await client.query(
        `UPDATE rmm_automations SET
           name=COALESCE(NULLIF($3,''),name),
           description=COALESCE($4,description),
           category=COALESCE(NULLIF($5,''),category),
           updated_by_user_id=$6,updated_at=now()
         WHERE id=$1 AND tenant_id=$2`,
        [automationId, auth.session.tenant_id, clean(body.name).slice(0, 160), body.description === undefined ? null : clean(body.description).slice(0, 2000), clean(body.category).slice(0, 80), auth.session.user_id],
      )
      if (body.scriptText !== undefined) {
        const scriptText = String(body.scriptText ?? '')
        if (!scriptText.trim()) throw new Error('Automation script cannot be empty.')
        if (Buffer.byteLength(scriptText, 'utf8') > 512 * 1024) throw new Error('Automation script is too large.')
        const latest = await client.query(
          `SELECT id,version_number,state FROM rmm_automation_versions WHERE automation_id=$1 ORDER BY version_number DESC LIMIT 1 FOR UPDATE`,
          [automationId],
        )
        const timeoutSeconds = boundedInteger(body.timeoutSeconds, 5, 3600, 120)
        if (latest.rows[0]?.state === 'draft') {
          await client.query(
            `UPDATE rmm_automation_versions SET script_text=$2,content_sha256=$3,timeout_seconds=$4,run_as='system',release_notes=$5
              WHERE id=$1`,
            [latest.rows[0].id, scriptText, sha256(scriptText), timeoutSeconds, clean(body.releaseNotes).slice(0, 2000)],
          )
        } else {
          const nextVersion = Number(latest.rows[0]?.version_number || 0) + 1
          await client.query(
            `INSERT INTO rmm_automation_versions
              (tenant_id,automation_id,version_number,state,script_text,content_sha256,timeout_seconds,run_as,release_notes,created_by_user_id)
             VALUES ($1,$2,$3,'draft',$4,$5,$6,'system',$7,$8)`,
            [auth.session.tenant_id, automationId, nextVersion, scriptText, sha256(scriptText), timeoutSeconds, clean(body.releaseNotes).slice(0, 2000), auth.session.user_id],
          )
        }
      }
      return true
    }).catch((error) => ({ error }))
    if (updated?.error) return c.json({ error: updated.error.message }, 400)
    if (!updated) return c.json({ error: 'Automation not found.' }, 404)
    return c.json({ success: true })
  })

  app.post('/api/v1/rmm/automations/:automationId/publish', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.manage'])
    if (auth.error) return auth.error
    const automationId = clean(c.req.param('automationId'))
    const result = await withTransaction(async (client) => {
      const automation = await client.query(
        `SELECT id FROM rmm_automations WHERE id=$1 AND tenant_id=$2 AND status<>'archived' FOR UPDATE`,
        [automationId, auth.session.tenant_id],
      )
      if (!automation.rowCount) return { status: 404, error: 'Automation not found.' }
      const draft = await client.query(
        `SELECT id,version_number,content_sha256 FROM rmm_automation_versions
          WHERE automation_id=$1 AND state='draft' ORDER BY version_number DESC LIMIT 1 FOR UPDATE`,
        [automationId],
      )
      if (!draft.rowCount) return { status: 400, error: 'There is no draft version to publish.' }
      await client.query(`UPDATE rmm_automation_versions SET state='superseded' WHERE automation_id=$1 AND state='published'`, [automationId])
      await client.query(
        `UPDATE rmm_automation_versions SET state='published',published_by_user_id=$2,published_at=now() WHERE id=$1`,
        [draft.rows[0].id, auth.session.user_id],
      )
      await client.query(
        `UPDATE rmm_automations SET status='published',published_version_id=$2,updated_by_user_id=$3,updated_at=now() WHERE id=$1`,
        [automationId, draft.rows[0].id, auth.session.user_id],
      )
      return { success: true, versionNumber: draft.rows[0].version_number, sha256: draft.rows[0].content_sha256 }
    })
    if (result.error) return c.json({ error: result.error }, result.status)
    return c.json(result)
  })

  app.post('/api/v1/rmm/automations/:automationId/run', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.run', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    const automationId = clean(c.req.param('automationId'))
    const body = await c.req.json().catch(() => ({}))
    const requestedIds = [...new Set(asArray(body.agentDeviceIds).map(clean).filter(Boolean))].slice(0, 500)
    if (!requestedIds.length) return c.json({ error: 'Select at least one managed device.' }, 400)
    const queued = await withTransaction(async (client) => {
      const automation = await client.query(
        `SELECT a.id,a.name,a.published_version_id,v.script_text,v.timeout_seconds,v.run_as,v.version_number,v.content_sha256
           FROM rmm_automations a
           JOIN rmm_automation_versions v ON v.id=a.published_version_id AND v.state='published'
          WHERE a.id=$1 AND a.tenant_id=$2 AND a.status='published'`,
        [automationId, auth.session.tenant_id],
      )
      if (!automation.rowCount) return { status: 400, error: 'Publish this automation before running it.' }
      const version = automation.rows[0]
      if (version.run_as !== 'system') return { status: 400, error: 'Current-user execution is not enabled in this Agent build yet.' }
      const targets = await client.query(
        `SELECT id FROM rmm_agent_devices WHERE tenant_id=$1 AND disabled_at IS NULL AND id=ANY($2::uuid[])`,
        [auth.session.tenant_id, requestedIds],
      )
      if (!targets.rowCount) return { status: 404, error: 'No valid managed Agent targets were found.' }
      const onlineTargets = targets.rows.filter((target) => {
        const socket = agentSocketForDevice(target.id)
        return socket && socket.readyState === 1
      })
      const offlineTargets = targets.rows.filter((target) => !onlineTargets.some((online) => online.id === target.id))
      if (!onlineTargets.length) {
        return { status: 409, error: 'All selected devices are offline. No jobs were queued.', offlineDeviceIds: offlineTargets.map((target) => target.id) }
      }

      const correlationId = randomUUID()
      const label = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
      const ids = []
      for (const target of onlineTargets) {
        const inserted = await client.query(
          `INSERT INTO rmm_agent_jobs
            (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,automation_id,automation_version_id,initiated_by,initiated_by_label,correlation_id,request_metadata)
           VALUES ($1,$2,'custom.command',$3::jsonb,$4,$5,$6,'technician',$7,$8,$9::jsonb)
           RETURNING id`,
          [auth.session.tenant_id, target.id, JSON.stringify({ command: version.script_text, timeout_seconds: version.timeout_seconds }), auth.session.user_id, automationId, version.published_version_id, label, correlationId, JSON.stringify({ automation_name: version.name, version_number: version.version_number, content_sha256: version.content_sha256 })],
        )
        ids.push(inserted.rows[0].id)
      }
      return {
        success: true,
        queued: ids.length,
        jobIds: ids,
        correlationId,
        skippedOffline: offlineTargets.length,
        skippedOfflineDeviceIds: offlineTargets.map((target) => target.id),
      }
    })
    if (queued.error) return c.json({ error: queued.error }, queued.status)
    return c.json(queued, 202)
  })

  app.get('/api/v1/rmm/jobs', async (c) => {
    const auth = await requireAccess(c, ['rmm.jobs.view', 'rmm.automation.view', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    const limit = boundedInteger(c.req.query('limit'), 1, 250, 100)
    const result = await pool.query(
      `SELECT j.id,j.job_type,j.status,j.result,j.error_message,j.claimed_at,j.completed_at,j.created_at,j.updated_at,
              j.initiated_by,j.initiated_by_label,j.correlation_id,j.automation_id,j.automation_version_id,
              i.name AS device_name,i.reference AS device_reference,a.name AS automation_name,
              v.version_number,v.content_sha256,u.name AS queued_by_name,u.email AS queued_by_email
         FROM rmm_agent_jobs j
         JOIN rmm_agent_devices ad ON ad.id=j.agent_device_id
         JOIN rmm_device_inventory i ON i.id=ad.inventory_id
         LEFT JOIN rmm_automations a ON a.id=j.automation_id
         LEFT JOIN rmm_automation_versions v ON v.id=j.automation_version_id
         LEFT JOIN users u ON u.id=j.queued_by_user_id
        WHERE j.tenant_id=$1
        ORDER BY j.created_at DESC
        LIMIT $2`,
      [auth.session.tenant_id, limit],
    )
    return c.json({ jobs: result.rows })
  })

  app.post('/api/v1/rmm/jobs/:jobId/cancel', async (c) => {
    const auth = await requireAccess(c, ['rmm.automation.run', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    const result = await pool.query(
      `UPDATE rmm_agent_jobs
          SET status='cancelled',updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status='queued'
        RETURNING id,agent_device_id,initiated_by_label,job_type,request_metadata,correlation_id`,
      [clean(c.req.param('jobId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Only queued jobs can be cancelled.' }, 409)
    const job = result.rows[0]
    const actorLabel = clean(auth.session.name || auth.session.email) || 'Technician'
    recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: job.agent_device_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel,
      eventType: 'job.cancelled',
      category: 'automation',
      summary: actorLabel + ' cancelled a queued RMM job',
      detail: clean(job.request_metadata?.automation_name || job.request_metadata?.tray_label || job.job_type),
      outcome: 'cancelled',
      jobId: job.id,
      correlationId: job.correlation_id,
      metadata: { jobType: job.job_type, requestMetadata: job.request_metadata || {} },
    }).catch(() => {})
    return c.json({ success: true })
  })

  app.get('/api/v1/rmm/tray-policy', async (c) => {
    const auth = await requireAccess(c, ['rmm.tray.view', 'rmm.tray.manage', 'rmm.policies.manage', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    return c.json({ policy: await trayPolicy(auth.session.tenant_id) })
  })

  app.put('/api/v1/rmm/tray-policy', async (c) => {
    const auth = await requireAccess(c, ['rmm.tray.manage', 'rmm.policies.manage', 'rmm.automation.manage'])
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const actions = asArray(body.actions).slice(0, 20)
    const result = await withTransaction(async (client) => {
      const published = new Map()
      if (actions.length) {
        const ids = [...new Set(actions.map((action) => clean(action.automationId)).filter(Boolean))]
        const found = await client.query(
          `SELECT a.id,a.name,a.published_version_id,v.version_number
             FROM rmm_automations a
             JOIN rmm_automation_versions v ON v.id=a.published_version_id AND v.state='published'
            WHERE a.tenant_id=$1 AND a.status='published' AND a.id=ANY($2::uuid[])`,
          [auth.session.tenant_id, ids],
        )
        for (const row of found.rows) published.set(row.id, row)
        if (published.size !== ids.length) return { status: 400, error: 'Every tray action must reference a published automation.' }
      }
      const policyResult = await client.query(
        `INSERT INTO rmm_tray_policies
          (tenant_id,name,enabled,scope_type,scope_id,priority,branding,support,created_by_user_id,updated_by_user_id)
         VALUES ($1,$2,$3,'tenant','',0,$4::jsonb,$5::jsonb,$6,$6)
         ON CONFLICT (tenant_id,scope_type,scope_id) DO UPDATE SET
           name=EXCLUDED.name,enabled=EXCLUDED.enabled,branding=EXCLUDED.branding,support=EXCLUDED.support,
           updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=now()
         RETURNING id`,
        [auth.session.tenant_id, clean(body.name).slice(0, 160) || 'Default tray policy', Boolean(body.enabled), JSON.stringify(asObject(body.branding)), JSON.stringify(asObject(body.support)), auth.session.user_id],
      )
      const policyId = policyResult.rows[0].id
      await client.query(`DELETE FROM rmm_tray_policy_actions WHERE policy_id=$1`, [policyId])
      for (let index = 0; index < actions.length; index += 1) {
        const action = actions[index]
        const automation = published.get(clean(action.automationId))
        if (!automation) continue
        await client.query(
          `INSERT INTO rmm_tray_policy_actions
            (tenant_id,policy_id,automation_id,automation_version_id,label,description,enabled,confirmation_required,sort_order)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [auth.session.tenant_id, policyId, automation.id, automation.published_version_id, clean(action.label).slice(0, 120) || automation.name, clean(action.description).slice(0, 500), action.enabled !== false, Boolean(action.confirmationRequired), index],
        )
      }
      return { success: true }
    })
    if (result.error) return c.json({ error: result.error }, result.status)
    return c.json({ ...result, policy: await trayPolicy(auth.session.tenant_id) })
  })

  app.get('/api/v1/agent/devices/tray-policy', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const policy = await trayPolicy(agent.tenant_id)
    return c.json({
      success: true,
      policy: {
        enabled: Boolean(policy.enabled), name: policy.name, branding: policy.branding || {}, support: policy.support || {},
        actions: (policy.actions || []).filter((action) => action.enabled).map((action) => ({
          id: action.id, label: action.label, description: action.description,
          confirmationRequired: Boolean(action.confirmation_required), sortOrder: action.sort_order,
        })),
      },
    })
  })

  app.post('/api/v1/agent/devices/tray-actions/:actionId/run', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const body = await c.req.json().catch(() => ({}))
    const action = await pool.query(
      `SELECT ta.id,ta.automation_id,ta.automation_version_id,ta.label,v.script_text,v.timeout_seconds,v.run_as,v.version_number,v.content_sha256
         FROM rmm_tray_policy_actions ta
         JOIN rmm_tray_policies p ON p.id=ta.policy_id AND p.enabled=true
         JOIN rmm_automation_versions v ON v.id=ta.automation_version_id AND v.state IN ('published','superseded')
        WHERE ta.id=$1 AND ta.tenant_id=$2 AND ta.enabled=true
          AND p.tenant_id=$2 AND p.scope_type='tenant' AND p.scope_id=''
        LIMIT 1`,
      [clean(c.req.param('actionId')), agent.tenant_id],
    )
    if (!action.rowCount) return c.json({ success: false, error: 'Tray action is not available for this device.' }, 404)
    const selected = action.rows[0]
    if (selected.run_as !== 'system') return c.json({ success: false, error: 'This action requires an unsupported execution context.' }, 409)
    const initiatedByLabel = clean(body.user || body.sessionUser || 'End user').slice(0, 255)
    const inserted = await pool.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,automation_id,automation_version_id,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'custom.command',$3::jsonb,$4,$5,'tray',$6,$7::jsonb)
       RETURNING id,status,created_at`,
      [agent.tenant_id, agent.id, JSON.stringify({ command: selected.script_text, timeout_seconds: selected.timeout_seconds }), selected.automation_id, selected.automation_version_id, initiatedByLabel, JSON.stringify({ tray_action_id: selected.id, tray_label: selected.label, version_number: selected.version_number, content_sha256: selected.content_sha256 })],
    )
    return c.json({ success: true, job: inserted.rows[0] }, 202)
  })
}
