import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

const recordTypes = new Set(['Incident', 'Problem', 'Change'])
const priorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const maxLimit = 200

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireTechnician(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician access is required.' }, 403) }
  return { session }
}

function effectiveConfiguration(row) {
  if (row?.configuration && Object.keys(row.configuration).length) return row.configuration
  return row?.onboarding_data || {}
}

async function numberingSettings(client, tenantId, recordType) {
  const result = await client.query(
    `SELECT configuration, onboarding_data
     FROM tenant_settings
     WHERE tenant_id = $1`,
    [tenantId],
  )
  const config = effectiveConfiguration(result.rows[0] || {})
  const itsm = object(config.itsm)
  const key = recordType === 'Incident' ? 'incident' : recordType === 'Problem' ? 'problem' : 'change'
  const defaults = { Incident: 'INC-', Problem: 'PRB-', Change: 'CHG-' }
  const custom = itsm.numberingMode === 'custom'
  const configured = custom ? text(object(itsm.recordPrefixes)[key], 12) : defaults[recordType]
  const cleaned = (configured || defaults[recordType]).toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 10)
  const prefix = (cleaned || defaults[recordType]).endsWith('-') ? (cleaned || defaults[recordType]) : `${cleaned || defaults[recordType]}-`
  const digits = Math.max(4, Math.min(8, Number(itsm.recordDigits || 5)))
  return { prefix, digits }
}

async function nextReference(client, tenantId, recordType) {
  const { prefix, digits } = await numberingSettings(client, tenantId, recordType)
  const counterKey = recordType.toLowerCase().replace(/\s+/g, '_')
  const counter = await client.query(
    `INSERT INTO tenant_record_counters (tenant_id, record_type, next_value, updated_at)
     VALUES ($1, $2, 1, now())
     ON CONFLICT (tenant_id, record_type) DO UPDATE SET
       next_value = tenant_record_counters.next_value + 1,
       updated_at = now()
     RETURNING next_value`,
    [tenantId, counterKey],
  )
  return `${prefix}${String(counter.rows[0].next_value).padStart(digits, '0')}`
}

async function personByExternalKey(client, tenantId, externalKey) {
  const key = text(externalKey, 120)
  if (!key) return null
  const result = await client.query(
    `SELECT id, external_key, name, email, job_title, user_id
     FROM organisation_people
     WHERE tenant_id = $1 AND external_key = $2
     LIMIT 1`,
    [tenantId, key],
  )
  return result.rows[0] || null
}

async function teamByName(client, tenantId, name) {
  const value = text(name, 160)
  if (!value) return null
  const result = await client.query(
    `SELECT id, external_key, name
     FROM organisation_teams
     WHERE tenant_id = $1 AND name = $2 AND active = true
     LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

async function personByIdentity(client, tenantId, value) {
  const identity = text(value, 254)
  if (!identity || identity === 'Unassigned') return null
  const result = await client.query(
    `SELECT p.id, p.external_key, p.name, p.email, p.job_title, p.user_id
     FROM organisation_people p
     JOIN tenant_memberships m
       ON m.tenant_id = p.tenant_id
      AND m.user_id = p.user_id
      AND m.status = 'active'
      AND m.role <> 'requester'
     WHERE p.tenant_id = $1
       AND p.active = true
       AND (p.name = $2 OR lower(p.email) = lower($2))
     ORDER BY CASE WHEN p.name = $2 THEN 0 ELSE 1 END
     LIMIT 1`,
    [tenantId, identity],
  )
  return result.rows[0] || null
}

function requesterSnapshot(person, body = {}) {
  return {
    personId: person?.external_key || text(body.requesterId, 120),
    name: person?.name || text(body.requester, 180),
    email: person?.email || text(body.requesterEmail, 254),
    jobTitle: person?.job_title || text(body.requesterJobTitle, 180),
    department: text(body.requesterDepartment, 180),
    site: text(body.requesterLocation || body.location, 180),
  }
}

function recordPayload(row, activities = []) {
  const requester = object(row.requester_snapshot)
  const team = object(row.assignment_team_snapshot)
  const assignee = object(row.assignee_snapshot)
  const data = object(row.record_data)
  return {
    id: row.reference,
    databaseId: row.id,
    type: row.record_type,
    title: row.title,
    description: row.description,
    requester: requester.name || '',
    requesterId: requester.personId || '',
    requesterEmail: requester.email || '',
    requesterJobTitle: requester.jobTitle || '',
    requesterDepartment: requester.department || '',
    requesterLocation: requester.site || '',
    service: row.service,
    category: row.category,
    priority: row.priority,
    status: row.status,
    team: team.name || '',
    assignee: assignee.name || 'Unassigned',
    source: row.source,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    closedAt: row.closed_at,
    ...data,
    activities: activities.map((activity) => ({
      id: activity.id,
      kind: activity.kind,
      visibility: activity.visibility,
      actor: object(activity.actor_snapshot).name || 'System',
      text: activity.body_text,
      createdAt: activity.created_at,
      metadata: activity.metadata || {},
    })),
  }
}

async function lookupRecord(tenantId, reference, db = pool) {
  const result = await db.query(
    `SELECT * FROM itsm_records WHERE tenant_id = $1 AND upper(reference) = upper($2) LIMIT 1`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

async function activitiesFor(recordId, db = pool) {
  const result = await db.query(
    `SELECT * FROM itsm_record_activities WHERE record_id = $1 ORDER BY created_at DESC LIMIT 250`,
    [recordId],
  )
  return result.rows
}

export function registerItsmRecordRoutes(app) {
  app.get('/api/v1/itsm-records', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error

    const recordType = text(c.req.query('type'), 40)
    if (recordType && !recordTypes.has(recordType)) return c.json({ error: 'Invalid record type.' }, 400)
    const status = text(c.req.query('status'), 80)
    const priority = text(c.req.query('priority'), 40)
    const team = text(c.req.query('team'), 160)
    const assignee = text(c.req.query('assignee'), 180)
    const search = text(c.req.query('search'), 240)
    const limit = Math.max(1, Math.min(maxLimit, Number(c.req.query('limit') || 50)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))

    const where = ['tenant_id = $1']
    const values = [auth.session.tenant_id]
    const add = (sql, value) => {
      values.push(value)
      where.push(sql.replace('?', `$${values.length}`))
    }
    if (recordType) add('record_type = ?', recordType)
    if (status && status !== 'All') add('status = ?', status)
    if (priority && priority !== 'All') add('priority = ?', priority)
    if (team && team !== 'All') add("COALESCE(assignment_team_snapshot->>'name','') = ?", team)
    if (assignee && assignee !== 'All') add("COALESCE(assignee_snapshot->>'name','Unassigned') = ?", assignee)
    if (search) {
      values.push(`%${search.toLowerCase()}%`)
      const p = `$${values.length}`
      where.push(`lower(reference || ' ' || title || ' ' || COALESCE(requester_snapshot->>'name','') || ' ' || service || ' ' || COALESCE(assignment_team_snapshot->>'name','') || ' ' || COALESCE(assignee_snapshot->>'name','')) LIKE ${p}`)
    }

    const whereSql = where.join(' AND ')
    const countResult = await pool.query(`SELECT count(*)::int AS total FROM itsm_records WHERE ${whereSql}`, values)
    values.push(limit, offset)
    const rows = await pool.query(
      `SELECT * FROM itsm_records WHERE ${whereSql}
       ORDER BY updated_at DESC
       LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values,
    )
    return c.json({
      items: rows.rows.map((row) => recordPayload(row)),
      total: countResult.rows[0]?.total || 0,
      limit,
      offset,
    })
  })

  app.get('/api/v1/itsm-records/:reference', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    return c.json(recordPayload(row, await activitiesFor(row.id)))
  })

  app.post('/api/v1/itsm-records', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const recordType = text(body?.type, 40)
    const title = text(body?.title, 240)
    if (!recordTypes.has(recordType)) return c.json({ error: 'Record type must be Incident, Problem or Change.' }, 400)
    if (title.length < 3) return c.json({ error: 'Add a summary of at least 3 characters.' }, 400)

    const created = await withTransaction(async (client) => {
      const reference = await nextReference(client, auth.session.tenant_id, recordType)
      const requesterPerson = await personByExternalKey(client, auth.session.tenant_id, body?.requesterId)
      const team = await teamByName(client, auth.session.tenant_id, body?.team)
      const assignee = await personByIdentity(client, auth.session.tenant_id, body?.assignee)
      const priority = priorities.has(body?.priority) ? body.priority : 'Medium'
      const status = text(body?.status || (recordType === 'Change' ? 'Draft' : 'New'), 80)
      const commonKeys = new Set(['type','title','description','requester','requesterId','requesterEmail','requesterJobTitle','requesterDepartment','requesterLocation','location','service','category','priority','status','team','assignee','source','activities','comments','created','updated','createdAt','updatedAt','id','databaseId','persistence'])
      const data = Object.fromEntries(Object.entries(object(body)).filter(([key]) => !commonKeys.has(key)))

      const result = await client.query(
        `INSERT INTO itsm_records (
           tenant_id, reference, record_type, requester_person_id, requester_snapshot,
           title, description, service, category, priority, status, source,
           assignment_team_id, assignment_team_snapshot, assigned_person_id, assignee_snapshot,
           record_data, created_by_user_id
         ) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16::jsonb,$17::jsonb,$18)
         RETURNING *`,
        [
          auth.session.tenant_id,
          reference,
          recordType,
          requesterPerson?.id || null,
          JSON.stringify(requesterSnapshot(requesterPerson, body)),
          title,
          text(body?.description, 20000),
          text(body?.service, 160),
          text(body?.category, 160),
          priority,
          status,
          text(body?.source || 'technician', 80),
          team?.id || null,
          JSON.stringify({ id: team?.external_key || '', name: team?.name || text(body?.team, 160) }),
          assignee?.id || null,
          JSON.stringify({ id: assignee?.external_key || '', name: assignee?.name || 'Unassigned', email: assignee?.email || '' }),
          JSON.stringify(data),
          auth.session.user_id,
        ],
      )
      const row = result.rows[0]
      await client.query(
        `INSERT INTO itsm_record_activities (
           tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
         ) VALUES ($1,$2,$3,$4::jsonb,'system','internal',$5,$6::jsonb)`,
        [auth.session.tenant_id, row.id, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email }), `${recordType} ${reference} created.`, JSON.stringify({ event: 'record.created' })],
      )
      return row
    })

    return c.json(recordPayload(created, await activitiesFor(created.id)), 201)
  })

  app.patch('/api/v1/itsm-records/:reference', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const current = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!current) return c.json({ error: 'ITSM record not found.' }, 404)

    const hasTeam = Object.prototype.hasOwnProperty.call(body, 'team')
    const hasAssignee = Object.prototype.hasOwnProperty.call(body, 'assignee')
    const assigneeIdentity = hasAssignee ? text(body.assignee, 254) : ''
    const clearAssignee = hasAssignee && (!assigneeIdentity || assigneeIdentity === 'Unassigned')
    const team = hasTeam ? await teamByName(pool, auth.session.tenant_id, body.team) : null
    const assignee = hasAssignee && !clearAssignee ? await personByIdentity(pool, auth.session.tenant_id, assigneeIdentity) : null

    if (hasAssignee && !clearAssignee && !assignee) {
      return c.json({ error: 'Assignee must be an active technician account in this tenant.' }, 422)
    }

    const data = { ...object(current.record_data), ...object(body.recordData) }
    const status = Object.prototype.hasOwnProperty.call(body, 'status') ? text(body.status, 80) : current.status
    const closedAt = ['Closed', 'Resolved', 'Completed', 'Cancelled'].includes(status) ? (current.closed_at || new Date()) : null

    const result = await pool.query(
      `UPDATE itsm_records SET
         title = COALESCE($3, title),
         description = COALESCE($4, description),
         service = COALESCE($5, service),
         category = COALESCE($6, category),
         priority = COALESCE($7, priority),
         status = $8,
         assignment_team_id = CASE WHEN $9::boolean THEN $10 ELSE assignment_team_id END,
         assignment_team_snapshot = CASE WHEN $9::boolean THEN $11::jsonb ELSE assignment_team_snapshot END,
         assigned_person_id = CASE WHEN $12::boolean THEN $13 ELSE assigned_person_id END,
         assignee_snapshot = CASE WHEN $12::boolean THEN $14::jsonb ELSE assignee_snapshot END,
         record_data = $15::jsonb,
         closed_at = $16,
         updated_at = now()
       WHERE tenant_id = $1 AND id = $2
       RETURNING *`,
      [
        auth.session.tenant_id,
        current.id,
        Object.prototype.hasOwnProperty.call(body, 'title') ? text(body.title, 240) : null,
        Object.prototype.hasOwnProperty.call(body, 'description') ? text(body.description, 20000) : null,
        Object.prototype.hasOwnProperty.call(body, 'service') ? text(body.service, 160) : null,
        Object.prototype.hasOwnProperty.call(body, 'category') ? text(body.category, 160) : null,
        Object.prototype.hasOwnProperty.call(body, 'priority') && priorities.has(body.priority) ? body.priority : null,
        status,
        hasTeam,
        team?.id || null,
        JSON.stringify({ id: team?.external_key || '', name: team?.name || text(body.team, 160) }),
        hasAssignee,
        assignee?.id || null,
        JSON.stringify({ id: assignee?.external_key || '', name: assignee?.name || 'Unassigned', email: assignee?.email || '' }),
        JSON.stringify(data),
        closedAt,
      ],
    )
    return c.json(recordPayload(result.rows[0], await activitiesFor(current.id)))
  })

  app.post('/api/v1/itsm-records/:reference/activities', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const kind = body?.kind === 'customer' ? 'customer' : body?.kind === 'system' ? 'system' : 'work'
    const visibility = kind === 'customer' ? 'customer' : 'internal'
    const bodyText = text(body?.text, 20000)
    if (!bodyText) return c.json({ error: 'Add activity text first.' }, 400)
    await pool.query(
      `INSERT INTO itsm_record_activities (
         tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
       ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8::jsonb)`,
      [auth.session.tenant_id, row.id, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email }), kind, visibility, bodyText, JSON.stringify(object(body?.metadata))],
    )
    await pool.query('UPDATE itsm_records SET updated_at = now() WHERE id = $1', [row.id])
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(recordPayload(refreshed, await activitiesFor(row.id)), 201)
  })
}
