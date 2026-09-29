import { createHash } from 'node:crypto'
import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

const priorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const impacts = new Set(['Low', 'Medium', 'High'])
const urgencies = new Set(['Low', 'Medium', 'High'])
const relationshipTypes = new Set(['related', 'caused-by', 'resolved-by', 'duplicates', 'blocks', 'blocked-by'])
const pausedIncidentStates = new Set(['Pending Customer', 'Pending Vendor'])
const statusByType = {
  Incident: ['New', 'Assigned', 'In Progress', 'Pending Customer', 'Pending Vendor', 'Resolved', 'Closed'],
  Problem: ['New', 'Investigation', 'Known Error', 'Resolved', 'Closed'],
  Change: ['Draft', 'Assessment', 'Awaiting Approval', 'Scheduled', 'Implementing', 'Review', 'Completed', 'Cancelled'],
}
const defaultPriorityMatrix = {
  'High:High': 'Critical',
  'High:Medium': 'High',
  'High:Low': 'Medium',
  'Medium:High': 'High',
  'Medium:Medium': 'Medium',
  'Medium:Low': 'Low',
  'Low:High': 'Medium',
  'Low:Medium': 'Low',
  'Low:Low': 'Low',
}
const defaultSlaTargets = {
  Critical: { responseMinutes: 15, resolutionMinutes: 240 },
  High: { responseMinutes: 30, resolutionMinutes: 480 },
  Medium: { responseMinutes: 240, resolutionMinutes: 1440 },
  Low: { responseMinutes: 480, resolutionMinutes: 2880 },
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function array(value) {
  return Array.isArray(value) ? value : []
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

async function configurationFor(tenantId, db = pool) {
  const result = await db.query(
    `SELECT configuration, onboarding_data FROM tenant_settings WHERE tenant_id = $1 LIMIT 1`,
    [tenantId],
  )
  const row = result.rows[0] || {}
  return row.configuration && Object.keys(row.configuration).length ? row.configuration : (row.onboarding_data || {})
}

function priorityFor(impact, urgency, configuration = {}) {
  const configured = object(object(configuration.itsm).priorityMatrix)
  const key = `${impact}:${urgency}`
  const value = text(configured[key], 20)
  return priorities.has(value) ? value : defaultPriorityMatrix[key] || 'Medium'
}

function slaTargetFor(priority, configuration = {}) {
  const configured = object(object(object(configuration.itsm).slaTargets)[priority])
  const fallback = defaultSlaTargets[priority] || defaultSlaTargets.Medium
  const responseMinutes = Math.max(1, Math.min(43200, Number(configured.responseMinutes || fallback.responseMinutes)))
  const resolutionMinutes = Math.max(responseMinutes, Math.min(129600, Number(configured.resolutionMinutes || fallback.resolutionMinutes)))
  return { responseMinutes, resolutionMinutes }
}

async function lookupRecord(tenantId, reference, db = pool, lock = false) {
  const result = await db.query(
    `SELECT * FROM itsm_records
     WHERE tenant_id = $1 AND upper(reference) = upper($2)
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

async function ensureIncidentLifecycle(row, tenantId) {
  if (!row || row.record_type !== 'Incident') return row
  const data = object(row.record_data)
  const impact = impacts.has(row.impact) && row.impact !== 'Medium'
    ? row.impact
    : impacts.has(data.impact) ? data.impact : (impacts.has(row.impact) ? row.impact : 'Medium')
  const urgency = urgencies.has(row.urgency) && row.urgency !== 'Medium'
    ? row.urgency
    : urgencies.has(data.urgency) ? data.urgency : (urgencies.has(row.urgency) ? row.urgency : 'Medium')
  const configuration = await configurationFor(tenantId)
  const priority = priorityFor(impact, urgency, configuration)
  const target = slaTargetFor(priority, configuration)
  const createdAt = new Date(row.created_at).getTime()
  const responseDueAt = row.response_due_at || new Date(createdAt + target.responseMinutes * 60000)
  const resolutionDueAt = row.resolution_due_at || new Date(createdAt + target.resolutionMinutes * 60000)
  const needsUpdate = row.impact !== impact || row.urgency !== urgency || row.priority !== priority || !row.response_due_at || !row.resolution_due_at
  if (!needsUpdate) return row
  const result = await pool.query(
    `UPDATE itsm_records
     SET impact = $3,
         urgency = $4,
         priority = $5,
         response_due_at = COALESCE(response_due_at, $6),
         resolution_due_at = COALESCE(resolution_due_at, $7),
         version = version + 1,
         updated_at = now()
     WHERE tenant_id = $1 AND id = $2
     RETURNING *`,
    [tenantId, row.id, impact, urgency, priority, responseDueAt, resolutionDueAt],
  )
  return result.rows[0]
}

async function activitiesFor(recordId) {
  const result = await pool.query(
    `SELECT id, kind, visibility, actor_snapshot, body_text, metadata, created_at
     FROM itsm_record_activities
     WHERE record_id = $1
     ORDER BY created_at DESC
     LIMIT 500`,
    [recordId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    kind: row.kind,
    visibility: row.visibility,
    actor: object(row.actor_snapshot).name || 'System',
    text: row.body_text,
    metadata: row.metadata || {},
    createdAt: row.created_at,
  }))
}

async function relationshipsFor(tenantId, recordId) {
  const result = await pool.query(
    `SELECT id, target_reference, target_type, relationship_type, created_at
     FROM itsm_record_relationships
     WHERE tenant_id = $1 AND source_record_id = $2
     ORDER BY created_at DESC`,
    [tenantId, recordId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    targetReference: row.target_reference,
    targetType: row.target_type,
    relationshipType: row.relationship_type,
    createdAt: row.created_at,
  }))
}

async function attachmentsFor(tenantId, recordId) {
  const result = await pool.query(
    `SELECT id, file_name, mime_type, byte_size, sha256, uploaded_by_snapshot, created_at
     FROM itsm_record_attachments
     WHERE tenant_id = $1 AND record_id = $2
     ORDER BY created_at DESC`,
    [tenantId, recordId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    fileName: row.file_name,
    mimeType: row.mime_type,
    byteSize: Number(row.byte_size),
    sha256: row.sha256,
    uploadedBy: object(row.uploaded_by_snapshot).name || 'Unknown',
    createdAt: row.created_at,
  }))
}

async function editorOptions(tenantId, currentReference) {
  const [people, teams, generic, requests] = await Promise.all([
    pool.query(
      `SELECT external_key, name, email, job_title, access_profile
       FROM organisation_people
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT external_key, name
       FROM organisation_teams
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT reference, record_type, title
       FROM itsm_records
       WHERE tenant_id = $1 AND upper(reference) <> upper($2)
       ORDER BY updated_at DESC
       LIMIT 100`,
      [tenantId, currentReference],
    ),
    pool.query(
      `SELECT reference, 'Service Request'::text AS record_type, title
       FROM service_requests
       WHERE tenant_id = $1
       ORDER BY updated_at DESC
       LIMIT 100`,
      [tenantId],
    ),
  ])
  const services = [...new Set([
    ...generic.rows.map((row) => text(row.service)).filter(Boolean),
  ])]
  return {
    people: people.rows.map((row) => ({ id: row.external_key, name: row.name, email: row.email, jobTitle: row.job_title, accessProfile: row.access_profile })),
    teams: teams.rows.map((row) => ({ id: row.external_key, name: row.name })),
    relatedRecords: [...generic.rows, ...requests.rows].map((row) => ({ reference: row.reference, type: row.record_type, title: row.title })),
    services,
  }
}

function slaMetric({ createdAt, dueAt, completedAt, pausedAt }) {
  if (!dueAt) return null
  const start = new Date(createdAt).getTime()
  const due = new Date(dueAt).getTime()
  const effectiveEnd = completedAt ? new Date(completedAt).getTime() : pausedAt ? new Date(pausedAt).getTime() : Date.now()
  const total = Math.max(1, due - start)
  const elapsed = Math.max(0, effectiveEnd - start)
  const percent = Math.max(0, Math.min(999, Math.round((elapsed / total) * 100)))
  const breached = effectiveEnd > due
  return {
    dueAt,
    completedAt: completedAt || null,
    percent,
    breached,
    state: completedAt ? (new Date(completedAt).getTime() <= due ? 'met' : 'breached') : breached ? 'breached' : percent >= 75 ? 'warning' : 'on_track',
  }
}

async function detailPayload(row, tenantId) {
  const record = await ensureIncidentLifecycle(row, tenantId)
  const requester = object(record.requester_snapshot)
  const team = object(record.assignment_team_snapshot)
  const assignee = object(record.assignee_snapshot)
  const data = object(record.record_data)
  const [activities, relationships, attachments, options] = await Promise.all([
    activitiesFor(record.id),
    relationshipsFor(tenantId, record.id),
    attachmentsFor(tenantId, record.id),
    editorOptions(tenantId, record.reference),
  ])
  const sla = record.record_type === 'Incident' ? {
    paused: Boolean(record.sla_paused_at),
    pausedAt: record.sla_paused_at,
    pausedSeconds: Number(record.sla_paused_seconds || 0),
    response: slaMetric({ createdAt: record.created_at, dueAt: record.response_due_at, completedAt: record.first_response_at, pausedAt: record.sla_paused_at }),
    resolution: slaMetric({ createdAt: record.created_at, dueAt: record.resolution_due_at, completedAt: record.resolved_at || record.closed_at, pausedAt: record.sla_paused_at }),
  } : null
  return {
    id: record.reference,
    databaseId: record.id,
    type: record.record_type,
    version: Number(record.version || 1),
    title: record.title,
    description: record.description,
    requester: requester.name || '',
    requesterId: requester.personId || '',
    requesterEmail: requester.email || '',
    requesterJobTitle: requester.jobTitle || '',
    requesterDepartment: requester.department || '',
    requesterLocation: requester.site || '',
    service: record.service,
    category: record.category,
    priority: record.priority,
    status: record.status,
    team: team.name || '',
    assignee: assignee.name || 'Unassigned',
    source: record.source,
    impact: record.impact,
    urgency: record.urgency,
    resolutionCode: record.resolution_code,
    resolutionSummary: record.resolution_summary,
    firstResponseAt: record.first_response_at,
    resolvedAt: record.resolved_at,
    closedAt: record.closed_at,
    createdAt: record.created_at,
    updatedAt: record.updated_at,
    recordData: data,
    activities,
    relationships,
    attachments,
    sla,
    allowedStatuses: statusByType[record.record_type] || [],
    options,
  }
}

async function personByExternalKey(client, tenantId, externalKey) {
  const key = text(externalKey, 120)
  if (!key) return null
  const result = await client.query(
    `SELECT id, external_key, name, email, job_title
     FROM organisation_people
     WHERE tenant_id = $1 AND external_key = $2 AND active = true
     LIMIT 1`,
    [tenantId, key],
  )
  return result.rows[0] || null
}

async function personByName(client, tenantId, name) {
  const value = text(name, 180)
  if (!value || value === 'Unassigned') return null
  const result = await client.query(
    `SELECT id, external_key, name, email, job_title
     FROM organisation_people
     WHERE tenant_id = $1 AND active = true AND (name = $2 OR lower(email) = lower($2))
     LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

async function teamByName(client, tenantId, name) {
  const value = text(name, 160)
  if (!value) return null
  const result = await client.query(
    `SELECT id, external_key, name FROM organisation_teams
     WHERE tenant_id = $1 AND name = $2 AND active = true LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

function snapshotPerson(person) {
  return person ? { personId: person.external_key, name: person.name, email: person.email, jobTitle: person.job_title } : {}
}

function snapshotAssignee(person) {
  return person ? { id: person.external_key, name: person.name, email: person.email } : { id: '', name: 'Unassigned', email: '' }
}

function snapshotTeam(team, fallback = '') {
  return { id: team?.external_key || '', name: team?.name || fallback }
}

function fieldChange(field, from, to) {
  const left = from ?? ''
  const right = to ?? ''
  return JSON.stringify(left) === JSON.stringify(right) ? null : { field, from: left, to: right }
}

function safeFileName(value) {
  const name = text(value, 220).replace(/[\r\n\\/]+/g, '-').replace(/^\.+/, '')
  return name || 'attachment'
}

async function relatedTarget(tenantId, reference) {
  const generic = await pool.query(
    `SELECT reference, record_type, title FROM itsm_records WHERE tenant_id = $1 AND upper(reference) = upper($2) LIMIT 1`,
    [tenantId, reference],
  )
  if (generic.rowCount) return { reference: generic.rows[0].reference, type: generic.rows[0].record_type, title: generic.rows[0].title }
  const request = await pool.query(
    `SELECT reference, 'Service Request'::text AS record_type, title FROM service_requests WHERE tenant_id = $1 AND upper(reference) = upper($2) LIMIT 1`,
    [tenantId, reference],
  )
  return request.rowCount ? { reference: request.rows[0].reference, type: 'Service Request', title: request.rows[0].title } : null
}

export function registerItsmLifecycleRoutes(app) {
  app.get('/api/v1/itsm-lifecycle/:reference', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    return c.json(await detailPayload(row, auth.session.tenant_id))
  })

  app.patch('/api/v1/itsm-lifecycle/:reference', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const expectedVersion = Number(body?.version)
    if (!Number.isInteger(expectedVersion) || expectedVersion < 1) return c.json({ error: 'A valid record version is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const current = await lookupRecord(auth.session.tenant_id, c.req.param('reference'), client, true)
      if (!current) return { notFound: true }
      if (Number(current.version || 1) !== expectedVersion) return { conflict: true, current }

      const configuration = await configurationFor(auth.session.tenant_id, client)
      const type = current.record_type
      const allowedStatuses = statusByType[type] || []
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? text(body.status, 80) : current.status
      if (!allowedStatuses.includes(status)) return { invalidStatus: true }

      const currentData = object(current.record_data)
      const nextData = { ...currentData, ...object(body.recordData) }
      const nextImpact = type === 'Incident' && impacts.has(body?.impact) ? body.impact : current.impact
      const nextUrgency = type === 'Incident' && urgencies.has(body?.urgency) ? body.urgency : current.urgency
      const nextPriority = type === 'Incident'
        ? priorityFor(nextImpact, nextUrgency, configuration)
        : (priorities.has(body?.priority) ? body.priority : current.priority)
      const target = type === 'Incident' ? slaTargetFor(nextPriority, configuration) : null

      const requesterChanged = Object.prototype.hasOwnProperty.call(body, 'requesterId')
      const requester = requesterChanged ? await personByExternalKey(client, auth.session.tenant_id, body.requesterId) : null
      if (requesterChanged && body.requesterId && !requester) return { invalidRequester: true }
      const teamChanged = Object.prototype.hasOwnProperty.call(body, 'team')
      const team = teamChanged ? await teamByName(client, auth.session.tenant_id, body.team) : null
      const assigneeChanged = Object.prototype.hasOwnProperty.call(body, 'assignee')
      const assignee = assigneeChanged ? await personByName(client, auth.session.tenant_id, body.assignee) : null

      const resolutionCode = Object.prototype.hasOwnProperty.call(body, 'resolutionCode') ? text(body.resolutionCode, 120) : current.resolution_code
      const resolutionSummary = Object.prototype.hasOwnProperty.call(body, 'resolutionSummary') ? text(body.resolutionSummary, 10000) : current.resolution_summary
      if (type === 'Incident' && ['Resolved', 'Closed'].includes(status) && (!resolutionCode || resolutionSummary.length < 3)) {
        return { resolutionRequired: true }
      }

      let responseDueAt = current.response_due_at
      let resolutionDueAt = current.resolution_due_at
      if (type === 'Incident' && (!responseDueAt || !resolutionDueAt || nextPriority !== current.priority)) {
        const created = new Date(current.created_at).getTime()
        responseDueAt = new Date(created + target.responseMinutes * 60000)
        resolutionDueAt = new Date(created + target.resolutionMinutes * 60000)
      }

      const wasPaused = type === 'Incident' && pausedIncidentStates.has(current.status)
      const willPause = type === 'Incident' && pausedIncidentStates.has(status)
      let pausedAt = current.sla_paused_at
      let pausedSeconds = Number(current.sla_paused_seconds || 0)
      if (!wasPaused && willPause) pausedAt = new Date()
      if (wasPaused && !willPause && current.sla_paused_at) {
        const delta = Math.max(0, Math.floor((Date.now() - new Date(current.sla_paused_at).getTime()) / 1000))
        pausedSeconds += delta
        responseDueAt = responseDueAt ? new Date(new Date(responseDueAt).getTime() + delta * 1000) : null
        resolutionDueAt = resolutionDueAt ? new Date(new Date(resolutionDueAt).getTime() + delta * 1000) : null
        pausedAt = null
      }

      const resolved = ['Resolved', 'Closed', 'Completed'].includes(status)
      const resolvedAt = resolved ? (current.resolved_at || new Date()) : null
      const closedAt = ['Closed', 'Completed', 'Cancelled'].includes(status) ? (current.closed_at || new Date()) : null

      const title = Object.prototype.hasOwnProperty.call(body, 'title') ? text(body.title, 240) : current.title
      const description = Object.prototype.hasOwnProperty.call(body, 'description') ? text(body.description, 20000) : current.description
      const service = Object.prototype.hasOwnProperty.call(body, 'service') ? text(body.service, 160) : current.service
      const category = Object.prototype.hasOwnProperty.call(body, 'category') ? text(body.category, 160) : current.category

      const changes = [
        fieldChange('title', current.title, title),
        fieldChange('description', current.description, description),
        fieldChange('service', current.service, service),
        fieldChange('category', current.category, category),
        fieldChange('status', current.status, status),
        fieldChange('priority', current.priority, nextPriority),
        fieldChange('impact', current.impact, nextImpact),
        fieldChange('urgency', current.urgency, nextUrgency),
        fieldChange('team', object(current.assignment_team_snapshot).name || '', teamChanged ? (team?.name || text(body.team, 160)) : (object(current.assignment_team_snapshot).name || '')),
        fieldChange('assignee', object(current.assignee_snapshot).name || 'Unassigned', assigneeChanged ? (assignee?.name || 'Unassigned') : (object(current.assignee_snapshot).name || 'Unassigned')),
        fieldChange('requester', object(current.requester_snapshot).name || '', requesterChanged ? (requester?.name || '') : (object(current.requester_snapshot).name || '')),
        fieldChange('resolutionCode', current.resolution_code, resolutionCode),
        fieldChange('resolutionSummary', current.resolution_summary, resolutionSummary),
        ...Object.keys(object(body.recordData)).map((key) => fieldChange(key, currentData[key], nextData[key])),
      ].filter(Boolean)

      const updated = await client.query(
        `UPDATE itsm_records SET
           requester_person_id = CASE WHEN $3::boolean THEN $4 ELSE requester_person_id END,
           requester_snapshot = CASE WHEN $3::boolean THEN $5::jsonb ELSE requester_snapshot END,
           title = $6,
           description = $7,
           service = $8,
           category = $9,
           priority = $10,
           status = $11,
           assignment_team_id = CASE WHEN $12::boolean THEN $13 ELSE assignment_team_id END,
           assignment_team_snapshot = CASE WHEN $12::boolean THEN $14::jsonb ELSE assignment_team_snapshot END,
           assigned_person_id = CASE WHEN $15::boolean THEN $16 ELSE assigned_person_id END,
           assignee_snapshot = CASE WHEN $15::boolean THEN $17::jsonb ELSE assignee_snapshot END,
           record_data = $18::jsonb,
           impact = $19,
           urgency = $20,
           response_due_at = $21,
           resolution_due_at = $22,
           sla_paused_at = $23,
           sla_paused_seconds = $24,
           resolved_at = $25,
           closed_at = $26,
           resolution_code = $27,
           resolution_summary = $28,
           version = version + 1,
           updated_at = now()
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        [
          auth.session.tenant_id,
          current.id,
          requesterChanged,
          requester?.id || null,
          JSON.stringify(requesterChanged ? snapshotPerson(requester) : object(current.requester_snapshot)),
          title,
          description,
          service,
          category,
          nextPriority,
          status,
          teamChanged,
          team?.id || null,
          JSON.stringify(teamChanged ? snapshotTeam(team, text(body.team, 160)) : object(current.assignment_team_snapshot)),
          assigneeChanged,
          assignee?.id || null,
          JSON.stringify(assigneeChanged ? snapshotAssignee(assignee) : object(current.assignee_snapshot)),
          JSON.stringify(nextData),
          nextImpact,
          nextUrgency,
          responseDueAt,
          resolutionDueAt,
          pausedAt,
          pausedSeconds,
          resolvedAt,
          closedAt,
          resolutionCode,
          resolutionSummary,
        ],
      )

      if (changes.length) {
        await client.query(
          `INSERT INTO itsm_record_activities (
             tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
           ) VALUES ($1,$2,$3,$4::jsonb,'field_change','internal',$5,$6::jsonb)`,
          [
            auth.session.tenant_id,
            current.id,
            auth.session.user_id,
            JSON.stringify({ name: auth.session.name, email: auth.session.email }),
            `${changes.length} field${changes.length === 1 ? '' : 's'} updated.`,
            JSON.stringify({ event: 'record.fields.changed', changes }),
          ],
        )
      }
      return { updated: updated.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.invalidStatus) return c.json({ error: 'That status is not valid for this record type.' }, 400)
    if (result.invalidRequester) return c.json({ error: 'Choose an active requester from this tenant.' }, 400)
    if (result.resolutionRequired) return c.json({ error: 'Add a resolution code and resolution summary before resolving or closing this Incident.' }, 400)
    if (result.conflict) {
      return c.json({ error: 'This record was changed by another technician. Reload the latest version before saving.', conflict: true, currentVersion: Number(result.current.version || 1) }, 409)
    }
    return c.json(await detailPayload(result.updated, auth.session.tenant_id))
  })

  app.post('/api/v1/itsm-lifecycle/:reference/activity', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const bodyText = text(body?.text, 20000)
    if (!bodyText) return c.json({ error: 'Add activity text first.' }, 400)
    const visibility = body?.visibility === 'customer' ? 'customer' : 'internal'
    const kind = visibility === 'customer' ? 'customer' : 'work'
    await withTransaction(async (client) => {
      await client.query(
        `INSERT INTO itsm_record_activities (
           tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
         ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8::jsonb)`,
        [auth.session.tenant_id, row.id, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email }), kind, visibility, bodyText, JSON.stringify(object(body?.metadata))],
      )
      await client.query(
        `UPDATE itsm_records
         SET first_response_at = CASE WHEN $2 = 'customer' THEN COALESCE(first_response_at, now()) ELSE first_response_at END,
             version = version + 1,
             updated_at = now()
         WHERE id = $1`,
        [row.id, visibility],
      )
    })
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(await detailPayload(refreshed, auth.session.tenant_id), 201)
  })

  app.post('/api/v1/itsm-lifecycle/:reference/relationships', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const targetReference = text(body?.targetReference, 80)
    if (!targetReference || targetReference.toUpperCase() === row.reference.toUpperCase()) return c.json({ error: 'Choose another record to link.' }, 400)
    const target = await relatedTarget(auth.session.tenant_id, targetReference)
    if (!target) return c.json({ error: 'The related record was not found in this tenant.' }, 404)
    const relationshipType = relationshipTypes.has(body?.relationshipType) ? body.relationshipType : 'related'
    try {
      await pool.query(
        `INSERT INTO itsm_record_relationships (
           tenant_id, source_record_id, target_reference, target_type, relationship_type, created_by_user_id
         ) VALUES ($1,$2,$3,$4,$5,$6)`,
        [auth.session.tenant_id, row.id, target.reference, target.type, relationshipType, auth.session.user_id],
      )
    } catch (error) {
      if (error?.code !== '23505') throw error
    }
    await pool.query(
      `INSERT INTO itsm_record_activities (
         tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
       ) VALUES ($1,$2,$3,$4::jsonb,'relationship','internal',$5,$6::jsonb)`,
      [auth.session.tenant_id, row.id, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email }), `Linked ${target.reference}.`, JSON.stringify({ event: 'record.relationship.added', targetReference: target.reference, relationshipType })],
    )
    await pool.query('UPDATE itsm_records SET version = version + 1, updated_at = now() WHERE id = $1', [row.id])
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(await detailPayload(refreshed, auth.session.tenant_id), 201)
  })

  app.post('/api/v1/itsm-lifecycle/:reference/relationships/remove', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const relationshipId = text(body?.relationshipId, 80)
    await pool.query(
      `DELETE FROM itsm_record_relationships WHERE id = $1 AND tenant_id = $2 AND source_record_id = $3`,
      [relationshipId, auth.session.tenant_id, row.id],
    )
    await pool.query('UPDATE itsm_records SET version = version + 1, updated_at = now() WHERE id = $1', [row.id])
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(await detailPayload(refreshed, auth.session.tenant_id))
  })

  app.post('/api/v1/itsm-lifecycle/:reference/attachments', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const fileName = safeFileName(body?.fileName)
    const mimeType = text(body?.mimeType || 'application/octet-stream', 180) || 'application/octet-stream'
    const encoded = String(body?.contentBase64 || '').replace(/^data:[^;]+;base64,/, '')
    let content
    try { content = Buffer.from(encoded, 'base64') } catch { return c.json({ error: 'Attachment content is invalid.' }, 400) }
    if (!content.length) return c.json({ error: 'Choose a non-empty file.' }, 400)
    if (content.length > 5 * 1024 * 1024) return c.json({ error: 'Attachments are limited to 5 MB each.' }, 413)
    const sha256 = createHash('sha256').update(content).digest('hex')
    await pool.query(
      `INSERT INTO itsm_record_attachments (
         tenant_id, record_id, file_name, mime_type, byte_size, sha256, content,
         uploaded_by_user_id, uploaded_by_snapshot
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
      [auth.session.tenant_id, row.id, fileName, mimeType, content.length, sha256, content, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email })],
    )
    await pool.query(
      `INSERT INTO itsm_record_activities (
         tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
       ) VALUES ($1,$2,$3,$4::jsonb,'attachment','internal',$5,$6::jsonb)`,
      [auth.session.tenant_id, row.id, auth.session.user_id, JSON.stringify({ name: auth.session.name, email: auth.session.email }), `Attached ${fileName}.`, JSON.stringify({ event: 'record.attachment.added', fileName, byteSize: content.length, sha256 })],
    )
    await pool.query('UPDATE itsm_records SET version = version + 1, updated_at = now() WHERE id = $1', [row.id])
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(await detailPayload(refreshed, auth.session.tenant_id), 201)
  })

  app.get('/api/v1/itsm-lifecycle/:reference/attachments/:attachmentId', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    const result = await pool.query(
      `SELECT file_name, mime_type, content
       FROM itsm_record_attachments
       WHERE id = $1 AND tenant_id = $2 AND record_id = $3
       LIMIT 1`,
      [text(c.req.param('attachmentId'), 80), auth.session.tenant_id, row.id],
    )
    if (!result.rowCount) return c.json({ error: 'Attachment not found.' }, 404)
    const attachment = result.rows[0]
    return new Response(attachment.content, {
      status: 200,
      headers: {
        'Content-Type': attachment.mime_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${safeFileName(attachment.file_name).replace(/"/g, '')}"`,
        'Cache-Control': 'private, no-store',
      },
    })
  })

  app.post('/api/v1/itsm-lifecycle/:reference/attachments/remove', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const row = await lookupRecord(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'ITSM record not found.' }, 404)
    await pool.query(
      `DELETE FROM itsm_record_attachments WHERE id = $1 AND tenant_id = $2 AND record_id = $3`,
      [text(body?.attachmentId, 80), auth.session.tenant_id, row.id],
    )
    await pool.query('UPDATE itsm_records SET version = version + 1, updated_at = now() WHERE id = $1', [row.id])
    const refreshed = await lookupRecord(auth.session.tenant_id, row.reference)
    return c.json(await detailPayload(refreshed, auth.session.tenant_id))
  })
}
