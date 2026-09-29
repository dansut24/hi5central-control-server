import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

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

async function recordFor(client, tenantId, reference, lock = false) {
  const result = await client.query(
    `SELECT * FROM itsm_records
     WHERE tenant_id = $1 AND upper(reference) = upper($2)
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, text(reference, 80)],
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

async function personByName(client, tenantId, name) {
  const value = text(name, 180)
  if (!value || value === 'Unassigned') return null
  const result = await client.query(
    `SELECT id, external_key, name, email, job_title
     FROM organisation_people
     WHERE tenant_id = $1
       AND active = true
       AND (name = $2 OR lower(email) = lower($2))
     LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

function teamSnapshot(team, fallback = '') {
  return { id: team?.external_key || '', name: team?.name || fallback }
}

function personSnapshot(person) {
  return person
    ? { id: person.external_key, name: person.name, email: person.email, jobTitle: person.job_title || '' }
    : { id: '', name: 'Unassigned', email: '' }
}

function actorSnapshot(session) {
  return { name: session.name || 'Technician', email: session.email || '' }
}

function safeRichHtml(value = '') {
  let html = String(value || '').slice(0, 50000)
  if (!html) return ''
  html = html.replace(/<(script|style|iframe|object|embed|form|svg|math)[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
  html = html.replace(/<\/?(script|style|iframe|object|embed|form|input|button|svg|math|meta|link)[^>]*>/gi, '')
  html = html.replace(/\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
  html = html.replace(/\s+(style|src|srcdoc)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
  html = html.replace(/href\s*=\s*(["'])\s*(javascript:|data:)[\s\S]*?\1/gi, 'href="#"')
  return html.slice(0, 45000)
}

function activityMetadata(body, extra = {}) {
  const metadata = object(body?.metadata)
  const richHtml = safeRichHtml(metadata.richHtml || body?.richHtml || '')
  return {
    ...metadata,
    ...extra,
    ...(richHtml ? { richHtml, format: 'rich' } : {}),
  }
}

async function addActivity(client, { tenantId, recordId, session, kind, visibility = 'internal', bodyText, metadata = {} }) {
  await client.query(
    `INSERT INTO itsm_record_activities (
       tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
     ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8::jsonb)`,
    [
      tenantId,
      recordId,
      session.user_id,
      JSON.stringify(actorSnapshot(session)),
      kind,
      visibility === 'customer' ? 'customer' : 'internal',
      text(bodyText, 20000),
      JSON.stringify(metadata),
    ],
  )
}

function expectedVersion(body) {
  const value = Number(body?.version)
  return Number.isInteger(value) && value > 0 ? value : null
}

async function parseJson(c) {
  try { return await c.req.json() } catch { return null }
}

function conflictResponse(c, current) {
  return c.json({
    error: 'This record was changed by another technician. Reload the latest version before applying this action.',
    conflict: true,
    currentVersion: Number(current?.version || 1),
  }, 409)
}

export function registerItsmActionRoutes(app) {
  app.post('/api/v1/itsm-actions/:reference/reassign', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseJson(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const version = expectedVersion(body)
    if (!version) return c.json({ error: 'A valid record version is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const current = await recordFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!current) return { notFound: true }
      if (Number(current.version || 1) !== version) return { conflict: true, current }

      const requestedTeam = text(body.team, 160)
      const requestedAssignee = text(body.assignee || 'Unassigned', 180) || 'Unassigned'
      const team = requestedTeam ? await teamByName(client, auth.session.tenant_id, requestedTeam) : null
      if (requestedTeam && !team) return { invalidTeam: true }
      const assignee = requestedAssignee !== 'Unassigned' ? await personByName(client, auth.session.tenant_id, requestedAssignee) : null
      if (requestedAssignee !== 'Unassigned' && !assignee) return { invalidAssignee: true }

      const fromTeam = object(current.assignment_team_snapshot).name || 'Unassigned'
      const fromAssignee = object(current.assignee_snapshot).name || 'Unassigned'
      const toTeam = team?.name || 'Unassigned'
      const toAssignee = assignee?.name || 'Unassigned'
      const note = text(body.note, 20000)

      const updated = await client.query(
        `UPDATE itsm_records
         SET assignment_team_id = $3,
             assignment_team_snapshot = $4::jsonb,
             assigned_person_id = $5,
             assignee_snapshot = $6::jsonb,
             version = version + 1,
             updated_at = now()
         WHERE tenant_id = $1 AND id = $2
         RETURNING reference, version`,
        [
          auth.session.tenant_id,
          current.id,
          team?.id || null,
          JSON.stringify(teamSnapshot(team, toTeam)),
          assignee?.id || null,
          JSON.stringify(personSnapshot(assignee)),
        ],
      )

      await addActivity(client, {
        tenantId: auth.session.tenant_id,
        recordId: current.id,
        session: auth.session,
        kind: 'reassign',
        visibility: 'internal',
        bodyText: note || `Reassigned from ${fromTeam} / ${fromAssignee} to ${toTeam} / ${toAssignee}.`,
        metadata: activityMetadata(body, {
          action: 'reassign',
          changes: [
            { field: 'team', from: fromTeam, to: toTeam },
            { field: 'assignee', from: fromAssignee, to: toAssignee },
          ],
        }),
      })
      return { updated: updated.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.invalidTeam) return c.json({ error: 'Choose an active assignment group from this tenant.' }, 400)
    if (result.invalidAssignee) return c.json({ error: 'Choose an active assignee from this tenant.' }, 400)
    if (result.conflict) return conflictResponse(c, result.current)
    return c.json({ ok: true, reference: result.updated.reference, version: Number(result.updated.version) })
  })

  app.post('/api/v1/itsm-actions/:reference/resolve', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseJson(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const version = expectedVersion(body)
    if (!version) return c.json({ error: 'A valid record version is required.' }, 400)
    const note = text(body.note, 20000)
    if (note.length < 3) return c.json({ error: 'Add resolution notes before resolving this record.' }, 400)

    const result = await withTransaction(async (client) => {
      const current = await recordFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!current) return { notFound: true }
      if (Number(current.version || 1) !== version) return { conflict: true, current }
      if (['Resolved', 'Closed', 'Completed', 'Cancelled'].includes(current.status)) return { alreadyFinal: true }

      const targetStatus = current.record_type === 'Change' ? 'Completed' : 'Resolved'
      const resolutionCode = current.record_type === 'Incident' ? text(body.resolutionCode, 120) : ''
      if (current.record_type === 'Incident' && !resolutionCode) return { resolutionCodeRequired: true }
      const visibility = body.visibility === 'customer' ? 'customer' : 'internal'

      let pausedSeconds = Number(current.sla_paused_seconds || 0)
      let responseDueAt = current.response_due_at
      let resolutionDueAt = current.resolution_due_at
      if (current.record_type === 'Incident' && current.sla_paused_at) {
        const deltaSeconds = Math.max(0, Math.floor((Date.now() - new Date(current.sla_paused_at).getTime()) / 1000))
        pausedSeconds += deltaSeconds
        responseDueAt = responseDueAt ? new Date(new Date(responseDueAt).getTime() + deltaSeconds * 1000) : null
        resolutionDueAt = resolutionDueAt ? new Date(new Date(resolutionDueAt).getTime() + deltaSeconds * 1000) : null
      }

      const updated = await client.query(
        `UPDATE itsm_records
         SET status = $3,
             resolution_code = CASE WHEN record_type = 'Incident' THEN $4 ELSE resolution_code END,
             resolution_summary = CASE WHEN record_type = 'Incident' THEN $5 ELSE resolution_summary END,
             first_response_at = CASE WHEN $6 = 'customer' THEN COALESCE(first_response_at, now()) ELSE first_response_at END,
             response_due_at = $7,
             resolution_due_at = $8,
             sla_paused_seconds = $9,
             resolved_at = COALESCE(resolved_at, now()),
             closed_at = CASE WHEN $3 = 'Completed' THEN COALESCE(closed_at, now()) ELSE closed_at END,
             sla_paused_at = NULL,
             version = version + 1,
             updated_at = now()
         WHERE tenant_id = $1 AND id = $2
         RETURNING reference, version`,
        [auth.session.tenant_id, current.id, targetStatus, resolutionCode, note, visibility, responseDueAt, resolutionDueAt, pausedSeconds],
      )

      await addActivity(client, {
        tenantId: auth.session.tenant_id,
        recordId: current.id,
        session: auth.session,
        kind: 'resolution',
        visibility,
        bodyText: note,
        metadata: activityMetadata(body, {
          action: 'resolve',
          fromStatus: current.status,
          toStatus: targetStatus,
          resolutionCode: resolutionCode || null,
        }),
      })
      return { updated: updated.rows[0], targetStatus }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.alreadyFinal) return c.json({ error: 'This record is already in a final state.' }, 409)
    if (result.resolutionCodeRequired) return c.json({ error: 'Choose a resolution code before resolving this Incident.' }, 400)
    if (result.conflict) return conflictResponse(c, result.current)
    return c.json({ ok: true, reference: result.updated.reference, version: Number(result.updated.version), status: result.targetStatus })
  })

  app.post('/api/v1/itsm-actions/:reference/pending', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseJson(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const version = expectedVersion(body)
    if (!version) return c.json({ error: 'A valid record version is required.' }, 400)
    const targetStatus = ['Pending Customer', 'Pending Vendor'].includes(body.status) ? body.status : null
    if (!targetStatus) return c.json({ error: 'Choose Pending Customer or Pending Vendor.' }, 400)
    const note = text(body.note, 20000)
    if (note.length < 2) return c.json({ error: 'Add a reason before setting the Incident to pending.' }, 400)

    const result = await withTransaction(async (client) => {
      const current = await recordFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!current) return { notFound: true }
      if (Number(current.version || 1) !== version) return { conflict: true, current }
      if (current.record_type !== 'Incident') return { incidentOnly: true }
      if (['Resolved', 'Closed'].includes(current.status)) return { alreadyFinal: true }
      const visibility = body.visibility === 'customer' ? 'customer' : 'internal'

      const updated = await client.query(
        `UPDATE itsm_records
         SET status = $3,
             first_response_at = CASE WHEN $4 = 'customer' THEN COALESCE(first_response_at, now()) ELSE first_response_at END,
             sla_paused_at = COALESCE(sla_paused_at, now()),
             version = version + 1,
             updated_at = now()
         WHERE tenant_id = $1 AND id = $2
         RETURNING reference, version`,
        [auth.session.tenant_id, current.id, targetStatus, visibility],
      )

      await addActivity(client, {
        tenantId: auth.session.tenant_id,
        recordId: current.id,
        session: auth.session,
        kind: 'pending',
        visibility,
        bodyText: note,
        metadata: activityMetadata(body, {
          action: 'pending',
          fromStatus: current.status,
          toStatus: targetStatus,
        }),
      })
      return { updated: updated.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.incidentOnly) return c.json({ error: 'Pending customer/vendor is currently available for Incidents only.' }, 400)
    if (result.alreadyFinal) return c.json({ error: 'Reopen the Incident before setting it to pending.' }, 409)
    if (result.conflict) return conflictResponse(c, result.current)
    return c.json({ ok: true, reference: result.updated.reference, version: Number(result.updated.version), status: targetStatus })
  })

  app.get('/api/v1/itsm-actions/:reference/tasks', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const record = await recordFor(pool, auth.session.tenant_id, c.req.param('reference'))
    if (!record) return c.json({ error: 'ITSM record not found.' }, 404)
    const result = await pool.query(
      `SELECT id, title, status, team_snapshot, assignee_snapshot, instructions, due_at, created_by_snapshot, completed_at, created_at, updated_at
       FROM itsm_record_tasks
       WHERE tenant_id = $1 AND record_id = $2
       ORDER BY created_at DESC`,
      [auth.session.tenant_id, record.id],
    )
    return c.json({
      tasks: result.rows.map((row) => ({
        id: row.id,
        title: row.title,
        status: row.status,
        team: object(row.team_snapshot).name || '',
        assignee: object(row.assignee_snapshot).name || 'Unassigned',
        instructions: row.instructions,
        dueAt: row.due_at,
        createdBy: object(row.created_by_snapshot).name || 'Technician',
        completedAt: row.completed_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    })
  })

  app.post('/api/v1/itsm-actions/:reference/tasks', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseJson(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const version = expectedVersion(body)
    if (!version) return c.json({ error: 'A valid record version is required.' }, 400)
    const title = text(body.title, 240)
    if (title.length < 2) return c.json({ error: 'Add a task title.' }, 400)
    const instructions = text(body.instructions || body.note, 20000)
    const requestedTeam = text(body.team, 160)
    const requestedAssignee = text(body.assignee || 'Unassigned', 180) || 'Unassigned'
    const dueAt = body.dueAt ? new Date(body.dueAt) : null
    if (dueAt && Number.isNaN(dueAt.getTime())) return c.json({ error: 'Choose a valid task due date.' }, 400)

    const result = await withTransaction(async (client) => {
      const current = await recordFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!current) return { notFound: true }
      if (Number(current.version || 1) !== version) return { conflict: true, current }
      const team = requestedTeam ? await teamByName(client, auth.session.tenant_id, requestedTeam) : null
      if (requestedTeam && !team) return { invalidTeam: true }
      const assignee = requestedAssignee !== 'Unassigned' ? await personByName(client, auth.session.tenant_id, requestedAssignee) : null
      if (requestedAssignee !== 'Unassigned' && !assignee) return { invalidAssignee: true }

      const created = await client.query(
        `INSERT INTO itsm_record_tasks (
           tenant_id, record_id, title, status, team_id, team_snapshot,
           assignee_person_id, assignee_snapshot, instructions, due_at,
           created_by_user_id, created_by_snapshot
         ) VALUES ($1,$2,$3,'Open',$4,$5::jsonb,$6,$7::jsonb,$8,$9,$10,$11::jsonb)
         RETURNING id, title, status, due_at, created_at`,
        [
          auth.session.tenant_id,
          current.id,
          title,
          team?.id || null,
          JSON.stringify(teamSnapshot(team, requestedTeam)),
          assignee?.id || null,
          JSON.stringify(personSnapshot(assignee)),
          instructions,
          dueAt,
          auth.session.user_id,
          JSON.stringify(actorSnapshot(auth.session)),
        ],
      )

      await client.query(
        `UPDATE itsm_records SET version = version + 1, updated_at = now()
         WHERE tenant_id = $1 AND id = $2`,
        [auth.session.tenant_id, current.id],
      )

      await addActivity(client, {
        tenantId: auth.session.tenant_id,
        recordId: current.id,
        session: auth.session,
        kind: 'task',
        visibility: 'internal',
        bodyText: instructions || `Task created: ${title}`,
        metadata: activityMetadata(body, {
          action: 'task_created',
          taskId: created.rows[0].id,
          title,
          team: team?.name || 'Unassigned',
          assignee: assignee?.name || 'Unassigned',
          dueAt: dueAt ? dueAt.toISOString() : null,
        }),
      })
      return { created: created.rows[0] }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.invalidTeam) return c.json({ error: 'Choose an active assignment group from this tenant.' }, 400)
    if (result.invalidAssignee) return c.json({ error: 'Choose an active assignee from this tenant.' }, 400)
    if (result.conflict) return conflictResponse(c, result.current)
    return c.json({
      task: {
        id: result.created.id,
        title: result.created.title,
        status: result.created.status,
        dueAt: result.created.due_at,
        createdAt: result.created.created_at,
      },
    }, 201)
  })
}
