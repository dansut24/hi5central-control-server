import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

const priorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const taskStatuses = new Set(['Waiting', 'Ready', 'In Progress', 'Completed', 'Blocked'])
const transitions = {
  New: new Set(['Pending Approval', 'In Progress']),
  'Pending Approval': new Set(['Approved']),
  Approved: new Set(['In Progress']),
  'In Progress': new Set(['Completed']),
  Completed: new Set(['Closed', 'In Progress']),
  Closed: new Set(),
  Rejected: new Set(),
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireSession(c, technician = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (technician && session.tenant_role === 'requester') {
    return { error: c.json({ error: 'Technician access is required.' }, 403) }
  }
  return { session }
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object || {}, key)
}

async function actorContext(db, session) {
  const result = await db.query(
    `SELECT id, external_key, name, email
     FROM organisation_people
     WHERE tenant_id = $1 AND user_id = $2
     LIMIT 1`,
    [session.tenant_id, session.user_id],
  )
  const person = result.rows[0] || null
  return {
    person,
    snapshot: {
      personId: person?.external_key || '',
      name: person?.name || session.name,
      email: person?.email || session.email,
    },
  }
}

async function findRequest(db, tenantId, reference, lock = false) {
  const result = await db.query(
    `SELECT * FROM service_requests
     WHERE tenant_id = $1 AND reference = $2
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, text(reference, 40).toUpperCase()],
  )
  return result.rows[0] || null
}

function requesterCanRead(session, row) {
  return session.tenant_role !== 'requester' || row.requester_user_id === session.user_id
}

async function resolveTeam(db, tenantId, value) {
  if (value === null || value === '') return null
  const query = text(value, 160)
  const result = await db.query(
    `SELECT id, external_key, name
     FROM organisation_teams
     WHERE tenant_id = $1 AND active = true
       AND (external_key = $2 OR lower(name) = lower($2))
     LIMIT 1`,
    [tenantId, query],
  )
  if (!result.rowCount) {
    const error = new Error('The selected fulfilment team does not exist in this tenant.')
    error.status = 400
    throw error
  }
  return result.rows[0]
}

async function resolvePerson(db, tenantId, value) {
  if (value === null || value === '' || value === 'Unassigned') return null
  const query = text(value, 254)
  const result = await db.query(
    `SELECT id, external_key, user_id, name, email
     FROM organisation_people
     WHERE tenant_id = $1 AND active = true
       AND (external_key = $2 OR lower(name) = lower($2) OR lower(email) = lower($2))
     LIMIT 1`,
    [tenantId, query],
  )
  if (!result.rowCount) {
    const error = new Error('The selected assignee does not exist in this tenant.')
    error.status = 400
    throw error
  }
  return result.rows[0]
}

function safeAttachments(value, visibility) {
  return asArray(value).slice(0, 20).map((attachment) => ({
    id: text(attachment?.id, 120),
    name: text(attachment?.name, 240),
    size: Math.max(0, Number(attachment?.size || 0)),
    type: text(attachment?.type, 160),
    visibility,
  }))
}

function operationalValues(input) {
  const allowedKeys = ['approvalNote', 'completionNotes', 'reopenReason']
  const output = {}
  for (const key of allowedKeys) {
    if (hasOwn(input, key)) output[key] = text(input[key], 10_000)
  }
  return output
}

async function insertActivity(db, { session, request, actor, kind, visibility, bodyText, bodyHtml = '', attachments = [], metadata = {} }) {
  const result = await db.query(
    `INSERT INTO service_request_activities (
       tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot,
       kind, visibility, body_text, body_html, attachments, metadata
     ) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10::jsonb,$11::jsonb)
     RETURNING *`,
    [
      session.tenant_id,
      request.id,
      session.user_id,
      actor.person?.id || null,
      JSON.stringify(actor.snapshot),
      kind,
      visibility,
      text(bodyText, 20_000),
      String(bodyHtml || '').slice(0, 100_000),
      JSON.stringify(safeAttachments(attachments, visibility)),
      JSON.stringify(asObject(metadata)),
    ],
  )
  return result.rows[0]
}

export function registerServiceRequestOperationRoutes(app) {
  app.patch('/api/v1/service-requests/:reference', async (c) => {
    const auth = await requireSession(c, true)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const changePriority = hasOwn(body, 'priority')
    const changeTeam = hasOwn(body, 'team') || hasOwn(body, 'teamId')
    const changeAssignee = hasOwn(body, 'assignee') || hasOwn(body, 'assigneeId')
    if (!changePriority && !changeTeam && !changeAssignee) {
      return c.json({ error: 'No supported Service Request fields were supplied.' }, 400)
    }
    if (changePriority && !priorities.has(body.priority)) {
      return c.json({ error: 'Priority must be Low, Medium, High or Critical.' }, 400)
    }

    try {
      const result = await withTransaction(async (client) => {
        const request = await findRequest(client, auth.session.tenant_id, c.req.param('reference'), true)
        if (!request) {
          const error = new Error('Service Request not found.')
          error.status = 404
          throw error
        }

        const team = changeTeam
          ? await resolveTeam(client, auth.session.tenant_id, body.teamId ?? body.team)
          : null
        const assignee = changeAssignee
          ? await resolvePerson(client, auth.session.tenant_id, body.assigneeId ?? body.assignee)
          : null

        await client.query(
          `UPDATE service_requests
           SET priority = CASE WHEN $2 THEN $3 ELSE priority END,
               fulfilment_team_id = CASE WHEN $4 THEN $5::uuid ELSE fulfilment_team_id END,
               fulfilment_team_snapshot = CASE WHEN $4 THEN $6::jsonb ELSE fulfilment_team_snapshot END,
               assigned_person_id = CASE WHEN $7 THEN $8::uuid ELSE assigned_person_id END,
               updated_at = now()
           WHERE id = $1`,
          [
            request.id,
            changePriority,
            changePriority ? body.priority : request.priority,
            changeTeam,
            team?.id || null,
            JSON.stringify(team ? { id: team.external_key, name: team.name } : {}),
            changeAssignee,
            assignee?.id || null,
          ],
        )

        const actor = await actorContext(client, auth.session)
        const descriptions = []
        if (changePriority && request.priority !== body.priority) descriptions.push(`priority to ${body.priority}`)
        if (changeTeam) descriptions.push(`fulfilment team to ${team?.name || 'Unassigned'}`)
        if (changeAssignee) descriptions.push(`assignee to ${assignee?.name || 'Unassigned'}`)
        if (descriptions.length) {
          await insertActivity(client, {
            session: auth.session,
            request,
            actor,
            kind: 'system',
            visibility: 'customer',
            bodyText: `${actor.snapshot.name} changed ${descriptions.join(' and ')}.`,
            metadata: { event: 'request.updated', fields: descriptions },
          })
        }

        return { reference: request.reference, updated: true }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/service-requests/:reference/transition', async (c) => {
    const auth = await requireSession(c, true)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const targetStatus = text(body?.targetStatus, 40)
    const values = asObject(body?.values)

    try {
      const result = await withTransaction(async (client) => {
        const request = await findRequest(client, auth.session.tenant_id, c.req.param('reference'), true)
        if (!request) {
          const error = new Error('Service Request not found.')
          error.status = 404
          throw error
        }
        if (!(transitions[request.status] || new Set()).has(targetStatus)) {
          const error = new Error(`${targetStatus || 'That status'} is not an allowed transition from ${request.status}.`)
          error.status = 409
          throw error
        }

        const pendingApprovalResult = await client.query(
          `SELECT * FROM service_request_approvals
           WHERE request_id = $1 AND status = 'Pending'
           ORDER BY sequence, created_at`,
          [request.id],
        )
        const pendingApprovals = pendingApprovalResult.rows

        if (request.status === 'New' && targetStatus === 'In Progress' && pendingApprovals.length) {
          const error = new Error('Required approvals must be completed before fulfilment can start.')
          error.status = 409
          throw error
        }
        if (targetStatus === 'Approved' && values.approvalConfirmation !== true) {
          const error = new Error('Confirm that the required approvals have been received.')
          error.status = 400
          throw error
        }
        if (targetStatus === 'Completed' && !text(values.completionNotes, 10_000)) {
          const error = new Error('Fulfilment summary is required before completion.')
          error.status = 400
          throw error
        }
        if (request.status === 'Completed' && targetStatus === 'In Progress' && !text(values.reopenReason, 10_000)) {
          const error = new Error('Reopen reason is required before fulfilment resumes.')
          error.status = 400
          throw error
        }

        const actor = await actorContext(client, auth.session)
        if (targetStatus === 'Approved' && pendingApprovals.length) {
          await client.query(
            `UPDATE service_request_approvals
             SET status = 'Approved',
                 decision_note = CASE WHEN $2 = '' THEN decision_note ELSE $2 END,
                 decided_at = COALESCE(decided_at, now()),
                 updated_at = now()
             WHERE request_id = $1 AND status = 'Pending'`,
            [request.id, text(values.approvalNote, 5000)],
          )
        }

        const operational = { ...asObject(request.operational_data), ...operationalValues(values) }
        await client.query(
          `UPDATE service_requests
           SET status = $2,
               operational_data = $3::jsonb,
               closed_at = CASE WHEN $2 = 'Closed' THEN now() ELSE closed_at END,
               updated_at = now()
           WHERE id = $1`,
          [request.id, targetStatus, JSON.stringify(operational)],
        )

        if (targetStatus === 'Approved') {
          await client.query(
            `UPDATE service_request_tasks
             SET status = 'Ready', updated_at = now()
             WHERE request_id = $1 AND status = 'Waiting'`,
            [request.id],
          )
        }

        const detail = targetStatus === 'Completed'
          ? text(values.completionNotes, 10_000)
          : request.status === 'Completed' && targetStatus === 'In Progress'
            ? text(values.reopenReason, 10_000)
            : targetStatus === 'Approved'
              ? text(values.approvalNote, 10_000)
              : ''
        await insertActivity(client, {
          session: auth.session,
          request,
          actor,
          kind: 'system',
          visibility: 'customer',
          bodyText: `Status changed from ${request.status} to ${targetStatus} by ${actor.snapshot.name}${detail ? ` — ${detail}` : ''}.`,
          metadata: { event: 'request.transitioned', from: request.status, to: targetStatus },
        })

        return { reference: request.reference, status: targetStatus }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/service-requests/:reference/activities', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const request = await findRequest(pool, auth.session.tenant_id, c.req.param('reference'))
    if (!request || !requesterCanRead(auth.session, request)) return c.json({ error: 'Service Request not found.' }, 404)

    const requestedKind = body?.kind === 'work' ? 'work' : 'customer'
    if (auth.session.tenant_role === 'requester' && requestedKind !== 'customer') {
      return c.json({ error: 'Requesters can only add customer-visible updates.' }, 403)
    }
    const visibility = requestedKind === 'work' ? 'internal' : 'customer'
    const bodyText = text(body?.text, 20_000)
    const bodyHtml = String(body?.html || '').slice(0, 100_000)
    const attachments = safeAttachments(body?.attachments, visibility)
    if (!bodyText && !bodyHtml && !attachments.length) return c.json({ error: 'Add a message or attachment.' }, 400)

    const result = await withTransaction(async (client) => {
      const locked = await findRequest(client, auth.session.tenant_id, request.reference, true)
      const actor = await actorContext(client, auth.session)
      const activity = await insertActivity(client, {
        session: auth.session,
        request: locked,
        actor,
        kind: requestedKind,
        visibility,
        bodyText,
        bodyHtml,
        attachments,
        metadata: { event: 'request.comment.added' },
      })
      await client.query('UPDATE service_requests SET updated_at = now() WHERE id = $1', [locked.id])
      return activity
    })

    return c.json({
      id: result.id,
      actor: asObject(result.actor_snapshot).name || auth.session.name,
      kind: result.kind,
      visibility: result.visibility,
      text: result.body_text,
      html: result.body_html,
      attachments: result.attachments || [],
      createdAt: result.created_at,
    }, 201)
  })

  app.patch('/api/v1/service-requests/:reference/tasks/:taskKey', async (c) => {
    const auth = await requireSession(c, true)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const changeStatus = hasOwn(body, 'status')
    const changeAssignee = hasOwn(body, 'assignee') || hasOwn(body, 'assigneeId')
    const changeTeam = hasOwn(body, 'team') || hasOwn(body, 'teamId')
    const changeCompletion = hasOwn(body, 'completionNotes')
    if (!changeStatus && !changeAssignee && !changeTeam && !changeCompletion) {
      return c.json({ error: 'No supported task fields were supplied.' }, 400)
    }
    if (changeStatus && !taskStatuses.has(body.status)) return c.json({ error: 'Unsupported task status.' }, 400)

    try {
      const result = await withTransaction(async (client) => {
        const request = await findRequest(client, auth.session.tenant_id, c.req.param('reference'), true)
        if (!request) {
          const error = new Error('Service Request not found.')
          error.status = 404
          throw error
        }
        const taskResult = await client.query(
          `SELECT * FROM service_request_tasks
           WHERE tenant_id = $1 AND request_id = $2 AND external_key = $3
           LIMIT 1 FOR UPDATE`,
          [auth.session.tenant_id, request.id, text(c.req.param('taskKey'), 160)],
        )
        if (!taskResult.rowCount) {
          const error = new Error('Service Request task not found.')
          error.status = 404
          throw error
        }
        const task = taskResult.rows[0]
        const assignee = changeAssignee
          ? await resolvePerson(client, auth.session.tenant_id, body.assigneeId ?? body.assignee)
          : null
        const team = changeTeam
          ? await resolveTeam(client, auth.session.tenant_id, body.teamId ?? body.team)
          : null

        await client.query(
          `UPDATE service_request_tasks
           SET status = CASE WHEN $2 THEN $3 ELSE status END,
               assignee_person_id = CASE WHEN $4 THEN $5::uuid ELSE assignee_person_id END,
               assignee_snapshot = CASE WHEN $4 THEN $6::jsonb ELSE assignee_snapshot END,
               team_id = CASE WHEN $7 THEN $8::uuid ELSE team_id END,
               team_snapshot = CASE WHEN $7 THEN $9::jsonb ELSE team_snapshot END,
               completion_notes = CASE WHEN $10 THEN $11 ELSE completion_notes END,
               completed_at = CASE WHEN $2 AND $3 = 'Completed' THEN now() WHEN $2 AND $3 <> 'Completed' THEN NULL ELSE completed_at END,
               updated_at = now()
           WHERE id = $1`,
          [
            task.id,
            changeStatus,
            changeStatus ? body.status : task.status,
            changeAssignee,
            assignee?.id || null,
            JSON.stringify(assignee ? { id: assignee.external_key, name: assignee.name, email: assignee.email } : {}),
            changeTeam,
            team?.id || null,
            JSON.stringify(team ? { id: team.external_key, name: team.name } : {}),
            changeCompletion,
            text(body?.completionNotes, 10_000),
          ],
        )
        await client.query('UPDATE service_requests SET updated_at = now() WHERE id = $1', [request.id])

        const actor = await actorContext(client, auth.session)
        await insertActivity(client, {
          session: auth.session,
          request,
          actor,
          kind: 'work',
          visibility: 'internal',
          bodyText: `${actor.snapshot.name} updated task ${task.external_key}${changeStatus ? ` to ${body.status}` : ''}.`,
          metadata: { event: 'request.task.updated', taskKey: task.external_key },
        })
        return { reference: request.reference, taskKey: task.external_key, updated: true }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })
}
