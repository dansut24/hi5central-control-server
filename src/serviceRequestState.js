import { effectiveAccessForUser, hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

const activeTaskStatuses = new Set(['Ready', 'In Progress', 'Blocked'])
const editableTaskStatuses = new Set([...activeTaskStatuses, 'Completed'])

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  return { session }
}

async function requireTaskPermission(c, permission) {
  const auth = await requireSession(c)
  if (auth.error) return auth
  if (auth.session.tenant_role === 'requester') {
    return { error: c.json({ error: 'Technician access is required.' }, 403) }
  }
  const access = auth.session.access || await effectiveAccessForUser(
    pool,
    auth.session.tenant_id,
    auth.session.user_id,
    auth.session.legacy_tenant_role || auth.session.tenant_role,
  )
  if (!hasPermission(access, permission)) {
    return { error: c.json({ error: 'You do not have permission to access Tasks.' }, 403) }
  }
  return auth
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function stateFromRow(row) {
  return {
    reference: row.reference,
    status: row.status,
    priority: row.priority,
    assignee: row.assignee_name || 'Unassigned',
    assigneeId: row.assignee_external_key || '',
    assigneeEmail: row.assignee_email || '',
    operationalData: row.operational_data || {},
    updatedAt: row.updated_at,
  }
}

function taskFromRow(row) {
  const requester = asObject(row.requester_snapshot)
  return {
    id: row.external_key,
    taskKey: row.external_key,
    title: row.title,
    status: row.status,
    team: row.team_name || asObject(row.team_snapshot).name || 'Unassigned',
    teamId: row.team_external_key || asObject(row.team_snapshot).id || '',
    assignee: row.assignee_name || asObject(row.assignee_snapshot).name || 'Unassigned',
    assigneeId: row.assignee_external_key || asObject(row.assignee_snapshot).id || '',
    assigneeEmail: row.assignee_email || asObject(row.assignee_snapshot).email || '',
    instructions: row.instructions || '',
    dependencies: Array.isArray(row.dependencies) ? row.dependencies : [],
    dueAt: row.due_at,
    completionNotes: row.completion_notes || '',
    completedAt: row.completed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    primaryRequest: {
      id: row.request_reference,
      title: row.request_title,
      status: row.request_status,
      priority: row.request_priority,
      service: row.request_service,
      requester: requester.name || '',
      requesterEmail: requester.email || '',
      team: asObject(row.request_team_snapshot).name || '',
    },
  }
}

const taskSelect = `
  SELECT
    t.*,
    r.reference AS request_reference,
    r.title AS request_title,
    r.status AS request_status,
    r.priority AS request_priority,
    r.service AS request_service,
    r.requester_snapshot,
    r.fulfilment_team_snapshot AS request_team_snapshot,
    team.external_key AS team_external_key,
    team.name AS team_name,
    assignee.external_key AS assignee_external_key,
    assignee.name AS assignee_name,
    assignee.email AS assignee_email
  FROM service_request_tasks t
  JOIN service_requests r ON r.id = t.request_id AND r.tenant_id = t.tenant_id
  LEFT JOIN organisation_teams team ON team.id = t.team_id
  LEFT JOIN organisation_people assignee ON assignee.id = t.assignee_person_id`

const dependenciesSatisfiedSql = `
  NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements_text(COALESCE(t.dependencies, '[]'::jsonb)) dependency(task_key)
    LEFT JOIN service_request_tasks predecessor
      ON predecessor.request_id = t.request_id
     AND predecessor.external_key = dependency.task_key
    WHERE predecessor.id IS NULL OR predecessor.status <> 'Completed'
  )`

async function taskByKey(db, tenantId, taskKey, lock = false) {
  const result = await db.query(
    `${taskSelect}
     WHERE t.tenant_id = $1 AND upper(t.external_key) = upper($2)
     ORDER BY t.created_at
     LIMIT 1${lock ? ' FOR UPDATE OF t, r' : ''}`,
    [tenantId, text(taskKey, 160)],
  )
  return result.rows[0] || null
}

async function dependenciesSatisfied(db, task) {
  const dependencies = Array.isArray(task.dependencies) ? task.dependencies : []
  if (!dependencies.length) return true
  const result = await db.query(
    `SELECT count(*)::int AS complete
     FROM service_request_tasks
     WHERE request_id = $1
       AND external_key = ANY($2::text[])
       AND status = 'Completed'`,
    [task.request_id, dependencies],
  )
  return Number(result.rows[0]?.complete || 0) === dependencies.length
}

async function resolveTaskTeam(db, tenantId, value) {
  if (value === null || value === '' || value === 'Unassigned') return null
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
    const error = new Error('The selected task team does not exist in this tenant.')
    error.status = 400
    throw error
  }
  return result.rows[0]
}

async function resolveTaskAssignee(db, tenantId, value) {
  if (value === null || value === '' || value === 'Unassigned') return null
  const query = text(value, 254)
  const result = await db.query(
    `SELECT id, external_key, name, email
     FROM organisation_people
     WHERE tenant_id = $1 AND active = true
       AND (external_key = $2 OR lower(name) = lower($2) OR lower(email) = lower($2))
     LIMIT 1`,
    [tenantId, query],
  )
  if (!result.rowCount) {
    const error = new Error('The selected task assignee does not exist in this tenant.')
    error.status = 400
    throw error
  }
  return result.rows[0]
}

async function actorSnapshot(db, session) {
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
      name: person?.name || session.name || 'Hi5Central',
      email: person?.email || session.email || '',
    },
  }
}

async function unlockReadyTasks(db, requestId) {
  await db.query(
    `UPDATE service_request_tasks candidate
     SET status = 'Ready', updated_at = now()
     WHERE candidate.request_id = $1
       AND candidate.status = 'Waiting'
       AND NOT EXISTS (
         SELECT 1
         FROM jsonb_array_elements_text(COALESCE(candidate.dependencies, '[]'::jsonb)) dependency(task_key)
         LEFT JOIN service_request_tasks predecessor
           ON predecessor.request_id = candidate.request_id
          AND predecessor.external_key = dependency.task_key
         WHERE predecessor.id IS NULL OR predecessor.status <> 'Completed'
       )`,
    [requestId],
  )
}

export function registerServiceRequestStateRoutes(app) {
  app.get('/api/v1/service-request-state', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    const values = [auth.session.tenant_id]
    const requesterClause = auth.session.tenant_role === 'requester' ? 'AND r.requester_user_id = $2' : ''
    if (auth.session.tenant_role === 'requester') values.push(auth.session.user_id)

    const result = await pool.query(
      `SELECT
         r.reference,
         r.status,
         r.priority,
         r.operational_data,
         r.updated_at,
         p.external_key AS assignee_external_key,
         p.name AS assignee_name,
         p.email AS assignee_email
       FROM service_requests r
       LEFT JOIN organisation_people p ON p.id = r.assigned_person_id
       WHERE r.tenant_id = $1 ${requesterClause}
       ORDER BY r.updated_at DESC`,
      values,
    )

    return c.json({ items: result.rows.map(stateFromRow) })
  })

  app.get('/api/v1/service-request-state/:reference', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    const values = [auth.session.tenant_id, text(c.req.param('reference'), 40).toUpperCase()]
    const requesterClause = auth.session.tenant_role === 'requester' ? 'AND r.requester_user_id = $3' : ''
    if (auth.session.tenant_role === 'requester') values.push(auth.session.user_id)

    const result = await pool.query(
      `SELECT
         r.reference,
         r.status,
         r.priority,
         r.operational_data,
         r.updated_at,
         p.external_key AS assignee_external_key,
         p.name AS assignee_name,
         p.email AS assignee_email
       FROM service_requests r
       LEFT JOIN organisation_people p ON p.id = r.assigned_person_id
       WHERE r.tenant_id = $1 AND r.reference = $2 ${requesterClause}
       LIMIT 1`,
      values,
    )

    if (!result.rowCount) return c.json({ error: 'Service Request not found.' }, 404)
    return c.json(stateFromRow(result.rows[0]))
  })

  app.get('/api/v1/tasks', async (c) => {
    const auth = await requireTaskPermission(c, 'itsm.tasks.view')
    if (auth.error) return auth.error

    const status = text(c.req.query('status'), 40)
    if (status === 'Waiting') return c.json({ error: 'Waiting workflow steps are not exposed in the Tasks queue.' }, 400)
    if (status && status !== 'All' && !editableTaskStatuses.has(status)) return c.json({ error: 'Unsupported task status.' }, 400)

    const limit = Math.max(1, Math.min(200, Number(c.req.query('limit') || 50)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))
    const values = [auth.session.tenant_id]
    const clauses = ['t.tenant_id = $1', "t.status <> 'Waiting'"]
    const add = (sql, value) => {
      values.push(value)
      const parameter = `$${values.length}`
      clauses.push(sql.replace(/\?/g, parameter))
    }

    if (status && status !== 'All') add('t.status = ?', status)
    else clauses.push("t.status IN ('Ready','In Progress','Blocked')")

    const activeOnly = !status || status === 'All' || activeTaskStatuses.has(status)
    if (activeOnly) {
      clauses.push("r.status NOT IN ('Pending Approval','Rejected','Closed')")
      clauses.push(dependenciesSatisfiedSql)
    }

    const search = text(c.req.query('search'), 200)
    if (search) add("(t.external_key ILIKE '%' || ? || '%' OR t.title ILIKE '%' || ? || '%' OR r.reference ILIKE '%' || ? || '%' OR r.title ILIKE '%' || ? || '%')", search)
    const team = text(c.req.query('team'), 160)
    if (team && team !== 'All') {
      if (team === 'Unassigned') clauses.push("COALESCE(team.name, t.team_snapshot->>'name', '') = ''")
      else add("COALESCE(team.name, t.team_snapshot->>'name', '') = ?", team)
    }
    const assignee = text(c.req.query('assignee'), 254)
    if (assignee && assignee !== 'All') {
      if (assignee === 'Unassigned') clauses.push('t.assignee_person_id IS NULL')
      else add("COALESCE(assignee.name, t.assignee_snapshot->>'name', '') = ?", assignee)
    }
    const service = text(c.req.query('service'), 160)
    if (service && service !== 'All') add('r.service = ?', service)

    values.push(limit, offset)
    const result = await pool.query(
      `${taskSelect}
       WHERE ${clauses.join(' AND ')}
       ORDER BY CASE t.status WHEN 'In Progress' THEN 0 WHEN 'Ready' THEN 1 WHEN 'Blocked' THEN 2 ELSE 3 END,
                t.due_at NULLS LAST, t.updated_at DESC
       LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values,
    )

    const countValues = values.slice(0, -2)
    const count = await pool.query(
      `SELECT count(*)::int AS total
       FROM service_request_tasks t
       JOIN service_requests r ON r.id = t.request_id AND r.tenant_id = t.tenant_id
       LEFT JOIN organisation_teams team ON team.id = t.team_id
       LEFT JOIN organisation_people assignee ON assignee.id = t.assignee_person_id
       WHERE ${clauses.join(' AND ')}`,
      countValues,
    )

    const filters = await pool.query(
      `SELECT
         array_remove(array_agg(DISTINCT COALESCE(team.name, t.team_snapshot->>'name')), NULL) AS teams,
         array_remove(array_agg(DISTINCT COALESCE(assignee.name, t.assignee_snapshot->>'name')), NULL) AS assignees,
         array_remove(array_agg(DISTINCT r.service), NULL) AS services
       FROM service_request_tasks t
       JOIN service_requests r ON r.id = t.request_id AND r.tenant_id = t.tenant_id
       LEFT JOIN organisation_teams team ON team.id = t.team_id
       LEFT JOIN organisation_people assignee ON assignee.id = t.assignee_person_id
       WHERE t.tenant_id = $1 AND t.status <> 'Waiting'`,
      [auth.session.tenant_id],
    )

    return c.json({
      items: result.rows.map(taskFromRow),
      total: Number(count.rows[0]?.total || 0),
      filters: {
        statuses: ['Ready', 'In Progress', 'Blocked', 'Completed'],
        teams: filters.rows[0]?.teams || [],
        assignees: filters.rows[0]?.assignees || [],
        services: filters.rows[0]?.services || [],
      },
    })
  })

  app.get('/api/v1/tasks/:taskKey', async (c) => {
    const auth = await requireTaskPermission(c, 'itsm.tasks.view')
    if (auth.error) return auth.error
    const task = await taskByKey(pool, auth.session.tenant_id, c.req.param('taskKey'))
    if (!task || task.status === 'Waiting') return c.json({ error: 'Task not found or not ready yet.' }, 404)
    if (activeTaskStatuses.has(task.status)) {
      if (['Pending Approval', 'Rejected', 'Closed'].includes(task.request_status)) return c.json({ error: 'Task not found or not ready yet.' }, 404)
      if (!await dependenciesSatisfied(pool, task)) return c.json({ error: 'Task not found or not ready yet.' }, 404)
    }
    return c.json(taskFromRow(task))
  })

  app.patch('/api/v1/tasks/:taskKey', async (c) => {
    const auth = await requireTaskPermission(c, 'itsm.tasks.manage')
    if (auth.error) return auth.error

    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const changeStatus = Object.prototype.hasOwnProperty.call(body, 'status')
    const changeTeam = Object.prototype.hasOwnProperty.call(body, 'team') || Object.prototype.hasOwnProperty.call(body, 'teamId')
    const changeAssignee = Object.prototype.hasOwnProperty.call(body, 'assignee') || Object.prototype.hasOwnProperty.call(body, 'assigneeId')
    const changeCompletion = Object.prototype.hasOwnProperty.call(body, 'completionNotes')
    if (!changeStatus && !changeTeam && !changeAssignee && !changeCompletion) return c.json({ error: 'No supported task fields were supplied.' }, 400)
    if (changeStatus && !editableTaskStatuses.has(body.status)) return c.json({ error: 'Unsupported task status.' }, 400)

    try {
      const result = await withTransaction(async (client) => {
        const task = await taskByKey(client, auth.session.tenant_id, c.req.param('taskKey'), true)
        if (!task || task.status === 'Waiting') {
          const error = new Error('Task not found or not ready yet.')
          error.status = 404
          throw error
        }
        if (['Pending Approval', 'Rejected', 'Closed'].includes(task.request_status)) {
          const error = new Error('This task is not available while its primary request is awaiting approval or closed.')
          error.status = 409
          throw error
        }
        if (!await dependenciesSatisfied(client, task)) {
          const error = new Error('This task is waiting for its earlier tasks to be completed.')
          error.status = 409
          throw error
        }
        if (task.status === 'Completed' && changeStatus && body.status !== 'Completed') {
          const error = new Error('Completed tasks cannot be reopened from the Tasks queue.')
          error.status = 409
          throw error
        }

        const actor = await actorSnapshot(client, auth.session)
        if ((changeStatus || changeCompletion) && (!actor.person?.id || task.assignee_person_id !== actor.person.id)) {
          const error = new Error('Take this task before starting, blocking or completing work.')
          error.status = 409
          throw error
        }

        const team = changeTeam ? await resolveTaskTeam(client, auth.session.tenant_id, body.teamId ?? body.team) : null
        const assignee = changeAssignee ? await resolveTaskAssignee(client, auth.session.tenant_id, body.assigneeId ?? body.assignee) : null
        const completionNotes = changeCompletion ? text(body.completionNotes, 10_000) : task.completion_notes
        if (changeStatus && body.status === 'Completed' && !text(completionNotes, 10_000)) {
          const error = new Error('Completion notes are required before a task can be completed.')
          error.status = 400
          throw error
        }

        await client.query(
          `UPDATE service_request_tasks
           SET status = CASE WHEN $2 THEN $3 ELSE status END,
               team_id = CASE WHEN $4 THEN $5::uuid ELSE team_id END,
               team_snapshot = CASE WHEN $4 THEN $6::jsonb ELSE team_snapshot END,
               assignee_person_id = CASE WHEN $7 THEN $8::uuid ELSE assignee_person_id END,
               assignee_snapshot = CASE WHEN $7 THEN $9::jsonb ELSE assignee_snapshot END,
               completion_notes = CASE WHEN $10 THEN $11 ELSE completion_notes END,
               completed_at = CASE WHEN $2 AND $3 = 'Completed' THEN now() WHEN $2 AND $3 <> 'Completed' THEN NULL ELSE completed_at END,
               updated_at = now()
           WHERE id = $1`,
          [
            task.id,
            changeStatus,
            changeStatus ? body.status : task.status,
            changeTeam,
            team?.id || null,
            JSON.stringify(team ? { id: team.external_key, name: team.name } : {}),
            changeAssignee,
            assignee?.id || null,
            JSON.stringify(assignee ? { id: assignee.external_key, name: assignee.name, email: assignee.email } : {}),
            changeCompletion,
            text(completionNotes, 10_000),
          ],
        )
        await client.query('UPDATE service_requests SET updated_at = now() WHERE id = $1', [task.request_id])

        await client.query(
          `INSERT INTO service_request_activities (
             tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot,
             kind, visibility, body_text, metadata
           ) VALUES ($1,$2,$3,$4,$5::jsonb,'work','internal',$6,$7::jsonb)`,
          [
            auth.session.tenant_id,
            task.request_id,
            auth.session.user_id,
            actor.person?.id || null,
            JSON.stringify(actor.snapshot),
            `${actor.snapshot.name} updated task ${task.external_key}${changeStatus ? ` to ${body.status}` : ''}.`,
            JSON.stringify({ event: 'request.task.updated', taskKey: task.external_key }),
          ],
        )

        if (changeStatus && body.status === 'Completed') await unlockReadyTasks(client, task.request_id)
        const updated = await taskByKey(client, auth.session.tenant_id, task.external_key)
        return taskFromRow(updated)
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })
}
