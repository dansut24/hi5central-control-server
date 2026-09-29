import { effectiveAccessForUser, hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

const queueScopes = new Set(['mine', 'team', 'unassigned', 'blocked', 'all', 'completed'])
const queueStatuses = new Set(['Ready', 'In Progress', 'Blocked', 'Completed'])
const queueDueFilters = new Set(['Overdue', 'Next 24 hours', 'Next 7 days', 'No due date'])

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

async function requireTaskAccess(c, permission) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (session.tenant_role === 'requester') {
    return { error: c.json({ error: 'Technician access is required.' }, 403) }
  }
  const access = session.access || await effectiveAccessForUser(
    pool,
    session.tenant_id,
    session.user_id,
    session.legacy_tenant_role || session.tenant_role,
  )
  if (!hasPermission(access, permission)) {
    return { error: c.json({ error: 'You do not have permission to access Tasks.' }, 403) }
  }
  return { session }
}

async function requireTaskManager(c) {
  return requireTaskAccess(c, 'itsm.tasks.manage')
}

async function taskViewer(db, session) {
  const result = await db.query(
    `SELECT
       p.id,
       p.external_key,
       p.name,
       p.email,
       COALESCE(array_agg(DISTINCT membership.team_id) FILTER (WHERE membership.team_id IS NOT NULL), ARRAY[]::uuid[]) AS team_ids,
       COALESCE(array_agg(DISTINCT team.name) FILTER (WHERE team.name IS NOT NULL), ARRAY[]::text[]) AS team_names
     FROM organisation_people p
     LEFT JOIN organisation_team_memberships membership
       ON membership.tenant_id = p.tenant_id
      AND membership.person_id = p.id
     LEFT JOIN organisation_teams team
       ON team.id = membership.team_id
      AND team.tenant_id = p.tenant_id
      AND team.active = true
     WHERE p.tenant_id = $1
       AND p.user_id = $2
       AND p.active = true
     GROUP BY p.id, p.external_key, p.name, p.email
     LIMIT 1`,
    [session.tenant_id, session.user_id],
  )
  return result.rows[0] || null
}

function queueTaskFromRow(row) {
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

const queueTaskSelect = `
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

const queueDependenciesSatisfiedSql = `
  NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements_text(COALESCE(t.dependencies, '[]'::jsonb)) dependency(task_key)
    LEFT JOIN service_request_tasks predecessor
      ON predecessor.request_id = t.request_id
     AND predecessor.external_key = dependency.task_key
    WHERE predecessor.id IS NULL OR predecessor.status <> 'Completed'
  )`

async function lockedTask(db, tenantId, taskKey) {
  const result = await db.query(
    `SELECT
       t.id,
       t.request_id,
       t.external_key,
       t.title,
       t.status,
       t.team_id,
       t.team_snapshot,
       t.assignee_person_id,
       t.assignee_snapshot,
       t.dependencies,
       r.status AS request_status,
       team.external_key AS team_external_key,
       team.name AS team_name
     FROM service_request_tasks t
     JOIN service_requests r
       ON r.id = t.request_id
      AND r.tenant_id = t.tenant_id
     LEFT JOIN organisation_teams team ON team.id = t.team_id
     WHERE t.tenant_id = $1
       AND upper(t.external_key) = upper($2)
     LIMIT 1
     FOR UPDATE OF t, r`,
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

async function personForUser(db, session) {
  const result = await db.query(
    `SELECT id, external_key, name, email
     FROM organisation_people
     WHERE tenant_id = $1
       AND user_id = $2
       AND active = true
     LIMIT 1`,
    [session.tenant_id, session.user_id],
  )
  return result.rows[0] || null
}

async function eligibleTechnician(db, session, teamId) {
  if (!teamId) return null
  const result = await db.query(
    `SELECT p.id, p.external_key, p.name, p.email
     FROM organisation_people p
     JOIN tenant_memberships membership
       ON membership.tenant_id = p.tenant_id
      AND membership.user_id = p.user_id
      AND membership.status = 'active'
     JOIN organisation_team_memberships team_membership
       ON team_membership.tenant_id = p.tenant_id
      AND team_membership.person_id = p.id
      AND team_membership.team_id = $3
     WHERE p.tenant_id = $1
       AND p.user_id = $2
       AND p.active = true
     LIMIT 1`,
    [session.tenant_id, session.user_id, teamId],
  )
  return result.rows[0] || null
}

function personSnapshot(person, session) {
  return {
    id: person?.external_key || '',
    name: person?.name || session.name || 'Hi5Central',
    email: person?.email || session.email || '',
  }
}

async function addActivity(db, session, task, person, event, body) {
  await db.query(
    `INSERT INTO service_request_activities (
       tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot,
       kind, visibility, body_text, metadata
     ) VALUES ($1,$2,$3,$4,$5::jsonb,'work','internal',$6,$7::jsonb)`,
    [
      session.tenant_id,
      task.request_id,
      session.user_id,
      person?.id || null,
      JSON.stringify({
        personId: person?.external_key || '',
        name: person?.name || session.name || 'Hi5Central',
        email: person?.email || session.email || '',
      }),
      body,
      JSON.stringify({ event, taskKey: task.external_key }),
    ],
  )
}

function ensureTakeable(task) {
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
  if (task.status !== 'Ready') {
    const error = new Error('Only Ready tasks can be taken or released.')
    error.status = 409
    throw error
  }
}

export function registerTaskOwnershipRoutes(app) {
  app.get('/api/v1/task-work-queue', async (c) => {
    const auth = await requireTaskAccess(c, 'itsm.tasks.view')
    if (auth.error) return auth.error

    const scope = text(c.req.query('scope') || 'team', 30).toLowerCase()
    if (!queueScopes.has(scope)) return c.json({ error: 'Unsupported task queue view.' }, 400)

    const status = text(c.req.query('status'), 40)
    if (status && status !== 'All' && !queueStatuses.has(status)) return c.json({ error: 'Unsupported task status.' }, 400)

    const due = text(c.req.query('due'), 40)
    if (due && due !== 'All' && !queueDueFilters.has(due)) return c.json({ error: 'Unsupported due-date filter.' }, 400)

    const viewer = await taskViewer(pool, auth.session)
    const viewerTeamIds = Array.isArray(viewer?.team_ids) ? viewer.team_ids : []
    const limit = Math.max(1, Math.min(200, Number(c.req.query('limit') || 50)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))
    const values = [auth.session.tenant_id]
    const clauses = ['t.tenant_id = $1', "t.status <> 'Waiting'"]
    const add = (sql, value) => {
      values.push(value)
      const parameter = `$${values.length}`
      clauses.push(sql.replace(/\?/g, parameter))
    }

    if (scope === 'completed') {
      clauses.push("t.status = 'Completed'")
    } else {
      clauses.push("t.status IN ('Ready','In Progress','Blocked')")
      clauses.push("r.status NOT IN ('Pending Approval','Rejected','Closed')")
      clauses.push(queueDependenciesSatisfiedSql)
      if (scope === 'mine') {
        if (viewer?.id) add('t.assignee_person_id = ?::uuid', viewer.id)
        else clauses.push('FALSE')
      }
      if (scope === 'team') {
        if (viewerTeamIds.length) add('t.team_id = ANY(?::uuid[])', viewerTeamIds)
        else clauses.push('FALSE')
      }
      if (scope === 'unassigned') clauses.push('t.assignee_person_id IS NULL')
      if (scope === 'blocked') clauses.push("t.status = 'Blocked'")
    }

    if (status && status !== 'All') add('t.status = ?', status)

    const search = text(c.req.query('search'), 200)
    if (search) add("(t.external_key ILIKE '%' || ? || '%' OR t.title ILIKE '%' || ? || '%' OR r.reference ILIKE '%' || ? || '%' OR r.title ILIKE '%' || ? || '%')", search)

    const priority = text(c.req.query('priority'), 40)
    if (priority && priority !== 'All') add('r.priority = ?', priority)

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

    if (due === 'Overdue') clauses.push('t.due_at IS NOT NULL AND t.due_at < now()')
    if (due === 'Next 24 hours') clauses.push("t.due_at >= now() AND t.due_at < now() + interval '24 hours'")
    if (due === 'Next 7 days') clauses.push("t.due_at >= now() AND t.due_at < now() + interval '7 days'")
    if (due === 'No due date') clauses.push('t.due_at IS NULL')

    values.push(limit, offset)
    const result = await pool.query(
      `${queueTaskSelect}
       WHERE ${clauses.join(' AND ')}
       ORDER BY
         CASE WHEN t.status <> 'Completed' AND t.due_at IS NOT NULL AND t.due_at < now() THEN 0 ELSE 1 END,
         CASE t.status WHEN 'In Progress' THEN 0 WHEN 'Ready' THEN 1 WHEN 'Blocked' THEN 2 ELSE 3 END,
         t.due_at NULLS LAST,
         t.updated_at DESC
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

    const activeCounts = await pool.query(
      `SELECT
         count(*)::int AS all,
         count(*) FILTER (WHERE t.assignee_person_id = $2::uuid)::int AS mine,
         count(*) FILTER (WHERE t.team_id = ANY($3::uuid[]))::int AS team,
         count(*) FILTER (WHERE t.assignee_person_id IS NULL)::int AS unassigned,
         count(*) FILTER (WHERE t.status = 'Blocked')::int AS blocked,
         count(*) FILTER (WHERE t.due_at IS NOT NULL AND t.due_at < now())::int AS overdue
       FROM service_request_tasks t
       JOIN service_requests r ON r.id = t.request_id AND r.tenant_id = t.tenant_id
       WHERE t.tenant_id = $1
         AND t.status IN ('Ready','In Progress','Blocked')
         AND r.status NOT IN ('Pending Approval','Rejected','Closed')
         AND ${queueDependenciesSatisfiedSql}`,
      [auth.session.tenant_id, viewer?.id || null, viewerTeamIds],
    )

    const completedCount = await pool.query(
      `SELECT count(*)::int AS completed
       FROM service_request_tasks t
       WHERE t.tenant_id = $1 AND t.status = 'Completed'`,
      [auth.session.tenant_id],
    )

    const filters = await pool.query(
      `SELECT
         array_remove(array_agg(DISTINCT COALESCE(team.name, t.team_snapshot->>'name')), NULL) AS teams,
         array_remove(array_agg(DISTINCT COALESCE(assignee.name, t.assignee_snapshot->>'name')), NULL) AS assignees,
         array_remove(array_agg(DISTINCT r.service), NULL) AS services,
         array_remove(array_agg(DISTINCT r.priority), NULL) AS priorities
       FROM service_request_tasks t
       JOIN service_requests r ON r.id = t.request_id AND r.tenant_id = t.tenant_id
       LEFT JOIN organisation_teams team ON team.id = t.team_id
       LEFT JOIN organisation_people assignee ON assignee.id = t.assignee_person_id
       WHERE t.tenant_id = $1 AND t.status <> 'Waiting'`,
      [auth.session.tenant_id],
    )

    const counts = activeCounts.rows[0] || {}
    return c.json({
      items: result.rows.map(queueTaskFromRow),
      total: Number(count.rows[0]?.total || 0),
      viewer: {
        personId: viewer?.external_key || '',
        name: viewer?.name || auth.session.name || '',
        email: viewer?.email || auth.session.email || '',
        teams: Array.isArray(viewer?.team_names) ? viewer.team_names : [],
      },
      views: {
        mine: Number(counts.mine || 0),
        team: Number(counts.team || 0),
        unassigned: Number(counts.unassigned || 0),
        blocked: Number(counts.blocked || 0),
        all: Number(counts.all || 0),
        completed: Number(completedCount.rows[0]?.completed || 0),
        overdue: Number(counts.overdue || 0),
      },
      filters: {
        statuses: ['Ready', 'In Progress', 'Blocked', 'Completed'],
        priorities: filters.rows[0]?.priorities || [],
        teams: filters.rows[0]?.teams || [],
        assignees: filters.rows[0]?.assignees || [],
        services: filters.rows[0]?.services || [],
        due: ['Overdue', 'Next 24 hours', 'Next 7 days', 'No due date'],
      },
    })
  })

  app.post('/api/v1/tasks/:taskKey/take', async (c) => {
    const auth = await requireTaskManager(c)
    if (auth.error) return auth.error

    try {
      const result = await withTransaction(async (client) => {
        const task = await lockedTask(client, auth.session.tenant_id, c.req.param('taskKey'))
        ensureTakeable(task)
        if (!await dependenciesSatisfied(client, task)) {
          const error = new Error('This task is waiting for its earlier tasks to be completed.')
          error.status = 409
          throw error
        }
        if (!task.team_id) {
          const error = new Error('This task must be routed to a team before it can be taken.')
          error.status = 409
          throw error
        }
        if (task.assignee_person_id) {
          const error = new Error('This task has already been taken by another technician.')
          error.status = 409
          throw error
        }

        const technician = await eligibleTechnician(client, auth.session, task.team_id)
        if (!technician) {
          const error = new Error('You must be an active member of this task’s assignment group to take it.')
          error.status = 403
          throw error
        }

        await client.query(
          `UPDATE service_request_tasks
           SET assignee_person_id = $2,
               assignee_snapshot = $3::jsonb,
               updated_at = now()
           WHERE id = $1`,
          [task.id, technician.id, JSON.stringify(personSnapshot(technician, auth.session))],
        )
        await client.query('UPDATE service_requests SET updated_at = now() WHERE id = $1', [task.request_id])
        await addActivity(
          client,
          auth.session,
          task,
          technician,
          'request.task.taken',
          `${technician.name} took task ${task.external_key}.`,
        )

        return {
          status: 'taken',
          taskKey: task.external_key,
          taskStatus: task.status,
          team: {
            id: task.team_external_key || '',
            name: task.team_name || task.team_snapshot?.name || 'Unassigned',
          },
          assignee: personSnapshot(technician, auth.session),
        }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/tasks/:taskKey/release', async (c) => {
    const auth = await requireTaskManager(c)
    if (auth.error) return auth.error

    try {
      const result = await withTransaction(async (client) => {
        const task = await lockedTask(client, auth.session.tenant_id, c.req.param('taskKey'))
        ensureTakeable(task)
        if (!task.assignee_person_id) {
          const error = new Error('This task is already unassigned.')
          error.status = 409
          throw error
        }

        const technician = await personForUser(client, auth.session)
        if (!technician || technician.id !== task.assignee_person_id) {
          const error = new Error('Only the technician who currently owns this Ready task can release it.')
          error.status = 403
          throw error
        }

        await client.query(
          `UPDATE service_request_tasks
           SET assignee_person_id = NULL,
               assignee_snapshot = '{}'::jsonb,
               updated_at = now()
           WHERE id = $1`,
          [task.id],
        )
        await client.query('UPDATE service_requests SET updated_at = now() WHERE id = $1', [task.request_id])
        await addActivity(
          client,
          auth.session,
          task,
          technician,
          'request.task.released',
          `${technician.name} released task ${task.external_key} back to ${task.team_name || task.team_snapshot?.name || 'the team'} queue.`,
        )

        return {
          status: 'released',
          taskKey: task.external_key,
          taskStatus: task.status,
          team: {
            id: task.team_external_key || '',
            name: task.team_name || task.team_snapshot?.name || 'Unassigned',
          },
          assignee: null,
        }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })
}