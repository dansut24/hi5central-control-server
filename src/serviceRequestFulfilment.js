import { hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

const maxTasks = 40
const autoDateField = '__auto__'
const noDateField = '__none__'

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

function catalogueKey(value) {
  return text(value, 100)
    .toUpperCase()
    .replace(/[^A-Z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function workflowTaskKey(value, index) {
  const cleaned = text(value, 80)
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
  return cleaned || `task-${index + 1}`
}

function normaliseTasks(value) {
  const source = asArray(value)
  if (source.length > maxTasks) {
    const error = new Error(`A fulfilment flow can contain up to ${maxTasks} tasks.`)
    error.status = 400
    throw error
  }

  const tasks = source.map((raw, index) => ({
    id: workflowTaskKey(raw?.id, index),
    title: text(raw?.title, 180),
    team: text(raw?.team, 160),
    teamId: text(raw?.teamId, 120),
    instructions: text(raw?.instructions, 5000),
    dependsOn: [...new Set(asArray(raw?.dependsOn).map((item) => workflowTaskKey(item, 0)).filter(Boolean))].slice(0, 20),
    titleDateFieldId: text(raw?.titleDateFieldId || autoDateField, 120) || autoDateField,
  }))

  const ids = new Set()
  for (const task of tasks) {
    if (!task.title) {
      const error = new Error('Every fulfilment task needs a name.')
      error.status = 400
      throw error
    }
    if (ids.has(task.id)) {
      const error = new Error('Fulfilment task identifiers must be unique.')
      error.status = 400
      throw error
    }
    ids.add(task.id)
  }

  const position = new Map(tasks.map((task, index) => [task.id, index]))
  tasks.forEach((task, index) => {
    for (const dependency of task.dependsOn) {
      if (!position.has(dependency)) {
        const error = new Error(`${task.title} depends on a task that no longer exists.`)
        error.status = 400
        throw error
      }
      if (position.get(dependency) >= index) {
        const error = new Error(`${task.title} can only wait for tasks above it in the flow.`)
        error.status = 400
        throw error
      }
    }
  })

  return tasks
}

async function requireCatalogueManager(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, 'catalogue.manage')) {
    return { error: c.json({ error: 'Service Catalogue management access is required.' }, 403) }
  }
  return { session }
}

async function activeTeams(db, tenantId) {
  const result = await db.query(
    `SELECT id, external_key, name
     FROM organisation_teams
     WHERE tenant_id = $1 AND active = true
     ORDER BY name`,
    [tenantId],
  )
  return result.rows
}

async function resolveTaskTeams(db, tenantId, tasks) {
  const teams = await activeTeams(db, tenantId)
  const byId = new Map()
  const byName = new Map()
  teams.forEach((team) => {
    byId.set(team.external_key, team)
    byId.set(String(team.id), team)
    byName.set(team.name.toLowerCase(), team)
  })

  return tasks.map((task) => {
    if (!task.team && !task.teamId) return { ...task, team: '', teamId: '' }
    const resolved = byId.get(task.teamId) || byId.get(task.team) || byName.get(task.team.toLowerCase())
    if (!resolved) {
      const error = new Error(`The team selected for ${task.title} is no longer active.`)
      error.status = 400
      throw error
    }
    return { ...task, team: resolved.name, teamId: resolved.external_key }
  })
}

async function flowForItem(db, tenantId, itemKey) {
  const result = await db.query(
    `SELECT tasks, updated_at
     FROM service_catalogue_fulfilment_flows
     WHERE tenant_id = $1 AND catalogue_item_key = $2
     LIMIT 1`,
    [tenantId, catalogueKey(itemKey)],
  )
  return result.rows[0] || null
}

async function catalogueFormSchema(db, tenantId, itemKey) {
  const result = await db.query(
    `SELECT form_schema
     FROM service_catalogue_items
     WHERE tenant_id = $1 AND external_key = $2
     LIMIT 1`,
    [tenantId, catalogueKey(itemKey)],
  )
  return asArray(result.rows[0]?.form_schema)
}

function dateFieldsFromSchema(schema) {
  return asArray(schema)
    .filter((field) => field?.id && ['date', 'datetime-local'].includes(field?.type))
    .map((field) => ({ id: text(field.id, 120), label: text(field.label || field.id, 180), type: field.type }))
}

function chosenDateField(task, dateFields) {
  if (task.titleDateFieldId === noDateField) return null
  if (task.titleDateFieldId === autoDateField) return dateFields.length === 1 ? dateFields[0] : null
  return dateFields.find((field) => field.id === task.titleDateFieldId) || null
}

function formatTaskDate(value) {
  const raw = text(value, 120)
  if (!raw) return ''

  const iso = raw.match(/^(\d{4})-(\d{2})-(\d{2})/)
  let date = null
  if (iso) {
    const year = Number(iso[1])
    const month = Number(iso[2])
    const day = Number(iso[3])
    date = new Date(Date.UTC(year, month - 1, day))
    if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return ''
  } else {
    const parsed = new Date(raw)
    if (Number.isNaN(parsed.getTime())) return ''
    date = parsed
  }

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(date)
}

function taskWithResolvedTitle(task, request, dateFields) {
  const field = chosenDateField(task, dateFields)
  const rawValue = field ? asObject(request.submitted_fields)[field.id] : ''
  const titleDate = formatTaskDate(rawValue)
  return {
    ...task,
    generatedTitle: titleDate ? text(`${task.title} · ${titleDate}`, 240) : task.title,
    titleDate,
    titleDateFieldLabel: field?.label || '',
  }
}

async function requestByReference(db, tenantId, reference, lock = false) {
  const result = await db.query(
    `SELECT * FROM service_requests
     WHERE tenant_id = $1 AND upper(reference) = upper($2)
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

function externalTaskKey(reference, index) {
  return `${reference}-T${String(index + 1).padStart(2, '0')}`
}

async function installRequestFlow(db, tenantId, reference) {
  const request = await requestByReference(db, tenantId, reference, true)
  if (!request) return null
  const flow = await flowForItem(db, tenantId, request.catalogue_item_key_snapshot)
  if (!flow) return null

  const configured = normaliseTasks(flow.tasks)
  if (!configured.length) return null
  const schema = await catalogueFormSchema(db, tenantId, request.catalogue_item_key_snapshot)
  const dateFields = dateFieldsFromSchema(schema)
  const routedTasks = await resolveTaskTeams(db, tenantId, configured)
  const tasks = routedTasks.map((task) => taskWithResolvedTitle(task, request, dateFields))
  const externalKeys = new Map(tasks.map((task, index) => [task.id, externalTaskKey(request.reference, index)]))

  await db.query('DELETE FROM service_request_tasks WHERE request_id = $1', [request.id])

  const created = []
  for (let index = 0; index < tasks.length; index += 1) {
    const task = tasks[index]
    const dependencies = task.dependsOn.map((dependency) => externalKeys.get(dependency)).filter(Boolean)
    const teamResult = task.teamId
      ? await db.query(
          `SELECT id, external_key, name FROM organisation_teams
           WHERE tenant_id = $1 AND active = true AND external_key = $2 LIMIT 1`,
          [tenantId, task.teamId],
        )
      : { rows: [] }
    const team = teamResult.rows[0] || null
    const status = request.status === 'Pending Approval' || dependencies.length ? 'Waiting' : 'Ready'
    const key = externalKeys.get(task.id)
    const inserted = await db.query(
      `INSERT INTO service_request_tasks (
         tenant_id, request_id, external_key, title, status, team_id, team_snapshot,
         instructions, dependencies
       ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb)
       RETURNING *`,
      [
        tenantId,
        request.id,
        key,
        task.generatedTitle,
        status,
        team?.id || null,
        JSON.stringify(team ? { id: team.external_key, name: team.name } : {}),
        task.instructions,
        JSON.stringify(dependencies),
      ],
    )
    created.push(inserted.rows[0])
  }

  const snapshot = tasks.map((task) => ({
    id: task.id,
    taskKey: externalKeys.get(task.id),
    title: task.generatedTitle,
    baseTitle: task.title,
    team: task.team,
    teamId: task.teamId,
    instructions: task.instructions,
    dependsOn: task.dependsOn,
    titleDateFieldId: task.titleDateFieldId,
    titleDateFieldLabel: task.titleDateFieldLabel,
    titleDate: task.titleDate,
  }))
  await db.query(
    `UPDATE service_requests
     SET workflow_tasks_snapshot = $2::jsonb, updated_at = now()
     WHERE id = $1`,
    [request.id, JSON.stringify(snapshot)],
  )

  return created
}

async function dependenciesComplete(db, requestId, dependencies) {
  if (!dependencies.length) return true
  const result = await db.query(
    `SELECT external_key, status
     FROM service_request_tasks
     WHERE request_id = $1 AND external_key = ANY($2::text[])`,
    [requestId, dependencies],
  )
  if (result.rowCount !== dependencies.length) return false
  return result.rows.every((row) => row.status === 'Completed')
}

async function reconcileTaskReadiness(db, tenantId, reference) {
  const request = await requestByReference(db, tenantId, reference, true)
  if (!request) return []
  if (request.status === 'Pending Approval') {
    await db.query(
      `UPDATE service_request_tasks
       SET status = 'Waiting', updated_at = now()
       WHERE request_id = $1 AND status = 'Ready'`,
      [request.id],
    )
    return []
  }
  if (['Rejected', 'Closed'].includes(request.status)) return []

  const result = await db.query(
    `SELECT id, external_key, title, status, dependencies
     FROM service_request_tasks
     WHERE request_id = $1 AND status IN ('Waiting','Ready')
     ORDER BY created_at, id`,
    [request.id],
  )
  const unlocked = []
  for (const task of result.rows) {
    const dependencies = asArray(task.dependencies)
    const ready = await dependenciesComplete(db, request.id, dependencies)
    const desired = ready ? 'Ready' : 'Waiting'
    if (task.status === desired) continue
    await db.query('UPDATE service_request_tasks SET status = $2, updated_at = now() WHERE id = $1', [task.id, desired])
    if (desired === 'Ready') unlocked.push({ taskKey: task.external_key, title: task.title })
  }
  return unlocked
}

async function taskDependenciesSatisfied(db, tenantId, reference, taskKey) {
  const request = await requestByReference(db, tenantId, reference)
  if (!request) return { exists: false, ready: false }
  const taskResult = await db.query(
    `SELECT status, dependencies
     FROM service_request_tasks
     WHERE tenant_id = $1 AND request_id = $2 AND external_key = $3
     LIMIT 1`,
    [tenantId, request.id, text(taskKey, 160)],
  )
  if (!taskResult.rowCount) return { exists: false, ready: false }
  const task = taskResult.rows[0]
  return {
    exists: true,
    status: task.status,
    ready: await dependenciesComplete(db, request.id, asArray(task.dependencies)),
  }
}

async function incompleteTaskCount(db, tenantId, reference) {
  const request = await requestByReference(db, tenantId, reference)
  if (!request) return 0
  if (!asArray(request.workflow_tasks_snapshot).length) return 0
  const result = await db.query(
    `SELECT count(*)::int AS count
     FROM service_request_tasks
     WHERE request_id = $1 AND status <> 'Completed'`,
    [request.id],
  )
  return Number(result.rows[0]?.count || 0)
}

function taskPayload(row) {
  return {
    id: row.external_key,
    title: row.title,
    status: row.status,
    team: row.team_snapshot?.name || '',
    assignee: row.assignee_snapshot?.name || '',
    instructions: row.instructions,
    dependencies: row.dependencies || [],
    dueAt: row.due_at,
    completionNotes: row.completion_notes,
  }
}

async function currentTaskPayloads(db, tenantId, reference) {
  const request = await requestByReference(db, tenantId, reference)
  if (!request) return []
  const result = await db.query(
    `SELECT * FROM service_request_tasks
     WHERE request_id = $1
     ORDER BY created_at, id`,
    [request.id],
  )
  return result.rows.map(taskPayload)
}

function responseHeaders(response) {
  const headers = new Headers(response.headers)
  headers.set('content-type', 'application/json; charset=UTF-8')
  headers.delete('content-length')
  return headers
}

function replaceJsonResponse(c, payload) {
  c.res = new Response(JSON.stringify(payload), {
    status: c.res.status,
    statusText: c.res.statusText,
    headers: responseHeaders(c.res),
  })
}

async function serviceRequestMiddleware(c, next) {
  const session = await resolveSession(c)
  if (!session || !originMatchesSession(c, session)) return next()

  const method = c.req.method.toUpperCase()
  const path = c.req.path
  let body = null
  if (['POST', 'PATCH', 'PUT'].includes(method)) {
    try { body = await c.req.raw.clone().json() } catch { body = null }
  }

  const taskMatch = path.match(/\/api\/v1\/service-requests\/([^/]+)\/tasks\/([^/]+)\/?$/i)
  const transitionMatch = path.match(/\/api\/v1\/service-requests\/([^/]+)\/transition\/?$/i)
  const approvalMatch = path.match(/\/api\/v1\/service-requests\/([^/]+)\/approvals\/[^/]+\/decision\/?$/i)
  const createRoute = method === 'POST' && path.replace(/\/$/, '') === '/api/v1/service-requests'

  if (method === 'PATCH' && taskMatch && body?.status && ['Ready', 'In Progress', 'Completed'].includes(body.status)) {
    const reference = decodeURIComponent(taskMatch[1])
    const taskKey = decodeURIComponent(taskMatch[2])
    const dependencyState = await taskDependenciesSatisfied(pool, session.tenant_id, reference, taskKey)
    if (dependencyState.exists && !dependencyState.ready) {
      return c.json({ error: 'This task is waiting for its earlier tasks to be completed.' }, 409)
    }
  }

  if (method === 'POST' && transitionMatch && body?.targetStatus === 'Completed') {
    const reference = decodeURIComponent(transitionMatch[1])
    const incomplete = await incompleteTaskCount(pool, session.tenant_id, reference)
    if (incomplete > 0) {
      return c.json({ error: `${incomplete} fulfilment task${incomplete === 1 ? '' : 's'} must be completed before the request can be completed.` }, 409)
    }
  }

  await next()
  if (!c.res || c.res.status < 200 || c.res.status >= 300) return

  if (createRoute && c.res.status === 201) {
    let payload
    try { payload = await c.res.clone().json() } catch { payload = null }
    const reference = payload?.reference || payload?.id
    if (reference) {
      const created = await withTransaction((client) => installRequestFlow(client, session.tenant_id, reference))
      if (created?.length) {
        payload.requestTasks = await currentTaskPayloads(pool, session.tenant_id, reference)
        replaceJsonResponse(c, payload)
      }
    }
    return
  }

  const reference = taskMatch
    ? decodeURIComponent(taskMatch[1])
    : transitionMatch
      ? decodeURIComponent(transitionMatch[1])
      : approvalMatch
        ? decodeURIComponent(approvalMatch[1])
        : ''
  if (!reference) return

  if ((method === 'PATCH' && taskMatch) || (method === 'POST' && (transitionMatch || approvalMatch))) {
    await withTransaction((client) => reconcileTaskReadiness(client, session.tenant_id, reference))
    let payload
    try { payload = await c.res.clone().json() } catch { payload = null }
    if (payload && Array.isArray(payload.requestTasks)) {
      payload.requestTasks = await currentTaskPayloads(pool, session.tenant_id, reference)
      replaceJsonResponse(c, payload)
    }
  }
}

export function registerServiceRequestFulfilmentRoutes(app) {
  app.get('/api/v1/catalogue/fulfilment-options', async (c) => {
    const auth = await requireCatalogueManager(c)
    if (auth.error) return auth.error
    const teams = await activeTeams(pool, auth.session.tenant_id)
    return c.json({
      teams: teams.map((team) => ({ id: team.external_key, name: team.name })),
    })
  })

  app.get('/api/v1/catalogue/:itemKey/fulfilment', async (c) => {
    const auth = await requireCatalogueManager(c)
    if (auth.error) return auth.error
    const key = catalogueKey(c.req.param('itemKey'))
    const [flow, schema] = await Promise.all([
      flowForItem(pool, auth.session.tenant_id, key),
      catalogueFormSchema(pool, auth.session.tenant_id, key),
    ])
    return c.json({
      itemKey: key,
      tasks: flow?.tasks || [],
      dateFields: dateFieldsFromSchema(schema),
      updatedAt: flow?.updated_at || null,
    })
  })

  app.put('/api/v1/catalogue/:itemKey/fulfilment', async (c) => {
    const auth = await requireCatalogueManager(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    try {
      const key = catalogueKey(c.req.param('itemKey'))
      const tasks = await resolveTaskTeams(pool, auth.session.tenant_id, normaliseTasks(body?.tasks))
      const schema = await catalogueFormSchema(pool, auth.session.tenant_id, key)
      const dateFields = dateFieldsFromSchema(schema)
      const knownDateIds = new Set(dateFields.map((field) => field.id))
      for (const task of tasks) {
        if (![autoDateField, noDateField].includes(task.titleDateFieldId) && !knownDateIds.has(task.titleDateFieldId)) {
          return c.json({ error: `The task title date field selected for ${task.title} no longer exists on this request form.` }, 400)
        }
      }
      await pool.query(
        `INSERT INTO service_catalogue_fulfilment_flows
           (tenant_id, catalogue_item_key, tasks, updated_by_user_id, updated_at)
         VALUES ($1,$2,$3::jsonb,$4,now())
         ON CONFLICT (tenant_id, catalogue_item_key) DO UPDATE SET
           tasks = EXCLUDED.tasks,
           updated_by_user_id = EXCLUDED.updated_by_user_id,
           updated_at = now()`,
        [auth.session.tenant_id, key, JSON.stringify(tasks), auth.session.user_id],
      )
      return c.json({ itemKey: key, tasks, dateFields })
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.use('/api/v1/service-requests', serviceRequestMiddleware)
  app.use('/api/v1/service-requests/*', serviceRequestMiddleware)
}
