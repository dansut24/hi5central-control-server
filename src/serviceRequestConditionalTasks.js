import { hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

const supportedOperators = new Set(['equals', 'not_equals', 'contains', 'not_contains', 'is_set', 'is_not_set'])

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
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

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function managerSession(c) {
  const session = await resolveSession(c)
  if (!session || !originMatchesSession(c, session)) return null
  if (!hasPermission(session.access, 'catalogue.manage')) return null
  return session
}

function optionPayload(option) {
  if (option && typeof option === 'object' && !Array.isArray(option)) {
    const value = text(option.value ?? option.label, 500)
    if (!value) return null
    return { value, label: text(option.label ?? option.value, 500) || value }
  }
  const value = text(option, 500)
  return value ? { value, label: value } : null
}

function conditionFieldsFromSchema(schema) {
  return asArray(schema)
    .filter((field) => field?.id && field?.type)
    .map((field) => ({
      id: text(field.id, 120),
      label: text(field.label || field.id, 180),
      type: text(field.type, 80),
      options: asArray(field.options).map(optionPayload).filter(Boolean),
    }))
}

async function catalogueConditionFields(db, tenantId, itemKey) {
  const result = await db.query(
    `SELECT form_schema
     FROM service_catalogue_items
     WHERE tenant_id = $1 AND external_key = $2
     LIMIT 1`,
    [tenantId, catalogueKey(itemKey)],
  )
  return conditionFieldsFromSchema(result.rows[0]?.form_schema)
}

function normaliseCondition(rawValue, fields) {
  const raw = asObject(rawValue)
  if (!raw.fieldId) return null

  const fieldId = text(raw.fieldId, 120)
  const field = fields.find((candidate) => candidate.id === fieldId)
  if (!field) {
    const error = new Error('A conditional fulfilment task refers to a request field that no longer exists.')
    error.status = 400
    throw error
  }

  const operator = text(raw.operator || 'equals', 40)
  if (!supportedOperators.has(operator)) {
    const error = new Error(`The condition on ${field.label} uses an unsupported comparison.`)
    error.status = 400
    throw error
  }

  const needsValue = !['is_set', 'is_not_set'].includes(operator)
  const value = needsValue ? text(raw.value, 1000) : ''
  if (needsValue && !value) {
    const error = new Error(`Choose a value for the condition on ${field.label}.`)
    error.status = 400
    throw error
  }

  return { fieldId, operator, value }
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

function hasValue(value) {
  if (Array.isArray(value)) return value.length > 0
  if (typeof value === 'boolean') return value
  return value !== null && value !== undefined && String(value).trim() !== ''
}

function valueEquals(current, expected) {
  if (Array.isArray(current)) return current.some((value) => String(value) === expected)
  if (typeof current === 'boolean') return String(current) === expected
  return String(current ?? '') === expected
}

function valueContains(current, expected) {
  if (Array.isArray(current)) return current.some((value) => String(value) === expected)
  return String(current ?? '').toLocaleLowerCase().includes(expected.toLocaleLowerCase())
}

function conditionMatches(condition, submittedFields) {
  if (!condition?.fieldId) return true
  const current = asObject(submittedFields)[condition.fieldId]
  switch (condition.operator) {
    case 'equals': return valueEquals(current, condition.value)
    case 'not_equals': return !valueEquals(current, condition.value)
    case 'contains': return valueContains(current, condition.value)
    case 'not_contains': return !valueContains(current, condition.value)
    case 'is_set': return hasValue(current)
    case 'is_not_set': return !hasValue(current)
    default: return false
  }
}

function configuredTasks(rawTasks) {
  return asArray(rawTasks).map((raw, index) => ({
    id: workflowTaskKey(raw?.id, index),
    dependsOn: [...new Set(asArray(raw?.dependsOn).map((dependency) => workflowTaskKey(dependency, 0)).filter(Boolean))],
    condition: raw?.condition && typeof raw.condition === 'object' ? raw.condition : null,
  }))
}

function effectiveDependencies(taskId, activeIds, byId, trail = new Set()) {
  if (trail.has(taskId)) return []
  const task = byId.get(taskId)
  if (!task) return []

  const nextTrail = new Set(trail)
  nextTrail.add(taskId)
  const result = []

  for (const dependency of task.dependsOn) {
    if (activeIds.has(dependency)) {
      if (!result.includes(dependency)) result.push(dependency)
      continue
    }
    for (const ancestor of effectiveDependencies(dependency, activeIds, byId, nextTrail)) {
      if (!result.includes(ancestor)) result.push(ancestor)
    }
  }

  return result
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

async function patchFlowConditions(c, next) {
  const match = c.req.path.match(/^\/api\/v1\/catalogue\/([^/]+)\/fulfilment\/?$/i)
  if (!match || !['GET', 'PUT'].includes(c.req.method.toUpperCase())) return next()

  const session = await managerSession(c)
  if (!session) return next()

  const itemKey = decodeURIComponent(match[1])
  const fields = await catalogueConditionFields(pool, session.tenant_id, itemKey)
  let incomingConditions = null

  if (c.req.method.toUpperCase() === 'PUT') {
    let body = null
    try { body = await c.req.raw.clone().json() } catch { body = null }
    if (body && Array.isArray(body.tasks)) {
      try {
        incomingConditions = new Map(body.tasks.map((task, index) => [
          workflowTaskKey(task?.id, index),
          normaliseCondition(task?.condition, fields),
        ]))
      } catch (error) {
        if (error?.status) return c.json({ error: error.message }, error.status)
        throw error
      }
    }
  }

  await next()
  if (!c.res || c.res.status < 200 || c.res.status >= 300) return

  let payload = null
  try { payload = await c.res.clone().json() } catch { payload = null }
  if (!payload) return

  if (incomingConditions) {
    const flow = await pool.query(
      `SELECT tasks
       FROM service_catalogue_fulfilment_flows
       WHERE tenant_id = $1 AND catalogue_item_key = $2
       LIMIT 1`,
      [session.tenant_id, catalogueKey(itemKey)],
    )
    const patchedTasks = asArray(flow.rows[0]?.tasks).map((task, index) => ({
      ...task,
      condition: incomingConditions.get(workflowTaskKey(task?.id, index)) || null,
    }))
    await pool.query(
      `UPDATE service_catalogue_fulfilment_flows
       SET tasks = $3::jsonb, updated_at = now()
       WHERE tenant_id = $1 AND catalogue_item_key = $2`,
      [session.tenant_id, catalogueKey(itemKey), JSON.stringify(patchedTasks)],
    )
    payload.tasks = patchedTasks
  }

  payload.conditionFields = fields
  replaceJsonResponse(c, payload)
}

async function applyConditionalRequestFlow(db, tenantId, reference) {
  const requestResult = await db.query(
    `SELECT id, reference, catalogue_item_key_snapshot, submitted_fields, status, workflow_tasks_snapshot
     FROM service_requests
     WHERE tenant_id = $1 AND upper(reference) = upper($2)
     LIMIT 1 FOR UPDATE`,
    [tenantId, text(reference, 80)],
  )
  const request = requestResult.rows[0]
  if (!request) return null

  const flowResult = await db.query(
    `SELECT tasks
     FROM service_catalogue_fulfilment_flows
     WHERE tenant_id = $1 AND catalogue_item_key = $2
     LIMIT 1`,
    [tenantId, catalogueKey(request.catalogue_item_key_snapshot)],
  )
  const configured = configuredTasks(flowResult.rows[0]?.tasks)
  if (!configured.length || !configured.some((task) => task.condition?.fieldId)) return null

  const byId = new Map(configured.map((task) => [task.id, task]))
  const activeIds = new Set(configured
    .filter((task) => conditionMatches(task.condition, request.submitted_fields))
    .map((task) => task.id))
  const originalSnapshot = asArray(request.workflow_tasks_snapshot)
  const taskKeyById = new Map(originalSnapshot.map((task) => [task.id, task.taskKey]))
  const inactiveTaskKeys = originalSnapshot
    .filter((task) => !activeIds.has(task.id))
    .map((task) => task.taskKey)
    .filter(Boolean)

  if (inactiveTaskKeys.length) {
    await db.query(
      `DELETE FROM service_request_tasks
       WHERE request_id = $1 AND external_key = ANY($2::text[])`,
      [request.id, inactiveTaskKeys],
    )
  }

  const activeSnapshot = []
  for (const snapshotTask of originalSnapshot) {
    if (!activeIds.has(snapshotTask.id)) continue
    const config = byId.get(snapshotTask.id)
    const dependencyIds = effectiveDependencies(snapshotTask.id, activeIds, byId)
    const dependencies = dependencyIds.map((id) => taskKeyById.get(id)).filter(Boolean)
    const status = request.status === 'Pending Approval' || dependencies.length ? 'Waiting' : 'Ready'

    await db.query(
      `UPDATE service_request_tasks
       SET dependencies = $3::jsonb, status = $4, updated_at = now()
       WHERE request_id = $1 AND external_key = $2`,
      [request.id, snapshotTask.taskKey, JSON.stringify(dependencies), status],
    )

    activeSnapshot.push({
      ...snapshotTask,
      dependsOn: dependencyIds,
      condition: config?.condition || null,
    })
  }

  await db.query(
    `UPDATE service_requests
     SET workflow_tasks_snapshot = $2::jsonb, updated_at = now()
     WHERE id = $1`,
    [request.id, JSON.stringify(activeSnapshot)],
  )

  const taskResult = await db.query(
    `SELECT * FROM service_request_tasks
     WHERE request_id = $1
     ORDER BY created_at, id`,
    [request.id],
  )

  return {
    tasks: taskResult.rows.map(taskPayload),
    skipped: configured.length - activeSnapshot.length,
  }
}

async function conditionalRequestMiddleware(c, next) {
  const isCreate = c.req.method.toUpperCase() === 'POST' && c.req.path.replace(/\/$/, '') === '/api/v1/service-requests'
  if (!isCreate) return next()

  const session = await resolveSession(c)
  await next()
  if (!session || !originMatchesSession(c, session) || !c.res || c.res.status !== 201) return

  let payload = null
  try { payload = await c.res.clone().json() } catch { payload = null }
  const reference = payload?.reference || payload?.id
  if (!reference) return

  const result = await withTransaction((client) => applyConditionalRequestFlow(client, session.tenant_id, reference))
  if (!result) return

  payload.requestTasks = result.tasks
  payload.skippedFulfilmentTasks = result.skipped
  replaceJsonResponse(c, payload)
}

export function registerServiceRequestConditionalTaskRoutes(app) {
  app.use('/api/v1/catalogue/*', patchFlowConditions)
  app.use('/api/v1/service-requests', conditionalRequestMiddleware)
}
