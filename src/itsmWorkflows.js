import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'

const PROBLEM_TRANSITIONS = {
  New: ['Investigation'],
  Investigation: ['Known Error', 'Resolved'],
  'Known Error': ['Investigation', 'Resolved'],
  Resolved: ['Investigation', 'Closed'],
  Closed: [],
}

const CHANGE_TRANSITIONS = {
  Draft: ['Assessment', 'Cancelled'],
  Assessment: ['Awaiting Approval', 'Scheduled', 'Cancelled'],
  'Awaiting Approval': ['Scheduled', 'Cancelled'],
  Scheduled: ['Implementing', 'Cancelled'],
  Implementing: ['Review', 'Failed', 'Backed Out'],
  Review: ['Completed', 'Failed', 'Backed Out'],
  Failed: ['Review', 'Backed Out', 'Cancelled'],
  'Backed Out': ['Review', 'Cancelled'],
  Completed: [],
  Cancelled: [],
}

const SERVICE_REQUEST_TRANSITIONS = {
  New: ['Pending Approval', 'In Progress'],
  'Pending Approval': ['Approved', 'Rejected'],
  Approved: ['In Progress'],
  'In Progress': ['Completed'],
  Completed: ['Closed', 'In Progress'],
  Closed: [],
  Rejected: ['New'],
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

async function parseBody(c) {
  try { return await c.req.json() } catch { return null }
}

async function findRecord(db, tenantId, reference, lock = false) {
  const ref = text(reference, 80).toUpperCase()
  const request = await db.query(
    `SELECT *, 'Service Request'::text AS resolved_type
     FROM service_requests
     WHERE tenant_id = $1 AND upper(reference) = $2
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, ref],
  )
  if (request.rowCount) return { kind: 'request', row: request.rows[0] }
  const generic = await db.query(
    `SELECT *, record_type AS resolved_type
     FROM itsm_records
     WHERE tenant_id = $1 AND upper(reference) = $2
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, ref],
  )
  return generic.rowCount ? { kind: 'record', row: generic.rows[0] } : null
}

async function configurationFor(db, tenantId) {
  const result = await db.query(
    'SELECT configuration, onboarding_data FROM tenant_settings WHERE tenant_id = $1 LIMIT 1',
    [tenantId],
  )
  const row = result.rows[0] || {}
  return row.configuration && Object.keys(row.configuration).length ? row.configuration : (row.onboarding_data || {})
}

function problemData(row) {
  const data = object(row.record_data)
  return {
    impactScope: text(data.impactScope, 5000),
    hypothesis: text(data.hypothesis, 10000),
    workaround: text(data.workaround, 15000),
    rootCause: text(data.rootCause, 15000),
    permanentFix: text(data.permanentFix, 15000),
    knownError: Boolean(data.knownError),
    knownErrorTitle: text(data.knownErrorTitle, 500),
    affectedVersions: array(data.affectedVersions).slice(0, 100),
    knowledgeArticle: text(data.knowledgeArticle, 500),
  }
}

function changeData(row) {
  const data = object(row.record_data)
  return {
    changeType: ['Standard', 'Normal', 'Emergency'].includes(data.changeType) ? data.changeType : 'Normal',
    risk: ['Low', 'Medium', 'High', 'Critical'].includes(data.risk) ? data.risk : row.priority || 'Medium',
    riskSummary: text(data.riskSummary, 10000),
    businessReason: text(data.businessReason, 10000),
    implementationPlan: text(data.implementationPlan, 20000),
    testPlan: text(data.testPlan, 20000),
    backoutPlan: text(data.backoutPlan, 20000),
    plannedStart: text(data.plannedStart, 80),
    plannedEnd: text(data.plannedEnd, 80),
    downtime: text(data.downtime, 500),
    approvalRoute: text(data.approvalRoute, 500),
    implementationNotes: text(data.implementationNotes, 20000),
    reviewOutcome: text(data.reviewOutcome, 20000),
    failureReason: text(data.failureReason, 10000),
    affectedServices: array(data.affectedServices).slice(0, 100),
    affectedCis: array(data.affectedCis).slice(0, 100),
  }
}

function problemBlockers(row, data, target = '') {
  const blockers = []
  if (target === 'Known Error') {
    if (!data.knownErrorTitle) blockers.push('Add a Known Error title.')
    if (!data.workaround && !data.rootCause) blockers.push('Record a workaround or root-cause finding before publishing a Known Error.')
  }
  if (target === 'Resolved') {
    if (!data.rootCause) blockers.push('Root cause is required before resolving the Problem.')
    if (!data.permanentFix) blockers.push('Permanent fix is required before resolving the Problem.')
  }
  if (target === 'Closed' && row.status !== 'Resolved') blockers.push('Resolve the Problem before closing it.')
  return blockers
}

function validDate(value) {
  return Boolean(value && !Number.isNaN(new Date(value).getTime()))
}

function changeBlockers(row, data, target = '', approvalState = '') {
  const blockers = []
  if (['Assessment', 'Awaiting Approval', 'Scheduled'].includes(target)) {
    if (!data.businessReason) blockers.push('Business reason is required.')
    if (!data.implementationPlan) blockers.push('Implementation plan is required.')
    if (!data.testPlan) blockers.push('Test plan is required.')
    if (!data.backoutPlan) blockers.push('Backout plan is required.')
    if (!validDate(data.plannedStart) || !validDate(data.plannedEnd)) blockers.push('Valid planned start and end dates are required.')
    if (validDate(data.plannedStart) && validDate(data.plannedEnd) && new Date(data.plannedEnd) <= new Date(data.plannedStart)) blockers.push('Planned end must be after planned start.')
  }
  if (target === 'Scheduled' && data.changeType !== 'Standard' && approvalState !== 'Approved') blockers.push('Required Change approval has not been completed.')
  if (target === 'Review' && !data.implementationNotes) blockers.push('Add implementation notes before starting the review.')
  if (target === 'Completed' && !data.reviewOutcome) blockers.push('Post-implementation review outcome is required before completion.')
  if (['Failed', 'Backed Out'].includes(target) && !data.failureReason && !data.implementationNotes) blockers.push('Record the failure/backout reason before using this outcome.')
  return blockers
}

async function genericApprovals(db, tenantId, reference) {
  const result = await db.query(
    `SELECT id, approval_type, sequence, status, approver_user_id, approver_snapshot, decision_note, decided_at, created_at, updated_at
     FROM workflow_approvals
     WHERE tenant_id = $1 AND upper(record_reference) = upper($2)
     ORDER BY sequence, created_at`,
    [tenantId, reference],
  )
  return result.rows.map((row) => ({
    id: row.id,
    type: row.approval_type,
    sequence: row.sequence,
    status: row.status,
    approverUserId: row.approver_user_id,
    approver: object(row.approver_snapshot).name || 'Unassigned approver',
    approverEmail: object(row.approver_snapshot).email || '',
    note: row.decision_note,
    decidedAt: row.decided_at,
    createdAt: row.created_at,
  }))
}

async function relationships(db, tenantId, recordId) {
  const result = await db.query(
    `SELECT target_reference, target_type, relationship_type
     FROM itsm_record_relationships
     WHERE tenant_id = $1 AND source_record_id = $2
     ORDER BY created_at`,
    [tenantId, recordId],
  )
  return result.rows.map((row) => ({ reference: row.target_reference, type: row.target_type, relationshipType: row.relationship_type }))
}

async function serviceRequestWorkflow(db, row, session) {
  const [approvals, tasks] = await Promise.all([
    db.query(
      `SELECT id, label, status, approver_user_id, approver_person_id, approver_snapshot, decision_note, decided_at, sequence
       FROM service_request_approvals WHERE request_id = $1 ORDER BY sequence, created_at`,
      [row.id],
    ),
    db.query(
      `SELECT external_key, title, status, dependencies, team_snapshot, assignee_snapshot, completion_notes
       FROM service_request_tasks WHERE request_id = $1 ORDER BY created_at`,
      [row.id],
    ),
  ])
  const mappedApprovals = approvals.rows.map((item) => ({
    id: item.id,
    label: item.label,
    status: item.status,
    approver: object(item.approver_snapshot).name || 'Unassigned approver',
    note: item.decision_note,
    decidedAt: item.decided_at,
    canDecide: item.status === 'Pending' && (item.approver_user_id === session?.user_id || ['owner', 'admin'].includes(session?.tenant_role)),
  }))
  const mappedTasks = tasks.rows.map((task) => ({
    id: task.external_key,
    title: task.title,
    status: task.status,
    dependencies: task.dependencies || [],
    team: object(task.team_snapshot).name || '',
    assignee: object(task.assignee_snapshot).name || 'Unassigned',
    completionNotes: task.completion_notes,
  }))
  const pending = mappedApprovals.filter((item) => item.status === 'Pending').length
  const rejected = mappedApprovals.filter((item) => item.status === 'Rejected').length
  const completedTasks = mappedTasks.filter((item) => item.status === 'Completed').length
  const blockedTasks = mappedTasks.filter((item) => item.status === 'Blocked').length
  const readyForCompletion = mappedTasks.length === 0
    ? ['In Progress', 'Approved'].includes(row.status)
    : completedTasks === mappedTasks.length
  const approvalComplete = mappedApprovals.length > 0 && mappedApprovals.every((item) => item.status === 'Approved')
  const stage = row.status === 'Rejected' ? 'Rejected'
    : row.status === 'Closed' ? 'Closed'
      : row.status === 'Completed' ? 'Completion'
        : pending > 0 || row.status === 'Pending Approval' ? 'Approval'
          : approvalComplete || ['Approved', 'In Progress'].includes(row.status) ? 'Fulfilment'
            : 'Submitted'
  const blockers = []
  if (pending) blockers.push(`${pending} approval${pending === 1 ? '' : 's'} pending.`)
  if (rejected) blockers.push('A required approval was rejected.')
  if (blockedTasks) blockers.push(`${blockedTasks} fulfilment task${blockedTasks === 1 ? '' : 's'} blocked.`)
  if (row.status === 'In Progress' && !readyForCompletion) blockers.push(`${mappedTasks.length - completedTasks} fulfilment task${mappedTasks.length - completedTasks === 1 ? '' : 's'} remaining.`)
  return {
    reference: row.reference,
    type: 'Service Request',
    status: row.status,
    stage,
    stages: ['Submitted', 'Approval', 'Fulfilment', 'Completion', 'Closed'],
    workflowState: row.workflow_state || {},
    blockers,
    readyForCompletion,
    approvals: mappedApprovals,
    tasks: mappedTasks,
    metrics: { pendingApprovals: pending, rejectedApprovals: rejected, taskTotal: mappedTasks.length, taskComplete: completedTasks, taskBlocked: blockedTasks },
    actions: approvalComplete && row.status === 'New' ? ['In Progress'] : (SERVICE_REQUEST_TRANSITIONS[row.status] || []),
  }
}

async function genericWorkflow(db, row, tenantId) {
  const approvals = await genericApprovals(db, tenantId, row.reference)
  const relationItems = await relationships(db, tenantId, row.id)
  const approvalState = approvals.some((item) => item.status === 'Rejected') ? 'Rejected'
    : approvals.length && approvals.every((item) => item.status === 'Approved') ? 'Approved'
      : approvals.some((item) => item.status === 'Pending') ? 'Pending'
        : 'Not required'

  if (row.record_type === 'Problem') {
    const data = problemData(row)
    const linkedIncidents = relationItems.filter((item) => item.type === 'Incident')
    const linkedChanges = relationItems.filter((item) => item.type === 'Change')
    return {
      reference: row.reference,
      type: 'Problem',
      status: row.status,
      stage: row.status,
      stages: ['New', 'Investigation', 'Known Error', 'Resolved', 'Closed'],
      data,
      workflowState: row.workflow_state || {},
      relationships: relationItems,
      metrics: { linkedIncidents: linkedIncidents.length, linkedChanges: linkedChanges.length },
      blockers: problemBlockers(row, data, row.status === 'Investigation' ? 'Resolved' : ''),
      actions: PROBLEM_TRANSITIONS[row.status] || [],
    }
  }

  const data = changeData(row)
  return {
    reference: row.reference,
    type: 'Change',
    status: row.status,
    stage: row.status,
    stages: ['Draft', 'Assessment', 'Awaiting Approval', 'Scheduled', 'Implementing', 'Review', 'Completed'],
    outcomeStates: ['Failed', 'Backed Out', 'Cancelled'],
    data,
    workflowState: row.workflow_state || {},
    approvals,
    approvalState,
    relationships: relationItems,
    blockers: changeBlockers(row, data, row.status === 'Assessment' ? 'Awaiting Approval' : '', approvalState),
    actions: CHANGE_TRANSITIONS[row.status] || [],
  }
}

async function workflowPayload(db, found, tenantId, session = null) {
  return found.kind === 'request'
    ? serviceRequestWorkflow(db, found.row, session)
    : genericWorkflow(db, found.row, tenantId)
}

async function addRecordActivity(db, session, row, bodyText, metadata = {}) {
  await db.query(
    `INSERT INTO itsm_record_activities (
       tenant_id, record_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
     ) VALUES ($1,$2,$3,$4::jsonb,'workflow','internal',$5,$6::jsonb)`,
    [session.tenant_id, row.id, session.user_id, JSON.stringify({ name: session.name, email: session.email }), text(bodyText, 20000), JSON.stringify(metadata)],
  )
}

async function addRequestActivity(db, session, row, bodyText, visibility = 'customer', metadata = {}) {
  await db.query(
    `INSERT INTO service_request_activities (
       tenant_id, request_id, actor_user_id, actor_snapshot, kind, visibility, body_text, metadata
     ) VALUES ($1,$2,$3,$4::jsonb,'system',$5,$6,$7::jsonb)`,
    [session.tenant_id, row.id, session.user_id, JSON.stringify({ name: session.name, email: session.email }), visibility, text(bodyText, 20000), JSON.stringify(metadata)],
  )
}

async function defaultApprover(db, tenantId, excludeUserId = null) {
  const result = await db.query(
    `SELECT u.id, u.name, u.email, m.role
     FROM tenant_memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.tenant_id = $1
       AND m.status = 'active'
       AND m.role IN ('owner', 'admin')
     ORDER BY CASE WHEN u.id = $2 THEN 1 ELSE 0 END, CASE WHEN m.role = 'owner' THEN 0 ELSE 1 END, u.name
     LIMIT 1`,
    [tenantId, excludeUserId],
  )
  return result.rows[0] || null
}

async function ensureChangeApproval(db, session, row, data, requestedApproverUserId = '') {
  const existing = await db.query(
    `SELECT id FROM workflow_approvals
     WHERE tenant_id = $1 AND record_reference = $2 AND status = 'Pending'
     LIMIT 1`,
    [session.tenant_id, row.reference],
  )
  if (existing.rowCount) return existing.rows[0].id

  let approver = null
  if (requestedApproverUserId) {
    const lookup = await db.query(
      `SELECT u.id, u.name, u.email, m.role
       FROM users u JOIN tenant_memberships m ON m.user_id = u.id
       WHERE m.tenant_id = $1 AND u.id = $2 AND m.status = 'active' LIMIT 1`,
      [session.tenant_id, requestedApproverUserId],
    )
    approver = lookup.rows[0] || null
  }
  if (!approver) approver = await defaultApprover(db, session.tenant_id, session.user_id)
  if (!approver) {
    const error = new Error('No active administrator is available to approve this Change.')
    error.status = 409
    throw error
  }

  const approvalType = data.changeType === 'Emergency' ? 'emergency-change' : 'change'
  const result = await db.query(
    `INSERT INTO workflow_approvals (
       tenant_id, record_reference, record_type, approval_type, sequence, status,
       approver_user_id, approver_snapshot
     ) VALUES ($1,$2,'Change',$3,1,'Pending',$4,$5::jsonb)
     RETURNING id`,
    [session.tenant_id, row.reference, approvalType, approver.id, JSON.stringify({ name: approver.name, email: approver.email, role: approver.role })],
  )

  const event = await db.query(
    `INSERT INTO domain_events (tenant_id, event_type, aggregate_type, aggregate_reference, actor_user_id, payload)
     VALUES ($1,'change.approval_required','Change',$2,$3,$4::jsonb) RETURNING id`,
    [session.tenant_id, row.reference, session.user_id, JSON.stringify({ approvalId: result.rows[0].id, approverUserId: approver.id, changeType: data.changeType })],
  )
  await db.query(
    `SELECT hi5_insert_notification($1,$2,$3,'change.approval_required',$4,$5,'Change',$6,$7::jsonb)`,
    [session.tenant_id, approver.id, event.rows[0].id, `${row.reference} needs approval`, `${data.changeType} Change · ${row.title}`, row.reference, JSON.stringify({ approvalId: result.rows[0].id })],
  )
  return result.rows[0].id
}

function sanitiseProblemPatch(input) {
  const current = object(input)
  return {
    impactScope: text(current.impactScope, 5000),
    hypothesis: text(current.hypothesis, 10000),
    workaround: text(current.workaround, 15000),
    rootCause: text(current.rootCause, 15000),
    permanentFix: text(current.permanentFix, 15000),
    knownError: Boolean(current.knownError),
    knownErrorTitle: text(current.knownErrorTitle, 500),
    affectedVersions: array(current.affectedVersions).map((item) => text(item, 200)).filter(Boolean).slice(0, 100),
    knowledgeArticle: text(current.knowledgeArticle, 500),
  }
}

function sanitiseChangePatch(input) {
  const current = object(input)
  return {
    changeType: ['Standard', 'Normal', 'Emergency'].includes(current.changeType) ? current.changeType : 'Normal',
    risk: ['Low', 'Medium', 'High', 'Critical'].includes(current.risk) ? current.risk : 'Medium',
    riskSummary: text(current.riskSummary, 10000),
    businessReason: text(current.businessReason, 10000),
    implementationPlan: text(current.implementationPlan, 20000),
    testPlan: text(current.testPlan, 20000),
    backoutPlan: text(current.backoutPlan, 20000),
    plannedStart: text(current.plannedStart, 80),
    plannedEnd: text(current.plannedEnd, 80),
    downtime: text(current.downtime, 500),
    approvalRoute: text(current.approvalRoute, 500),
    implementationNotes: text(current.implementationNotes, 20000),
    reviewOutcome: text(current.reviewOutcome, 20000),
    failureReason: text(current.failureReason, 10000),
    affectedServices: array(current.affectedServices).map((item) => text(item, 300)).filter(Boolean).slice(0, 100),
    affectedCis: array(current.affectedCis).map((item) => text(item, 300)).filter(Boolean).slice(0, 100),
  }
}

export function registerWorkflowRoutes(app) {
  app.get('/api/v1/workflows/:reference', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const found = await findRecord(pool, auth.session.tenant_id, c.req.param('reference'))
    if (!found) return c.json({ error: 'ITSM record not found.' }, 404)
    return c.json(await workflowPayload(pool, found, auth.session.tenant_id, auth.session))
  })

  app.patch('/api/v1/workflows/:reference/data', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseBody(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)

    const result = await withTransaction(async (db) => {
      const found = await findRecord(db, auth.session.tenant_id, c.req.param('reference'), true)
      if (!found) return { notFound: true }
      if (found.kind === 'request') return { unsupported: true }
      if (!['Problem', 'Change'].includes(found.row.record_type)) return { unsupported: true }

      const before = object(found.row.record_data)
      const patch = found.row.record_type === 'Problem'
        ? sanitiseProblemPatch({ ...problemData(found.row), ...object(body.data) })
        : sanitiseChangePatch({ ...changeData(found.row), ...object(body.data) })
      const next = { ...before, ...patch }
      const updated = await db.query(
        `UPDATE itsm_records
         SET record_data = $3::jsonb, version = version + 1, updated_at = now()
         WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [auth.session.tenant_id, found.row.id, JSON.stringify(next)],
      )
      await addRecordActivity(db, auth.session, found.row, `${found.row.record_type} workflow details updated.`, { event: `${found.row.record_type.toLowerCase()}.workflow_data_updated` })
      return { found: { kind: 'record', row: updated.rows[0] } }
    })

    if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
    if (result.unsupported) return c.json({ error: 'Workflow data is available for Problems and Changes.' }, 400)
    return c.json(await workflowPayload(pool, result.found, auth.session.tenant_id, auth.session))
  })

  app.post('/api/v1/workflows/:reference/transition', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseBody(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const target = text(body.targetStatus, 80)

    try {
      const result = await withTransaction(async (db) => {
        const found = await findRecord(db, auth.session.tenant_id, c.req.param('reference'), true)
        if (!found) return { notFound: true }

        if (found.kind === 'request') {
          const row = found.row
          if (!(SERVICE_REQUEST_TRANSITIONS[row.status] || []).includes(target)) return { invalid: `${target} is not allowed from ${row.status}.` }
          const approvals = await db.query('SELECT status FROM service_request_approvals WHERE request_id = $1', [row.id])
          const tasks = await db.query('SELECT status FROM service_request_tasks WHERE request_id = $1', [row.id])
          const pending = approvals.rows.filter((item) => item.status === 'Pending').length
          const rejected = approvals.rows.filter((item) => item.status === 'Rejected').length
          const incomplete = tasks.rows.filter((item) => item.status !== 'Completed').length
          const values = object(body.values)
          if (target === 'Approved' && (pending || rejected)) return { invalid: 'Required approvals have not all been approved.' }
          if (target === 'In Progress' && (pending || rejected)) return { invalid: 'Required approvals must be completed before fulfilment starts.' }
          if (target === 'Completed' && incomplete) return { invalid: 'Complete all fulfilment tasks before completing the request.' }
          if (target === 'Completed' && !text(values.completionNotes, 10000)) return { invalid: 'Fulfilment summary is required before completion.' }
          if (row.status === 'Completed' && target === 'In Progress' && !text(values.reopenReason, 10000)) return { invalid: 'Reopen reason is required.' }

          const operational = {
            ...object(row.operational_data),
            ...(values.completionNotes ? { completionNotes: text(values.completionNotes, 10000) } : {}),
            ...(values.reopenReason ? { reopenReason: text(values.reopenReason, 10000) } : {}),
          }
          const updated = await db.query(
            `UPDATE service_requests
             SET status = $3,
                 operational_data = $4::jsonb,
                 workflow_state = coalesce(workflow_state, '{}'::jsonb) || $5::jsonb,
                 closed_at = CASE WHEN $3 = 'Closed' THEN now() ELSE closed_at END,
                 updated_at = now()
             WHERE tenant_id = $1 AND id = $2 RETURNING *`,
            [auth.session.tenant_id, row.id, target, JSON.stringify(operational), JSON.stringify({ lastTransitionAt: new Date().toISOString(), lastTransitionBy: auth.session.user_id, readyForCompletion: target === 'Completed' })],
          )
          await addRequestActivity(db, auth.session, row, `Status changed from ${row.status} to ${target}${target === 'Completed' ? ` — ${text(values.completionNotes, 10000)}` : ''}.`, 'customer', { event: 'service_request.workflow_transition', from: row.status, to: target })
          return { found: { kind: 'request', row: updated.rows[0] } }
        }

        const row = found.row
        if (row.record_type === 'Problem') {
          if (!(PROBLEM_TRANSITIONS[row.status] || []).includes(target)) return { invalid: `${target} is not allowed from ${row.status}.` }
          const data = problemData(row)
          const blockers = problemBlockers(row, data, target)
          if (blockers.length) return { invalid: blockers[0], blockers }
          const nextData = target === 'Known Error' ? { ...object(row.record_data), knownError: true } : object(row.record_data)
          const updated = await db.query(
            `UPDATE itsm_records
             SET status = $3, record_data = $4::jsonb,
                 workflow_state = coalesce(workflow_state, '{}'::jsonb) || $5::jsonb,
                 resolved_at = CASE WHEN $3 = 'Resolved' THEN COALESCE(resolved_at, now()) ELSE resolved_at END,
                 closed_at = CASE WHEN $3 = 'Closed' THEN COALESCE(closed_at, now()) ELSE closed_at END,
                 version = version + 1, updated_at = now()
             WHERE tenant_id = $1 AND id = $2 RETURNING *`,
            [auth.session.tenant_id, row.id, target, JSON.stringify(nextData), JSON.stringify({ lastTransitionAt: new Date().toISOString(), lastTransitionBy: auth.session.user_id })],
          )
          await addRecordActivity(db, auth.session, row, `Problem moved from ${row.status} to ${target}.`, { event: 'problem.workflow_transition', from: row.status, to: target })
          return { found: { kind: 'record', row: updated.rows[0] } }
        }

        if (row.record_type === 'Change') {
          if (!(CHANGE_TRANSITIONS[row.status] || []).includes(target)) return { invalid: `${target} is not allowed from ${row.status}.` }
          const data = changeData(row)
          const approvals = await genericApprovals(db, auth.session.tenant_id, row.reference)
          const approvalState = approvals.some((item) => item.status === 'Rejected') ? 'Rejected'
            : approvals.length && approvals.every((item) => item.status === 'Approved') ? 'Approved'
              : approvals.some((item) => item.status === 'Pending') ? 'Pending'
                : 'Not required'
          const config = await configurationFor(db, auth.session.tenant_id)
          const standardAuto = Boolean(object(config.itsm).standardChangeAutoApprove)
          let resolvedTarget = target
          const blockers = changeBlockers(row, data, target, approvalState)
          if (target === 'Scheduled' && data.changeType === 'Standard' && standardAuto) {
            const filtered = blockers.filter((item) => !item.includes('approval'))
            if (filtered.length) return { invalid: filtered[0], blockers: filtered }
          } else if (blockers.length) {
            return { invalid: blockers[0], blockers }
          }

          if (target === 'Awaiting Approval') {
            if (data.changeType === 'Standard' && standardAuto) {
              const approver = await defaultApprover(db, auth.session.tenant_id, auth.session.user_id)
              await db.query(
                `INSERT INTO workflow_approvals (tenant_id, record_reference, record_type, approval_type, sequence, status, approver_user_id, approver_snapshot, decision_note, decided_at)
                 VALUES ($1,$2,'Change','standard-auto',1,'Approved',$3,$4::jsonb,'Automatically approved by Standard Change policy.',now())`,
                [auth.session.tenant_id, row.reference, approver?.id || null, JSON.stringify({ name: approver?.name || 'Standard Change policy', email: approver?.email || '' })],
              )
              resolvedTarget = 'Scheduled'
            } else {
              await ensureChangeApproval(db, auth.session, row, data, text(body.approverUserId, 80))
            }
          }

          const updated = await db.query(
            `UPDATE itsm_records
             SET status = $3,
                 workflow_state = coalesce(workflow_state, '{}'::jsonb) || $4::jsonb,
                 closed_at = CASE WHEN $3 IN ('Completed','Cancelled','Backed Out') THEN COALESCE(closed_at, now()) ELSE closed_at END,
                 version = version + 1, updated_at = now()
             WHERE tenant_id = $1 AND id = $2 RETURNING *`,
            [auth.session.tenant_id, row.id, resolvedTarget, JSON.stringify({ lastTransitionAt: new Date().toISOString(), lastTransitionBy: auth.session.user_id, changeType: data.changeType })],
          )
          await addRecordActivity(db, auth.session, row, `Change moved from ${row.status} to ${resolvedTarget}.`, { event: 'change.workflow_transition', from: row.status, to: resolvedTarget })
          return { found: { kind: 'record', row: updated.rows[0] } }
        }

        return { unsupported: true }
      })

      if (result.notFound) return c.json({ error: 'ITSM record not found.' }, 404)
      if (result.unsupported) return c.json({ error: 'This workflow is not available for this record type.' }, 400)
      if (result.invalid) return c.json({ error: result.invalid, blockers: result.blockers || [result.invalid] }, 409)
      return c.json(await workflowPayload(pool, result.found, auth.session.tenant_id, auth.session))
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/workflows/:reference/approvals/:approvalId/decision', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error
    const body = await parseBody(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const decision = body.decision === 'Approved' ? 'Approved' : body.decision === 'Rejected' ? 'Rejected' : ''
    if (!decision) return c.json({ error: 'Decision must be Approved or Rejected.' }, 400)

    const result = await withTransaction(async (db) => {
      const found = await findRecord(db, auth.session.tenant_id, c.req.param('reference'), true)
      if (!found || found.kind !== 'record' || found.row.record_type !== 'Change') return { notFound: true }
      const approval = await db.query(
        `SELECT * FROM workflow_approvals
         WHERE id = $1 AND tenant_id = $2 AND record_reference = $3
         LIMIT 1 FOR UPDATE`,
        [c.req.param('approvalId'), auth.session.tenant_id, found.row.reference],
      )
      if (!approval.rowCount) return { approvalMissing: true }
      const current = approval.rows[0]
      if (current.status !== 'Pending') return { alreadyDecided: true }
      if (current.approver_user_id && current.approver_user_id !== auth.session.user_id && !['owner', 'admin'].includes(auth.session.tenant_role)) return { forbidden: true }

      await db.query(
        `UPDATE workflow_approvals
         SET status = $2, decision_note = $3, decided_at = now(), updated_at = now()
         WHERE id = $1`,
        [current.id, decision, text(body.note, 5000)],
      )
      const event = await db.query(
        `INSERT INTO domain_events (tenant_id, event_type, aggregate_type, aggregate_reference, actor_user_id, payload)
         VALUES ($1,$2,'Change',$3,$4,$5::jsonb) RETURNING id`,
        [auth.session.tenant_id, decision === 'Approved' ? 'change.approval_approved' : 'change.approval_rejected', found.row.reference, auth.session.user_id, JSON.stringify({ approvalId: current.id, decision, note: text(body.note, 5000) })],
      )
      const approvals = await genericApprovals(db, auth.session.tenant_id, found.row.reference)
      const anyRejected = approvals.some((item) => item.status === 'Rejected')
      const allApproved = approvals.length > 0 && approvals.every((item) => item.status === 'Approved')
      let nextStatus = found.row.status
      if (anyRejected) nextStatus = 'Cancelled'
      else if (allApproved && found.row.status === 'Awaiting Approval') nextStatus = 'Scheduled'

      const updated = await db.query(
        `UPDATE itsm_records
         SET status = $3,
             workflow_state = coalesce(workflow_state, '{}'::jsonb) || $4::jsonb,
             closed_at = CASE WHEN $3 = 'Cancelled' THEN COALESCE(closed_at, now()) ELSE closed_at END,
             version = version + 1, updated_at = now()
         WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [auth.session.tenant_id, found.row.id, nextStatus, JSON.stringify({ approvalState: anyRejected ? 'Rejected' : allApproved ? 'Approved' : 'Pending' })],
      )
      await addRecordActivity(db, auth.session, found.row, `Change approval ${decision.toLowerCase()}${body.note ? ` — ${text(body.note, 5000)}` : ''}.`, { event: decision === 'Approved' ? 'change.approval_approved' : 'change.approval_rejected', approvalId: current.id })

      if (found.row.created_by_user_id && found.row.created_by_user_id !== auth.session.user_id) {
        await db.query(
          `SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,'Change',$7,$8::jsonb)`,
          [auth.session.tenant_id, found.row.created_by_user_id, event.rows[0].id, decision === 'Approved' ? 'change.approval_approved' : 'change.approval_rejected', `${found.row.reference} ${decision.toLowerCase()}`, text(body.note, 5000) || `Change approval ${decision.toLowerCase()}.`, found.row.reference, JSON.stringify({ approvalId: current.id, decision })],
        )
      }
      return { found: { kind: 'record', row: updated.rows[0] } }
    })

    if (result.notFound) return c.json({ error: 'Change not found.' }, 404)
    if (result.approvalMissing) return c.json({ error: 'Approval not found.' }, 404)
    if (result.alreadyDecided) return c.json({ error: 'This approval has already been decided.' }, 409)
    if (result.forbidden) return c.json({ error: 'This approval is assigned to another approver.' }, 403)
    return c.json(await workflowPayload(pool, result.found, auth.session.tenant_id, auth.session))
  })
}
