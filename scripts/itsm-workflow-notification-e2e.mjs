import { createHash, randomBytes } from 'node:crypto'
import pg from 'pg'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-workflow-${suffix}`.slice(0, 42)
const ownerEmail = `workflow-owner-${suffix}@hi5central.test`
const tenantOrigin = `https://${slug}.hi5central.com`
const token = randomBytes(32).toString('base64url')
const cookie = `hi5central_session=${token}`
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

async function json(path, { method = 'GET', body } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: tenantOrigin,
      Cookie: cookie,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

async function expectStatus(path, options, status, label) {
  const result = await json(path, options)
  assert(result.response.status === status, `${label}: expected ${status}, got ${result.response.status}: ${result.payload.error || JSON.stringify(result.payload)}`)
  return result.payload
}

async function transition(reference, targetStatus, values = {}, extra = {}) {
  return expectStatus(
    `/api/v1/workflows/${encodeURIComponent(reference)}/transition`,
    { method: 'POST', body: { targetStatus, values, ...extra } },
    200,
    `${reference} -> ${targetStatus}`,
  )
}

async function patchWorkflow(reference, data) {
  return expectStatus(
    `/api/v1/workflows/${encodeURIComponent(reference)}/data`,
    { method: 'PATCH', body: { data } },
    200,
    `${reference} workflow data update`,
  )
}

await db.connect()
let tenantId = null
let ownerId = null
try {
  console.log(`Workflow/notification E2E tenant: ${slug}`)
  console.log('1. Seeding isolated tenant, owner session and linked Person')

  const tenant = await db.query(
    `INSERT INTO tenants (slug, company_name, status)
     VALUES ($1, 'CI Workflow Validation', 'active') RETURNING id`,
    [slug],
  )
  tenantId = tenant.rows[0].id

  const owner = await db.query(
    `INSERT INTO users (email, name, password_hash, email_verified_at)
     VALUES ($1, 'CI Workflow Owner', 'test-only', now()) RETURNING id`,
    [ownerEmail],
  )
  ownerId = owner.rows[0].id

  await db.query(
    `INSERT INTO tenant_memberships (tenant_id, user_id, role, status)
     VALUES ($1, $2, 'owner', 'active')`,
    [tenantId, ownerId],
  )

  const configuration = {
    security: { requireMfa: false },
    itsm: { standardChangeAutoApprove: true },
  }
  await db.query(
    `INSERT INTO tenant_settings (
       tenant_id, modules, onboarding_step, onboarding_completed_at,
       tenant_url, portal_url, onboarding_data, configuration
     ) VALUES ($1, '{"itsm":true,"rmm":true}'::jsonb, 'complete', now(), $2, $3, $4::jsonb, $4::jsonb)`,
    [tenantId, tenantOrigin, `https://${slug}-portal.hi5central.com`, JSON.stringify(configuration)],
  )

  await db.query(
    `INSERT INTO auth_sessions (tenant_id, user_id, token_hash, expires_at)
     VALUES ($1, $2, $3, now() + interval '1 hour')`,
    [tenantId, ownerId, createHash('sha256').update(token).digest('hex')],
  )

  const department = await db.query(
    `INSERT INTO organisation_departments (tenant_id, external_key, name)
     VALUES ($1, 'DEPT-WF', 'Workflow Validation') RETURNING id`,
    [tenantId],
  )
  const team = await db.query(
    `INSERT INTO organisation_teams (tenant_id, external_key, department_id, name)
     VALUES ($1, 'TEAM-WF', $2, 'Workflow Team') RETURNING id`,
    [tenantId, department.rows[0].id],
  )
  const person = await db.query(
    `INSERT INTO organisation_people (
       tenant_id, external_key, user_id, primary_team_id, department_id,
       name, email, job_title, access_profile, active
     ) VALUES ($1, 'USR-WF-OWNER', $2, $3, $4, 'CI Workflow Owner', $5, 'Owner', 'admin', true)
     RETURNING id`,
    [tenantId, ownerId, team.rows[0].id, department.rows[0].id, ownerEmail],
  )
  const personId = person.rows[0].id

  console.log('2. Applying notification defaults before workflow activity')
  const tenantSettings = await expectStatus('/api/v1/notification-settings', {
    method: 'PATCH',
    body: {
      settings: {
        channels: { inApp: true, email: false, browser: true },
        categories: { calendar: true, platform: true, serviceRequests: true, problems: true, changes: true },
      },
    },
  }, 200, 'tenant notification settings')
  assert(tenantSettings.settings.channels.email === false, 'Tenant email default was not persisted')
  assert(tenantSettings.settings.channels.browser === true, 'Tenant browser default was not persisted')

  const personal = await expectStatus('/api/v1/notification-preferences', {
    method: 'PATCH',
    body: { preferences: { categories: { calendar: false } } },
  }, 200, 'personal notification preferences')
  assert(personal.preferences.categories.calendar === false, 'Personal notification category override was not persisted')

  await expectStatus('/api/v1/notification-preferences', {
    method: 'PATCH',
    body: { preferences: { categories: { calendar: true } } },
  }, 200, 'personal notification preference restore')

  console.log('3. Exercising Service Request approval, dependency orchestration and migration 018 regression guard')
  const request = await db.query(
    `INSERT INTO service_requests (
       tenant_id, reference, requester_user_id, requester_person_id, requester_snapshot,
       title, status, fulfilment_team_id, fulfilment_team_snapshot, assigned_person_id,
       approval_mode_snapshot, workflow_key_snapshot, created_by_user_id
     ) VALUES (
       $1, 'REQ-WF-0001', $2, $3, $4::jsonb,
       'Workflow validation request', 'Pending Approval', $5, $6::jsonb, $3,
       'manager', 'ci-dependent-flow', $2
     ) RETURNING id`,
    [tenantId, ownerId, personId, JSON.stringify({ name: 'CI Workflow Owner', email: ownerEmail }), team.rows[0].id, JSON.stringify({ name: 'Workflow Team' })],
  )
  const requestId = request.rows[0].id

  const approval = await db.query(
    `INSERT INTO service_request_approvals (
       tenant_id, request_id, sequence, label, status, approver_user_id, approver_snapshot
     ) VALUES ($1, $2, 1, 'Manager approval', 'Pending', $3, $4::jsonb)
     RETURNING id`,
    [tenantId, requestId, ownerId, JSON.stringify({ name: 'CI Workflow Owner', email: ownerEmail })],
  )

  await db.query(
    `INSERT INTO service_request_tasks (
       tenant_id, request_id, external_key, title, status, team_id, team_snapshot,
       assignee_person_id, assignee_snapshot, dependencies
     ) VALUES
       ($1,$2,'task-a','Prepare access','Waiting',$3,$4::jsonb,$5,$6::jsonb,'[]'::jsonb),
       ($1,$2,'task-b','Validate access','Waiting',$3,$4::jsonb,$5,$6::jsonb,'["task-a"]'::jsonb)`,
    [tenantId, requestId, team.rows[0].id, JSON.stringify({ name: 'Workflow Team' }), personId, JSON.stringify({ name: 'CI Workflow Owner', email: ownerEmail })],
  )

  const waitingBeforeApproval = await db.query(
    `SELECT external_key, status FROM service_request_tasks WHERE request_id = $1 ORDER BY external_key`,
    [requestId],
  )
  assert(waitingBeforeApproval.rows.every((row) => row.status === 'Waiting'), 'Tasks were released before approval completed')

  await db.query(
    `UPDATE service_request_approvals
     SET status = 'Approved', decision_note = 'CI approved', decided_at = now(), updated_at = now()
     WHERE id = $1`,
    [approval.rows[0].id],
  )

  let requestState = await db.query('SELECT status, workflow_state FROM service_requests WHERE id = $1', [requestId])
  assert(requestState.rows[0].status === 'Approved', `Approval reconciliation did not set Approved: ${requestState.rows[0].status}`)
  assert(requestState.rows[0].workflow_state.approvalState === 'Approved', 'Approval workflow state was not reconciled')

  const released = await db.query(
    `SELECT external_key, status FROM service_request_tasks WHERE request_id = $1 ORDER BY external_key`,
    [requestId],
  )
  assert(released.rows[0].external_key === 'task-a' && released.rows[0].status === 'Ready', 'Root fulfilment task was not released after approval')
  assert(released.rows[1].external_key === 'task-b' && released.rows[1].status === 'Waiting', 'Dependent fulfilment task released too early')

  await db.query(`UPDATE service_requests SET status = 'New' WHERE id = $1`, [requestId])
  requestState = await db.query('SELECT status FROM service_requests WHERE id = $1', [requestId])
  assert(requestState.rows[0].status === 'Approved', 'Migration 018 failed: legacy Approved -> New regression was not blocked')

  await db.query(
    `UPDATE service_request_tasks
     SET status = 'Completed', completion_notes = 'Prepared', completed_at = now(), updated_at = now()
     WHERE request_id = $1 AND external_key = 'task-a'`,
    [requestId],
  )
  const afterFirstTask = await db.query(
    `SELECT external_key, status FROM service_request_tasks WHERE request_id = $1 ORDER BY external_key`,
    [requestId],
  )
  assert(afterFirstTask.rows[1].status === 'Ready', 'Dependent task did not release after prerequisite completion')
  requestState = await db.query('SELECT status FROM service_requests WHERE id = $1', [requestId])
  assert(requestState.rows[0].status === 'In Progress', 'Parent request did not enter In Progress when fulfilment started')

  await db.query(
    `UPDATE service_request_tasks
     SET status = 'Completed', completion_notes = 'Validated', completed_at = now(), updated_at = now()
     WHERE request_id = $1 AND external_key = 'task-b'`,
    [requestId],
  )
  requestState = await db.query('SELECT workflow_state FROM service_requests WHERE id = $1', [requestId])
  assert(requestState.rows[0].workflow_state.readyForCompletion === true, 'Parent request was not marked ready for completion')

  const requestWorkflow = await expectStatus('/api/v1/workflows/REQ-WF-0001', {}, 200, 'service request workflow read')
  assert(requestWorkflow.readyForCompletion === true, 'Workflow API did not report completion readiness')
  await transition('REQ-WF-0001', 'Completed', { completionNotes: 'All fulfilment steps completed.' })
  const closedRequest = await transition('REQ-WF-0001', 'Closed')
  assert(closedRequest.status === 'Closed', 'Service Request did not close through the governed workflow')

  console.log('4. Exercising the complete Problem lifecycle and workflow gates')
  await db.query(
    `INSERT INTO itsm_records (
       tenant_id, reference, record_type, requester_person_id, requester_snapshot,
       title, description, priority, status, assignment_team_id, assignment_team_snapshot,
       assigned_person_id, assignee_snapshot, record_data, created_by_user_id
     ) VALUES ($1,'PRB-WF-0001','Problem',$2,$3::jsonb,'Recurring CI failure','Workflow lifecycle validation','High','New',$4,$5::jsonb,$2,$3::jsonb,'{}'::jsonb,$6)`,
    [tenantId, personId, JSON.stringify({ name: 'CI Workflow Owner', email: ownerEmail }), team.rows[0].id, JSON.stringify({ name: 'Workflow Team' }), ownerId],
  )

  await transition('PRB-WF-0001', 'Investigation')
  const blockedKnownError = await expectStatus('/api/v1/workflows/PRB-WF-0001/transition', {
    method: 'POST', body: { targetStatus: 'Known Error', values: {} },
  }, 409, 'Problem Known Error gate')
  assert(blockedKnownError.blockers?.length > 0, 'Problem Known Error gate did not return blockers')

  await patchWorkflow('PRB-WF-0001', {
    impactScope: 'Multiple CI users', hypothesis: 'Race condition', workaround: 'Restart the affected service',
    knownErrorTitle: 'CI recurring failure', affectedVersions: ['1.0'], knowledgeArticle: 'KB-CI-001',
  })
  let problem = await transition('PRB-WF-0001', 'Known Error')
  assert(problem.data.knownError === true, 'Problem did not mark itself as a Known Error')

  const blockedResolution = await expectStatus('/api/v1/workflows/PRB-WF-0001/transition', {
    method: 'POST', body: { targetStatus: 'Resolved', values: {} },
  }, 409, 'Problem resolution gate')
  assert(blockedResolution.blockers?.some((item) => item.includes('Root cause')), 'Problem resolution gate did not require root cause')

  await patchWorkflow('PRB-WF-0001', {
    rootCause: 'Confirmed CI race condition', permanentFix: 'Serialise token refresh', knownError: true,
  })
  problem = await transition('PRB-WF-0001', 'Resolved')
  assert(problem.status === 'Resolved', 'Problem did not reach Resolved')
  problem = await transition('PRB-WF-0001', 'Closed')
  assert(problem.status === 'Closed', 'Problem did not reach Closed')

  console.log('5. Exercising Standard, Normal and Emergency Change governance')
  const changeRecords = [
    ['CHG-STD-0001', 'Standard'],
    ['CHG-NRM-0001', 'Normal'],
    ['CHG-EMG-0001', 'Emergency'],
  ]
  for (const [reference, changeType] of changeRecords) {
    await db.query(
      `INSERT INTO itsm_records (
         tenant_id, reference, record_type, requester_person_id, requester_snapshot,
         title, description, priority, status, assignment_team_id, assignment_team_snapshot,
         assigned_person_id, assignee_snapshot, record_data, created_by_user_id
       ) VALUES ($1,$2,'Change',$3,$4::jsonb,$5,'Change workflow validation','High','Draft',$6,$7::jsonb,$3,$4::jsonb,$8::jsonb,$9)`,
      [tenantId, reference, personId, JSON.stringify({ name: 'CI Workflow Owner', email: ownerEmail }), `${changeType} CI Change`, team.rows[0].id, JSON.stringify({ name: 'Workflow Team' }), JSON.stringify({ changeType }), ownerId],
    )
    await patchWorkflow(reference, {
      changeType,
      risk: changeType === 'Emergency' ? 'Critical' : 'Medium',
      riskSummary: `${changeType} risk`,
      businessReason: `${changeType} CI business reason`,
      implementationPlan: 'Apply the validated CI change',
      testPlan: 'Run CI verification',
      backoutPlan: 'Restore the previous CI state',
      plannedStart: '2026-09-12T09:00:00+01:00',
      plannedEnd: '2026-09-12T10:00:00+01:00',
    })
    await transition(reference, 'Assessment')
  }

  const standard = await transition('CHG-STD-0001', 'Awaiting Approval')
  assert(standard.status === 'Scheduled', 'Standard Change was not auto-approved and scheduled')
  assert(standard.approvalState === 'Approved', 'Standard Change approval state was not Approved')
  const standardApproval = await db.query(
    `SELECT approval_type, status FROM workflow_approvals WHERE tenant_id = $1 AND record_reference = 'CHG-STD-0001'`,
    [tenantId],
  )
  assert(standardApproval.rows[0]?.approval_type === 'standard-auto' && standardApproval.rows[0]?.status === 'Approved', 'Standard Change did not create the expected auto-approval record')

  const normalBlocked = await expectStatus('/api/v1/workflows/CHG-NRM-0001/transition', {
    method: 'POST', body: { targetStatus: 'Scheduled', values: {} },
  }, 409, 'Normal Change approval gate')
  assert(normalBlocked.error?.includes('approval'), 'Normal Change was not blocked on approval')

  let normal = await transition('CHG-NRM-0001', 'Awaiting Approval')
  assert(normal.status === 'Awaiting Approval' && normal.approvals?.length === 1, 'Normal Change did not create a pending approval')
  const normalApprovalId = normal.approvals[0].id
  normal = await expectStatus(`/api/v1/workflows/CHG-NRM-0001/approvals/${encodeURIComponent(normalApprovalId)}/decision`, {
    method: 'POST', body: { decision: 'Approved', note: 'CI CAB approved' },
  }, 200, 'Normal Change approval decision')
  assert(normal.status === 'Scheduled' && normal.approvalState === 'Approved', 'Approved Normal Change did not move to Scheduled')

  await transition('CHG-NRM-0001', 'Implementing')
  const reviewBlocked = await expectStatus('/api/v1/workflows/CHG-NRM-0001/transition', {
    method: 'POST', body: { targetStatus: 'Review', values: {} },
  }, 409, 'Change implementation-notes gate')
  assert(reviewBlocked.error?.includes('implementation notes'), 'Change Review gate did not require implementation notes')
  await patchWorkflow('CHG-NRM-0001', { implementationNotes: 'CI implementation completed successfully.' })
  await transition('CHG-NRM-0001', 'Review')
  const completionBlocked = await expectStatus('/api/v1/workflows/CHG-NRM-0001/transition', {
    method: 'POST', body: { targetStatus: 'Completed', values: {} },
  }, 409, 'Change PIR gate')
  assert(completionBlocked.error?.includes('Post-implementation'), 'Change completion gate did not require PIR outcome')
  await patchWorkflow('CHG-NRM-0001', { reviewOutcome: 'CI PIR passed with no issues.' })
  normal = await transition('CHG-NRM-0001', 'Completed')
  assert(normal.status === 'Completed', 'Normal Change did not complete after PIR')

  let emergency = await transition('CHG-EMG-0001', 'Awaiting Approval')
  assert(emergency.approvals?.[0]?.type === 'emergency-change', 'Emergency Change did not create emergency approval type')
  emergency = await expectStatus(`/api/v1/workflows/CHG-EMG-0001/approvals/${encodeURIComponent(emergency.approvals[0].id)}/decision`, {
    method: 'POST', body: { decision: 'Rejected', note: 'CI emergency risk rejected' },
  }, 200, 'Emergency Change rejection')
  assert(emergency.status === 'Cancelled' && emergency.approvalState === 'Rejected', 'Rejected Emergency Change did not cancel')

  console.log('6. Exercising central notifications, read state, browser delivery and client-event deduplication')
  const externalId = `calendar-${suffix}`
  const createdNotification = await expectStatus('/api/v1/notifications/client-event', {
    method: 'POST',
    body: {
      source: 'calendar',
      externalId,
      title: 'CI calendar event changed',
      detail: 'Workflow validation calendar notification',
      target: { type: 'Event', eventId: `event-${suffix}` },
      tone: 'info',
    },
  }, 201, 'client notification bridge')
  assert(createdNotification.id, 'Client notification bridge did not return an id')

  const duplicateNotification = await expectStatus('/api/v1/notifications/client-event', {
    method: 'POST',
    body: {
      source: 'calendar', externalId, title: 'CI calendar event changed',
      detail: 'Duplicate should collapse', target: { type: 'Event', eventId: `event-${suffix}` },
    },
  }, 200, 'client notification deduplication')
  assert(duplicateNotification.duplicate === true && duplicateNotification.id === createdNotification.id, 'Client notification externalId was not deduplicated')

  let notifications = await expectStatus('/api/v1/notifications?limit=250', {}, 200, 'notification centre list')
  const calendarItem = notifications.items.find((item) => item.id === createdNotification.id)
  assert(calendarItem && calendarItem.category === 'calendar' && calendarItem.read === false, 'Calendar notification was not visible in the Notification Centre')
  assert(notifications.unreadCount > 0, 'Notification Centre did not report unread notifications')

  await expectStatus(`/api/v1/notifications/${encodeURIComponent(createdNotification.id)}/read`, { method: 'POST' }, 200, 'notification read state')
  notifications = await expectStatus('/api/v1/notifications?limit=250', {}, 200, 'notification centre reread')
  assert(notifications.items.find((item) => item.id === createdNotification.id)?.read === true, 'Notification read state did not persist')

  await expectStatus(`/api/v1/notifications/${encodeURIComponent(createdNotification.id)}/browser-delivered`, { method: 'POST' }, 200, 'browser delivery acknowledgement')
  const deliveries = await db.query(
    `SELECT channel, status FROM notification_deliveries WHERE notification_id = $1 ORDER BY channel`,
    [createdNotification.id],
  )
  assert(deliveries.rows.some((row) => row.channel === 'email'), 'Notification email delivery row was not queued')
  assert(deliveries.rows.some((row) => row.channel === 'browser' && row.status === 'sent'), 'Browser notification delivery was not marked sent')

  console.log('7. Verifying domain-event coverage and tenant-scoped workflow state')
  const eventCounts = await db.query(
    `SELECT event_type, count(*)::int AS count
     FROM domain_events
     WHERE tenant_id = $1
     GROUP BY event_type`,
    [tenantId],
  )
  const eventMap = new Map(eventCounts.rows.map((row) => [row.event_type, row.count]))
  assert((eventMap.get('service_request.approval_approved') || 0) >= 1, 'Service Request approval domain event is missing')
  assert((eventMap.get('problem.status_changed') || 0) >= 4, 'Problem lifecycle status events are incomplete')
  assert((eventMap.get('change.status_changed') || 0) >= 6, 'Change lifecycle status events are incomplete')
  assert((eventMap.get('calendar.event') || 0) === 1, 'Client calendar event was not stored exactly once in the domain event store')

  const guardDefinition = await db.query(
    `SELECT pg_get_functiondef(p.oid) AS definition
     FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = current_schema() AND p.proname = 'hi5_service_request_status_guard'`,
  )
  assert(guardDefinition.rowCount === 1 && guardDefinition.rows[0].definition.includes("OLD.status = 'Approved'"), 'Migration 018 status-guard function is not installed')

  console.log('Workflow and notification runtime E2E passed')
} finally {
  if (tenantId) await db.query('DELETE FROM tenants WHERE id = $1', [tenantId]).catch(() => {})
  if (ownerId) await db.query('DELETE FROM users WHERE id = $1', [ownerId]).catch(() => {})
  await db.end()
}
