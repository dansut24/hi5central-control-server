import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'
const origin = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const portalOrigin = process.env.E2E_PORTAL_ORIGIN || origin
const portalReferer = process.env.E2E_PORTAL_REFERER || `${portalOrigin}/portal`
const results = []

function ok(name, detail = '') {
  results.push({ name, ok: true, detail })
  console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`)
}

async function api(token, path, { method = 'GET', body, portal = false } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: portal ? portalOrigin : origin,
      ...(portal ? { Referer: portalReferer } : {}),
      Cookie: `${portal ? 'hi5central_portal_session' : 'hi5central_session'}=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}
async function main() {
  const tenantResult = await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])
  assert.equal(tenantResult.rowCount, 1, 'test tenant must exist')
  const tenantId = tenantResult.rows[0].id
  const users = await pool.query(
    `SELECT u.id,u.email,p.external_key,p.name
     FROM users u
     JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenantId, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = users.rows.find((row) => row.email.toLowerCase() === OWNER_EMAIL)
  const requester = users.rows.find((row) => row.email.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.id && owner?.external_key, 'owner person is required')
  assert(requester?.id && requester?.external_key, 'requester person is required')

  const ownerToken = await createSession(pool, {
    tenantId, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace',
  })
  const requesterToken = await createSession(pool, {
    tenantId, userId: requester.id, mfaVerified: true, ttlSeconds: 3600, surface: 'portal',
  })
  const session = await api(ownerToken, '/api/v1/auth/session')
  assert.equal(session.authenticated, true)
  ok('workspace session', session.user.email)

  const stamp = new Date().toISOString()
  const incident = await api(ownerToken, '/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Incident', title: `Overnight E2E Incident ${stamp}`,
      description: 'Automated end-to-end validation incident.',
      requesterId: requester.external_key, priority: 'High',
      team: 'Servers', assignee: OWNER_EMAIL, source: 'overnight-e2e',
    },
  })
  assert.match(incident.id, /^INC-/)
  ok('incident created', incident.id)
  let detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}`)
  assert(detail.sla?.response?.dueAt)
  assert(detail.sla?.resolution?.dueAt)
  ok('incident SLA initialised', `v${detail.version}`)

  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}/activity`, {
    method: 'POST', body: { visibility: 'internal', text: 'Internal technician note — should not be customer-visible.' },
  })
  assert.equal(detail.activities[0].visibility, 'internal')
  ok('internal note added')

  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}/activity`, {
    method: 'POST', body: { visibility: 'customer', text: 'Customer-facing E2E update from Hi5Central.' },
  })
  assert(detail.firstResponseAt)
  assert.equal(detail.activities[0].visibility, 'customer')
  ok('customer update added and SLA response captured')

  const attachmentContent = Buffer.from('Hi5Central overnight E2E attachment').toString('base64')
  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}/attachments`, {
    method: 'POST',
    body: { fileName: 'overnight-e2e.txt', mimeType: 'text/plain', contentBase64: attachmentContent },
  })
  assert(detail.attachments.some((item) => item.fileName === 'overnight-e2e.txt'))
  ok('attachment uploaded')

  let version = detail.version
  const taskCreate = await api(ownerToken, `/api/v1/itsm-actions/${incident.id}/tasks`, {
    method: 'POST',
    body: { version, title: 'Validate incident task lifecycle', team: 'Servers', assignee: OWNER_EMAIL,
      instructions: 'Start and complete this task as part of E2E.', dueAt: new Date(Date.now() + 3600000).toISOString() },
  })
  assert.equal(taskCreate.task.status, 'Open')
  ok('incident task created', taskCreate.task.id)
  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}`)
  version = detail.version
  let taskUpdate = await api(ownerToken, `/api/v1/itsm-actions/${incident.id}/tasks/${taskCreate.task.id}`, {
    method: 'PATCH', body: { version, status: 'In Progress' },
  })
  assert.equal(taskUpdate.task.status, 'In Progress')
  ok('incident task started')

  taskUpdate = await api(ownerToken, `/api/v1/itsm-actions/${incident.id}/tasks/${taskCreate.task.id}`, {
    method: 'PATCH', body: { version: taskUpdate.version, status: 'Completed' },
  })
  assert.equal(taskUpdate.task.status, 'Completed')
  assert(taskUpdate.task.completedAt)
  ok('incident task completed')

  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}`)
  const pending = await api(ownerToken, `/api/v1/itsm-actions/${incident.id}/pending`, {
    method: 'POST', body: { version: detail.version, status: 'Pending Customer',
      visibility: 'customer', note: 'Waiting for requester confirmation during E2E.' },
  })
  assert.equal(pending.status, 'Pending Customer')
  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}`)
  assert.equal(detail.sla.paused, true)
  ok('incident SLA paused')

  detail = await api(ownerToken, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH', body: { version: detail.version, status: 'In Progress' },
  })
  assert.equal(detail.sla.paused, false)
  ok('incident SLA resumed')
  const resolved = await api(ownerToken, `/api/v1/itsm-actions/${incident.id}/resolve`, {
    method: 'POST',
    body: { version: detail.version, resolutionCode: 'Resolved', visibility: 'customer',
      note: 'Incident resolved successfully by the overnight E2E test.' },
  })
  assert.equal(resolved.status, 'Resolved')
  ok('incident resolved')

  const problem = await api(ownerToken, '/api/v1/itsm-records', {
    method: 'POST', body: { type: 'Problem', title: `Overnight E2E Problem ${stamp}`,
      description: 'Problem lifecycle validation.', requesterId: requester.external_key,
      team: 'Servers', assignee: OWNER_EMAIL, source: 'overnight-e2e' },
  })
  let problemDetail = await api(ownerToken, `/api/v1/itsm-lifecycle/${problem.id}`)
  problemDetail = await api(ownerToken, `/api/v1/itsm-lifecycle/${problem.id}`, {
    method: 'PATCH', body: { version: problemDetail.version, status: 'Investigation' },
  })
  assert.equal(problemDetail.status, 'Investigation')
  ok('problem created and moved to Investigation', problem.id)

  const change = await api(ownerToken, '/api/v1/itsm-records', {
    method: 'POST', body: { type: 'Change', title: `Overnight E2E Change ${stamp}`,
      description: 'Change lifecycle validation.', requesterId: requester.external_key,
      team: 'Servers', assignee: OWNER_EMAIL, source: 'overnight-e2e' },
  })
  let changeDetail = await api(ownerToken, `/api/v1/itsm-lifecycle/${change.id}`)
  changeDetail = await api(ownerToken, `/api/v1/itsm-lifecycle/${change.id}`, {
    method: 'PATCH', body: { version: changeDetail.version, status: 'Assessment' },
  })
  assert.equal(changeDetail.status, 'Assessment')
  ok('change created and moved to Assessment', change.id)
  const notificationRows = await pool.query(
    `SELECT n.event_type,n.user_id,d.channel,d.status,u.email
     FROM platform_notifications n
     JOIN users u ON u.id=n.user_id
     LEFT JOIN notification_deliveries d ON d.notification_id=n.id
     WHERE n.tenant_id=$1 AND n.target_reference=ANY($2::text[])
     ORDER BY n.created_at`,
    [tenantId, [incident.id, problem.id, change.id]],
  )
  assert(notificationRows.rows.some((row) => row.event_type === 'incident.customer_update_added' && row.email === REQUESTER_EMAIL))
  assert(notificationRows.rows.some((row) => row.event_type.startsWith('incident.task_') && row.email === OWNER_EMAIL))
  assert(notificationRows.rows.every((row) => [OWNER_EMAIL, REQUESTER_EMAIL].includes(row.email)))
  ok('bell/email delivery rows created only for approved test inboxes', `${notificationRows.rowCount} rows`)

  const portalSession = await api(requesterToken, '/api/v1/portal/auth/session', { portal: true })
  assert.equal(portalSession.authenticated, true)
  ok('requester portal session', portalSession.user.email)

  console.log('\nSUMMARY', JSON.stringify({ incident: incident.id, problem: problem.id, change: change.id, checks: results.length }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
