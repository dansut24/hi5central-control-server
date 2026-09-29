import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'
const PORTAL_REFERER = `${ORIGIN}/portal`

function pass(name, detail = '') {
  console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`)
}

async function request(token, path, { method = 'GET', body, portal = false, raw = false } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      ...(portal ? { Referer: PORTAL_REFERER } : {}),
      Cookie: `${portal ? 'hi5central_portal_session' : 'hi5central_session'}=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (raw) return response
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}
async function main() {
  const tenant = await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])
  assert.equal(tenant.rowCount, 1)
  const tenantId = tenant.rows[0].id
  const users = await pool.query(
    `SELECT u.id,u.email,p.external_key,p.name
     FROM users u
     JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenantId, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = users.rows.find((row) => row.email.toLowerCase() === OWNER_EMAIL)
  const requester = users.rows.find((row) => row.email.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.id && owner?.external_key)
  assert(requester?.id && requester?.external_key)

  const ownerToken = await createSession(pool, {
    tenantId, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace',
  })
  const requesterToken = await createSession(pool, {
    tenantId, userId: requester.id, mfaVerified: true, ttlSeconds: 3600, surface: 'portal',
  })

  const settings = await request(ownerToken, '/api/v1/notification-settings')
  await request(ownerToken, '/api/v1/notification-settings', {
    method: 'PATCH',
    body: { settings: {
      ...settings.settings,
      channels: { ...settings.settings.channels, inApp: true, email: true },
      requesterEvents: {
        customerUpdates: true, statusChanges: true, recordCreated: true,
        approvals: true, taskUpdates: false, systemUpdates: false,
      },
    } },
  })
  await request(ownerToken, '/api/v1/notification-preferences', {
    method: 'PATCH', body: { preferences: { channels: { inApp: true, email: true, browser: false } } },
  })
  await request(requesterToken, '/api/v1/notification-preferences', {
    method: 'PATCH', portal: true,
    body: { preferences: { channels: { inApp: true, email: true, browser: false } } },
  })
  pass('notification policy enabled with requester task/system noise suppressed')
  const stamp = new Date().toISOString()
  let serviceRequest = await request(ownerToken, '/api/v1/service-requests', {
    method: 'POST',
    body: {
      catalogueItemId: 'CAT-GENERAL',
      summary: `Overnight E2E Service Request ${stamp}`,
      requesterPersonId: requester.external_key,
      urgency: 'High',
      fields: {
        requestType: 'Advice',
        requestDetails: 'Full overnight Service Request end-to-end validation.',
      },
      details: { text: 'Service Request submitted by the overnight E2E test.' },
    },
  })
  assert(serviceRequest.id)
  assert(serviceRequest.sla?.response?.dueAt)
  assert(serviceRequest.sla?.resolution?.dueAt)
  assert.equal(serviceRequest.sla.paused, false)
  pass('service request created with SLA', serviceRequest.id)

  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`, {
    method: 'PATCH', body: { team: 'Servers', assignee: OWNER_EMAIL, priority: 'High' },
  })
  serviceRequest = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`)
  assert.equal(serviceRequest.team, 'Servers')
  assert.equal(serviceRequest.assigneeEmail, OWNER_EMAIL)
  pass('service request assigned to team and technician')

  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/transition`, {
    method: 'POST', body: { targetStatus: 'In Progress', values: {} },
  })
  serviceRequest = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`)
  assert.equal(serviceRequest.status, 'In Progress')
  const taskKey = serviceRequest.requestTasks[0]?.id
  assert(taskKey)
  pass('service request moved to In Progress', taskKey)

  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/tasks/${encodeURIComponent(taskKey)}`, {
    method: 'PATCH', body: { team: 'Servers', assignee: OWNER_EMAIL },
  })
  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/tasks/${encodeURIComponent(taskKey)}`, {
    method: 'PATCH', body: { status: 'In Progress' },
  })
  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/tasks/${encodeURIComponent(taskKey)}`, {
    method: 'PATCH', body: { status: 'Completed', completionNotes: 'Fulfilment task completed by overnight E2E.' },
  })
  serviceRequest = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`)
  assert.equal(serviceRequest.requestTasks[0].status, 'Completed')
  assert.equal(serviceRequest.requestTasks[0].assignee, owner.name)
  pass('fulfilment task assigned, started and completed')
  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/activities`, {
    method: 'POST', body: { kind: 'work', text: 'Internal Service Request E2E note — requester must not see this.' },
  })
  const customerFile = Buffer.from('Hi5Central customer-visible Service Request attachment')
  const customerAttachment = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/attachments`, {
    method: 'POST',
    body: {
      fileName: 'service-request-customer-e2e.txt', mimeType: 'text/plain',
      contentBase64: customerFile.toString('base64'), visibility: 'customer', recordActivity: false,
    },
  })
  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/activities`, {
    method: 'POST',
    body: {
      kind: 'customer', text: 'Customer-facing Service Request E2E update.',
      attachments: [{ id: customerAttachment.id, name: customerAttachment.fileName, size: customerAttachment.byteSize, type: customerAttachment.mimeType }],
    },
  })
  serviceRequest = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`)
  assert(serviceRequest.firstResponseAt)
  assert(serviceRequest.attachments.some((item) => item.id === customerAttachment.id))
  pass('customer note, first-response SLA and real attachment recorded')

  const internalFile = Buffer.from('Hi5Central internal Service Request attachment')
  const internalAttachment = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/attachments`, {
    method: 'POST',
    body: {
      fileName: 'service-request-internal-e2e.txt', mimeType: 'text/plain',
      contentBase64: internalFile.toString('base64'), visibility: 'internal',
    },
  })
  const requesterView = await request(requesterToken, `/api/v1/service-requests/${serviceRequest.id}`, { portal: true })
  assert(requesterView.activities.every((item) => item.visibility === 'customer'))
  assert(!requesterView.activities.some((item) => item.text?.includes('requester must not see this')))
  assert(requesterView.attachments.some((item) => item.id === customerAttachment.id))
  assert(!requesterView.attachments.some((item) => item.id === internalAttachment.id))
  pass('requester visibility hides internal notes and attachments')
  const customerDownload = await request(
    requesterToken,
    `/api/v1/service-requests/${serviceRequest.id}/attachments/${customerAttachment.id}`,
    { portal: true, raw: true },
  )
  assert.equal(customerDownload.status, 200)
  assert.equal(Buffer.from(await customerDownload.arrayBuffer()).toString(), customerFile.toString())
  const forbiddenInternalDownload = await request(
    requesterToken,
    `/api/v1/service-requests/${serviceRequest.id}/attachments/${internalAttachment.id}`,
    { portal: true, raw: true },
  )
  assert.equal(forbiddenInternalDownload.status, 404)
  pass('attachment download permissions enforced')

  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/transition`, {
    method: 'POST',
    body: { targetStatus: 'Completed', values: { completionNotes: 'Service Request completed successfully by overnight E2E.' } },
  })
  await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Closed', values: {} },
  })
  serviceRequest = await request(ownerToken, `/api/v1/service-requests/${serviceRequest.id}`)
  assert.equal(serviceRequest.status, 'Closed')
  assert(serviceRequest.resolvedAt)
  assert(serviceRequest.sla?.resolution?.completedAt)
  pass('service request completed and closed with resolution SLA captured')

  const ownerBell = await request(ownerToken, '/api/v1/notifications?limit=250')
  const requesterBell = await request(requesterToken, '/api/v1/notifications?limit=250', { portal: true })
  const ownerEvents = ownerBell.items.filter((item) => item.target?.reference === serviceRequest.id).map((item) => item.eventType)
  const requesterEvents = requesterBell.items.filter((item) => item.target?.reference === serviceRequest.id).map((item) => item.eventType)
  assert(ownerEvents.some((event) => event.startsWith('service_request.task_')))
  assert(requesterEvents.includes('service_request.created'))
  assert(requesterEvents.includes('service_request.status_changed'))
  assert(requesterEvents.includes('service_request.customer_update_added'))
  assert(!requesterEvents.some((event) => event.startsWith('service_request.task_')))
  pass('technician bell receives task events while requester task noise is suppressed')
  const deadline = Date.now() + 40000
  let deliveries = []
  while (Date.now() < deadline) {
    const result = await pool.query(
      `SELECT n.event_type,u.email,d.channel,d.status,d.sent_at,d.last_error
       FROM platform_notifications n
       JOIN users u ON u.id=n.user_id
       JOIN notification_deliveries d ON d.notification_id=n.id
       WHERE n.tenant_id=$1 AND n.target_reference=$2
       ORDER BY n.created_at,d.channel`,
      [tenantId, serviceRequest.id],
    )
    deliveries = result.rows
    const emailRows = deliveries.filter((row) => row.channel === 'email')
    if (emailRows.length && emailRows.every((row) => ['sent','suppressed'].includes(row.status))) break
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  const emailRows = deliveries.filter((row) => row.channel === 'email')
  assert(emailRows.length > 0)
  assert(emailRows.every((row) => [OWNER_EMAIL, REQUESTER_EMAIL].includes(row.email)))
  assert(emailRows.some((row) => row.email === OWNER_EMAIL && row.event_type.startsWith('service_request.task_') && row.status === 'sent'))
  assert(!emailRows.some((row) => row.email === REQUESTER_EMAIL && row.event_type.startsWith('service_request.task_') && row.status === 'sent'))
  assert(emailRows.some((row) => row.email === REQUESTER_EMAIL && row.event_type === 'service_request.customer_update_added' && row.status === 'sent'))
  pass('SMTP deliveries sent/suppressed according to policy', `${emailRows.length} email deliveries`)

  console.log('\nSUMMARY', JSON.stringify({ serviceRequest: serviceRequest.id, task: taskKey, emailDeliveries: emailRows.length }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
