import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'
const origin = process.env.E2E_ORIGIN || `https://${SLUG}.hi5central.com`
const portalOrigin = process.env.E2E_PORTAL_ORIGIN || `https://${SLUG}-portal.hi5central.com`
const portalReferer = process.env.E2E_PORTAL_REFERER || `${portalOrigin}/`
let temporaryMembership = false
const checks = []

function pass(name, detail='') { checks.push(name); console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`) }

async function request(token, path, { method='GET', body, portal=false, expect } = {}) {
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
  if (expect) {
    assert.equal(response.status, expect)
    return response.json().catch(() => ({}))
  }
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}

async function raw(token, path, { portal=false } = {}) {
  return fetch(`${BASE}${path}`, {
    headers: { Origin: portal ? portalOrigin : origin, ...(portal ? { Referer: portalReferer } : {}), Cookie: `${portal ? 'hi5central_portal_session' : 'hi5central_session'}=${token}` },
  })
}
async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1', [SLUG])).rows[0]
  assert(tenant?.id)
  const users = await pool.query(
    `SELECT u.id,u.email,p.id person_id,p.external_key,p.name
     FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenant.id, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = users.rows.find((x) => x.email.toLowerCase() === OWNER_EMAIL)
  const requester = users.rows.find((x) => x.email.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.person_id && requester?.external_key)

  const team = (await pool.query('SELECT id FROM organisation_teams WHERE tenant_id=$1 AND name=$2', [tenant.id, 'Servers'])).rows[0]
  assert(team?.id)
  const existingMembership = await pool.query(
    'SELECT 1 FROM organisation_team_memberships WHERE tenant_id=$1 AND team_id=$2 AND person_id=$3',
    [tenant.id, team.id, owner.person_id],
  )
  if (!existingMembership.rowCount) {
    await pool.query(
      `INSERT INTO organisation_team_memberships(tenant_id,team_id,person_id,role,is_primary,created_at)
       VALUES($1,$2,$3,'member',false,now())`,
      [tenant.id, team.id, owner.person_id],
    )
    temporaryMembership = true
  }

  const ownerToken = await createSession(pool, { tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace' })
  const requesterToken = await createSession(pool, { tenantId: tenant.id, userId: requester.id, mfaVerified: true, ttlSeconds: 3600, surface: 'portal' })

  const stamp = new Date().toISOString()
  let detail = await request(ownerToken, '/api/v1/service-requests', {
    method: 'POST',
    body: {
      catalogueItemId: 'CAT-GENERAL',
      summary: `Overnight Service Request E2E ${stamp}`,
      requesterPersonId: requester.external_key,
      urgency: 'High',
      fields: { requestType: 'Configuration change', requestDetails: 'End-to-end Service Request validation.' },
      details: { text: 'Raised by overnight E2E harness.', attachments: [] },
    },
  })
  assert.match(detail.id, /^REQ-/)
  assert(detail.sla?.response?.dueAt && detail.sla?.resolution?.dueAt)
  pass('service request created with SLA', detail.id)
  await request(ownerToken, `/api/v1/service-requests/${detail.id}`, {
    method: 'PATCH', body: { team: 'Servers', assignee: OWNER_EMAIL, priority: 'High' },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert.equal(detail.team, 'Servers')
  assert(detail.activities.some((a) => a.metadata?.event === 'request.updated' && a.visibility === 'internal'))
  pass('assignment/reassignment is internal')

  const requesterDetailBefore = await request(requesterToken, `/api/v1/service-requests/${detail.id}`, { portal: true })
  assert(!requesterDetailBefore.activities.some((a) => a.visibility === 'internal'))
  pass('requester cannot read internal activity')

  await request(requesterToken, `/api/v1/service-requests/${detail.id}`, {
    portal: true, method: 'PATCH', body: { priority: 'Critical' }, expect: 403,
  })
  pass('requester cannot perform technician assignment edits')

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/transition`, {
    method: 'POST', body: { targetStatus: 'In Progress', values: {} },
  })
  pass('request moved to In Progress')

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/activities`, {
    method: 'POST', body: { kind: 'work', text: 'Internal diagnostic note', attachments: [] },
  })
  await request(ownerToken, `/api/v1/service-requests/${detail.id}/activities`, {
    method: 'POST', body: { kind: 'customer', text: 'Customer-facing Service Request update', attachments: [] },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert(detail.firstResponseAt)
  pass('customer update captures first-response SLA')

  const internalAttachment = await request(ownerToken, `/api/v1/service-requests/${detail.id}/attachments`, {
    method: 'POST', body: { fileName: 'internal-evidence.txt', mimeType: 'text/plain', contentBase64: Buffer.from('internal evidence').toString('base64'), visibility: 'internal' },
  })
  const customerAttachment = await request(ownerToken, `/api/v1/service-requests/${detail.id}/attachments`, {
    method: 'POST', body: { fileName: 'customer-evidence.txt', mimeType: 'text/plain', contentBase64: Buffer.from('customer evidence').toString('base64'), visibility: 'customer' },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert(detail.attachments.some((a) => a.id === internalAttachment.id))
  assert(detail.attachments.some((a) => a.id === customerAttachment.id))
  const download = await raw(ownerToken, `/api/v1/service-requests/${detail.id}/attachments/${customerAttachment.id}`)
  assert.equal(download.status, 200)
  assert.equal(await download.text(), 'customer evidence')
  pass('server-backed attachment upload/download')
  const requesterDetail = await request(requesterToken, `/api/v1/service-requests/${detail.id}`, { portal: true })
  assert(requesterDetail.attachments.some((a) => a.id === customerAttachment.id))
  assert(!requesterDetail.attachments.some((a) => a.id === internalAttachment.id))
  assert(!requesterDetail.activities.some((a) => a.visibility === 'internal'))
  const hiddenDownload = await raw(requesterToken, `/api/v1/service-requests/${detail.id}/attachments/${internalAttachment.id}`, { portal: true })
  assert.equal(hiddenDownload.status, 404)
  pass('requester sees customer attachments only')

  const task = detail.requestTasks[0]
  assert(task?.id)
  await request(ownerToken, `/api/v1/service-requests/${detail.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { team: 'Servers', assignee: 'Unassigned', status: 'Ready' },
  })
  const taken = await request(ownerToken, `/api/v1/tasks/${task.id}/take`, { method: 'POST' })
  assert.equal(taken.assignee.email, OWNER_EMAIL)
  pass('task taken by team member', task.id)

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { status: 'In Progress' },
  })
  await request(ownerToken, `/api/v1/service-requests/${detail.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { status: 'Completed', completionNotes: 'Fulfilment task completed by E2E.' },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert.equal(detail.requestTasks[0].status, 'Completed')
  pass('task started and completed')

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Completed', values: { completionNotes: 'Request fulfilled successfully.' } },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert(detail.resolvedAt)
  assert(detail.sla.resolution.completedAt)
  pass('request completed with resolution SLA')

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/transition`, {
    method: 'POST', body: { targetStatus: 'In Progress', values: { reopenReason: 'Regression-check reopen.' } },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert.equal(detail.resolvedAt, null)
  pass('completed request reopened with reason')

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Completed', values: { completionNotes: 'Recompleted after reopen.' } },
  })
  await request(ownerToken, `/api/v1/service-requests/${detail.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Closed', values: {} },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert.equal(detail.status, 'Closed')
  pass('request closed')
  const notificationRows = await pool.query(
    `SELECT n.event_type,u.email,d.channel,d.status
     FROM platform_notifications n JOIN users u ON u.id=n.user_id
     LEFT JOIN notification_deliveries d ON d.notification_id=n.id
     WHERE n.tenant_id=$1 AND n.target_reference=$2 ORDER BY n.created_at`,
    [tenant.id, detail.id],
  )
  assert(notificationRows.rows.some((r) => r.event_type === 'service_request.customer_update_added' && r.email === REQUESTER_EMAIL))
  assert(notificationRows.rows.some((r) => r.event_type.startsWith('service_request.task_') && r.email === OWNER_EMAIL))
  assert(notificationRows.rows.every((r) => [OWNER_EMAIL, REQUESTER_EMAIL].includes(r.email)))
  pass('Service Request bell/email events target approved identities', `${notificationRows.rowCount} rows`)

  await request(ownerToken, `/api/v1/service-requests/${detail.id}/attachments/remove`, {
    method: 'POST', body: { attachmentId: internalAttachment.id },
  })
  detail = await request(ownerToken, `/api/v1/service-requests/${detail.id}`)
  assert(!detail.attachments.some((a) => a.id === internalAttachment.id))
  pass('attachment removal')

  console.log('\nSUMMARY', JSON.stringify({ request: detail.id, checks: checks.length }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  if (temporaryMembership) {
    await pool.query(
      'DELETE FROM organisation_team_memberships WHERE tenant_id=$1 AND team_id=(SELECT id FROM organisation_teams WHERE tenant_id=$1 AND name=$2) AND person_id=(SELECT id FROM organisation_people WHERE tenant_id=$1 AND user_id=(SELECT id FROM users WHERE lower(email)=lower($3) LIMIT 1) LIMIT 1)',
      [(await pool.query('SELECT id FROM tenants WHERE slug=$1', [SLUG])).rows[0]?.id, 'Servers', OWNER_EMAIL],
    ).catch(() => {})
    console.log('CLEANUP temporary Servers membership removed')
  }
  await pool.end()
})

[executed on device: hi5central-prod-01 (39f38b48-395a-48ec-b87b-4b9bb80cf4b5)]
