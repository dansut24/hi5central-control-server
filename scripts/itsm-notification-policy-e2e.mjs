import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'

let token = ''
let previousSettings = null

async function api(path, { method = 'GET', body } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      Cookie: `hi5central_session=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}

async function deliveryRows(tenantId, reference, eventType, requesterId) {
  return (await pool.query(
    `SELECT n.event_type,d.channel,d.status,d.sent_at
     FROM platform_notifications n
     LEFT JOIN notification_deliveries d ON d.notification_id=n.id
     WHERE n.tenant_id=$1 AND n.user_id=$2 AND n.target_reference=$3 AND n.event_type=$4
     ORDER BY n.created_at,d.channel`,
    [tenantId, requesterId, reference, eventType],
  )).rows
}

async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const users = await pool.query(
    `SELECT u.id,u.email,p.external_key
     FROM users u
     JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenant.id, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = users.rows.find((row) => row.email.toLowerCase() === OWNER_EMAIL)
  const requester = users.rows.find((row) => row.email.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.id && requester?.id && requester?.external_key)

  token = await createSession(pool, {
    tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 1800, surface: 'workspace',
  })

  previousSettings = (await api('/api/v1/notification-settings')).settings
  const testSettings = {
    ...previousSettings,
    channels: { ...(previousSettings.channels || {}), email: true, inApp: true },
    requesterEvents: {
      ...(previousSettings.requesterEvents || {}),
      customerUpdates: true,
      statusChanges: false,
      recordCreated: false,
      approvals: false,
      taskUpdates: false,
      systemUpdates: false,
    },
  }
  await api('/api/v1/notification-settings', { method: 'PATCH', body: { settings: testSettings } })
  console.log('PASS  temporary requester policy applied')

  const incident = await api('/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Incident',
      title: `Notification policy E2E ${new Date().toISOString()}`,
      description: 'Validate requester email suppression versus customer-visible updates.',
      requesterId: requester.external_key,
      priority: 'Medium',
      source: 'notification-policy-e2e',
    },
  })
  assert.match(incident.id, /^INC-/)
  console.log('PASS  incident created', incident.id)

  let createdRows = await deliveryRows(tenant.id, incident.id, 'incident.created', requester.id)
  assert(createdRows.length >= 1, 'requester notification record must exist for incident.created')
  assert(createdRows.every((row) => row.channel === null), 'incident.created must not create delivery rows while disabled')
  console.log('PASS  creation notification retained in audit but customer delivery suppressed')

  let detail = await api(`/api/v1/itsm-lifecycle/${incident.id}`)
  detail = await api(`/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH',
    body: { version: detail.version, status: 'In Progress' },
  })
  assert.equal(detail.status, 'In Progress')

  const statusRows = await deliveryRows(tenant.id, incident.id, 'incident.status_changed', requester.id)
  assert(statusRows.length >= 1, 'requester notification record must exist for incident.status_changed')
  assert(statusRows.every((row) => row.channel === null), 'incident.status_changed must not create delivery rows while disabled')
  console.log('PASS  status update customer delivery suppressed')

  await api(`/api/v1/itsm-lifecycle/${incident.id}/activity`, {
    method: 'POST',
    body: { visibility: 'customer', text: 'Notification policy E2E customer-visible update.' },
  })

  let updateRows = []
  for (let attempt = 0; attempt < 120; attempt += 1) {
    updateRows = await deliveryRows(tenant.id, incident.id, 'incident.customer_update_added', requester.id)
    if (updateRows.some((row) => row.channel === 'email' && row.status === 'sent')) break
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  assert(updateRows.some((row) => row.channel === 'email' && row.status === 'sent'), 'customer update email must be sent')
  assert(updateRows.some((row) => row.channel === 'browser'), 'customer update browser delivery must be queued')
  console.log('PASS  genuine customer-visible update email sent to', REQUESTER_EMAIL)
  console.log('SUMMARY', JSON.stringify({ incident: incident.id, emailRecipient: REQUESTER_EMAIL }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  if (previousSettings) {
    try {
      await api('/api/v1/notification-settings', { method: 'PATCH', body: { settings: previousSettings } })
      console.log('CLEANUP tenant notification policy restored')
    } catch (error) {
      console.error('CLEANUP API restore failed', error.message)
    }
  }
  await pool.end()
})