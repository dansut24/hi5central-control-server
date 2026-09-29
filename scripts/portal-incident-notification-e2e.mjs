import { createHash, randomBytes } from 'node:crypto'
import pg from 'pg'

const { Client } = pg
const API = 'http://127.0.0.1:3001'
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex')
}

async function json(path, { method = 'GET', body, cookie = '', origin } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      ...(origin ? { Origin: origin } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

async function issueSession(tenantId, userId, cookieName) {
  const token = randomBytes(32).toString('base64url')
  await db.query(
    `INSERT INTO auth_sessions (tenant_id,user_id,token_hash,expires_at,mfa_verified_at)
     VALUES ($1,$2,$3,now() + interval '1 hour',now())`,
    [tenantId, userId, sha256(token)],
  )
  return `${cookieName}=${token}`
}

await db.connect()
try {
  console.log('Portal Incident notification acceptance')

  const tenantResult = await db.query(
    `SELECT id, slug
     FROM tenants
     WHERE slug LIKE 'ci-portal-%'
     ORDER BY created_at DESC
     LIMIT 1`,
  )
  assert(tenantResult.rowCount === 1, 'Fresh-tenant Portal E2E tenant was not found')
  const tenant = tenantResult.rows[0]
  const tenantOrigin = `https://${tenant.slug}.hi5central.com`
  const portalOrigin = `https://${tenant.slug}-portal.hi5central.com`

  const identities = await db.query(
    `SELECT m.role, u.id AS user_id, u.email, u.name, p.id AS person_id,
            p.external_key AS person_key, team.name AS team_name
     FROM tenant_memberships m
     JOIN users u ON u.id = m.user_id
     LEFT JOIN organisation_people p
       ON p.tenant_id = m.tenant_id AND p.user_id = m.user_id AND p.active = true
     LEFT JOIN organisation_teams team ON team.id = p.primary_team_id
     WHERE m.tenant_id = $1 AND m.status = 'active'`,
    [tenant.id],
  )
  const owner = identities.rows.find((row) => row.role === 'owner')
  const requester = identities.rows.find((row) => row.role === 'requester')
  assert(owner?.user_id, 'Fresh tenant owner was not found')
  assert(owner?.person_id, 'Fresh tenant owner Person record was not found')
  assert(requester?.user_id && requester?.person_id, 'Activated requester identity was not found')

  const ownerCookie = await issueSession(tenant.id, owner.user_id, 'hi5central_session')
  const requesterCookie = await issueSession(tenant.id, requester.user_id, 'hi5central_portal_session')

  console.log('1. Proving requester-only Portal session isolation')
  const portalSession = await json('/api/v1/portal/auth/session', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalSession.response.ok && portalSession.payload.user?.tenantRole === 'requester', 'Requester Portal session was not accepted')
  const requesterWorkspace = await json('/api/v1/auth/session', { cookie: requesterCookie, origin: tenantOrigin })
  assert(requesterWorkspace.response.status === 401, 'Portal cookie was incorrectly accepted by the technician workspace')

  console.log('2. Verifying migration 020 permanently blocks legacy organisation seeds')
  const guards = await db.query(
    `SELECT conname
     FROM pg_constraint
     WHERE conname IN (
       'organisation_people_no_legacy_demo_keys',
       'organisation_teams_no_legacy_demo_keys',
       'organisation_departments_no_legacy_demo_keys'
     )`,
  )
  assert(guards.rowCount === 3, `Expected all three legacy organisation guards, found ${guards.rowCount}`)
  let legacyBlocked = false
  try {
    await db.query(
      `INSERT INTO organisation_people (tenant_id, external_key, name, email)
       VALUES ($1, 'AGT-DANA', 'Legacy Demo Probe', $2)`,
      [tenant.id, `legacy-probe-${randomBytes(5).toString('hex')}@hi5central.test`],
    )
  } catch (error) {
    legacyBlocked = error?.code === '23514'
  }
  assert(legacyBlocked, 'Legacy organisation Person key was not rejected by the database guard')

  console.log('3. Raising a direct Incident from the dedicated Portal path')
  const submitted = await json('/api/v1/portal/incidents', {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: {
      summary: 'Portal incident notification acceptance',
      urgency: 'High',
      fields: { affectedService: 'Microsoft 365', impact: 'me' },
      details: { text: 'Outlook will not open and displays a startup error.', attachments: [] },
    },
  })
  assert(submitted.response.status === 201, `Portal Incident submission failed: ${submitted.payload.error || submitted.response.status}`)
  const reference = submitted.payload.reference
  assert(/^INC-\d+$/.test(reference || ''), `Portal Incident did not receive an INC reference: ${reference || 'none'}`)
  assert(submitted.payload.requestType === 'Incident' && submitted.payload.source === 'portal', 'Portal Incident payload is not classified correctly')
  assert(submitted.payload.submittedFields?.impact === 'me', 'Direct Portal Incident fields were not persisted')

  console.log('4. Verifying requester-scoped Incident history and technician isolation')
  const myRequests = await json('/api/v1/portal/requests', { cookie: requesterCookie, origin: portalOrigin })
  const requesterItem = (myRequests.payload.items || []).find((item) => item.reference === reference)
  assert(myRequests.response.ok && requesterItem?.requestType === 'Incident', 'Incident is missing from requester My Requests')

  const detail = await json(`/api/v1/portal/requests/${encodeURIComponent(reference)}`, { cookie: requesterCookie, origin: portalOrigin })
  assert(detail.response.ok && detail.payload.reference === reference, 'Requester cannot reopen the Incident')
  assert((detail.payload.activities || []).every((item) => item.kind !== 'internal'), 'Requester detail leaked an internal activity')

  const technicianApiAsRequester = await json(`/api/v1/itsm-records/${encodeURIComponent(reference)}`, { cookie: requesterCookie, origin: portalOrigin })
  assert(technicianApiAsRequester.response.status === 403, `Requester reached technician-only Incident API: ${technicianApiAsRequester.response.status}`)

  console.log('5. Verifying analyst creation notification and exact Incident target')
  const ownerNotifications = await json('/api/v1/notifications?limit=150', { cookie: ownerCookie, origin: tenantOrigin })
  assert(ownerNotifications.response.ok, `Could not read owner notifications: ${ownerNotifications.payload.error || ownerNotifications.response.status}`)
  const createdNotification = (ownerNotifications.payload.items || []).find((item) =>
    item.eventType === 'incident.created'
      && item.target?.type === 'Incident'
      && item.target?.reference === reference
      && !item.read)
  assert(createdNotification, `Owner did not receive an unread incident.created notification for ${reference}`)

  const ownerIncident = await json(`/api/v1/itsm-records/${encodeURIComponent(reference)}`, { cookie: ownerCookie, origin: tenantOrigin })
  assert(ownerIncident.response.ok && ownerIncident.payload.id === reference, 'Notification target Incident is not available to the technician')

  console.log('6. Reassigning the Incident and verifying explicit assigned-to-you notification')
  const assignment = await json(`/api/v1/itsm-records/${encodeURIComponent(reference)}`, {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { assignee: owner.email },
  })
  assert(assignment.response.ok, `Incident assignment failed: ${assignment.payload.error || assignment.response.status}`)
  assert(assignment.payload.assignee === owner.name, `Incident was not assigned to ${owner.name}`)

  const notificationsAfterAssignment = await json('/api/v1/notifications?limit=150', { cookie: ownerCookie, origin: tenantOrigin })
  const assignmentNotification = (notificationsAfterAssignment.payload.items || []).find((item) =>
    item.eventType === 'incident.assigned'
      && item.target?.type === 'Incident'
      && item.target?.reference === reference
      && item.title === `${reference} assigned to you`
      && !item.read)
  assert(assignmentNotification, `Owner did not receive an explicit incident.assigned notification for ${reference}`)

  const badAssignment = await json(`/api/v1/itsm-records/${encodeURIComponent(reference)}`, {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { assignee: 'Inactive Missing Technician' },
  })
  assert(badAssignment.response.status === 422, `Invalid assignee was not rejected: ${badAssignment.response.status}`)
  const afterBadAssignment = await json(`/api/v1/itsm-records/${encodeURIComponent(reference)}`, { cookie: ownerCookie, origin: tenantOrigin })
  assert(afterBadAssignment.payload.assignee === owner.name, 'Rejected assignment unexpectedly changed the current assignee')

  console.log('7. Verifying requester reply produces another analyst notification')
  const replyText = 'I have restarted twice and Outlook still fails to open.'
  const reply = await json(`/api/v1/portal/requests/${encodeURIComponent(reference)}/activities`, {
    method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { text: replyText },
  })
  assert(reply.response.status === 201, `Requester Incident update failed: ${reply.payload.error || reply.response.status}`)

  const notificationsAfterReply = await json('/api/v1/notifications?limit=150', { cookie: ownerCookie, origin: tenantOrigin })
  const replyNotification = (notificationsAfterReply.payload.items || []).find((item) =>
    item.eventType === 'incident.customer_update_added'
      && item.target?.type === 'Incident'
      && item.target?.reference === reference
      && !item.read)
  assert(replyNotification, `Owner did not receive the requester update notification for ${reference}`)

  console.log('8. Verifying PostgreSQL evidence')
  const evidence = await db.query(
    `SELECT r.reference, r.source, r.record_type, r.requester_person_id, r.assigned_person_id,
            count(DISTINCT n.id) FILTER (WHERE n.user_id = $3 AND n.event_type = 'incident.created')::int AS technician_created_notifications,
            count(DISTINCT n.id) FILTER (WHERE n.user_id = $3 AND n.event_type = 'incident.assigned')::int AS technician_assignment_notifications,
            count(DISTINCT n.id) FILTER (WHERE n.user_id = $3 AND n.event_type = 'incident.customer_update_added')::int AS technician_reply_notifications,
            count(DISTINCT a.id) FILTER (WHERE a.visibility = 'customer')::int AS customer_activities,
            count(DISTINCT a.id) FILTER (WHERE a.visibility = 'internal')::int AS internal_activities
     FROM itsm_records r
     LEFT JOIN platform_notifications n
       ON n.tenant_id = r.tenant_id AND n.target_reference = r.reference
     LEFT JOIN itsm_record_activities a ON a.record_id = r.id
     WHERE r.tenant_id = $1 AND r.reference = $2
     GROUP BY r.reference, r.source, r.record_type, r.requester_person_id, r.assigned_person_id`,
    [tenant.id, reference, owner.user_id],
  )
  const row = evidence.rows[0]
  assert(row?.record_type === 'Incident' && row?.source === 'portal', 'Incident persistence evidence is incorrect')
  assert(row.requester_person_id === requester.person_id, 'Incident is not linked to the authenticated requester Person')
  assert(row.assigned_person_id === owner.person_id, 'Incident is not persisted against the assigned technician Person')
  assert(Number(row.technician_created_notifications) >= 1, 'PostgreSQL has no technician Incident-created notification')
  assert(Number(row.technician_assignment_notifications) >= 1, 'PostgreSQL has no technician Incident-assignment notification')
  assert(Number(row.technician_reply_notifications) >= 1, 'PostgreSQL has no technician requester-update notification')
  assert(Number(row.customer_activities) >= 2, 'Portal Incident customer activity history is incomplete')

  console.log(`Portal Incident notification E2E passed: ${tenant.slug} / ${reference}`)
} finally {
  await db.end()
}
