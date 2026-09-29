import { createHash, randomBytes } from 'node:crypto'
import pg from 'pg'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) { if (!condition) throw new Error(message) }
function sha256(value) { return createHash('sha256').update(String(value)).digest('hex') }

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
     VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
    [tenantId, userId, sha256(token)],
  )
  return `${cookieName}=${token}`
}

await db.connect()
try {
  console.log('Live Chat production operations acceptance')

  const tenantResult = await db.query(`SELECT id,slug FROM tenants WHERE slug LIKE 'ci-portal-%' ORDER BY created_at DESC LIMIT 1`)
  assert(tenantResult.rowCount === 1, 'Fresh Portal tenant not found')
  const tenant = tenantResult.rows[0]
  const workspaceOrigin = `https://${tenant.slug}.hi5central.com`
  const portalOrigin = `https://${tenant.slug}-portal.hi5central.com`

  const identities = await db.query(
    `SELECT m.role,u.id AS user_id,u.email,u.name,p.id AS person_id,p.external_key AS person_key,p.active
     FROM tenant_memberships m
     JOIN users u ON u.id=m.user_id
     LEFT JOIN organisation_people p ON p.tenant_id=m.tenant_id AND p.user_id=m.user_id
     WHERE m.tenant_id=$1 AND m.status='active'`,
    [tenant.id],
  )
  const owner = identities.rows.find((row) => row.role === 'owner')
  const requester = identities.rows.find((row) => row.role === 'requester')
  assert(owner?.person_id && requester?.person_id, 'Owner/requester Person missing')

  const suffix = Date.now().toString(36)
  const analyst = await db.query(
    `WITH u AS (
       INSERT INTO users (email,name,password_hash,email_verified_at)
       VALUES ($1,'Second Analyst','ci-session-only',now()) RETURNING id,email,name
     ), m AS (
       INSERT INTO tenant_memberships (tenant_id,user_id,role,status)
       SELECT $2,id,'analyst','active' FROM u
     ), p AS (
       INSERT INTO organisation_people (tenant_id,external_key,user_id,name,email,job_title,access_profile,active)
       SELECT $2,$3,id,name,email,'Support Analyst','analyst',true FROM u
       RETURNING id,external_key,user_id,name,email
     ) SELECT * FROM p`,
    [`ci-analyst-${suffix}@example.invalid`, tenant.id, `CI-ANALYST-${suffix.toUpperCase()}`],
  )
  const analyst2 = analyst.rows[0]

  const ownerCookie = await issueSession(tenant.id, owner.user_id, 'hi5central_session')
  const analystCookie = await issueSession(tenant.id, analyst2.user_id, 'hi5central_session')
  const requesterCookie = await issueSession(tenant.id, requester.user_id, 'hi5central_portal_session')

  console.log('1. Enabling requester and owner availability')
  await json(`/api/v1/live-chat/entitlements/${encodeURIComponent(requester.person_key)}`, { method: 'PATCH', cookie: ownerCookie, origin: workspaceOrigin, body: { enabled: true } })
  const online = await json('/api/v1/live-chat/presence', { method: 'PATCH', cookie: ownerCookie, origin: workspaceOrigin, body: { status: 'Online' } })
  assert(online.response.ok && online.payload.support?.available === true, 'Owner could not make chat available')

  console.log('2. Starting chat and proving typing state')
  const started = await json('/api/v1/portal/live-chat', { method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { subject: 'Operations acceptance', message: 'Please help with this test.' } })
  assert(started.response.status === 201, `Could not start chat: ${started.payload.error || started.response.status}`)
  const chatRef = started.payload.reference
  const typing = await json(`/api/v1/portal/live-chat/${chatRef}/typing`, { method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { active: true } })
  assert(typing.response.ok, 'Requester typing endpoint failed')
  const opsTyping = await json(`/api/v1/live-chat/conversations/${chatRef}/operations`, { cookie: ownerCookie, origin: workspaceOrigin })
  assert(opsTyping.response.ok && opsTyping.payload.requesterTyping === true, 'Analyst could not see requester typing')

  console.log('3. Claiming, canned responses and attachment persistence')
  const claimed = await json(`/api/v1/live-chat/conversations/${chatRef}/claim`, { method: 'POST', cookie: ownerCookie, origin: workspaceOrigin })
  assert(claimed.response.ok && claimed.payload.assignedTo === owner.name, 'Owner could not claim chat')
  const canned = await json('/api/v1/live-chat/canned-responses', { method: 'POST', cookie: ownerCookie, origin: workspaceOrigin, body: { shortcut: `hello_${suffix}`, title: 'CI hello', body: 'Hello from a real canned response.' } })
  assert(canned.response.status === 201, 'Canned response creation failed')
  const attachment = await json(`/api/v1/portal/live-chat/${chatRef}/attachments`, { method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { name: 'evidence.txt', type: 'text/plain', dataBase64: Buffer.from('real attachment evidence').toString('base64') } })
  assert(attachment.response.status === 201, `Attachment upload failed: ${attachment.payload.error || attachment.response.status}`)
  const opsAttachment = await json(`/api/v1/live-chat/conversations/${chatRef}/operations`, { cookie: ownerCookie, origin: workspaceOrigin })
  assert((opsAttachment.payload.attachments || []).some((item) => item.id === attachment.payload.id), 'Attachment missing from operations state')
  const attachmentDownload = await fetch(`${API}/api/v1/live-chat/attachments/${attachment.payload.id}`, { headers: { Origin: workspaceOrigin, Cookie: ownerCookie } })
  assert(attachmentDownload.ok && await attachmentDownload.text() === 'real attachment evidence', 'Attachment download failed')

  console.log('4. Preventing silent claim theft and explicitly transferring')
  const analystSteal = await json(`/api/v1/live-chat/conversations/${chatRef}/claim`, { method: 'POST', cookie: analystCookie, origin: workspaceOrigin })
  assert(analystSteal.response.status === 409 && analystSteal.payload.code === 'live_chat_already_assigned', 'Claim silently stole another analyst chat')
  const transferred = await json(`/api/v1/live-chat/conversations/${chatRef}/transfer`, { method: 'POST', cookie: ownerCookie, origin: workspaceOrigin, body: { personId: analyst2.external_key } })
  assert(transferred.response.ok && transferred.payload.assignedTo === analyst2.name, 'Explicit transfer failed')

  console.log('5. Read receipts and analyst typing')
  const agentTyping = await json(`/api/v1/live-chat/conversations/${chatRef}/typing`, { method: 'POST', cookie: analystCookie, origin: workspaceOrigin, body: { active: true } })
  assert(agentTyping.response.ok, 'Analyst typing endpoint failed')
  const portalOpsTyping = await json(`/api/v1/portal/live-chat/${chatRef}/operations`, { cookie: requesterCookie, origin: portalOrigin })
  assert(portalOpsTyping.response.ok && portalOpsTyping.payload.agentTyping === true, 'Portal could not see analyst typing')
  const agentMessage = await json(`/api/v1/live-chat/conversations/${chatRef}/messages`, { method: 'POST', cookie: analystCookie, origin: workspaceOrigin, body: { message: 'Transferred analyst response.' } })
  assert(agentMessage.response.status === 201, 'Transferred analyst could not reply')
  await json(`/api/v1/portal/live-chat/${chatRef}/read`, { method: 'POST', cookie: requesterCookie, origin: portalOrigin })
  const readOps = await json(`/api/v1/live-chat/conversations/${chatRef}/operations`, { cookie: analystCookie, origin: workspaceOrigin })
  assert(readOps.payload.requesterReadAt, 'Requester read receipt was not recorded')

  console.log('6. Converting chat to Incident and preserving transcript')
  const createdIncident = await json(`/api/v1/live-chat/conversations/${chatRef}/create-incident`, { method: 'POST', cookie: analystCookie, origin: workspaceOrigin })
  assert(createdIncident.response.status === 201 && /^INC-/.test(createdIncident.payload.incident?.reference || ''), `Chat to Incident failed: ${createdIncident.payload.error || createdIncident.response.status}`)
  const incidentRef = createdIncident.payload.incident.reference
  const linkedOps = await json(`/api/v1/live-chat/conversations/${chatRef}/operations`, { cookie: analystCookie, origin: workspaceOrigin })
  assert(linkedOps.payload.linkedRecord?.reference === incidentRef, 'Created Incident was not linked back to chat')
  const transcript = await json(`/api/v1/live-chat/conversations/${chatRef}/transcript`, { cookie: analystCookie, origin: workspaceOrigin })
  assert(transcript.response.ok && transcript.payload.content.includes(chatRef) && transcript.payload.content.includes('evidence.txt'), 'Transcript did not preserve chat evidence')

  console.log('7. Linking a second chat to an existing record')
  const second = await json('/api/v1/portal/live-chat', { method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { subject: 'Existing record link', message: 'Link this chat to the existing incident.' } })
  assert(second.response.status === 201, 'Second chat could not start')
  const linked = await json(`/api/v1/live-chat/conversations/${second.payload.reference}/link-record`, { method: 'POST', cookie: ownerCookie, origin: workspaceOrigin, body: { recordReference: incidentRef } })
  assert(linked.response.ok && linked.payload.record?.reference === incidentRef, 'Existing record link failed')

  console.log('8. Queue metrics and service-hours enforcement')
  const metrics = await json('/api/v1/live-chat/metrics', { cookie: ownerCookie, origin: workspaceOrigin })
  assert(metrics.response.ok && Number.isFinite(metrics.payload.waiting) && metrics.payload.analystsOnline >= 1, 'Live Chat metrics failed')
  const schedule = Object.fromEntries(['0','1','2','3','4','5','6'].map((day) => [day, [['00:00','23:59']]]))
  const hours = await json('/api/v1/live-chat/service-hours', { method: 'PATCH', cookie: ownerCookie, origin: workspaceOrigin, body: { enabled: true, timezone: 'Europe/London', schedule } })
  assert(hours.response.ok && hours.payload.enabled === true, 'Service hours save failed')
  await db.query(`UPDATE live_chat_service_settings SET schedule='{}'::jsonb WHERE tenant_id=$1`, [tenant.id])
  const closedPresence = await json('/api/v1/portal/live-chat-presence', { cookie: requesterCookie, origin: portalOrigin })
  assert(closedPresence.response.ok && closedPresence.payload.available === false && closedPresence.payload.serviceHours?.open === false, 'Service hours did not gate portal availability')
  const blocked = await json('/api/v1/portal/live-chat', { method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { subject: 'Blocked by hours', message: 'This must not open.' } })
  assert(blocked.response.status === 409 && blocked.payload.code === 'live_chat_outside_service_hours', 'New chat was not blocked outside service hours')
  await db.query(`UPDATE live_chat_service_settings SET service_hours_enabled=false,updated_at=now() WHERE tenant_id=$1`, [tenant.id])

  console.log('9. Verifying PostgreSQL evidence')
  const evidence = await db.query(
    `SELECT
       (SELECT count(*)::int FROM live_chat_attachments WHERE tenant_id=$1) AS attachments,
       (SELECT count(*)::int FROM live_chat_canned_responses WHERE tenant_id=$1) AS canned,
       (SELECT count(*)::int FROM itsm_records WHERE tenant_id=$1 AND reference=$2 AND source='live_chat') AS incidents,
       (SELECT count(*)::int FROM live_chat_conversations WHERE tenant_id=$1 AND linked_record_reference=$2) AS linked_chats`,
    [tenant.id, incidentRef],
  )
  const row = evidence.rows[0]
  assert(row.attachments >= 1 && row.canned >= 1 && row.incidents === 1 && row.linked_chats >= 2, 'Expected operational evidence missing from PostgreSQL')

  console.log(`PASS: ${chatRef} hardened, transferred and converted to ${incidentRef}`)
} finally {
  await db.end()
}
