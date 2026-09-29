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
  console.log('Knowledge + Live Chat + analyst presence production acceptance')

  const tenantResult = await db.query(
    `SELECT id,slug FROM tenants WHERE slug LIKE 'ci-portal-%' ORDER BY created_at DESC LIMIT 1`,
  )
  assert(tenantResult.rowCount === 1, 'Fresh Portal tenant not found')
  const tenant = tenantResult.rows[0]
  const tenantOrigin = `https://${tenant.slug}.hi5central.com`
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
  assert(owner?.user_id && owner?.person_id && owner.active, 'Active owner Person missing')
  assert(requester?.user_id && requester?.person_id && requester.active, 'Active requester Person missing')

  const ownerCookie = await issueSession(tenant.id, owner.user_id, 'hi5central_session')
  const requesterCookie = await issueSession(tenant.id, requester.user_id, 'hi5central_portal_session')

  console.log('1. Creating a real draft Knowledge article')
  const created = await json('/api/v1/knowledge', {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: {
      title: 'Reset Microsoft 365 sign-in',
      summary: 'Steps for resolving a cached Microsoft 365 sign-in problem.',
      bodyText: 'Close all Microsoft 365 applications.\n\nOpen the Company Portal and choose Sync.\n\nRestart Outlook and sign in again.',
      category: 'Microsoft 365',
      tags: ['outlook', 'sign-in'],
      visibility: 'both',
      status: 'Draft',
    },
  })
  assert(created.response.status === 201, `Knowledge create failed: ${created.payload.error || created.response.status}`)
  assert(/^KB-\d+$/.test(created.payload.reference || ''), 'Knowledge article did not receive a KB reference')
  assert(created.payload.version === 1 && created.payload.status === 'Draft', 'Knowledge initial version/status incorrect')
  const kbRef = created.payload.reference

  console.log('2. Proving drafts are private, then publishing to Portal')
  const portalBefore = await json('/api/v1/portal/knowledge', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalBefore.response.ok && !(portalBefore.payload.items || []).some((item) => item.reference === kbRef), 'Draft leaked into Portal Knowledge')

  const published = await json(`/api/v1/knowledge/${encodeURIComponent(kbRef)}`, {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { status: 'Published', visibility: 'both', changeNote: 'Published for requester self-service' },
  })
  assert(published.response.ok && published.payload.status === 'Published' && published.payload.version === 2, 'Knowledge publish/version failed')

  const portalAfter = await json('/api/v1/portal/knowledge?q=outlook', { cookie: requesterCookie, origin: portalOrigin })
  assert((portalAfter.payload.items || []).some((item) => item.reference === kbRef), 'Published article missing from Portal search')

  const portalArticle = await json(`/api/v1/portal/knowledge/${encodeURIComponent(published.payload.slug)}`, {
    cookie: requesterCookie,
    origin: portalOrigin,
  })
  assert(portalArticle.response.ok && portalArticle.payload.reference === kbRef, 'Portal article detail failed')

  const feedback = await json(`/api/v1/portal/knowledge/${encodeURIComponent(kbRef)}/feedback`, {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: { helpful: true },
  })
  assert(feedback.response.status === 201, 'Portal Knowledge feedback failed')

  console.log('3. Linking Knowledge to an ITSM record reference')
  const link = await json(`/api/v1/knowledge/${encodeURIComponent(kbRef)}/links`, {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { recordType: 'Incident', recordReference: 'INC-TEST-KB' },
  })
  assert(link.response.ok && link.payload.linked, 'Knowledge record link failed')

  const refreshedArticle = await json(`/api/v1/knowledge/${encodeURIComponent(kbRef)}`, {
    cookie: ownerCookie,
    origin: tenantOrigin,
  })
  assert((refreshedArticle.payload.links || []).some((item) => item.recordReference === 'INC-TEST-KB'), 'Knowledge record link was not persisted')

  console.log('4. Enabling requester Live Chat entitlement')
  const initialEntitlement = await json(`/api/v1/live-chat/entitlements/${encodeURIComponent(requester.person_key)}`, {
    cookie: ownerCookie,
    origin: tenantOrigin,
  })
  assert(initialEntitlement.response.ok && initialEntitlement.payload.liveChatEnabled === false, 'Requester Live Chat should default to disabled')

  const portalChatBefore = await json('/api/v1/portal/live-chat', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalChatBefore.response.ok && portalChatBefore.payload.enabled === false, 'Portal exposed Live Chat before entitlement')

  const enabled = await json(`/api/v1/live-chat/entitlements/${encodeURIComponent(requester.person_key)}`, {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { enabled: true },
  })
  assert(enabled.response.ok && enabled.payload.liveChatEnabled === true, 'Could not enable requester Live Chat')

  console.log('5. Proving true analyst presence starts Offline and gates new chats')
  const initialPresence = await json('/api/v1/live-chat/presence', { cookie: ownerCookie, origin: tenantOrigin })
  assert(initialPresence.response.ok, 'Analyst presence endpoint failed')
  assert(initialPresence.payload.status === 'Offline' && initialPresence.payload.desiredStatus === 'Offline', 'Analyst should start Offline')

  const portalPresenceOffline = await json('/api/v1/portal/live-chat-presence', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalPresenceOffline.response.ok && portalPresenceOffline.payload.enabled === true, 'Portal presence did not honour entitlement')
  assert(portalPresenceOffline.payload.status === 'Offline' && portalPresenceOffline.payload.available === false, 'Portal should report Service Desk Offline')

  const blockedOffline = await json('/api/v1/portal/live-chat', {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: { subject: 'Should not start', message: 'No analyst is online yet.' },
  })
  assert(blockedOffline.response.status === 409 && blockedOffline.payload.code === 'live_chat_offline', 'New Live Chat was not blocked while every analyst was Offline')

  console.log('6. Going Online, heartbeating, and exposing real availability to Portal')
  const online = await json('/api/v1/live-chat/presence', {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { status: 'Online' },
  })
  assert(online.response.ok && online.payload.status === 'Online' && online.payload.desiredStatus === 'Online', 'Analyst could not go Online')
  assert(online.payload.support?.available === true && online.payload.support?.online >= 1, 'Online analyst did not make Live Chat available')

  const heartbeat = await json('/api/v1/live-chat/presence/heartbeat', {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
  })
  assert(heartbeat.response.ok && heartbeat.payload.status === 'Online', 'Analyst presence heartbeat failed')

  const portalPresenceOnline = await json('/api/v1/portal/live-chat-presence', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalPresenceOnline.response.ok && portalPresenceOnline.payload.status === 'Online' && portalPresenceOnline.payload.available === true, 'Portal did not report Service Desk Online')

  console.log('7. Starting a real requester conversation and notifying the Service Desk')
  const started = await json('/api/v1/portal/live-chat', {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: { subject: 'Outlook still will not open', message: 'I followed the Knowledge article but Outlook still shows an error.' },
  })
  assert(started.response.status === 201 && /^CHAT-\d+$/.test(started.payload.reference || ''), `Live Chat start failed: ${started.payload.error || started.response.status}`)
  const chatRef = started.payload.reference
  assert(started.payload.status === 'Waiting', 'New chat did not enter Waiting state')

  const ownerNotifications = await json('/api/v1/notifications?limit=150', { cookie: ownerCookie, origin: tenantOrigin })
  assert((ownerNotifications.payload.items || []).some((item) => item.eventType === 'live_chat.started' && item.target?.reference === chatRef), 'Service Desk did not receive new Live Chat notification')

  console.log('8. Claiming the chat and sending a genuine technician message')
  const queue = await json('/api/v1/live-chat/conversations', { cookie: ownerCookie, origin: tenantOrigin })
  assert(queue.response.ok && (queue.payload.items || []).some((item) => item.reference === chatRef && item.unread >= 1), 'Real chat missing from analyst queue')

  const claimed = await json(`/api/v1/live-chat/conversations/${encodeURIComponent(chatRef)}/claim`, {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
  })
  assert(claimed.response.ok && claimed.payload.status === 'Open' && claimed.payload.assignedTo === owner.name, 'Technician could not claim chat')

  const agentText = 'Thanks — I can see the conversation. Please try Outlook once more while I check your account.'
  const agentMessage = await json(`/api/v1/live-chat/conversations/${encodeURIComponent(chatRef)}/messages`, {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { message: agentText },
  })
  assert(agentMessage.response.status === 201 && agentMessage.payload.messages.some((item) => item.text === agentText && item.sender === 'agent'), 'Technician message was not persisted')

  console.log('9. Setting Away: new chats stop, existing chat remains usable')
  const away = await json('/api/v1/live-chat/presence', {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { status: 'Away' },
  })
  assert(away.response.ok && away.payload.status === 'Away' && away.payload.support?.available === false, 'Away presence did not remove new-chat availability')

  const portalPresenceAway = await json('/api/v1/portal/live-chat-presence', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalPresenceAway.response.ok && portalPresenceAway.payload.status === 'Away' && portalPresenceAway.payload.available === false, 'Portal did not report Service Desk Away')

  const blockedAway = await json('/api/v1/portal/live-chat', {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: { subject: 'Second chat should wait', message: 'An Away analyst must not count as available.' },
  })
  assert(blockedAway.response.status === 409 && blockedAway.payload.code === 'live_chat_offline', 'New chat was not blocked while support was Away')

  const requesterDetail = await json(`/api/v1/portal/live-chat/${encodeURIComponent(chatRef)}`, {
    cookie: requesterCookie,
    origin: portalOrigin,
  })
  assert(requesterDetail.response.ok && requesterDetail.payload.messages.some((item) => item.text === agentText), 'Requester did not receive technician message')

  const requesterText = 'Retried it now. The same error is still appearing.'
  const requesterReply = await json(`/api/v1/portal/live-chat/${encodeURIComponent(chatRef)}/messages`, {
    method: 'POST',
    cookie: requesterCookie,
    origin: portalOrigin,
    body: { message: requesterText },
  })
  assert(requesterReply.response.status === 201 && requesterReply.payload.messages.some((item) => item.text === requesterText && item.sender === 'requester'), 'Existing conversation stopped working while analyst was Away')

  const ownerNotificationsAfterReply = await json('/api/v1/notifications?limit=150', { cookie: ownerCookie, origin: tenantOrigin })
  assert((ownerNotificationsAfterReply.payload.items || []).some((item) => item.eventType === 'live_chat.requester_message' && item.target?.reference === chatRef), 'Assigned technician did not receive requester Live Chat notification')

  console.log('10. Closing the chat, going Offline and revoking entitlement')
  const closed = await json(`/api/v1/live-chat/conversations/${encodeURIComponent(chatRef)}/state`, {
    method: 'POST',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { status: 'Closed' },
  })
  assert(closed.response.ok && closed.payload.status === 'Closed', 'Chat close failed')

  const offline = await json('/api/v1/live-chat/presence', {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { status: 'Offline' },
  })
  assert(offline.response.ok && offline.payload.status === 'Offline' && offline.payload.desiredStatus === 'Offline', 'Analyst could not go Offline')

  const disabled = await json(`/api/v1/live-chat/entitlements/${encodeURIComponent(requester.person_key)}`, {
    method: 'PATCH',
    cookie: ownerCookie,
    origin: tenantOrigin,
    body: { enabled: false },
  })
  assert(disabled.response.ok && disabled.payload.liveChatEnabled === false, 'Could not disable requester Live Chat')

  const portalChatAfter = await json('/api/v1/portal/live-chat', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalChatAfter.response.ok && portalChatAfter.payload.enabled === false, 'Portal still exposes Live Chat after entitlement removal')

  const portalPresenceAfter = await json('/api/v1/portal/live-chat-presence', { cookie: requesterCookie, origin: portalOrigin })
  assert(portalPresenceAfter.response.ok && portalPresenceAfter.payload.enabled === false && portalPresenceAfter.payload.available === false, 'Portal presence leaked after entitlement removal')

  console.log('11. Verifying PostgreSQL evidence, presence and Knowledge version history')
  const evidence = await db.query(
    `SELECT
       (SELECT count(*)::int FROM knowledge_articles WHERE tenant_id=$1 AND reference=$2 AND status='Published') AS articles,
       (SELECT count(*)::int FROM knowledge_article_versions v JOIN knowledge_articles a ON a.id=v.article_id WHERE a.tenant_id=$1 AND a.reference=$2) AS versions,
       (SELECT count(*)::int FROM knowledge_article_feedback f JOIN knowledge_articles a ON a.id=f.article_id WHERE a.tenant_id=$1 AND a.reference=$2 AND f.helpful=true) AS helpful,
       (SELECT count(*)::int FROM live_chat_conversations WHERE tenant_id=$1 AND reference=$3 AND status='Closed') AS conversations,
       (SELECT count(*)::int FROM live_chat_messages m JOIN live_chat_conversations c ON c.id=m.conversation_id WHERE c.tenant_id=$1 AND c.reference=$3) AS messages,
       (SELECT count(*)::int FROM live_chat_agent_presence WHERE tenant_id=$1 AND user_id=$4 AND desired_status='Offline') AS offline_presence`,
    [tenant.id, kbRef, chatRef, owner.user_id],
  )
  const row = evidence.rows[0]
  assert(row.articles === 1 && row.versions >= 2 && row.helpful === 1, 'Knowledge persistence evidence incomplete')
  assert(row.conversations === 1 && row.messages >= 4, 'Live Chat persistence evidence incomplete')
  assert(row.offline_presence === 1, 'Server-backed analyst presence evidence incomplete')

  console.log(`Knowledge + Live Chat + presence E2E passed: ${tenant.slug} / ${kbRef} / ${chatRef}`)
} finally {
  await db.end()
}
