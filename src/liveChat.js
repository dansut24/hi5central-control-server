import { pool, withTransaction } from './db.js'
import { originMatchesPortalTenant, originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

function text(value, max = 4000) {
  return String(value ?? '').trim().slice(0, max)
}

function workspaceOrigin(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

function portalOrigin(c, session) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), session.slug)
}

async function requireWorkspace(c, admin = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!workspaceOrigin(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician workspace access is required.' }, 403) }
  if (admin && !['owner', 'admin'].includes(session.tenant_role)) {
    return { error: c.json({ error: 'Tenant administrator access is required.' }, 403) }
  }
  return { session }
}

async function requirePortal(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!portalOrigin(c, session)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (session.tenant_role !== 'requester') return { error: c.json({ error: 'Requester Portal access is required.' }, 403) }
  return { session }
}

async function personForUser(db, tenantId, userId) {
  const result = await db.query(
    `SELECT id, external_key, user_id, name, email, job_title, active
     FROM organisation_people
     WHERE tenant_id=$1 AND user_id=$2 AND active=true
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function entitlementForPerson(db, tenantId, personId) {
  const result = await db.query(
    `SELECT live_chat_enabled FROM person_feature_entitlements
     WHERE tenant_id=$1 AND person_id=$2 LIMIT 1`,
    [tenantId, personId],
  )
  return result.rows[0]?.live_chat_enabled === true
}

async function nextReference(client, tenantId) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`live-chat:${tenantId}`])
  const result = await client.query(
    `SELECT COALESCE(MAX(NULLIF(regexp_replace(reference, '\\D', '', 'g'), '')::integer), 0) + 1 AS next
     FROM live_chat_conversations WHERE tenant_id=$1`,
    [tenantId],
  )
  return `CHAT-${String(Number(result.rows[0]?.next || 1)).padStart(5, '0')}`
}

async function eventAndNotify(client, { tenantId, eventType, reference, actorUserId, title, body, recipients = [], metadata = {} }) {
  const event = await client.query(
    `INSERT INTO domain_events (tenant_id,event_type,aggregate_type,aggregate_reference,actor_user_id,payload)
     VALUES ($1,$2,'Live Chat',$3,$4,$5::jsonb) RETURNING id`,
    [tenantId, eventType, reference, actorUserId || null, JSON.stringify(metadata)],
  )
  for (const userId of [...new Set(recipients.filter(Boolean))]) {
    if (userId === actorUserId) continue
    await client.query(
      `SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,'Live Chat',$7,$8::jsonb)`,
      [tenantId, userId, event.rows[0].id, eventType, title, body, reference, JSON.stringify(metadata)],
    )
  }
}

async function supportUsers(client, tenantId) {
  const result = await client.query(
    `SELECT DISTINCT u.id
     FROM tenant_memberships m
     JOIN users u ON u.id=m.user_id
     WHERE m.tenant_id=$1 AND m.status='active' AND m.role IN ('owner','admin','analyst')`,
    [tenantId],
  )
  return result.rows.map((row) => row.id)
}

const CONVERSATION_SELECT = `
  SELECT c.*,
    rp.external_key AS requester_external_key, rp.name AS requester_name, rp.email AS requester_email, rp.job_title AS requester_role,
    ap.external_key AS assigned_external_key, ap.name AS assigned_name,
    (SELECT count(*) FROM live_chat_messages m WHERE m.conversation_id=c.id AND m.sender_role='requester' AND m.created_at > COALESCE(c.agent_read_at, 'epoch'::timestamptz)) AS agent_unread,
    (SELECT count(*) FROM live_chat_messages m WHERE m.conversation_id=c.id AND m.sender_role='agent' AND m.created_at > COALESCE(c.requester_read_at, 'epoch'::timestamptz)) AS requester_unread,
    (SELECT body FROM live_chat_messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
    (SELECT created_at FROM live_chat_messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at
  FROM live_chat_conversations c
  JOIN organisation_people rp ON rp.id=c.requester_person_id
  LEFT JOIN organisation_people ap ON ap.id=c.assigned_person_id`

function conversationJson(row, perspective = 'agent') {
  return {
    id: row.id,
    reference: row.reference,
    status: row.status,
    subject: row.subject,
    participant: {
      id: row.requester_external_key,
      name: row.requester_name,
      email: row.requester_email,
      role: row.requester_role || 'Requester',
      initials: String(row.requester_name || '').split(/\s+/).filter(Boolean).slice(0,2).map((part) => part[0]).join('').toUpperCase(),
      presence: 'Online',
    },
    assignedPersonId: row.assigned_external_key || '',
    assignedTo: row.assigned_name || '',
    unread: Number(perspective === 'requester' ? row.requester_unread : row.agent_unread || 0),
    lastMessage: row.last_message || '',
    updatedAt: row.last_message_at || row.updated_at,
    createdAt: row.created_at,
    closedAt: row.closed_at,
  }
}

async function messagesFor(db, conversationId) {
  const result = await db.query(
    `SELECT id, sender_role, sender_name, body, created_at
     FROM live_chat_messages WHERE conversation_id=$1 ORDER BY created_at ASC`,
    [conversationId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    sender: row.sender_role,
    senderName: row.sender_name,
    text: row.body,
    createdAt: row.created_at,
  }))
}

async function loadConversation(db, tenantId, reference, perspective = 'agent') {
  const result = await db.query(`${CONVERSATION_SELECT} WHERE c.tenant_id=$1 AND c.reference=$2 LIMIT 1`, [tenantId, reference])
  if (!result.rowCount) return null
  const item = conversationJson(result.rows[0], perspective)
  item.messages = await messagesFor(db, result.rows[0].id)
  return item
}

async function portalContext(db, session) {
  const person = await personForUser(db, session.tenant_id, session.user_id)
  if (!person) return { person: null, enabled: false }
  return { person, enabled: await entitlementForPerson(db, session.tenant_id, person.id) }
}

export function registerLiveChatRoutes(app) {
  app.get('/api/v1/live-chat/conversations', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const result = await pool.query(`${CONVERSATION_SELECT} WHERE c.tenant_id=$1 ORDER BY CASE c.status WHEN 'Waiting' THEN 0 WHEN 'Open' THEN 1 ELSE 2 END, c.updated_at DESC LIMIT 500`, [auth.session.tenant_id])
    return c.json({ items: result.rows.map((row) => conversationJson(row, 'agent')) })
  })

  app.get('/api/v1/live-chat/conversations/:reference', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const item = await loadConversation(pool, auth.session.tenant_id, text(c.req.param('reference'), 120).toUpperCase(), 'agent')
    if (!item) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(item)
  })

  app.post('/api/v1/live-chat/conversations/:reference/read', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    await pool.query(`UPDATE live_chat_conversations SET agent_read_at=now() WHERE tenant_id=$1 AND reference=$2`, [auth.session.tenant_id, reference])
    return c.json({ read: true })
  })

  app.post('/api/v1/live-chat/conversations/:reference/claim', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const person = await personForUser(pool, auth.session.tenant_id, auth.session.user_id)
    if (!person) return c.json({ error: 'Your account is not linked to an active Person.' }, 409)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const updated = await withTransaction(async (client) => {
      const current = await client.query(`SELECT * FROM live_chat_conversations WHERE tenant_id=$1 AND reference=$2 FOR UPDATE`, [auth.session.tenant_id, reference])
      if (!current.rowCount) return false
      await client.query(
        `UPDATE live_chat_conversations SET assigned_person_id=$3, assigned_user_id=$4, status=CASE WHEN status='Closed' THEN status ELSE 'Open' END, agent_read_at=now(), updated_at=now() WHERE tenant_id=$1 AND reference=$2`,
        [auth.session.tenant_id, reference, person.id, auth.session.user_id],
      )
      await client.query(
        `INSERT INTO live_chat_messages (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'system',$5,$6)`,
        [auth.session.tenant_id, current.rows[0].id, auth.session.user_id, person.id, auth.session.name || person.name, `${auth.session.name || person.name} joined the conversation.`],
      )
      await eventAndNotify(client, { tenantId: auth.session.tenant_id, eventType: 'live_chat.claimed', reference, actorUserId: auth.session.user_id, title: `${reference} claimed`, body: `${auth.session.name || person.name} joined the conversation.`, recipients: [current.rows[0].requester_user_id], metadata: { assignedPersonId: person.external_key } })
      return true
    })
    if (!updated) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'agent'))
  })

  app.post('/api/v1/live-chat/conversations/:reference/messages', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const message = text(body?.message, 8000)
    if (!message) return c.json({ error: 'Message is required.' }, 400)
    const person = await personForUser(pool, auth.session.tenant_id, auth.session.user_id)
    if (!person) return c.json({ error: 'Your account is not linked to an active Person.' }, 409)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const ok = await withTransaction(async (client) => {
      const current = await client.query(`SELECT * FROM live_chat_conversations WHERE tenant_id=$1 AND reference=$2 FOR UPDATE`, [auth.session.tenant_id, reference])
      if (!current.rowCount) return false
      if (current.rows[0].status === 'Closed') throw Object.assign(new Error('Reopen the conversation before replying.'), { status: 409 })
      await client.query(
        `INSERT INTO live_chat_messages (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'agent',$5,$6)`,
        [auth.session.tenant_id, current.rows[0].id, auth.session.user_id, person.id, auth.session.name || person.name, message],
      )
      await client.query(
        `UPDATE live_chat_conversations SET assigned_person_id=COALESCE(assigned_person_id,$3), assigned_user_id=COALESCE(assigned_user_id,$4), status='Open', agent_read_at=now(), updated_at=now() WHERE id=$2 AND tenant_id=$1`,
        [auth.session.tenant_id, current.rows[0].id, person.id, auth.session.user_id],
      )
      await eventAndNotify(client, { tenantId: auth.session.tenant_id, eventType: 'live_chat.agent_message', reference, actorUserId: auth.session.user_id, title: `New Live Chat message · ${reference}`, body: message.slice(0, 500), recipients: [current.rows[0].requester_user_id], metadata: { conversationId: current.rows[0].id } })
      return true
    }).catch((error) => ({ error }))
    if (ok?.error) return c.json({ error: ok.error.message }, ok.error.status || 500)
    if (!ok) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'agent'), 201)
  })

  app.post('/api/v1/live-chat/conversations/:reference/state', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const target = body?.status === 'Open' ? 'Open' : body?.status === 'Closed' ? 'Closed' : ''
    if (!target) return c.json({ error: 'Status must be Open or Closed.' }, 400)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const result = await pool.query(
      `UPDATE live_chat_conversations SET status=$3, closed_at=CASE WHEN $3='Closed' THEN now() ELSE NULL END, updated_at=now() WHERE tenant_id=$1 AND reference=$2 RETURNING id`,
      [auth.session.tenant_id, reference, target],
    )
    if (!result.rowCount) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'agent'))
  })

  app.get('/api/v1/live-chat/entitlements/:externalKey', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const externalKey = text(c.req.param('externalKey'), 100)
    const result = await pool.query(
      `SELECT p.external_key,p.name,p.email,p.user_id,p.active,COALESCE(e.live_chat_enabled,false) AS live_chat_enabled
       FROM organisation_people p LEFT JOIN person_feature_entitlements e ON e.tenant_id=p.tenant_id AND e.person_id=p.id
       WHERE p.tenant_id=$1 AND p.external_key=$2 LIMIT 1`,
      [auth.session.tenant_id, externalKey],
    )
    if (!result.rowCount) return c.json({ error: 'Person not found.' }, 404)
    return c.json({ personId: result.rows[0].external_key, name: result.rows[0].name, email: result.rows[0].email, userId: result.rows[0].user_id, active: result.rows[0].active, liveChatEnabled: result.rows[0].live_chat_enabled })
  })

  app.patch('/api/v1/live-chat/entitlements/:externalKey', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    if (typeof body?.enabled !== 'boolean') return c.json({ error: 'enabled must be true or false.' }, 400)
    const externalKey = text(c.req.param('externalKey'), 100)
    const person = await pool.query('SELECT id,external_key,name,email,active FROM organisation_people WHERE tenant_id=$1 AND external_key=$2 LIMIT 1', [auth.session.tenant_id, externalKey])
    if (!person.rowCount) return c.json({ error: 'Person not found.' }, 404)
    if (!person.rows[0].active) return c.json({ error: 'Live Chat cannot be enabled for an inactive Person.' }, 409)
    await pool.query(
      `INSERT INTO person_feature_entitlements (tenant_id,person_id,live_chat_enabled,updated_by_user_id)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (tenant_id,person_id) DO UPDATE SET live_chat_enabled=EXCLUDED.live_chat_enabled,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=now()`,
      [auth.session.tenant_id, person.rows[0].id, body.enabled, auth.session.user_id],
    )
    return c.json({ personId: externalKey, name: person.rows[0].name, liveChatEnabled: body.enabled })
  })

  app.get('/api/v1/portal/live-chat', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const context = await portalContext(pool, auth.session)
    if (!context.person) return c.json({ enabled: false, items: [] })
    if (!context.enabled) return c.json({ enabled: false, items: [] })
    const result = await pool.query(`${CONVERSATION_SELECT} WHERE c.tenant_id=$1 AND c.requester_person_id=$2 ORDER BY c.updated_at DESC LIMIT 100`, [auth.session.tenant_id, context.person.id])
    return c.json({ enabled: true, items: result.rows.map((row) => conversationJson(row, 'requester')) })
  })

  app.get('/api/v1/portal/live-chat/:reference', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const context = await portalContext(pool, auth.session)
    if (!context.enabled || !context.person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const allowed = await pool.query('SELECT 1 FROM live_chat_conversations WHERE tenant_id=$1 AND requester_person_id=$2 AND reference=$3', [auth.session.tenant_id, context.person.id, reference])
    if (!allowed.rowCount) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'requester'))
  })

  app.post('/api/v1/portal/live-chat', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const context = await portalContext(pool, auth.session)
    if (!context.enabled || !context.person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const subject = text(body?.subject, 240)
    const message = text(body?.message, 8000)
    if (subject.length < 3 || message.length < 1) return c.json({ error: 'Add a subject and message.' }, 400)
    const reference = await withTransaction(async (client) => {
      const next = await nextReference(client, auth.session.tenant_id)
      const conversation = await client.query(
        `INSERT INTO live_chat_conversations (tenant_id,reference,requester_person_id,requester_user_id,subject,status,requester_read_at)
         VALUES ($1,$2,$3,$4,$5,'Waiting',now()) RETURNING id`,
        [auth.session.tenant_id, next, context.person.id, auth.session.user_id, subject],
      )
      await client.query(
        `INSERT INTO live_chat_messages (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'requester',$5,$6)`,
        [auth.session.tenant_id, conversation.rows[0].id, auth.session.user_id, context.person.id, context.person.name, message],
      )
      const recipients = await supportUsers(client, auth.session.tenant_id)
      await eventAndNotify(client, { tenantId: auth.session.tenant_id, eventType: 'live_chat.started', reference: next, actorUserId: auth.session.user_id, title: `New Live Chat · ${context.person.name}`, body: `${subject} — ${message.slice(0, 400)}`, recipients, metadata: { requesterPersonId: context.person.external_key } })
      return next
    })
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'requester'), 201)
  })

  app.post('/api/v1/portal/live-chat/:reference/read', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const context = await portalContext(pool, auth.session)
    if (!context.enabled || !context.person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    await pool.query('UPDATE live_chat_conversations SET requester_read_at=now() WHERE tenant_id=$1 AND requester_person_id=$2 AND reference=$3', [auth.session.tenant_id, context.person.id, reference])
    return c.json({ read: true })
  })

  app.post('/api/v1/portal/live-chat/:reference/messages', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const context = await portalContext(pool, auth.session)
    if (!context.enabled || !context.person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const message = text(body?.message, 8000)
    if (!message) return c.json({ error: 'Message is required.' }, 400)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const outcome = await withTransaction(async (client) => {
      const current = await client.query(`SELECT * FROM live_chat_conversations WHERE tenant_id=$1 AND requester_person_id=$2 AND reference=$3 FOR UPDATE`, [auth.session.tenant_id, context.person.id, reference])
      if (!current.rowCount) return 'missing'
      if (current.rows[0].status === 'Closed') return 'closed'
      await client.query(
        `INSERT INTO live_chat_messages (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'requester',$5,$6)`,
        [auth.session.tenant_id, current.rows[0].id, auth.session.user_id, context.person.id, context.person.name, message],
      )
      await client.query(`UPDATE live_chat_conversations SET requester_read_at=now(),updated_at=now() WHERE id=$1`, [current.rows[0].id])
      const recipients = current.rows[0].assigned_user_id ? [current.rows[0].assigned_user_id] : await supportUsers(client, auth.session.tenant_id)
      await eventAndNotify(client, { tenantId: auth.session.tenant_id, eventType: 'live_chat.requester_message', reference, actorUserId: auth.session.user_id, title: `New message from ${context.person.name}`, body: message.slice(0, 500), recipients, metadata: { requesterPersonId: context.person.external_key } })
      return 'ok'
    })
    if (outcome === 'missing') return c.json({ error: 'Conversation not found.' }, 404)
    if (outcome === 'closed') return c.json({ error: 'This conversation is closed.' }, 409)
    return c.json(await loadConversation(pool, auth.session.tenant_id, reference, 'requester'), 201)
  })
}
