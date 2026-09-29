import { pool, withTransaction } from './db.js'
import { originMatchesPortalTenant, originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'
import {
  loadLiveChatServiceSettings,
  liveChatServiceWindow,
  saveLiveChatServiceSettings,
} from './liveChatServiceWindow.js'

const PRESENCE_STALE_SECONDS = 90
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
const ALLOWED_ATTACHMENT_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
])

const ATTACHMENT_TYPE_BY_EXTENSION = new Map([
  ['jpg', 'image/jpeg'],
  ['jpeg', 'image/jpeg'],
  ['png', 'image/png'],
  ['gif', 'image/gif'],
  ['webp', 'image/webp'],
  ['pdf', 'application/pdf'],
  ['txt', 'text/plain'],
  ['csv', 'text/csv'],
  ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
])

function text(value, max = 4000) {
  return String(value ?? '').trim().slice(0, max)
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
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

async function activePersonForUser(db, tenantId, userId) {
  const result = await db.query(
    `SELECT p.id,p.external_key,p.user_id,p.name,p.email,p.job_title,p.primary_team_id,
            d.name AS department_name,s.name AS site_name,t.name AS team_name
     FROM organisation_people p
     LEFT JOIN organisation_departments d ON d.id=p.department_id
     LEFT JOIN organisation_sites s ON s.id=p.site_id
     LEFT JOIN organisation_teams t ON t.id=p.primary_team_id
     WHERE p.tenant_id=$1 AND p.user_id=$2 AND p.active=true
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function portalPerson(db, session) {
  const person = await activePersonForUser(db, session.tenant_id, session.user_id)
  if (!person) return null
  const entitlement = await db.query(
    `SELECT live_chat_enabled
     FROM person_feature_entitlements
     WHERE tenant_id=$1 AND person_id=$2
     LIMIT 1`,
    [session.tenant_id, person.id],
  )
  return entitlement.rows[0]?.live_chat_enabled === true ? person : null
}

async function supportUsers(db, tenantId) {
  const result = await db.query(
    `SELECT DISTINCT m.user_id
     FROM tenant_memberships m
     WHERE m.tenant_id=$1
       AND m.status='active'
       AND m.role IN ('owner','admin','analyst')`,
    [tenantId],
  )
  return result.rows.map((row) => row.user_id).filter(Boolean)
}

async function eventAndNotify(client, {
  tenantId,
  eventType,
  reference,
  actorUserId,
  title,
  body,
  recipients = [],
  metadata = {},
}) {
  const event = await client.query(
    `INSERT INTO domain_events
       (tenant_id,event_type,aggregate_type,aggregate_reference,actor_user_id,payload)
     VALUES ($1,$2,'Live Chat',$3,$4,$5::jsonb)
     RETURNING id`,
    [tenantId, eventType, reference, actorUserId || null, JSON.stringify(metadata)],
  )

  for (const userId of [...new Set(recipients.filter(Boolean))]) {
    if (userId === actorUserId) continue
    await client.query(
      `SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,'Live Chat',$7,$8::jsonb)`,
      [
        tenantId,
        userId,
        event.rows[0].id,
        eventType,
        title,
        body,
        reference,
        JSON.stringify(metadata),
      ],
    )
  }
}

async function conversationByReference(db, tenantId, reference, lock = false) {
  const result = await db.query(
    `SELECT c.*,
            rp.external_key AS requester_external_key,
            rp.name AS requester_name,
            rp.email AS requester_email,
            ap.external_key AS assigned_external_key,
            ap.name AS assigned_name
     FROM live_chat_conversations c
     JOIN organisation_people rp ON rp.id=c.requester_person_id
     LEFT JOIN organisation_people ap ON ap.id=c.assigned_person_id
     WHERE c.tenant_id=$1 AND c.reference=$2
     LIMIT 1
     ${lock ? 'FOR UPDATE OF c' : ''}`,
    [tenantId, reference],
  )
  return result.rows[0] || null
}

async function supportAgentByExternalKey(db, tenantId, externalKey) {
  const result = await db.query(
    `SELECT p.id,p.external_key,p.name,p.email,p.user_id,m.role,
            pr.desired_status,pr.last_seen_at
     FROM organisation_people p
     JOIN tenant_memberships m
       ON m.tenant_id=p.tenant_id
      AND m.user_id=p.user_id
      AND m.status='active'
      AND m.role IN ('owner','admin','analyst')
     LEFT JOIN live_chat_agent_presence pr
       ON pr.tenant_id=p.tenant_id
      AND pr.user_id=p.user_id
     WHERE p.tenant_id=$1
       AND p.external_key=$2
       AND p.active=true
       AND p.user_id IS NOT NULL
     LIMIT 1`,
    [tenantId, externalKey],
  )
  return result.rows[0] || null
}

function effectivePresence(row) {
  if (!row?.desired_status || row.desired_status === 'Offline') return 'Offline'
  const seen = new Date(row.last_seen_at).getTime()
  if (!Number.isFinite(seen) || Date.now() - seen > PRESENCE_STALE_SECONDS * 1000) return 'Offline'
  return row.desired_status === 'Away' ? 'Away' : 'Online'
}

async function attachmentList(db, conversationId) {
  const result = await db.query(
    `SELECT id,file_name,mime_type,size_bytes,sender_role,sender_name,created_at
     FROM live_chat_attachments
     WHERE conversation_id=$1
     ORDER BY created_at ASC`,
    [conversationId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    fileName: row.file_name,
    mimeType: row.mime_type,
    size: Number(row.size_bytes || 0),
    sender: row.sender_role,
    senderName: row.sender_name,
    createdAt: row.created_at,
  }))
}

async function operationsState(db, conversation, perspective) {
  const attachments = await attachmentList(db, conversation.id)
  return {
    reference: conversation.reference,
    requesterTyping: Boolean(
      conversation.requester_typing_until
      && new Date(conversation.requester_typing_until).getTime() > Date.now()
    ),
    agentTyping: Boolean(
      conversation.agent_typing_until
      && new Date(conversation.agent_typing_until).getTime() > Date.now()
    ),
    otherPartyTyping: perspective === 'requester'
      ? Boolean(conversation.agent_typing_until && new Date(conversation.agent_typing_until).getTime() > Date.now())
      : Boolean(conversation.requester_typing_until && new Date(conversation.requester_typing_until).getTime() > Date.now()),
    requesterReadAt: conversation.requester_read_at || null,
    agentReadAt: conversation.agent_read_at || null,
    firstAgentResponseAt: conversation.first_agent_response_at || null,
    linkedRecord: conversation.linked_record_reference ? {
      type: conversation.linked_record_type || '',
      reference: conversation.linked_record_reference,
    } : null,
    attachments,
  }
}

function cleanFileName(value) {
  const raw = text(value, 240).replace(/[\u0000-\u001f\u007f/\\]/g, '_')
  return raw || 'attachment'
}

function decodeAttachment(dataBase64) {
  const value = String(dataBase64 || '')
  if (!value || value.length > Math.ceil(MAX_ATTACHMENT_BYTES * 4 / 3) + 100) {
    throw Object.assign(new Error('Attachment is empty or larger than 5 MB.'), { status: 413 })
  }
  let buffer
  try {
    buffer = Buffer.from(value, 'base64')
  } catch {
    buffer = null
  }
  if (!buffer?.length || buffer.length > MAX_ATTACHMENT_BYTES) {
    throw Object.assign(new Error('Attachment is empty or larger than 5 MB.'), { status: 413 })
  }
  return buffer
}

async function saveAttachment({
  session,
  person,
  reference,
  senderRole,
  body,
}) {
  const fileName = cleanFileName(body?.name)
  const extension = fileName.includes('.') ? fileName.split('.').pop().toLowerCase() : ''
  const suppliedType = text(body?.type, 180).toLowerCase()
  const mimeType = ALLOWED_ATTACHMENT_TYPES.has(suppliedType)
    ? suppliedType
    : ATTACHMENT_TYPE_BY_EXTENSION.get(extension) || suppliedType
  if (!ALLOWED_ATTACHMENT_TYPES.has(mimeType)) {
    throw Object.assign(new Error('This file type is not supported in Live Chat.'), { status: 415 })
  }
  const content = decodeAttachment(body?.dataBase64)

  return withTransaction(async (client) => {
    const current = await conversationByReference(client, session.tenant_id, reference, true)
    if (!current) throw Object.assign(new Error('Conversation not found.'), { status: 404 })
    if (current.status === 'Closed') throw Object.assign(new Error('Reopen the conversation before adding an attachment.'), { status: 409 })
    if (senderRole === 'requester' && current.requester_user_id !== session.user_id) {
      throw Object.assign(new Error('Conversation not found.'), { status: 404 })
    }

    const inserted = await client.query(
      `INSERT INTO live_chat_attachments
         (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,file_name,mime_type,size_bytes,content)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id,created_at`,
      [
        session.tenant_id,
        current.id,
        session.user_id,
        person.id,
        senderRole,
        person.name || session.name || '',
        fileName,
        mimeType,
        content.length,
        content,
      ],
    )

    await client.query(
      `UPDATE live_chat_conversations
       SET requester_read_at=CASE WHEN $3='requester' THEN now() ELSE requester_read_at END,
           agent_read_at=CASE WHEN $3='agent' THEN now() ELSE agent_read_at END,
           updated_at=now()
       WHERE tenant_id=$1 AND id=$2`,
      [session.tenant_id, current.id, senderRole],
    )

    const recipients = senderRole === 'requester'
      ? (current.assigned_user_id ? [current.assigned_user_id] : await supportUsers(client, session.tenant_id))
      : [current.requester_user_id]

    await eventAndNotify(client, {
      tenantId: session.tenant_id,
      eventType: senderRole === 'requester' ? 'live_chat.requester_attachment' : 'live_chat.agent_attachment',
      reference,
      actorUserId: session.user_id,
      title: `Live Chat attachment · ${reference}`,
      body: `${person.name || session.name || 'User'} shared ${fileName}`,
      recipients,
      metadata: { attachmentId: inserted.rows[0].id, fileName, mimeType, size: content.length },
    })

    return {
      id: inserted.rows[0].id,
      fileName,
      mimeType,
      size: content.length,
      sender: senderRole,
      senderName: person.name || session.name || '',
      createdAt: inserted.rows[0].created_at,
    }
  })
}

async function permittedAttachment(db, { tenantId, attachmentId, userId, portal = false }) {
  if (portal) {
    const result = await db.query(
      `SELECT a.file_name,a.mime_type,a.size_bytes,a.content
       FROM live_chat_attachments a
       JOIN live_chat_conversations c ON c.id=a.conversation_id
       WHERE a.tenant_id=$1 AND a.id=$2 AND c.requester_user_id=$3
       LIMIT 1`,
      [tenantId, attachmentId, userId],
    )
    return result.rows[0] || null
  }

  const result = await db.query(
    `SELECT file_name,mime_type,size_bytes,content
     FROM live_chat_attachments
     WHERE tenant_id=$1 AND id=$2
     LIMIT 1`,
    [tenantId, attachmentId],
  )
  return result.rows[0] || null
}

function attachmentResponse(row) {
  const encoded = encodeURIComponent(row.file_name || 'attachment')
  return new Response(row.content, {
    status: 200,
    headers: {
      'Content-Type': row.mime_type || 'application/octet-stream',
      'Content-Length': String(Number(row.size_bytes || row.content?.length || 0)),
      'Content-Disposition': `attachment; filename*=UTF-8''${encoded}`,
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

function effectiveConfiguration(row) {
  if (row?.configuration && Object.keys(row.configuration).length) return row.configuration
  return row?.onboarding_data || {}
}

async function nextIncidentReference(client, tenantId) {
  const settings = await client.query(
    `SELECT configuration,onboarding_data
     FROM tenant_settings
     WHERE tenant_id=$1
     LIMIT 1`,
    [tenantId],
  )
  const config = effectiveConfiguration(settings.rows[0] || {})
  const itsm = asObject(config.itsm)
  const custom = itsm.numberingMode === 'custom'
  const configured = custom ? text(asObject(itsm.recordPrefixes).incident, 12) : 'INC-'
  const cleaned = (configured || 'INC-').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 10)
  const prefix = (cleaned || 'INC-').endsWith('-') ? (cleaned || 'INC-') : `${cleaned || 'INC-'}-`
  const digits = Math.max(4, Math.min(8, Number(itsm.recordDigits || 5)))
  const counter = await client.query(
    `INSERT INTO tenant_record_counters (tenant_id,record_type,next_value,updated_at)
     VALUES ($1,'incident',1,now())
     ON CONFLICT (tenant_id,record_type) DO UPDATE SET
       next_value=tenant_record_counters.next_value+1,
       updated_at=now()
     RETURNING next_value`,
    [tenantId],
  )
  return `${prefix}${String(counter.rows[0].next_value).padStart(digits, '0')}`
}

async function defaultIncidentTeam(client, tenantId) {
  const result = await client.query(
    `SELECT id,external_key,name
     FROM organisation_teams
     WHERE tenant_id=$1
       AND active=true
       AND (external_key='TEAM-SERVICE-DESK' OR lower(name)='service desk')
     ORDER BY CASE WHEN external_key='TEAM-SERVICE-DESK' THEN 0 ELSE 1 END
     LIMIT 1`,
    [tenantId],
  )
  return result.rows[0] || null
}

async function transcriptText(db, conversation) {
  const [messages, attachments] = await Promise.all([
    db.query(
      `SELECT sender_role,sender_name,body,created_at
       FROM live_chat_messages
       WHERE conversation_id=$1
       ORDER BY created_at ASC`,
      [conversation.id],
    ),
    db.query(
      `SELECT sender_role,sender_name,file_name,size_bytes,created_at
       FROM live_chat_attachments
       WHERE conversation_id=$1
       ORDER BY created_at ASC`,
      [conversation.id],
    ),
  ])

  const timeline = [
    ...messages.rows.map((row) => ({
      at: row.created_at,
      line: `[${new Date(row.created_at).toISOString()}] ${row.sender_name || row.sender_role}: ${row.body}`,
    })),
    ...attachments.rows.map((row) => ({
      at: row.created_at,
      line: `[${new Date(row.created_at).toISOString()}] ${row.sender_name || row.sender_role}: [Attachment] ${row.file_name} (${row.size_bytes} bytes)`,
    })),
  ].sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime())

  return [
    `Hi5Central Live Chat transcript`,
    `${conversation.reference} · ${conversation.subject}`,
    `Requester: ${conversation.requester_name} <${conversation.requester_email}>`,
    `Status: ${conversation.status}`,
    `Assigned: ${conversation.assigned_name || 'Unassigned'}`,
    '',
    ...timeline.map((item) => item.line),
    '',
  ].join('\n')
}

async function findRecord(db, tenantId, reference) {
  const normalized = text(reference, 120).toUpperCase()
  const itsm = await db.query(
    `SELECT reference,record_type AS type,title,status,updated_at
     FROM itsm_records
     WHERE tenant_id=$1 AND upper(reference)=$2
     LIMIT 1`,
    [tenantId, normalized],
  )
  if (itsm.rowCount) return itsm.rows[0]

  const request = await db.query(
    `SELECT reference,'Service Request'::text AS type,title,status,updated_at
     FROM service_requests
     WHERE tenant_id=$1 AND upper(reference)=$2
     LIMIT 1`,
    [tenantId, normalized],
  )
  return request.rows[0] || null
}

export function registerLiveChatOperationsRoutes(app) {
  // Prevent the legacy claim handler from silently stealing a conversation that
  // another analyst already owns. Explicit reassignment must use /transfer.
  app.use('/api/v1/live-chat/conversations/:reference/claim', async (c, next) => {
    if (c.req.method !== 'POST') return next()
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const current = await pool.query(
      `SELECT assigned_user_id
       FROM live_chat_conversations
       WHERE tenant_id=$1 AND reference=$2
       LIMIT 1`,
      [auth.session.tenant_id, reference],
    )
    if (!current.rowCount) return next()
    const assignedUserId = current.rows[0].assigned_user_id
    if (assignedUserId && assignedUserId !== auth.session.user_id) {
      return c.json({
        error: 'This conversation is already assigned to another analyst. Use Transfer to reassign it.',
        code: 'live_chat_already_assigned',
      }, 409)
    }
    return next()
  })

  app.get('/api/v1/live-chat/agents', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error

    const result = await pool.query(
      `SELECT p.external_key,p.name,p.email,p.user_id,m.role,
              pr.desired_status,pr.last_seen_at,
              count(conv.id) FILTER (WHERE conv.status='Open')::int AS open_chats
       FROM organisation_people p
       JOIN tenant_memberships m
         ON m.tenant_id=p.tenant_id
        AND m.user_id=p.user_id
        AND m.status='active'
        AND m.role IN ('owner','admin','analyst')
       LEFT JOIN live_chat_agent_presence pr
         ON pr.tenant_id=p.tenant_id
        AND pr.user_id=p.user_id
       LEFT JOIN live_chat_conversations conv
         ON conv.tenant_id=p.tenant_id
        AND conv.assigned_user_id=p.user_id
        AND conv.status='Open'
       WHERE p.tenant_id=$1
         AND p.active=true
         AND p.user_id IS NOT NULL
       GROUP BY p.external_key,p.name,p.email,p.user_id,m.role,pr.desired_status,pr.last_seen_at
       ORDER BY p.name`,
      [auth.session.tenant_id],
    )

    return c.json({
      items: result.rows.map((row) => ({
        personId: row.external_key,
        name: row.name,
        email: row.email,
        role: row.role,
        presence: effectivePresence(row),
        openChats: Number(row.open_chats || 0),
        current: row.user_id === auth.session.user_id,
      })),
    })
  })

  app.get('/api/v1/live-chat/metrics', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error

    const [metrics, presence, serviceHours] = await Promise.all([
      pool.query(
        `SELECT
           count(*) FILTER (WHERE status='Waiting')::int AS waiting,
           count(*) FILTER (WHERE status='Open')::int AS open,
           count(*) FILTER (WHERE status='Closed' AND closed_at >= date_trunc('day',now()))::int AS closed_today,
           count(*) FILTER (WHERE status<>'Closed' AND assigned_user_id IS NULL)::int AS unassigned,
           EXTRACT(EPOCH FROM (now() - min(created_at) FILTER (WHERE status='Waiting')))::int AS oldest_waiting_seconds,
           round(avg(EXTRACT(EPOCH FROM (first_agent_response_at-created_at)))
             FILTER (WHERE first_agent_response_at IS NOT NULL))::int AS avg_first_response_seconds
         FROM live_chat_conversations
         WHERE tenant_id=$1`,
        [auth.session.tenant_id],
      ),
      pool.query(
        `SELECT
           count(*) FILTER (
             WHERE desired_status='Online' AND last_seen_at > now()-interval '90 seconds'
           )::int AS online,
           count(*) FILTER (
             WHERE desired_status='Away' AND last_seen_at > now()-interval '90 seconds'
           )::int AS away
         FROM live_chat_agent_presence
         WHERE tenant_id=$1`,
        [auth.session.tenant_id],
      ),
      liveChatServiceWindow(pool, auth.session.tenant_id),
    ])

    const row = metrics.rows[0] || {}
    const agents = presence.rows[0] || {}
    return c.json({
      waiting: Number(row.waiting || 0),
      open: Number(row.open || 0),
      closedToday: Number(row.closed_today || 0),
      unassigned: Number(row.unassigned || 0),
      oldestWaitingSeconds: Number(row.oldest_waiting_seconds || 0),
      averageFirstResponseSeconds: Number(row.avg_first_response_seconds || 0),
      analystsOnline: Number(agents.online || 0),
      analystsAway: Number(agents.away || 0),
      serviceHours,
    })
  })

  app.get('/api/v1/live-chat/conversations/:reference/operations', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const conversation = await conversationByReference(pool, auth.session.tenant_id, reference)
    if (!conversation) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json(await operationsState(pool, conversation, 'agent'))
  })

  app.get('/api/v1/portal/live-chat/:reference/operations', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const person = await portalPerson(pool, auth.session)
    if (!person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const conversation = await conversationByReference(pool, auth.session.tenant_id, reference)
    if (!conversation || conversation.requester_user_id !== auth.session.user_id) {
      return c.json({ error: 'Conversation not found.' }, 404)
    }
    return c.json(await operationsState(pool, conversation, 'requester'))
  })

  app.post('/api/v1/live-chat/conversations/:reference/typing', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const result = await pool.query(
      `UPDATE live_chat_conversations
       SET agent_typing_until=CASE WHEN $3 THEN now()+interval '7 seconds' ELSE NULL END
       WHERE tenant_id=$1 AND reference=$2 AND status<>'Closed'
       RETURNING id`,
      [auth.session.tenant_id, reference, Boolean(body?.active)],
    )
    if (!result.rowCount) return c.json({ error: 'Conversation not found or closed.' }, 404)
    return c.json({ typing: Boolean(body?.active) })
  })

  app.post('/api/v1/portal/live-chat/:reference/typing', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const person = await portalPerson(pool, auth.session)
    if (!person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const result = await pool.query(
      `UPDATE live_chat_conversations
       SET requester_typing_until=CASE WHEN $4 THEN now()+interval '7 seconds' ELSE NULL END
       WHERE tenant_id=$1 AND reference=$2 AND requester_person_id=$3 AND status<>'Closed'
       RETURNING id`,
      [auth.session.tenant_id, reference, person.id, Boolean(body?.active)],
    )
    if (!result.rowCount) return c.json({ error: 'Conversation not found or closed.' }, 404)
    return c.json({ typing: Boolean(body?.active) })
  })

  app.post('/api/v1/live-chat/conversations/:reference/transfer', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const externalKey = text(body?.personId, 120)
    if (!externalKey) return c.json({ error: 'Choose an analyst to transfer this conversation to.' }, 400)

    const target = await supportAgentByExternalKey(pool, auth.session.tenant_id, externalKey)
    if (!target) return c.json({ error: 'The selected analyst is not an active support user.' }, 409)

    const result = await withTransaction(async (client) => {
      const current = await conversationByReference(client, auth.session.tenant_id, reference, true)
      if (!current) return null
      if (current.status === 'Closed') {
        throw Object.assign(new Error('Reopen the conversation before transferring it.'), { status: 409 })
      }
      if (current.assigned_user_id === target.user_id) return current

      const actor = await activePersonForUser(client, auth.session.tenant_id, auth.session.user_id)
      await client.query(
        `UPDATE live_chat_conversations
         SET assigned_person_id=$3,assigned_user_id=$4,status='Open',
             transferred_at=now(),agent_read_at=now(),updated_at=now()
         WHERE tenant_id=$1 AND reference=$2`,
        [auth.session.tenant_id, reference, target.id, target.user_id],
      )
      const sentence = `${actor?.name || auth.session.name || 'An analyst'} transferred the conversation to ${target.name}.`
      await client.query(
        `INSERT INTO live_chat_messages
           (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'system',$5,$6)`,
        [
          auth.session.tenant_id,
          current.id,
          auth.session.user_id,
          actor?.id || null,
          actor?.name || auth.session.name || 'Service Desk',
          sentence,
        ],
      )
      await eventAndNotify(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'live_chat.transferred',
        reference,
        actorUserId: auth.session.user_id,
        title: `${reference} transferred to you`,
        body: sentence,
        recipients: [target.user_id, current.requester_user_id],
        metadata: { assignedPersonId: target.external_key },
      })
      return current
    }).catch((error) => ({ error }))

    if (result?.error) return c.json({ error: result.error.message }, result.error.status || 500)
    if (!result) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json({ transferred: true, assignedPersonId: target.external_key, assignedTo: target.name })
  })

  app.post('/api/v1/live-chat/conversations/:reference/attachments', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const person = await activePersonForUser(pool, auth.session.tenant_id, auth.session.user_id)
    if (!person) return c.json({ error: 'Your account is not linked to an active Person.' }, 409)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    try {
      return c.json(await saveAttachment({ session: auth.session, person, reference, senderRole: 'agent', body }), 201)
    } catch (error) {
      return c.json({ error: error.message }, error.status || 500)
    }
  })

  app.post('/api/v1/portal/live-chat/:reference/attachments', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const person = await portalPerson(pool, auth.session)
    if (!person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    try {
      return c.json(await saveAttachment({ session: auth.session, person, reference, senderRole: 'requester', body }), 201)
    } catch (error) {
      return c.json({ error: error.message }, error.status || 500)
    }
  })

  app.get('/api/v1/live-chat/attachments/:id', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const row = await permittedAttachment(pool, {
      tenantId: auth.session.tenant_id,
      attachmentId: text(c.req.param('id'), 100),
      userId: auth.session.user_id,
    })
    if (!row) return c.json({ error: 'Attachment not found.' }, 404)
    return attachmentResponse(row)
  })

  app.get('/api/v1/portal/live-chat-attachments/:id', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const person = await portalPerson(pool, auth.session)
    if (!person) return c.json({ error: 'Live Chat is not enabled for your account.' }, 403)
    const row = await permittedAttachment(pool, {
      tenantId: auth.session.tenant_id,
      attachmentId: text(c.req.param('id'), 100),
      userId: auth.session.user_id,
      portal: true,
    })
    if (!row) return c.json({ error: 'Attachment not found.' }, 404)
    return attachmentResponse(row)
  })

  app.get('/api/v1/live-chat/canned-responses', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id,shortcut,title,body,active,updated_at
       FROM live_chat_canned_responses
       WHERE tenant_id=$1
       ORDER BY active DESC,title`,
      [auth.session.tenant_id],
    )
    return c.json({
      canManage: ['owner', 'admin'].includes(auth.session.tenant_role),
      items: result.rows.map((row) => ({
        id: row.id,
        shortcut: row.shortcut,
        title: row.title,
        body: row.body,
        active: row.active,
        updatedAt: row.updated_at,
      })),
    })
  })

  app.post('/api/v1/live-chat/canned-responses', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const shortcut = text(body?.shortcut, 40).toLowerCase().replace(/^\/+/, '')
    const title = text(body?.title, 160)
    const responseBody = text(body?.body, 8000)
    if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(shortcut) || !title || !responseBody) {
      return c.json({ error: 'Add a title, response and shortcut using letters, numbers, - or _.' }, 400)
    }
    try {
      const result = await pool.query(
        `INSERT INTO live_chat_canned_responses
           (tenant_id,shortcut,title,body,created_by_user_id,updated_by_user_id)
         VALUES ($1,$2,$3,$4,$5,$5)
         RETURNING id,shortcut,title,body,active,updated_at`,
        [auth.session.tenant_id, shortcut, title, responseBody, auth.session.user_id],
      )
      return c.json(result.rows[0], 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'That canned-response shortcut already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/v1/live-chat/canned-responses/:id', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const current = await pool.query(
      `SELECT shortcut,title,body,active
       FROM live_chat_canned_responses
       WHERE tenant_id=$1 AND id=$2
       LIMIT 1`,
      [auth.session.tenant_id, text(c.req.param('id'), 100)],
    )
    if (!current.rowCount) return c.json({ error: 'Canned response not found.' }, 404)

    const row = current.rows[0]
    const shortcut = body?.shortcut === undefined ? row.shortcut : text(body.shortcut, 40).toLowerCase().replace(/^\/+/, '')
    const title = body?.title === undefined ? row.title : text(body.title, 160)
    const responseBody = body?.body === undefined ? row.body : text(body.body, 8000)
    const active = body?.active === undefined ? row.active : Boolean(body.active)

    if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(shortcut) || !title || !responseBody) {
      return c.json({ error: 'Add a title, response and valid shortcut.' }, 400)
    }

    try {
      const updated = await pool.query(
        `UPDATE live_chat_canned_responses
         SET shortcut=$3,title=$4,body=$5,active=$6,updated_by_user_id=$7,updated_at=now()
         WHERE tenant_id=$1 AND id=$2
         RETURNING id,shortcut,title,body,active,updated_at`,
        [
          auth.session.tenant_id,
          text(c.req.param('id'), 100),
          shortcut,
          title,
          responseBody,
          active,
          auth.session.user_id,
        ],
      )
      return c.json(updated.rows[0])
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'That canned-response shortcut already exists.' }, 409)
      throw error
    }
  })

  app.get('/api/v1/live-chat/records', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const q = text(c.req.query('q'), 120)
    const pattern = `%${q.replace(/[%_]/g, '\\$&')}%`
    const result = await pool.query(
      `SELECT * FROM (
         SELECT reference,record_type AS type,title,status,updated_at
         FROM itsm_records
         WHERE tenant_id=$1
           AND ($2='' OR reference ILIKE $3 ESCAPE '\\' OR title ILIKE $3 ESCAPE '\\')
         UNION ALL
         SELECT reference,'Service Request'::text AS type,title,status,updated_at
         FROM service_requests
         WHERE tenant_id=$1
           AND ($2='' OR reference ILIKE $3 ESCAPE '\\' OR title ILIKE $3 ESCAPE '\\')
       ) records
       ORDER BY updated_at DESC
       LIMIT 40`,
      [auth.session.tenant_id, q, pattern],
    )
    return c.json({ items: result.rows })
  })

  app.post('/api/v1/live-chat/conversations/:reference/link-record', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const record = await findRecord(pool, auth.session.tenant_id, body?.recordReference)
    if (!record) return c.json({ error: 'Record not found in this tenant.' }, 404)

    const result = await withTransaction(async (client) => {
      const current = await conversationByReference(client, auth.session.tenant_id, reference, true)
      if (!current) return false
      await client.query(
        `UPDATE live_chat_conversations
         SET linked_record_type=$3,linked_record_reference=$4,updated_at=now()
         WHERE tenant_id=$1 AND reference=$2`,
        [auth.session.tenant_id, reference, record.type, record.reference],
      )
      const actor = await activePersonForUser(client, auth.session.tenant_id, auth.session.user_id)
      const sentence = `${record.type} ${record.reference} linked to this conversation.`
      await client.query(
        `INSERT INTO live_chat_messages
           (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'system',$5,$6)`,
        [
          auth.session.tenant_id,
          current.id,
          auth.session.user_id,
          actor?.id || null,
          actor?.name || auth.session.name || 'Service Desk',
          sentence,
        ],
      )
      await eventAndNotify(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'live_chat.record_linked',
        reference,
        actorUserId: auth.session.user_id,
        title: `${reference} linked to ${record.reference}`,
        body: sentence,
        recipients: [current.requester_user_id],
        metadata: { recordType: record.type, recordReference: record.reference },
      })
      return true
    })
    if (!result) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json({ linked: true, record: { type: record.type, reference: record.reference, title: record.title, status: record.status } })
  })

  app.post('/api/v1/live-chat/conversations/:reference/create-incident', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const reference = text(c.req.param('reference'), 120).toUpperCase()

    const outcome = await withTransaction(async (client) => {
      const conversation = await conversationByReference(client, auth.session.tenant_id, reference, true)
      if (!conversation) return null
      if (conversation.linked_record_reference) {
        throw Object.assign(new Error(`This chat is already linked to ${conversation.linked_record_reference}.`), { status: 409 })
      }

      const incidentReference = await nextIncidentReference(client, auth.session.tenant_id)
      const team = await defaultIncidentTeam(client, auth.session.tenant_id)
      const requester = await client.query(
        `SELECT p.*,d.name AS department_name,s.name AS site_name,t.name AS team_name
         FROM organisation_people p
         LEFT JOIN organisation_departments d ON d.id=p.department_id
         LEFT JOIN organisation_sites s ON s.id=p.site_id
         LEFT JOIN organisation_teams t ON t.id=p.primary_team_id
         WHERE p.id=$1 AND p.tenant_id=$2
         LIMIT 1`,
        [conversation.requester_person_id, auth.session.tenant_id],
      )
      const requesterRow = requester.rows[0] || {}
      const assigned = conversation.assigned_person_id
        ? await client.query(
          `SELECT id,external_key,name,email,job_title
           FROM organisation_people
           WHERE tenant_id=$1 AND id=$2
           LIMIT 1`,
          [auth.session.tenant_id, conversation.assigned_person_id],
        )
        : { rows: [] }
      const assignedRow = assigned.rows[0] || null
      const transcript = await transcriptText(client, conversation)

      const requesterSnapshot = {
        userId: requesterRow.user_id || conversation.requester_user_id || null,
        personId: requesterRow.external_key || '',
        name: requesterRow.name || conversation.requester_name || '',
        email: requesterRow.email || conversation.requester_email || '',
        phone: requesterRow.phone || '',
        jobTitle: requesterRow.job_title || '',
        department: requesterRow.department_name || '',
        team: requesterRow.team_name || '',
        site: requesterRow.site_name || '',
      }
      const teamSnapshot = team ? { id: team.external_key, name: team.name } : {}
      const assigneeSnapshot = assignedRow ? {
        id: assignedRow.external_key,
        name: assignedRow.name,
        email: assignedRow.email,
        jobTitle: assignedRow.job_title || '',
      } : {}

      const incident = await client.query(
        `INSERT INTO itsm_records
           (tenant_id,reference,record_type,requester_person_id,requester_snapshot,title,description,
            service,category,priority,status,source,assignment_team_id,assignment_team_snapshot,
            assigned_person_id,assignee_snapshot,record_data,created_by_user_id)
         VALUES ($1,$2,'Incident',$3,$4::jsonb,$5,$6,
                 'Service Desk','Live Chat','Medium','New','live_chat',$7,$8::jsonb,
                 $9,$10::jsonb,$11::jsonb,$12)
         RETURNING id,reference,title,status`,
        [
          auth.session.tenant_id,
          incidentReference,
          conversation.requester_person_id,
          JSON.stringify(requesterSnapshot),
          conversation.subject,
          transcript,
          team?.id || null,
          JSON.stringify(teamSnapshot),
          assignedRow?.id || null,
          JSON.stringify(assigneeSnapshot),
          JSON.stringify({ liveChatReference: reference, createdFromLiveChat: true }),
          auth.session.user_id,
        ],
      )

      const actor = await activePersonForUser(client, auth.session.tenant_id, auth.session.user_id)
      await client.query(
        `INSERT INTO itsm_record_activities
           (tenant_id,record_id,actor_user_id,actor_person_id,actor_snapshot,kind,visibility,body_text,metadata)
         VALUES ($1,$2,$3,$4,$5::jsonb,'system','customer',$6,$7::jsonb)`,
        [
          auth.session.tenant_id,
          incident.rows[0].id,
          auth.session.user_id,
          actor?.id || null,
          JSON.stringify({ name: actor?.name || auth.session.name || 'Service Desk', personId: actor?.external_key || '' }),
          `Incident ${incidentReference} was created from Live Chat ${reference}.`,
          JSON.stringify({ liveChatReference: reference }),
        ],
      )

      await client.query(
        `UPDATE live_chat_conversations
         SET linked_record_type='Incident',linked_record_reference=$3,updated_at=now()
         WHERE tenant_id=$1 AND reference=$2`,
        [auth.session.tenant_id, reference, incidentReference],
      )
      await client.query(
        `INSERT INTO live_chat_messages
           (tenant_id,conversation_id,sender_user_id,sender_person_id,sender_role,sender_name,body)
         VALUES ($1,$2,$3,$4,'system',$5,$6)`,
        [
          auth.session.tenant_id,
          conversation.id,
          auth.session.user_id,
          actor?.id || null,
          actor?.name || auth.session.name || 'Service Desk',
          `Incident ${incidentReference} was created and linked to this conversation.`,
        ],
      )
      await eventAndNotify(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'live_chat.incident_created',
        reference,
        actorUserId: auth.session.user_id,
        title: `${incidentReference} created from ${reference}`,
        body: `Incident ${incidentReference} was created from your Live Chat conversation.`,
        recipients: [conversation.requester_user_id],
        metadata: { recordType: 'Incident', recordReference: incidentReference },
      })
      return incident.rows[0]
    }).catch((error) => ({ error }))

    if (outcome?.error) return c.json({ error: outcome.error.message }, outcome.error.status || 500)
    if (!outcome) return c.json({ error: 'Conversation not found.' }, 404)
    return c.json({ created: true, incident: outcome }, 201)
  })

  app.get('/api/v1/live-chat/conversations/:reference/transcript', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const reference = text(c.req.param('reference'), 120).toUpperCase()
    const conversation = await conversationByReference(pool, auth.session.tenant_id, reference)
    if (!conversation) return c.json({ error: 'Conversation not found.' }, 404)
    const content = await transcriptText(pool, conversation)
    return c.json({ fileName: `${reference.toLowerCase()}-transcript.txt`, content })
  })

  app.get('/api/v1/live-chat/service-hours', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const [settings, state] = await Promise.all([
      loadLiveChatServiceSettings(pool, auth.session.tenant_id),
      liveChatServiceWindow(pool, auth.session.tenant_id),
    ])
    return c.json({
      ...settings,
      open: state.open,
      reason: state.reason,
      localTime: state.localTime,
      today: state.today,
      canManage: ['owner', 'admin'].includes(auth.session.tenant_role),
    })
  })

  app.patch('/api/v1/live-chat/service-hours', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    try {
      const settings = await saveLiveChatServiceSettings(pool, {
        tenantId: auth.session.tenant_id,
        userId: auth.session.user_id,
        enabled: Boolean(body?.enabled),
        timezone: body?.timezone,
        schedule: body?.schedule,
      })
      const state = await liveChatServiceWindow(pool, auth.session.tenant_id)
      return c.json({ ...settings, open: state.open, reason: state.reason, localTime: state.localTime, today: state.today, canManage: true })
    } catch (error) {
      return c.json({ error: error.message }, error.status || 500)
    }
  })
}
