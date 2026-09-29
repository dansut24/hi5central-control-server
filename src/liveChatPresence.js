import { originMatchesPortalTenant, originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { liveChatServiceWindow } from './liveChatServiceWindow.js'
import { resolveSession } from './session.js'

const PRESENCE_STALE_SECONDS = 90
const VALID_STATUSES = new Set(['Online', 'Away', 'Offline'])

function workspaceOrigin(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

function portalOrigin(c, session) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), session.slug)
}

async function requireWorkspace(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!workspaceOrigin(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician workspace access is required.' }, 403) }
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
    `SELECT id, external_key, name, email
     FROM organisation_people
     WHERE tenant_id=$1 AND user_id=$2 AND active=true
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function portalLiveChatEnabled(db, tenantId, userId) {
  const result = await db.query(
    `SELECT COALESCE(e.live_chat_enabled, false) AS enabled
     FROM organisation_people p
     LEFT JOIN person_feature_entitlements e
       ON e.tenant_id=p.tenant_id AND e.person_id=p.id
     WHERE p.tenant_id=$1 AND p.user_id=$2 AND p.active=true
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0]?.enabled === true
}

function effectiveStatus(row) {
  if (!row || row.desired_status === 'Offline') return 'Offline'
  const seen = new Date(row.last_seen_at).getTime()
  if (!Number.isFinite(seen) || Date.now() - seen > PRESENCE_STALE_SECONDS * 1000) return 'Offline'
  return row.desired_status === 'Away' ? 'Away' : 'Online'
}

async function presenceForUser(db, tenantId, userId) {
  const result = await db.query(
    `SELECT desired_status, last_seen_at, updated_at
     FROM live_chat_agent_presence
     WHERE tenant_id=$1 AND user_id=$2
     LIMIT 1`,
    [tenantId, userId],
  )
  const row = result.rows[0] || null
  return {
    status: effectiveStatus(row),
    desiredStatus: row?.desired_status || 'Offline',
    lastSeenAt: row?.last_seen_at || null,
    updatedAt: row?.updated_at || null,
    staleAfterSeconds: PRESENCE_STALE_SECONDS,
  }
}

export async function liveChatSupportAvailability(db, tenantId) {
  const [result, serviceHours] = await Promise.all([
    db.query(
      `SELECT
         count(*) FILTER (
           WHERE p.desired_status='Online'
             AND p.last_seen_at > now() - ($2::text || ' seconds')::interval
         )::int AS online,
         count(*) FILTER (
           WHERE p.desired_status='Away'
             AND p.last_seen_at > now() - ($2::text || ' seconds')::interval
         )::int AS away,
         count(*)::int AS total
       FROM tenant_memberships m
       LEFT JOIN live_chat_agent_presence p
         ON p.tenant_id=m.tenant_id AND p.user_id=m.user_id
       WHERE m.tenant_id=$1
         AND m.status='active'
         AND m.role IN ('owner','admin','analyst')`,
      [tenantId, PRESENCE_STALE_SECONDS],
    ),
    liveChatServiceWindow(db, tenantId),
  ])
  const row = result.rows[0] || {}
  const online = Number(row.online || 0)
  const away = Number(row.away || 0)
  const total = Number(row.total || 0)
  const withinHours = serviceHours.open !== false
  return {
    status: withinHours ? (online > 0 ? 'Online' : away > 0 ? 'Away' : 'Offline') : 'Offline',
    online,
    away,
    offline: Math.max(0, total - online - away),
    available: withinHours && online > 0,
    staleAfterSeconds: PRESENCE_STALE_SECONDS,
    serviceHours,
  }
}

async function upsertPresence(db, { tenantId, userId, personId, status, heartbeatOnly = false }) {
  if (heartbeatOnly) {
    await db.query(
      `INSERT INTO live_chat_agent_presence
         (tenant_id,user_id,person_id,desired_status,last_seen_at,updated_at)
       VALUES ($1,$2,$3,'Offline',now(),now())
       ON CONFLICT (tenant_id,user_id) DO UPDATE
       SET person_id=EXCLUDED.person_id,
           last_seen_at=CASE
             WHEN live_chat_agent_presence.desired_status IN ('Online','Away') THEN now()
             ELSE live_chat_agent_presence.last_seen_at
           END,
           updated_at=CASE
             WHEN live_chat_agent_presence.desired_status IN ('Online','Away') THEN now()
             ELSE live_chat_agent_presence.updated_at
           END`,
      [tenantId, userId, personId],
    )
    return
  }

  await db.query(
    `INSERT INTO live_chat_agent_presence
       (tenant_id,user_id,person_id,desired_status,last_seen_at,updated_at)
     VALUES ($1,$2,$3,$4,now(),now())
     ON CONFLICT (tenant_id,user_id) DO UPDATE
     SET person_id=EXCLUDED.person_id,
         desired_status=EXCLUDED.desired_status,
         last_seen_at=now(),
         updated_at=now()`,
    [tenantId, userId, personId, status],
  )
}

export function registerLiveChatPresenceRoutes(app) {
  app.get('/api/v1/live-chat/presence', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const presence = await presenceForUser(pool, auth.session.tenant_id, auth.session.user_id)
    const support = await liveChatSupportAvailability(pool, auth.session.tenant_id)
    return c.json({ ...presence, support })
  })

  app.patch('/api/v1/live-chat/presence', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const status = String(body?.status || '')
    if (!VALID_STATUSES.has(status)) return c.json({ error: 'status must be Online, Away or Offline.' }, 400)
    const person = await activePersonForUser(pool, auth.session.tenant_id, auth.session.user_id)
    if (!person) return c.json({ error: 'Your account is not linked to an active Person.' }, 409)
    await upsertPresence(pool, {
      tenantId: auth.session.tenant_id,
      userId: auth.session.user_id,
      personId: person.id,
      status,
    })
    const presence = await presenceForUser(pool, auth.session.tenant_id, auth.session.user_id)
    const support = await liveChatSupportAvailability(pool, auth.session.tenant_id)
    return c.json({ ...presence, support })
  })

  app.post('/api/v1/live-chat/presence/heartbeat', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const person = await activePersonForUser(pool, auth.session.tenant_id, auth.session.user_id)
    if (!person) return c.json({ error: 'Your account is not linked to an active Person.' }, 409)
    await upsertPresence(pool, {
      tenantId: auth.session.tenant_id,
      userId: auth.session.user_id,
      personId: person.id,
      heartbeatOnly: true,
    })
    const presence = await presenceForUser(pool, auth.session.tenant_id, auth.session.user_id)
    const support = await liveChatSupportAvailability(pool, auth.session.tenant_id)
    return c.json({ ...presence, support })
  })

  app.get('/api/v1/portal/live-chat-presence', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const enabled = await portalLiveChatEnabled(pool, auth.session.tenant_id, auth.session.user_id)
    if (!enabled) return c.json({ enabled: false, status: 'Offline', online: 0, away: 0, offline: 0, available: false })
    const support = await liveChatSupportAvailability(pool, auth.session.tenant_id)
    return c.json({ enabled: true, ...support })
  })

  app.use('/api/v1/portal/live-chat', async (c, next) => {
    if (c.req.method !== 'POST') return next()
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const enabled = await portalLiveChatEnabled(pool, auth.session.tenant_id, auth.session.user_id)
    if (!enabled) return next()
    const support = await liveChatSupportAvailability(pool, auth.session.tenant_id)
    if (!support.available) {
      const outsideHours = support.serviceHours?.open === false
      return c.json({
        error: outsideHours
          ? 'Live Chat is currently outside Service Desk opening hours. Please raise an incident or try again during service hours.'
          : 'Live Chat is currently offline. Please raise an incident or try again when the Service Desk is online.',
        code: outsideHours ? 'live_chat_outside_service_hours' : 'live_chat_offline',
        support,
      }, 409)
    }
    return next()
  })
}
