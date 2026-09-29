import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { WebSocketServer } from 'ws'
import { hasPermission } from './access.js'
import { deployment, originMatchesTenant, tenantUrls } from './deploymentConfig.js'
import { pool } from './db.js'
import { agentSocketForDevice, subscribeAgentConnections } from './rmmAgent.js'
import { recordRmmActivity } from './rmmActivity.js'
import { resolveSession } from './session.js'

const ROOT_DOMAIN = deployment.rootDomain
const VIEWER_DOWNLOAD_URL = process.env.VIEWER_DOWNLOAD_URL || `https://downloads.${ROOT_DOMAIN}/viewer/latest/Hi5CentralViewerSetup.exe`
const VIEWER_WS_URL = process.env.VIEWER_WS_URL || `wss://rmm.${ROOT_DOMAIN}/viewer/ws`
const TURN_HOST = process.env.TURN_HOST || `turn.${ROOT_DOMAIN}`
const TURN_SHARED_SECRET_FILE = process.env.TURN_SHARED_SECRET_FILE || '/run/secrets/turn_shared_secret'
const SESSION_TTL_SECONDS = 15 * 60
const ACTIVE_RECONNECT_TTL_SECONDS = 8 * 60 * 60
const MAX_VIEWER_PAYLOAD_BYTES = 8 * 1024 * 1024
const VIEWER_RECONNECT_GRACE_MS = 90 * 1000
const AGENT_RESTART_GRACE_MS = 10 * 60 * 1000
const activeViewerSessions = new Map()

const VIEWER_MESSAGE_TYPES = new Set([
  'webrtc_answer', 'answer', 'ice_candidate',
  'switch_monitor', 'input_event',
  'service_shortcut', 'system_shortcut', 'shortcut', 'service_command',
  'backstage_start', 'backstage_stop', 'console_start',
  'chat_message', 'chat_close',
  'remote_file_list_request', 'remote_file_download_request', 'remote_file_upload_request',
  'remote_file_upload_start', 'remote_file_upload_chunk', 'remote_file_upload_complete_request', 'remote_file_upload_cancel',
  'remote_file_delete_request', 'remote_file_mkdir_request', 'remote_file_rename_request',
  'viewer_disconnected', 'viewer_closed', 'viewer_left', 'end_session', 'stop_webrtc',
])

function clean(value = '') { return String(value ?? '').trim() }
function sha256(value = '') { return createHash('sha256').update(String(value)).digest('hex') }
function randomSecret(prefix) { return `${prefix}_${randomBytes(32).toString('base64url')}` }
function isPortableUserAgent(value = '') {
  return /Android|iPhone|iPad|iPod|Mobile|Tablet|Kindle|Silk/i.test(String(value || ''))
}
function viewerClientForRequest(c, requestedClient = '') {
  const requested = clean(requestedClient).toLowerCase()
  // The authenticated portal performs the richer physical-device detection in
  // JavaScript, where platform/touch hardware signals are available even when
  // a browser intentionally presents a desktop User-Agent. Keep header-based
  // detection only as a backwards-compatible fallback for older portal builds.
  if (requested === 'browser' || requested === 'native') return requested
  const mobileHint = clean(c.req.header('sec-ch-ua-mobile')).toLowerCase()
  return mobileHint === '?1' || isPortableUserAgent(c.req.header('user-agent')) ? 'browser' : 'native'
}
function safeSend(ws, payload) {
  if (!ws || ws.readyState !== 1) return false
  try { ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload)); return true } catch { return false }
}
function turnSharedSecret() {
  try { return clean(readFileSync(TURN_SHARED_SECRET_FILE, 'utf8')) } catch { return '' }
}
function iceConfiguration(sessionId) {
  const viewer = [
    { urls: `stun:${TURN_HOST}:3478` },
    { urls: 'stun:stun.l.google.com:19302' },
  ]
  const agent = [`stun:${TURN_HOST}:3478`, 'stun:stun.l.google.com:19302']
  const sharedSecret = turnSharedSecret()
  if (!sharedSecret) return { viewer, agent }

  const expiry = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS + 300
  const username = `${expiry}:${clean(sessionId)}`
  const credential = createHmac('sha1', sharedSecret).update(username).digest('base64')
  viewer.push({
    urls: [`turn:${TURN_HOST}:3478?transport=udp`, `turn:${TURN_HOST}:3478?transport=tcp`],
    username,
    credential,
  })
  const user = encodeURIComponent(username)
  const pass = encodeURIComponent(credential)
  agent.push(`turn:${user}:${pass}@${TURN_HOST}:3478?transport=udp`)
  return { viewer, agent }
}

async function requireRemoteAccess(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!hasPermission(session.access, 'rmm.devices.remote')) {
    return { error: c.json({ error: 'You do not have permission to start unattended console remote sessions.' }, 403) }
  }
  return { session }
}

function canUseBackstage(session) {
  return hasPermission(session?.access, 'rmm.devices.backstage')
}

function ensureSessionModeAccess(c, session, mode) {
  if (mode === 'backstage' && !canUseBackstage(session)) {
    return c.json({ error: 'You do not have permission to start Background remote sessions.' }, 403)
  }
  return null
}

async function agentForRemoteSession(tenantId, agentDeviceId) {
  const result = await pool.query(
    `SELECT a.id,a.tenant_id,a.inventory_id,a.websocket_status,a.last_telemetry_at,
            i.reference,i.name,i.serial_number
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id
      WHERE a.id::text=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL AND i.active=true
      LIMIT 1`,
    [clean(agentDeviceId), tenantId],
  )
  return result.rows[0] || null
}

function browserLaunchUrl(slug, payload) {
  const ice = Buffer.from(JSON.stringify(payload.iceServers), 'utf8').toString('base64url')
  const fragment = new URLSearchParams({
    session_id: payload.sessionId,
    device_id: payload.deviceId,
    token: payload.token,
    wss_url: payload.wssUrl,
    mode: payload.mode,
    ice,
  })
  const base = tenantUrls(slug, { rmm: true }).rmmUrl || `https://${slug}-rmm.${ROOT_DOMAIN}`
  return `${base.replace(/\/$/, '')}/rmm-viewer/index.html#${fragment.toString()}`
}

function nativeLaunchUrl(payload) {
  const query = new URLSearchParams({
    session_id: payload.sessionId,
    device_id: payload.deviceId,
    token: payload.token,
    wss_url: payload.wssUrl,
    mode: payload.mode,
  })
  return `hi5central-viewer://connect?${query.toString()}`
}


async function supersedePriorTechnicianRemoteSessions({ tenantId, agentDeviceId, userId, mode, liveAgentWs }) {
  const prior = await pool.query(
    `SELECT id
       FROM rmm_remote_sessions
      WHERE tenant_id=$1
        AND agent_device_id::text=$2
        AND created_by_user_id=$3
        AND mode=$4
        AND status IN ('created','viewer_connected','active')
        AND ended_at IS NULL
        AND expires_at>now()
      ORDER BY created_at ASC`,
    [tenantId, String(agentDeviceId), userId, mode],
  )

  for (const row of prior.rows) {
    const priorSessionId = String(row.id)
    const live = activeViewerSessions.get(priorSessionId)
    if (live?.viewerWs) {
      safeSend(live.viewerWs, {
        type: 'session_terminated',
        session_id: priorSessionId,
        reason: 'superseded_by_new_session',
      })
      try { live.viewerWs.close(4000, 'Superseded by new session') } catch {}
    }

    if (live?.finalize) {
      live.finalize('superseded_by_new_session')
      continue
    }

    if (live?.cleanupTimer) clearTimeout(live.cleanupTimer)
    if (live?.agentRestartTimer) clearTimeout(live.agentRestartTimer)
    if (live?.agentWs && live?.relayFromAgent) {
      try { live.agentWs.off('message', live.relayFromAgent) } catch {}
    }
    if (live) live.finalized = true
    activeViewerSessions.delete(priorSessionId)
    safeSend(live?.agentWs || liveAgentWs, {
      type: 'end_session',
      session_id: priorSessionId,
      reason: 'superseded_by_new_session',
    })
    await pool.query(
      `UPDATE rmm_remote_sessions
          SET status='ended',
              ended_at=COALESCE(ended_at,now()),
              end_reason=COALESCE(end_reason,'superseded_by_new_session'),
              updated_at=now()
        WHERE id=$1 AND ended_at IS NULL`,
      [priorSessionId],
    ).catch(() => {})
  }
}

export function registerRmmRemoteRoutes(app) {
  app.post('/api/v1/rmm/remote-sessions', async (c) => {
    const auth = await requireRemoteAccess(c)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const agent = await agentForRemoteSession(auth.session.tenant_id, body.agentDeviceId)
    if (!agent) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const liveSocket = agentSocketForDevice(agent.id)
    if (!liveSocket || liveSocket.readyState !== 1) return c.json({ error: 'The Hi5Central Agent is currently offline.' }, 409)

    const mode = clean(body.mode).toLowerCase() === 'backstage' ? 'backstage' : 'console'
    const modeError = ensureSessionModeAccess(c, auth.session, mode)
    if (modeError) return modeError

    // A technician starting a new same-device/same-mode session is an explicit
    // replacement of their prior session. Tear the previous Agent/WebRTC
    // session down before issuing the new launch token so an abandoned browser
    // tab cannot occupy the capture/input pipeline during reconnect grace.
    await supersedePriorTechnicianRemoteSessions({
      tenantId: auth.session.tenant_id,
      agentDeviceId: agent.id,
      userId: auth.session.user_id,
      mode,
      liveAgentWs: liveSocket,
    })

    const viewerClient = viewerClientForRequest(c, body.viewerClient)
    const sessionId = randomUUID()
    const token = randomSecret('h5v')
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000)
    await pool.query(
      `INSERT INTO rmm_remote_sessions
         (id,tenant_id,agent_device_id,inventory_id,created_by_user_id,mode,viewer_client,viewer_token_hash,status,expires_at,last_activity_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'created',$9,now())`,
      [sessionId, auth.session.tenant_id, agent.id, agent.inventory_id, auth.session.user_id, mode, viewerClient, sha256(token), expiresAt],
    )

    const ice = iceConfiguration(sessionId)
    const connection = {
      sessionId,
      deviceId: String(agent.id),
      token,
      wssUrl: VIEWER_WS_URL,
      mode,
      iceServers: ice.viewer,
    }
    return c.json({
      session: { id: sessionId, mode, expiresAt: expiresAt.toISOString(), deviceName: agent.name, reference: agent.reference },
      connection,
      viewerClient,
      browserUrl: viewerClient === 'browser' ? browserLaunchUrl(auth.session.slug, connection) : null,
      nativeUrl: viewerClient === 'native' ? nativeLaunchUrl(connection) : null,
      viewerDownloadUrl: viewerClient === 'native' ? VIEWER_DOWNLOAD_URL : null,
    }, 201)
  })

  app.get('/api/v1/rmm/remote-sessions', async (c) => {
    const auth = await requireRemoteAccess(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT s.id,s.agent_device_id,s.mode,s.viewer_client,s.status,s.expires_at,s.viewer_connected_at,s.started_at,
              s.last_activity_at,s.created_at,i.name AS device_name,i.reference,
              COALESCE(NULLIF(u.name,''),u.email,'Hi5Central technician') AS technician
         FROM rmm_remote_sessions s
         LEFT JOIN rmm_device_inventory i ON i.id=s.inventory_id
         LEFT JOIN users u ON u.id=s.created_by_user_id
        WHERE s.tenant_id=$1
          AND ($2::boolean OR s.mode <> 'backstage')
          AND s.status IN ('created','viewer_connected','active')
          AND s.expires_at>now()
        ORDER BY COALESCE(s.started_at,s.viewer_connected_at,s.created_at) DESC`,
      [auth.session.tenant_id, canUseBackstage(auth.session)],
    )
    return c.json({ sessions: result.rows })
  })

  app.post('/api/v1/rmm/remote-sessions/:sessionId/terminate', async (c) => {
    const auth = await requireRemoteAccess(c)
    if (auth.error) return auth.error
    const sessionId = clean(c.req.param('sessionId'))
    const result = await pool.query(
      `SELECT id,agent_device_id,inventory_id,mode,status FROM rmm_remote_sessions WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
      [sessionId, auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Remote session not found.' }, 404)
    const remote = result.rows[0]
    const modeError = ensureSessionModeAccess(c, auth.session, remote.mode)
    if (modeError) return modeError
    if (!['created','viewer_connected','active'].includes(remote.status)) {
      return c.json({ session: { id: remote.id, status: remote.status }, alreadyEnded: true })
    }

    await pool.query(
      `UPDATE rmm_remote_sessions
          SET status='ended',ended_at=COALESCE(ended_at,now()),end_reason='terminated_by_technician',last_activity_at=now(),updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [sessionId, auth.session.tenant_id],
    )

    const live = activeViewerSessions.get(sessionId)
    const agentWs = live?.agentWs || agentSocketForDevice(remote.agent_device_id)
    safeSend(agentWs, { type: 'end_session', session_id: sessionId, reason: 'terminated_by_technician' })
    if (live?.viewerWs) {
      safeSend(live.viewerWs, { type: 'session_terminated', session_id: sessionId, reason: 'terminated_by_technician' })
      try { live.viewerWs.close(4000, 'Session terminated') } catch {}
    }
    activeViewerSessions.delete(sessionId)
    recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: remote.agent_device_id,
      inventoryId: remote.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel: clean(auth.session.name || auth.session.email) || 'Technician',
      eventType: remote.mode === 'backstage' ? 'remote.background_ended' : 'remote.console_ended',
      category: 'remote',
      summary: (clean(auth.session.name || auth.session.email) || 'Technician') + ' ended a ' + (remote.mode === 'backstage' ? 'Background' : 'remote') + ' session',
      detail: 'Session terminated by technician.',
      outcome: 'success',
      remoteSessionId: sessionId,
      metadata: { mode: remote.mode, endReason: 'terminated_by_technician' },
    }).catch(() => {})
    return c.json({ session: { id: sessionId, status: 'ended', endReason: 'terminated_by_technician' } })
  })

  app.get('/api/v1/rmm/remote-sessions/:sessionId', async (c) => {
    const auth = await requireRemoteAccess(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id,agent_device_id,mode,status,expires_at,viewer_connected_at,started_at,ended_at,last_activity_at,end_reason,created_at
         FROM rmm_remote_sessions WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
      [clean(c.req.param('sessionId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Remote session not found.' }, 404)
    const remote = result.rows[0]
    const modeError = ensureSessionModeAccess(c, auth.session, remote.mode)
    if (modeError) return modeError
    return c.json({ session: remote })
  })
}

async function authenticateViewer(sessionId, deviceId, token) {
  if (!clean(sessionId) || !clean(deviceId) || !clean(token)) return null
  const result = await pool.query(
    `SELECT s.id,s.tenant_id,s.agent_device_id,s.inventory_id,s.created_by_user_id,s.mode,s.viewer_client,s.status,s.expires_at,
            u.name AS technician_name,u.email AS technician_email
       FROM rmm_remote_sessions s
       LEFT JOIN users u ON u.id=s.created_by_user_id
      WHERE s.id::text=$1 AND s.agent_device_id::text=$2 AND s.viewer_token_hash=$3
        AND s.status IN ('created','viewer_connected','active') AND s.expires_at>now()
      LIMIT 1`,
    [clean(sessionId), clean(deviceId), sha256(token)],
  )
  return result.rows[0] || null
}

export function attachRmmViewerWebSocket(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_VIEWER_PAYLOAD_BYTES })

  server.on('upgrade', async (request, socket, head) => {
    let url
    try { url = new URL(request.url || '/', 'http://localhost') } catch { return }
    if (url.pathname !== '/viewer/ws') return
    const viewerSession = await authenticateViewer(
      url.searchParams.get('session_id'),
      url.searchParams.get('device_id'),
      url.searchParams.get('token'),
    ).catch(() => null)
    if (viewerSession?.viewer_client === 'browser') {
      const requestedClient = clean(url.searchParams.get('client')).toLowerCase()
      // The session itself already authorises the browser Viewer. Do not
      // re-classify the physical device from the WebSocket User-Agent because
      // desktop-mode/mobile wrapper browsers may intentionally spoof it.
      if (requestedClient !== 'browser') {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
        socket.destroy()
        return
      }
    } else if (viewerSession?.viewer_client === 'native' && clean(url.searchParams.get('client')).toLowerCase() === 'browser') {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    if (!viewerSession) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.hi5RemoteSession = viewerSession
      wss.emit('connection', ws, request)
    })
  })

  wss.on('connection', async (viewerWs) => {
    const remote = viewerWs.hi5RemoteSession
    const sessionId = String(remote.id)
    let agentWs = agentSocketForDevice(remote.agent_device_id)
    if (agentWs?.readyState !== 1) agentWs = null

    const ice = iceConfiguration(sessionId)
    await pool.query(
      `UPDATE rmm_remote_sessions
          SET status=CASE WHEN started_at IS NULL THEN 'viewer_connected' ELSE 'active' END,
              viewer_connected_at=COALESCE(viewer_connected_at,now()),last_activity_at=now(),
              expires_at=GREATEST(expires_at, now() + ($2::text || ' seconds')::interval),updated_at=now()
        WHERE id=$1`,
      [remote.id, ACTIVE_RECONNECT_TTL_SECONDS],
    ).catch(() => {})
    const previousActive = activeViewerSessions.get(sessionId)
    const viewerInterruptedAt = previousActive?.viewerDisconnectedAt || 0
    if (previousActive?.cleanupTimer) clearTimeout(previousActive.cleanupTimer)
    if (previousActive?.agentRestartTimer) clearTimeout(previousActive.agentRestartTimer)
    if (previousActive?.agentWs && previousActive?.relayFromAgent) {
      try { previousActive.agentWs.off('message', previousActive.relayFromAgent) } catch {}
    }
    if (previousActive) { previousActive.finalized = true; previousActive.agentWs = null }
    if (previousActive?.viewerWs && previousActive.viewerWs !== viewerWs) {
      try { previousActive.viewerWs.close(4001, 'Viewer superseded') } catch {}
    }
    const active = {
      viewerWs, agentWs: null, tenantId: remote.tenant_id, agentDeviceId: String(remote.agent_device_id),
      cleanupTimer: null, agentRestartTimer: null, relayFromAgent: null,
      mode: remote.mode, technicianName: clean(remote.technician_name || remote.technician_email) || 'Hi5Central technician',
      iceAgent: ice.agent, finalized: false, onAgentConnected: null, onAgentDisconnected: null, finalize: null,
      agentDisconnectedAt: 0,
    }
    activeViewerSessions.set(sessionId, active)
    if (viewerInterruptedAt) {
      const interruptionSeconds = Math.max(0, Math.round((Date.now() - viewerInterruptedAt) / 1000))
      recordRmmActivity({
        tenantId: remote.tenant_id, agentDeviceId: remote.agent_device_id, inventoryId: remote.inventory_id,
        actorUserId: remote.created_by_user_id, actorType: 'system', actorLabel: 'SYSTEM',
        eventType: 'remote.viewer_transport_recovered', category: 'remote',
        summary: 'SYSTEM: remote Viewer connection recovered',
        detail: 'The same remote session resumed after ' + interruptionSeconds + ' seconds.',
        outcome: 'success', severity: 'info', remoteSessionId: remote.id,
        metadata: { mode: remote.mode, viewerClient: remote.viewer_client, interruptionSeconds, reason: 'viewer_reconnected' },
      }).catch(() => {})
    }

    const relayFromAgent = (buffer) => {
      const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer)
      let payload
      try { payload = JSON.parse(text) } catch { return }
      const payloadSessionId = clean(payload?.session_id || payload?.sessionId)
      if (payloadSessionId !== sessionId) return
      safeSend(viewerWs, text)
      if (payload?.type === 'webrtc_offer') {
        pool.query(
          `UPDATE rmm_remote_sessions
              SET status='active',started_at=now(),last_activity_at=now(),updated_at=now()
            WHERE id=$1 AND started_at IS NULL
            RETURNING started_at`,
          [remote.id],
        ).then(async (started) => {
          if (!started.rowCount) {
            await pool.query(
              `UPDATE rmm_remote_sessions SET status='active',last_activity_at=now(),updated_at=now() WHERE id=$1`,
              [remote.id],
            )
            return
          }
          const active = activeViewerSessions.get(sessionId)
          if (active) active.activityStarted = true
          const technician = clean(remote.technician_name || remote.technician_email) || 'Technician'
          return recordRmmActivity({
            tenantId: remote.tenant_id,
            agentDeviceId: remote.agent_device_id,
            inventoryId: remote.inventory_id,
            actorUserId: remote.created_by_user_id,
            actorType: 'technician',
            actorLabel: technician,
            eventType: remote.mode === 'backstage' ? 'remote.background_started' : 'remote.console_started',
            category: 'remote',
            summary: technician + ' started a ' + (remote.mode === 'backstage' ? 'Background' : 'remote') + ' session',
            detail: 'Remote session connected successfully.',
            outcome: 'success',
            remoteSessionId: remote.id,
            metadata: { mode: remote.mode, viewerClient: remote.viewer_client },
          })
        }).catch(() => {})
      } else {
        pool.query(`UPDATE rmm_remote_sessions SET last_activity_at=now(),expires_at=GREATEST(expires_at,now() + interval '8 hours'),updated_at=now() WHERE id=$1`, [remote.id]).catch(() => {})
      }
    }
    active.relayFromAgent = relayFromAgent

    const detachAgentSocket = () => {
      if (active.agentWs && active.relayFromAgent) {
        try { active.agentWs.off('message', active.relayFromAgent) } catch {}
      }
      active.agentWs = null
    }

    const bindAgentSocket = (nextAgentWs, { restarted = false } = {}) => {
      if (!nextAgentWs || nextAgentWs.readyState !== 1 || active.finalized) return false
      detachAgentSocket()
      if (active.agentRestartTimer) { clearTimeout(active.agentRestartTimer); active.agentRestartTimer = null }
      active.agentWs = nextAgentWs
      nextAgentWs.on('message', relayFromAgent)
      if (restarted) safeSend(active.viewerWs, { type: 'agent_reconnected', session_id: sessionId })
      const sent = safeSend(nextAgentWs, {
        type: 'start_webrtc', session_id: sessionId, mode: remote.mode,
        technician_name: active.technicianName, iceServers: active.iceAgent,
      })
      if (sent) safeSend(active.viewerWs, { type: 'start_webrtc_sent', session_id: sessionId, restarted })
      return sent
    }

    let explicitViewerClose = false
    viewerWs.on('message', (buffer) => {
      const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer)
      let payload
      try { payload = JSON.parse(text) } catch { return }
      const type = clean(payload?.type)
      if (!VIEWER_MESSAGE_TYPES.has(type)) return
      if (['viewer_disconnected','viewer_closed','viewer_left','end_session','stop_webrtc'].includes(type)) explicitViewerClose = true
      if (remote.mode !== 'backstage' && (type === 'backstage_start' || type === 'backstage_stop')) {
        safeSend(viewerWs, { type: 'viewer_error', session_id: sessionId, error: 'Background mode is not authorised for this remote session.' })
        return
      }
      if (remote.mode === 'backstage' && type === 'console_start') {
        safeSend(viewerWs, { type: 'viewer_error', session_id: sessionId, error: 'Console mode is not authorised for this Background remote session.' })
        return
      }
      payload.session_id = sessionId
      delete payload.sessionId
      if (!safeSend(active.agentWs, payload)) {
        safeSend(viewerWs, { type: 'agent_reconnecting', session_id: sessionId, grace_ms: AGENT_RESTART_GRACE_MS })
      }
      pool.query(`UPDATE rmm_remote_sessions SET last_activity_at=now(),expires_at=GREATEST(expires_at,now() + interval '8 hours'),updated_at=now() WHERE id=$1`, [remote.id]).catch(() => {})
    })

    let disconnectHandled = false
    const finalizeCleanup = (reason = 'viewer_disconnected') => {
      const currentActive = activeViewerSessions.get(sessionId)
      if (currentActive?.viewerWs && currentActive.viewerWs !== viewerWs) return
      const boundAgentWs = currentActive?.agentWs || agentWs
      if (currentActive?.cleanupTimer) clearTimeout(currentActive.cleanupTimer)
      if (currentActive) {
        currentActive.finalized = true
        if (currentActive.agentRestartTimer) clearTimeout(currentActive.agentRestartTimer)
      }
      safeSend(boundAgentWs, { type: 'viewer_disconnected', session_id: sessionId })
      detachAgentSocket()
      activeViewerSessions.delete(sessionId)
      pool.query(
        `UPDATE rmm_remote_sessions
            SET status=CASE WHEN status IN ('ended','expired') THEN status ELSE 'ended' END,
                ended_at=COALESCE(ended_at,now()),end_reason=COALESCE(end_reason,$2),updated_at=now()
          WHERE id=$1 AND ended_at IS NULL
          RETURNING started_at,ended_at`,
        [remote.id, reason],
      ).then((updated) => {
        if (!updated.rowCount) return
        const technician = clean(remote.technician_name || remote.technician_email) || 'Technician'
        const startedAt = updated.rows[0]?.started_at ? new Date(updated.rows[0].started_at).getTime() : 0
        const endedAt = updated.rows[0]?.ended_at ? new Date(updated.rows[0].ended_at).getTime() : Date.now()
        const durationSeconds = startedAt ? Math.max(0, Math.round((endedAt - startedAt) / 1000)) : null
        return recordRmmActivity({
          tenantId: remote.tenant_id, agentDeviceId: remote.agent_device_id, inventoryId: remote.inventory_id,
          actorUserId: remote.created_by_user_id, actorType: 'technician', actorLabel: technician,
          eventType: remote.mode === 'backstage' ? 'remote.background_ended' : 'remote.console_ended', category: 'remote',
          summary: technician + ' ended a ' + (remote.mode === 'backstage' ? 'Background' : 'remote') + ' session',
          detail: durationSeconds == null ? 'Remote session ended.' : 'Session duration ' + durationSeconds + ' seconds.',
          outcome: reason === 'viewer_error' ? 'failed' : 'success', severity: reason === 'viewer_error' ? 'warning' : 'info',
          remoteSessionId: remote.id, metadata: { mode: remote.mode, viewerClient: remote.viewer_client, reason, durationSeconds },
        })
      }).catch(() => {})
    }

    const cleanup = (reason = 'viewer_disconnected') => {
      if (disconnectHandled) return
      disconnectHandled = true
      detachAgentSocket()
      const latestActive = activeViewerSessions.get(sessionId)
      if (latestActive?.viewerWs !== viewerWs) return
      if (explicitViewerClose) { finalizeCleanup(reason); return }
      const cleanupTimer = setTimeout(() => {
        const latest = activeViewerSessions.get(sessionId)
        if (latest?.cleanupTimer !== cleanupTimer || latest?.viewerWs) return
        finalizeCleanup(reason)
      }, VIEWER_RECONNECT_GRACE_MS)
      active.viewerWs = null
      active.viewerDisconnectedAt = Date.now()
      active.cleanupTimer = cleanupTimer
      recordRmmActivity({
        tenantId: remote.tenant_id, agentDeviceId: remote.agent_device_id, inventoryId: remote.inventory_id,
        actorUserId: remote.created_by_user_id, actorType: 'system', actorLabel: 'SYSTEM',
        eventType: 'remote.viewer_transport_interrupted', category: 'remote',
        summary: 'SYSTEM: remote Viewer connection interrupted',
        detail: 'The session remains authorised while the Viewer reconnects.',
        outcome: 'pending', severity: 'warning', remoteSessionId: remote.id,
        metadata: { mode: remote.mode, viewerClient: remote.viewer_client, reason, graceMs: VIEWER_RECONNECT_GRACE_MS },
      }).catch(() => {})
      activeViewerSessions.set(sessionId, active)
      pool.query(`UPDATE rmm_remote_sessions SET last_activity_at=now(),expires_at=GREATEST(expires_at,now() + interval '8 hours'),updated_at=now() WHERE id=$1`, [remote.id]).catch(() => {})
    }
    viewerWs.once('close', () => cleanup('viewer_disconnected'))
    viewerWs.once('error', () => cleanup('viewer_error'))

    active.finalize = finalizeCleanup
    active.onAgentConnected = (nextWs) => {
      if (active.finalized || !active.viewerWs || active.viewerWs.readyState !== 1) return
      const disconnectedAt = active.agentDisconnectedAt
      active.agentDisconnectedAt = 0
      const rebound = bindAgentSocket(nextWs, { restarted: true })
      if (rebound && disconnectedAt) {
        const interruptedSeconds = Math.max(0, Math.round((Date.now() - disconnectedAt) / 1000))
        recordRmmActivity({
          tenantId: remote.tenant_id, agentDeviceId: remote.agent_device_id, inventoryId: remote.inventory_id,
          actorUserId: remote.created_by_user_id, actorType: 'system', actorLabel: 'SYSTEM',
          eventType: 'remote.transport_recovered', category: 'remote',
          summary: 'SYSTEM: remote session recovered after endpoint reconnect',
          detail: 'The existing remote session resumed after ' + interruptedSeconds + ' seconds without creating a new technician session.',
          outcome: 'success', severity: 'info', remoteSessionId: remote.id,
          metadata: { mode: remote.mode, viewerClient: remote.viewer_client, interruptionSeconds: interruptedSeconds, reason: 'agent_reconnected' },
        }).catch(() => {})
      }
    }
    active.onAgentDisconnected = (closedWs) => {
      if (active.finalized || active.agentWs !== closedWs) return
      detachAgentSocket()
      if (!active.agentDisconnectedAt) {
        active.agentDisconnectedAt = Date.now()
        recordRmmActivity({
          tenantId: remote.tenant_id, agentDeviceId: remote.agent_device_id, inventoryId: remote.inventory_id,
          actorUserId: remote.created_by_user_id, actorType: 'system', actorLabel: 'SYSTEM',
          eventType: 'remote.transport_interrupted', category: 'remote',
          summary: 'SYSTEM: remote session interrupted while endpoint reconnects',
          detail: 'The Viewer remains authorised and will automatically resume if the same Agent returns within the restart grace period.',
          outcome: 'pending', severity: 'warning', remoteSessionId: remote.id,
          metadata: { mode: remote.mode, viewerClient: remote.viewer_client, reason: 'agent_disconnected', graceMs: AGENT_RESTART_GRACE_MS },
        }).catch(() => {})
      }
      safeSend(active.viewerWs, { type: 'agent_reconnecting', session_id: sessionId, grace_ms: AGENT_RESTART_GRACE_MS })
      if (active.agentRestartTimer) clearTimeout(active.agentRestartTimer)
      active.agentRestartTimer = setTimeout(() => {
        if (active.finalized || active.agentWs?.readyState === 1) return
        safeSend(active.viewerWs, { type: 'viewer_error', session_id: sessionId, error: 'Endpoint did not return after restart.' })
        finalizeCleanup('agent_restart_timeout')
      }, AGENT_RESTART_GRACE_MS)
      pool.query(`UPDATE rmm_remote_sessions SET last_activity_at=now(),expires_at=GREATEST(expires_at,now() + interval '8 hours'),updated_at=now() WHERE id=$1`, [remote.id]).catch(() => {})
    }

    safeSend(viewerWs, { type: 'viewer_connected', session_id: sessionId })
    safeSend(viewerWs, { type: 'session_config', session_id: sessionId, mode: remote.mode, ice_servers: ice.viewer })
    if (agentWs) bindAgentSocket(agentWs)
    else {
      safeSend(viewerWs, { type: 'agent_reconnecting', session_id: sessionId, grace_ms: AGENT_RESTART_GRACE_MS })
      active.agentRestartTimer = setTimeout(() => {
        if (active.finalized || active.agentWs?.readyState === 1) return
        safeSend(active.viewerWs, { type: 'viewer_error', session_id: sessionId, error: 'Endpoint did not return after restart.' })
        finalizeCleanup('agent_restart_timeout')
      }, AGENT_RESTART_GRACE_MS)
    }
  })

  const unsubscribeAgentConnections = subscribeAgentConnections(({ type, agent, ws }) => {
    const deviceId = String(agent?.id || '')
    if (!deviceId) return
    for (const active of activeViewerSessions.values()) {
      if (active.agentDeviceId !== deviceId || active.finalized) continue
      if (type === 'connected') active.onAgentConnected?.(ws)
      else if (type === 'disconnected') active.onAgentDisconnected?.(ws)
    }
  })
  wss.on('close', () => unsubscribeAgentConnections())

  return wss
}
