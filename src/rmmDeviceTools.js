import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { WebSocketServer } from 'ws'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { agentSocketForDevice, sendAgentMessage, subscribeAgentMessages } from './rmmAgent.js'
import { recordRmmActivity } from './rmmActivity.js'
import { resolveSession } from './session.js'

const TOOL_SESSION_TTL_MS = 10 * 60 * 1000
const toolSessions = new Map()

function clean(value = '') { return String(value ?? '').trim() }
function sha256(value = '') { return createHash('sha256').update(String(value)).digest('hex') }
function boundedInteger(value, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return null
  return Math.min(max, Math.max(min, Math.trunc(number)))
}
function versionAtLeast(value, minimum) {
  const parse = (input) => String(input || '').match(/\d+/g)?.slice(0, 3).map(Number) || []
  const actual = parse(value)
  const required = parse(minimum)
  for (let index = 0; index < 3; index += 1) {
    const left = actual[index] || 0
    const right = required[index] || 0
    if (left !== right) return left > right
  }
  return true
}

async function requireDeviceControl(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!hasPermission(session.access, 'rmm.devices.control') && !hasPermission(session.access, 'rmm.automation.run')) {
    return { error: c.json({ error: 'You do not have permission to control RMM devices.' }, 403) }
  }
  return { session }
}


async function requireDeviceView(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!hasPermission(session.access, 'rmm.devices.view') && !hasPermission(session.access, 'rmm.devices.control')) {
    return { error: c.json({ error: 'You do not have permission to view RMM device jobs.' }, 403) }
  }
  return { session }
}

function payloadForAction(type, body = {}) {
  const payload = body?.payload && typeof body.payload === 'object' && !Array.isArray(body.payload) ? body.payload : {}
  if (['processes.list', 'services.list', 'inventory.scan'].includes(type)) return {}
  if (['process.kill', 'process.restart'].includes(type)) {
    const pid = boundedInteger(payload.pid ?? payload.processId, 5, 2147483647)
    if (!pid) throw new Error('A valid process ID is required.')
    return { pid }
  }
  if (['services.start', 'services.stop', 'services.restart'].includes(type)) {
    const serviceName = clean(payload.serviceName || payload.service_name).slice(0, 256)
    if (!serviceName) throw new Error('A service name is required.')
    return { serviceName }
  }
  if (type === 'services.set_start_type') {
    const serviceName = clean(payload.serviceName || payload.service_name).slice(0, 256)
    const startType = clean(payload.startType || payload.start_type).slice(0, 64)
    if (!serviceName || !['Automatic', 'AutomaticDelayed', 'Manual', 'Disabled'].includes(startType)) {
      throw new Error('A valid service and startup type are required.')
    }
    return { serviceName, startType }
  }
  if (type === 'files.list') {
    const path = clean(payload.path || 'C:\\').slice(0, 2048) || 'C:\\'
    return { path }
  }
  if (type === 'registry.list') {
    const path = clean(payload.path).slice(0, 2048)
    if (!/^HK(?:LM|CU|CR|U|CC):\\/i.test(path)) throw new Error('Select a registry hive before reading registry data.')
    return { path }
  }
  if (type === 'events.list') {
    const logName = clean(payload.logName || payload.log_name || 'System')
    const level = clean(payload.level || 'All')
    const maxEvents = boundedInteger(payload.maxEvents ?? payload.max_events, 25, 500) || 200
    if (!['System', 'Application', 'Security'].includes(logName)) throw new Error('Unsupported event log.')
    if (!['All', 'Critical', 'Error', 'Warning', 'Information', 'Verbose'].includes(level)) throw new Error('Unsupported event level.')
    return { logName, level, maxEvents }
  }
  if (['registry.create_key', 'registry.delete_key', 'registry.set_value', 'registry.delete_value'].includes(type)) {
    const path = clean(payload.path).slice(0, 2048)
    const name = clean(payload.name).slice(0, 512)
    const value = String(payload.value ?? '').slice(0, 65536)
    const kind = clean(payload.kind || 'String').slice(0, 32)
    if (!/^HK(?:LM|CU|CR|U|CC):\\/i.test(path)) throw new Error('A valid registry path is required.')
    if (type !== 'registry.delete_key' && !name) throw new Error('A registry key or value name is required.')
    if (type === 'registry.set_value' && !['String', 'ExpandString', 'MultiString', 'DWord', 'QWord', 'Binary'].includes(kind)) {
      throw new Error('Unsupported registry value type.')
    }
    return { path, name, value, kind }
  }
  if (type === 'software.uninstall') {
    const name = clean(payload.name).slice(0, 512)
    const registryKey = clean(payload.registry_key || payload.registryKey).slice(0, 512)
    const scope = clean(payload.scope).slice(0, 192)
    const userProfile = clean(payload.user_profile || payload.userProfile).slice(0, 1024)
    if (!name && !registryKey) throw new Error('Software name or registry identity is required.')
    const validScope = !scope || ['machine64', 'machine32', 'user'].includes(scope) || /^user:S-1-(?:5-21|12-1)-[0-9-]+$/i.test(scope)
    if (!validScope) throw new Error('Unsupported software scope.')
    return { name, registry_key: registryKey, scope, user_profile: userProfile }
  }
  throw new Error('Unsupported device action.')
}

async function managedAgent(tenantId, agentDeviceId) {
  const result = await pool.query(
    "SELECT a.id,a.agent_version,i.id AS inventory_id,i.name,i.reference " +
    "FROM rmm_agent_devices a " +
    "JOIN rmm_device_inventory i ON i.id=a.inventory_id " +
    "WHERE a.id::text=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL AND i.active=true LIMIT 1",
    [clean(agentDeviceId), tenantId],
  )
  return result.rows[0] || null
}

function requestAgentProbe(deviceId, requestType, responseType, timeoutMs = 4000) {
  const requestId = randomUUID()
  return new Promise((resolve, reject) => {
    let settled = false
    let timer = null
    const finish = (error, payload) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      unsubscribe()
      if (error) reject(error)
      else resolve(payload)
    }
    const unsubscribe = subscribeAgentMessages(deviceId, (payload) => {
      if (clean(payload?.type) !== responseType) return
      if (clean(payload?.request_id || payload?.requestId) !== requestId) return
      finish(null, payload)
    })
    timer = setTimeout(() => finish(new Error('The device did not return live network statistics in time.')), timeoutMs)
    if (!sendAgentMessage(deviceId, { type: requestType, request_id: requestId })) {
      finish(new Error('The device went offline before live network statistics could be requested.'))
    }
  })
}

export function registerRmmDeviceToolRoutes(app) {
  app.get('/api/v1/rmm/devices/:agentDeviceId/network-stats', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    if (!versionAtLeast(device.agent_version, '0.1.149')) return c.json({ error: 'Agent 0.1.149 or newer is required for live network throughput.', upgradeRequired: true }, 426)
    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) return c.json({ error: 'This device is offline.', offline: true }, 409)
    try {
      const payload = await requestAgentProbe(device.id, 'network_stats_request', 'network_stats_response', 4500)
      return c.json({
        collectedAt: payload.collected_at || payload.collectedAt || null,
        unixMs: payload.unix_ms || payload.unixMs || Date.now(),
        adapters: Array.isArray(payload.adapters) ? payload.adapters : [],
      })
    } catch (error) {
      return c.json({ error: error?.message || 'Unable to read live network statistics.' }, 504)
    }
  })
  app.post('/api/v1/rmm/devices/:agentDeviceId/bitlocker-recovery/escrow', async (c) => {
    const auth = await requireDeviceControl(c)
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.security.recovery_keys.read')) {
      return c.json({ error: 'You do not have permission to manage BitLocker recovery keys.' }, 403)
    }
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    if (!versionAtLeast(device.agent_version, '0.1.171')) {
      return c.json({ error: 'Agent 0.1.171 or newer is required for BitLocker recovery-key escrow.', upgradeRequired: true }, 426)
    }
    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) return c.json({ error: 'This device is offline. Recovery-key escrow requires a live Agent connection.', offline: true }, 409)
    if (!sendAgentMessage(device.id, { type: 'bitlocker_recovery_escrow_request' })) {
      return c.json({ error: 'The device went offline before recovery-key escrow could be requested.', offline: true }, 409)
    }
    const label = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    await recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: device.id,
      inventoryId: device.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel: label,
      eventType: 'bitlocker.recovery_key.escrow_requested',
      category: 'security',
      summary: label + ' requested BitLocker recovery-key escrow',
      detail: 'The Agent was asked to escrow any RecoveryPassword protectors without adding them to normal inventory.',
      outcome: 'requested',
      severity: 'info',
      metadata: {},
    }).catch(() => {})
    return c.json({ success: true, requested: true }, 202)
  })

  app.post('/api/v1/rmm/devices/:agentDeviceId/power', async (c) => {
    const auth = await requireDeviceControl(c)
    if (auth.error) return auth.error
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) return c.json({ error: 'This device is offline. No power action was queued.', offline: true }, 409)

    const body = await c.req.json().catch(() => ({}))
    const action = clean(body.action || 'restart').toLowerCase()
    if (!['restart','shutdown'].includes(action)) return c.json({ error: 'Power action must be restart or shutdown.' }, 400)
    const delaySeconds = boundedInteger(body.delaySeconds ?? body.delay_seconds, 0, 300) ?? 15
    const switchValue = action === 'restart' ? '/r' : '/s'
    const comment = action === 'restart' ? 'Hi5Central remote restart' : 'Hi5Central remote shutdown'
    const command = 'shutdown.exe ' + switchValue + ' /t ' + delaySeconds + ' /d p:4:1 /c "' + comment + '"'
    const label = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    const payload = { command, timeout_seconds: 30 }
    const requestMetadata = {
      source: 'device_power_action',
      power_action: action,
      delay_seconds: delaySeconds,
      device_name: device.name,
      device_reference: device.reference,
    }
    const inserted = await pool.query(
      "INSERT INTO rmm_agent_jobs " +
      "(tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata) " +
      "VALUES ($1,$2,'custom.command',$3::jsonb,$4,'technician',$5,$6::jsonb) " +
      "RETURNING id,job_type,status,created_at",
      [auth.session.tenant_id, device.id, JSON.stringify(payload), auth.session.user_id, label, JSON.stringify(requestMetadata)],
    )
    const job = inserted.rows[0]
    const claimed = await pool.query(
      "UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status='queued' RETURNING status,claimed_at,updated_at",
      [job.id, auth.session.tenant_id],
    )
    if (!claimed.rowCount) return c.json({ error: 'Unable to claim the power action.' }, 409)
    Object.assign(job, claimed.rows[0])
    const pushed = sendAgentMessage(device.id, {
      type: 'job_execute',
      job: { id: job.id, job_type: 'custom.command', payload, created_at: job.created_at },
    })
    if (!pushed) {
      await pool.query(
        "UPDATE rmm_agent_jobs SET status='cancelled',claimed_at=NULL,completed_at=now(),error_message=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2",
        [job.id, auth.session.tenant_id, 'Device went offline before the power action could be dispatched.'],
      )
      return c.json({ error: 'The device went offline before the power action could start.', offline: true }, 409)
    }
    await recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: device.id,
      inventoryId: device.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel: label,
      eventType: 'device.' + action + '.requested',
      category: 'device',
      summary: label + ' requested device ' + action,
      detail: delaySeconds ? delaySeconds + ' second countdown before ' + action : 'Immediate ' + action,
      outcome: 'requested',
      severity: 'info',
      jobId: job.id,
      metadata: { action, delaySeconds },
    }).catch(() => {})
    return c.json({ success: true, action, delaySeconds, job }, 202)
  })

  app.post('/api/v1/rmm/devices/:agentDeviceId/actions', async (c) => {
    const auth = await requireDeviceControl(c)
    if (auth.error) return auth.error
    const agentDeviceId = clean(c.req.param('agentDeviceId'))
    const body = await c.req.json().catch(() => ({}))
    const type = clean(body.type || body.action)
    let payload
    try { payload = payloadForAction(type, body) } catch (error) {
      return c.json({ error: error.message || 'Invalid device action.' }, 400)
    }

    const device = await managedAgent(auth.session.tenant_id, agentDeviceId)
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const liveSocket = agentSocketForDevice(device.id)
    if (!liveSocket || liveSocket.readyState !== 1) {
      return c.json({ error: 'This device is offline. No job was queued.', offline: true }, 409)
    }

    const cacheSeconds = {
      'processes.list': 8,
      'services.list': 15,
      'registry.list': 6,
      'events.list': 8,
    }[type] || 0
    if (cacheSeconds > 0) {
      const cached = await pool.query(
        "SELECT id,job_type,status,result,error_message,created_at,claimed_at,completed_at,updated_at " +
        "FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type=$3 AND payload=$4::jsonb " +
        "AND status='completed' AND completed_at > now()-($5::int * interval '1 second') " +
        "ORDER BY completed_at DESC LIMIT 1",
        [auth.session.tenant_id, device.id, type, JSON.stringify(payload), cacheSeconds],
      )
      if (cached.rowCount) return c.json({ job: cached.rows[0], cached: true })
    }

    const label = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    const inserted = await pool.query(
      "INSERT INTO rmm_agent_jobs " +
      "(tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata) " +
      "VALUES ($1,$2,$3,$4::jsonb,$5,'technician',$6,$7::jsonb) " +
      "RETURNING id,job_type,status,created_at",
      [
        auth.session.tenant_id,
        device.id,
        type,
        JSON.stringify(payload),
        auth.session.user_id,
        label,
        JSON.stringify({ source: 'device_details', device_name: device.name, device_reference: device.reference }),
      ],
    )

    const job = inserted.rows[0]
    if (versionAtLeast(device.agent_version, '0.1.63')) {
      const claimed = await pool.query(
        "UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() " +
        "WHERE id=$1 AND tenant_id=$2 AND status='queued' RETURNING status,claimed_at,updated_at",
        [job.id, auth.session.tenant_id],
      )
      if (claimed.rowCount) {
        job.status = 'claimed'
        job.claimed_at = claimed.rows[0].claimed_at
        job.updated_at = claimed.rows[0].updated_at
        const pushed = sendAgentMessage(device.id, {
          type: 'job_execute',
          job: { id: job.id, job_type: type, payload, created_at: job.created_at },
        })
        if (pushed) return c.json({ job, dispatched: 'websocket' }, 202)

        await pool.query(
          "UPDATE rmm_agent_jobs SET status='cancelled',claimed_at=NULL,completed_at=now(),error_message=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status='claimed'",
          [job.id, auth.session.tenant_id, 'Device went offline before the action could be dispatched. The job was not retained for later execution.'],
        )
        recordRmmActivity({
          tenantId: auth.session.tenant_id,
          agentDeviceId: device.id,
          inventoryId: device.inventory_id,
          actorUserId: auth.session.user_id,
          actorType: 'technician',
          actorLabel: label,
          eventType: 'job.cancelled_offline',
          category: 'job',
          summary: label + ' action was cancelled because the device went offline',
          detail: type,
          outcome: 'cancelled',
          severity: 'warning',
          jobId: job.id,
          metadata: { jobType: type, reason: 'device_offline_before_dispatch' },
        }).catch(() => {})
        return c.json({ error: 'The device went offline before the action could start. No job was queued for later.', offline: true, job: { ...job, status: 'cancelled' } }, 409)
      }
    }

    return c.json({ job, dispatched: 'poll' }, 202)
  })

  app.get('/api/v1/rmm/device-actions/:jobId', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      "SELECT j.id,j.agent_device_id,j.job_type,j.payload,j.status,j.result,j.error_message,j.created_at,j.claimed_at,j.completed_at,j.updated_at," +
      "j.queued_by_user_id,j.initiated_by,j.initiated_by_label,j.correlation_id,j.request_metadata," +
      "i.name AS device_name,i.reference AS device_reference " +
      "FROM rmm_agent_jobs j " +
      "JOIN rmm_agent_devices a ON a.id=j.agent_device_id " +
      "JOIN rmm_device_inventory i ON i.id=a.inventory_id " +
      "WHERE j.id=$1 AND j.tenant_id=$2 LIMIT 1",
      [clean(c.req.param('jobId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Device action not found.' }, 404)
    return c.json({ job: result.rows[0] })
  })

  app.get('/api/v1/rmm/devices/:agentDeviceId/actions', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    const limit = boundedInteger(c.req.query('limit'), 1, 100) || 25
    const result = await pool.query(
      "SELECT j.id,j.agent_device_id,j.job_type,j.payload,j.status,j.result,j.error_message,j.created_at,j.claimed_at,j.completed_at,j.updated_at," +
      "j.queued_by_user_id,j.initiated_by,j.initiated_by_label,j.correlation_id,j.request_metadata " +
      "FROM rmm_agent_jobs j WHERE j.tenant_id=$1 AND j.agent_device_id::text=$2 " +
      "ORDER BY j.created_at DESC LIMIT $3",
      [auth.session.tenant_id, clean(c.req.param('agentDeviceId')), limit],
    )
    return c.json({ jobs: result.rows })
  })

  app.post('/api/v1/rmm/devices/:agentDeviceId/tool-sessions', async (c) => {
    const auth = await requireDeviceControl(c)
    if (auth.error) return auth.error
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) return c.json({ error: 'The Hi5Central Agent is currently offline.' }, 409)

    const body = await c.req.json().catch(() => ({}))
    const tool = clean(body.tool || 'terminal').toLowerCase()
    const shell = clean(body.shell || 'powershell').toLowerCase()
    const runAs = clean(body.runAs || body.run_as || 'system').toLowerCase()
    if (!['terminal', 'files'].includes(tool)) return c.json({ error: 'Unsupported live tool session.' }, 400)
    if (tool === 'terminal' && !['cmd', 'powershell'].includes(shell)) return c.json({ error: 'Terminal shell must be cmd or powershell.' }, 400)
    if (tool === 'terminal' && !['system', 'user'].includes(runAs)) return c.json({ error: 'Terminal execution context must be user or system.' }, 400)

    const id = randomUUID()
    const token = 'h5t_' + randomBytes(32).toString('base64url')
    const expiresAt = Date.now() + TOOL_SESSION_TTL_MS
    const actorLabel = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    await pool.query(
      "INSERT INTO rmm_tool_sessions (id,tenant_id,agent_device_id,inventory_id,initiated_by_user_id,initiated_by_label,tool,shell,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'created')",
      [id, auth.session.tenant_id, device.id, device.inventory_id, auth.session.user_id, actorLabel, tool, shell],
    )
    toolSessions.set(id, {
      id,
      tenantId: auth.session.tenant_id,
      userId: auth.session.user_id,
      actorLabel,
      agentDeviceId: String(device.id),
      inventoryId: device.inventory_id,
      deviceName: device.name,
      tool,
      shell,
      runAs: tool === 'terminal' ? runAs : '',
      tokenHash: sha256(token),
      expiresAt,
      transcript: '',
      transcriptTruncated: false,
      commandCount: 0,
      startedAt: null,
    })
    const cleanup = setTimeout(() => toolSessions.delete(id), TOOL_SESSION_TTL_MS + 5000)
    cleanup.unref?.()
    return c.json({
      session: { id, tool, shell, runAs: tool === 'terminal' ? runAs : '', deviceName: device.name, expiresAt: new Date(expiresAt).toISOString() },
      token,
      websocketPath: '/rmm-tools/ws',
    }, 201)
  })
}

function safeSend(ws, payload) {
  if (!ws || ws.readyState !== 1) return false
  try { ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload)); return true } catch { return false }
}


function appendToolTranscript(session, text) {
  if (!session || !text) return
  const MAX_TRANSCRIPT_CHARS = 700000
  const value = String(text)
  if (session.transcript.length >= MAX_TRANSCRIPT_CHARS) {
    session.transcriptTruncated = true
    return
  }
  const remaining = MAX_TRANSCRIPT_CHARS - session.transcript.length
  session.transcript += value.slice(0, remaining)
  if (value.length > remaining) session.transcriptTruncated = true
}

function fileActionDescription(type, payload = {}) {
  if (type === 'files_download_request') return { eventType: 'files.download', summary: 'started downloading ' + (clean(payload.path) || 'a file'), detail: clean(payload.path) }
  if (type === 'files_delete_request') return { eventType: 'files.delete', summary: 'requested deletion of ' + (clean(payload.path) || 'a file'), detail: clean(payload.path) }
  if (type === 'files_rename_request') return { eventType: 'files.rename', summary: 'renamed ' + (clean(payload.path) || 'a file') + ' to ' + clean(payload.name), detail: clean(payload.path) }
  if (type === 'files_mkdir_request') return { eventType: 'files.mkdir', summary: 'created folder ' + clean(payload.name), detail: clean(payload.currentPath || payload.current_path) }
  if (type === 'files_upload_complete') return { eventType: 'files.upload', summary: 'uploaded ' + clean(payload.filename || payload.name), detail: clean(payload.directory || payload.currentPath) }
  return null
}

export function attachRmmDeviceToolWebSocket(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 })
  server.on('upgrade', (request, socket, head) => {
    let url
    try { url = new URL(request.url || '/', 'http://localhost') } catch { return }
    if (url.pathname !== '/rmm-tools/ws') return
    const id = clean(url.searchParams.get('session_id'))
    const token = clean(url.searchParams.get('token'))
    const session = toolSessions.get(id)
    if (!session || session.expiresAt <= Date.now() || session.tokenHash !== sha256(token)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    const agent = agentSocketForDevice(session.agentDeviceId)
    if (!agent || agent.readyState !== 1) {
      socket.write('HTTP/1.1 409 Conflict\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.hi5ToolSession = session
      wss.emit('connection', ws, request)
    })
  })

  wss.on('connection', (browserWs) => {
    const session = browserWs.hi5ToolSession
    const sessionId = String(session.id)
    const isTerminal = session.tool === 'terminal'
    const isFiles = session.tool === 'files'
    session.startedAt = Date.now()
    pool.query(
      "UPDATE rmm_tool_sessions SET status='active',started_at=COALESCE(started_at,now()),updated_at=now() WHERE id=$1 AND tenant_id=$2",
      [sessionId, session.tenantId],
    ).catch(() => {})
    const toolLabel = isTerminal ? (session.shell === 'cmd' ? 'Command Prompt' : 'PowerShell') : 'File Browser'
    const terminalContextLabel = session.runAs === 'user' ? 'signed-in user' : 'SYSTEM'
    recordRmmActivity({
      tenantId: session.tenantId,
      agentDeviceId: session.agentDeviceId,
      inventoryId: session.inventoryId,
      actorUserId: session.userId,
      actorType: 'technician',
      actorLabel: session.actorLabel,
      eventType: isTerminal ? 'terminal.started' : 'files.session_started',
      category: isTerminal ? 'terminal' : 'files',
      summary: session.actorLabel + ' started a ' + toolLabel + (isTerminal ? ' session as ' + terminalContextLabel : ' session'),
      detail: isTerminal ? 'Live terminal started in the ' + terminalContextLabel + ' execution context.' : 'Live device tool session started.',
      outcome: 'success',
      toolSessionId: sessionId,
      metadata: { tool: session.tool, shell: session.shell, runAs: session.runAs || '' },
    }).catch(() => {})

    const unsubscribe = subscribeAgentMessages(session.agentDeviceId, (payload) => {
      const type = String(payload?.type || '')
      if (isTerminal && !type.startsWith('terminal_')) return
      if (isFiles && !type.startsWith('files_')) return
      if (clean(payload.session_id || payload.sessionId) !== sessionId) return
      if (isTerminal && type === 'terminal_output') appendToolTranscript(session, String(payload.data || ''))
      if (isFiles && type === 'files_action_result') {
        const action = clean(payload.action)
        const labels = {
          files_mkdir_request: 'folder creation',
          files_rename_request: 'rename',
          files_delete_request: 'delete',
        }
        const success = payload.success !== false
        recordRmmActivity({
          tenantId: session.tenantId,
          agentDeviceId: session.agentDeviceId,
          inventoryId: session.inventoryId,
          actorUserId: session.userId,
          actorType: 'technician',
          actorLabel: session.actorLabel,
          eventType: action.replace('_request', '').replaceAll('_', '.'),
          category: 'files',
          summary: session.actorLabel + ' ' + (success ? 'completed ' : 'failed ') + (labels[action] || 'a file operation'),
          detail: clean(payload.message || payload.error || payload.refreshPath || payload.refresh_path),
          outcome: success ? 'success' : 'failed',
          severity: success ? 'info' : 'warning',
          toolSessionId: sessionId,
          metadata: { action, success, refreshPath: payload.refreshPath || payload.refresh_path || '', error: payload.error || '' },
        }).catch(() => {})
      }
      if (isFiles && type === 'files_upload_result') {
        const success = payload.success !== false
        const filename = clean(payload.filename) || 'file'
        recordRmmActivity({
          tenantId: session.tenantId,
          agentDeviceId: session.agentDeviceId,
          inventoryId: session.inventoryId,
          actorUserId: session.userId,
          actorType: 'technician',
          actorLabel: session.actorLabel,
          eventType: 'files.upload_completed',
          category: 'files',
          summary: session.actorLabel + (success ? ' uploaded ' : ' failed to upload ') + '“' + filename + '”',
          detail: clean(payload.message || payload.error || payload.refreshPath || payload.refresh_path),
          outcome: success ? 'success' : 'failed',
          severity: success ? 'info' : 'warning',
          toolSessionId: sessionId,
          metadata: { filename, success, error: payload.error || '' },
        }).catch(() => {})
      }
      if (isFiles && type === 'files_download_complete') {
        const filename = clean(payload.filename) || 'file'
        recordRmmActivity({
          tenantId: session.tenantId,
          agentDeviceId: session.agentDeviceId,
          inventoryId: session.inventoryId,
          actorUserId: session.userId,
          actorType: 'technician',
          actorLabel: session.actorLabel,
          eventType: 'files.download_completed',
          category: 'files',
          summary: session.actorLabel + ' downloaded “' + filename + '”',
          detail: clean(payload.path),
          outcome: 'success',
          toolSessionId: sessionId,
          metadata: { filename, path: payload.path || '', sizeBytes: payload.size_bytes || payload.size || null },
        }).catch(() => {})
      }
      safeSend(browserWs, payload)
    })

    if (isTerminal) {
      const started = sendAgentMessage(session.agentDeviceId, {
        type: 'terminal_start',
        session_id: sessionId,
        shell: session.shell,
        run_as: session.runAs || 'system',
        arch: 'x64',
        cols: 120,
        rows: 32,
      })
      if (!started) {
        safeSend(browserWs, { type: 'terminal_error', session_id: sessionId, error: 'Agent is offline.' })
        pool.query(
          "UPDATE rmm_tool_sessions SET status='failed',ended_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2",
          [sessionId, session.tenantId],
        ).catch(() => {})
        recordRmmActivity({
          tenantId: session.tenantId,
          agentDeviceId: session.agentDeviceId,
          inventoryId: session.inventoryId,
          actorUserId: session.userId,
          actorType: 'technician',
          actorLabel: session.actorLabel,
          eventType: 'terminal.failed',
          category: 'terminal',
          summary: session.actorLabel + ' failed to start a ' + toolLabel + ' session',
          detail: 'The Agent connection was unavailable.',
          outcome: 'failed',
          severity: 'warning',
          toolSessionId: sessionId,
        }).catch(() => {})
        try { browserWs.close(1013, 'Agent offline') } catch {}
        unsubscribe()
        toolSessions.delete(sessionId)
        return
      }
    }

    browserWs.on('message', (buffer) => {
      let payload
      try { payload = JSON.parse(Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer)) } catch { return }
      const type = clean(payload?.type)
      let allowed = false
      if (isTerminal) allowed = ['terminal_input', 'terminal_resize', 'terminal_stop'].includes(type)
      if (isFiles) allowed = [
        'files_list', 'files_cancel', 'files_download_request', 'files_download_cancel',
        'files_rename_request', 'files_delete_request', 'files_mkdir_request',
        'files_upload_start', 'files_upload_chunk', 'files_upload_complete', 'files_upload_cancel',
      ].includes(type)
      if (!allowed) return

      const outgoing = { ...payload, session_id: sessionId, sessionId }
      if (type === 'terminal_input') {
        outgoing.data = String(payload.data || '').slice(0, 65536)
        const command = outgoing.data.replace(/[\r\n]+$/g, '').trim()
        if (command) {
          session.commandCount += 1
          appendToolTranscript(session, '\n> ' + command + '\n')
        }
      }
      if (type === 'terminal_resize') {
        outgoing.cols = boundedInteger(payload.cols, 20, 300) || 120
        outgoing.rows = boundedInteger(payload.rows, 5, 100) || 32
      }
      if (isFiles) {
        if (outgoing.path != null) outgoing.path = clean(outgoing.path).slice(0, 4096)
        if (outgoing.currentPath != null) outgoing.currentPath = clean(outgoing.currentPath).slice(0, 4096)
        if (outgoing.current_path != null) outgoing.current_path = clean(outgoing.current_path).slice(0, 4096)
        if (outgoing.directory != null) outgoing.directory = clean(outgoing.directory).slice(0, 4096)
        if (outgoing.name != null) outgoing.name = clean(outgoing.name).slice(0, 512)
        if (outgoing.filename != null) outgoing.filename = clean(outgoing.filename).slice(0, 512)
        if (outgoing.data != null) outgoing.data = String(outgoing.data).slice(0, 262144)
        const activity = fileActionDescription(type, outgoing)
        if (activity) {
          recordRmmActivity({
            tenantId: session.tenantId,
            agentDeviceId: session.agentDeviceId,
            inventoryId: session.inventoryId,
            actorUserId: session.userId,
            actorType: 'technician',
            actorLabel: session.actorLabel,
            eventType: activity.eventType,
            category: 'files',
            summary: session.actorLabel + ' ' + activity.summary,
            detail: activity.detail,
            outcome: 'requested',
            toolSessionId: sessionId,
            metadata: { type, path: outgoing.path || '', currentPath: outgoing.currentPath || outgoing.current_path || '', directory: outgoing.directory || '', name: outgoing.name || outgoing.filename || '' },
          }).catch(() => {})
        }
      }
      sendAgentMessage(session.agentDeviceId, outgoing)
    })

    browserWs.on('close', () => {
      if (isTerminal) sendAgentMessage(session.agentDeviceId, { type: 'terminal_stop', session_id: sessionId, sessionId })
      if (isFiles) sendAgentMessage(session.agentDeviceId, { type: 'files_cancel', session_id: sessionId, sessionId })
      unsubscribe()
      const durationSeconds = session.startedAt ? Math.max(0, Math.round((Date.now() - session.startedAt) / 1000)) : null
      pool.query(
        "UPDATE rmm_tool_sessions SET status='ended',ended_at=now(),command_count=$3,transcript=$4,transcript_truncated=$5,updated_at=now() WHERE id=$1 AND tenant_id=$2",
        [sessionId, session.tenantId, session.commandCount || 0, session.transcript || '', Boolean(session.transcriptTruncated)],
      ).catch(() => {})
      recordRmmActivity({
        tenantId: session.tenantId,
        agentDeviceId: session.agentDeviceId,
        inventoryId: session.inventoryId,
        actorUserId: session.userId,
        actorType: 'technician',
        actorLabel: session.actorLabel,
        eventType: isTerminal ? 'terminal.ended' : 'files.session_ended',
        category: isTerminal ? 'terminal' : 'files',
        summary: session.actorLabel + ' ended a ' + toolLabel + ' session',
        detail: isTerminal
          ? (session.commandCount || 0) + ' command' + ((session.commandCount || 0) === 1 ? '' : 's') + ' executed · See output'
          : 'File Browser session ended.',
        outcome: 'success',
        toolSessionId: sessionId,
        metadata: { tool: session.tool, shell: session.shell, commandCount: session.commandCount || 0, durationSeconds, transcriptTruncated: Boolean(session.transcriptTruncated) },
      }).catch(() => {})
      toolSessions.delete(sessionId)
    })
  })
}

