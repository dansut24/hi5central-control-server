import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { resolveSession } from './session.js'

function clean(value = '') { return String(value ?? '').trim() }
function boundedInteger(value, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return null
  return Math.min(max, Math.max(min, Math.trunc(number)))
}
function normaliseOutcome(value = 'info') {
  return ['info', 'requested', 'running', 'success', 'failed', 'cancelled', 'not_applicable'].includes(value) ? value : 'info'
}
function normaliseSeverity(value = 'info') {
  return ['info', 'warning', 'critical'].includes(value) ? value : 'info'
}

export async function recordRmmActivity(event, db = pool) {
  if (!event?.tenantId || !event?.eventType || !event?.summary) return null
  const sql =
    "INSERT INTO rmm_activity_events " +
    "(tenant_id,agent_device_id,inventory_id,actor_user_id,actor_type,actor_label,event_type,category,summary,detail,outcome,severity,correlation_id,job_id,remote_session_id,tool_session_id,metadata) " +
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb) RETURNING *"
  const result = await db.query(sql, [
    event.tenantId,
    event.agentDeviceId || null,
    event.inventoryId || null,
    event.actorUserId || null,
    clean(event.actorType || 'system') || 'system',
    clean(event.actorLabel || 'SYSTEM').slice(0, 255) || 'SYSTEM',
    clean(event.eventType).slice(0, 120),
    clean(event.category || 'device').slice(0, 80) || 'device',
    clean(event.summary).slice(0, 1200),
    clean(event.detail).slice(0, 4000),
    normaliseOutcome(event.outcome),
    normaliseSeverity(event.severity),
    event.correlationId || null,
    event.jobId || null,
    event.remoteSessionId || null,
    event.toolSessionId || null,
    JSON.stringify(event.metadata && typeof event.metadata === 'object' ? event.metadata : {}),
  ])
  return result.rows[0] || null
}

function actorFromJob(job) {
  const initiatedBy = clean(job?.initiated_by)
  const label = clean(job?.initiated_by_label) || (initiatedBy === 'automation' ? 'AUTOMATION' : initiatedBy === 'system' ? 'SYSTEM' : 'Technician')
  return {
    actorType: initiatedBy === 'tray' ? 'user' : (['technician', 'system', 'automation', 'agent', 'user'].includes(initiatedBy) ? initiatedBy : 'technician'),
    actorLabel: initiatedBy === 'system' ? 'SYSTEM' : label,
    actorUserId: job?.queued_by_user_id || null,
  }
}
function quoted(value) {
  const text = clean(value)
  return text ? '“' + text + '”' : ''
}

export function jobActivityDescriptor(job, success, result = {}, errorMessage = '') {
  const payload = job?.payload && typeof job.payload === 'object' ? job.payload : {}
  const type = clean(job?.job_type)
  const actor = actorFromJob(job)
  const ok = Boolean(success)
  const outcome = ok ? 'success' : 'failed'
  const suffix = ok ? 'Job completed · See details' : 'Job failed' + (errorMessage ? ' · ' + clean(errorMessage).slice(0, 260) : '') + ' · See details'
  const common = { ...actor, outcome, severity: ok ? 'info' : 'warning', category: 'job' }

  if (type === 'windows_update.manage') {
    const resultStatus = clean(result.status || (result.parsed && result.parsed.status)).toLowerCase()
    const notApplicable = ['conflict', 'unsupported', 'not_applicable'].includes(resultStatus)
    if (notApplicable) {
      return {
        ...actor,
        outcome: 'not_applicable',
        severity: 'info',
        eventType: 'windows_updates.management_not_applicable',
        category: 'updates',
        summary: actor.actorLabel + ': Windows Update management not applicable',
        detail: [clean(result.message), Array.isArray(result.conflicts) ? result.conflicts.join(', ') : '', 'See details'].filter(Boolean).join(' · '),
        metadata: { result },
      }
    }
    return {
      ...common,
      eventType: ok ? 'windows_updates.management_completed' : 'windows_updates.management_failed',
      category: 'updates',
      summary: ok ? actor.actorLabel + ': Windows Update management evaluated' : actor.actorLabel + ': Windows Update management failed',
      detail: [clean(result.message), suffix].filter(Boolean).join(' · '),
      metadata: { result },
    }
  }

  if (type === 'software.uninstall') {
    const name = clean(result.name || payload.name) || 'software'
    return { ...common, eventType: type, category: 'software', summary: ok ? actor.actorLabel + ' uninstalled ' + quoted(name) : actor.actorLabel + ' attempted to uninstall ' + quoted(name), detail: suffix, metadata: { software: name, result } }
  }
  if (type === 'patch.software') {
    const name = clean(result.applicationName || result.application_name || payload.applicationName) || 'software'
    const intent = clean(result.intent || payload.intent || 'update').toLowerCase()
    const installing = intent === 'install'
    const fromVersion = clean(result.installedVersion || result.installed_version || payload.installedVersion)
    const targetVersion = clean(payload.targetVersion || result.targetVersion || result.target_version)
    const verifiedVersion = clean(result.verifiedVersion || result.verified_version)
    const provider = clean(result.provider || payload.provider)
    const verificationFailed = Boolean(result.verificationFailed || result.verification_failed)
    const installerOutput = clean(result.installerOutput || result.installer_output).toLowerCase()
    const providerBlocked = verificationFailed
      && !installing
      && provider.toLowerCase() === 'winget'
      && (
        clean(result.error).toLowerCase() === 'provider_no_upgrade'
        || installerOutput.includes('no available upgrade found')
        || installerOutput.includes('no newer package versions are available')
      )
    const patchSuffix = ok
      ? 'Job completed · See details'
      : providerBlocked
        ? 'Verification failed · WinGet reports no applicable upgrade · See details'
        : verificationFailed
          ? 'Verification failed · See details'
          : suffix
    const detailParts = [
      installing
        ? (targetVersion ? 'Installed target ' + targetVersion : '')
        : fromVersion && targetVersion ? fromVersion + ' → ' + targetVersion : '',
      provider ? 'Provider: ' + provider : '',
      verifiedVersion && verifiedVersion !== targetVersion ? 'Verified: ' + verifiedVersion : '',
      patchSuffix,
    ].filter(Boolean)
    return {
      ...common,
      eventType: installing ? 'software.install' : type,
      category: installing ? 'software' : 'patching',
      summary: installing
        ? (ok ? actor.actorLabel + ' installed ' + quoted(name) : actor.actorLabel + ' failed to install ' + quoted(name))
        : (ok ? actor.actorLabel + ' patched ' + quoted(name) : actor.actorLabel + ' failed to patch ' + quoted(name)),
      detail: detailParts.join(' · '),
      metadata: { software: name, intent, installedVersion: fromVersion, targetVersion, verifiedVersion, provider, providerBlocked, result },
    }
  }
  if (type === 'patch.software.bulk') {
    const items = Array.isArray(result?.items) ? result.items : []
    const serverSummary = result?.serverSummary && typeof result.serverSummary === 'object' ? result.serverSummary : {}
    const succeeded = Number(serverSummary.succeeded ?? items.filter((item) => item?.serverStatus === 'succeeded' || item?.success === true && !item?.rebootRequired).length)
    const rebootRequired = Number(serverSummary.rebootRequired ?? items.filter((item) => item?.serverStatus === 'reboot_required' || item?.success === true && item?.rebootRequired === true).length)
    const remediationRequired = Number(serverSummary.remediationRequired ?? items.filter((item) => item?.serverStatus === 'remediation_required' || item?.remediationRequired === true).length)
    const failed = Number(serverSummary.failed ?? items.filter((item) => ['failed','verification_failed'].includes(clean(item?.serverStatus)) || item?.success === false && item?.remediationRequired !== true).length)
    const successful = succeeded + rebootRequired
    const needsAttention = remediationRequired + failed
    const bulkOutcome = needsAttention > 0 ? 'warning' : 'success'
    return {
      ...actor,
      outcome: bulkOutcome,
      severity: needsAttention > 0 ? 'warning' : 'info',
      eventType: type,
      category: 'patching',
      summary: actor.actorLabel + ' completed software patch batch' + (needsAttention ? ' with attention required' : ''),
      detail: [
        successful + ' succeeded',
        rebootRequired ? rebootRequired + ' require restart' : '',
        remediationRequired ? remediationRequired + ' require old-version cleanup' : '',
        failed ? failed + ' failed' : '',
        'See details',
      ].filter(Boolean).join(' · '),
      metadata: { result, successful, rebootRequired, remediationRequired, failed },
    }
  }
  if (type === 'process.kill') {
    const name = clean(result.name) || ('PID ' + (payload.pid || '')).trim()
    return { ...common, eventType: 'process.end', category: 'process', summary: ok ? actor.actorLabel + ' ended process ' + quoted(name) : actor.actorLabel + ' failed to end process ' + quoted(name), detail: suffix, metadata: { pid: payload.pid, result } }
  }
  if (type === 'process.restart') {
    const name = clean(result.name) || ('PID ' + (payload.pid || '')).trim()
    return { ...common, eventType: type, category: 'process', summary: ok ? actor.actorLabel + ' restarted process ' + quoted(name) : actor.actorLabel + ' failed to restart process ' + quoted(name), detail: suffix, metadata: { pid: payload.pid, result } }
  }
  if (['services.start', 'services.stop', 'services.restart'].includes(type)) {
    const verb = type.split('.')[1]
    const past = { start: 'started', stop: 'stopped', restart: 'restarted' }[verb] || verb
    const name = clean(result.display_name || result.service_name || payload.serviceName) || 'service'
    return { ...common, eventType: type, category: 'service', summary: ok ? actor.actorLabel + ' ' + past + ' service ' + quoted(name) : actor.actorLabel + ' failed to ' + verb + ' service ' + quoted(name), detail: suffix, metadata: { service: payload.serviceName, result } }
  }
  if (type === 'services.set_start_type') {
    const name = clean(result.display_name || result.service_name || payload.serviceName) || 'service'
    const startType = clean(payload.startType || result.start_mode)
    return { ...common, eventType: type, category: 'service', summary: ok ? actor.actorLabel + ' changed ' + quoted(name) + ' startup type to ' + (startType || 'a new value') : actor.actorLabel + ' failed to change ' + quoted(name) + ' startup type', detail: suffix, metadata: { service: payload.serviceName, startType, result } }
  }
  if (type.startsWith('registry.') && type !== 'registry.list') {
    const action = type.split('.')[1]
    const phrases = { create_key: 'created registry key', delete_key: 'deleted registry key', set_value: 'changed registry value', delete_value: 'deleted registry value' }
    const target = [payload.path, payload.name].filter(Boolean).join('\\')
    return { ...common, eventType: type, category: 'registry', summary: ok ? actor.actorLabel + ' ' + (phrases[action] || 'changed the registry') + ' ' + quoted(target) : actor.actorLabel + ' failed to change registry ' + quoted(target), detail: suffix, metadata: { path: payload.path, name: payload.name, kind: payload.kind, result } }
  }
  if (type === 'inventory.scan') {
    return { ...common, eventType: type, category: 'inventory', summary: ok ? actor.actorLabel + ' refreshed device inventory' : actor.actorLabel + ' failed to refresh device inventory', detail: suffix, metadata: { result } }
  }
  if (type === 'custom.command') {
    const requestMetadata = job?.request_metadata && typeof job.request_metadata === 'object' ? job.request_metadata : {}
    if (clean(requestMetadata.source) === 'agent_upgrade') {
      const version = clean(requestMetadata.release_version) || 'selected release'
      const targetPatchHost = clean(requestMetadata.target_patch_host_version)
      const scheduledCommon = ok ? { ...common, outcome: 'info' } : common
      return {
        ...scheduledCommon,
        eventType: ok ? 'agent.upgrade.scheduled' : 'agent.upgrade.failed',
        category: 'device',
        summary: ok
          ? actor.actorLabel + ' scheduled Hi5Central Agent ' + version + ' upgrade'
          : actor.actorLabel + ' failed to prepare Hi5Central Agent ' + version + ' upgrade',
        detail: [targetPatchHost ? 'Target PatchHost ' + targetPatchHost : '', suffix].filter(Boolean).join(' · '),
        metadata: { releaseVersion: version, targetPatchHostVersion: targetPatchHost, result, requestMetadata },
      }
    }
    if (clean(requestMetadata.source) === 'device_power_action') {
      const action = clean(requestMetadata.power_action) || 'restart'
      const verb = action === 'shutdown' ? 'shut down' : 'restart'
      return {
        ...common,
        eventType: ok ? 'device.' + action + '.scheduled' : 'device.' + action + '.failed',
        category: 'device',
        summary: ok
          ? actor.actorLabel + ' scheduled device ' + verb
          : actor.actorLabel + ' failed to schedule device ' + verb,
        detail: [
          requestMetadata.delay_seconds != null ? String(requestMetadata.delay_seconds) + ' second countdown' : '',
          suffix,
        ].filter(Boolean).join(' · '),
        metadata: { action, delaySeconds: requestMetadata.delay_seconds, result },
      }
    }
    if (clean(requestMetadata.source) === 'vendor_artifact_trust_probe') return null
    if (clean(requestMetadata.source) === 'vendor_verification_probe') {
      const filePath = clean(requestMetadata.verification_file_path)
      return {
        ...common,
        eventType: ok ? 'patch.vendor_verification_probe.completed' : 'patch.vendor_verification_probe.failed',
        category: 'patching',
        summary: ok
          ? actor.actorLabel + ' completed vendor verification probe'
          : actor.actorLabel + ' vendor verification probe failed',
        detail: [filePath ? 'File VERSIONINFO · ' + filePath : '', suffix].filter(Boolean).join(' · '),
        metadata: { method: 'file_version', filePath, result, requestMetadata },
      }
    }
    const automationName = clean(requestMetadata.automation_name || requestMetadata.tray_label) || 'automation'
    return {
      ...common,
      eventType: 'automation.run',
      category: 'automation',
      summary: ok ? actor.actorLabel + ' ran automation ' + quoted(automationName) : actor.actorLabel + ' automation ' + quoted(automationName) + ' failed',
      detail: suffix,
      metadata: { automation: automationName, result, requestMetadata },
    }
  }
  if (['processes.list', 'services.list', 'files.list', 'registry.list', 'events.list'].includes(type)) return null
  return { ...common, eventType: type || 'job.completed', summary: actor.actorLabel + ' ' + (ok ? 'completed ' : 'failed ') + (type || 'a device job'), detail: suffix, metadata: { result } }
}

export async function recordJobCompletionActivity(job, success, result, errorMessage, db = pool) {
  const descriptor = jobActivityDescriptor(job, success, result, errorMessage)
  if (!descriptor) return null
  return recordRmmActivity({
    tenantId: job.tenant_id,
    agentDeviceId: job.agent_device_id,
    inventoryId: job.inventory_id || null,
    correlationId: job.correlation_id || null,
    jobId: job.id,
    ...descriptor,
  }, db)
}

async function requireActivityAccess(c, tenantWide = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (tenantWide) {
    if (!hasPermission(session.access, 'rmm.audit.view') && !hasPermission(session.access, 'audit.view')) return { error: c.json({ error: 'You do not have permission to view the RMM audit log.' }, 403) }
  } else if (!hasPermission(session.access, 'rmm.devices.view')) {
    return { error: c.json({ error: 'You do not have permission to view device activity.' }, 403) }
  }
  return { session }
}

function activityFilters(c, tenantId, deviceId = null) {
  const values = [tenantId]
  const where = ['e.tenant_id=$1']
  const requestedDeviceId = deviceId || clean(c.req.query('agentDeviceId'))
  if (requestedDeviceId) { values.push(clean(requestedDeviceId)); where.push('e.agent_device_id::text=$' + values.length) }
  const actor = clean(c.req.query('actor'))
  if (actor) { values.push('%' + actor + '%'); where.push("(e.actor_label ILIKE $" + values.length + " OR COALESCE(u.email,'') ILIKE $" + values.length + ')') }
  const category = clean(c.req.query('category'))
  if (category) { values.push(category); where.push('e.category=$' + values.length) }
  const outcome = clean(c.req.query('outcome'))
  if (outcome) { values.push(outcome); where.push('e.outcome=$' + values.length) }
  const eventType = clean(c.req.query('eventType'))
  if (eventType) { values.push(eventType); where.push('e.event_type=$' + values.length) }
  const q = clean(c.req.query('q'))
  if (q) { values.push('%' + q + '%'); where.push('(e.summary ILIKE $' + values.length + ' OR e.detail ILIKE $' + values.length + ' OR i.name ILIKE $' + values.length + ')') }
  const from = clean(c.req.query('from'))
  if (from) { values.push(from); where.push('e.created_at >= $' + values.length + '::timestamptz') }
  const to = clean(c.req.query('to'))
  if (to) { values.push(to); where.push('e.created_at <= $' + values.length + '::timestamptz') }
  return { values, where }
}

async function queryActivity(c, tenantId, deviceId = null) {
  const filtered = activityFilters(c, tenantId, deviceId)
  const values = filtered.values
  const where = filtered.where
  const limit = boundedInteger(c.req.query('limit'), 1, 250) || 75
  const offset = boundedInteger(c.req.query('offset'), 0, 100000) || 0
  values.push(limit, offset)
  const sql =
    "SELECT e.id,e.agent_device_id,e.inventory_id,e.actor_user_id,e.actor_type,e.actor_label,e.event_type,e.category,e.summary,e.detail,e.outcome,e.severity,e.correlation_id,e.job_id,e.remote_session_id,e.tool_session_id,e.metadata,e.created_at," +
    "i.name AS device_name,i.reference AS device_reference,COALESCE(NULLIF(u.name,''),u.email,'') AS actor_user_name " +
    "FROM rmm_activity_events e LEFT JOIN rmm_agent_devices a ON a.id=e.agent_device_id LEFT JOIN rmm_device_inventory i ON i.id=COALESCE(e.inventory_id,a.inventory_id) LEFT JOIN users u ON u.id=e.actor_user_id " +
    "WHERE " + where.join(' AND ') + " ORDER BY e.created_at DESC LIMIT $" + (values.length - 1) + " OFFSET $" + values.length
  const result = await pool.query(sql, values)
  return result.rows
}

export function registerRmmActivityRoutes(app) {
  app.get('/api/v1/rmm/activity', async (c) => {
    const auth = await requireActivityAccess(c, true)
    if (auth.error) return auth.error
    return c.json({ events: await queryActivity(c, auth.session.tenant_id) })
  })

  app.get('/api/v1/rmm/activity/:eventId', async (c) => {
    const auth = await requireActivityAccess(c, true)
    if (auth.error) return auth.error
    const sql =
      "SELECT e.id,e.agent_device_id,e.inventory_id,e.actor_user_id,e.actor_type,e.actor_label,e.event_type,e.category,e.summary,e.detail,e.outcome,e.severity,e.correlation_id,e.job_id,e.remote_session_id,e.tool_session_id,e.metadata,e.created_at," +
      "i.name AS device_name,i.reference AS device_reference,COALESCE(NULLIF(u.name,''),u.email,'') AS actor_user_name " +
      "FROM rmm_activity_events e LEFT JOIN rmm_agent_devices a ON a.id=e.agent_device_id LEFT JOIN rmm_device_inventory i ON i.id=COALESCE(e.inventory_id,a.inventory_id) LEFT JOIN users u ON u.id=e.actor_user_id " +
      "WHERE e.id=$1 AND e.tenant_id=$2 LIMIT 1"
    const result = await pool.query(sql, [clean(c.req.param('eventId')), auth.session.tenant_id])
    if (!result.rowCount) return c.json({ error: 'RMM activity record not found.' }, 404)
    return c.json({ event: result.rows[0] })
  })

  app.get('/api/v1/rmm/devices/:agentDeviceId/activity', async (c) => {
    const auth = await requireActivityAccess(c, false)
    if (auth.error) return auth.error
    return c.json({ events: await queryActivity(c, auth.session.tenant_id, c.req.param('agentDeviceId')) })
  })

  app.get('/api/v1/rmm/tool-sessions/:sessionId', async (c) => {
    const auth = await requireActivityAccess(c, false)
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.terminal')) return c.json({ error: 'You do not have permission to view terminal transcripts.' }, 403)
    const sql =
      "SELECT s.id,s.agent_device_id,s.inventory_id,s.initiated_by_label,s.tool,s.shell,s.status,s.started_at,s.ended_at,s.command_count,s.transcript,s.transcript_truncated,s.created_at,i.name AS device_name " +
      "FROM rmm_tool_sessions s LEFT JOIN rmm_device_inventory i ON i.id=s.inventory_id WHERE s.id=$1 AND s.tenant_id=$2 LIMIT 1"
    const result = await pool.query(sql, [clean(c.req.param('sessionId')), auth.session.tenant_id])
    if (!result.rowCount) return c.json({ error: 'Tool session not found.' }, 404)
    return c.json({ session: result.rows[0] })
  })
}
