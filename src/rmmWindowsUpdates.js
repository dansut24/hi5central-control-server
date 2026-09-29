import { createHash } from 'node:crypto'
import { pool } from './db.js'
import { recordRmmActivity } from './rmmActivity.js'

function clean(value = '') { return String(value ?? '').trim() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function array(value) { return Array.isArray(value) ? value : [] }
function clampInt(value, min, max, fallback = min) {
  const n = Number(value)
  return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.trunc(n))) : fallback
}
function parseDate(value) {
  if (!value) return null
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? null : parsed
}
function versionParts(value = '') { return clean(value).match(/\d+/g)?.slice(0, 4).map(Number) || [] }
function versionAtLeast(current, target) {
  if (clean(current) === '1.0.0' && /^0\.1\./.test(clean(target))) return false
  const left = versionParts(current)
  const right = versionParts(target)
  for (let index = 0; index < Math.max(left.length, right.length, 1); index += 1) {
    const delta = (left[index] || 0) - (right[index] || 0)
    if (delta) return delta > 0
  }
  return Boolean(left.length && right.length)
}

function classifyUpdate(update = {}) {
  const title = clean(update.title).toLowerCase()
  const categories = array(update.categories).map((value) => clean(value).toLowerCase())
  const severity = clean(update.severity || update.msrc_severity).toLowerCase()
  const has = (needle) => categories.some((value) => value.includes(needle))
  if (has('driver') || title.includes('driver')) return 'driver'
  if (has('definition') || title.includes('security intelligence update') || title.includes('definition update')) return 'definition'
  if (has('upgrades') || title.includes('feature update to windows')) return 'feature'
  if (severity === 'critical' || has('critical updates')) return 'critical'
  if (severity || has('security updates') || title.includes('security update')) return 'security'
  if (has('update rollups') || has('updates') || title.includes('cumulative update')) return 'quality'
  return 'other'
}

function observationKey(update = {}) {
  const id = clean(update.update_id || update.updateId)
  const revision = clampInt(update.revision_number ?? update.revisionNumber, 0, 1000000, 0)
  if (id) return id + ':' + revision
  const kbs = array(update.kb || update.kb_articles || update.kbArticles)
    .map((value) => clean(value).toUpperCase().replace(/^KB/, ''))
    .filter(Boolean)
    .sort()
  return (kbs.join(',') + '|' + clean(update.title).toLowerCase().replace(/\s+/g, ' ')).slice(0, 900)
}

export async function ingestWindowsUpdateInventory(agent, payload, client = pool) {
  const windows = object(payload?.windows_updates)
  if (!Array.isArray(windows.updates) || clean(windows.error)) return { authoritative: false, observed: 0 }

  const scanAt = parseDate(windows.last_scan_utc) || parseDate(payload?.collected_at) || new Date()
  await client.query(
    'UPDATE rmm_windows_update_observations SET pending=false,last_scan_at=$4,updated_at=now() ' +
    'WHERE tenant_id=$1 AND inventory_id=$2 AND agent_device_id=$3 AND pending=true',
    [agent.tenant_id, agent.inventory_id, agent.id, scanAt.toISOString()],
  )

  let observed = 0
  for (const update of windows.updates) {
    const title = clean(update?.title).slice(0, 1000)
    if (!title) continue
    const kbs = array(update?.kb || update?.kb_articles || update?.kbArticles)
      .map((value) => {
        const text = clean(value).toUpperCase()
        return text && !text.startsWith('KB') ? 'KB' + text : text
      }).filter(Boolean).slice(0, 50)
    const categories = array(update?.categories).map((value) => clean(value)).filter(Boolean).slice(0, 50)
    const releaseAt = parseDate(update?.last_deployment_change_time || update?.lastDeploymentChangeTime)

    await client.query(
      'INSERT INTO rmm_windows_update_observations ' +
      '(tenant_id,inventory_id,agent_device_id,update_key,update_id,revision_number,title,kb_articles,categories,severity,update_class,' +
      'downloaded,mandatory,reboot_required,auto_select,browse_only,release_at,first_seen_at,last_seen_at,last_scan_at,pending,metadata) ' +
      'VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,now(),now(),$18,true,$19::jsonb) ' +
      'ON CONFLICT (tenant_id,inventory_id,update_key) DO UPDATE SET agent_device_id=EXCLUDED.agent_device_id,' +
      'update_id=EXCLUDED.update_id,revision_number=EXCLUDED.revision_number,title=EXCLUDED.title,kb_articles=EXCLUDED.kb_articles,' +
      'categories=EXCLUDED.categories,severity=EXCLUDED.severity,update_class=EXCLUDED.update_class,downloaded=EXCLUDED.downloaded,' +
      'mandatory=EXCLUDED.mandatory,reboot_required=EXCLUDED.reboot_required,auto_select=EXCLUDED.auto_select,browse_only=EXCLUDED.browse_only,' +
      'release_at=COALESCE(EXCLUDED.release_at,rmm_windows_update_observations.release_at),last_seen_at=now(),last_scan_at=EXCLUDED.last_scan_at,' +
      'pending=true,metadata=EXCLUDED.metadata,updated_at=now()',
      [
        agent.tenant_id, agent.inventory_id, agent.id, observationKey(update),
        clean(update?.update_id || update?.updateId).slice(0, 180),
        clampInt(update?.revision_number ?? update?.revisionNumber, 0, 1000000, 0),
        title, JSON.stringify(kbs), JSON.stringify(categories),
        clean(update?.severity || update?.msrc_severity).slice(0, 80),
        classifyUpdate(update), update?.downloaded === true || update?.is_downloaded === true,
        update?.mandatory === true, update?.reboot_required === true || update?.requires_reboot === true,
        update?.auto_select === true, update?.browse_only === true,
        releaseAt?.toISOString() || null, scanAt.toISOString(),
        JSON.stringify({ source: 'windows_update_agent', inventoryScanAt: scanAt.toISOString() }),
      ],
    )
    observed += 1
  }
  return { authoritative: true, observed, scannedAt: scanAt.toISOString() }
}

async function effectiveWindowsPolicy(tenantId, inventoryId) {
  const result = await pool.query(
    'SELECT p.*,x.priority AS assignment_priority,x.scope_type AS assignment_scope_type,x.scope_name AS assignment_scope_name ' +
    'FROM rmm_patch_assignments x JOIN rmm_patch_policies p ON p.id=x.policy_id AND p.tenant_id=x.tenant_id ' +
    "AND p.status='active' AND p.windows_enabled=true JOIN rmm_device_inventory i ON i.id=$2 AND i.tenant_id=x.tenant_id " +
    'LEFT JOIN organisation_people op ON op.tenant_id=i.tenant_id AND op.id=i.assigned_person_id ' +
    'LEFT JOIN organisation_sites os ON os.tenant_id=i.tenant_id AND os.id=op.site_id ' +
    "WHERE x.tenant_id=$1 AND x.enabled=true AND ((x.scope_type='Estate' AND x.scope_id='ALL') OR " +
    "(x.scope_type='Device' AND x.scope_id IN (i.id::text,i.reference,COALESCE((SELECT id::text FROM rmm_agent_devices WHERE inventory_id=i.id AND disabled_at IS NULL LIMIT 1),''))) OR " +
    "(x.scope_type='Site' AND x.scope_id IN (COALESCE(os.id::text,''),COALESCE(os.external_key,''),COALESCE(os.name,''))) OR " +
    "(x.scope_type='Group' AND EXISTS (SELECT 1 FROM rmm_device_group_memberships gm WHERE gm.tenant_id=i.tenant_id AND gm.inventory_id=i.id AND gm.group_id::text=x.scope_id))) " +
    'ORDER BY x.priority DESC,x.created_at DESC LIMIT 1',
    [tenantId, inventoryId],
  )
  return result.rows[0] || null
}

function normalizeTimezone(value) {
  const timezone = clean(value)
  if (!timezone || timezone === 'tenant') return 'Europe/London'
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: timezone }).format(new Date())
    return timezone
  } catch {
    return 'Europe/London'
  }
}

const DAY_INDEX = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 }
function localClock(at, timezone) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(at)
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]))
  return { day: DAY_INDEX[values.weekday] || 1, minutes: Number(values.hour || 0) * 60 + Number(values.minute || 0) }
}
function timeMinutes(value, fallback) {
  const match = clean(value).match(/^(\d{1,2}):(\d{2})$/)
  if (!match) return fallback
  const hour = Number(match[1])
  const minute = Number(match[2])
  return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 ? hour * 60 + minute : fallback
}
function previousDay(day) { return day <= 1 ? 7 : day - 1 }

export function windowsMaintenanceWindow(policy, at = new Date()) {
  const config = object(policy?.maintenance_window)
  const timezone = normalizeTimezone(config.timezone)
  const configuredDays = array(config.days).map((value) => clampInt(value, 1, 7, 0)).filter(Boolean)
  const days = new Set(configuredDays.length ? configuredDays : [1, 2, 3, 4, 5, 6, 7])
  const start = timeMinutes(config.start, 0)
  const end = timeMinutes(config.end, 1439)
  const clock = localClock(at, timezone)
  let open = false
  if (start === end) open = days.has(clock.day)
  else if (start < end) open = days.has(clock.day) && clock.minutes >= start && clock.minutes < end
  else open = (days.has(clock.day) && clock.minutes >= start) || (days.has(previousDay(clock.day)) && clock.minutes < end)
  return { open, timezone, start: clean(config.start || '00:00'), end: clean(config.end || '23:59'), days: [...days] }
}

const DEFAULT_ROLLOUT_WAVES = [
  { id: 'pilot', name: 'Pilot', percentage: 5, delayDays: 0 },
  { id: 'early', name: 'Early', percentage: 15, delayDays: 1 },
  { id: 'broad', name: 'Broad', percentage: 60, delayDays: 3 },
  { id: 'final', name: 'Final', percentage: 20, delayDays: 5 },
]

function normalizedRollout(value = {}) {
  const source = object(value)
  const configured = new Map(array(source.waves).map((wave) => [clean(wave?.id).toLowerCase(), object(wave)]))
  let remaining = 100
  let previousDelay = 0
  const waves = DEFAULT_ROLLOUT_WAVES.map((fallback, index) => {
    const candidate = configured.get(fallback.id) || {}
    const delayDays = Math.max(previousDelay, clampInt(candidate.delayDays, 0, 365, fallback.delayDays))
    previousDelay = delayDays
    const percentage = index === DEFAULT_ROLLOUT_WAVES.length - 1
      ? remaining
      : Math.min(remaining, clampInt(candidate.percentage, 0, 100, fallback.percentage))
    remaining -= percentage
    return { id: fallback.id, name: fallback.name, percentage, delayDays }
  })
  const deadlineDays = Math.max(previousDelay, clampInt(source.deadlineDays, 0, 365, 7))
  return { enabled: source.enabled === true, deadlineDays, waves }
}

function normalizedRules(policy) {
  const rules = object(policy?.windows_rules)
  const delays = object(rules.delayDays)
  const base = clampInt(policy?.deployment_delay_days, 0, 365, 0)
  return {
    autoInstall: rules.autoInstall === true,
    includeDrivers: rules.includeDrivers === true,
    includeFeatureUpdates: rules.includeFeatureUpdates === true,
    includeDefinitions: rules.includeDefinitions !== false,
    rollout: normalizedRollout(rules.rollout),
    delayDays: {
      critical: clampInt(delays.critical, 0, 365, 0),
      security: clampInt(delays.security, 0, 365, base),
      quality: clampInt(delays.quality, 0, 365, base),
      feature: clampInt(delays.feature, 0, 365, Math.max(base, 14)),
      driver: clampInt(delays.driver, 0, 365, Math.max(base, 14)),
      definition: clampInt(delays.definition, 0, 365, 0),
      other: clampInt(delays.other, 0, 365, base),
    },
  }
}

function rolloutBucket(tenantId, policyId, inventoryId) {
  const digest = createHash('sha256').update([tenantId, policyId, inventoryId].map(clean).join(':')).digest()
  return digest.readUInt32BE(0) % 100
}

function rolloutWaveFor(rules, tenantId, policyId, inventoryId) {
  const bucket = rolloutBucket(tenantId, policyId, inventoryId)
  let upper = 0
  for (const wave of rules.rollout.waves) {
    upper += wave.percentage
    if (bucket < upper) return { ...wave, bucket }
  }
  return { ...rules.rollout.waves[rules.rollout.waves.length - 1], bucket }
}

function updateEligibility(row, rules, now, context = {}, control = null) {
  const klass = clean(row.update_class) || 'other'
  if (klass === 'driver' && !rules.includeDrivers) return { eligible: false, reason: 'drivers_disabled' }
  if (klass === 'feature' && !rules.includeFeatureUpdates) return { eligible: false, reason: 'feature_updates_disabled' }
  if (klass === 'definition' && !rules.includeDefinitions) return { eligible: false, reason: 'definitions_disabled' }

  const delayDays = rules.delayDays[klass] ?? rules.delayDays.other
  const anchor = parseDate(row.release_at) || parseDate(row.first_seen_at) || now
  const baseEligibleAt = new Date(anchor.getTime() + delayDays * 86400000)

  if (clean(control?.state) === 'paused') {
    return {
      eligible: false,
      reason: 'rollout_paused',
      delayDays,
      eligibleAt: baseEligibleAt.toISOString(),
      pausedReason: clean(control.reason),
      pausedAt: control.paused_at || null,
    }
  }

  if (!rules.rollout.enabled || klass === 'definition') {
    return {
      eligible: now >= baseEligibleAt,
      reason: now >= baseEligibleAt ? 'delay_elapsed' : 'deployment_delay',
      delayDays,
      eligibleAt: baseEligibleAt.toISOString(),
      rolloutEnabled: false,
    }
  }

  const wave = rolloutWaveFor(rules, context.tenantId, context.policyId, context.inventoryId)
  const waveEligibleAt = new Date(baseEligibleAt.getTime() + wave.delayDays * 86400000)
  const deadlineAt = new Date(baseEligibleAt.getTime() + rules.rollout.deadlineDays * 86400000)
  const deadlineReached = now >= deadlineAt
  const waveOpen = now >= waveEligibleAt
  return {
    eligible: deadlineReached || waveOpen,
    reason: deadlineReached ? 'compliance_deadline' : waveOpen ? 'rollout_wave_open' : 'rollout_wave_wait',
    delayDays,
    baseEligibleAt: baseEligibleAt.toISOString(),
    eligibleAt: waveEligibleAt.toISOString(),
    deadlineAt: deadlineAt.toISOString(),
    deadlineReached,
    rolloutEnabled: true,
    rolloutBucket: wave.bucket,
    rolloutWave: wave.id,
    rolloutWaveName: wave.name,
    rolloutWavePercentage: wave.percentage,
    rolloutWaveDelayDays: wave.delayDays,
  }
}

async function saveDecision(input) {
  await pool.query(
    'INSERT INTO rmm_windows_patch_decisions ' +
    '(tenant_id,inventory_id,agent_device_id,policy_id,agent_job_id,state,reason,eligible_update_keys,decision,evaluated_at,dispatched_at,updated_at) ' +
    'VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,now(),CASE WHEN $10 THEN now() ELSE NULL END,now()) ' +
    'ON CONFLICT (tenant_id,inventory_id) DO UPDATE SET agent_device_id=EXCLUDED.agent_device_id,policy_id=EXCLUDED.policy_id,' +
    'agent_job_id=EXCLUDED.agent_job_id,state=EXCLUDED.state,reason=EXCLUDED.reason,eligible_update_keys=EXCLUDED.eligible_update_keys,' +
    'decision=EXCLUDED.decision,evaluated_at=now(),dispatched_at=CASE WHEN $10 THEN now() ELSE rmm_windows_patch_decisions.dispatched_at END,updated_at=now()',
    [
      input.tenantId, input.inventoryId, input.agentDeviceId, input.policyId || null, input.agentJobId || null,
      input.state, input.reason, JSON.stringify(input.eligibleKeys || []), JSON.stringify(input.decision || {}),
      input.dispatched === true,
    ],
  )
}

async function dispatchInstall(tenantId, device, policy, eligible, sendAgentMessage) {
  const kbArticles = [...new Set(eligible.flatMap((row) => array(row.kb_articles).map(clean)).filter(Boolean))]
  const titles = [...new Set(eligible.filter((row) => !array(row.kb_articles).length).map((row) => clean(row.title)).filter(Boolean))]
  const payload = {
    install_all: false,
    include_drivers: eligible.some((row) => row.update_class === 'driver'),
    kb_articles: kbArticles,
    titles,
    timeout_seconds: 7200,
  }
  const metadata = {
    source: 'windows_patch_schedule',
    policy_id: policy.id,
    policy_name: policy.name,
    update_keys: eligible.map((row) => row.update_key),
    update_classes: [...new Set(eligible.map((row) => row.update_class))],
  }
  const inserted = await pool.query(
    "INSERT INTO rmm_agent_jobs (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata) " +
    "VALUES ($1,$2,'windows_update.install',$3::jsonb,'system','SYSTEM · Windows patch schedule',$4::jsonb) " +
    "ON CONFLICT DO NOTHING RETURNING id,status,created_at",
    [tenantId, device.agent_device_id, JSON.stringify(payload), JSON.stringify(metadata)],
  )
  if (!inserted.rowCount) {
    const existing = await pool.query(
      "SELECT id FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='windows_update.install' " +
      "AND status IN ('queued','claimed') AND request_metadata->>'source'='windows_patch_schedule' ORDER BY created_at DESC LIMIT 1",
      [tenantId, device.agent_device_id],
    )
    return { dispatched: false, jobId: existing.rows[0]?.id || null, error: 'install_already_running' }
  }
  const job = inserted.rows[0]
  const claimed = await pool.query(
    "UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND status='queued' RETURNING id",
    [job.id],
  )
  if (!claimed.rowCount) return { dispatched: false, jobId: job.id, error: 'claim_failed' }

  const pushed = sendAgentMessage(device.agent_device_id, {
    type: 'job_execute',
    job: { id: job.id, job_type: 'windows_update.install', payload, created_at: job.created_at },
  })
  if (!pushed) {
    await pool.query(
      "UPDATE rmm_agent_jobs SET status='cancelled',completed_at=now(),error_message='Device went offline before scheduled Windows Update dispatch.',updated_at=now() WHERE id=$1",
      [job.id],
    )
    return { dispatched: false, jobId: job.id, error: 'device_offline' }
  }

  await recordRmmActivity({
    tenantId,
    agentDeviceId: device.agent_device_id,
    inventoryId: device.inventory_id,
    actorType: 'system',
    actorLabel: 'SYSTEM',
    eventType: 'windows_updates.scheduled_install',
    category: 'updates',
    summary: 'SYSTEM: started ' + eligible.length + ' scheduled Windows update' + (eligible.length === 1 ? '' : 's'),
    detail: clean(policy.name) + ' · ' + eligible.map((row) => clean(row.title)).slice(0, 5).join(' · '),
    outcome: 'requested',
    jobId: job.id,
    metadata,
  }).catch(() => null)

  return { dispatched: true, jobId: job.id }
}

async function ensureWindowsUpdateManagement(tenantId, device, policy, state, options = {}) {
  const desired = Boolean(policy)
  const policyId = policy?.id || null
  const policyName = clean(policy?.name)
  const previous = state || {}
  const previousResult = object(previous.last_result)
  const previousResultStatus = clean(previousResult.status || object(previousResult.parsed).status).toLowerCase()
  const checkedAt = parseDate(previous.last_applied_at) || parseDate(previous.updated_at)
  const samePolicy = clean(previous.policy_id) === clean(policyId)
  const notApplicableRecent = desired
    && previous.applied_managed !== true
    && samePolicy
    && ['conflict', 'unsupported', 'not_applicable'].includes(previousResultStatus)
    && checkedAt
    && Date.now() - checkedAt.getTime() <= 24 * 60 * 60 * 1000
  const appliedAt = parseDate(previous.last_applied_at)
  const verificationStale = desired && (!appliedAt || Date.now() - appliedAt.getTime() > 24 * 60 * 60 * 1000)
  const needsChange = desired
    ? !notApplicableRecent && (previous.applied_managed !== true || !samePolicy || verificationStale)
    : previous.applied_managed === true || previous.desired_managed === true

  await pool.query(
    'INSERT INTO rmm_windows_update_management ' +
    '(tenant_id,inventory_id,agent_device_id,desired_managed,applied_managed,policy_id,policy_name,last_result,last_error,updated_at) ' +
    'VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,now()) ' +
    'ON CONFLICT (tenant_id,inventory_id) DO UPDATE SET ' +
    'agent_device_id=EXCLUDED.agent_device_id,desired_managed=EXCLUDED.desired_managed,policy_id=EXCLUDED.policy_id,' +
    'policy_name=EXCLUDED.policy_name,updated_at=now()',
    [
      tenantId,
      device.inventory_id,
      device.agent_device_id,
      desired,
      previous.applied_managed ?? null,
      policyId,
      policyName,
      JSON.stringify(object(previous.last_result)),
      clean(previous.last_error),
    ],
  )

  if (!needsChange) {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: notApplicableRecent ? 'not_applicable' : (desired ? 'managed' : 'unmanaged'),
      blocking: notApplicableRecent ? desired : false,
      reason: notApplicableRecent ? 'windows_update_management_not_applicable' : '',
      detail: notApplicableRecent ? clean(previousResult.message) : '',
      policyId,
      policyName,
    }
  }

  if (!versionAtLeast(device.agent_version, '0.1.214')) {
    await pool.query(
      'UPDATE rmm_windows_update_management SET last_error=$3,updated_at=now() WHERE tenant_id=$1 AND inventory_id=$2',
      [tenantId, device.inventory_id, 'Agent 0.1.214 or later is required for managed Windows Update mode.'],
    )
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'blocked',
      blocking: desired,
      reason: 'windows_update_management_agent_upgrade_required',
      requiredAgentVersion: '0.1.214',
      currentAgentVersion: clean(device.agent_version),
      policyId,
      policyName,
    }
  }

  const socket = typeof options.agentSocketForDevice === 'function'
    ? options.agentSocketForDevice(device.agent_device_id)
    : null
  if (!socket || socket.readyState !== 1) {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'offline',
      blocking: desired,
      reason: 'windows_update_management_device_offline',
      policyId,
      policyName,
    }
  }

  const active = await pool.query(
    "SELECT id,status FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='windows_update.manage' " +
    "AND status IN ('queued','claimed') AND request_metadata->>'source'='windows_update_management' ORDER BY created_at DESC LIMIT 1",
    [tenantId, device.agent_device_id],
  )
  if (active.rowCount) {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'running',
      blocking: desired,
      reason: 'windows_update_management_pending',
      jobId: active.rows[0].id,
      policyId,
      policyName,
    }
  }

  if (options.dispatch === false || typeof options.sendAgentMessage !== 'function') {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'ready',
      blocking: desired,
      reason: 'windows_update_management_ready',
      policyId,
      policyName,
    }
  }

  const payload = {
    enabled: desired,
    policy_id: policyId || '',
    policy_name: policyName,
    timeout_seconds: 120,
  }
  const metadata = {
    source: 'windows_update_management',
    desired_managed: desired,
    policy_id: policyId,
    policy_name: policyName,
  }
  const inserted = await pool.query(
    "INSERT INTO rmm_agent_jobs " +
    "(tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata) " +
    "VALUES ($1,$2,'windows_update.manage',$3::jsonb,'system','SYSTEM · Windows Update management',$4::jsonb) " +
    "ON CONFLICT DO NOTHING RETURNING id,status,created_at",
    [tenantId, device.agent_device_id, JSON.stringify(payload), JSON.stringify(metadata)],
  )
  if (!inserted.rowCount) {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'running',
      blocking: desired,
      reason: 'windows_update_management_pending',
      policyId,
      policyName,
    }
  }

  const job = inserted.rows[0]
  const claimed = await pool.query(
    "UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND status='queued' RETURNING id",
    [job.id],
  )
  if (!claimed.rowCount) {
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'failed',
      blocking: desired,
      reason: 'windows_update_management_claim_failed',
      jobId: job.id,
      policyId,
      policyName,
    }
  }

  const pushed = options.sendAgentMessage(device.agent_device_id, {
    type: 'job_execute',
    job: { id: job.id, job_type: 'windows_update.manage', payload, created_at: job.created_at },
  })
  if (!pushed) {
    await pool.query(
      "UPDATE rmm_agent_jobs SET status='cancelled',completed_at=now(),error_message='Device went offline before Windows Update management dispatch.',updated_at=now() WHERE id=$1",
      [job.id],
    )
    return {
      desired,
      applied: previous.applied_managed === true,
      state: 'offline',
      blocking: desired,
      reason: 'windows_update_management_device_offline',
      jobId: job.id,
      policyId,
      policyName,
    }
  }

  await pool.query(
    'UPDATE rmm_windows_update_management SET agent_job_id=$3,last_error=$4,updated_at=now() WHERE tenant_id=$1 AND inventory_id=$2',
    [tenantId, device.inventory_id, job.id, ''],
  )
  await recordRmmActivity({
    tenantId,
    agentDeviceId: device.agent_device_id,
    inventoryId: device.inventory_id,
    actorType: 'system',
    actorLabel: 'SYSTEM',
    eventType: desired ? 'windows_updates.management_requested' : 'windows_updates.management_remove_requested',
    category: 'updates',
    summary: desired
      ? 'SYSTEM: applying Hi5Central Windows Update management'
      : 'SYSTEM: removing Hi5Central Windows Update management',
    detail: desired ? policyName : 'No effective Windows patch policy remains on this device.',
    outcome: 'requested',
    jobId: job.id,
    metadata,
  }).catch(() => null)

  return {
    desired,
    applied: previous.applied_managed === true,
    state: 'dispatched',
    blocking: desired,
    reason: 'windows_update_management_pending',
    jobId: job.id,
    policyId,
    policyName,
  }
}

export async function evaluateWindowsUpdatePolicies(tenantId, options = {}) {
  const [devices, controlResult, managementResult] = await Promise.all([
    pool.query(
      'SELECT a.id AS agent_device_id,a.inventory_id,a.agent_version,a.websocket_status,a.last_telemetry_at,i.name,i.reference ' +
      'FROM rmm_agent_devices a JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true ' +
      'WHERE a.tenant_id=$1 AND a.disabled_at IS NULL',
      [tenantId],
    ),
    pool.query(
      "SELECT update_key,state,reason,paused_at,resumed_at,updated_at FROM rmm_windows_update_controls WHERE tenant_id=$1",
      [tenantId],
    ),
    pool.query(
      'SELECT * FROM rmm_windows_update_management WHERE tenant_id=$1',
      [tenantId],
    ),
  ])
  const controls = new Map(controlResult.rows.map((row) => [row.update_key, row]))
  const management = new Map(managementResult.rows.map((row) => [row.inventory_id, row]))
  const decisions = []

  for (const device of devices.rows) {
    const policy = await effectiveWindowsPolicy(tenantId, device.inventory_id)
    const managed = await ensureWindowsUpdateManagement(
      tenantId,
      device,
      policy,
      management.get(device.inventory_id) || null,
      options,
    )

    const pendingResult = await pool.query(
      'SELECT * FROM rmm_windows_update_observations WHERE tenant_id=$1 AND inventory_id=$2 AND pending=true ORDER BY first_seen_at,lower(title)',
      [tenantId, device.inventory_id],
    )
    const pending = pendingResult.rows
    if (!pending.length) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id,
        policyId: policy?.id || null,
        state: managed.blocking ? 'blocked' : 'waiting',
        reason: managed.blocking ? managed.reason : 'no_pending_updates',
        decision: { pending: 0, management: managed },
      })
      continue
    }

    if (!policy) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id,
        state: 'waiting', reason: 'no_windows_patch_policy', decision: { pending: pending.length, management: managed },
      })
      continue
    }

    if (managed.blocking) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        state: 'blocked', reason: managed.reason, decision: { pending: pending.length, management: managed },
      })
      decisions.push({ inventoryId: device.inventory_id, policyId: policy.id, state: 'blocked', reason: managed.reason })
      continue
    }

    const rules = normalizedRules(policy)
    const now = new Date()
    const window = windowsMaintenanceWindow(policy, now)
    const evaluated = pending.map((row) => ({
      row,
      eligibility: updateEligibility(
        row,
        rules,
        now,
        { tenantId, policyId: policy.id, inventoryId: device.inventory_id },
        controls.get(row.update_key) || null,
      ),
    }))
    const eligible = evaluated.filter((item) => item.eligibility.eligible).map((item) => item.row)
    const decision = {
      policyId: policy.id, policyName: policy.name, pending: pending.length, eligible: eligible.length,
      window, rules, management: managed,
      updates: evaluated.map(({ row, eligibility }) => ({
        updateKey: row.update_key, title: row.title, updateClass: row.update_class, ...eligibility,
      })),
    }

    if (!rules.autoInstall || !eligible.length || !window.open) {
      const paused = evaluated.find((item) => item.eligibility.reason === 'rollout_paused')
      const waitingWave = evaluated.find((item) => item.eligibility.reason === 'rollout_wave_wait')
      const reason = !rules.autoInstall
        ? 'manual_windows_install'
        : !eligible.length
          ? (paused?.eligibility.reason || waitingWave?.eligibility.reason || evaluated.find((item) => !item.eligibility.eligible)?.eligibility.reason || 'no_eligible_updates')
          : 'outside_maintenance_window'
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        state: eligible.length ? 'eligible' : 'waiting', reason,
        eligibleKeys: eligible.map((row) => row.update_key), decision,
      })
      decisions.push({ inventoryId: device.inventory_id, policyId: policy.id, state: eligible.length ? 'eligible' : 'waiting', reason })
      continue
    }

    if (!versionAtLeast(device.agent_version, '0.1.210')) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        state: 'blocked', reason: 'agent_upgrade_required',
        eligibleKeys: eligible.map((row) => row.update_key),
        decision: { ...decision, requiredAgentVersion: '0.1.210', currentAgentVersion: clean(device.agent_version) },
      })
      decisions.push({ inventoryId: device.inventory_id, policyId: policy.id, state: 'blocked', reason: 'agent_upgrade_required' })
      continue
    }

    const socket = typeof options.agentSocketForDevice === 'function' ? options.agentSocketForDevice(device.agent_device_id) : null
    if (!socket || socket.readyState !== 1) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        state: 'offline', reason: 'device_offline', eligibleKeys: eligible.map((row) => row.update_key), decision,
      })
      continue
    }

    const active = await pool.query(
      "SELECT id,status FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='windows_update.install' " +
      "AND request_metadata->>'source'='windows_patch_schedule' AND status IN ('queued','claimed') ORDER BY created_at DESC LIMIT 1",
      [tenantId, device.agent_device_id],
    )
    if (active.rowCount) {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        agentJobId: active.rows[0].id, state: 'dispatched', reason: 'install_already_running',
        eligibleKeys: eligible.map((row) => row.update_key), decision,
      })
      continue
    }

    if (options.dispatch === false || typeof options.sendAgentMessage !== 'function') {
      await saveDecision({
        tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
        state: 'eligible', reason: 'ready_to_dispatch', eligibleKeys: eligible.map((row) => row.update_key), decision,
      })
      continue
    }

    const pushed = await dispatchInstall(tenantId, device, policy, eligible, options.sendAgentMessage)
    const alreadyRunning = pushed.error === 'install_already_running'
    await saveDecision({
      tenantId, inventoryId: device.inventory_id, agentDeviceId: device.agent_device_id, policyId: policy.id,
      agentJobId: pushed.jobId,
      state: pushed.dispatched || alreadyRunning ? 'dispatched' : (pushed.error === 'device_offline' ? 'offline' : 'failed'),
      reason: pushed.dispatched ? 'scheduled_install_dispatched' : pushed.error,
      eligibleKeys: eligible.map((row) => row.update_key), decision, dispatched: pushed.dispatched,
    })
    decisions.push({ inventoryId: device.inventory_id, policyId: policy.id, ...pushed })
  }
  return decisions
}

export async function windowsUpdateBundle(tenantId) {
  const [observations, decisions, controlsResult, jobsResult, managementResult] = await Promise.all([
    pool.query(
      'SELECT o.*,i.reference AS device_reference,i.name AS device_name,a.agent_version,a.websocket_status,a.last_telemetry_at ' +
      'FROM rmm_windows_update_observations o JOIN rmm_device_inventory i ON i.id=o.inventory_id ' +
      'LEFT JOIN rmm_agent_devices a ON a.id=o.agent_device_id AND a.disabled_at IS NULL ' +
      'WHERE o.tenant_id=$1 ORDER BY o.pending DESC,lower(i.name),o.update_class,o.first_seen_at,lower(o.title)',
      [tenantId],
    ),
    pool.query(
      'SELECT d.*,p.name AS policy_name,p.maintenance_window,p.windows_rules,p.reboot_policy,i.name AS device_name,i.reference AS device_reference,' +
      'j.status AS job_status,j.result AS job_result,j.error_message AS job_error,j.created_at AS job_created_at ' +
      'FROM rmm_windows_patch_decisions d JOIN rmm_device_inventory i ON i.id=d.inventory_id ' +
      'LEFT JOIN rmm_patch_policies p ON p.id=d.policy_id LEFT JOIN rmm_agent_jobs j ON j.id=d.agent_job_id ' +
      'WHERE d.tenant_id=$1 ORDER BY lower(i.name)',
      [tenantId],
    ),
    pool.query(
      'SELECT update_key,state,reason,paused_at,resumed_at,updated_at FROM rmm_windows_update_controls WHERE tenant_id=$1 ORDER BY updated_at DESC',
      [tenantId],
    ),
    pool.query(
      "SELECT j.id,j.agent_device_id,j.job_type,j.status,j.result,j.request_metadata,j.created_at,j.completed_at," +
      "a.inventory_id,a.agent_version,a.websocket_status,a.last_telemetry_at,i.name AS device_name,i.reference AS device_reference " +
      "FROM rmm_agent_jobs j LEFT JOIN rmm_agent_devices a ON a.id=j.agent_device_id " +
      "LEFT JOIN rmm_device_inventory i ON i.id=a.inventory_id " +
      "WHERE j.tenant_id=$1 AND j.job_type IN ('windows_update.install','windows_update.rollback') " +
      "AND j.created_at > now()-interval '90 days' ORDER BY j.created_at DESC",
      [tenantId],
    ),
    pool.query(
      'SELECT m.*,i.name AS device_name,i.reference AS device_reference,a.agent_version,a.websocket_status,a.last_telemetry_at ' +
      'FROM rmm_windows_update_management m JOIN rmm_device_inventory i ON i.id=m.inventory_id ' +
      'LEFT JOIN rmm_agent_devices a ON a.id=m.agent_device_id AND a.disabled_at IS NULL ' +
      'WHERE m.tenant_id=$1 ORDER BY lower(i.name)',
      [tenantId],
    ),
  ])
  const pending = observations.rows.filter((row) => row.pending)
  const byClass = {}
  for (const row of pending) byClass[row.update_class] = (byClass[row.update_class] || 0) + 1
  const controls = new Map(controlsResult.rows.map((row) => [row.update_key, row]))
  const recentKeys = new Set()
  for (const job of jobsResult.rows) {
    for (const key of array(object(job.request_metadata).update_keys)) recentKeys.add(clean(key))
    const oneKey = clean(object(job.request_metadata).update_key)
    if (oneKey) recentKeys.add(oneKey)
  }
  const releaseRows = observations.rows.filter((row) => row.pending || recentKeys.has(row.update_key))
  const releaseMap = releaseRows.reduce((result, row) => {
    let release = result.get(row.update_key)
    if (!release) {
      const control = controls.get(row.update_key) || null
      release = {
        updateKey: row.update_key,
        updateId: row.update_id,
        revisionNumber: row.revision_number,
        title: row.title,
        kbArticles: row.kb_articles,
        updateClass: row.update_class,
        severity: row.severity,
        releaseAt: row.release_at,
        firstSeenAt: row.first_seen_at,
        devices: 0,
        observedDevices: 0,
        downloadedDevices: 0,
        rollbackTargets: [],
        control,
        paused: control?.state === 'paused',
      }
      result.set(row.update_key, release)
    }
    release.observedDevices += 1
    if (row.pending) {
      release.devices += 1
      if (row.downloaded) release.downloadedDevices += 1
    }
    return result
  }, new Map())

  const rolledBack = new Set()
  for (const job of jobsResult.rows) {
    if (job.job_type !== 'windows_update.rollback' || job.status !== 'completed') continue
    if (clean(object(job.result).status) !== 'ok') continue
    const key = clean(object(job.request_metadata).update_key)
    if (key) rolledBack.add(job.agent_device_id + ':' + key)
  }
  const targetMaps = new Map()
  for (const job of jobsResult.rows) {
    if (job.job_type !== 'windows_update.install' || job.status !== 'completed') continue
    const resultItems = array(object(job.result).results)
    if (!resultItems.length) continue
    for (const release of releaseMap.values()) {
      if (rolledBack.has(job.agent_device_id + ':' + release.updateKey)) continue
      const releaseId = clean(release.updateId).toLowerCase()
      const releaseKbs = new Set(array(release.kbArticles).map((value) => clean(value).toUpperCase()))
      const match = resultItems.find((item) => {
        if (releaseId && clean(item?.update_id).toLowerCase() === releaseId) return true
        return array(item?.kb_articles).some((kb) => releaseKbs.has(clean(kb).toUpperCase()))
      })
      if (match?.rollback_supported !== true) continue
      let targets = targetMaps.get(release.updateKey)
      if (!targets) {
        targets = new Map()
        targetMaps.set(release.updateKey, targets)
      }
      if (targets.has(job.agent_device_id)) continue
      const online = job.websocket_status === 'Connected'
        && job.last_telemetry_at
        && Date.now() - new Date(job.last_telemetry_at).getTime() <= 90000
      targets.set(job.agent_device_id, {
        agentDeviceId: job.agent_device_id,
        inventoryId: job.inventory_id,
        deviceName: job.device_name,
        deviceReference: job.device_reference,
        agentVersion: job.agent_version,
        online,
        rollbackReady: versionAtLeast(job.agent_version, '0.1.210'),
        installJobId: job.id,
        installedAt: job.completed_at,
      })
    }
  }
  const releases = [...releaseMap.values()]
  for (const release of releases) {
    release.rollbackTargets = [...(targetMaps.get(release.updateKey)?.values() || [])]
    release.rollbackAvailableDevices = release.rollbackTargets.length
    release.rollbackOnlineDevices = release.rollbackTargets.filter((target) => target.online && target.rollbackReady).length
  }
  return {
    summary: {
      pending: pending.length,
      devices: new Set(pending.map((row) => row.inventory_id)).size,
      critical: byClass.critical || 0,
      security: byClass.security || 0,
      quality: byClass.quality || 0,
      feature: byClass.feature || 0,
      driver: byClass.driver || 0,
      definition: byClass.definition || 0,
      other: byClass.other || 0,
      pausedReleases: releases.filter((row) => row.paused).length,
      rollbackAvailable: releases.reduce((sum, row) => sum + row.rollbackAvailableDevices, 0),
      managedDevices: managementResult.rows.filter((row) => row.applied_managed === true).length,
      managementConflicts: managementResult.rows.filter((row) => row.desired_managed === true && clean(row.last_error)).length,
      rebootRequired: decisions.rows.filter((row) => row.state === 'reboot_required').length,
    },
    observations: observations.rows,
    decisions: decisions.rows,
    controls: controlsResult.rows,
    management: managementResult.rows,
    releases,
  }
}

export async function setWindowsUpdateControl(tenantId, updateKey, state, options = {}) {
  const normalizedState = state === 'paused' ? 'paused' : 'active'
  const known = await pool.query(
    'SELECT title,kb_articles FROM rmm_windows_update_observations WHERE tenant_id=$1 AND update_key=$2 ORDER BY pending DESC,last_seen_at DESC LIMIT 1',
    [tenantId, updateKey],
  )
  if (!known.rowCount) return null
  const reason = clean(options.reason).slice(0, 1000)
  const result = await pool.query(
    "INSERT INTO rmm_windows_update_controls " +
    "(tenant_id,update_key,state,reason,paused_by_user_id,paused_at,resumed_at,metadata) " +
    "VALUES ($1,$2,$3,$4,$5,CASE WHEN $3='paused' THEN now() ELSE NULL END,CASE WHEN $3='active' THEN now() ELSE NULL END,$6::jsonb) " +
    "ON CONFLICT (tenant_id,update_key) DO UPDATE SET " +
    "state=EXCLUDED.state,reason=EXCLUDED.reason," +
    "paused_by_user_id=CASE WHEN EXCLUDED.state='paused' THEN EXCLUDED.paused_by_user_id ELSE rmm_windows_update_controls.paused_by_user_id END," +
    "paused_at=CASE WHEN EXCLUDED.state='paused' THEN now() ELSE rmm_windows_update_controls.paused_at END," +
    "resumed_at=CASE WHEN EXCLUDED.state='active' THEN now() ELSE rmm_windows_update_controls.resumed_at END," +
    "metadata=EXCLUDED.metadata,updated_at=now() RETURNING *",
    [
      tenantId,
      updateKey,
      normalizedState,
      reason,
      options.userId || null,
      JSON.stringify({ source: 'windows_update_rollout_console' }),
    ],
  )
  if (normalizedState === 'paused') {
    await pool.query(
      "UPDATE rmm_agent_jobs SET status='cancelled',completed_at=now()," +
      "error_message='Windows Update rollout was paused before dispatch.',updated_at=now() " +
      "WHERE tenant_id=$1 AND job_type='windows_update.install' AND status='queued' " +
      "AND request_metadata->>'source'='windows_patch_schedule' AND (request_metadata->'update_keys') ? $2",
      [tenantId, updateKey],
    ).catch(() => null)
  }
  return { control: result.rows[0], release: known.rows[0] }
}

export async function dispatchWindowsUpdateRollback(tenantId, updateKey, options = {}) {
  const bundle = await windowsUpdateBundle(tenantId)
  const release = bundle.releases.find((row) => row.updateKey === updateKey)
  if (!release) return { error: 'update_not_found', results: [] }

  const requestedIds = new Set(array(options.agentDeviceIds).map(clean).filter(Boolean))
  const targets = release.rollbackTargets.filter((target) => !requestedIds.size || requestedIds.has(target.agentDeviceId))
  if (!targets.length) return { error: 'rollback_not_supported', release, results: [] }

  await setWindowsUpdateControl(tenantId, updateKey, 'paused', {
    userId: options.userId || null,
    reason: clean(options.pauseReason) || 'Paused automatically before Windows Update rollback',
  })

  const results = []
  for (const target of targets) {
    if (!target.rollbackReady) {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'blocked', reason: 'agent_upgrade_required', requiredAgentVersion: '0.1.210' })
      continue
    }
    const socket = typeof options.agentSocketForDevice === 'function' ? options.agentSocketForDevice(target.agentDeviceId) : null
    if (!socket || socket.readyState !== 1) {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'offline', reason: 'device_offline' })
      continue
    }
    const active = await pool.query(
      "SELECT id,status FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='windows_update.rollback' " +
      "AND status IN ('queued','claimed') AND request_metadata->>'source'='windows_update_rollback' ORDER BY created_at DESC LIMIT 1",
      [tenantId, target.agentDeviceId],
    )
    if (active.rowCount) {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'running', jobId: active.rows[0].id })
      continue
    }
    if (options.dispatch === false || typeof options.sendAgentMessage !== 'function') {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'ready' })
      continue
    }

    const payload = {
      update_ids: release.updateId ? [release.updateId] : [],
      kb_articles: array(release.kbArticles),
      titles: [release.title],
      timeout_seconds: 7200,
    }
    const metadata = {
      source: 'windows_update_rollback',
      update_key: release.updateKey,
      update_id: release.updateId,
      kb_articles: array(release.kbArticles),
      title: release.title,
      install_job_id: target.installJobId,
    }
    const inserted = await pool.query(
      "INSERT INTO rmm_agent_jobs " +
      "(tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata) " +
      "VALUES ($1,$2,'windows_update.rollback',$3::jsonb,$4,$5,$6,$7::jsonb) ON CONFLICT DO NOTHING " +
      "RETURNING id,status,created_at",
      [
        tenantId,
        target.agentDeviceId,
        JSON.stringify(payload),
        options.userId || null,
        clean(options.actorType) || 'technician',
        clean(options.actorLabel) || 'Technician',
        JSON.stringify(metadata),
      ],
    )
    if (!inserted.rowCount) {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'running', reason: 'rollback_already_running' })
      continue
    }
    const job = inserted.rows[0]
    const claimed = await pool.query(
      "UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND status='queued' RETURNING id",
      [job.id],
    )
    if (!claimed.rowCount) {
      results.push({ agentDeviceId: target.agentDeviceId, status: 'failed', jobId: job.id, reason: 'claim_failed' })
      continue
    }
    const pushed = options.sendAgentMessage(target.agentDeviceId, {
      type: 'job_execute',
      job: { id: job.id, job_type: 'windows_update.rollback', payload, created_at: job.created_at },
    })
    if (!pushed) {
      await pool.query(
        "UPDATE rmm_agent_jobs SET status='cancelled',completed_at=now(),error_message='Device went offline before Windows Update rollback dispatch.',updated_at=now() WHERE id=$1",
        [job.id],
      )
      results.push({ agentDeviceId: target.agentDeviceId, status: 'offline', jobId: job.id, reason: 'device_offline' })
      continue
    }
    await recordRmmActivity({
      tenantId,
      agentDeviceId: target.agentDeviceId,
      inventoryId: target.inventoryId,
      actorUserId: options.userId || null,
      actorType: clean(options.actorType) || 'technician',
      actorLabel: clean(options.actorLabel) || 'Technician',
      eventType: 'windows_updates.rollback_requested',
      category: 'updates',
      summary: (clean(options.actorLabel) || 'Technician') + ': requested Windows Update rollback',
      detail: release.title + (array(release.kbArticles).length ? ' · ' + array(release.kbArticles).join(', ') : ''),
      outcome: 'requested',
      severity: 'warning',
      jobId: job.id,
      metadata,
    }).catch(() => null)
    results.push({ agentDeviceId: target.agentDeviceId, status: 'dispatched', jobId: job.id })
  }
  return { release, results }
}

export async function reconcileWindowsUpdateJobResult(job, resultPayload = {}, success = false) {
  const jobType = clean(job?.job_type)
  if (jobType === 'windows_update.manage') {
    const resultStatus = clean(resultPayload.status || object(resultPayload.parsed).status).toLowerCase()
    const notApplicable = ['conflict', 'unsupported', 'not_applicable'].includes(resultStatus)
    const managedKnown = typeof resultPayload.managed === 'boolean'
    const appliedManaged = managedKnown ? resultPayload.managed : null
    const detail = [
      clean(resultPayload.message),
      array(resultPayload.conflicts).join(', '),
      array(resultPayload.mdm_signals).join(', '),
      !notApplicable ? clean(job.error_message) : '',
    ].filter(Boolean).join(' · ')
    await pool.query(
      'UPDATE rmm_windows_update_management SET ' +
      'applied_managed=CASE WHEN $3::boolean IS NULL THEN applied_managed ELSE $3 END,' +
      'agent_job_id=$4,last_result=$5::jsonb,last_error=$6,' +
      'last_applied_at=CASE WHEN $7 THEN now() ELSE last_applied_at END,updated_at=now() ' +
      'WHERE tenant_id=$1 AND inventory_id=$2',
      [
        job.tenant_id,
        job.inventory_id,
        appliedManaged,
        job.id,
        JSON.stringify(resultPayload),
        notApplicable || success ? '' : (detail || 'Windows Update management policy could not be applied.'),
        notApplicable || success,
      ],
    )
    await recordRmmActivity({
      tenantId: job.tenant_id,
      agentDeviceId: job.agent_device_id,
      inventoryId: job.inventory_id || null,
      actorType: 'system',
      actorLabel: 'SYSTEM',
      eventType: notApplicable
        ? 'windows_updates.management_not_applicable'
        : success
          ? (appliedManaged ? 'windows_updates.management_applied' : 'windows_updates.management_removed')
          : 'windows_updates.management_failed',
      category: 'updates',
      summary: notApplicable
        ? 'SYSTEM: Windows Update management is not applicable'
        : success
          ? (appliedManaged ? 'SYSTEM: Windows Update is now managed by Hi5Central' : 'SYSTEM: Hi5Central Windows Update management removed')
          : 'SYSTEM: Windows Update management could not be applied',
      detail,
      outcome: notApplicable ? 'not_applicable' : (success ? 'success' : 'failed'),
      severity: notApplicable || success ? 'info' : 'warning',
      jobId: job.id,
      metadata: { result: resultPayload, request: object(job.request_metadata) },
    }).catch(() => null)
    return
  }
  if (jobType === 'windows_update.rollback') {
    const rebootRequired = resultPayload.reboot_required === true || resultPayload.rebootRequired === true
    await recordRmmActivity({
      tenantId: job.tenant_id,
      agentDeviceId: job.agent_device_id,
      inventoryId: job.inventory_id || null,
      actorType: clean(job.initiated_by) || 'technician',
      actorLabel: clean(job.initiated_by_label) || 'Technician',
      eventType: 'windows_updates.rollback_completed',
      category: 'updates',
      summary: success
        ? 'Windows Update rollback completed' + (rebootRequired ? ' · reboot required' : '')
        : 'Windows Update rollback failed',
      detail: [
        resultPayload.selected_count != null ? String(resultPayload.selected_count) + ' update(s) selected' : '',
        clean(resultPayload.rollback_result), clean(resultPayload.message), clean(job.error_message),
      ].filter(Boolean).join(' · '),
      outcome: success ? 'success' : 'failed',
      severity: success ? (rebootRequired ? 'warning' : 'info') : 'warning',
      jobId: job.id,
      metadata: { result: resultPayload, request: object(job.request_metadata) },
    }).catch(() => null)
    return
  }
  if (jobType !== 'windows_update.install') return
  const rebootRequired = resultPayload.reboot_required === true || resultPayload.rebootRequired === true
  const state = success ? (rebootRequired ? 'reboot_required' : 'completed') : 'failed'
  await pool.query(
    'UPDATE rmm_windows_patch_decisions SET state=$2,reason=$3,completed_at=now(),updated_at=now(),decision=decision || $4::jsonb ' +
    'WHERE tenant_id=$1 AND agent_job_id=$5',
    [
      job.tenant_id, state,
      success ? (rebootRequired ? 'install_completed_reboot_required' : 'install_completed') : 'install_failed',
      JSON.stringify({ result: resultPayload, completedAt: new Date().toISOString() }),
      job.id,
    ],
  )
  await recordRmmActivity({
    tenantId: job.tenant_id,
    agentDeviceId: job.agent_device_id,
    inventoryId: job.inventory_id || null,
    actorType: clean(job.initiated_by) || 'system',
    actorLabel: clean(job.initiated_by_label) || 'SYSTEM',
    eventType: 'windows_updates.install_completed',
    category: 'updates',
    summary: success
      ? 'SYSTEM: Windows Update install completed' + (rebootRequired ? ' · reboot required' : '')
      : 'SYSTEM: Windows Update install failed',
    detail: [
      resultPayload.selected_count != null ? String(resultPayload.selected_count) + ' update(s) selected' : '',
      clean(resultPayload.install_result), clean(job.error_message),
    ].filter(Boolean).join(' · '),
    outcome: success ? 'success' : 'failed',
    severity: success && rebootRequired ? 'warning' : (success ? 'info' : 'warning'),
    jobId: job.id,
    metadata: { result: resultPayload },
  }).catch(() => null)
}
