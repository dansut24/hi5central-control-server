import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { recordRmmActivity } from './rmmActivity.js'
import { resolveSession } from './session.js'

function clean(value = '') { return String(value ?? '').trim() }
function asObject(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function asArray(value) { return Array.isArray(value) ? value : [] }
function ci(value = '') { return clean(value).toLowerCase() }
function includesCi(value, needle) { return !clean(needle) || ci(value).includes(ci(needle)) }
function priorityForScope(scopeType) {
  return ({ Estate: 100, Site: 220, Group: 340, Device: 900 })[scopeType] || 100
}

async function requireScopeAccess(c, manage = false, policy = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  const required = policy
    ? (manage ? ['rmm.policies.manage'] : ['rmm.policies.view', 'rmm.policies.manage', 'rmm.devices.view'])
    : (manage ? ['rmm.groups.manage'] : ['rmm.groups.view', 'rmm.groups.manage', 'rmm.policies.view', 'rmm.policies.manage', 'rmm.devices.view'])
  if (!required.some((permission) => hasPermission(session.access, permission))) {
    return { error: c.json({ error: 'You do not have permission to access this RMM configuration.' }, 403) }
  }
  return { session }
}

async function requireSavedViewAccess(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!['rmm.groups.view', 'rmm.groups.manage', 'rmm.devices.view'].some((permission) => hasPermission(session.access, permission))) {
    return { error: c.json({ error: 'You do not have permission to save RMM views.' }, 403) }
  }
  return { session }
}

async function audit(session, eventType, summary, detail = '', metadata = {}) {
  await recordRmmActivity({
    tenantId: session.tenant_id,
    actorUserId: session.user_id,
    actorType: 'technician',
    actorLabel: session.name || session.email || 'Technician',
    eventType,
    category: 'policy',
    summary,
    detail,
    outcome: 'success',
    metadata,
  }).catch(() => null)
}

async function scopeDeviceRows(tenantId) {
  const sql = [
    "SELECT d.id,d.reference,d.name,d.platform,d.operating_system,d.os_version,d.manufacturer,d.model,",
    "       d.user_display_name,d.user_principal_name,d.category_name,d.compliance_state,d.is_encrypted,d.source,d.source_payload,",
    "       p.name AS assigned_person_name,p.email AS assigned_person_email,",
    "       os.external_key AS site_id,os.name AS site_name,",
    "       CASE WHEN COALESCE(self_agent.websocket_status,agent_match.websocket_status)='Connected'",
    "             AND COALESCE(self_agent.last_telemetry_at,agent_match.last_telemetry_at)>now()-interval '90 seconds'",
    "            THEN true ELSE false END AS agent_online,",
    "       CASE WHEN d.source='hi5central_agent' THEN d.source_payload ELSE agent_match.agent_payload END AS agent_payload",
    "  FROM rmm_device_inventory d",
    "  LEFT JOIN organisation_people p ON p.tenant_id=d.tenant_id AND p.id=d.assigned_person_id",
    "  LEFT JOIN organisation_sites os ON os.tenant_id=d.tenant_id AND os.id=p.site_id",
    "  LEFT JOIN rmm_agent_devices self_agent ON self_agent.inventory_id=d.id AND self_agent.disabled_at IS NULL",
    "  LEFT JOIN LATERAL (",
    "    SELECT ad.websocket_status,ad.last_telemetry_at,a.source_payload AS agent_payload",
    "      FROM rmm_device_inventory a",
    "      JOIN rmm_agent_devices ad ON ad.inventory_id=a.id AND ad.disabled_at IS NULL",
    "     WHERE a.tenant_id=d.tenant_id AND a.source='hi5central_agent' AND a.active=true AND a.id<>d.id",
    "       AND (",
    "         (NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND NULLIF(trim(a.directory_device_id),'') IS NOT NULL",
    "          AND lower(trim(a.directory_device_id))=lower(trim(d.directory_device_id)))",
    "         OR",
    "         (NULLIF(trim(d.serial_number),'') IS NOT NULL AND NULLIF(trim(a.serial_number),'') IS NOT NULL",
    "          AND lower(trim(a.serial_number))=lower(trim(d.serial_number))",
    "          AND (NULLIF(trim(d.manufacturer),'') IS NULL OR NULLIF(trim(a.manufacturer),'') IS NULL",
    "               OR lower(trim(a.manufacturer))=lower(trim(d.manufacturer))))",
    "       )",
    "     ORDER BY a.updated_at DESC LIMIT 1",
    "  ) agent_match ON d.source='intune'",
    " WHERE d.tenant_id=$1 AND d.active=true",
    "   AND NOT (d.source='hi5central_agent' AND EXISTS (",
    "     SELECT 1 FROM rmm_device_inventory i",
    "      WHERE i.tenant_id=d.tenant_id AND i.source='intune' AND i.active=true",
    "        AND (",
    "          (NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND NULLIF(trim(i.directory_device_id),'') IS NOT NULL",
    "           AND lower(trim(i.directory_device_id))=lower(trim(d.directory_device_id)))",
    "          OR",
    "          (NULLIF(trim(d.serial_number),'') IS NOT NULL AND NULLIF(trim(i.serial_number),'') IS NOT NULL",
    "           AND lower(trim(i.serial_number))=lower(trim(d.serial_number))",
    "           AND (NULLIF(trim(d.manufacturer),'') IS NULL OR NULLIF(trim(i.manufacturer),'') IS NULL",
    "                OR lower(trim(i.manufacturer))=lower(trim(d.manufacturer))))",
    "        )",
    "   ))",
    " ORDER BY d.name",
  ].join(' ')
  const result = await pool.query(sql, [tenantId])
  return result.rows
}

function inventoryPayload(device) {
  return asObject(device.agent_payload && Object.keys(asObject(device.agent_payload)).length
    ? device.agent_payload
    : device.source_payload)
}

function dynamicDeviceMatches(device, rules = {}) {
  const rule = asObject(rules)
  const payload = inventoryPayload(device)
  const software = asArray(asObject(payload.software).items)
  const security = asObject(payload.security)
  const updates = asObject(payload.windows_updates)
  const tags = [
    ...asArray(payload.tags),
    device.category_name,
    device.source,
    device.compliance_state,
  ].filter(Boolean)

  if (clean(rule.siteId) && clean(rule.siteId) !== clean(device.site_id)) return false
  if (!includesCi(device.platform + ' ' + device.operating_system, rule.platformContains)) return false
  if (!includesCi(device.operating_system + ' ' + device.os_version, rule.osContains)) return false
  if (!includesCi(device.manufacturer, rule.manufacturerContains)) return false
  if (!includesCi(device.model, rule.modelContains)) return false
  const userText = [device.assigned_person_name, device.assigned_person_email, device.user_display_name, device.user_principal_name].join(' ')
  if (!includesCi(userText, rule.userContains)) return false
  if (clean(rule.tagContains) && !tags.some((tag) => includesCi(tag, rule.tagContains))) return false

  const onlineState = ci(rule.onlineState)
  if (onlineState === 'online' && !device.agent_online) return false
  if (onlineState === 'offline' && device.agent_online) return false

  const softwareName = clean(rule.softwareNameContains)
  const softwareVersion = clean(rule.softwareVersionContains)
  if (softwareName || softwareVersion) {
    const matched = software.some((item) =>
      includesCi(item?.name, softwareName) && includesCi(item?.version, softwareVersion))
    if (!matched) return false
  }

  const encryption = ci(rule.encryptionState)
  const protectedState = device.is_encrypted === true || ci(security.bitlocker_status) === 'on'
  if (encryption === 'protected' && !protectedState) return false
  if (encryption === 'unprotected' && protectedState) return false

  const updateState = ci(rule.updateState)
  const pendingCount = Number(updates.pending_count || 0)
  if (updateState === 'pending' && !(pendingCount > 0)) return false
  if (updateState === 'clear' && pendingCount > 0) return false

  return true
}

function ruleSummary(rules = {}) {
  const rule = asObject(rules)
  const parts = []
  if (rule.siteId) parts.push('Site = ' + (rule.siteName || rule.siteId))
  if (rule.platformContains) parts.push('Platform contains ' + rule.platformContains)
  if (rule.osContains) parts.push('OS contains ' + rule.osContains)
  if (rule.manufacturerContains) parts.push('Manufacturer contains ' + rule.manufacturerContains)
  if (rule.modelContains) parts.push('Model contains ' + rule.modelContains)
  if (rule.userContains) parts.push('User contains ' + rule.userContains)
  if (rule.tagContains) parts.push('Tag contains ' + rule.tagContains)
  if (rule.onlineState && rule.onlineState !== 'Any') parts.push('State = ' + rule.onlineState)
  if (rule.softwareNameContains) parts.push('Software contains ' + rule.softwareNameContains)
  if (rule.softwareVersionContains) parts.push('Version contains ' + rule.softwareVersionContains)
  if (rule.encryptionState && rule.encryptionState !== 'Any') parts.push('Encryption = ' + rule.encryptionState)
  if (rule.updateState && rule.updateState !== 'Any') parts.push('Updates = ' + rule.updateState)
  return parts.length ? parts.join(' AND ') : 'All devices in scope'
}

async function loadGroups(tenantId, devices) {
  const result = await pool.query(
    "SELECT g.*,mp.name AS monitoring_policy_name," +
    " COALESCE((SELECT jsonb_agg(i.reference ORDER BY i.name) FROM rmm_device_group_memberships gm JOIN rmm_device_inventory i ON i.id=gm.inventory_id WHERE gm.group_id=g.id),'[]'::jsonb) AS static_refs" +
    " FROM rmm_device_groups g LEFT JOIN rmm_monitoring_policies mp ON mp.id=g.monitoring_policy_id" +
    " WHERE g.tenant_id=$1 ORDER BY lower(g.name)",
    [tenantId],
  )
  return result.rows.map((group) => {
    const staticRefs = asArray(group.static_refs)
    const members = group.mode === 'dynamic'
      ? devices.filter((device) => dynamicDeviceMatches(device, group.rules)).map((device) => device.reference)
      : staticRefs
    return {
      id: group.id,
      name: group.name,
      description: group.description || 'Tenant device group.',
      mode: group.mode === 'dynamic' ? 'Dynamic' : 'Static',
      type: group.mode === 'dynamic' ? 'Smart group' : 'Custom',
      siteId: group.site_id || '',
      scope: group.site_id || 'All sites',
      rules: asObject(group.rules),
      ruleText: group.mode === 'dynamic' ? ruleSummary(group.rules) : (members.length ? members.length + ' manually assigned devices' : 'No devices assigned'),
      devices: members.length,
      deviceIds: members,
      monitoringPolicyId: group.monitoring_policy_id || '',
      monitoringPolicy: group.monitoring_policy_name || 'Inherited',
      patchRing: group.patch_ring || 'Inherited',
      softwareProfile: group.software_profile || 'Inherited',
      automationProfile: group.automation_profile || 'Inherited',
      source: 'Server',
      createdAt: group.created_at,
      updatedAt: group.updated_at,
    }
  })
}

async function loadSavedViews(tenantId, userId) {
  const result = await pool.query(
    "SELECT v.*,u.email AS owner_email FROM rmm_saved_views v LEFT JOIN users u ON u.id=v.owner_user_id" +
    " WHERE v.tenant_id=$1 AND (v.owner_user_id=$2 OR v.visibility='shared')" +
    " ORDER BY v.is_default DESC,v.is_favourite DESC,lower(v.name)",
    [tenantId, userId],
  )
  return result.rows.map((view) => ({
    id: view.id,
    name: view.name,
    visibility: view.visibility === 'shared' ? 'Shared' : 'Private',
    owner: view.owner_user_id === userId ? 'You' : (view.owner_email || 'RMM user'),
    builtIn: false,
    description: view.visibility === 'shared' ? 'Shared tenant device view.' : 'Personal device view.',
    filters: asObject(view.filters),
    sort: asObject(view.sort),
    columns: asArray(view.columns),
    favourite: Boolean(view.is_favourite),
    default: Boolean(view.is_default),
  }))
}

async function loadMonitoring(tenantId) {
  const [policiesResult, assignmentsResult, overridesResult] = await Promise.all([
    pool.query(
      "SELECT * FROM rmm_monitoring_policies WHERE tenant_id=$1 AND status<>'archived' ORDER BY lower(name)",
      [tenantId],
    ),
    pool.query(
      "SELECT * FROM rmm_monitoring_assignments WHERE tenant_id=$1 ORDER BY priority,created_at",
      [tenantId],
    ),
    pool.query(
      "SELECT o.*,i.reference AS device_reference FROM rmm_monitoring_device_overrides o" +
      " JOIN rmm_device_inventory i ON i.id=o.inventory_id WHERE o.tenant_id=$1 AND o.enabled=true ORDER BY o.created_at",
      [tenantId],
    ),
  ])
  const policies = policiesResult.rows.map((policy) => ({
    id: policy.id,
    name: policy.name,
    description: policy.description,
    platform: policy.platform,
    category: 'Endpoint',
    evaluation: policy.evaluation,
    alertDelay: policy.alert_delay,
    autoResolve: Boolean(policy.auto_resolve),
    checks: asArray(policy.checks),
    status: policy.status === 'disabled' ? 'Disabled' : 'Active',
    source: 'Server',
  }))
  const assignments = assignmentsResult.rows.map((assignment) => ({
    id: assignment.id,
    policyId: assignment.policy_id,
    scopeType: assignment.scope_type,
    scopeId: assignment.scope_id,
    scopeName: assignment.scope_name,
    priority: assignment.priority,
    enabled: Boolean(assignment.enabled),
    source: 'Server',
  }))
  const overrides = overridesResult.rows.map((override) => ({
    id: override.id,
    deviceId: override.device_reference,
    policyId: override.policy_id,
    checkOverrides: asObject(override.check_overrides),
    reason: override.reason,
    enabled: Boolean(override.enabled),
    source: 'Server',
  }))
  return { policies, assignments, overrides }
}

function resolveEffectivePolicies(devices, groups, monitoring) {
  const policyMap = new Map(monitoring.policies.map((policy) => [policy.id, policy]))
  const groupMembers = new Map(groups.map((group) => [group.id, new Set(group.deviceIds || [])]))
  const rank = { Estate: 1, Site: 2, Group: 3, Device: 4 }
  return devices.map((device) => {
    const candidates = monitoring.assignments.filter((assignment) => {
      if (!assignment.enabled) return false
      if (assignment.scopeType === 'Estate') return true
      if (assignment.scopeType === 'Site') return clean(device.site_id) === clean(assignment.scopeId)
      if (assignment.scopeType === 'Group') return groupMembers.get(assignment.scopeId)?.has(device.reference) || false
      if (assignment.scopeType === 'Device') return clean(assignment.scopeId) === clean(device.reference) || clean(assignment.scopeId) === clean(device.id)
      return false
    }).sort((a, b) => {
      const rankDelta = (rank[a.scopeType] || 0) - (rank[b.scopeType] || 0)
      return rankDelta || Number(a.priority || 0) - Number(b.priority || 0)
    })
    const override = monitoring.overrides.filter((item) => item.enabled && item.deviceId === device.reference).slice(-1)[0] || null
    const winner = candidates[candidates.length - 1] || null
    const policyId = override?.policyId || winner?.policyId || ''
    const chain = candidates.map((item) => ({
      ...item,
      policy: policyMap.get(item.policyId) || null,
      winning: !override && item.id === winner?.id,
    }))
    if (override) {
      chain.push({
        id: override.id,
        policyId: override.policyId,
        scopeType: 'Device override',
        scopeId: device.reference,
        scopeName: device.name,
        priority: 1000,
        enabled: true,
        policy: policyMap.get(override.policyId) || null,
        winning: true,
        reason: override.reason,
      })
    }
    return {
      deviceId: device.reference,
      inventoryId: device.id,
      policyId,
      policy: policyMap.get(policyId) || null,
      assignment: override || winner,
      override,
      chain,
    }
  })
}

async function scopeBundle(session) {
  const devices = await scopeDeviceRows(session.tenant_id)
  const monitoring = await loadMonitoring(session.tenant_id)
  const groups = await loadGroups(session.tenant_id, devices)
  const savedViews = await loadSavedViews(session.tenant_id, session.user_id)
  return {
    groups,
    savedViews,
    monitoring: {
      ...monitoring,
      effectivePolicies: resolveEffectivePolicies(devices, groups, monitoring),
    },
  }
}

async function resolveInventoryIds(tenantId, refs) {
  const values = asArray(refs).map(clean).filter(Boolean).slice(0, 1000)
  if (!values.length) return []
  const result = await pool.query(
    "SELECT id FROM rmm_device_inventory WHERE tenant_id=$1 AND active=true AND (reference=ANY($2::text[]) OR id::text=ANY($2::text[]))",
    [tenantId, values],
  )
  return result.rows.map((row) => row.id)
}

export function registerRmmScopeRoutes(app) {
  app.get('/api/v1/rmm/scope', async (c) => {
    const auth = await requireScopeAccess(c, false, false)
    if (auth.error) return auth.error
    return c.json(await scopeBundle(auth.session))
  })

  app.post('/api/v1/rmm/groups', async (c) => {
    const auth = await requireScopeAccess(c, true, false)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    const mode = ci(body.mode) === 'dynamic' ? 'dynamic' : 'static'
    if (name.length < 2) return c.json({ error: 'Group name must be at least 2 characters.' }, 400)
    const ids = await resolveInventoryIds(auth.session.tenant_id, body.deviceIds)
    const result = await withTransaction(async (client) => {
      const inserted = await client.query(
        "INSERT INTO rmm_device_groups (tenant_id,name,description,mode,site_id,rules,patch_ring,software_profile,automation_profile,created_by_user_id,updated_by_user_id)" +
        " VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$10) RETURNING id",
        [
          auth.session.tenant_id,
          name,
          clean(body.description).slice(0, 1000) || 'Tenant device group.',
          mode,
          clean(body.siteId).slice(0, 255),
          JSON.stringify(asObject(body.rules)),
          clean(body.patchRing).slice(0, 160) || 'Inherited',
          clean(body.softwareProfile).slice(0, 160) || 'Inherited',
          clean(body.automationProfile).slice(0, 160) || 'Inherited',
          auth.session.user_id,
        ],
      )
      const groupId = inserted.rows[0].id
      if (mode === 'static') {
        for (const inventoryId of ids) {
          await client.query(
            "INSERT INTO rmm_device_group_memberships (group_id,tenant_id,inventory_id,added_by_user_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            [groupId, auth.session.tenant_id, inventoryId, auth.session.user_id],
          )
        }
      }
      return groupId
    })
    await audit(auth.session, 'group.created', 'Created device group “' + name + '”', mode === 'dynamic' ? ruleSummary(body.rules) : ids.length + ' static members', { groupId: result, mode })
    return c.json({ success: true, id: result, bundle: await scopeBundle(auth.session) }, 201)
  })

  app.put('/api/v1/rmm/groups/:groupId', async (c) => {
    const auth = await requireScopeAccess(c, true, false)
    if (auth.error) return auth.error
    const groupId = clean(c.req.param('groupId'))
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    const mode = ci(body.mode) === 'dynamic' ? 'dynamic' : 'static'
    if (name.length < 2) return c.json({ error: 'Group name must be at least 2 characters.' }, 400)
    const ids = await resolveInventoryIds(auth.session.tenant_id, body.deviceIds)
    const updated = await withTransaction(async (client) => {
      const result = await client.query(
        "UPDATE rmm_device_groups SET name=$3,description=$4,mode=$5,site_id=$6,rules=$7::jsonb,patch_ring=$8,software_profile=$9,automation_profile=$10,updated_by_user_id=$11,updated_at=now()" +
        " WHERE id=$1 AND tenant_id=$2 RETURNING id",
        [
          groupId,
          auth.session.tenant_id,
          name,
          clean(body.description).slice(0, 1000),
          mode,
          clean(body.siteId).slice(0, 255),
          JSON.stringify(asObject(body.rules)),
          clean(body.patchRing).slice(0, 160) || 'Inherited',
          clean(body.softwareProfile).slice(0, 160) || 'Inherited',
          clean(body.automationProfile).slice(0, 160) || 'Inherited',
          auth.session.user_id,
        ],
      )
      if (!result.rowCount) return false
      await client.query("DELETE FROM rmm_device_group_memberships WHERE group_id=$1 AND tenant_id=$2", [groupId, auth.session.tenant_id])
      if (mode === 'static') {
        for (const inventoryId of ids) {
          await client.query(
            "INSERT INTO rmm_device_group_memberships (group_id,tenant_id,inventory_id,added_by_user_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            [groupId, auth.session.tenant_id, inventoryId, auth.session.user_id],
          )
        }
      }
      return true
    })
    if (!updated) return c.json({ error: 'Device group not found.' }, 404)
    await audit(auth.session, 'group.updated', 'Updated device group “' + name + '”', '', { groupId, mode })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.delete('/api/v1/rmm/groups/:groupId', async (c) => {
    const auth = await requireScopeAccess(c, true, false)
    if (auth.error) return auth.error
    const groupId = clean(c.req.param('groupId'))
    const deleted = await withTransaction(async (client) => {
      const found = await client.query("SELECT name FROM rmm_device_groups WHERE id=$1 AND tenant_id=$2", [groupId, auth.session.tenant_id])
      if (!found.rowCount) return null
      await client.query("DELETE FROM rmm_monitoring_assignments WHERE tenant_id=$1 AND scope_type='Group' AND scope_id=$2", [auth.session.tenant_id, groupId])
      await client.query("DELETE FROM rmm_device_groups WHERE id=$1 AND tenant_id=$2", [groupId, auth.session.tenant_id])
      return found.rows[0].name
    })
    if (!deleted) return c.json({ error: 'Device group not found.' }, 404)
    await audit(auth.session, 'group.deleted', 'Deleted device group “' + deleted + '”', '', { groupId })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.post('/api/v1/rmm/saved-views', async (c) => {
    const auth = await requireSavedViewAccess(c)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    if (name.length < 2) return c.json({ error: 'View name must be at least 2 characters.' }, 400)
    const visibility = ci(body.visibility) === 'shared' ? 'shared' : 'private'
    const makeDefault = Boolean(body.default)
    const result = await withTransaction(async (client) => {
      if (makeDefault) {
        await client.query(
          "UPDATE rmm_saved_views SET is_default=false,updated_at=now() WHERE tenant_id=$1 AND owner_user_id=$2 AND is_default=true",
          [auth.session.tenant_id, auth.session.user_id],
        )
      }
      return client.query(
        "INSERT INTO rmm_saved_views (tenant_id,owner_user_id,name,visibility,filters,sort,columns,is_favourite,is_default)" +
        " VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8,$9) RETURNING id",
        [
          auth.session.tenant_id,
          auth.session.user_id,
          name,
          visibility,
          JSON.stringify(asObject(body.filters)),
          JSON.stringify(asObject(body.sort)),
          JSON.stringify(asArray(body.columns).slice(0, 50)),
          Boolean(body.favourite),
          makeDefault,
        ],
      )
    })
    await audit(auth.session, 'saved_view.created', 'Created ' + visibility + ' saved view “' + name + '”', '', { savedViewId: result.rows[0].id })
    return c.json({ success: true, id: result.rows[0].id, bundle: await scopeBundle(auth.session) }, 201)
  })

  app.patch('/api/v1/rmm/saved-views/:viewId', async (c) => {
    const auth = await requireSavedViewAccess(c)
    if (auth.error) return auth.error
    const viewId = clean(c.req.param('viewId'))
    const body = await c.req.json().catch(() => ({}))
    const result = await withTransaction(async (client) => {
      if (body.default === true) {
        await client.query(
          "UPDATE rmm_saved_views SET is_default=false,updated_at=now() WHERE tenant_id=$1 AND owner_user_id=$2 AND id<>$3 AND is_default=true",
          [auth.session.tenant_id, auth.session.user_id, viewId],
        )
      }
      return client.query(
        "UPDATE rmm_saved_views SET is_favourite=COALESCE($4,is_favourite),is_default=COALESCE($5,is_default)," +
        " visibility=COALESCE($6,visibility),updated_at=now()" +
        " WHERE id=$1 AND tenant_id=$2 AND owner_user_id=$3 RETURNING name",
        [
          viewId,
          auth.session.tenant_id,
          auth.session.user_id,
          typeof body.favourite === 'boolean' ? body.favourite : null,
          typeof body.default === 'boolean' ? body.default : null,
          ['private', 'shared'].includes(ci(body.visibility)) ? ci(body.visibility) : null,
        ],
      )
    })
    if (!result.rowCount) return c.json({ error: 'Saved view not found or not owned by you.' }, 404)
    await audit(auth.session, 'saved_view.updated', 'Updated saved view “' + result.rows[0].name + '”', '', { savedViewId: viewId })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.delete('/api/v1/rmm/saved-views/:viewId', async (c) => {
    const auth = await requireSavedViewAccess(c)
    if (auth.error) return auth.error
    const viewId = clean(c.req.param('viewId'))
    const result = await pool.query(
      "DELETE FROM rmm_saved_views WHERE id=$1 AND tenant_id=$2 AND owner_user_id=$3 RETURNING name",
      [viewId, auth.session.tenant_id, auth.session.user_id],
    )
    if (!result.rowCount) return c.json({ error: 'Saved view not found or not owned by you.' }, 404)
    await audit(auth.session, 'saved_view.deleted', 'Deleted saved view “' + result.rows[0].name + '”', '', { savedViewId: viewId })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.post('/api/v1/rmm/monitoring-policies', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    if (name.length < 2) return c.json({ error: 'Policy name must be at least 2 characters.' }, 400)
    const result = await pool.query(
      "INSERT INTO rmm_monitoring_policies (tenant_id,name,description,platform,evaluation,alert_delay,auto_resolve,checks,created_by_user_id,updated_by_user_id)" +
      " VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$9) RETURNING id",
      [
        auth.session.tenant_id,
        name,
        clean(body.description).slice(0, 2000),
        clean(body.platform).slice(0, 120) || 'All',
        clean(body.evaluation).slice(0, 120) || 'Every 5 minutes',
        clean(body.alertDelay).slice(0, 120) || '5 minutes',
        body.autoResolve !== false,
        JSON.stringify(asArray(body.checks).slice(0, 100)),
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'monitoring_policy.created', 'Created monitoring policy “' + name + '”', '', { policyId: result.rows[0].id })
    return c.json({ success: true, id: result.rows[0].id, bundle: await scopeBundle(auth.session) }, 201)
  })

  app.put('/api/v1/rmm/monitoring-policies/:policyId', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const policyId = clean(c.req.param('policyId'))
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name).slice(0, 160)
    if (name.length < 2) return c.json({ error: 'Policy name must be at least 2 characters.' }, 400)
    const result = await pool.query(
      "UPDATE rmm_monitoring_policies SET name=$3,description=$4,platform=$5,evaluation=$6,alert_delay=$7,auto_resolve=$8,checks=$9::jsonb,updated_by_user_id=$10,updated_at=now()" +
      " WHERE id=$1 AND tenant_id=$2 AND status<>'archived' RETURNING id",
      [
        policyId,
        auth.session.tenant_id,
        name,
        clean(body.description).slice(0, 2000),
        clean(body.platform).slice(0, 120) || 'All',
        clean(body.evaluation).slice(0, 120) || 'Every 5 minutes',
        clean(body.alertDelay).slice(0, 120) || '5 minutes',
        body.autoResolve !== false,
        JSON.stringify(asArray(body.checks).slice(0, 100)),
        auth.session.user_id,
      ],
    )
    if (!result.rowCount) return c.json({ error: 'Monitoring policy not found.' }, 404)
    await audit(auth.session, 'monitoring_policy.updated', 'Updated monitoring policy “' + name + '”', '', { policyId })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.delete('/api/v1/rmm/monitoring-policies/:policyId', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const policyId = clean(c.req.param('policyId'))
    const result = await withTransaction(async (client) => {
      const found = await client.query(
        "SELECT name FROM rmm_monitoring_policies WHERE id=$1 AND tenant_id=$2 AND status<>'archived'",
        [policyId, auth.session.tenant_id],
      )
      if (!found.rowCount) return null
      await client.query("UPDATE rmm_monitoring_assignments SET enabled=false,updated_at=now() WHERE tenant_id=$1 AND policy_id=$2", [auth.session.tenant_id, policyId])
      await client.query("UPDATE rmm_monitoring_device_overrides SET enabled=false,updated_at=now() WHERE tenant_id=$1 AND policy_id=$2", [auth.session.tenant_id, policyId])
      await client.query("UPDATE rmm_monitoring_policies SET status='archived',updated_by_user_id=$3,updated_at=now() WHERE id=$1 AND tenant_id=$2", [policyId, auth.session.tenant_id, auth.session.user_id])
      return found.rows[0].name
    })
    if (!result) return c.json({ error: 'Monitoring policy not found.' }, 404)
    await audit(auth.session, 'monitoring_policy.deleted', 'Archived monitoring policy “' + result + '”', '', { policyId })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.post('/api/v1/rmm/monitoring-assignments', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const scopeType = clean(body.scopeType)
    if (!['Estate', 'Site', 'Group', 'Device'].includes(scopeType)) return c.json({ error: 'Invalid monitoring scope type.' }, 400)
    const policyId = clean(body.policyId)
    const policy = await pool.query(
      "SELECT id FROM rmm_monitoring_policies WHERE id=$1 AND tenant_id=$2 AND status='active'",
      [policyId, auth.session.tenant_id],
    )
    if (!policy.rowCount) return c.json({ error: 'Monitoring policy not found.' }, 404)
    const priority = Number.isFinite(Number(body.priority)) ? Math.trunc(Number(body.priority)) : priorityForScope(scopeType)
    const result = await pool.query(
      "INSERT INTO rmm_monitoring_assignments (tenant_id,policy_id,scope_type,scope_id,scope_name,priority,enabled,created_by_user_id)" +
      " VALUES ($1,$2,$3,$4,$5,$6,true,$7) RETURNING id",
      [
        auth.session.tenant_id,
        policyId,
        scopeType,
        clean(body.scopeId).slice(0, 255),
        clean(body.scopeName).slice(0, 255) || scopeType,
        priority,
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'monitoring_assignment.created', 'Assigned monitoring policy to ' + scopeType + ' “' + (clean(body.scopeName) || clean(body.scopeId) || 'Estate') + '”', '', { assignmentId: result.rows[0].id, policyId, scopeType })
    return c.json({ success: true, id: result.rows[0].id, bundle: await scopeBundle(auth.session) }, 201)
  })

  app.delete('/api/v1/rmm/monitoring-assignments/:assignmentId', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const assignmentId = clean(c.req.param('assignmentId'))
    const result = await pool.query(
      "DELETE FROM rmm_monitoring_assignments WHERE id=$1 AND tenant_id=$2 RETURNING scope_type,scope_name,policy_id",
      [assignmentId, auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Monitoring assignment not found.' }, 404)
    await audit(auth.session, 'monitoring_assignment.deleted', 'Removed monitoring assignment from ' + result.rows[0].scope_type + ' “' + result.rows[0].scope_name + '”', '', { assignmentId, policyId: result.rows[0].policy_id })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.delete('/api/v1/rmm/monitoring-overrides/:overrideId', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const overrideId = clean(c.req.param('overrideId'))
    const result = await pool.query(
      "DELETE FROM rmm_monitoring_device_overrides WHERE id=$1 AND tenant_id=$2 RETURNING inventory_id,policy_id,reason",
      [overrideId, auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Monitoring override not found.' }, 404)
    await audit(auth.session, 'monitoring_override.deleted', 'Removed device monitoring override', result.rows[0].reason || '', { overrideId, policyId: result.rows[0].policy_id, inventoryId: result.rows[0].inventory_id })
    return c.json({ success: true, bundle: await scopeBundle(auth.session) })
  })

  app.post('/api/v1/rmm/monitoring-overrides', async (c) => {
    const auth = await requireScopeAccess(c, true, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const inventoryIds = await resolveInventoryIds(auth.session.tenant_id, [body.deviceId])
    if (!inventoryIds.length) return c.json({ error: 'Device not found.' }, 404)
    const policyId = clean(body.policyId)
    const policy = await pool.query(
      "SELECT id FROM rmm_monitoring_policies WHERE id=$1 AND tenant_id=$2 AND status='active'",
      [policyId, auth.session.tenant_id],
    )
    if (!policy.rowCount) return c.json({ error: 'Monitoring policy not found.' }, 404)
    const result = await pool.query(
      "INSERT INTO rmm_monitoring_device_overrides (tenant_id,inventory_id,policy_id,check_overrides,reason,enabled,created_by_user_id)" +
      " VALUES ($1,$2,$3,$4::jsonb,$5,true,$6)" +
      " ON CONFLICT (tenant_id,inventory_id) DO UPDATE SET policy_id=EXCLUDED.policy_id,check_overrides=EXCLUDED.check_overrides,reason=EXCLUDED.reason,enabled=true,updated_at=now()" +
      " RETURNING id",
      [
        auth.session.tenant_id,
        inventoryIds[0],
        policyId,
        JSON.stringify(asObject(body.checkOverrides)),
        clean(body.reason).slice(0, 1000),
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'monitoring_override.updated', 'Updated device monitoring override', clean(body.reason), { overrideId: result.rows[0].id, policyId, deviceId: clean(body.deviceId) })
    return c.json({ success: true, id: result.rows[0].id, bundle: await scopeBundle(auth.session) }, 201)
  })
}
