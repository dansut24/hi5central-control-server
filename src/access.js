const permissionCatalog = [
  ['workspace.access', 'Workspace', 'Access the technician/admin workspace'],
  ['dashboard.view', 'Workspace', 'View dashboards'],
  ['portal.access', 'Portal', 'Access the requester portal'],
  ['portal.requests.create', 'Portal', 'Raise incidents and requests'],
  ['portal.requests.view_own', 'Portal', 'View own incidents and requests'],
  ['portal.requests.comment', 'Portal', 'Add requester comments'],
  ['portal.approvals.view', 'Portal', 'View approvals assigned to the user'],
  ['portal.approvals.decide', 'Portal', 'Approve or reject assigned approvals'],
  ['portal.knowledge.view', 'Portal', 'View published portal knowledge'],
  ['portal.live_chat.use', 'Portal', 'Use portal Live Chat when entitled'],
  ['itsm.records.view_all', 'ITSM', 'View all ITSM record types'],
  ['itsm.records.create_all', 'ITSM', 'Create all ITSM record types'],
  ['itsm.incidents.view', 'ITSM · Incidents', 'View incidents'],
  ['itsm.incidents.create', 'ITSM · Incidents', 'Create incidents'],
  ['itsm.incidents.edit', 'ITSM · Incidents', 'Edit incidents'],
  ['itsm.incidents.assign', 'ITSM · Incidents', 'Assign and reassign incidents'],
  ['itsm.incidents.resolve', 'ITSM · Incidents', 'Resolve and close incidents'],
  ['itsm.incidents.delete', 'ITSM · Incidents', 'Delete incidents'],
  ['itsm.requests.view', 'ITSM · Requests', 'View service requests'],
  ['itsm.requests.create', 'ITSM · Requests', 'Create service requests'],
  ['itsm.requests.edit', 'ITSM · Requests', 'Edit service requests'],
  ['itsm.requests.assign', 'ITSM · Requests', 'Assign and reassign service requests'],
  ['itsm.requests.fulfil', 'ITSM · Requests', 'Fulfil request tasks and complete requests'],
  ['itsm.requests.delete', 'ITSM · Requests', 'Delete service requests'],
  ['itsm.problems.view', 'ITSM · Problems', 'View problems'],
  ['itsm.problems.create', 'ITSM · Problems', 'Create problems'],
  ['itsm.problems.edit', 'ITSM · Problems', 'Edit problems'],
  ['itsm.problems.assign', 'ITSM · Problems', 'Assign and reassign problems'],
  ['itsm.problems.resolve', 'ITSM · Problems', 'Resolve and close problems'],
  ['itsm.problems.delete', 'ITSM · Problems', 'Delete problems'],
  ['itsm.changes.view', 'ITSM · Changes', 'View changes'],
  ['itsm.changes.create', 'ITSM · Changes', 'Create changes'],
  ['itsm.changes.edit', 'ITSM · Changes', 'Edit changes'],
  ['itsm.changes.assign', 'ITSM · Changes', 'Assign and reassign changes'],
  ['itsm.changes.approve', 'ITSM · Changes', 'Approve or reject changes'],
  ['itsm.changes.cab', 'ITSM · Changes', 'Participate in the Change Advisory Board'],
  ['itsm.changes.implement', 'ITSM · Changes', 'Move changes through implementation'],
  ['itsm.changes.delete', 'ITSM · Changes', 'Delete changes'],
  ['itsm.tasks.view', 'ITSM', 'View record and request tasks'],
  ['itsm.tasks.manage', 'ITSM', 'Create, assign and complete tasks'],
  ['itsm.comments.internal', 'ITSM', 'Add internal work notes'],
  ['itsm.export', 'ITSM', 'Export ITSM records'],
  ['catalogue.view', 'Service Catalogue', 'View the service catalogue administration view'],
  ['catalogue.manage', 'Service Catalogue', 'Create and manage catalogue items and workflows'],
  ['knowledge.view_internal', 'Knowledge', 'View internal knowledge'],
  ['knowledge.create', 'Knowledge', 'Create knowledge articles'],
  ['knowledge.edit', 'Knowledge', 'Edit knowledge articles'],
  ['knowledge.publish', 'Knowledge', 'Publish knowledge articles'],
  ['knowledge.archive', 'Knowledge', 'Archive knowledge articles'],
  ['knowledge.link', 'Knowledge', 'Link knowledge to ITSM records'],
  ['live_chat.view', 'Live Chat', 'View the Live Chat workspace and queue'],
  ['live_chat.claim', 'Live Chat', 'Claim waiting conversations'],
  ['live_chat.reply', 'Live Chat', 'Reply to conversations'],
  ['live_chat.transfer', 'Live Chat', 'Transfer conversations to another analyst'],
  ['live_chat.close', 'Live Chat', 'Close and reopen conversations'],
  ['live_chat.manage_canned', 'Live Chat', 'Manage canned responses'],
  ['live_chat.manage_hours', 'Live Chat', 'Manage Live Chat service hours'],
  ['organisation.people.view', 'People', 'View the people directory'],
  ['organisation.people.create', 'People', 'Create people'],
  ['organisation.people.edit', 'People', 'Edit people'],
  ['organisation.people.manage_access', 'People', 'Manage user access and role assignments'],
  ['organisation.teams.view', 'Organisation', 'View teams'],
  ['organisation.teams.manage', 'Organisation', 'Create and manage teams'],
  ['organisation.departments.view', 'Organisation', 'View departments'],
  ['organisation.departments.manage', 'Organisation', 'Create and manage departments'],
  ['organisation.sites.view', 'Organisation', 'View sites'],
  ['organisation.sites.manage', 'Organisation', 'Create and manage sites'],
  ['projects.view', 'Projects', 'View projects'],
  ['projects.manage', 'Projects', 'Create and manage projects'],
  ['calendar.view', 'Calendar', 'View the unified calendar'],
  ['calendar.manage', 'Calendar', 'Create and manage calendar entries'],
  ['rota.view', 'Rota', 'View staff rota'],
  ['rota.manage', 'Rota', 'Create and manage rota entries'],
  ['notifications.view', 'Notifications', 'View notifications'],
  ['notifications.manage', 'Notifications', 'Manage notification configuration'],
  ['cmdb.view', 'CMDB', 'View configuration items and asset relationships'],
  ['cmdb.manage', 'CMDB', 'Create and manage configuration items'],
  ['reports.view', 'Reports', 'View reports and operational insights'],
  ['reports.manage', 'Reports', 'Create and manage reports'],
  ['access.roles.view', 'Access Control', 'View roles and effective access'],
  ['access.roles.manage', 'Access Control', 'Create and edit roles'],
  ['access.roles.assign', 'Access Control', 'Assign stacked roles to users'],
  ['settings.view', 'Settings', 'Open tenant settings'],
  ['settings.organisation.manage', 'Settings', 'Manage organisation settings'],
  ['settings.appearance.manage', 'Settings', 'Manage branding and appearance'],
  ['settings.directory.manage', 'Settings', 'Manage directory configuration'],
  ['settings.roles.manage', 'Settings', 'Manage roles and permissions'],
  ['settings.security.manage', 'Settings', 'Manage security and MFA policies'],
  ['settings.itsm.manage', 'Settings', 'Manage ITSM configuration'],
  ['settings.integrations.manage', 'Settings', 'Manage integrations'],
  ['settings.billing.manage', 'Settings', 'Manage subscription and billing settings'],
  ['integrations.view', 'Integrations', 'View provider connections and sync state'],
  ['integrations.manage', 'Integrations', 'Create and manage integrations, API access and webhooks'],
  ['rmm.access', 'RMM', 'Access the RMM workspace'],
  ['rmm.devices.view', 'RMM', 'View devices'],
  ['rmm.devices.control', 'RMM', 'Run device control actions'],
  ['rmm.security.recovery_keys.read', 'RMM', 'Reveal escrowed BitLocker recovery keys'],
  ['rmm.devices.files', 'RMM', 'Use remote file management'],
  ['rmm.devices.terminal', 'RMM', 'Use remote terminal'],
  ['rmm.devices.remote', 'RMM', 'Start unattended console remote sessions'],
  ['rmm.devices.backstage', 'RMM', 'Start Background remote sessions'],
  ['rmm.sites.view', 'RMM', 'View RMM sites'],
  ['rmm.sites.manage', 'RMM', 'Manage RMM sites'],
  ['rmm.groups.view', 'RMM', 'View device groups and saved views'],
  ['rmm.groups.manage', 'RMM', 'Manage device groups and saved views'],
  ['rmm.policies.view', 'RMM', 'View monitoring and patch policies'],
  ['rmm.policies.manage', 'RMM', 'Manage monitoring and patch policies'],
  ['rmm.software.manage', 'RMM', 'Manage software deployment'],
  ['rmm.scripts.manage', 'RMM', 'Manage scripts and automations'],
  ['rmm.alerts.manage', 'RMM', 'Manage alerts and remediation'],
  ['rmm.audit.view', 'RMM', 'View tenant-wide RMM activity and audit history'],
  ['audit.view', 'Security', 'View audit and security events'],
  ['billing.view', 'Billing', 'View subscription and billing information'],
  ['tenant.owner.transfer', 'Ownership', 'Transfer tenant ownership'],
]

export const permissionDefinitions = permissionCatalog.map(([key, group, label]) => ({ key, group, label }))
export const permissionKeys = new Set(permissionDefinitions.map((item) => item.key))

export const defaultRoleDefinitions = [
  { key: 'owner', name: 'Owner', description: 'Protected tenant owner with unrestricted access.', permissions: ['*'], systemKey: 'owner', protected: true },
  { key: 'administrator', name: 'Administrator', description: 'Broad tenant administration without ownership transfer.', permissions: ['workspace.access','dashboard.view','access.roles.view','access.roles.manage','access.roles.assign','settings.*','organisation.*','itsm.*','catalogue.*','knowledge.*','live_chat.*','projects.*','calendar.*','rota.*','notifications.*','cmdb.*','reports.*','integrations.*','rmm.*','audit.view','billing.view'], systemKey: 'administrator' },
  { key: 'analyst', name: 'Analyst', description: 'General ITSM analyst access for day-to-day service desk work.', permissions: ['workspace.access','dashboard.view','itsm.records.view_all','itsm.records.create_all','itsm.incidents.*','itsm.requests.*','itsm.problems.*','itsm.changes.view','itsm.changes.create','itsm.changes.edit','itsm.tasks.*','itsm.comments.internal','itsm.export','catalogue.view','knowledge.view_internal','live_chat.view','live_chat.claim','live_chat.reply','live_chat.close','live_chat.transfer','organisation.people.view','organisation.teams.view','organisation.departments.view','organisation.sites.view','projects.view','calendar.view','rota.view','cmdb.view','reports.view','notifications.view'], systemKey: 'analyst' },
  { key: 'requester', name: 'Requester', description: 'Portal-only requester access.', permissions: ['portal.access','portal.requests.create','portal.requests.view_own','portal.requests.comment','portal.knowledge.view','portal.live_chat.use'], systemKey: 'requester' },
  { key: 'approver', name: 'Approver', description: 'Portal approval capability. Stack with Requester for normal approvers.', permissions: ['portal.access','portal.approvals.view','portal.approvals.decide'], systemKey: 'approver' },
  { key: 'management', name: 'Management', description: 'Management visibility across operational work and people.', permissions: ['workspace.access','dashboard.view','itsm.incidents.view','itsm.requests.view','itsm.problems.view','itsm.changes.view','organisation.people.view','organisation.teams.view','organisation.departments.view','projects.view','calendar.view','rota.view','reports.view','notifications.view'], systemKey: 'management' },
  { key: 'change-board', name: 'Change Board / CAB', description: 'Focused Change Advisory Board access.', permissions: ['workspace.access','itsm.changes.view','itsm.changes.cab','itsm.changes.approve','notifications.view'], systemKey: 'change-board' },
  { key: 'knowledge-publisher', name: 'Knowledge Publisher', description: 'Create, edit and publish internal and portal knowledge.', permissions: ['workspace.access','knowledge.view_internal','knowledge.create','knowledge.edit','knowledge.publish','knowledge.archive','knowledge.link'], systemKey: 'knowledge-publisher' },
  { key: 'live-chat-analyst', name: 'Live Chat Analyst', description: 'Operate Live Chat without granting wider ITSM administration.', permissions: ['workspace.access','live_chat.view','live_chat.claim','live_chat.reply','live_chat.transfer','live_chat.close','notifications.view'], systemKey: 'live-chat-analyst' },
  { key: 'rmm-operator', name: 'RMM Operator', description: 'Operate endpoint monitoring and remote management.', permissions: ['workspace.access','rmm.access','rmm.devices.view','rmm.devices.control','rmm.security.recovery_keys.read','rmm.devices.files','rmm.devices.terminal','rmm.devices.remote','rmm.alerts.manage','rmm.sites.view','rmm.groups.view','notifications.view'], systemKey: 'rmm-operator' },
]

function cleanPermissions(values = []) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value || '').trim()).filter(Boolean))]
}

export function permissionMatches(grant, permission) {
  if (grant === '*') return true
  if (grant === permission) return true
  if (grant.endsWith('*')) return permission.startsWith(grant.slice(0, -1))
  return false
}

export function hasPermission(access, permission) {
  return Boolean(access?.permissions?.some((grant) => permissionMatches(grant, permission)))
}

export function expandedPermissions(access) {
  if (!access) return []
  const grants = cleanPermissions(access.permissions)
  return permissionDefinitions.filter((definition) => grants.some((grant) => permissionMatches(grant, definition.key))).map((definition) => definition.key)
}

export async function ensureDefaultRoles(db, tenantId) {
  for (const role of defaultRoleDefinitions) {
    await db.query(
      `INSERT INTO access_roles
         (tenant_id, role_key, name, description, permissions, system_key, is_default, is_protected)
       VALUES ($1,$2,$3,$4,$5::text[],$6,true,$7)
       ON CONFLICT (tenant_id, role_key) DO NOTHING`,
      [tenantId, role.key, role.name, role.description, role.permissions, role.systemKey, Boolean(role.protected)],
    )
  }
}

function fallbackSystemKey(legacyRole) {
  if (legacyRole === 'owner') return 'owner'
  if (legacyRole === 'admin') return 'administrator'
  if (legacyRole === 'analyst') return 'analyst'
  return 'requester'
}

export async function ensureLegacyRoleAssignment(db, tenantId, userId, legacyRole = '') {
  const existing = await db.query('SELECT 1 FROM access_user_roles WHERE tenant_id=$1 AND user_id=$2 LIMIT 1', [tenantId, userId])
  if (existing.rowCount) return
  await ensureDefaultRoles(db, tenantId)
  await db.query(
    `INSERT INTO access_user_roles (tenant_id,user_id,role_id)
     SELECT $1,$2,id FROM access_roles
     WHERE tenant_id=$1 AND system_key=$3 AND active=true
     LIMIT 1 ON CONFLICT DO NOTHING`,
    [tenantId, userId, fallbackSystemKey(legacyRole)],
  )
}

export async function effectiveAccessForUser(db, tenantId, userId, legacyRole = '') {
  await ensureLegacyRoleAssignment(db, tenantId, userId, legacyRole)
  const result = await db.query(
    `SELECT r.id,r.role_key,r.name,r.description,r.permissions,r.system_key,r.is_default,r.is_protected,r.active
     FROM access_user_roles ur
     JOIN access_roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
     WHERE ur.tenant_id=$1 AND ur.user_id=$2 AND r.active=true
     ORDER BY r.is_protected DESC,r.is_default DESC,r.name`,
    [tenantId, userId],
  )
  const roles = result.rows.map((row) => ({
    id: row.id, key: row.role_key, name: row.name, description: row.description,
    systemKey: row.system_key, isDefault: row.is_default, isProtected: row.is_protected,
    permissions: cleanPermissions(row.permissions),
  }))
  const permissions = cleanPermissions(roles.flatMap((role) => role.permissions))
  return {
    roles,
    roleKeys: roles.map((role) => role.key),
    permissions,
    effectivePermissions: expandedPermissions({ permissions }),
    workspaceAccess: permissions.some((grant) => permissionMatches(grant, 'workspace.access')),
    portalAccess: permissions.some((grant) => permissionMatches(grant, 'portal.access')),
  }
}

export function compatibilityTenantRole(access, legacyRole = '', surface = 'workspace') {
  const systemKeys = new Set(access?.roles?.map((role) => role.systemKey).filter(Boolean) || [])
  if (systemKeys.has('owner')) return 'owner'
  if (surface === 'portal' && hasPermission(access, 'portal.access')) return 'requester'
  if (systemKeys.has('administrator')) return 'admin'
  const administrativeCompatibility = ['access.roles.manage','access.roles.assign','settings.organisation.manage','settings.appearance.manage','settings.directory.manage','settings.roles.manage','settings.security.manage','settings.itsm.manage','settings.integrations.manage','settings.billing.manage','organisation.people.create','organisation.people.edit','organisation.people.manage_access','organisation.teams.manage','organisation.departments.manage','organisation.sites.manage'].some((permission) => hasPermission(access, permission))
  if (administrativeCompatibility) return 'admin'
  if (hasPermission(access, 'workspace.access')) return 'analyst'
  if (hasPermission(access, 'portal.access')) return 'requester'
  return legacyRole || 'requester'
}

export function attachAccess(row, access, surface = 'workspace') {
  return {
    ...row,
    legacy_tenant_role: row?.legacy_tenant_role || row?.tenant_role || '',
    tenant_role: compatibilityTenantRole(access, row?.tenant_role || '', surface),
    access,
  }
}

export function validatePermissionSelection(values) {
  const selected = cleanPermissions(values)
  return selected.filter((permission) => permissionKeys.has(permission))
}

export function roleKeyFromName(value = '') {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80)
}
