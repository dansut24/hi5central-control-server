import { effectiveAccessForUser, hasPermission } from './access.js'
import { pool } from './db.js'
import { originMatchesTenant, portalRequestFromHeaders } from './deploymentConfig.js'
import { resolveSession } from './session.js'

function typePermission(type, action = 'view') {
  const key = String(type || '').toLowerCase()
  if (key === 'incident') return `itsm.incidents.${action}`
  if (key === 'service request') return `itsm.requests.${action}`
  if (key === 'problem') return `itsm.problems.${action}`
  if (key === 'change') return `itsm.changes.${action}`
  return ''
}

async function requestJson(c) {
  try { return await c.req.raw.clone().json() } catch { return {} }
}

async function recordType(tenantId, reference) {
  const generic = await pool.query('SELECT record_type FROM itsm_records WHERE tenant_id=$1 AND upper(reference)=upper($2) LIMIT 1', [tenantId, reference])
  if (generic.rowCount) return generic.rows[0].record_type
  const request = await pool.query("SELECT 'Service Request'::text AS record_type FROM service_requests WHERE tenant_id=$1 AND upper(reference)=upper($2) LIMIT 1", [tenantId, reference])
  return request.rows[0]?.record_type || ''
}

function rule(any = [], all = []) {
  return { any: any.filter(Boolean), all: all.filter(Boolean) }
}

function permitted(access, required) {
  if (!required) return true
  if (required.all?.some((permission) => !hasPermission(access, permission))) return false
  if (!required.any?.length) return true
  return required.any.some((permission) => hasPermission(access, permission))
}

async function requiredAccess(c, session) {
  const path = c.req.path
  const method = c.req.method.toUpperCase()

  if (path.startsWith('/api/v1/access/')) {
    if (method === 'GET') return rule(['access.roles.view'])
    if (path.includes('/users/') && path.endsWith('/roles')) return rule(['access.roles.assign'])
    return rule(['access.roles.manage'])
  }

  if (path === '/api/v1/itsm-queue') {
    const type = String(c.req.query('type') || '').trim()
    return type ? rule([typePermission(type, 'view'), 'itsm.records.view_all']) : rule(['itsm.records.view_all'])
  }

  if (path === '/api/v1/itsm-records') {
    if (method === 'GET') {
      const type = String(c.req.query('type') || '').trim()
      return type ? rule([typePermission(type, 'view'), 'itsm.records.view_all']) : rule(['itsm.records.view_all'])
    }
    if (method === 'POST') {
      const body = await requestJson(c)
      return rule([typePermission(body?.type, 'create'), 'itsm.records.create_all'])
    }
  }

  const recordMatch = path.match(/^\/api\/v1\/(?:itsm-records|itsm-lifecycle)\/([^/]+)/i)
  if (recordMatch) {
    const type = await recordType(session.tenant_id, decodeURIComponent(recordMatch[1]))
    if (!type) return null
    if (method === 'GET') return rule([typePermission(type, 'view'), 'itsm.records.view_all'])
    if (path.includes('/relationships')) return rule([], [typePermission(type, 'edit')])
    if (path.includes('/attachments')) return rule([], [typePermission(type, 'edit')])
    if (path.includes('/activity') || path.includes('/activities')) return rule([], [typePermission(type, 'edit')])
    if (method === 'PATCH') {
      const body = await requestJson(c)
      const assigning = Object.prototype.hasOwnProperty.call(body, 'team') || Object.prototype.hasOwnProperty.call(body, 'assignee')
      const editableKeys = ['title','description','service','category','priority','status','impact','urgency','requesterId','resolutionCode','resolutionSummary','recordData']
      const editing = editableKeys.some((key) => Object.prototype.hasOwnProperty.call(body, key))
      const all = []
      if (assigning) all.push(typePermission(type, 'assign'))
      if (editing || !assigning) all.push(typePermission(type, 'edit'))
      return rule([], all)
    }
    return rule([], [typePermission(type, 'edit')])
  }

  const actionMatch = path.match(/^\/api\/v1\/itsm-actions\/([^/]+)\/(.+)$/i)
  if (actionMatch) {
    const type = await recordType(session.tenant_id, decodeURIComponent(actionMatch[1]))
    if (!type) return null
    const action = actionMatch[2]
    if (action.startsWith('reassign')) return rule([], [typePermission(type, 'assign')])
    if (action.startsWith('resolve')) return rule([], [typePermission(type, type === 'Change' ? 'implement' : 'resolve')])
    if (action.startsWith('pending')) return rule([], [typePermission(type, 'edit')])
    if (action.startsWith('tasks')) return rule([], [method === 'GET' ? 'itsm.tasks.view' : 'itsm.tasks.manage'])
    return rule([], [typePermission(type, 'edit')])
  }

  if (path.startsWith('/api/v1/service-requests')) {
    if (method === 'POST' && /\/approvals\/[^/]+\/decision\/?$/i.test(path)) return null
    if (method === 'GET') return rule(['itsm.requests.view','itsm.records.view_all'])
    if (path.includes('/approval') || path.includes('/decision') || path.includes('/complete')) return rule([], ['itsm.requests.fulfil'])
    if (path.includes('/assign') || path.includes('/reassign')) return rule([], ['itsm.requests.assign'])
    if (method === 'POST' && path === '/api/v1/service-requests') return rule([], ['itsm.requests.create'])
    return rule([], ['itsm.requests.edit'])
  }

  if (path.startsWith('/api/v1/knowledge')) {
    if (method === 'GET') return rule(['knowledge.view_internal'])
    if (path.includes('/links')) return rule([], ['knowledge.link'])
    if (method === 'POST' && path === '/api/v1/knowledge') return rule([], ['knowledge.create'])
    if (method === 'PATCH') {
      const body = await requestJson(c)
      const all = ['knowledge.edit']
      if (body?.status === 'Published') all.push('knowledge.publish')
      if (body?.status === 'Archived') all.push('knowledge.archive')
      return rule([], all)
    }
    return rule([], ['knowledge.edit'])
  }

  if (path.startsWith('/api/v1/live-chat')) {
    if (method === 'GET') return rule(['live_chat.view'])
    if (path.includes('/claim')) return rule([], ['live_chat.claim'])
    if (path.includes('/transfer')) return rule([], ['live_chat.transfer'])
    if (path.includes('/close') || path.includes('/reopen')) return rule([], ['live_chat.close'])
    if (path.includes('/canned')) return rule([], ['live_chat.manage_canned'])
    if (path.includes('/service-settings') || path.includes('/hours')) return rule([], ['live_chat.manage_hours'])
    return rule([], ['live_chat.reply'])
  }

  if (path.startsWith('/api/v1/organisation')) {
    if (method === 'GET') return rule(['organisation.people.view','organisation.teams.view','organisation.departments.view','organisation.sites.view'])
    const collection = path.split('/').filter(Boolean).at(-1)
    if (collection === 'people') return rule(['organisation.people.edit','organisation.people.create'])
    if (collection === 'teams') return rule([], ['organisation.teams.manage'])
    if (collection === 'departments') return rule([], ['organisation.departments.manage'])
    if (collection === 'sites') return rule([], ['organisation.sites.manage'])
    return rule(['organisation.people.edit','organisation.teams.manage','organisation.departments.manage','organisation.sites.manage'])
  }

  if (path.startsWith('/api/v1/catalogue')) return rule([method === 'GET' ? 'catalogue.view' : 'catalogue.manage'])
  if (path.startsWith('/api/v1/notifications')) return rule([method === 'GET' ? 'notifications.view' : 'notifications.manage'])
  if (path.startsWith('/api/v1/security/audit')) return rule(['audit.view'])
  if (path.startsWith('/api/v1/security/')) return rule(['settings.security.manage'])

  const settingsMatch = path.match(/^\/api\/v1\/settings(?:\/([^/]+))?$/i)
  if (settingsMatch) {
    if (method === 'GET') return rule(['settings.view'])
    const area = settingsMatch[1] || ''
    const map = {
      company: 'settings.organisation.manage',
      theme: 'settings.appearance.manage',
      users: 'settings.directory.manage',
      groups: 'settings.directory.manage',
      permissions: 'settings.roles.manage',
      security: 'settings.security.manage',
      itsm: 'settings.itsm.manage',
      rmm: 'rmm.policies.manage',
      integrations: 'settings.integrations.manage',
      billing: 'settings.billing.manage',
    }
    return rule([map[area] || 'settings.view'])
  }

  if (path.startsWith('/api/v1/integrations')) return rule([method === 'GET' ? 'integrations.view' : 'integrations.manage'])
  if (path.startsWith('/api/v1/rmm/')) {
    if (path.includes('/remote') || path.includes('/connect-sessions')) return rule([], ['rmm.devices.remote'])
    if (path.includes('/terminal')) return rule([], ['rmm.devices.terminal'])
    if (path.includes('/files')) return rule([], ['rmm.devices.files'])
    if (method === 'GET') return rule(['rmm.devices.view','rmm.sites.view','rmm.groups.view','rmm.policies.view'])
    return rule(['rmm.devices.control','rmm.sites.manage','rmm.groups.manage','rmm.policies.manage','rmm.software.manage','rmm.scripts.manage','rmm.alerts.manage'])
  }

  return null
}

export async function enforceWorkspacePermissions(c, next) {
  const path = c.req.path
  if (!path.startsWith('/api/v1/')) return next()
  if (path.startsWith('/api/v1/auth/') || path.startsWith('/api/v1/portal/') || path.startsWith('/api/v1/system/')) return next()
  if (portalRequestFromHeaders(c.req.header('origin'), c.req.header('referer'))) return next()
  const session = await resolveSession(c)
  if (!session) return next()
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) return next()
  const access = session.access || await effectiveAccessForUser(pool, session.tenant_id, session.user_id, session.legacy_tenant_role || session.tenant_role)
  const required = await requiredAccess(c, session)
  if (!required || permitted(access, required)) return next()
  return c.json({
    error: 'You do not have permission to perform this action.',
    requiredAny: required.any,
    requiredAll: required.all,
  }, 403)
}