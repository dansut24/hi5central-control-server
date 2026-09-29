import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { hashPassword } from '../src/password.js'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-rbac-${suffix}`.slice(0, 42)
const ownerEmail = `owner-${suffix}@hi5central.test`
const requesterEmail = `requester-${suffix}@hi5central.test`
const ownerPassword = `Owner-${randomBytes(12).toString('base64url')}Aa1`
const requesterPassword = `Requester-${randomBytes(12).toString('base64url')}Bb2`
const tenantOrigin = `https://${slug}.hi5central.com`
const portalOrigin = `https://${slug}-portal.hi5central.com`
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function cookieFrom(response, name = 'hi5central_session') {
  const raw = response.headers.get('set-cookie') || ''
  const match = raw.match(new RegExp(`${name}=([^;]+)`))
  return match ? `${name}=${match[1]}` : ''
}

async function json(path, { method = 'GET', body, cookie = '', origin = tenantOrigin } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: origin,
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

async function workspaceLogin(email, password) {
  return json('/api/v1/auth/login', { method: 'POST', body: { tenantSlug: slug, email, password } })
}

async function portalLogin(email, password) {
  return json('/api/v1/portal/auth/login', { method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email, password } })
}

await db.connect()
try {
  console.log(`RBAC tenant: ${slug}`)
  const [ownerHash, requesterHash] = await Promise.all([hashPassword(ownerPassword), hashPassword(requesterPassword)])

  console.log('1. Creating an isolated active tenant with owner + requester')
  const tenant = await db.query(
    `INSERT INTO tenants (slug,company_name,status) VALUES ($1,'RBAC Acceptance Tenant','active') RETURNING id`,
    [slug],
  )
  const tenantId = tenant.rows[0].id
  const owner = await db.query(
    `INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,'RBAC Owner',$2,now()) RETURNING id`,
    [ownerEmail, ownerHash],
  )
  const requester = await db.query(
    `INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,'RBAC Requester',$2,now()) RETURNING id`,
    [requesterEmail, requesterHash],
  )
  const ownerId = owner.rows[0].id
  const requesterId = requester.rows[0].id
  await db.query("INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,'owner','active'),($1,$3,'requester','active')", [tenantId, ownerId, requesterId])
  await db.query(
    `INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,onboarding_completed_at,onboarding_data,configuration,tenant_url,portal_url,rmm_url)
     VALUES ($1,'{"itsm":true,"rmm":false}'::jsonb,'complete',now(),'{}'::jsonb,'{"security":{"requireMfa":false,"sessionHours":"12","passwordPolicy":"strong"}}'::jsonb,$2,$3,NULL)`,
    [tenantId, tenantOrigin, portalOrigin],
  )

  console.log('2. Proving Requester is portal-only at the workspace login boundary')
  const requesterWorkspaceDenied = await workspaceLogin(requesterEmail, requesterPassword)
  assert(requesterWorkspaceDenied.response.status === 403, `Requester workspace login should be 403, got ${requesterWorkspaceDenied.response.status}`)
  assert(/roles do not include access/i.test(requesterWorkspaceDenied.payload.error || ''), 'Requester workspace denial did not come from RBAC')

  const requesterPortal = await portalLogin(requesterEmail, requesterPassword)
  assert(requesterPortal.response.ok, `Requester Portal login failed: ${requesterPortal.payload.error || requesterPortal.response.status}`)
  const requesterPortalCookie = cookieFrom(requesterPortal.response, 'hi5central_portal_session')
  assert(requesterPortalCookie, 'Requester Portal login did not issue a Portal cookie')
  assert(requesterPortal.payload.access?.portalAccess === true, 'Requester Portal session did not expose portalAccess')
  assert(requesterPortal.payload.access?.workspaceAccess === false, 'Requester unexpectedly received workspace access')

  console.log('3. Signing in owner and verifying default role library')
  const ownerLogin = await workspaceLogin(ownerEmail, ownerPassword)
  assert(ownerLogin.response.ok, `Owner login failed: ${ownerLogin.payload.error || ownerLogin.response.status}`)
  const ownerCookie = cookieFrom(ownerLogin.response)
  assert(ownerCookie, 'Owner login did not issue a workspace cookie')
  assert(ownerLogin.payload.access?.workspaceAccess === true, 'Owner did not receive workspace access')
  const rolesResult = await json('/api/v1/access/roles', { cookie: ownerCookie })
  assert(rolesResult.response.ok, `Could not read role library: ${rolesResult.payload.error || rolesResult.response.status}`)
  const roles = rolesResult.payload.roles || []
  for (const requiredKey of ['owner','administrator','analyst','requester','approver','management','change-board','knowledge-publisher','live-chat-analyst','rmm-operator']) {
    assert(roles.some((role) => role.key === requiredKey), `Missing default role ${requiredKey}`)
  }
  const role = (key) => roles.find((item) => item.key === key)

  console.log('4. Stacking Requester + Approver while keeping the user portal-only')
  const requesterApprover = await json(`/api/v1/access/users/${requesterId}/roles`, {
    method: 'PUT',
    cookie: ownerCookie,
    body: { roleIds: [role('requester').id, role('approver').id] },
  })
  assert(requesterApprover.response.ok, `Requester + Approver assignment failed: ${requesterApprover.payload.error || requesterApprover.response.status}`)
  assert(requesterApprover.payload.effective?.portalAccess === true, 'Requester + Approver lost Portal access')
  assert(requesterApprover.payload.effective?.workspaceAccess === false, 'Requester + Approver incorrectly gained workspace access')
  const approverWorkspaceDenied = await workspaceLogin(requesterEmail, requesterPassword)
  assert(approverWorkspaceDenied.response.status === 403, `Requester + Approver workspace login should be 403, got ${approverWorkspaceDenied.response.status}`)

  console.log('5. Adding Change Board and proving focused workspace access')
  const cabAssignment = await json(`/api/v1/access/users/${requesterId}/roles`, {
    method: 'PUT',
    cookie: ownerCookie,
    body: { roleIds: [role('requester').id, role('approver').id, role('change-board').id] },
  })
  assert(cabAssignment.response.ok, `Change Board stacking failed: ${cabAssignment.payload.error || cabAssignment.response.status}`)
  assert(cabAssignment.payload.effective?.workspaceAccess === true, 'Change Board did not add workspace access')
  assert(cabAssignment.payload.effective?.permissions?.includes('itsm.changes.view'), 'Change Board did not grant Change view')
  assert(!cabAssignment.payload.effective?.permissions?.includes('itsm.incidents.view'), 'Change Board unexpectedly granted Incident view')

  const cabLogin = await workspaceLogin(requesterEmail, requesterPassword)
  assert(cabLogin.response.ok, `Stacked CAB workspace login failed: ${cabLogin.payload.error || cabLogin.response.status}`)
  const cabCookie = cookieFrom(cabLogin.response)
  assert(cabCookie, 'Stacked CAB login did not issue a workspace cookie')
  assert(cabLogin.payload.access?.roleKeys?.includes('requester'), 'Stacked session lost Requester role')
  assert(cabLogin.payload.access?.roleKeys?.includes('approver'), 'Stacked session lost Approver role')
  assert(cabLogin.payload.access?.roleKeys?.includes('change-board'), 'Stacked session lost Change Board role')

  const changeQueue = await json('/api/v1/itsm-queue?type=Change', { cookie: cabCookie })
  assert(changeQueue.response.ok, `Change Board could not view Change queue: ${changeQueue.payload.error || changeQueue.response.status}`)
  const incidentQueue = await json('/api/v1/itsm-queue?type=Incident', { cookie: cabCookie })
  assert(incidentQueue.response.status === 403, `Change Board should be denied Incident queue, got ${incidentQueue.response.status}`)

  console.log('6. Proving portal access survives workspace-capable stacked roles')
  const stackedPortal = await portalLogin(requesterEmail, requesterPassword)
  assert(stackedPortal.response.ok, `Stacked user lost Portal login: ${stackedPortal.payload.error || stackedPortal.response.status}`)
  assert(stackedPortal.payload.access?.portalAccess === true, 'Stacked Portal session does not expose portal access')

  console.log('7. Creating and stacking a granular custom role')
  const custom = await json('/api/v1/access/roles', {
    method: 'POST',
    cookie: ownerCookie,
    body: {
      name: 'Knowledge Reader Test',
      description: 'Acceptance-test custom role.',
      permissions: ['workspace.access','knowledge.view_internal'],
    },
  })
  assert(custom.response.status === 201, `Custom role creation failed: ${custom.payload.error || custom.response.status}`)
  assert(custom.payload.isDefault === false, 'Custom role was incorrectly marked default')

  const customAssignment = await json(`/api/v1/access/users/${requesterId}/roles`, {
    method: 'PUT',
    cookie: ownerCookie,
    body: { roleIds: [role('requester').id, custom.payload.id] },
  })
  assert(customAssignment.response.ok, `Custom role assignment failed: ${customAssignment.payload.error || customAssignment.response.status}`)
  assert(customAssignment.payload.effective?.portalAccess === true, 'Custom stack lost requester Portal access')
  assert(customAssignment.payload.effective?.workspaceAccess === true, 'Custom workspace role did not add workspace access')
  assert(customAssignment.payload.effective?.permissions?.includes('knowledge.view_internal'), 'Custom permission did not appear in effective permissions')
  assert(!customAssignment.payload.effective?.permissions?.includes('itsm.incidents.view'), 'Custom role over-granted Incident access')

  const customLogin = await workspaceLogin(requesterEmail, requesterPassword)
  assert(customLogin.response.ok, `Custom-role workspace login failed: ${customLogin.payload.error || customLogin.response.status}`)
  const customCookie = cookieFrom(customLogin.response)
  const knowledge = await json('/api/v1/knowledge', { cookie: customCookie })
  assert(knowledge.response.ok, `Knowledge custom role could not read Knowledge: ${knowledge.payload.error || knowledge.response.status}`)
  const customIncidentDenied = await json('/api/v1/itsm-queue?type=Incident', { cookie: customCookie })
  assert(customIncidentDenied.response.status === 403, `Knowledge-only custom role should be denied Incidents, got ${customIncidentDenied.response.status}`)

  console.log('8. Protecting the Owner role from accidental removal')
  const ownerRemoval = await json(`/api/v1/access/users/${ownerId}/roles`, {
    method: 'PUT',
    cookie: ownerCookie,
    body: { roleIds: [role('administrator').id] },
  })
  assert(ownerRemoval.response.status === 409, `Owner role removal should be 409, got ${ownerRemoval.response.status}`)

  console.log('9. Verifying compatibility role follows the effective stack')
  const membership = await db.query('SELECT role FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2', [tenantId, requesterId])
  assert(membership.rows[0]?.role === 'analyst', `Expected compatibility role analyst for custom workspace role, found ${membership.rows[0]?.role}`)
  const assignments = await db.query(
    `SELECT r.role_key FROM access_user_roles ur JOIN access_roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
     WHERE ur.tenant_id=$1 AND ur.user_id=$2 ORDER BY r.role_key`,
    [tenantId, requesterId],
  )
  assert(assignments.rows.some((row) => row.role_key === 'requester'), 'Requester role was not persisted in stack')
  assert(assignments.rows.some((row) => row.role_key === custom.payload.key), 'Custom role was not persisted in stack')

  console.log('10. Proving workspace-only users get an explicit Portal access denial')
  const analystOnly = await json(`/api/v1/access/users/${requesterId}/roles`, {
    method: 'PUT',
    cookie: ownerCookie,
    body: { roleIds: [role('analyst').id] },
  })
  assert(analystOnly.response.ok, `Analyst-only assignment failed: ${analystOnly.payload.error || analystOnly.response.status}`)
  assert(analystOnly.payload.effective?.workspaceAccess === true, 'Analyst-only user lost workspace access')
  assert(analystOnly.payload.effective?.portalAccess === false, 'Analyst-only user unexpectedly has Portal access')

  const analystPortalDenied = await portalLogin(requesterEmail, requesterPassword)
  assert(analystPortalDenied.response.status === 403, `Analyst Portal login should be 403, got ${analystPortalDenied.response.status}`)
  assert(/does not have access to the requester portal/i.test(analystPortalDenied.payload.error || ''), 'Analyst Portal denial was not explicit')

  const analystWorkspaceLogin = await workspaceLogin(requesterEmail, requesterPassword)
  assert(analystWorkspaceLogin.response.ok, `Analyst workspace login failed: ${analystWorkspaceLogin.payload.error || analystWorkspaceLogin.response.status}`)

  console.log('RBAC acceptance passed')
} finally {
  await db.end()
}
