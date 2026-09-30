import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'
const profiles = {
  owner: 'danielsuttonsamsung@gmail.com',
  admin: 'danieljamessutton18+user1@outlook.com',
  analystMember: 'danieljamessutton18+user2@outlook.com',
  analystNonMember: 'danieljamessutton18+user3@outlook.com',
}

function pass(name) { console.log('PASS ', name) }
async function api(token, path, { method = 'GET', body, expect = 200, portal = false } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      Cookie: `${portal ? 'hi5central_portal_session' : 'hi5central_session'}=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : {}
  assert.equal(response.status, expect, `${method} ${path} expected ${expect}, got ${response.status}: ${text}`)
  return payload
}

async function identity(tenantId, email) {
  const result = await pool.query(
    `SELECT u.id,p.external_key,p.name,p.email
     FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1 AND lower(p.email)=lower($2)
     WHERE lower(u.email)=lower($2) LIMIT 1`,
    [tenantId, email],
  )
  return result.rows[0]
}

async function workspaceToken(tenantId, userId) {
  return createSession(pool, { tenantId, userId, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace' })
}

let adminRoleId = null
let adminUserId = null
async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const people = {}
  for (const [key, email] of Object.entries(profiles)) people[key] = await identity(tenant.id, email)
  const requester = await identity(tenant.id, REQUESTER_EMAIL)
  for (const value of [...Object.values(people), requester]) assert(value?.id)
  adminUserId = people.admin.id
  adminRoleId = (await pool.query(
    `SELECT id FROM access_roles WHERE tenant_id=$1 AND system_key='administrator' AND active=true LIMIT 1`,
    [tenant.id],
  )).rows[0]?.id
  assert(adminRoleId)
  await pool.query(
    'INSERT INTO access_user_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
    [tenant.id, adminUserId, adminRoleId],
  )

  const tokens = {
    owner: await workspaceToken(tenant.id, people.owner.id),
    admin: await workspaceToken(tenant.id, people.admin.id),
    analystMember: await workspaceToken(tenant.id, people.analystMember.id),
    analystNonMember: await workspaceToken(tenant.id, people.analystNonMember.id),
    requester: await createSession(pool, { tenantId: tenant.id, userId: requester.id, mfaVerified: true, ttlSeconds: 3600, surface: 'portal' }),
  }
  await assert.rejects(() => workspaceToken(tenant.id, requester.id))
  pass('Requester cannot create a technician workspace session')

  const stamp = new Date().toISOString()
  const incident = await api(tokens.owner, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Incident', title: `RBAC Incident ${stamp}`, requesterId: requester.external_key, priority: 'Medium' },
  })
  pass('Owner can create Incident')
  let detail = await api(tokens.owner, `/api/v1/itsm-lifecycle/${incident.id}`)
  await api(tokens.owner, `/api/v1/itsm-actions/${incident.id}/reassign`, {
    method: 'POST',
    body: { version: detail.version, team: 'Servers', assignee: people.analystMember.name, note: 'Owner assignment test.' },
  })
  pass('Owner can assign Incident to a valid team member')

  const adminIncident = await api(tokens.admin, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Incident', title: `RBAC Admin Incident ${stamp}`, requesterId: requester.external_key },
  })
  pass('Administrator can create Incident')

  const analystIncident = await api(tokens.analystMember, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Incident', title: `RBAC Analyst Incident ${stamp}`, requesterId: requester.external_key },
  })
  detail = await api(tokens.analystMember, `/api/v1/itsm-lifecycle/${analystIncident.id}`)
  await api(tokens.analystMember, `/api/v1/itsm-actions/${analystIncident.id}/reassign`, {
    method: 'POST',
    body: { version: detail.version, team: 'Servers', assignee: people.analystMember.name, note: 'Analyst member self-assignment.' },
  })
  pass('Analyst with team membership can create and assign Incident')
  const nonMemberIncident = await api(tokens.analystNonMember, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Incident', title: `RBAC Non-member Incident ${stamp}`, requesterId: requester.external_key },
  })
  detail = await api(tokens.analystNonMember, `/api/v1/itsm-lifecycle/${nonMemberIncident.id}`)
  await api(tokens.analystNonMember, `/api/v1/itsm-actions/${nonMemberIncident.id}/reassign`, {
    method: 'POST', expect: 422,
    body: { version: detail.version, team: 'Servers', assignee: people.analystNonMember.name, note: 'Must reject non-member assignment.' },
  })
  pass('Team membership guard rejects assigning a non-member into Servers')

  await api(tokens.requester, `/api/v1/itsm-records/${incident.id}`, { expect: 401, portal: true })
  pass('Requester portal token cannot access technician ITSM record endpoint')

  const change = await api(tokens.owner, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Change', title: `RBAC Change ${stamp}`, requesterId: requester.external_key, priority: 'Medium' },
  })
  const plannedStart = new Date(Date.now() + 3600000).toISOString()
  const plannedEnd = new Date(Date.now() + 7200000).toISOString()
  await api(tokens.analystMember, `/api/v1/workflows/${change.id}/data`, {
    method: 'PATCH',
    body: { data: {
      businessReason: 'RBAC workflow edit allowed.',
      riskSummary: 'Controlled RBAC validation risk.',
      implementationPlan: 'Apply the controlled RBAC validation change.',
      testPlan: 'Validate authorization and workflow state.',
      backoutPlan: 'Restore the pre-test state.',
      plannedStart, plannedEnd,
    } },
  })
  pass('Analyst can edit Change workflow data')
  detail = await api(tokens.analystMember, `/api/v1/itsm-lifecycle/${change.id}`)
  await api(tokens.analystMember, `/api/v1/itsm-actions/${change.id}/reassign`, {
    method: 'POST', expect: 403,
    body: { version: detail.version, team: 'Servers', assignee: people.analystMember.name, note: 'Forbidden Change assignment.' },
  })
  await api(tokens.analystMember, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Assessment' },
  })
  await api(tokens.analystMember, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', expect: 403, body: { targetStatus: 'Cancelled' },
  })
  pass('Analyst Change assignment/implementation mutations are forbidden')

  await api(tokens.owner, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Cancelled' },
  })
  pass('Owner can perform privileged Change transition')

  await api(tokens.analystMember, '/api/v1/projects')
  await api(tokens.analystMember, '/api/v1/projects', {
    method: 'POST', expect: 403, body: { name: `Forbidden analyst project ${stamp}` },
  })
  pass('Analyst can view Projects but cannot manage them')
  const adminProject = await api(tokens.admin, '/api/v1/projects', {
    method: 'POST', expect: 201,
    body: { name: `RBAC Admin Project ${stamp}`, ownerId: people.owner.external_key, team: 'Servers', priority: 'Low' },
  })
  assert.match(adminProject.id, /^PRJ-/)
  pass('Administrator can manage Projects')
  await api(tokens.requester, '/api/v1/projects', { expect: 401, portal: true })
  pass('Requester cannot access Projects workspace API')

  const taskHost = await api(tokens.analystMember, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Problem', title: `RBAC Task Host ${stamp}`, requesterId: requester.external_key },
  })
  detail = await api(tokens.analystMember, `/api/v1/itsm-lifecycle/${taskHost.id}`)
  await api(tokens.analystMember, `/api/v1/itsm-actions/${taskHost.id}/tasks`, {
    method: 'POST', expect: 201,
    body: { version: detail.version, title: 'RBAC analyst task', team: 'Servers', assignee: people.analystMember.name },
  })
  pass('Analyst task.manage permission is enforced and usable')

  console.log('SUMMARY', JSON.stringify({ incident: incident.id, adminIncident: adminIncident.id, analystIncident: analystIncident.id, change: change.id, adminProject: adminProject.id }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  if (adminRoleId && adminUserId) {
    await pool.query('DELETE FROM access_user_roles WHERE user_id=$1 AND role_id=$2', [adminUserId, adminRoleId]).catch(() => {})
  }
  await pool.end()
})