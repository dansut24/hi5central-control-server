import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { hashPassword } from '../src/password.js'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-assign-${suffix}`.slice(0, 42)
const ownerEmail = `owner-${suffix}@hi5central.test`
const analystEmail = `analyst-${suffix}@hi5central.test`
const outsiderEmail = `outsider-${suffix}@hi5central.test`
const requesterEmail = `requester-${suffix}@hi5central.test`
const password = `Assign-${randomBytes(12).toString('base64url')}Aa1`
const tenantOrigin = `https://${slug}.hi5central.com`
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function cookieFrom(response) {
  const raw = response.headers.get('set-cookie') || ''
  const match = raw.match(/hi5central_session=([^;]+)/)
  return match ? `hi5central_session=${match[1]}` : ''
}

async function json(path, { method = 'GET', body, cookie = '' } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: tenantOrigin,
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

await db.connect()
try {
  console.log(`Assignment tenant: ${slug}`)
  const hash = await hashPassword(password)
  const tenant = await db.query(
    `INSERT INTO tenants (slug,company_name,status) VALUES ($1,'Assignment Acceptance Tenant','active') RETURNING id`,
    [slug],
  )
  const tenantId = tenant.rows[0].id

  const users = {}
  for (const [key, email, name, role] of [
    ['owner', ownerEmail, 'Assignment Owner', 'owner'],
    ['analyst', analystEmail, 'Team Analyst', 'analyst'],
    ['outsider', outsiderEmail, 'Other Analyst', 'analyst'],
    ['requester', requesterEmail, 'Portal Requester', 'requester'],
  ]) {
    const created = await db.query(
      `INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,$2,$3,now()) RETURNING id`,
      [email, name, hash],
    )
    users[key] = created.rows[0].id
    await db.query(
      `INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,$3,'active')`,
      [tenantId, users[key], role],
    )
  }

  await db.query(
    `INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,onboarding_completed_at,onboarding_data,configuration,tenant_url,portal_url,rmm_url)
     VALUES ($1,'{"itsm":true,"rmm":false}'::jsonb,'complete',now(),'{}'::jsonb,'{}'::jsonb,$2,$3,NULL)`,
    [tenantId, tenantOrigin, `https://${slug}-portal.hi5central.com`],
  )

  const people = {}
  for (const [key, name, email, userId] of [
    ['owner', 'Assignment Owner', ownerEmail, users.owner],
    ['analyst', 'Team Analyst', analystEmail, users.analyst],
    ['outsider', 'Other Analyst', outsiderEmail, users.outsider],
    ['requester', 'Portal Requester', requesterEmail, users.requester],
  ]) {
    const created = await db.query(
      `INSERT INTO organisation_people (tenant_id,external_key,user_id,name,email,access_profile,active)
       VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING id,external_key`,
      [tenantId, `PERSON-${key.toUpperCase()}`, userId, name, email, key === 'requester' ? 'employee' : 'technician'],
    )
    people[key] = created.rows[0]
  }

  const teamA = await db.query(
    `INSERT INTO organisation_teams (tenant_id,external_key,name,description,active)
     VALUES ($1,'TEAM-SERVICE-DESK','Service Desk','Primary support team',true) RETURNING id`,
    [tenantId],
  )
  const teamB = await db.query(
    `INSERT INTO organisation_teams (tenant_id,external_key,name,description,active)
     VALUES ($1,'TEAM-CI-INFRASTRUCTURE','Infrastructure','Infrastructure support',true) RETURNING id`,
    [tenantId],
  )
  await db.query(
    `INSERT INTO organisation_team_memberships (tenant_id,person_id,team_id,role,is_primary)
     VALUES ($1,$2,$3,'member',true),($1,$4,$5,'member',true)`,
    [tenantId, people.analyst.id, teamA.rows[0].id, people.outsider.id, teamB.rows[0].id],
  )
  await db.query('UPDATE organisation_people SET primary_team_id=$2 WHERE id=$1', [people.analyst.id, teamA.rows[0].id])
  await db.query('UPDATE organisation_people SET primary_team_id=$2 WHERE id=$1', [people.outsider.id, teamB.rows[0].id])

  console.log('1. Signing in owner and forcing default roles to exist')
  const login = await json('/api/v1/auth/login', { method: 'POST', body: { tenantSlug: slug, email: ownerEmail, password } })
  assert(login.response.ok, `Owner login failed: ${login.payload.error || login.response.status}`)
  const cookie = cookieFrom(login.response)
  const roles = await json('/api/v1/access/roles', { cookie })
  assert(roles.response.ok, `Could not load role library: ${roles.payload.error || roles.response.status}`)
  const analystRole = (roles.payload.roles || []).find((role) => role.key === 'analyst')
  const requesterRole = (roles.payload.roles || []).find((role) => role.key === 'requester')
  assert(analystRole && requesterRole, 'Required default roles are missing')

  for (const userId of [users.analyst, users.outsider]) {
    const assigned = await json(`/api/v1/access/users/${userId}/roles`, {
      method: 'PUT', cookie, body: { roleIds: [analystRole.id] },
    })
    assert(assigned.response.ok, `Analyst role assignment failed: ${assigned.payload.error || assigned.response.status}`)
  }
  const requesterAssigned = await json(`/api/v1/access/users/${users.requester}/roles`, {
    method: 'PUT', cookie, body: { roleIds: [requesterRole.id] },
  })
  assert(requesterAssigned.response.ok, `Requester role assignment failed: ${requesterAssigned.payload.error || requesterAssigned.response.status}`)

  console.log('2. Creating an Incident assigned to Service Desk')
  await db.query(
    `INSERT INTO itsm_records (
       tenant_id,reference,record_type,requester_person_id,requester_snapshot,title,description,service,category,priority,status,source,
       assignment_team_id,assignment_team_snapshot,record_data,created_by_user_id
     ) VALUES ($1,'INC-90001','Incident',$2,$3::jsonb,'Assignment acceptance incident','Test assignment routing','IT Support','General','Medium','New','technician',$4,$5::jsonb,'{}'::jsonb,$6)`,
    [tenantId, people.requester.id, JSON.stringify({ personId: people.requester.external_key, name: 'Portal Requester', email: requesterEmail }), teamA.rows[0].id, JSON.stringify({ id: 'TEAM-SERVICE-DESK', name: 'Service Desk' }), users.owner],
  )

  const incident = await json('/api/v1/itsm-lifecycle/INC-90001', { cookie })
  assert(incident.response.ok, `Could not load Incident: ${incident.payload.error || incident.response.status}`)
  const serviceDesk = (incident.payload.options?.assignmentTeams || []).find((team) => team.name === 'Service Desk')
  assert(serviceDesk, 'Service Desk was not returned as an assignment target')
  const eligibleNames = new Set((serviceDesk.members || []).map((person) => person.name))
  assert(eligibleNames.has('Team Analyst'), 'Service Desk analyst was not returned as eligible')
  assert(!eligibleNames.has('Other Analyst'), 'Analyst from another team leaked into Service Desk assignment choices')
  assert(!eligibleNames.has('Portal Requester'), 'Portal-only requester leaked into technician assignment choices')

  console.log('3. Accepting a valid team-member assignment')
  const validAssign = await json('/api/v1/itsm-lifecycle/INC-90001', {
    method: 'PATCH',
    cookie,
    body: { version: incident.payload.version, team: 'Service Desk', assignee: 'Team Analyst' },
  })
  assert(validAssign.response.ok, `Valid Incident assignment failed: ${validAssign.payload.error || validAssign.response.status}`)
  assert(validAssign.payload.assignee === 'Team Analyst', 'Incident assignee was not persisted')

  console.log('4. Rejecting an analyst who is not a member of the selected team')
  const invalidTeamMember = await json('/api/v1/itsm-lifecycle/INC-90001', {
    method: 'PATCH',
    cookie,
    body: { version: validAssign.payload.version, team: 'Service Desk', assignee: 'Other Analyst' },
  })
  assert(invalidTeamMember.response.status === 422, `Cross-team assignment should be 422, got ${invalidTeamMember.response.status}`)

  console.log('5. Rejecting a portal-only requester as assignee')
  const invalidRequester = await json('/api/v1/itsm-lifecycle/INC-90001', {
    method: 'PATCH',
    cookie,
    body: { version: validAssign.payload.version, team: 'Service Desk', assignee: 'Portal Requester' },
  })
  assert(invalidRequester.response.status === 422, `Requester assignment should be 422, got ${invalidRequester.response.status}`)

  console.log('6. Creating a Service Request and enforcing the same team boundary')
  await db.query(
    `INSERT INTO service_requests (
       tenant_id,reference,requester_user_id,requester_person_id,requester_snapshot,title,description,service,priority,status,source,
       fulfilment_team_id,fulfilment_team_snapshot,created_by_user_id
     ) VALUES ($1,'REQ-90001',$2,$3,$4::jsonb,'Assignment acceptance request','Test request routing','Service Catalogue','Medium','New','technician',$5,$6::jsonb,$7)`,
    [tenantId, users.requester, people.requester.id, JSON.stringify({ personId: people.requester.external_key, name: 'Portal Requester', email: requesterEmail }), teamA.rows[0].id, JSON.stringify({ id: 'TEAM-SERVICE-DESK', name: 'Service Desk' }), users.owner],
  )

  const requestAssign = await json('/api/v1/service-requests/REQ-90001', {
    method: 'PATCH', cookie, body: { team: 'Service Desk', assignee: 'Team Analyst' },
  })
  assert(requestAssign.response.ok, `Valid Service Request assignment failed: ${requestAssign.payload.error || requestAssign.response.status}`)

  const requestInvalid = await json('/api/v1/service-requests/REQ-90001', {
    method: 'PATCH', cookie, body: { team: 'Service Desk', assignee: 'Other Analyst' },
  })
  assert(requestInvalid.response.status === 422, `Cross-team Service Request assignment should be 422, got ${requestInvalid.response.status}`)

  console.log('Assignment acceptance passed')
} finally {
  await db.end()
}
