import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { hashPassword } from '../src/password.js'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-approvals-${suffix}`.slice(0, 42)
const password = `Approval-${randomBytes(12).toString('base64url')}Aa1`
const ownerEmail = `owner-${suffix}@hi5central.test`
const requesterEmail = `requester-${suffix}@hi5central.test`
const approverEmail = `approver-${suffix}@hi5central.test`
const tenantOrigin = `https://${slug}.hi5central.com`
const portalOrigin = `https://${slug}-portal.hi5central.com`
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function cookieFrom(response, name) {
  const raw = response.headers.get('set-cookie') || ''
  const match = raw.match(new RegExp(`${name}=([^;]+)`))
  return match ? `${name}=${match[1]}` : ''
}

async function json(path, { method = 'GET', body, cookie = '', origin = tenantOrigin } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: origin,
      Referer: `${origin}/`,
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

async function createUser(tenantId, email, name, role) {
  const hash = await hashPassword(password)
  const user = await db.query(
    `INSERT INTO users (email,name,password_hash,email_verified_at)
     VALUES ($1,$2,$3,now()) RETURNING id`,
    [email, name, hash],
  )
  await db.query(
    `INSERT INTO tenant_memberships (tenant_id,user_id,role,status)
     VALUES ($1,$2,$3,'active')`,
    [tenantId, user.rows[0].id, role],
  )
  return user.rows[0].id
}

await db.connect()
try {
  console.log(`Portal approvals tenant: ${slug}`)
  const tenant = await db.query(
    `INSERT INTO tenants (slug,company_name,status)
     VALUES ($1,'Portal Approval E2E','active') RETURNING id`,
    [slug],
  )
  const tenantId = tenant.rows[0].id
  await db.query(
    `INSERT INTO tenant_settings (
       tenant_id,modules,onboarding_step,onboarding_completed_at,onboarding_data,configuration,tenant_url,portal_url,rmm_url
     ) VALUES ($1,'{"itsm":true,"rmm":false}'::jsonb,'complete',now(),'{}'::jsonb,'{}'::jsonb,$2,$3,NULL)`,
    [tenantId, tenantOrigin, portalOrigin],
  )

  const ownerId = await createUser(tenantId, ownerEmail, 'Approval Owner', 'owner')
  const approverId = await createUser(tenantId, approverEmail, 'Approval Manager', 'analyst')
  const requesterId = await createUser(tenantId, requesterEmail, 'Approval Requester', 'requester')

  const team = await db.query(
    `INSERT INTO organisation_teams (tenant_id,external_key,name,description,active)
     VALUES ($1,'TEAM-SERVICE-DESK','Service Desk','Approval E2E team',true) RETURNING id`,
    [tenantId],
  )
  const approverPerson = await db.query(
    `INSERT INTO organisation_people (tenant_id,external_key,user_id,name,email,job_title,access_profile,active)
     VALUES ($1,'PERSON-APPROVER',$2,'Approval Manager',$3,'Manager','analyst',true) RETURNING id`,
    [tenantId, approverId, approverEmail],
  )
  await db.query(
    `INSERT INTO organisation_people (
       tenant_id,external_key,user_id,name,email,job_title,access_profile,primary_team_id,manager_id,active
     ) VALUES ($1,'PERSON-REQUESTER',$2,'Approval Requester',$3,'Requester','employee',$4,$5,true)`,
    [tenantId, requesterId, requesterEmail, team.rows[0].id, approverPerson.rows[0].id],
  )
  await db.query(
    `INSERT INTO organisation_people (tenant_id,external_key,user_id,name,email,job_title,access_profile,primary_team_id,active)
     VALUES ($1,'PERSON-OWNER',$2,'Approval Owner',$3,'Owner','tenant_admin',$4,true)`,
    [tenantId, ownerId, ownerEmail, team.rows[0].id],
  )

  console.log('1. Configure a manager-approved Portal request and dependent task flow')
  const ownerLogin = await json('/api/v1/auth/login', {
    method: 'POST', body: { tenantSlug: slug, email: ownerEmail, password },
  })
  assert(ownerLogin.response.ok, `Owner login failed: ${ownerLogin.payload.error || ownerLogin.response.status}`)
  const ownerCookie = cookieFrom(ownerLogin.response, 'hi5central_session')
  assert(ownerCookie, 'Owner workspace cookie missing')

  const catalogue = await json('/api/v1/catalogue', {
    method: 'PUT', cookie: ownerCookie,
    body: {
      categories: ['Access'],
      items: [{
        id: 'CAT-APPROVAL-E2E', title: 'Approval E2E access', category: 'Access',
        description: 'Manager approval E2E request.', kind: 'request-form', requestType: 'Service Request',
        service: 'Access Management', team: 'Service Desk', approval: 'manager', approvalThreshold: null,
        visibility: 'portal', vendor: '', sku: '', priceMode: 'none', oneOffPrice: 0, monthlyPrice: 0,
        currency: 'GBP', workflow: 'Approval E2E',
        formSchema: [{ id: 'businessNeed', type: 'textarea', label: 'Business justification', required: true }],
        options: [], source: { provider: 'ci' }, active: true,
      }],
    },
  })
  assert(catalogue.response.ok, `Catalogue setup failed: ${catalogue.payload.error || catalogue.response.status}`)

  const flow = await json('/api/v1/catalogue/CAT-APPROVAL-E2E/fulfilment', {
    method: 'PUT', cookie: ownerCookie,
    body: { tasks: [
      { id: 'review', title: 'Review approved access', team: 'Service Desk', dependsOn: [] },
      { id: 'apply', title: 'Apply approved access', team: 'Service Desk', dependsOn: ['review'] },
    ] },
  })
  assert(flow.response.ok, `Fulfilment setup failed: ${flow.payload.error || flow.response.status}`)

  console.log('2. Confirm the analyst cannot use the Portal before an approval is assigned')
  const beforeAssignment = await json('/api/v1/portal/auth/login', {
    method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email: approverEmail, password },
  })
  assert(beforeAssignment.response.status === 403, `Unassigned analyst Portal login should be 403, got ${beforeAssignment.response.status}`)

  console.log('3. Submit as the real requester and keep the parent Service Request unassigned')
  const requesterLogin = await json('/api/v1/portal/auth/login', {
    method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email: requesterEmail, password },
  })
  assert(requesterLogin.response.ok, `Requester Portal login failed: ${requesterLogin.payload.error || requesterLogin.response.status}`)
  const requesterCookie = cookieFrom(requesterLogin.response, 'hi5central_portal_session')
  assert(requesterCookie, 'Requester Portal cookie missing')

  const submitted = await json('/api/v1/service-requests', {
    method: 'POST', origin: portalOrigin, cookie: requesterCookie,
    body: {
      catalogueItemId: 'CAT-APPROVAL-E2E', summary: 'Approval E2E access request',
      fields: { businessNeed: 'Validate Portal approval and task routing.' },
      details: { text: 'Approval E2E request.' }, urgency: 'Medium',
    },
  })
  assert(submitted.response.status === 201, `Request submission failed: ${submitted.payload.error || submitted.response.status}`)
  const reference = submitted.payload.reference
  assert(submitted.payload.status === 'Pending Approval', 'Request did not enter Pending Approval')
  assert(!submitted.payload.team, `Parent request inherited task team ${submitted.payload.team}`)
  assert(submitted.payload.requestTasks?.every((task) => task.status === 'Waiting'), 'Tasks were exposed before approval')

  const parent = await db.query(
    `SELECT fulfilment_team_id, fulfilment_team_snapshot, assigned_person_id
     FROM service_requests WHERE tenant_id=$1 AND reference=$2`,
    [tenantId, reference],
  )
  assert(parent.rows[0]?.fulfilment_team_id === null, 'Parent request was assigned a fulfilment team automatically')
  assert(parent.rows[0]?.assigned_person_id === null, 'Parent request was assigned a person automatically')
  assert(Object.keys(parent.rows[0]?.fulfilment_team_snapshot || {}).length === 0, 'Parent request retained an automatic team snapshot')

  console.log('4. Confirm assigned approver can decide from an ITSM-capable workspace')
  const approverWorkspace = await json('/api/v1/auth/login', {
    method: 'POST', body: { tenantSlug: slug, email: approverEmail, password },
  })
  assert(approverWorkspace.response.ok, `Approver workspace login failed: ${approverWorkspace.payload.error || approverWorkspace.response.status}`)
  const approverWorkspaceCookie = cookieFrom(approverWorkspace.response, 'hi5central_session')
  const workflow = await json(`/api/v1/workflows/${reference}`, { cookie: approverWorkspaceCookie })
  assert(workflow.response.ok, `Approver could not load request workflow: ${workflow.payload.error || workflow.response.status}`)
  assert(workflow.payload.approvals?.[0]?.canDecide === true, 'Assigned workspace approver was not given a decision action')

  console.log('5. Confirm assigned approver receives approval-only Portal access and My Approvals')
  const approverPortal = await json('/api/v1/portal/auth/login', {
    method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email: approverEmail, password },
  })
  assert(approverPortal.response.ok, `Assigned approver Portal login failed: ${approverPortal.payload.error || approverPortal.response.status}`)
  assert(approverPortal.payload.portalCapabilities?.requests === false, 'Approval-only analyst unexpectedly received requester Portal access')
  assert(approverPortal.payload.portalCapabilities?.approvals === true, 'Assigned approver did not receive My Approvals capability')
  const approverPortalCookie = cookieFrom(approverPortal.response, 'hi5central_portal_session')
  assert(approverPortalCookie, 'Approver Portal cookie missing')

  const approvals = await json('/api/v1/portal/approvals', { origin: portalOrigin, cookie: approverPortalCookie })
  assert(approvals.response.ok, `My Approvals failed: ${approvals.payload.error || approvals.response.status}`)
  const approval = approvals.payload.items?.find((item) => item.request?.reference === reference)
  assert(approval?.status === 'Pending', 'Assigned request did not appear in My Approvals')

  const detail = await json(`/api/v1/portal/approvals/${approval.id}`, { origin: portalOrigin, cookie: approverPortalCookie })
  assert(detail.response.ok && detail.payload.canDecide === true, 'Approval detail was not decision-enabled')
  assert(detail.payload.request?.requester === 'Approval Requester', 'Approval detail did not include requester context')

  console.log('6. Approve from Portal and release only the first dependency-ready task')
  const decision = await json(`/api/v1/service-requests/${reference}/approvals/${approval.id}/decision`, {
    method: 'POST', origin: portalOrigin, cookie: approverPortalCookie,
    body: { decision: 'Approved', note: 'Approved in Portal E2E.' },
  })
  assert(decision.response.ok, `Portal approval failed: ${decision.payload.error || decision.response.status}`)

  const finalState = await db.query(
    `SELECT status, fulfilment_team_id, assigned_person_id
     FROM service_requests WHERE tenant_id=$1 AND reference=$2`,
    [tenantId, reference],
  )
  assert(finalState.rows[0]?.status === 'Approved', `Approved parent request should remain in Approved queue, got ${finalState.rows[0]?.status}`)
  assert(finalState.rows[0]?.fulfilment_team_id === null, 'Approved parent request was automatically team-owned')
  assert(finalState.rows[0]?.assigned_person_id === null, 'Approved parent request was automatically person-owned')

  const tasks = await db.query(
    `SELECT title,status,team_snapshot FROM service_request_tasks
     WHERE tenant_id=$1 AND request_id=(SELECT id FROM service_requests WHERE tenant_id=$1 AND reference=$2)
     ORDER BY created_at`,
    [tenantId, reference],
  )
  assert(tasks.rows.length === 2, 'Expected two fulfilment tasks')
  assert(tasks.rows[0]?.status === 'Ready', 'First task was not released after approval')
  assert(tasks.rows[1]?.status === 'Waiting', 'Dependent task was released too early')
  assert(tasks.rows.every((task) => task.team_snapshot?.name === 'Service Desk'), 'Tasks did not retain their configured team routing')

  console.log('Portal approvals E2E passed')
} finally {
  await db.end()
}
