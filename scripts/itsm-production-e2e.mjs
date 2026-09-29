import { createHash, randomBytes } from 'node:crypto'
import pg from 'pg'

const { Client } = pg
const API = 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-itsm-${suffix}`.slice(0, 42)
const otherSlug = `ci-other-${suffix}`.slice(0, 42)
const ownerEmail = `itsm-owner-${suffix}@hi5central.test`
const tenantOrigin = `https://${slug}.hi5central.com`
const db = new Client({ connectionString: process.env.DATABASE_URL })
const token = randomBytes(32).toString('base64url')
const cookie = `hi5central_session=${token}`

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

async function json(path, { method = 'GET', body } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: tenantOrigin,
      Cookie: cookie,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

await db.connect()
let tenantId = null
let otherTenantId = null
let ownerId = null
try {
  console.log(`Production ITSM tenant: ${slug}`)
  console.log('1. Seeding an isolated completed tenant and technician session')

  const tenant = await db.query(
    `INSERT INTO tenants (slug, company_name, status)
     VALUES ($1, 'CI Production ITSM', 'active') RETURNING id`,
    [slug],
  )
  tenantId = tenant.rows[0].id

  const owner = await db.query(
    `INSERT INTO users (email, name, password_hash, email_verified_at)
     VALUES ($1, 'CI ITSM Owner', 'test-only', now()) RETURNING id`,
    [ownerEmail],
  )
  ownerId = owner.rows[0].id

  await db.query(
    `INSERT INTO tenant_memberships (tenant_id, user_id, role, status)
     VALUES ($1, $2, 'owner', 'active')`,
    [tenantId, ownerId],
  )

  const configuration = {
    security: { requireMfa: false },
    itsm: {
      numberingMode: 'default',
      recordPrefixes: { incident: 'INC-', serviceRequest: 'REQ-', problem: 'PRB-', change: 'CHG-' },
      recordDigits: '5',
      managerApprovalThreshold: '500',
    },
  }
  await db.query(
    `INSERT INTO tenant_settings (
       tenant_id, modules, onboarding_step, onboarding_completed_at,
       tenant_url, portal_url, onboarding_data, configuration
     ) VALUES ($1, '{"itsm":true,"rmm":false}'::jsonb, 'complete', now(), $2, $3, $4::jsonb, $4::jsonb)`,
    [tenantId, tenantOrigin, `https://${slug}-portal.hi5central.com`, JSON.stringify(configuration)],
  )

  await db.query(
    `INSERT INTO auth_sessions (tenant_id, user_id, token_hash, expires_at)
     VALUES ($1, $2, $3, now() + interval '1 hour')`,
    [tenantId, ownerId, createHash('sha256').update(token).digest('hex')],
  )

  const department = await db.query(
    `INSERT INTO organisation_departments (tenant_id, external_key, name)
     VALUES ($1, 'DEPT-ITSM', 'IT') RETURNING id`,
    [tenantId],
  )
  const team = await db.query(
    `INSERT INTO organisation_teams (tenant_id, external_key, department_id, name)
     VALUES ($1, 'TEAM-CI-SD', $2, 'Service Desk') RETURNING id`,
    [tenantId, department.rows[0].id],
  )
  await db.query(
    `INSERT INTO organisation_people (
       tenant_id, external_key, user_id, primary_team_id, department_id, name, email, job_title, access_profile, active
     ) VALUES ($1, 'CI-AGT-OWNER', $2, $3, $4, 'CI ITSM Owner', $5, 'Service Desk Owner', 'tenant_admin', true)`,
    [tenantId, ownerId, team.rows[0].id, department.rows[0].id, ownerEmail],
  )
  await db.query(
    `INSERT INTO organisation_people (
       tenant_id, external_key, primary_team_id, department_id, name, email, job_title, access_profile, active
     ) VALUES ($1, 'USR-E2E-REQUESTER', $2, $3, 'CI Requester', $4, 'Employee', 'employee', true)`,
    [tenantId, team.rows[0].id, department.rows[0].id, `requester-${suffix}@hi5central.test`],
  )

  console.log('2. Creating persistent Incident, Problem and Change records')
  const incident = await json('/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Incident', requesterId: 'USR-E2E-REQUESTER', requester: 'CI Requester',
      title: 'CI production incident', description: 'Persistent incident E2E',
      service: 'Identity', category: 'Authentication', priority: 'High', status: 'New',
      team: 'Service Desk', assignee: 'Unassigned', impact: 'High', urgency: 'Medium', slaPercent: 12,
    },
  })
  assert(incident.response.status === 201, `Incident creation failed: ${incident.payload.error || incident.response.status}`)
  assert(/^INC-\d+$/.test(incident.payload.id), `Unexpected Incident reference: ${incident.payload.id}`)
  assert(incident.payload.requester === 'CI Requester', 'Incident requester snapshot was not persisted')

  const problem = await json('/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Problem', requesterId: 'USR-E2E-REQUESTER', title: 'CI recurring authentication failures',
      description: 'Root cause investigation', service: 'Identity', category: 'Authentication', priority: 'Medium',
      team: 'Service Desk', problemImpactScope: 'Multiple users', problemHypothesis: 'Token expiry race', relatedIncidents: [incident.payload.id],
    },
  })
  assert(problem.response.status === 201 && /^PRB-\d+$/.test(problem.payload.id), `Problem creation failed: ${problem.payload.error || problem.response.status}`)

  const change = await json('/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Change', requesterId: 'USR-E2E-REQUESTER', title: 'CI identity policy update',
      description: 'Controlled policy change', service: 'Identity', category: 'Configuration', priority: 'High',
      status: 'Draft', team: 'Service Desk', changeType: 'Normal', risk: 'High', implementationPlan: 'Apply policy', backoutPlan: 'Restore previous policy',
    },
  })
  assert(change.response.status === 201 && /^CHG-\d+$/.test(change.payload.id), `Change creation failed: ${change.payload.error || change.response.status}`)

  console.log('3. Updating Incident state and activity through the production API')
  const patched = await json(`/api/v1/itsm-records/${encodeURIComponent(incident.payload.id)}`, {
    method: 'PATCH',
    body: { status: 'In Progress', assignee: 'CI ITSM Owner', recordData: { impact: 'High', urgency: 'Medium', slaPercent: 22 } },
  })
  assert(patched.response.ok && patched.payload.status === 'In Progress', 'Incident state update was not persisted')
  assert(patched.payload.assignee === 'CI ITSM Owner', 'Incident assignee was not resolved to an active technician account')

  const activity = await json(`/api/v1/itsm-records/${encodeURIComponent(incident.payload.id)}/activities`, {
    method: 'POST', body: { kind: 'work', text: 'Internal CI investigation note' },
  })
  assert(activity.response.status === 201, `Incident activity failed: ${activity.payload.error || activity.response.status}`)
  assert(activity.payload.activities?.some((item) => item.text === 'Internal CI investigation note' && item.visibility === 'internal'), 'Internal Incident activity was not persisted')

  console.log('4. Proving shared queue filtering and pagination')
  const incidentQueue = await json('/api/v1/itsm-queue?type=Incident&limit=1&offset=0')
  assert(incidentQueue.response.ok, `Incident queue failed: ${incidentQueue.payload.error || incidentQueue.response.status}`)
  assert(incidentQueue.payload.total === 1 && incidentQueue.payload.items?.length === 1, 'Incident queue pagination/total is incorrect')
  assert(incidentQueue.payload.items[0].id === incident.payload.id, 'Incident queue returned the wrong record')
  assert(incidentQueue.payload.filters?.teams?.includes('Service Desk'), 'Queue filter metadata omitted the real assignment group')

  const searched = await json('/api/v1/itsm-queue?type=Problem&search=recurring&limit=25&offset=0')
  assert(searched.response.ok && searched.payload.total === 1 && searched.payload.items[0].id === problem.payload.id, 'Queue search did not find the persisted Problem')

  console.log('5. Proving tenant isolation')
  const otherTenant = await db.query(
    `INSERT INTO tenants (slug, company_name, status) VALUES ($1, 'Other CI Tenant', 'active') RETURNING id`,
    [otherSlug],
  )
  otherTenantId = otherTenant.rows[0].id
  await db.query(
    `INSERT INTO itsm_records (tenant_id, reference, record_type, title, status)
     VALUES ($1, 'INC-99999', 'Incident', 'Other tenant secret incident', 'New')`,
    [otherTenantId],
  )
  const isolated = await json('/api/v1/itsm-queue?type=Incident&search=secret&limit=25&offset=0')
  assert(isolated.response.ok && isolated.payload.total === 0, 'Shared ITSM queue leaked another tenant record')

  console.log('6. Proving concurrent Incident numbering is collision-safe')
  const concurrentBody = (suffixLabel) => ({
    type: 'Incident', requesterId: 'USR-E2E-REQUESTER', requester: 'CI Requester',
    title: `Concurrent CI incident ${suffixLabel}`, description: 'Parallel reference allocation test',
    service: 'Identity', category: 'Concurrency', priority: 'Medium', status: 'New',
    team: 'Service Desk', assignee: 'Unassigned',
  })
  const [concurrentA, concurrentB] = await Promise.all([
    json('/api/v1/itsm-records', { method: 'POST', body: concurrentBody('A') }),
    json('/api/v1/itsm-records', { method: 'POST', body: concurrentBody('B') }),
  ])
  assert(concurrentA.response.status === 201, `Concurrent Incident A failed: ${concurrentA.payload.error || concurrentA.response.status}`)
  assert(concurrentB.response.status === 201, `Concurrent Incident B failed: ${concurrentB.payload.error || concurrentB.response.status}`)
  assert(concurrentA.payload.id !== concurrentB.payload.id, `Concurrent Incidents received the same reference: ${concurrentA.payload.id}`)
  const concurrentNumbers = [concurrentA.payload.id, concurrentB.payload.id]
    .map((reference) => Number(String(reference).split('-').pop()))
    .sort((left, right) => left - right)
  assert(concurrentNumbers.every(Number.isFinite), 'Concurrent Incident references were not numeric')
  assert(concurrentNumbers[1] === concurrentNumbers[0] + 1, `Concurrent Incident references were not consecutive: ${concurrentA.payload.id}, ${concurrentB.payload.id}`)

  console.log('7. Publishing a real technician Service Catalogue form')
  const catalogue = await json('/api/v1/catalogue', {
    method: 'PUT',
    body: {
      categories: ['Software'],
      items: [
        {
          id: 'PROD-E2E-APP', title: 'CI Licensed App', category: 'Software', description: 'E2E priced product', kind: 'product',
          visibility: 'technicians', vendor: 'Hi5 Vendor', sku: 'APP-E2E', priceMode: 'fixed', oneOffPrice: 125, monthlyPrice: 0, currency: 'GBP', active: true,
        },
        {
          id: 'FORM-E2E-APP', title: 'Request CI application', category: 'Software', description: 'Technician on-behalf Service Request E2E', kind: 'request-form',
          requestType: 'Service Request', service: 'Applications', team: 'Service Desk', approval: 'none', visibility: 'technicians', active: true,
          formSchema: [
            { id: 'application', type: 'product', label: 'Application', required: true, options: [{ value: 'ci-app', label: 'Stale client label', itemId: 'PROD-E2E-APP', cost: 1 }] },
            { id: 'access', type: 'select', label: 'Access required', required: true, options: ['Standard user', 'Read only'] },
          ],
        },
      ],
    },
  })
  assert(catalogue.response.ok, `Catalogue publish failed: ${catalogue.payload.error || catalogue.response.status}`)

  console.log('8. Creating a technician Service Request on behalf of the Person')
  const request = await json('/api/v1/service-requests', {
    method: 'POST',
    body: {
      requesterPersonId: 'USR-E2E-REQUESTER',
      catalogueItemId: 'FORM-E2E-APP',
      summary: 'CI application access',
      urgency: 'Medium',
      fields: { application: 'ci-app', access: 'Standard user' },
      details: { text: 'Created by technician on behalf of requester.' },
    },
  })
  assert(request.response.status === 201, `Technician Service Request failed: ${request.payload.error || request.response.status}`)
  assert(/^REQ-\d+$/.test(request.payload.id), `Unexpected Service Request reference: ${request.payload.id}`)
  assert(request.payload.requester === 'CI Requester', 'Technician Service Request did not snapshot selected requester')
  assert(Number(request.payload.oneOffCost) === 125, `Server-side Service Request price was not authoritative: ${request.payload.oneOffCost}`)
  assert(request.payload.requestedItems?.[0]?.name === 'CI Licensed App', 'Service Request did not snapshot the live product')

  const requestQueue = await json('/api/v1/itsm-queue?type=Service%20Request&limit=25&offset=0')
  assert(requestQueue.response.ok && requestQueue.payload.items?.some((item) => item.id === request.payload.id), 'Shared queue did not include the real Service Request')

  console.log('9. Verifying database persistence directly')
  const counts = await db.query(
    `SELECT
       (SELECT count(*)::int FROM itsm_records WHERE tenant_id = $1) AS generic_records,
       (SELECT count(DISTINCT reference)::int FROM itsm_records WHERE tenant_id = $1) AS unique_references,
       (SELECT count(*)::int FROM itsm_record_activities a JOIN itsm_records r ON r.id = a.record_id WHERE r.tenant_id = $1) AS generic_activities,
       (SELECT count(*)::int FROM service_requests WHERE tenant_id = $1) AS service_requests`,
    [tenantId],
  )
  assert(counts.rows[0].generic_records === 5, `Expected 5 persistent generic ITSM records, got ${counts.rows[0].generic_records}`)
  assert(counts.rows[0].unique_references === 5, `Expected 5 unique persistent ITSM references, got ${counts.rows[0].unique_references}`)
  assert(counts.rows[0].generic_activities >= 6, 'Expected create/activity audit rows for generic ITSM records')
  assert(counts.rows[0].service_requests === 1, 'Expected one persistent Service Request')

  console.log('Production ITSM persistence E2E passed')
} finally {
  if (tenantId) await db.query('DELETE FROM tenants WHERE id = $1', [tenantId]).catch(() => {})
  if (otherTenantId) await db.query('DELETE FROM tenants WHERE id = $1', [otherTenantId]).catch(() => {})
  if (ownerId) await db.query('DELETE FROM users WHERE id = $1', [ownerId]).catch(() => {})
  await db.end()
}
