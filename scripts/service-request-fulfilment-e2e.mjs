import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { hashPassword } from '../src/password.js'

const { Client } = pg
const API = process.env.API_URL || 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-flow-${suffix}`.slice(0, 42)
const email = `owner-${suffix}@hi5central.test`
const password = `Flow-${randomBytes(12).toString('base64url')}Aa1`
const tenantOrigin = `https://${slug}.hi5central.com`
const db = new Client({ connectionString: process.env.DATABASE_URL })
const targetDate = '2026-10-12'
const titleDate = '12 Oct 2026'
const skippedTargetDate = '2026-10-19'
const skippedTitleDate = '19 Oct 2026'

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

function taskByTitle(payload, title) {
  return (payload.requestTasks || []).find((task) => task.title === title)
}

const flowTasks = [
  { id: 'identity', title: 'Prepare identity', team: 'Service Desk', dependsOn: [] },
  { id: 'entitlement', title: 'Prepare entitlement', team: 'Procurement', dependsOn: [] },
  {
    id: 'equipment',
    title: 'Prepare equipment',
    team: 'Procurement',
    dependsOn: ['identity', 'entitlement'],
    condition: { fieldId: 'needsEquipment', operator: 'equals', value: 'Yes' },
  },
  { id: 'handover', title: 'Complete workstation handover', team: 'Desktop', dependsOn: ['equipment'] },
]

await db.connect()
try {
  console.log(`Fulfilment tenant: ${slug}`)
  const hash = await hashPassword(password)
  const tenant = await db.query(
    `INSERT INTO tenants (slug,company_name,status) VALUES ($1,'Fulfilment Flow Tenant','active') RETURNING id`,
    [slug],
  )
  const tenantId = tenant.rows[0].id
  const user = await db.query(
    `INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,'Flow Owner',$2,now()) RETURNING id`,
    [email, hash],
  )
  const userId = user.rows[0].id
  await db.query(`INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,'owner','active')`, [tenantId, userId])
  await db.query(
    `INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,onboarding_completed_at,onboarding_data,configuration,tenant_url,portal_url,rmm_url)
     VALUES ($1,'{"itsm":true,"rmm":false}'::jsonb,'complete',now(),'{}'::jsonb,'{}'::jsonb,$2,$3,NULL)`,
    [tenantId, tenantOrigin, `https://${slug}-portal.hi5central.com`],
  )
  await db.query(
    `INSERT INTO organisation_people (tenant_id,external_key,user_id,name,email,access_profile,active)
     VALUES ($1,'PERSON-OWNER',$2,'Flow Owner',$3,'technician',true)`,
    [tenantId, userId, email],
  )
  for (const [key, name] of [
    ['TEAM-SERVICE-DESK', 'Service Desk'],
    ['TEAM-PROCUREMENT', 'Procurement'],
    ['TEAM-DESKTOP', 'Desktop'],
  ]) {
    await db.query(
      `INSERT INTO organisation_teams (tenant_id,external_key,name,description,active)
       VALUES ($1,$2,$3,'Fulfilment acceptance team',true)`,
      [tenantId, key, name],
    )
  }

  console.log('1. Sign in as tenant owner')
  const login = await json('/api/v1/auth/login', { method: 'POST', body: { tenantSlug: slug, email, password } })
  assert(login.response.ok, `Owner login failed: ${login.payload.error || login.response.status}`)
  const cookie = cookieFrom(login.response)
  assert(cookie, 'Owner session cookie was not issued')

  console.log('2. Create a request-form catalogue item with date and branching fields')
  const catalogue = await json('/api/v1/catalogue', {
    method: 'PUT',
    cookie,
    body: {
      categories: ['Joiners & movers'],
      items: [{
        id: 'CAT-JOINER-FLOW',
        title: 'Joiner preparation',
        category: 'Joiners & movers',
        description: 'Acceptance request for fulfilment dependencies.',
        kind: 'request-form',
        requestType: 'Service Request',
        service: 'People services',
        team: 'Service Desk',
        approval: 'none',
        approvalThreshold: null,
        visibility: 'technicians',
        vendor: '',
        sku: '',
        priceMode: 'none',
        oneOffPrice: 0,
        monthlyPrice: 0,
        currency: 'GBP',
        workflow: 'Joiner preparation',
        formSchema: [
          { id: 'targetDate', label: 'Target date', type: 'date', required: true },
          { id: 'needsEquipment', label: 'Equipment required?', type: 'select', required: true, options: ['Yes', 'No'] },
        ],
        options: [],
        source: { provider: 'ci' },
        active: true,
      }],
    },
  })
  assert(catalogue.response.ok, `Catalogue save failed: ${catalogue.payload.error || catalogue.response.status}`)

  console.log('3. Save a four-task flow with a conditional middle stage')
  const flow = await json('/api/v1/catalogue/CAT-JOINER-FLOW/fulfilment', {
    method: 'PUT',
    cookie,
    body: { tasks: flowTasks },
  })
  assert(flow.response.ok, `Flow save failed: ${flow.payload.error || flow.response.status}`)
  assert(flow.payload.tasks?.length === 4, 'Flow did not persist four tasks')
  assert(flow.payload.tasks.every((task) => task.titleDateFieldId === '__auto__'), 'Flow did not default task title dates to automatic')
  assert(flow.payload.tasks.find((task) => task.id === 'equipment')?.condition?.fieldId === 'needsEquipment', 'Conditional task rule was not persisted')
  assert(flow.payload.dateFields?.[0]?.id === 'targetDate', 'Flow did not return the request date field')
  assert(flow.payload.conditionFields?.some((field) => field.id === 'needsEquipment'), 'Flow did not return request fields for condition editing')

  console.log('4. Reject a condition that refers to a missing request field')
  const invalidFlow = await json('/api/v1/catalogue/CAT-JOINER-FLOW/fulfilment', {
    method: 'PUT',
    cookie,
    body: {
      tasks: [{ id: 'bad', title: 'Invalid conditional task', team: 'Service Desk', dependsOn: [], condition: { fieldId: 'missingField', operator: 'equals', value: 'Yes' } }],
    },
  })
  assert(invalidFlow.response.status === 400, `Invalid condition should return 400, got ${invalidFlow.response.status}`)
  const flowAfterInvalid = await json('/api/v1/catalogue/CAT-JOINER-FLOW/fulfilment', { cookie })
  assert(flowAfterInvalid.payload.tasks?.length === 4, 'Invalid conditional save changed the valid flow')

  console.log('5. Submit a matching Service Request and verify all four dated tasks')
  const request = await json('/api/v1/service-requests', {
    method: 'POST',
    cookie,
    body: { catalogueItemId: 'CAT-JOINER-FLOW', summary: 'Prepare colleague access and equipment', fields: { targetDate, needsEquipment: 'Yes' }, details: { text: 'Fulfilment flow acceptance request.' }, urgency: 'Medium' },
  })
  assert(request.response.status === 201, `Request creation failed: ${request.payload.error || request.response.status}`)
  assert(request.payload.requestTasks?.length === 4, `Expected four request tasks, got ${request.payload.requestTasks?.length || 0}`)
  assert(request.payload.skippedFulfilmentTasks === 0, 'Matching condition should not skip a task')
  const reference = request.payload.reference
  const identity = taskByTitle(request.payload, `Prepare identity · ${titleDate}`)
  const entitlement = taskByTitle(request.payload, `Prepare entitlement · ${titleDate}`)
  const equipment = taskByTitle(request.payload, `Prepare equipment · ${titleDate}`)
  const handover = taskByTitle(request.payload, `Complete workstation handover · ${titleDate}`)
  assert(identity, 'First task did not include the submitted request date in its title')
  assert(entitlement, 'Second task did not include the submitted request date in its title')
  assert(equipment, 'Conditional task did not include the submitted request date in its title')
  assert(handover, 'Final task did not include the submitted request date in its title')
  assert(identity?.status === 'Ready', 'First parallel task should be Ready')
  assert(entitlement?.status === 'Ready', 'Second parallel task should be Ready')
  assert(equipment?.status === 'Waiting', 'Dependent task should start Waiting')
  assert(handover?.status === 'Waiting', 'Final dependent task should start Waiting')
  assert(identity?.team === 'Service Desk', 'First task did not route to Service Desk')
  assert(entitlement?.team === 'Procurement', 'Second task did not route to Procurement')
  assert(handover?.team === 'Desktop', 'Final task did not route to Desktop')

  console.log('6. Prevent a waiting task from being worked early')
  const early = await json(`/api/v1/service-requests/${reference}/tasks/${equipment.id}`, {
    method: 'PATCH', cookie, body: { status: 'In Progress' },
  })
  assert(early.response.status === 409, `Waiting task should be rejected with 409, got ${early.response.status}`)

  console.log('7. Complete only one parallel task and keep the next stage waiting')
  const completeIdentity = await json(`/api/v1/service-requests/${reference}/tasks/${identity.id}`, {
    method: 'PATCH', cookie, body: { status: 'Completed', completionNotes: 'Identity ready.' },
  })
  assert(completeIdentity.response.ok, `Identity task completion failed: ${completeIdentity.payload.error || completeIdentity.response.status}`)
  let refreshed = await json(`/api/v1/service-requests/${reference}`, { cookie })
  assert(taskByTitle(refreshed.payload, `Prepare equipment · ${titleDate}`)?.status === 'Waiting', 'Equipment should wait for both prerequisite tasks')

  console.log('8. Complete the second parallel task and unlock the conditional stage')
  const completeEntitlement = await json(`/api/v1/service-requests/${reference}/tasks/${entitlement.id}`, {
    method: 'PATCH', cookie, body: { status: 'Completed', completionNotes: 'Entitlement ready.' },
  })
  assert(completeEntitlement.response.ok, `Entitlement task completion failed: ${completeEntitlement.payload.error || completeEntitlement.response.status}`)
  refreshed = await json(`/api/v1/service-requests/${reference}`, { cookie })
  const equipmentReady = taskByTitle(refreshed.payload, `Prepare equipment · ${titleDate}`)
  assert(equipmentReady?.status === 'Ready', 'Equipment should become Ready when both prerequisite tasks are complete')

  console.log('9. Unlock the final task only after the conditional intermediate task completes')
  const completeEquipment = await json(`/api/v1/service-requests/${reference}/tasks/${equipmentReady.id}`, {
    method: 'PATCH', cookie, body: { status: 'Completed', completionNotes: 'Equipment prepared.' },
  })
  assert(completeEquipment.response.ok, `Equipment task completion failed: ${completeEquipment.payload.error || completeEquipment.response.status}`)
  refreshed = await json(`/api/v1/service-requests/${reference}`, { cookie })
  const handoverReady = taskByTitle(refreshed.payload, `Complete workstation handover · ${titleDate}`)
  assert(handoverReady?.status === 'Ready', 'Final task should unlock after its prerequisite completes')

  console.log('10. Block request completion until every generated task is complete')
  const startRequest = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie, body: { targetStatus: 'In Progress', values: {} },
  })
  assert(startRequest.response.ok, `Could not start request: ${startRequest.payload.error || startRequest.response.status}`)
  const prematureComplete = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie, body: { targetStatus: 'Completed', values: { completionNotes: 'Done.' } },
  })
  assert(prematureComplete.response.status === 409, `Request completion should be blocked while tasks remain, got ${prematureComplete.response.status}`)

  const completeHandover = await json(`/api/v1/service-requests/${reference}/tasks/${handoverReady.id}`, {
    method: 'PATCH', cookie, body: { status: 'Completed', completionNotes: 'Handover complete.' },
  })
  assert(completeHandover.response.ok, `Final task completion failed: ${completeHandover.payload.error || completeHandover.response.status}`)
  const completeRequest = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie, body: { targetStatus: 'Completed', values: { completionNotes: 'All fulfilment tasks completed.' } },
  })
  assert(completeRequest.response.ok, `Request completion failed: ${completeRequest.payload.error || completeRequest.response.status}`)

  console.log('11. Confirm the matching request keeps an immutable dated conditional flow snapshot')
  const snapshot = await db.query(`SELECT workflow_tasks_snapshot FROM service_requests WHERE tenant_id=$1 AND reference=$2`, [tenantId, reference])
  const savedFlow = snapshot.rows[0]?.workflow_tasks_snapshot
  assert(Array.isArray(savedFlow) && savedFlow.length === 4, 'Request workflow snapshot was not stored')
  assert(savedFlow[0]?.baseTitle === 'Prepare identity', 'Snapshot did not retain the base task title')
  assert(savedFlow[0]?.title === `Prepare identity · ${titleDate}`, 'Snapshot did not retain the generated dated title')
  assert(savedFlow[0]?.titleDate === titleDate, 'Snapshot did not retain the resolved task title date')
  assert(savedFlow[0]?.titleDateFieldLabel === 'Target date', 'Snapshot did not retain the date field context')
  assert(savedFlow.find((task) => task.id === 'equipment')?.condition?.fieldId === 'needsEquipment', 'Snapshot did not retain the matched task condition')

  console.log('12. Submit a non-matching request and skip the equipment task')
  const skippedRequest = await json('/api/v1/service-requests', {
    method: 'POST',
    cookie,
    body: { catalogueItemId: 'CAT-JOINER-FLOW', summary: 'Prepare colleague access without equipment', fields: { targetDate: skippedTargetDate, needsEquipment: 'No' }, details: { text: 'Conditional skip acceptance request.' }, urgency: 'Medium' },
  })
  assert(skippedRequest.response.status === 201, `Conditional request creation failed: ${skippedRequest.payload.error || skippedRequest.response.status}`)
  assert(skippedRequest.payload.requestTasks?.length === 3, `Expected three generated tasks after conditional skip, got ${skippedRequest.payload.requestTasks?.length || 0}`)
  assert(skippedRequest.payload.skippedFulfilmentTasks === 1, 'Non-matching condition should report one skipped task')
  assert(!taskByTitle(skippedRequest.payload, `Prepare equipment · ${skippedTitleDate}`), 'Equipment task should not be generated when equipment is not required')
  const skippedReference = skippedRequest.payload.reference
  const skippedIdentity = taskByTitle(skippedRequest.payload, `Prepare identity · ${skippedTitleDate}`)
  const skippedEntitlement = taskByTitle(skippedRequest.payload, `Prepare entitlement · ${skippedTitleDate}`)
  const skippedHandover = taskByTitle(skippedRequest.payload, `Complete workstation handover · ${skippedTitleDate}`)
  assert(skippedIdentity?.status === 'Ready', 'Identity should remain Ready in the skipped branch')
  assert(skippedEntitlement?.status === 'Ready', 'Entitlement should remain Ready in the skipped branch')
  assert(skippedHandover?.status === 'Waiting', 'Handover should inherit the skipped task prerequisites rather than start early')
  assert(skippedHandover?.dependencies?.length === 2, 'Handover should inherit both active prerequisites from the skipped equipment task')

  console.log('13. Complete inherited prerequisites and unlock the final task')
  for (const task of [skippedIdentity, skippedEntitlement]) {
    const completed = await json(`/api/v1/service-requests/${skippedReference}/tasks/${task.id}`, {
      method: 'PATCH', cookie, body: { status: 'Completed', completionNotes: 'Prerequisite completed.' },
    })
    assert(completed.response.ok, `Conditional prerequisite completion failed: ${completed.payload.error || completed.response.status}`)
  }
  const skippedRefreshed = await json(`/api/v1/service-requests/${skippedReference}`, { cookie })
  assert(taskByTitle(skippedRefreshed.payload, `Complete workstation handover · ${skippedTitleDate}`)?.status === 'Ready', 'Handover did not unlock after inherited prerequisites completed')

  console.log('14. Confirm the skipped request snapshot contains only generated work')
  const skippedSnapshot = await db.query(`SELECT workflow_tasks_snapshot FROM service_requests WHERE tenant_id=$1 AND reference=$2`, [tenantId, skippedReference])
  const skippedSavedFlow = skippedSnapshot.rows[0]?.workflow_tasks_snapshot
  assert(Array.isArray(skippedSavedFlow) && skippedSavedFlow.length === 3, 'Skipped request snapshot should contain only three generated tasks')
  assert(!skippedSavedFlow.some((task) => task.id === 'equipment'), 'Skipped task should not be retained as generated work in the immutable request snapshot')
  const savedHandover = skippedSavedFlow.find((task) => task.id === 'handover')
  assert(savedHandover?.dependsOn?.length === 2, 'Snapshot did not retain inherited prerequisites after a conditional skip')

  console.log('Service Request fulfilment flow acceptance passed')
} finally {
  await db.end()
}
