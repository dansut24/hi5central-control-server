import { createHash, createHmac, randomBytes } from 'node:crypto'
import pg from 'pg'

const { Client } = pg
const API = 'http://127.0.0.1:3001'
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`
const slug = `ci-portal-${suffix}`.slice(0, 42)
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

function cookieFrom(response) {
  const raw = response.headers.get('set-cookie') || ''
  const match = raw.match(/hi5central_session=([^;]+)/)
  return match ? `hi5central_session=${match[1]}` : ''
}

async function json(path, { method = 'GET', body, cookie = '', origin = tenantOrigin, redirect = 'follow' } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    redirect,
    headers: {
      Origin: origin,
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = redirect === 'manual' ? {} : await response.json().catch(() => ({}))
  return { response, payload }
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const output = []
  for (const ch of String(input).replace(/=+$/g, '').toUpperCase()) {
    const index = alphabet.indexOf(ch)
    if (index < 0) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(output)
}

function totp(secret) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const digest = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const offset = digest[digest.length - 1] & 15
  const binary = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) >>> 0
  return String(binary % 1_000_000).padStart(6, '0')
}

async function saveOnboarding(cookie, step, data) {
  const result = await json('/api/v1/onboarding/step', { method: 'POST', cookie, body: { step, data } })
  assert(result.response.ok, `Onboarding step ${step} failed: ${result.payload.error || result.response.status}`)
  return result.payload
}

await db.connect()
try {
  console.log(`Fresh tenant: ${slug}`)
  console.log('1. Creating tenant through public signup')
  const signup = await json('/api/v1/auth/signup', {
    method: 'POST',
    origin: 'https://hi5central.com',
    body: {
      companyName: 'CI Portal Fresh Tenant',
      tenantSlug: slug,
      name: 'CI Tenant Owner',
      email: ownerEmail,
      password: ownerPassword,
      modules: ['itsm'],
    },
  })
  assert(signup.response.ok, `Signup failed: ${signup.payload.error || signup.response.status}`)

  const identity = await db.query(
    `SELECT t.id AS tenant_id, u.id AS user_id
     FROM tenants t
     JOIN tenant_memberships m ON m.tenant_id = t.id
     JOIN users u ON u.id = m.user_id
     WHERE t.slug = $1 AND u.email = $2`,
    [slug, ownerEmail],
  )
  assert(identity.rowCount === 1, 'Signup did not persist tenant owner')
  const tenantId = identity.rows[0].tenant_id

  console.log('2. Verifying email through the real verification endpoint')
  const verificationToken = randomBytes(32).toString('base64url')
  const verificationHash = createHash('sha256').update(verificationToken).digest('hex')
  await db.query(
    `UPDATE user_email_verifications
     SET token_hash = $3, expires_at = now() + interval '1 hour', used_at = NULL
     WHERE tenant_id = $1 AND user_id = $2`,
    [tenantId, identity.rows[0].user_id, verificationHash],
  )
  const verified = await json(`/api/v1/auth/verify-email?token=${encodeURIComponent(verificationToken)}`, {
    origin: tenantOrigin,
    redirect: 'manual',
  })
  assert([301, 302, 303, 307, 308].includes(verified.response.status), `Email verification did not redirect: ${verified.response.status}`)
  const ownerCookie = cookieFrom(verified.response)
  assert(ownerCookie, 'Email verification did not issue the owner session cookie')

  console.log('3. Completing full onboarding with enforced MFA')
  await saveOnboarding(ownerCookie, 'company', { displayName: 'CI Portal Fresh Tenant', legalName: 'CI Portal Fresh Tenant', timezone: 'Europe/London', locale: 'en-GB', country: 'United Kingdom', industry: 'Technology', employeeBand: '1-50' })
  await saveOnboarding(ownerCookie, 'theme', { accent: 'amber', mode: 'light', brandName: 'CI Portal Fresh Tenant', portalTitle: 'IT Help Centre' })
  await saveOnboarding(ownerCookie, 'users', { source: 'local', syncUsers: false, syncGroups: false, inviteMode: 'later', invites: '' })
  await saveOnboarding(ownerCookie, 'groups', { serviceDeskTeam: 'Service Desk', firstDepartment: 'IT', firstSite: 'Head Office', assignmentModel: 'team-first' })
  await saveOnboarding(ownerCookie, 'permissions', { preset: 'balanced', requesterAccess: 'portal', changeApprovalRole: 'admin-change' })

  const mfaSetup = await json('/api/v1/mfa/setup', { method: 'POST', cookie: ownerCookie, body: {} })
  assert(mfaSetup.response.ok && mfaSetup.payload.secret && mfaSetup.payload.setupToken, 'MFA setup failed during fresh onboarding')
  const mfaConfirm = await json('/api/v1/mfa/confirm', {
    method: 'POST',
    cookie: ownerCookie,
    body: { setupToken: mfaSetup.payload.setupToken, code: totp(mfaSetup.payload.secret) },
  })
  assert(mfaConfirm.response.ok && mfaConfirm.payload.enrolled === true, 'MFA confirmation failed during onboarding')

  await saveOnboarding(ownerCookie, 'security', { requireMfa: true, sessionHours: '8', passwordPolicy: 'strong', auditRetention: '365' })
  await saveOnboarding(ownerCookie, 'itsm', {
    numberingMode: 'default', recordPrefixes: { incident: 'INC-', serviceRequest: 'REQ-', problem: 'PRB-', change: 'CHG-' }, recordDigits: '5',
    supportEmail: 'support', defaultTeam: 'Service Desk', businessHours: 'uk-business', defaultPriority: 'Medium',
    p1ResponseMinutes: '15', p1ResolutionMinutes: '240', managerApprovalThreshold: '500', portalName: 'IT Help Centre',
    portalKnowledge: true, requesterComments: true, liveChat: true, aiAssistant: false, requesterNotifications: true, slaWarnings: true,
  })
  await saveOnboarding(ownerCookie, 'billing', { plan: 'trial', billingLater: true, expectedTechnicians: '5', expectedDevices: '0' })
  const complete = await json('/api/v1/onboarding/complete', { method: 'POST', cookie: ownerCookie })
  assert(complete.response.ok && complete.payload.onboarding?.completedAt, `Onboarding completion failed: ${complete.payload.error || complete.response.status}`)

  console.log('4. Creating a real Site and requester Person record')
  const organisation = await json('/api/v1/organisation', { cookie: ownerCookie })
  assert(organisation.response.ok && organisation.payload.people?.length, 'Authenticated owner Person was not created')
  assert(!(organisation.payload.sites || []).length, 'Fresh tenant unexpectedly contains a generated Site')

  const sitePut = await json('/api/v1/organisation/sites', {
    method: 'PUT',
    cookie: ownerCookie,
    body: { items: [{ id: 'SITE-PORTAL-E2E', code: 'HQ', name: 'Head Office', type: 'Office', city: 'London', country: 'United Kingdom', timezone: 'Europe/London', active: true }] },
  })
  assert(sitePut.response.ok && sitePut.payload.sites?.some((site) => site.id === 'SITE-PORTAL-E2E'), 'Explicit tenant Site was not persisted')

  const ownerPersonBase = organisation.payload.people[0]
  const ownerPerson = { ...ownerPersonBase, siteId: 'SITE-PORTAL-E2E', location: 'Head Office' }
  const requesterPerson = {
    id: 'USR-PORTAL-E2E',
    name: 'CI Portal Requester',
    email: requesterEmail,
    phone: '',
    role: 'Employee',
    teamId: ownerPerson.teamId || '',
    departmentId: ownerPerson.departmentId || '',
    siteId: ownerPerson.siteId,
    location: ownerPerson.location,
    managerId: ownerPerson.id,
    status: 'Available',
    capacityHours: 35,
    skills: [],
    workingPattern: {},
    accessProfile: 'employee',
    directorySource: { provider: 'local', label: 'Hi5Central', managedFields: [] },
    active: true,
  }
  const peoplePut = await json('/api/v1/organisation/people', {
    method: 'PUT', cookie: ownerCookie, body: { items: [ownerPerson, ...organisation.payload.people.slice(1), requesterPerson] },
  })
  assert(peoplePut.response.ok && peoplePut.payload.people?.some((person) => person.email === requesterEmail), 'Requester Person was not persisted')

  console.log('5. Publishing a priced Portal catalogue item')
  const catalogue = await json('/api/v1/catalogue', {
    method: 'PUT',
    cookie: ownerCookie,
    body: {
      categories: ['Hardware'],
      items: [
        {
          id: 'PROD-CI-LAPTOP', title: 'CI Laptop', category: 'Hardware', description: 'Production E2E laptop product', kind: 'product',
          visibility: 'portal', vendor: 'Hi5 Vendor', sku: 'CI-LAPTOP-001', priceMode: 'fixed', oneOffPrice: 1399, monthlyPrice: 0, currency: 'GBP', active: true,
        },
        {
          id: 'FORM-CI-LAPTOP', title: 'Request a laptop', category: 'Hardware', description: 'Request a standard laptop for work.', kind: 'request-form',
          requestType: 'Service Request', service: 'End User Computing', team: 'Service Desk', approval: 'none', visibility: 'portal', workflow: 'standard-fulfilment', active: true,
          formSchema: [
            { id: 'device', type: 'product', label: 'Laptop', required: true, options: [{ value: 'standard-laptop', label: 'Stale laptop label', itemId: 'PROD-CI-LAPTOP', cost: 1 }] },
            { id: 'businessNeed', type: 'textarea', label: 'Business need', required: true },
          ],
        },
      ],
    },
  })
  assert(catalogue.response.ok, `Catalogue publish failed: ${catalogue.payload.error || catalogue.response.status}`)
  const publicCatalogue = await json(`/api/v1/portal/catalogue/${slug}`, { origin: portalOrigin })
  assert(publicCatalogue.response.ok && publicCatalogue.payload.items?.length === 1, 'Published Portal catalogue was not available')
  const publicLaptop = publicCatalogue.payload.items[0]?.fields?.find((field) => field.id === 'device')?.options?.[0]
  assert(Number(publicLaptop?.cost) === 1399, 'Portal catalogue did not replace stale form cost with the live product price')

  console.log('6. Self-activating requester Portal access')
  const activationRequest = await json('/api/v1/portal/auth/activate/request', {
    method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email: requesterEmail },
  })
  assert(activationRequest.response.ok && activationRequest.payload.activationToken, 'Portal activation did not issue the test activation token')
  const activation = await json('/api/v1/portal/auth/activate/complete', {
    method: 'POST', origin: portalOrigin,
    body: { tenantSlug: slug, token: activationRequest.payload.activationToken, password: requesterPassword },
  })
  assert(activation.response.ok && activation.payload.activated === true, `Portal activation failed: ${activation.payload.error || activation.response.status}`)

  console.log('7. Signing in as the real requester')
  const requesterLogin = await json('/api/v1/portal/auth/login', {
    method: 'POST', origin: portalOrigin, body: { tenantSlug: slug, email: requesterEmail, password: requesterPassword },
  })
  assert(requesterLogin.response.ok && requesterLogin.payload.user?.role === 'requester', `Requester login failed: ${requesterLogin.payload.error || requesterLogin.response.status}`)
  const requesterCookie = cookieFrom(requesterLogin.response)
  assert(requesterCookie, 'Requester login did not issue a Portal session cookie')
  const requesterSession = await json('/api/v1/portal/auth/session', { cookie: requesterCookie, origin: portalOrigin })
  assert(requesterSession.response.ok && requesterSession.payload.user?.tenantRole === 'requester', 'Requester Portal session was not restored')

  console.log('8. Submitting the real Service Request from the Portal')
  const submitted = await json('/api/v1/service-requests', {
    method: 'POST', cookie: requesterCookie, origin: portalOrigin,
    body: {
      catalogueItemId: 'FORM-CI-LAPTOP',
      summary: 'Laptop for CI requester',
      fields: { device: 'standard-laptop', businessNeed: 'Required for the fresh-tenant production acceptance test.' },
      details: { text: 'Please provide the standard CI laptop.', attachments: [] },
      urgency: 'Medium',
    },
  })
  assert(submitted.response.ok && /^REQ-\d+$/.test(submitted.payload.reference || ''), `Portal request submission failed: ${submitted.payload.error || submitted.response.status}`)
  const reference = submitted.payload.reference
  assert(Number(submitted.payload.oneOffCost) === 1399, 'Server did not persist the live £1,399 price snapshot')

  console.log('9. Verifying requester-scoped My Requests')
  const myRequests = await json('/api/v1/portal/requests', { cookie: requesterCookie, origin: portalOrigin })
  assert(myRequests.response.ok && myRequests.payload.items?.some((item) => item.reference === reference), 'Submitted request is missing from My Requests')
  const firstDetail = await json(`/api/v1/portal/requests/${reference}`, { cookie: requesterCookie, origin: portalOrigin })
  assert(firstDetail.response.ok && Number(firstDetail.payload.oneOffCost) === 1399, 'Requester detail did not preserve the cost snapshot')

  console.log('10. Working the request as the tenant technician')
  const start = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie: ownerCookie, body: { targetStatus: 'In Progress', values: {} },
  })
  assert(start.response.ok, `Could not start fulfilment: ${start.payload.error || start.response.status}`)
  const internalNote = 'INTERNAL-E2E-NOTE-MUST-NOT-LEAK'
  const work = await json(`/api/v1/service-requests/${reference}/activities`, {
    method: 'POST', cookie: ownerCookie, body: { kind: 'work', text: internalNote },
  })
  assert(work.response.ok, 'Technician internal work note failed')
  const customerUpdate = 'Your laptop has been prepared and is ready for final checks.'
  const customer = await json(`/api/v1/service-requests/${reference}/activities`, {
    method: 'POST', cookie: ownerCookie, body: { kind: 'customer', text: customerUpdate },
  })
  assert(customer.response.ok, 'Technician customer-visible update failed')

  const requesterReply = 'Thanks — please deliver it to Head Office reception.'
  const reply = await json(`/api/v1/service-requests/${reference}/activities`, {
    method: 'POST', cookie: requesterCookie, origin: portalOrigin, body: { kind: 'customer', text: requesterReply },
  })
  assert(reply.response.ok, 'Requester could not add a customer-visible reply')

  const completed = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie: ownerCookie, body: { targetStatus: 'Completed', values: { completionNotes: 'Laptop delivered and requester confirmed receipt.' } },
  })
  assert(completed.response.ok, `Completion failed: ${completed.payload.error || completed.response.status}`)
  const closed = await json(`/api/v1/service-requests/${reference}/transition`, {
    method: 'POST', cookie: ownerCookie, body: { targetStatus: 'Closed', values: {} },
  })
  assert(closed.response.ok, `Closure failed: ${closed.payload.error || closed.response.status}`)

  console.log('11. Proving requester sees completion but never internal notes')
  const finalDetail = await json(`/api/v1/portal/requests/${reference}`, { cookie: requesterCookie, origin: portalOrigin })
  assert(finalDetail.response.ok && finalDetail.payload.status === 'Closed', 'Requester does not see the final Closed state')
  const visibleActivityText = (finalDetail.payload.activities || []).map((item) => item.text).join('\n')
  assert(visibleActivityText.includes(customerUpdate), 'Customer-visible technician update is missing')
  assert(visibleActivityText.includes(requesterReply), 'Requester reply is missing from Portal history')
  assert(!visibleActivityText.includes(internalNote), 'Internal technician work note leaked into the requester Portal')

  const dbEvidence = await db.query(
    `SELECT sr.reference, sr.one_off_cost, sr.requester_user_id, u.email,
            count(*) FILTER (WHERE a.visibility = 'internal')::int AS internal_activities,
            count(*) FILTER (WHERE a.visibility = 'customer')::int AS customer_activities
     FROM service_requests sr
     JOIN users u ON u.id = sr.requester_user_id
     LEFT JOIN service_request_activities a ON a.request_id = sr.id
     WHERE sr.tenant_id = $1 AND sr.reference = $2
     GROUP BY sr.reference, sr.one_off_cost, sr.requester_user_id, u.email`,
    [tenantId, reference],
  )
  assert(dbEvidence.rows[0]?.email === requesterEmail, 'Request is not linked to the activated requester identity')
  assert(Number(dbEvidence.rows[0]?.one_off_cost) === 1399, 'PostgreSQL cost snapshot changed unexpectedly')
  assert(Number(dbEvidence.rows[0]?.internal_activities) >= 1 && Number(dbEvidence.rows[0]?.customer_activities) >= 3, 'Activity visibility evidence is incomplete')

  console.log(`Fresh-tenant Portal E2E passed: ${slug} / ${reference}`)
} finally {
  await db.end()
}
