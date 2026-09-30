import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'

function pass(name, detail = '') { console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`) }
async function api(token, path, { method = 'GET', body, expect = 200 } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { Origin: ORIGIN, Cookie: `hi5central_session=${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? (() => { try { return JSON.parse(text) } catch { return text } })() : {}
  assert.equal(response.status, expect, `${method} ${path} expected ${expect}, got ${response.status}: ${text}`)
  return payload
}
async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const people = await pool.query(
    `SELECT u.id,p.external_key,p.email FROM users u
     JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenant.id, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = people.rows.find((r) => r.email?.toLowerCase() === OWNER_EMAIL)
  const requester = people.rows.find((r) => r.email?.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.id && requester?.external_key)
  const token = await createSession(pool, { tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace' })

  const incident = await api(token, '/api/v1/itsm-records', {
    method: 'POST', expect: 201,
    body: { type: 'Incident', title: `SLA edge E2E ${new Date().toISOString()}`, requesterId: requester.external_key, priority: 'High' },
  })
  assert.match(incident.id, /^INC-/)
  await pool.query(
    `UPDATE itsm_records SET response_due_at=now()-interval '5 minutes',
       resolution_due_at=now()-interval '1 minute', first_response_at=NULL, resolved_at=NULL
     WHERE tenant_id=$1 AND reference=$2`,
    [tenant.id, incident.id],
  )
  let detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`)
  assert.equal(detail.sla.response.state, 'breached')
  assert.equal(detail.sla.resolution.state, 'breached')
  pass('forced response and resolution breaches are reported', incident.id)

  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH',
    body: { version: detail.version, status: 'Pending Customer' },
  })
  assert.equal(detail.status, 'Pending Customer')
  assert.equal(detail.sla.paused, true)
  pass('Pending Customer pauses Incident SLA')

  await pool.query(
    `UPDATE itsm_records SET sla_paused_at=now()-interval '120 seconds'
     WHERE tenant_id=$1 AND reference=$2`,
    [tenant.id, incident.id],
  )
  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`)
  const beforeDue = new Date(detail.sla.resolution.dueAt).getTime()
  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH',
    body: { version: detail.version, status: 'In Progress' },
  })
  const afterDue = new Date(detail.sla.resolution.dueAt).getTime()
  assert.equal(detail.sla.paused, false)
  assert(detail.sla.pausedSeconds >= 119)
  assert(afterDue - beforeDue >= 119000)
  pass('resuming extends SLA deadlines by paused duration')
  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`)
  await api(token, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH', expect: 400,
    body: { version: detail.version, status: 'Resolved' },
  })
  pass('Incident cannot resolve without resolution data')

  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`)
  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH',
    body: { version: detail.version, status: 'Resolved', resolutionCode: 'Fixed', resolutionSummary: 'SLA edge E2E resolved.' },
  })
  assert.equal(detail.status, 'Resolved')
  assert(detail.sla.resolution.completedAt)
  pass('Incident resolution captures SLA completion')

  detail = await api(token, `/api/v1/itsm-lifecycle/${incident.id}`, {
    method: 'PATCH',
    body: { version: detail.version, status: 'In Progress' },
  })
  assert.equal(detail.status, 'In Progress')
  assert.equal(detail.sla.resolution.completedAt, null)
  pass('reopening clears resolution completion and resumes tracking')

  console.log('SUMMARY', JSON.stringify({ incident: incident.id, checks: 6 }))
}

main().catch((error) => { console.error('FAIL', error.stack || error); process.exitCode = 1 })
  .finally(async () => { await pool.end() })