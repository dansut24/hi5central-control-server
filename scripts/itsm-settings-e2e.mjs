import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'

const incidentTargets = {
  Critical: { responseMinutes: '15', resolutionMinutes: '240' },
  High: { responseMinutes: '30', resolutionMinutes: '480' },
  Medium: { responseMinutes: '240', resolutionMinutes: '1440' },
  Low: { responseMinutes: '480', resolutionMinutes: '2880' },
}
const requestTargets = {
  Critical: { responseMinutes: '30', resolutionMinutes: '480' },
  High: { responseMinutes: '60', resolutionMinutes: '960' },
  Medium: { responseMinutes: '240', resolutionMinutes: '2880' },
  Low: { responseMinutes: '480', resolutionMinutes: '5760' },
}
const projectTargets = {
  Critical: { targetDays: '14' },
  High: { targetDays: '30' },
  Medium: { targetDays: '60' },
  Low: { targetDays: '90' },
}

async function api(token, path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method: options.method || 'GET',
    headers: {
      Origin: ORIGIN,
      Cookie: `hi5central_session=${token}`,
      ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${options.method || 'GET'} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}

async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const owner = (await pool.query(
    `SELECT u.id FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     WHERE lower(u.email)=lower($2) AND m.status='active' LIMIT 1`,
    [tenant.id, OWNER_EMAIL],
  )).rows[0]
  assert(owner?.id)

  const token = await createSession(pool, {
    tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 1800, surface: 'workspace',
  })
  const before = await api(token, '/api/v1/settings')
  const itsm = { ...(before.settings?.itsm || {}) }
  delete itsm.p1ResponseMinutes
  delete itsm.p1ResolutionMinutes
  itsm.slaTargets = incidentTargets
  itsm.serviceRequestSlaTargets = requestTargets
  itsm.projectSlaTargets = projectTargets

  const saved = await api(token, '/api/v1/settings/itsm', { method: 'POST', body: { data: itsm } })
  assert.deepEqual(saved.settings?.itsm?.slaTargets, incidentTargets)
  assert.deepEqual(saved.settings?.itsm?.serviceRequestSlaTargets, requestTargets)
  assert.deepEqual(saved.settings?.itsm?.projectSlaTargets, projectTargets)
  assert.equal(saved.settings?.itsm?.p1ResponseMinutes, undefined)
  assert.equal(saved.settings?.itsm?.p1ResolutionMinutes, undefined)

  const confirmed = await api(token, '/api/v1/settings')
  assert.deepEqual(confirmed.settings?.itsm?.slaTargets, incidentTargets)
  assert.deepEqual(confirmed.settings?.itsm?.serviceRequestSlaTargets, requestTargets)
  assert.deepEqual(confirmed.settings?.itsm?.projectSlaTargets, projectTargets)
  console.log('PASS  Settings API persisted Incident SLA targets')
  console.log('PASS  Settings API persisted Service Request SLA targets')
  console.log('PASS  Settings API persisted Project SLA targets')
  console.log('PASS  obsolete flat P1 SLA fields removed')
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
