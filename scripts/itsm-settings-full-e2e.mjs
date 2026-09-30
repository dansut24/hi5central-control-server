import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'

async function api(token, path, options = {}) {
  const response = await fetch(BASE + path, {
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
  const expected = options.expect ?? 200
  if (response.status !== expected) {
    throw new Error(`${options.method || 'GET'} ${path} -> ${response.status}: ${payload.error || text}`)
  }
  return payload
}

function pass(label) { console.log('PASS ', label) }

async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const owner = (await pool.query(
    `SELECT u.id FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     WHERE lower(u.email)=lower($2) AND m.status='active' LIMIT 1`,
    [tenant.id, OWNER_EMAIL],
  )).rows[0]
  assert(owner?.id)
  const token = await createSession(pool, { tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace' })

  const before = await api(token, '/api/v1/settings')
  assert(before.settings?.company && before.settings?.theme && before.settings?.itsm)
  pass('tenant Settings API returns General, Appearance and ITSM configuration')

  for (const area of ['company','users','groups','permissions','security','rmm','integrations','billing']) {
    const original = structuredClone(before.settings?.[area] || {})
    const roundTrip = await api(token, `/api/v1/settings/${area}`, { method: 'POST', body: { data: original } })
    const persisted = roundTrip.settings?.[area] || {}
    for (const [key, value] of Object.entries(original)) assert.deepEqual(persisted[key], value, `${area}.${key} did not round-trip`)
  }
  pass('General, security, RMM and Platform Settings round-trip through production API')

  const originalTheme = structuredClone(before.settings.theme || {})
  const qaTheme = { ...originalTheme, brandName: 'Hi5Central Test2', portalTitle: 'Test2 IT Help Centre' }
  const savedTheme = await api(token, '/api/v1/settings/theme', { method: 'POST', body: { data: qaTheme } })
  assert.equal(savedTheme.settings?.theme?.brandName, qaTheme.brandName)
  assert.equal(savedTheme.settings?.theme?.portalTitle, qaTheme.portalTitle)
  const confirmedTheme = await api(token, '/api/v1/settings')
  assert.equal(confirmedTheme.settings?.theme?.brandName, qaTheme.brandName)
  assert.equal(confirmedTheme.settings?.theme?.portalTitle, qaTheme.portalTitle)
  pass('Appearance & branding persists workspace brand and Portal title')
  await api(token, '/api/v1/settings/theme', { method: 'POST', body: { data: originalTheme } })
  pass('Appearance & branding test values restored')

  const desiredItsm = {
    ...(before.settings.itsm || {}),
    dashboard: { defaultRange: 'today', showServiceHealth: true, showRecentActivity: true, showApprovals: true, showProjects: true },
    queues: { defaultView: 'table', pageSize: '25', rememberFilters: true, allowSavedViews: true, showSla: true, openInTabs: true },
    incidents: { defaultStatus: 'New', defaultPriority: 'Medium', requireResolutionCode: true, reopenDays: '7', autoAssignDefaultTeam: true },
    serviceRequests: { defaultStatus: 'New', requesterCanCancel: true, pauseSlaForApproval: true, autoCloseDays: '3', requireCompletionNote: true },
    problems: { defaultStatus: 'New', requireRootCause: true, requireKnownErrorReview: true, allowIncidentLinking: true },
    changes: { defaultType: 'Normal', requireImplementationPlan: true, requireTestPlan: true, requireBackoutPlan: true, enforceApproval: true },
    tasks: { defaultStatus: 'Open', inheritParentTeam: true, requireAssigneeToStart: true, requireCompletionNote: false, showOnCalendar: true },
    catalogue: { enabled: true, requireOwner: true, showPrices: true, allowOneOffRequests: true, requireApprovalForCost: true },
    projects: { enabled: true, requireOwner: true, syncCalendar: true, showTaskDueDates: true, showMilestones: true, defaultHealth: 'On track' },
    calendar: { weekStart: 'monday', workingDayStart: '09:00', workingDayEnd: '17:30', showChanges: true, showProjects: true, showTasks: true, showRota: true },
    liveChatConfig: { enabled: true, autoClaimOnReply: true, allowTransfer: true, createIncidentFromChat: true, inactivityMinutes: '30' },
    cmdb: { enabled: true, linkRecords: true, showRmmDevices: true, requireOwnerForManualCi: false, allowManualCi: true },
    knowledge: { internalEnabled: true, portalEnabled: true, feedbackEnabled: true, requireReview: true, reviewDays: '180' },
    reports: { enabled: true, allowExport: true, allowSavedViews: true, defaultRangeDays: '30', includeClosed: true },
    attachments: { maxMb: '5', requesterUploads: true, internalAttachments: true },
  }
  const savedItsm = await api(token, '/api/v1/settings/itsm', { method: 'POST', body: { data: desiredItsm } })
  for (const key of ['dashboard','queues','incidents','serviceRequests','problems','changes','tasks','catalogue','projects','calendar','liveChatConfig','cmdb','knowledge','reports','attachments']) {
    assert.deepEqual(savedItsm.settings?.itsm?.[key], desiredItsm[key])
  }
  pass('all major ITSM module settings persist to tenant configuration')

  const notificationBefore = await api(token, '/api/v1/notification-settings')
  const originalNotifications = structuredClone(notificationBefore.settings)
  const testNotifications = {
    ...originalNotifications,
    requesterEvents: {
      ...(originalNotifications.requesterEvents || {}),
      systemUpdates: !originalNotifications.requesterEvents?.systemUpdates,
    },
  }
  const notificationSaved = await api(token, '/api/v1/notification-settings', { method: 'PATCH', body: { settings: testNotifications } })
  assert.equal(notificationSaved.settings?.requesterEvents?.systemUpdates, testNotifications.requesterEvents.systemUpdates)
  pass('Notification Settings uses production delivery policy')
  await api(token, '/api/v1/notification-settings', { method: 'PATCH', body: { settings: originalNotifications } })
  pass('Notification policy restored after test')

  const allRecords = await api(token, '/api/v1/itsm-queue?limit=100')
  const types = new Set(allRecords.items.map((item) => item.type))
  for (const type of ['Incident','Service Request','Problem','Change']) assert(types.has(type), `Missing ${type} from All Records`)
  for (const type of ['Incident','Service Request','Problem','Change']) assert(allRecords.filters.types.includes(type))
  pass('All Records production queue returns all four process types and type filters')

  const view = await api(token, '/api/v1/itsm/saved-views', { method: 'POST', expect: 201, body: {
    recordType: 'All', name: 'E2E All Records', query: '', filters: { recordType: 'All', status: 'All' },
    viewStyle: 'table', columns: { pageSize: 25 },
  }})
  assert(view.id)
  const views = await api(token, '/api/v1/itsm/saved-views?type=All')
  assert(views.items.some((item) => item.id === view.id))
  await api(token, `/api/v1/itsm/saved-views/${view.id}`, { method: 'DELETE' })
  pass('All Records saved views persist and delete')

  const latestIncident = (await pool.query(
    `SELECT reference FROM itsm_records WHERE tenant_id=$1 AND record_type='Incident' ORDER BY created_at DESC LIMIT 1`,
    [tenant.id],
  )).rows[0]
  assert(latestIncident?.reference)
  const originalItsm = structuredClone(savedItsm.settings.itsm)
  const oneMbItsm = { ...originalItsm, attachments: { ...(originalItsm.attachments || {}), maxMb: '1', internalAttachments: true } }
  await api(token, '/api/v1/settings/itsm', { method: 'POST', body: { data: oneMbItsm } })
  const oversized = Buffer.alloc(1024 * 1024 + 1, 65).toString('base64')
  await api(token, `/api/v1/itsm-lifecycle/${latestIncident.reference}/attachments`, { method: 'POST', expect: 413, body: {
    fileName: 'settings-limit-test.bin', mimeType: 'application/octet-stream', contentBase64: oversized,
  }})
  pass('Attachment maximum from Settings is enforced by production endpoint')
  await api(token, '/api/v1/settings/itsm', { method: 'POST', body: { data: originalItsm } })

  const finalSettings = await api(token, '/api/v1/settings')
  assert.equal(finalSettings.settings?.itsm?.attachments?.maxMb, '5')
  assert.equal(finalSettings.settings?.itsm?.queues?.allowSavedViews, true)
  pass('ITSM settings remain persisted after policy tests')

  console.log('SUMMARY', JSON.stringify({ checks: 11, allRecords: allRecords.total, recordTypes: [...types].sort() }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
