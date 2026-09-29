import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'

function pass(name, detail = '') { console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`) }

async function api(token, path, { method = 'GET', body, raw = false } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      Cookie: `hi5central_session=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (raw) return response
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}

async function users() {
  const tenant = await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])
  assert.equal(tenant.rowCount, 1)
  const tenantId = tenant.rows[0].id
  const result = await pool.query(
    `SELECT u.id,u.email,p.external_key,p.name
     FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenantId, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  return {
    tenantId,
    owner: result.rows.find((row) => row.email.toLowerCase() === OWNER_EMAIL),
    requester: result.rows.find((row) => row.email.toLowerCase() === REQUESTER_EMAIL),
  }
}
async function addTask(token, reference, title) {
  let detail = await api(token, `/api/v1/itsm-lifecycle/${reference}`)
  const rejected = await api(token, `/api/v1/itsm-actions/${reference}/tasks`, {
    method: 'POST', raw: true,
    body: {
      version: detail.version, title: `${title} invalid assignment`, team: 'Servers', assignee: REQUESTER_EMAIL,
      instructions: 'This task assignment must be rejected.', dueAt: new Date(Date.now() + 3600000).toISOString(),
    },
  })
  assert.equal(rejected.status, 422)
  const created = await api(token, `/api/v1/itsm-actions/${reference}/tasks`, {
    method: 'POST',
    body: {
      version: detail.version, title, team: 'Servers', assignee: OWNER_EMAIL,
      instructions: 'Overnight E2E lifecycle validation.', dueAt: new Date(Date.now() + 3600000).toISOString(),
    },
  })
  detail = await api(token, `/api/v1/itsm-lifecycle/${reference}`)
  let updated = await api(token, `/api/v1/itsm-actions/${reference}/tasks/${created.task.id}`, {
    method: 'PATCH', body: { version: detail.version, status: 'In Progress' },
  })
  updated = await api(token, `/api/v1/itsm-actions/${reference}/tasks/${created.task.id}`, {
    method: 'PATCH', body: { version: updated.version, status: 'Completed' },
  })
  assert.equal(updated.task.status, 'Completed')
  return updated.task.id
}

async function exerciseSharedRecord(token, record, label) {
  let detail = await api(token, `/api/v1/itsm-lifecycle/${record.id}`)
  const rejected = await api(token, `/api/v1/itsm-actions/${record.id}/reassign`, {
    method: 'POST', raw: true,
    body: { version: detail.version, team: 'Servers', assignee: REQUESTER_EMAIL, note: 'This invalid assignment must be rejected.' },
  })
  assert.equal(rejected.status, 422)
  const reassigned = await api(token, `/api/v1/itsm-actions/${record.id}/reassign`, {
    method: 'POST',
    body: { version: detail.version, team: 'Servers', assignee: OWNER_EMAIL, note: `${label} assigned by overnight E2E.` },
  })
  assert(reassigned.version > detail.version)
  detail = await api(token, `/api/v1/itsm-lifecycle/${record.id}`)
  assert.equal(detail.assignee, 'Dan Samsung')
  assert.equal(detail.team, 'Servers')
  pass(`${label} assignment guard and valid assignment`)

  detail = await api(token, `/api/v1/itsm-lifecycle/${record.id}/activity`, {
    method: 'POST', body: { visibility: 'internal', text: `${label} internal E2E note.` },
  })
  detail = await api(token, `/api/v1/itsm-lifecycle/${record.id}/activity`, {
    method: 'POST', body: { visibility: 'customer', text: `${label} customer-facing E2E update.` },
  })
  assert.equal(detail.activities[0].visibility, 'customer')

  const bytes = Buffer.from(`Hi5Central ${label} attachment`)
  detail = await api(token, `/api/v1/itsm-lifecycle/${record.id}/attachments`, {
    method: 'POST',
    body: { fileName: `${label.toLowerCase()}-e2e.txt`, mimeType: 'text/plain', contentBase64: bytes.toString('base64') },
  })
  const attachment = detail.attachments.find((item) => item.fileName === `${label.toLowerCase()}-e2e.txt`)
  assert(attachment?.id)
  const download = await api(token, `/api/v1/itsm-lifecycle/${record.id}/attachments/${attachment.id}`, { raw: true })
  assert.equal(download.status, 200)
  assert.equal(Buffer.from(await download.arrayBuffer()).toString(), bytes.toString())
  pass(`${label} notes and attachment`)

  const taskId = await addTask(token, record.id, `${label} overnight validation task`)
  pass(`${label} task assigned, started and completed`, taskId)
  return taskId
}
async function main() {
  const { tenantId, owner, requester } = await users()
  assert(owner?.id && owner?.external_key)
  assert(requester?.id && requester?.external_key)
  const token = await createSession(pool, {
    tenantId, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace',
  })
  const stamp = new Date().toISOString()

  const problem = await api(token, '/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Problem', title: `Overnight full Problem E2E ${stamp}`,
      description: 'Full Problem workflow validation.', requesterId: requester.external_key,
      priority: 'High', source: 'overnight-e2e',
    },
  })
  assert.match(problem.id, /^PRB-/)
  await exerciseSharedRecord(token, problem, 'Problem')
  let workflow = await api(token, `/api/v1/workflows/${problem.id}`)
  workflow = await api(token, `/api/v1/workflows/${problem.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Investigation' },
  })
  assert.equal(workflow.status, 'Investigation')
  workflow = await api(token, `/api/v1/workflows/${problem.id}/data`, {
    method: 'PATCH',
    body: { data: {
      impactScope: 'Affected requester validation scope.',
      hypothesis: 'Configuration drift reproduced in E2E.',
      workaround: 'Temporary workaround confirmed.',
      rootCause: 'Overnight E2E root cause confirmed.',
      permanentFix: 'Permanent remediation validated by E2E.',
      knownErrorTitle: 'E2E known error',
    } },
  })
  workflow = await api(token, `/api/v1/workflows/${problem.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Known Error' },
  })
  assert.equal(workflow.status, 'Known Error')
  workflow = await api(token, `/api/v1/workflows/${problem.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Resolved' },
  })
  assert.equal(workflow.status, 'Resolved')
  workflow = await api(token, `/api/v1/workflows/${problem.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Closed' },
  })
  assert.equal(workflow.status, 'Closed')
  pass('Problem workflow completed through Known Error, Resolved and Closed', problem.id)
  const change = await api(token, '/api/v1/itsm-records', {
    method: 'POST',
    body: {
      type: 'Change', title: `Overnight full Change E2E ${stamp}`,
      description: 'Full Change workflow and approval validation.', requesterId: requester.external_key,
      priority: 'Medium', source: 'overnight-e2e',
    },
  })
  assert.match(change.id, /^CHG-/)
  await exerciseSharedRecord(token, change, 'Change')
  const plannedStart = new Date(Date.now() + 2 * 3600000).toISOString()
  const plannedEnd = new Date(Date.now() + 3 * 3600000).toISOString()
  let changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/data`, {
    method: 'PATCH',
    body: { data: {
      changeType: 'Normal', risk: 'Medium',
      riskSummary: 'Controlled E2E validation risk.',
      businessReason: 'Validate end-to-end Change management.',
      implementationPlan: 'Apply the controlled E2E change.',
      testPlan: 'Verify workflow, notifications and task completion.',
      backoutPlan: 'Restore the pre-test state.',
      plannedStart, plannedEnd, downtime: 'None',
    } },
  })
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Assessment' },
  })
  assert.equal(changeWorkflow.status, 'Assessment')
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Awaiting Approval', approverUserId: owner.id },
  })
  assert.equal(changeWorkflow.status, 'Awaiting Approval')
  const approval = changeWorkflow.approvals.find((item) => item.status === 'Pending')
  assert(approval?.id)
  assert.equal(approval.approverEmail, OWNER_EMAIL)
  pass('Change approval raised to approved test inbox', approval.id)

  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/approvals/${approval.id}/decision`, {
    method: 'POST', body: { decision: 'Approved', note: 'Approved by overnight E2E.' },
  })
  assert.equal(changeWorkflow.status, 'Scheduled')
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Implementing' },
  })
  assert.equal(changeWorkflow.status, 'Implementing')
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/data`, {
    method: 'PATCH', body: { data: { ...changeWorkflow.data, implementationNotes: 'Implementation completed successfully in overnight E2E.' } },
  })
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Review' },
  })
  assert.equal(changeWorkflow.status, 'Review')
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/data`, {
    method: 'PATCH', body: { data: { ...changeWorkflow.data, reviewOutcome: 'Successful implementation; no adverse impact.' } },
  })
  changeWorkflow = await api(token, `/api/v1/workflows/${change.id}/transition`, {
    method: 'POST', body: { targetStatus: 'Completed' },
  })
  assert.equal(changeWorkflow.status, 'Completed')
  pass('Change workflow approved, implemented, reviewed and completed', change.id)

  const bell = await api(token, '/api/v1/notifications?limit=250')
  for (const reference of [problem.id, change.id]) {
    const events = bell.items.filter((item) => item.target?.reference === reference).map((item) => item.eventType)
    assert(events.some((event) => event.includes('task_')))
  }
  assert(bell.items.some((item) => item.target?.reference === change.id && item.eventType === 'change.approval_required'))
  pass('technician bell contains task and Change approval events')

  const deadline = Date.now() + 40000
  let deliveries = []
  while (Date.now() < deadline) {
    const result = await pool.query(
      `SELECT n.target_reference,n.event_type,u.email,d.channel,d.status,d.sent_at,d.last_error
       FROM platform_notifications n
       JOIN users u ON u.id=n.user_id
       JOIN notification_deliveries d ON d.notification_id=n.id
       WHERE n.tenant_id=$1 AND n.target_reference=ANY($2::text[])
       ORDER BY n.created_at,d.channel`,
      [tenantId, [problem.id, change.id]],
    )
    deliveries = result.rows
    const emails = deliveries.filter((row) => row.channel === 'email')
    if (emails.length && emails.every((row) => ['sent','suppressed'].includes(row.status))) break
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  const emails = deliveries.filter((row) => row.channel === 'email')
  assert(emails.length > 0)
  assert(emails.every((row) => [OWNER_EMAIL, REQUESTER_EMAIL].includes(row.email)))
  assert(emails.some((row) => row.target_reference === change.id && row.event_type === 'change.approval_required' && row.email === OWNER_EMAIL && row.status === 'sent'))
  assert(emails.some((row) => row.target_reference === problem.id && row.email === REQUESTER_EMAIL && row.status === 'sent'))
  assert(emails.some((row) => row.target_reference === change.id && row.email === REQUESTER_EMAIL && row.status === 'sent'))
  pass('Problem/Change SMTP delivery confirmed only to approved inboxes', `${emails.length} email deliveries`)

  console.log('\nSUMMARY', JSON.stringify({ problem: problem.id, change: change.id, emailDeliveries: emails.length }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
