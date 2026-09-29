import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:3001'
const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const SLUG = process.env.E2E_TENANT_SLUG || 'test2'
const OWNER_EMAIL = 'danielsuttonsamsung@gmail.com'
const REQUESTER_EMAIL = 'danieljamessutton18@outlook.com'
const passes = []

function pass(name, detail = '') {
  passes.push(name)
  console.log(`PASS  ${name}${detail ? ` · ${detail}` : ''}`)
}

async function api(token, path, { method = 'GET', body, expect, portal = false } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      ...(portal ? { Referer: `${ORIGIN}/portal` } : {}),
      Cookie: `${portal ? 'hi5central_portal_session' : 'hi5central_session'}=${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (expect !== undefined) {
    assert.equal(response.status, expect, `${method} ${path} expected ${expect} got ${response.status}`)
    return payload
  }
  if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}: ${payload.error || text}`)
  return payload
}

function isoDate(date) {
  return date.toISOString().slice(0, 10)
}

async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  assert(tenant?.id)
  const users = await pool.query(
    `SELECT u.id,u.email,p.external_key,p.name
     FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenant.id, [OWNER_EMAIL, REQUESTER_EMAIL]],
  )
  const owner = users.rows.find((row) => row.email.toLowerCase() === OWNER_EMAIL)
  const requester = users.rows.find((row) => row.email.toLowerCase() === REQUESTER_EMAIL)
  assert(owner?.id && owner?.external_key && requester?.id)

  const ownerToken = await createSession(pool, {
    tenantId: tenant.id, userId: owner.id, mfaVerified: true, ttlSeconds: 3600, surface: 'workspace',
  })
  const requesterToken = await createSession(pool, {
    tenantId: tenant.id, userId: requester.id, mfaVerified: true, ttlSeconds: 3600, surface: 'portal',
  })

  await api(requesterToken, '/api/v1/projects', { expect: 403, portal: true })
  pass('requester denied Projects workspace')

  const startDate = isoDate(new Date())
  let project = await api(ownerToken, '/api/v1/projects', {
    method: 'POST',
    body: {
      name: `Overnight Project E2E ${new Date().toISOString()}`,
      description: 'Full production project-management validation.',
      ownerId: owner.external_key,
      team: 'Servers',
      priority: 'Medium',
      startDate,
    },
  })
  assert.match(project.id, /^PRJ-/)
  assert.equal(project.ownerEmail, OWNER_EMAIL)
  assert.equal(project.team, 'Servers')
  assert(project.targetDate)
  assert(project.sla?.dueAt)
  assert.equal(project.milestones.length, 1)
  pass('project created with owner, team, default milestone and SLA', project.id)

  const list = await api(ownerToken, '/api/v1/projects')
  assert(list.items.some((item) => item.id === project.id))
  pass('project list persisted')

  project = await api(ownerToken, `/api/v1/projects/${project.id}`, {
    method: 'PATCH', body: { ownerId: '' },
  })
  assert.equal(project.ownerId, '')
  project = await api(ownerToken, `/api/v1/projects/${project.id}`, {
    method: 'PATCH', body: { ownerId: owner.external_key },
  })
  assert.equal(project.ownerEmail, OWNER_EMAIL)
  pass('project owner reassigned')

  project = await api(ownerToken, `/api/v1/projects/${project.id}`, {
    method: 'PATCH', body: { status: 'In Progress', health: 'At Risk' },
  })
  assert.equal(project.status, 'In Progress')
  assert.equal(project.health, 'At Risk')
  pass('project status and health changed')

  project = await api(ownerToken, `/api/v1/projects/${project.id}/activity`, {
    method: 'POST', body: { text: 'Project E2E journal update: delivery plan validated.' },
  })
  assert(project.activity.some((item) => item.action.includes('delivery plan validated')))
  pass('project journal update persisted')

  const milestone = project.milestones[0]
  project = await api(ownerToken, `/api/v1/projects/${project.id}/milestones/${milestone.id}`, {
    method: 'PATCH', body: { status: 'In Progress' },
  })
  project = await api(ownerToken, `/api/v1/projects/${project.id}/milestones/${milestone.id}`, {
    method: 'PATCH', body: { status: 'Complete' },
  })
  assert.equal(project.milestones[0].status, 'Complete')
  assert(project.milestones[0].completedAt)
  pass('milestone progressed and completed')

  const taskDue = new Date()
  taskDue.setUTCDate(taskDue.getUTCDate() + 7)
  project = await api(ownerToken, `/api/v1/projects/${project.id}/tasks`, {
    method: 'POST',
    body: {
      title: 'Deploy project deliverable',
      status: 'To Do',
      priority: 'High',
      startDate,
      dueDate: isoDate(taskDue),
      plannedHours: 8,
      milestoneId: milestone.id,
      linkedRecord: 'INC-00011',
    },
  })
  const task = project.tasks.find((item) => item.title === 'Deploy project deliverable')
  assert(task?.id)
  assert.equal(task.assigneeId, '')
  pass('project task created unassigned', task.id)

  project = await api(ownerToken, `/api/v1/projects/${project.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { assigneeId: owner.external_key },
  })
  let updatedTask = project.tasks.find((item) => item.id === task.id)
  assert.equal(updatedTask.assigneeEmail, OWNER_EMAIL)
  pass('project task assigned/reassigned')

  project = await api(ownerToken, `/api/v1/projects/${project.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { status: 'In Progress' },
  })
  project = await api(ownerToken, `/api/v1/projects/${project.id}/tasks/${task.id}`, {
    method: 'PATCH', body: { status: 'Done' },
  })
  updatedTask = project.tasks.find((item) => item.id === task.id)
  assert.equal(updatedTask.status, 'Done')
  assert(updatedTask.completedAt)
  assert.equal(updatedTask.sla.state, 'met')
  pass('project task started, completed and SLA met')

  project = await api(ownerToken, `/api/v1/projects/${project.id}/risks`, {
    method: 'POST',
    body: {
      kind: 'Risk', title: 'E2E delivery risk', severity: 'High',
      response: 'Mitigate during the controlled validation window.', ownerId: owner.external_key,
    },
  })
  const risk = project.risks.find((item) => item.title === 'E2E delivery risk')
  assert(risk?.id)
  project = await api(ownerToken, `/api/v1/projects/${project.id}/risks/${risk.id}`, {
    method: 'PATCH', body: { status: 'Closed' },
  })
  assert.equal(project.risks.find((item) => item.id === risk.id).status, 'Closed')
  pass('project risk created and closed')

  const calendar = await api(ownerToken, '/api/v1/projects/calendar')
  assert(calendar.items.some((item) => item.projectId === project.id && item.type === 'project-target'))
  assert(calendar.items.some((item) => item.id === milestone.id && item.type === 'project-milestone'))
  assert(calendar.items.some((item) => item.id === task.id && item.type === 'project-task'))
  pass('project, milestone and task dates projected to calendar')

  project = await api(ownerToken, `/api/v1/projects/${project.id}`, {
    method: 'PATCH', body: { health: 'Complete', status: 'Complete' },
  })
  assert.equal(project.status, 'Complete')
  assert(project.completedAt)
  assert.equal(project.sla.state, 'met')
  pass('project completed with SLA result')

  const bell = await api(ownerToken, '/api/v1/notifications?limit=250')
  const projectEvents = bell.items.filter((item) => item.target?.reference === project.id).map((item) => item.eventType)
  assert(projectEvents.includes('project.task_assigned'))
  assert(projectEvents.includes('project.status_changed'))
  assert(projectEvents.includes('project.milestone_updated'))
  pass('technician bell contains project lifecycle notifications')

  const deadline = Date.now() + 40000
  let emailRows = []
  while (Date.now() < deadline) {
    const rows = await pool.query(
      `SELECT n.event_type,u.email,d.status,d.sent_at,d.last_error
       FROM platform_notifications n
       JOIN users u ON u.id=n.user_id
       JOIN notification_deliveries d ON d.notification_id=n.id AND d.channel='email'
       WHERE n.tenant_id=$1 AND n.target_reference=$2
       ORDER BY n.created_at`,
      [tenant.id, project.id],
    )
    emailRows = rows.rows
    if (emailRows.length && emailRows.every((row) => ['sent','suppressed'].includes(row.status))) break
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  assert(emailRows.length > 0)
  assert(emailRows.every((row) => row.email === OWNER_EMAIL))
  assert(emailRows.some((row) => row.event_type === 'project.task_assigned' && row.status === 'sent'))
  assert(emailRows.some((row) => row.event_type === 'project.status_changed' && row.status === 'sent'))
  pass('project emails delivered only to approved technician inbox', `${emailRows.length} deliveries`)

  console.log('\nSUMMARY', JSON.stringify({ project: project.id, task: task.id, milestone: milestone.id, risk: risk.id, checks: passes.length, emailDeliveries: emailRows.length }))
}

main().catch((error) => {
  console.error('FAIL', error.stack || error)
  process.exitCode = 1
}).finally(async () => {
  await pool.end()
})
