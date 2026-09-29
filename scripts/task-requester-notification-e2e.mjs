import pg from 'pg'
import { randomBytes } from 'node:crypto'

const { Client } = pg
const db = new Client({ connectionString: process.env.DATABASE_URL })
const suffix = `${Date.now().toString(36)}${randomBytes(3).toString('hex')}`

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

await db.connect()
let tenantId = null
let requesterUserId = null
let assigneeUserId = null

try {
  const tenant = await db.query(
    `INSERT INTO tenants (slug, company_name, status)
     VALUES ($1, 'Task Notification Guard', 'active') RETURNING id`,
    [`task-notify-${suffix}`.slice(0, 42)],
  )
  tenantId = tenant.rows[0].id

  const requester = await db.query(
    `INSERT INTO users (email, name, password_hash, email_verified_at)
     VALUES ($1, 'CI Requester', 'test-only', now()) RETURNING id`,
    [`requester-${suffix}@hi5central.test`],
  )
  requesterUserId = requester.rows[0].id

  const assignee = await db.query(
    `INSERT INTO users (email, name, password_hash, email_verified_at)
     VALUES ($1, 'CI Technician', 'test-only', now()) RETURNING id`,
    [`technician-${suffix}@hi5central.test`],
  )
  assigneeUserId = assignee.rows[0].id

  await db.query(
    `INSERT INTO tenant_memberships (tenant_id, user_id, role, status)
     VALUES ($1,$2,'requester','active'), ($1,$3,'analyst','active')`,
    [tenantId, requesterUserId, assigneeUserId],
  )

  const department = await db.query(
    `INSERT INTO organisation_departments (tenant_id, external_key, name)
     VALUES ($1,'DEPT-NOTIFY','Notification Test') RETURNING id`,
    [tenantId],
  )
  const team = await db.query(
    `INSERT INTO organisation_teams (tenant_id, external_key, department_id, name)
     VALUES ($1,'TEAM-NOTIFY',$2,'Service Desk') RETURNING id`,
    [tenantId, department.rows[0].id],
  )
  const requesterPerson = await db.query(
    `INSERT INTO organisation_people (
       tenant_id, external_key, user_id, primary_team_id, department_id,
       name, email, job_title, access_profile, active
     ) VALUES ($1,'USR-NOTIFY-REQUESTER',$2,$3,$4,'CI Requester',$5,'Requester','requester',true)
     RETURNING id`,
    [tenantId, requesterUserId, team.rows[0].id, department.rows[0].id, `requester-${suffix}@hi5central.test`],
  )
  const technicianPerson = await db.query(
    `INSERT INTO organisation_people (
       tenant_id, external_key, user_id, primary_team_id, department_id,
       name, email, job_title, access_profile, active
     ) VALUES ($1,'USR-NOTIFY-TECH',$2,$3,$4,'CI Technician',$5,'Technician','analyst',true)
     RETURNING id`,
    [tenantId, assigneeUserId, team.rows[0].id, department.rows[0].id, `technician-${suffix}@hi5central.test`],
  )

  const request = await db.query(
    `INSERT INTO service_requests (
       tenant_id, reference, requester_user_id, requester_person_id, requester_snapshot,
       title, status, priority, service, fulfilment_team_id, fulfilment_team_snapshot,
       assigned_person_id, created_by_user_id
     ) VALUES (
       $1,'REQ-NOTIFY-0001',$2,$3,$4::jsonb,
       'Notification guard request','In Progress','Medium','Hardware',$5,$6::jsonb,$7,$2
     ) RETURNING id`,
    [
      tenantId,
      requesterUserId,
      requesterPerson.rows[0].id,
      JSON.stringify({ name: 'CI Requester', email: `requester-${suffix}@hi5central.test` }),
      team.rows[0].id,
      JSON.stringify({ id: 'TEAM-NOTIFY', name: 'Service Desk' }),
      technicianPerson.rows[0].id,
    ],
  )

  await db.query(
    `INSERT INTO service_request_tasks (
       tenant_id, request_id, external_key, title, status,
       team_id, team_snapshot, assignee_person_id, assignee_snapshot,
       dependencies, instructions
     ) VALUES ($1,$2,'REQ-NOTIFY-0001-TASK-1','Prepare device','Ready',$3,$4::jsonb,$5,$6::jsonb,'[]'::jsonb,'Prepare the requested device.')`,
    [tenantId, request.rows[0].id, team.rows[0].id, JSON.stringify({ id: 'TEAM-NOTIFY', name: 'Service Desk' }), technicianPerson.rows[0].id, JSON.stringify({ id: 'USR-NOTIFY-TECH', name: 'CI Technician', email: `technician-${suffix}@hi5central.test` })],
  )

  await db.query(
    `UPDATE service_request_tasks
     SET status = 'In Progress', updated_at = now()
     WHERE request_id = $1 AND external_key = 'REQ-NOTIFY-0001-TASK-1'`,
    [request.rows[0].id],
  )
  await db.query(
    `UPDATE service_request_tasks
     SET status = 'Completed', completion_notes = 'Device prepared and verified.', completed_at = now(), updated_at = now()
     WHERE request_id = $1 AND external_key = 'REQ-NOTIFY-0001-TASK-1'`,
    [request.rows[0].id],
  )

  const requesterTaskNotifications = await db.query(
    `SELECT count(*)::int AS count
     FROM platform_notifications
     WHERE tenant_id = $1 AND user_id = $2 AND event_type LIKE 'service_request.task_%'`,
    [tenantId, requesterUserId],
  )
  assert(requesterTaskNotifications.rows[0].count === 0, 'Requester received a task-level notification')

  const requesterTaskDeliveries = await db.query(
    `SELECT count(*)::int AS count
     FROM notification_deliveries d
     JOIN platform_notifications n ON n.id = d.notification_id
     WHERE n.tenant_id = $1 AND n.user_id = $2 AND n.event_type LIKE 'service_request.task_%'`,
    [tenantId, requesterUserId],
  )
  assert(requesterTaskDeliveries.rows[0].count === 0, 'Requester received task-level email/browser delivery rows')

  const technicianTaskNotifications = await db.query(
    `SELECT count(*)::int AS count
     FROM platform_notifications
     WHERE tenant_id = $1 AND user_id = $2 AND event_type LIKE 'service_request.task_%'`,
    [tenantId, assigneeUserId],
  )
  assert(technicianTaskNotifications.rows[0].count >= 2, 'Task assignee stopped receiving operational task notifications')

  await db.query(
    `UPDATE service_requests SET status = 'Completed', updated_at = now() WHERE id = $1`,
    [request.rows[0].id],
  )
  await db.query(
    `INSERT INTO service_request_activities (
       tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot,
       kind, visibility, body_text, metadata
     ) VALUES ($1,$2,$3,$4,$5::jsonb,'system','customer',$6,$7::jsonb)`,
    [
      tenantId,
      request.rows[0].id,
      assigneeUserId,
      technicianPerson.rows[0].id,
      JSON.stringify({ name: 'CI Technician', email: `technician-${suffix}@hi5central.test` }),
      'Service Request completed — all fulfilment work has been verified.',
      JSON.stringify({ event: 'service_request.workflow_transition', from: 'In Progress', to: 'Completed' }),
    ],
  )

  const completionNotification = await db.query(
    `SELECT n.id
     FROM platform_notifications n
     WHERE n.tenant_id = $1 AND n.user_id = $2
       AND n.event_type = 'service_request.customer_update_added'
       AND n.target_reference = 'REQ-NOTIFY-0001'
     ORDER BY n.created_at DESC LIMIT 1`,
    [tenantId, requesterUserId],
  )
  assert(completionNotification.rowCount === 1, 'Requester did not receive the parent Service Request completion update')

  const completionEmail = await db.query(
    `SELECT status FROM notification_deliveries
     WHERE notification_id = $1 AND channel = 'email'`,
    [completionNotification.rows[0].id],
  )
  assert(completionEmail.rowCount === 1, 'Parent Service Request completion did not queue requester email delivery')

  console.log('Task requester notification guard E2E passed')
} finally {
  if (tenantId) await db.query('DELETE FROM tenants WHERE id = $1', [tenantId]).catch(() => {})
  if (requesterUserId) await db.query('DELETE FROM users WHERE id = $1', [requesterUserId]).catch(() => {})
  if (assigneeUserId) await db.query('DELETE FROM users WHERE id = $1', [assigneeUserId]).catch(() => {})
  await db.end()
}
