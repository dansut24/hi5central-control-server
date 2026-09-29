import { execFileSync } from 'node:child_process'
import pg from 'pg'

const { Client } = pg
const connectionString = process.env.DATABASE_URL
if (!connectionString) throw new Error('DATABASE_URL is required')

const tenantId = '00000000-0000-4000-8000-000000000701'
const userId = '00000000-0000-4000-8000-000000000702'
const teamId = '00000000-0000-4000-8000-000000000703'
const categoryId = '00000000-0000-4000-8000-000000000704'
const srItemId = '00000000-0000-4000-8000-000000000705'
const incidentItemId = '00000000-0000-4000-8000-000000000706'
const requestId = '00000000-0000-4000-8000-000000000707'
const slug = 'ci-service-request-reset'

await seed()
execFileSync(process.execPath, ['scripts/reset-service-request-defaults.mjs'], {
  cwd: process.cwd(),
  env: { ...process.env, TENANT_SLUG: slug },
  stdio: 'inherit',
})
await verify()

async function client() {
  const db = new Client({ connectionString })
  await db.connect()
  return db
}

async function seed() {
  const db = await client()
  try {
    await db.query('BEGIN')
    await db.query(
      `INSERT INTO tenants (id, slug, company_name, status)
       VALUES ($1,$2,'CI Service Request Reset','active')`,
      [tenantId, slug],
    )
    await db.query(
      `INSERT INTO users (id, email, name, password_hash, email_verified_at)
       VALUES ($1,'reset-ci@hi5central.test','Reset CI Owner','unused',now())`,
      [userId],
    )
    await db.query(
      `INSERT INTO tenant_memberships (tenant_id, user_id, role, status)
       VALUES ($1,$2,'owner','active')`,
      [tenantId, userId],
    )
    await db.query(
      `INSERT INTO tenant_settings (
         tenant_id, modules, onboarding_step, onboarding_completed_at,
         tenant_url, portal_url, onboarding_data, configuration
       ) VALUES (
         $1,'{"itsm":true}'::jsonb,'complete',now(),
         'https://ci-service-request-reset.hi5central.test',
         'https://ci-service-request-reset-portal.hi5central.test',
         '{}'::jsonb,'{}'::jsonb
       )`,
      [tenantId],
    )
    await db.query(
      `INSERT INTO organisation_teams (id, tenant_id, external_key, name, active)
       VALUES ($1,$2,'TEAM-SERVICE-DESK','Service Desk',true)`,
      [teamId, tenantId],
    )
    await db.query(
      `INSERT INTO service_catalogue_categories (id, tenant_id, external_key, name, sort_order, active)
       VALUES ($1,$2,'CATEGORY-TEST','Test',0,true)`,
      [categoryId, tenantId],
    )
    await db.query(
      `INSERT INTO service_catalogue_items (
         id, tenant_id, external_key, category_id, title, kind, request_type, service,
         fulfilment_team_id, fulfilment_team_name, approval_mode, visibility, workflow_key, active
       ) VALUES
         ($1,$3,'CAT-CUSTOM-SR',$4,'Custom Service Request','request-form','Service Request','Test',$5,'Service Desk','none','technicians','custom-flow',true),
         ($2,$3,'CAT-KEEP-INCIDENT',$4,'Keep Incident','request-form','Incident','IT Support',$5,'Service Desk','none','portal','incident-flow',true)`,
      [srItemId, incidentItemId, tenantId, categoryId, teamId],
    )
    await db.query(
      `INSERT INTO service_catalogue_fulfilment_flows (tenant_id, catalogue_item_key, tasks)
       VALUES ($1,'CAT-CUSTOM-SR','[{"id":"old","title":"Old task"}]'::jsonb)`,
      [tenantId],
    )
    await db.query(
      `INSERT INTO service_requests (
         id, tenant_id, reference, catalogue_item_id, catalogue_item_key_snapshot, catalogue_item_title_snapshot,
         requester_user_id, requester_snapshot, title, request_type, service, priority, status, source,
         fulfilment_team_id, fulfilment_team_snapshot, created_by_user_id
       ) VALUES ($1,$2,'REQ-00042',$3,'CAT-CUSTOM-SR','Custom Service Request',$4,
         '{"name":"Reset CI Owner","email":"reset-ci@hi5central.test"}'::jsonb,'Old request','Service Request','Test','Medium','New','technician',$5,
         '{"id":"TEAM-SERVICE-DESK","name":"Service Desk"}'::jsonb,$4)`,
      [requestId, tenantId, srItemId, userId, teamId],
    )
    await db.query(
      `INSERT INTO tenant_record_counters (tenant_id, record_type, next_value)
       VALUES ($1,'service_request',42)`,
      [tenantId],
    )
    await db.query(
      `INSERT INTO domain_events (tenant_id, event_type, aggregate_type, aggregate_reference)
       VALUES ($1,'service_request.test','Service Request','REQ-00042')`,
      [tenantId],
    )
    await db.query(
      `INSERT INTO workflow_approvals (tenant_id, record_reference, record_type, approval_type)
       VALUES ($1,'REQ-00042','Service Request','workflow')`,
      [tenantId],
    )
    await db.query('COMMIT')
  } catch (error) {
    await db.query('ROLLBACK')
    throw error
  } finally {
    await db.end()
  }
}

async function verify() {
  const db = await client()
  try {
    const [requests, forms, flows, incident, counter, events, approvals] = await Promise.all([
      db.query('SELECT count(*)::int AS count FROM service_requests WHERE tenant_id=$1', [tenantId]),
      db.query("SELECT external_key,visibility,active FROM service_catalogue_items WHERE tenant_id=$1 AND kind='request-form' AND request_type='Service Request' ORDER BY external_key", [tenantId]),
      db.query('SELECT catalogue_item_key,tasks FROM service_catalogue_fulfilment_flows WHERE tenant_id=$1 ORDER BY catalogue_item_key', [tenantId]),
      db.query("SELECT count(*)::int AS count FROM service_catalogue_items WHERE tenant_id=$1 AND external_key='CAT-KEEP-INCIDENT' AND active=true", [tenantId]),
      db.query("SELECT count(*)::int AS count FROM tenant_record_counters WHERE tenant_id=$1 AND record_type='service_request'", [tenantId]),
      db.query("SELECT count(*)::int AS count FROM domain_events WHERE tenant_id=$1 AND aggregate_type='Service Request'", [tenantId]),
      db.query("SELECT count(*)::int AS count FROM workflow_approvals WHERE tenant_id=$1 AND record_type='Service Request'", [tenantId]),
    ])

    if (requests.rows[0].count !== 0) throw new Error('Service Requests were not cleared.')
    if (forms.rowCount !== 8) throw new Error(`Expected 8 default Service Request forms, found ${forms.rowCount}.`)
    if (forms.rows.some((row) => row.visibility !== 'portal' || row.active !== true)) throw new Error('A default Service Request is not active and Portal visible.')
    if (flows.rowCount !== 8) throw new Error(`Expected 8 default fulfilment flows, found ${flows.rowCount}.`)
    if (flows.rows.some((row) => !Array.isArray(row.tasks) || !row.tasks.length)) throw new Error('A default fulfilment flow has no tasks.')
    if (incident.rows[0].count !== 1) throw new Error('Non-Service-Request catalogue data was removed.')
    if (counter.rows[0].count !== 0) throw new Error('Service Request counter was not reset.')
    if (events.rows[0].count !== 0) throw new Error('Service Request domain events were not cleared.')
    if (approvals.rows[0].count !== 0) throw new Error('Service Request workflow approvals were not cleared.')

    for (const required of ['CAT-ONBOARDING', 'CAT-MOVER', 'CAT-LEAVER']) {
      if (!forms.rows.some((row) => row.external_key === required)) throw new Error(`Missing reseeded default ${required}.`)
    }

    console.log('Service Request reset e2e passed.')
  } finally {
    await db.query('DELETE FROM tenants WHERE id=$1', [tenantId])
    await db.query('DELETE FROM users WHERE id=$1', [userId])
    await db.end()
  }
}
