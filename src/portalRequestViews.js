import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesPortalTenant } from './deploymentConfig.js'

const allowedPriorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const maxFieldsBytes = 250_000
const genericIncidentSchema = [
  { id: 'affectedService', type: 'text', label: 'Affected service', required: false },
  { id: 'impact', type: 'select', label: 'Impact', required: true },
]

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function key(value) {
  return text(value, 100)
    .toUpperCase()
    .replace(/[^A-Z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function portalOrigin(c, slug) {
  return originMatchesPortalTenant(
    c.req.header('origin'),
    c.req.header('referer'),
    slug,
  )
}

async function requireRequester(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!portalOrigin(c, session.slug)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (session.tenant_role !== 'requester') return { error: c.json({ error: 'Requester Portal access is required.' }, 403) }
  return { session }
}

function visibleField(field, values) {
  const condition = asObject(field?.showWhen)
  if (!Object.keys(condition).length) return true
  const current = values[condition.field]
  if (Object.prototype.hasOwnProperty.call(condition, 'equals')) return current === condition.equals
  if (Array.isArray(condition.oneOf)) return condition.oneOf.includes(current)
  return true
}

function fieldHasValue(field, value) {
  if (Array.isArray(value)) return value.length > 0
  if (field?.type === 'checkbox') return Boolean(value)
  return String(value ?? '').trim().length > 0
}

function requestInformation(schema, values) {
  return schema
    .filter((field) => visibleField(field, values))
    .map((field) => {
      const raw = values[field.id]
      const value = Array.isArray(raw) ? raw.join(', ') : raw
      if (value === undefined || value === null || value === '') return null
      return { label: text(field.label, 180), value: text(value, 4000) }
    })
    .filter(Boolean)
}

function safeAttachments(value) {
  return asArray(value).slice(0, 20).map((attachment) => ({
    id: text(attachment?.id, 120),
    name: text(attachment?.name, 240),
    size: Math.max(0, Number(attachment?.size || 0)),
    type: text(attachment?.type, 160),
    visibility: 'customer',
  }))
}

async function requesterPerson(session, db = pool) {
  const result = await db.query(
    `SELECT
       p.id,
       p.external_key,
       p.user_id,
       p.name,
       p.email,
       p.phone,
       p.job_title,
       p.primary_team_id,
       d.name AS department_name,
       s.name AS site_name,
       team.name AS team_name
     FROM organisation_people p
     LEFT JOIN organisation_departments d ON d.id = p.department_id
     LEFT JOIN organisation_sites s ON s.id = p.site_id
     LEFT JOIN organisation_teams team ON team.id = p.primary_team_id
     WHERE p.tenant_id = $1 AND p.user_id = $2 AND p.active = true
     LIMIT 1`,
    [session.tenant_id, session.user_id],
  )
  return result.rows[0] || null
}

function requesterSnapshot(person, session) {
  return {
    userId: person?.user_id || session.user_id,
    personId: person?.external_key || '',
    name: person?.name || session.name,
    email: person?.email || session.email,
    phone: person?.phone || '',
    jobTitle: person?.job_title || '',
    department: person?.department_name || '',
    team: person?.team_name || '',
    site: person?.site_name || '',
  }
}

function effectiveConfiguration(row) {
  if (row?.configuration && Object.keys(row.configuration).length) return row.configuration
  return row?.onboarding_data || {}
}

async function nextIncidentReference(client, tenantId) {
  const settings = await client.query(
    `SELECT configuration, onboarding_data
     FROM tenant_settings
     WHERE tenant_id = $1
     LIMIT 1`,
    [tenantId],
  )
  const config = effectiveConfiguration(settings.rows[0] || {})
  const itsm = asObject(config.itsm)
  const custom = itsm.numberingMode === 'custom'
  const configured = custom ? text(asObject(itsm.recordPrefixes).incident, 12) : 'INC-'
  const cleaned = (configured || 'INC-').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 10)
  const prefix = (cleaned || 'INC-').endsWith('-') ? (cleaned || 'INC-') : `${cleaned || 'INC-'}-`
  const digits = Math.max(4, Math.min(8, Number(itsm.recordDigits || 5)))
  const counter = await client.query(
    `INSERT INTO tenant_record_counters (tenant_id, record_type, next_value, updated_at)
     VALUES ($1, 'incident', 1, now())
     ON CONFLICT (tenant_id, record_type) DO UPDATE SET
       next_value = tenant_record_counters.next_value + 1,
       updated_at = now()
     RETURNING next_value`,
    [tenantId],
  )
  return `${prefix}${String(counter.rows[0].next_value).padStart(digits, '0')}`
}

async function portalIncidentForm(client, tenantId, externalKey) {
  const result = await client.query(
    `SELECT i.*, c.name AS category_name, team.name AS resolved_team_name
     FROM service_catalogue_items i
     LEFT JOIN service_catalogue_categories c ON c.id = i.category_id
     LEFT JOIN organisation_teams team ON team.id = i.fulfilment_team_id
     WHERE i.tenant_id = $1
       AND i.external_key = $2
       AND i.active = true
       AND i.kind = 'request-form'
       AND i.visibility = 'portal'
       AND i.request_type = 'Incident'
     LIMIT 1`,
    [tenantId, key(externalKey)],
  )
  return result.rows[0] || null
}

async function defaultIncidentTeam(client, tenantId) {
  const result = await client.query(
    `SELECT id, external_key, name
     FROM organisation_teams
     WHERE tenant_id = $1
       AND active = true
       AND (external_key = 'TEAM-SERVICE-DESK' OR lower(name) = 'service desk')
     ORDER BY CASE WHEN external_key = 'TEAM-SERVICE-DESK' THEN 0 ELSE 1 END
     LIMIT 1`,
    [tenantId],
  )
  return result.rows[0] || null
}

async function incidentTechnicianRecipients(client, tenantId, teamId) {
  const result = await client.query(
    `WITH team_users AS (
       SELECT DISTINCT p.user_id
       FROM organisation_people p
       JOIN tenant_memberships m
         ON m.tenant_id = p.tenant_id
        AND m.user_id = p.user_id
        AND m.status = 'active'
        AND m.role <> 'requester'
       WHERE p.tenant_id = $1
         AND p.active = true
         AND p.user_id IS NOT NULL
         AND $2::uuid IS NOT NULL
         AND p.primary_team_id = $2
     )
     SELECT user_id FROM team_users
     UNION
     SELECT m.user_id
     FROM tenant_memberships m
     WHERE m.tenant_id = $1
       AND m.status = 'active'
       AND m.role <> 'requester'
       AND NOT EXISTS (SELECT 1 FROM team_users)`,
    [tenantId, teamId || null],
  )
  return result.rows.map((row) => row.user_id).filter(Boolean)
}

async function notifyIncidentTechnicians(client, incident, body, eventType = 'incident.created') {
  if (incident.assigned_person_id) return

  const event = await client.query(
    `SELECT id
     FROM domain_events
     WHERE tenant_id = $1
       AND aggregate_reference = $2
       AND event_type = $3
     ORDER BY created_at DESC
     LIMIT 1`,
    [incident.tenant_id, incident.reference, eventType],
  )
  if (!event.rowCount) return

  const recipients = await incidentTechnicianRecipients(client, incident.tenant_id, incident.assignment_team_id)
  for (const userId of recipients) {
    await client.query(
      `SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
      [
        incident.tenant_id,
        userId,
        event.rows[0].id,
        eventType,
        `${incident.reference} · ${incident.title}`,
        text(body, 2000),
        'Incident',
        incident.reference,
        JSON.stringify({
          source: 'portal',
          status: incident.status,
          priority: incident.priority,
          team: asObject(incident.assignment_team_snapshot).name || '',
        }),
      ],
    )
  }
}

function serviceRequestListRow(row) {
  return {
    id: row.reference,
    reference: row.reference,
    type: 'Service Request',
    catalogueItemTitle: row.catalogue_item_title_snapshot,
    requestType: row.request_type,
    service: row.service,
    priority: row.priority,
    status: row.status,
    source: row.source,
    oneOffCost: Number(row.one_off_cost || 0),
    monthlyCost: Number(row.monthly_cost || 0),
    currency: row.currency || 'GBP',
    title: row.title,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function incidentListRow(row) {
  const data = asObject(row.record_data)
  return {
    id: row.reference,
    reference: row.reference,
    type: 'Incident',
    catalogueItemTitle: data.catalogueItemTitle || '',
    requestType: 'Incident',
    service: row.service,
    priority: row.priority,
    status: row.status,
    source: row.source,
    oneOffCost: 0,
    monthlyCost: 0,
    currency: 'GBP',
    title: row.title,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

async function serviceRequestDetailPayload(request) {
  const [items, approvals, tasks, activities] = await Promise.all([
    pool.query(
      `SELECT catalogue_item_key_snapshot, name_snapshot, category_snapshot, quantity,
              unit_one_off_cost, unit_monthly_cost, currency, options_snapshot, product_snapshot
       FROM service_request_items
       WHERE request_id = $1
       ORDER BY created_at, id`,
      [request.id],
    ),
    pool.query(
      `SELECT id, sequence, label, status, updated_at
       FROM service_request_approvals
       WHERE request_id = $1
       ORDER BY sequence, created_at`,
      [request.id],
    ),
    pool.query(
      `SELECT external_key, title, status, due_at, completed_at
       FROM service_request_tasks
       WHERE request_id = $1
       ORDER BY created_at, id`,
      [request.id],
    ),
    pool.query(
      `SELECT id, actor_snapshot, kind, visibility, body_text, body_html, attachments, metadata, created_at
       FROM service_request_activities
       WHERE request_id = $1 AND visibility = 'customer'
       ORDER BY created_at, id`,
      [request.id],
    ),
  ])

  return {
    ...serviceRequestListRow(request),
    description: request.description,
    descriptionHtml: request.description_html,
    requester: asObject(request.requester_snapshot),
    requestInformation: asArray(request.request_information),
    submittedFields: asObject(request.submitted_fields),
    items: items.rows.map((row) => ({
      id: row.catalogue_item_key_snapshot,
      name: row.name_snapshot,
      category: row.category_snapshot,
      quantity: Number(row.quantity || 1),
      unitOneOffCost: Number(row.unit_one_off_cost || 0),
      unitMonthlyCost: Number(row.unit_monthly_cost || 0),
      currency: row.currency || 'GBP',
      options: asArray(row.options_snapshot),
      product: asObject(row.product_snapshot),
    })),
    approvals: approvals.rows.map((row) => ({
      id: row.id,
      sequence: row.sequence,
      label: row.label,
      status: row.status,
      updatedAt: row.updated_at,
    })),
    tasks: tasks.rows.map((row) => ({
      id: row.external_key,
      title: row.title,
      status: row.status,
      dueAt: row.due_at,
      completedAt: row.completed_at,
    })),
    activities: activities.rows.map((row) => ({
      id: row.id,
      actor: asObject(row.actor_snapshot).name || 'Hi5Central',
      kind: row.kind,
      text: row.body_text,
      html: row.body_html,
      attachments: asArray(row.attachments),
      metadata: asObject(row.metadata),
      createdAt: row.created_at,
    })),
  }
}

async function incidentDetailPayload(incident, db = pool) {
  const activities = await db.query(
    `SELECT id, actor_snapshot, kind, visibility, body_text, metadata, created_at
     FROM itsm_record_activities
     WHERE record_id = $1 AND visibility = 'customer'
     ORDER BY created_at, id`,
    [incident.id],
  )
  const data = asObject(incident.record_data)
  return {
    ...incidentListRow(incident),
    description: incident.description,
    descriptionHtml: '',
    requester: asObject(incident.requester_snapshot),
    requestInformation: asArray(data.requestInformation),
    submittedFields: asObject(data.submittedFields),
    items: [],
    approvals: [],
    tasks: [],
    activities: activities.rows.map((row) => ({
      id: row.id,
      actor: asObject(row.actor_snapshot).name || 'Hi5Central',
      kind: row.kind,
      text: row.body_text,
      html: '',
      attachments: asArray(asObject(row.metadata).attachments),
      metadata: asObject(row.metadata),
      createdAt: row.created_at,
    })),
  }
}

async function ownIncident(session, reference, db = pool) {
  const person = await requesterPerson(session, db)
  if (!person) return null
  const result = await db.query(
    `SELECT *
     FROM itsm_records
     WHERE tenant_id = $1
       AND requester_person_id = $2
       AND record_type = 'Incident'
       AND upper(reference) = upper($3)
     LIMIT 1`,
    [session.tenant_id, person.id, text(reference, 80)],
  )
  return result.rows[0] || null
}

export function registerPortalRequestViewRoutes(app) {
  app.post('/api/v1/portal/incidents', async (c) => {
    const auth = await requireRequester(c)
    if (auth.error) return auth.error

    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const catalogueItemId = key(body?.catalogueItemId)
    const summary = text(body?.summary, 240)
    const fields = asObject(body?.fields)
    const details = asObject(body?.details)
    const detailText = text(details.text, 20_000)
    const priority = allowedPriorities.has(body?.urgency) ? body.urgency : 'Medium'

    if (summary.length < 3) return c.json({ error: 'Add a summary of at least 3 characters.' }, 400)
    if (!catalogueItemId && detailText.length < 3) return c.json({ error: 'Tell the Service Desk what happened.' }, 400)
    if (JSON.stringify(fields).length > maxFieldsBytes) return c.json({ error: 'Submitted request fields are too large.' }, 413)

    try {
      const created = await withTransaction(async (client) => {
        const form = catalogueItemId ? await portalIncidentForm(client, auth.session.tenant_id, catalogueItemId) : null
        if (catalogueItemId && !form) {
          const error = new Error('That Incident form is unavailable in this Help Centre.')
          error.status = 404
          throw error
        }

        const schema = form ? asArray(form.form_schema) : genericIncidentSchema
        const visible = schema.filter((field) => visibleField(field, fields))
        const missing = visible.filter((field) => field?.required && !fieldHasValue(field, fields[field.id]))
        if (missing.length) {
          const error = new Error(`Complete the required field${missing.length === 1 ? '' : 's'}: ${missing.map((field) => field.label).join(', ')}.`)
          error.status = 400
          throw error
        }

        const person = await requesterPerson(auth.session, client)
        if (!person) {
          const error = new Error('Your Portal account is not linked to an active Person record.')
          error.status = 409
          throw error
        }

        let teamId = form?.fulfilment_team_id || null
        let teamKey = ''
        let teamName = form?.resolved_team_name || form?.fulfilment_team_name || ''
        if (!teamId && teamName) {
          const team = await client.query(
            `SELECT id, external_key, name
             FROM organisation_teams
             WHERE tenant_id = $1 AND name = $2 AND active = true
             LIMIT 1`,
            [auth.session.tenant_id, teamName],
          )
          if (team.rowCount) {
            teamId = team.rows[0].id
            teamKey = team.rows[0].external_key
            teamName = team.rows[0].name
          }
        }
        if (!form && !teamId) {
          const team = await defaultIncidentTeam(client, auth.session.tenant_id)
          if (team) {
            teamId = team.id
            teamKey = team.external_key
            teamName = team.name
          }
        }

        const reference = await nextIncidentReference(client, auth.session.tenant_id)
        const info = requestInformation(schema, fields)
        const snapshot = requesterSnapshot(person, auth.session)
        const attachments = safeAttachments(details.attachments)
        const result = await client.query(
          `INSERT INTO itsm_records (
             tenant_id, reference, record_type, requester_person_id, requester_snapshot,
             title, description, service, category, priority, status, source,
             assignment_team_id, assignment_team_snapshot, assignee_snapshot,
             record_data, created_by_user_id
           ) VALUES (
             $1,$2,'Incident',$3,$4::jsonb,$5,$6,$7,$8,$9,'New','portal',$10,$11::jsonb,'{}'::jsonb,$12::jsonb,$13
           ) RETURNING *`,
          [
            auth.session.tenant_id,
            reference,
            person.id,
            JSON.stringify(snapshot),
            summary,
            detailText,
            text(form?.service || 'IT Support', 160),
            text(form?.category_name || 'Incident', 160),
            priority,
            teamId || null,
            JSON.stringify({ id: teamKey || teamId || '', name: teamName }),
            JSON.stringify({
              catalogueItemId: form?.external_key || '',
              catalogueItemTitle: form?.title || 'Raise incident',
              submittedFields: fields,
              requestInformation: info,
              attachments,
              portalEntryPoint: form ? 'catalogue' : 'raise-incident',
            }),
            auth.session.user_id,
          ],
        )
        const incident = result.rows[0]

        await client.query(
          `INSERT INTO itsm_record_activities (
             tenant_id, record_id, actor_user_id, actor_person_id, actor_snapshot,
             kind, visibility, body_text, metadata
           ) VALUES ($1,$2,$3,$4,$5::jsonb,'customer','customer',$6,$7::jsonb)`,
          [
            auth.session.tenant_id,
            incident.id,
            auth.session.user_id,
            person.id,
            JSON.stringify({ name: snapshot.name, email: snapshot.email }),
            detailText || `Reported ${form?.title || 'an incident'}.`,
            JSON.stringify({ event: 'incident.portal_submitted', catalogueItemId: form?.external_key || '', attachments, portalEntryPoint: form ? 'catalogue' : 'raise-incident' }),
          ],
        )

        await notifyIncidentTechnicians(
          client,
          incident,
          `${snapshot.name} reported an incident through the Help Centre.`,
          'incident.created',
        )

        return incident
      })

      return c.json(await incidentDetailPayload(created), 201)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.get('/api/v1/portal/requests', async (c) => {
    const auth = await requireRequester(c)
    if (auth.error) return auth.error

    const limit = Math.max(1, Math.min(100, Number(c.req.query('limit') || 50)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))
    const fetchLimit = Math.min(200, limit + offset)
    const person = await requesterPerson(auth.session)

    const [serviceRequests, incidents] = await Promise.all([
      pool.query(
        `SELECT *
         FROM service_requests
         WHERE tenant_id = $1 AND requester_user_id = $2
         ORDER BY updated_at DESC
         LIMIT $3`,
        [auth.session.tenant_id, auth.session.user_id, fetchLimit],
      ),
      person ? pool.query(
        `SELECT *
         FROM itsm_records
         WHERE tenant_id = $1 AND requester_person_id = $2 AND record_type = 'Incident'
         ORDER BY updated_at DESC
         LIMIT $3`,
        [auth.session.tenant_id, person.id, fetchLimit],
      ) : Promise.resolve({ rows: [] }),
    ])

    const items = [
      ...serviceRequests.rows.map(serviceRequestListRow),
      ...incidents.rows.map(incidentListRow),
    ]
      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
      .slice(offset, offset + limit)

    return c.json({ items, limit, offset })
  })

  app.get('/api/v1/portal/requests/:reference', async (c) => {
    const auth = await requireRequester(c)
    if (auth.error) return auth.error

    const reference = text(c.req.param('reference'), 80).toUpperCase()
    const serviceRequest = await pool.query(
      `SELECT *
       FROM service_requests
       WHERE tenant_id = $1 AND requester_user_id = $2 AND reference = $3
       LIMIT 1`,
      [auth.session.tenant_id, auth.session.user_id, reference],
    )
    if (serviceRequest.rowCount) return c.json(await serviceRequestDetailPayload(serviceRequest.rows[0]))

    const incident = await ownIncident(auth.session, reference)
    if (incident) return c.json(await incidentDetailPayload(incident))
    return c.json({ error: 'Request not found.' }, 404)
  })

  app.post('/api/v1/portal/requests/:reference/activities', async (c) => {
    const auth = await requireRequester(c)
    if (auth.error) return auth.error

    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const message = text(body?.text, 20_000)
    if (!message) return c.json({ error: 'Add an update before sending.' }, 400)

    const reference = text(c.req.param('reference'), 80).toUpperCase()
    const person = await requesterPerson(auth.session)
    const snapshot = requesterSnapshot(person, auth.session)

    const serviceRequest = await pool.query(
      `SELECT *
       FROM service_requests
       WHERE tenant_id = $1 AND requester_user_id = $2 AND reference = $3
       LIMIT 1`,
      [auth.session.tenant_id, auth.session.user_id, reference],
    )
    if (serviceRequest.rowCount) {
      await pool.query(
        `INSERT INTO service_request_activities (
           tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot,
           kind, visibility, body_text, metadata
         ) VALUES ($1,$2,$3,$4,$5::jsonb,'customer','customer',$6,$7::jsonb)`,
        [
          auth.session.tenant_id,
          serviceRequest.rows[0].id,
          auth.session.user_id,
          person?.id || null,
          JSON.stringify({ name: snapshot.name, email: snapshot.email }),
          message,
          JSON.stringify({ event: 'requester.customer_update', source: 'portal' }),
        ],
      )
      const refreshed = await pool.query('SELECT * FROM service_requests WHERE id = $1', [serviceRequest.rows[0].id])
      return c.json(await serviceRequestDetailPayload(refreshed.rows[0]), 201)
    }

    const incident = await ownIncident(auth.session, reference)
    if (!incident) return c.json({ error: 'Request not found.' }, 404)

    await withTransaction(async (client) => {
      await client.query(
        `INSERT INTO itsm_record_activities (
           tenant_id, record_id, actor_user_id, actor_person_id, actor_snapshot,
           kind, visibility, body_text, metadata
         ) VALUES ($1,$2,$3,$4,$5::jsonb,'customer','customer',$6,$7::jsonb)`,
        [
          auth.session.tenant_id,
          incident.id,
          auth.session.user_id,
          person?.id || null,
          JSON.stringify({ name: snapshot.name, email: snapshot.email }),
          message,
          JSON.stringify({ event: 'requester.customer_update', source: 'portal' }),
        ],
      )

      if (!incident.assigned_person_id) {
        await notifyIncidentTechnicians(client, incident, `${snapshot.name} added a customer update: ${message}`, 'incident.customer_update_added')
      }
    })

    const refreshed = await ownIncident(auth.session, reference)
    return c.json(await incidentDetailPayload(refreshed), 201)
  })
}
