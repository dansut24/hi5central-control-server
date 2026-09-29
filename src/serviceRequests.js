import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'
import { originMatchesTenant, portalRequestFromHeaders } from './deploymentConfig.js'

const allowedPriorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const allowedDecisions = new Set(['Approved', 'Rejected'])
const maxFieldsBytes = 250_000

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  return { session }
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function key(value) {
  return text(value, 100)
    .toUpperCase()
    .replace(/[^A-Z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
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

function effectiveConfiguration(row) {
  if (row?.configuration && Object.keys(row.configuration).length) return row.configuration
  return row?.onboarding_data || {}
}

async function numberingSettings(client, tenantId) {
  const result = await client.query(
    `SELECT configuration, onboarding_data
     FROM tenant_settings
     WHERE tenant_id = $1`,
    [tenantId],
  )
  const config = effectiveConfiguration(result.rows[0] || {})
  const itsm = asObject(config.itsm)
  const custom = itsm.numberingMode === 'custom'
  const configuredPrefix = custom ? text(asObject(itsm.recordPrefixes).serviceRequest, 12) : 'REQ-'
  const prefixBase = (configuredPrefix || 'REQ-').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 10) || 'REQ-'
  const prefix = prefixBase.endsWith('-') ? prefixBase : `${prefixBase}-`
  const digits = Math.max(4, Math.min(8, Number(itsm.recordDigits || 5)))
  return { prefix, digits, config }
}

async function nextReference(client, tenantId) {
  const { prefix, digits } = await numberingSettings(client, tenantId)
  const counter = await client.query(
    `INSERT INTO tenant_record_counters (tenant_id, record_type, next_value, updated_at)
     VALUES ($1, 'service_request', 1, now())
     ON CONFLICT (tenant_id, record_type) DO UPDATE SET
       next_value = tenant_record_counters.next_value + 1,
       updated_at = now()
     RETURNING next_value`,
    [tenantId],
  )
  return `${prefix}${String(counter.rows[0].next_value).padStart(digits, '0')}`
}

async function requesterContext(client, session, requestedPersonKey = '') {
  const externalKey = session.tenant_role === 'requester' ? '' : text(requestedPersonKey, 120)
  const where = externalKey
    ? 'p.tenant_id = $1 AND p.external_key = $2 AND p.active = true'
    : 'p.tenant_id = $1 AND p.user_id = $2'
  const lookupValue = externalKey || session.user_id
  const result = await client.query(
    `SELECT
       p.id,
       p.external_key,
       p.user_id,
       p.name,
       p.email,
       p.phone,
       p.job_title,
       p.manager_id,
       d.name AS department_name,
       s.name AS site_name,
       team.name AS team_name,
       manager.id AS manager_person_id,
       manager.external_key AS manager_external_key,
       manager.name AS manager_name,
       manager.email AS manager_email,
       manager.user_id AS manager_user_id
     FROM organisation_people p
     LEFT JOIN organisation_departments d ON d.id = p.department_id
     LEFT JOIN organisation_sites s ON s.id = p.site_id
     LEFT JOIN organisation_teams team ON team.id = p.primary_team_id
     LEFT JOIN organisation_people manager ON manager.id = p.manager_id
     WHERE ${where}
     LIMIT 1`,
    [session.tenant_id, lookupValue],
  )

  const person = result.rows[0] || null
  return {
    person,
    snapshot: {
      userId: person?.user_id || (externalKey ? '' : session.user_id),
      personId: person?.external_key || '',
      name: person?.name || session.name,
      email: person?.email || session.email,
      phone: person?.phone || '',
      jobTitle: person?.job_title || '',
      department: person?.department_name || '',
      team: person?.team_name || '',
      site: person?.site_name || '',
    },
    manager: person?.manager_person_id ? {
      personId: person.manager_person_id,
      externalKey: person.manager_external_key,
      userId: person.manager_user_id,
      name: person.manager_name,
      email: person.manager_email,
    } : null,
  }
}

async function catalogueRequestForm(client, tenantId, externalKey, requesterRole) {
  const result = await client.query(
    `SELECT i.*, c.name AS category_name, team.name AS resolved_team_name
     FROM service_catalogue_items i
     LEFT JOIN service_catalogue_categories c ON c.id = i.category_id
     LEFT JOIN organisation_teams team ON team.id = i.fulfilment_team_id
     WHERE i.tenant_id = $1
       AND i.external_key = $2
       AND i.active = true
       AND i.kind = 'request-form'
     LIMIT 1`,
    [tenantId, key(externalKey)],
  )
  if (!result.rowCount) return null
  const row = result.rows[0]
  if (requesterRole === 'requester' && row.visibility !== 'portal') return null
  if (row.visibility === 'hidden' && !['owner', 'admin'].includes(requesterRole)) return null
  return row
}

async function catalogueProducts(client, tenantId, schema) {
  const productKeys = [...new Set(schema.flatMap((field) => {
    if (!['product', 'checkbox-products'].includes(field?.type)) return []
    return asArray(field.options).map((option) => key(option?.itemId)).filter(Boolean)
  }))]
  if (!productKeys.length) return new Map()

  const result = await client.query(
    `SELECT i.*, c.name AS category_name
     FROM service_catalogue_items i
     LEFT JOIN service_catalogue_categories c ON c.id = i.category_id
     WHERE i.tenant_id = $1
       AND i.external_key = ANY($2::text[])
       AND i.kind = 'product'`,
    [tenantId, productKeys],
  )
  return new Map(result.rows.map((row) => [row.external_key, row]))
}

function selectedProductOptions(field, values) {
  const raw = values[field.id]
  if (field.type === 'product') {
    if (!raw) return []
    const option = asArray(field.options).find((candidate) => candidate?.value === raw)
    return option ? [option] : []
  }
  if (field.type === 'checkbox-products') {
    const selected = new Set(asArray(raw))
    return asArray(field.options).filter((candidate) => selected.has(candidate?.value))
  }
  return []
}

function itemSnapshots(schema, values, productMap, portalSource) {
  const items = []
  let oneOff = 0
  let monthly = 0

  for (const field of schema) {
    if (!visibleField(field, values)) continue
    if (!['product', 'checkbox-products'].includes(field.type)) continue

    for (const option of selectedProductOptions(field, values)) {
      const productKey = key(option?.itemId)
      if (!productKey) continue
      const product = productMap.get(productKey)
      if (!product || !product.active) {
        const error = new Error(`${field.label || 'A selected product'} is no longer available.`)
        error.status = 409
        throw error
      }
      if (portalSource && product.visibility !== 'portal') {
        const error = new Error(`${field.label || 'A selected product'} is no longer available in the Portal.`)
        error.status = 409
        throw error
      }

      const item = {
        databaseId: product.id,
        id: product.external_key,
        name: product.title,
        category: product.category_name || option?.category || '',
        quantity: 1,
        unitOneOffCost: Number(product.one_off_price || 0),
        unitMonthlyCost: Number(product.monthly_price || 0),
        currency: product.currency || 'GBP',
        selectedVia: text(field.label, 180),
        options: [text(field.label, 180)],
        productSnapshot: {
          id: product.external_key,
          title: product.title,
          vendor: product.vendor || '',
          sku: product.sku || '',
          priceMode: product.price_mode,
          oneOffPrice: Number(product.one_off_price || 0),
          monthlyPrice: Number(product.monthly_price || 0),
          currency: product.currency || 'GBP',
        },
      }
      oneOff += item.unitOneOffCost
      monthly += item.unitMonthlyCost
      items.push(item)
    }
  }

  return { items, oneOff, monthly }
}

function approvalPlan(form, totalValue, config, requester) {
  const mode = text(form.approval_mode || 'none', 80)
  if (mode === 'none') return null

  const configuredThreshold = Number(asObject(config.itsm).managerApprovalThreshold || 500)
  const threshold = form.approval_threshold === null
    ? configuredThreshold
    : Number(form.approval_threshold)

  if (mode === 'manager-cost' && totalValue < threshold) return null

  if (mode === 'manager' || mode === 'manager-cost') {
    return {
      label: mode === 'manager-cost' ? `Manager approval · ${threshold.toFixed(2)} threshold` : 'Manager approval',
      approver: requester.manager,
      threshold,
    }
  }

  return {
    label: 'Request approval',
    approver: null,
    threshold: form.approval_threshold === null ? null : Number(form.approval_threshold),
  }
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

async function requestPayload(db, requestRow) {
  const [itemsResult, approvalsResult, tasksResult, activitiesResult] = await Promise.all([
    db.query('SELECT * FROM service_request_items WHERE request_id = $1 ORDER BY created_at, id', [requestRow.id]),
    db.query('SELECT * FROM service_request_approvals WHERE request_id = $1 ORDER BY sequence, created_at', [requestRow.id]),
    db.query('SELECT * FROM service_request_tasks WHERE request_id = $1 ORDER BY created_at, id', [requestRow.id]),
    db.query('SELECT * FROM service_request_activities WHERE request_id = $1 ORDER BY created_at, id', [requestRow.id]),
  ])

  return {
    databaseId: requestRow.id,
    id: requestRow.reference,
    reference: requestRow.reference,
    type: 'Service Request',
    catalogueItemId: requestRow.catalogue_item_key_snapshot,
    catalogueItemTitle: requestRow.catalogue_item_title_snapshot,
    title: requestRow.title,
    description: requestRow.description,
    descriptionHtml: requestRow.description_html,
    requester: asObject(requestRow.requester_snapshot).name || '',
    requesterEmail: asObject(requestRow.requester_snapshot).email || '',
    requesterJobTitle: asObject(requestRow.requester_snapshot).jobTitle || '',
    requesterDepartment: asObject(requestRow.requester_snapshot).department || '',
    requesterSite: asObject(requestRow.requester_snapshot).site || '',
    requesterSnapshot: requestRow.requester_snapshot || {},
    service: requestRow.service,
    team: asObject(requestRow.fulfilment_team_snapshot).name || '',
    priority: requestRow.priority,
    status: requestRow.status,
    source: requestRow.source,
    requestInformation: requestRow.request_information || [],
    submittedFields: requestRow.submitted_fields || {},
    oneOffCost: Number(requestRow.one_off_cost || 0),
    monthlyCost: Number(requestRow.monthly_cost || 0),
    currency: requestRow.currency,
    approvalMode: requestRow.approval_mode_snapshot,
    approvalThreshold: requestRow.approval_threshold_snapshot === null ? null : Number(requestRow.approval_threshold_snapshot),
    workflow: requestRow.workflow_key_snapshot,
    createdAt: requestRow.created_at,
    updatedAt: requestRow.updated_at,
    requestedItems: itemsResult.rows.map((item) => ({
      databaseId: item.id,
      id: item.catalogue_item_key_snapshot,
      name: item.name_snapshot,
      category: item.category_snapshot,
      quantity: item.quantity,
      unitOneOffCost: Number(item.unit_one_off_cost || 0),
      unitMonthlyCost: Number(item.unit_monthly_cost || 0),
      unitCost: Number(item.unit_monthly_cost || 0) > 0 ? Number(item.unit_monthly_cost) : Number(item.unit_one_off_cost || 0),
      recurring: Number(item.unit_monthly_cost || 0) > 0 ? 'monthly' : '',
      currency: item.currency,
      options: item.options_snapshot || [],
      productSnapshot: item.product_snapshot || {},
    })),
    requestApprovals: approvalsResult.rows.map((approval) => ({
      id: approval.id,
      label: approval.label,
      status: approval.status,
      approver: asObject(approval.approver_snapshot).name || 'Unassigned approver',
      approverEmail: asObject(approval.approver_snapshot).email || '',
      approverId: asObject(approval.approver_snapshot).personId || '',
      decisionNote: approval.decision_note,
      updated: approval.updated_at,
    })),
    requestTasks: tasksResult.rows.map((task) => ({
      id: task.external_key,
      title: task.title,
      status: task.status,
      team: asObject(task.team_snapshot).name || '',
      assignee: asObject(task.assignee_snapshot).name || '',
      instructions: task.instructions,
      dependencies: task.dependencies || [],
      dueAt: task.due_at,
      completionNotes: task.completion_notes,
    })),
    activities: activitiesResult.rows.map((activity) => ({
      id: activity.id,
      actor: asObject(activity.actor_snapshot).name || 'Hi5Central',
      kind: activity.kind,
      visibility: activity.visibility,
      text: activity.body_text,
      html: activity.body_html,
      attachments: activity.attachments || [],
      metadata: activity.metadata || {},
      createdAt: activity.created_at,
    })),
  }
}

async function lookupRequest(tenantId, reference) {
  const result = await pool.query(
    `SELECT * FROM service_requests
     WHERE tenant_id = $1 AND reference = $2
     LIMIT 1`,
    [tenantId, text(reference, 40).toUpperCase()],
  )
  return result.rows[0] || null
}

function canReadRequest(session, row) {
  if (session.tenant_role !== 'requester') return true
  return row.requester_user_id === session.user_id
}

export function registerServiceRequestRoutes(app) {
  app.get('/api/v1/service-requests', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    const limit = Math.max(1, Math.min(200, Number(c.req.query('limit') || 100)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))
    const values = [auth.session.tenant_id, limit, offset]
    const requesterClause = auth.session.tenant_role === 'requester' ? 'AND requester_user_id = $4' : ''
    if (auth.session.tenant_role === 'requester') values.push(auth.session.user_id)

    const result = await pool.query(
      `SELECT * FROM service_requests
       WHERE tenant_id = $1 ${requesterClause}
       ORDER BY updated_at DESC
       LIMIT $2 OFFSET $3`,
      values,
    )

    const items = []
    for (const row of result.rows) items.push(await requestPayload(pool, row))
    return c.json({ items, limit, offset })
  })

  app.get('/api/v1/service-requests/:reference', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    const row = await lookupRequest(auth.session.tenant_id, c.req.param('reference'))
    if (!row || !canReadRequest(auth.session, row)) return c.json({ error: 'Service Request not found.' }, 404)
    return c.json(await requestPayload(pool, row))
  })

  app.post('/api/v1/service-requests', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const catalogueItemId = key(body?.catalogueItemId)
    const summary = text(body?.summary, 240)
    const fields = asObject(body?.fields)
    const details = asObject(body?.details)
    const priority = allowedPriorities.has(body?.urgency) ? body.urgency : 'Medium'
    const requestedPersonKey = auth.session.tenant_role === 'requester' ? '' : text(body?.requesterPersonId, 120)

    if (!catalogueItemId) return c.json({ error: 'Select a Service Catalogue item.' }, 400)
    if (summary.length < 3) return c.json({ error: 'Add a summary of at least 3 characters.' }, 400)
    if (JSON.stringify(fields).length > maxFieldsBytes) return c.json({ error: 'Submitted request fields are too large.' }, 413)

    try {
      const created = await withTransaction(async (client) => {
        const form = await catalogueRequestForm(client, auth.session.tenant_id, catalogueItemId, auth.session.tenant_role)
        if (!form) {
          const error = new Error('That Service Catalogue item is unavailable.')
          error.status = 404
          throw error
        }
        if (form.request_type !== 'Service Request') {
          const error = new Error('This catalogue item creates a different record type and cannot be submitted as a Service Request.')
          error.status = 409
          throw error
        }

        const schema = asArray(form.form_schema)
        const visible = schema.filter((field) => visibleField(field, fields))
        const missing = visible.filter((field) => field?.required && !fieldHasValue(field, fields[field.id]))
        if (missing.length) {
          const error = new Error(`Complete the required field${missing.length === 1 ? '' : 's'}: ${missing.map((field) => field.label).join(', ')}.`)
          error.status = 400
          throw error
        }

        const products = await catalogueProducts(client, auth.session.tenant_id, schema)
        const origin = c.req.header('origin') || ''
        const portalSource = portalRequestFromHeaders(origin, c.req.header('referer')) || auth.session.tenant_role === 'requester'
        const priced = itemSnapshots(schema, fields, products, portalSource)
        const requester = await requesterContext(client, auth.session, requestedPersonKey)
        if (requestedPersonKey && !requester.person) {
          const error = new Error('Select an active Person from this tenant.')
          error.status = 400
          throw error
        }
        const { config } = await numberingSettings(client, auth.session.tenant_id)
        const approval = approvalPlan(form, priced.oneOff + priced.monthly, config, requester)
        const reference = await nextReference(client, auth.session.tenant_id)

        let teamId = form.fulfilment_team_id
        let teamName = form.resolved_team_name || form.fulfilment_team_name || ''
        if (!teamId && teamName) {
          const teamResult = await client.query(
            `SELECT id, name FROM organisation_teams
             WHERE tenant_id = $1 AND name = $2 AND active = true
             LIMIT 1`,
            [auth.session.tenant_id, teamName],
          )
          if (teamResult.rowCount) {
            teamId = teamResult.rows[0].id
            teamName = teamResult.rows[0].name
          }
        }

        const requestResult = await client.query(
          `INSERT INTO service_requests (
             tenant_id, reference, catalogue_item_id, catalogue_item_key_snapshot, catalogue_item_title_snapshot,
             requester_user_id, requester_person_id, requester_snapshot, title, description, description_html,
             request_type, service, priority, status, source, fulfilment_team_id, fulfilment_team_snapshot,
             submitted_fields, request_information, approval_mode_snapshot, approval_threshold_snapshot,
             workflow_key_snapshot, one_off_cost, monthly_cost, currency, created_by_user_id
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,'',$11,$12,$13,$14,$15,$16,$17::jsonb,$18::jsonb,$19::jsonb,
             $20,$21,$22,$23,$24,$25,$26
           ) RETURNING *`,
          [
            auth.session.tenant_id,
            reference,
            form.id,
            form.external_key,
            form.title,
            requester.person?.user_id || (requestedPersonKey ? null : auth.session.user_id),
            requester.person?.id || null,
            JSON.stringify(requester.snapshot),
            summary,
            text(details.text, 20_000),
            'Service Request',
            form.service || 'Service Catalogue',
            priority,
            approval ? 'Pending Approval' : 'New',
            portalSource ? 'portal' : 'technician',
            null,
            JSON.stringify({}),
            JSON.stringify(fields),
            JSON.stringify(requestInformation(schema, fields)),
            form.approval_mode || 'none',
            form.approval_threshold === null ? null : Number(form.approval_threshold),
            form.workflow_key || '',
            priced.oneOff,
            priced.monthly,
            form.currency || 'GBP',
            auth.session.user_id,
          ],
        )
        const request = requestResult.rows[0]

        for (const item of priced.items) {
          await client.query(
            `INSERT INTO service_request_items (
               tenant_id, request_id, catalogue_item_id, catalogue_item_key_snapshot, name_snapshot,
               category_snapshot, quantity, unit_one_off_cost, unit_monthly_cost, currency,
               selected_via, options_snapshot, product_snapshot
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb)`,
            [
              auth.session.tenant_id,
              request.id,
              item.databaseId,
              item.id,
              item.name,
              item.category,
              item.quantity,
              item.unitOneOffCost,
              item.unitMonthlyCost,
              item.currency,
              item.selectedVia,
              JSON.stringify(item.options),
              JSON.stringify(item.productSnapshot),
            ],
          )
        }

        if (approval) {
          const approver = approval.approver
          await client.query(
            `INSERT INTO service_request_approvals (
               tenant_id, request_id, sequence, label, status, approver_user_id, approver_person_id, approver_snapshot
             ) VALUES ($1,$2,1,$3,'Pending',$4,$5,$6::jsonb)`,
            [
              auth.session.tenant_id,
              request.id,
              approval.label,
              approver?.userId || null,
              approver?.personId || null,
              JSON.stringify({
                personId: approver?.externalKey || '',
                name: approver?.name || 'Unassigned approver',
                email: approver?.email || '',
              }),
            ],
          )
        }

        await client.query(
          `INSERT INTO service_request_tasks (
             tenant_id, request_id, external_key, title, status, team_id, team_snapshot, instructions
           ) VALUES ($1,$2,$3,'Review and fulfil request',$4,$5,$6::jsonb,$7)`,
          [
            auth.session.tenant_id,
            request.id,
            `${reference}-FULFIL`,
            approval ? 'Waiting' : 'Ready',
            teamId || null,
            JSON.stringify({ id: teamId || '', name: teamName }),
            'Review the submitted information, complete fulfilment actions and record the outcome.',
          ],
        )

        await client.query(
          `INSERT INTO service_request_activities (
             tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot, kind, visibility,
             body_text, attachments, metadata
           ) VALUES ($1,$2,$3,$4,$5::jsonb,'customer','customer',$6,$7::jsonb,$8::jsonb)`,
          [
            auth.session.tenant_id,
            request.id,
            auth.session.user_id,
            requester.person?.id || null,
            JSON.stringify({ name: auth.session.name, email: auth.session.email }),
            text(details.text || `Submitted ${form.title}.`, 20_000),
            JSON.stringify(safeAttachments(details.attachments)),
            JSON.stringify({ event: 'request.submitted', catalogueItemId: form.external_key, onBehalfOf: requester.snapshot.personId || null }),
          ],
        )

        return requestPayload(client, request)
      })

      return c.json(created, 201)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message }, error.status)
      throw error
    }
  })

  app.post('/api/v1/service-requests/:reference/approvals/:approvalId/decision', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }
    const decision = text(body?.decision, 20)
    if (!allowedDecisions.has(decision)) return c.json({ error: 'Decision must be Approved or Rejected.' }, 400)

    const row = await lookupRequest(auth.session.tenant_id, c.req.param('reference'))
    if (!row) return c.json({ error: 'Service Request not found.' }, 404)

    const approvalId = text(c.req.param('approvalId'), 80)
    const approvalResult = await pool.query(
      `SELECT * FROM service_request_approvals
       WHERE id::text = $1 AND tenant_id = $2 AND request_id = $3
       LIMIT 1`,
      [approvalId, auth.session.tenant_id, row.id],
    )
    if (!approvalResult.rowCount) return c.json({ error: 'Approval not found.' }, 404)
    const approval = approvalResult.rows[0]

    const requester = await requesterContext(pool, auth.session)
    const privileged = ['owner', 'admin'].includes(auth.session.tenant_role)
    const assigned = approval.approver_user_id === auth.session.user_id || approval.approver_person_id === requester.person?.id
    if (!privileged && !assigned) return c.json({ error: 'This approval is not assigned to you.' }, 403)
    if (approval.status !== 'Pending') return c.json({ error: 'This approval has already been decided.' }, 409)

    await withTransaction(async (client) => {
      await client.query(
        `UPDATE service_request_approvals
         SET status = $1, decision_note = $2, decided_at = now(), updated_at = now()
         WHERE id = $3`,
        [decision, text(body?.note, 5000), approval.id],
      )

      if (decision === 'Rejected') {
        await client.query(
          `UPDATE service_requests SET status = 'Rejected', updated_at = now() WHERE id = $1`,
          [row.id],
        )
      } else {
        const pending = await client.query(
          `SELECT 1 FROM service_request_approvals
           WHERE request_id = $1 AND id <> $2 AND status = 'Pending'
           LIMIT 1`,
          [row.id, approval.id],
        )
        if (!pending.rowCount) {
          await client.query(`UPDATE service_requests SET status = 'New', updated_at = now() WHERE id = $1`, [row.id])
          await client.query(`UPDATE service_request_tasks SET status = 'Ready', updated_at = now() WHERE request_id = $1 AND status = 'Waiting'`, [row.id])
        }
      }

      await client.query(
        `INSERT INTO service_request_activities (
           tenant_id, request_id, actor_user_id, actor_person_id, actor_snapshot, kind, visibility,
           body_text, metadata
         ) VALUES ($1,$2,$3,$4,$5::jsonb,'system','customer',$6,$7::jsonb)`,
        [
          auth.session.tenant_id,
          row.id,
          auth.session.user_id,
          requester.person?.id || null,
          JSON.stringify({ name: requester.snapshot.name, email: requester.snapshot.email }),
          `${requester.snapshot.name} ${decision.toLowerCase()} the approval${body?.note ? `: ${text(body.note, 1000)}` : '.'}`,
          JSON.stringify({ event: 'approval.decided', decision, approvalId: approval.id }),
        ],
      )
    })

    const refreshed = await lookupRequest(auth.session.tenant_id, row.reference)
    return c.json(await requestPayload(pool, refreshed))
  })
}
