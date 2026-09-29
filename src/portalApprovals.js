import { hasPermission } from './access.js'
import { pool } from './db.js'
import { originMatchesPortalTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function portalOrigin(c, slug) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), slug)
}

async function personIdForUser(db, tenantId, userId) {
  const result = await db.query(
    `SELECT id
     FROM organisation_people
     WHERE tenant_id = $1 AND user_id = $2 AND active = true
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0]?.id || null
}

export async function hasAssignedPortalApproval(db, tenantId, userId) {
  if (!tenantId || !userId) return false
  const personId = await personIdForUser(db, tenantId, userId)
  const result = await db.query(
    `SELECT 1
     FROM service_request_approvals a
     WHERE a.tenant_id = $1
       AND (a.approver_user_id = $2 OR ($3::uuid IS NOT NULL AND a.approver_person_id = $3::uuid))
     LIMIT 1`,
    [tenantId, userId, personId],
  )
  return result.rowCount > 0
}

export async function portalApprovalCapabilities(session, db = pool) {
  const requestAccess = hasPermission(session?.access, 'portal.access')
  const explicitApprovalAccess = hasPermission(session?.access, 'portal.approvals.view')
  const assignedApprovalAccess = await hasAssignedPortalApproval(db, session?.tenant_id, session?.user_id)
  return {
    requests: requestAccess,
    approvals: explicitApprovalAccess || assignedApprovalAccess,
  }
}

async function requirePortalApprovalSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!portalOrigin(c, session.slug)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (!session.onboarding_completed_at) return { error: c.json({ error: 'This tenant has not completed setup.' }, 403) }
  const capabilities = await portalApprovalCapabilities(session)
  if (!capabilities.approvals) return { error: c.json({ error: 'You do not have any approval access in this Portal.' }, 403) }
  const personId = await personIdForUser(pool, session.tenant_id, session.user_id)
  return { session, capabilities, personId }
}

function approvalListItem(row) {
  return {
    id: row.approval_id,
    label: row.approval_label,
    status: row.approval_status,
    decisionNote: row.decision_note || '',
    decidedAt: row.decided_at,
    createdAt: row.approval_created_at,
    updatedAt: row.approval_updated_at,
    request: {
      reference: row.reference,
      title: row.title,
      service: row.service,
      priority: row.priority,
      status: row.request_status,
      requester: asObject(row.requester_snapshot).name || '',
      requesterEmail: asObject(row.requester_snapshot).email || '',
      oneOffCost: Number(row.one_off_cost || 0),
      monthlyCost: Number(row.monthly_cost || 0),
      currency: row.currency || 'GBP',
      createdAt: row.request_created_at,
      updatedAt: row.request_updated_at,
    },
  }
}

async function assignedApproval(db, tenantId, userId, personId, approvalId) {
  const result = await db.query(
    `SELECT
       a.id AS approval_id,
       a.label AS approval_label,
       a.status AS approval_status,
       a.decision_note,
       a.decided_at,
       a.created_at AS approval_created_at,
       a.updated_at AS approval_updated_at,
       r.*,
       r.status AS request_status,
       r.created_at AS request_created_at,
       r.updated_at AS request_updated_at
     FROM service_request_approvals a
     JOIN service_requests r ON r.id = a.request_id AND r.tenant_id = a.tenant_id
     WHERE a.tenant_id = $1
       AND a.id::text = $4
       AND (a.approver_user_id = $2 OR ($3::uuid IS NOT NULL AND a.approver_person_id = $3::uuid))
     LIMIT 1`,
    [tenantId, userId, personId, text(approvalId, 80)],
  )
  return result.rows[0] || null
}

export function registerPortalApprovalRoutes(app) {
  app.get('/api/v1/portal/approvals', async (c) => {
    const auth = await requirePortalApprovalSession(c)
    if (auth.error) return auth.error

    const status = text(c.req.query('status'), 40)
    const values = [auth.session.tenant_id, auth.session.user_id, auth.personId]
    let statusClause = ''
    if (status && status !== 'All') {
      values.push(status)
      statusClause = `AND a.status = $${values.length}`
    }

    const result = await pool.query(
      `SELECT
         a.id AS approval_id,
         a.label AS approval_label,
         a.status AS approval_status,
         a.decision_note,
         a.decided_at,
         a.created_at AS approval_created_at,
         a.updated_at AS approval_updated_at,
         r.reference,
         r.title,
         r.service,
         r.priority,
         r.status AS request_status,
         r.requester_snapshot,
         r.one_off_cost,
         r.monthly_cost,
         r.currency,
         r.created_at AS request_created_at,
         r.updated_at AS request_updated_at
       FROM service_request_approvals a
       JOIN service_requests r ON r.id = a.request_id AND r.tenant_id = a.tenant_id
       WHERE a.tenant_id = $1
         AND (a.approver_user_id = $2 OR ($3::uuid IS NOT NULL AND a.approver_person_id = $3::uuid))
         ${statusClause}
       ORDER BY CASE a.status WHEN 'Pending' THEN 0 ELSE 1 END, a.updated_at DESC
       LIMIT 200`,
      values,
    )

    return c.json({ items: result.rows.map(approvalListItem) })
  })

  app.get('/api/v1/portal/approvals/:approvalId', async (c) => {
    const auth = await requirePortalApprovalSession(c)
    if (auth.error) return auth.error
    const row = await assignedApproval(
      pool,
      auth.session.tenant_id,
      auth.session.user_id,
      auth.personId,
      c.req.param('approvalId'),
    )
    if (!row) return c.json({ error: 'Approval not found.' }, 404)

    const items = await pool.query(
      `SELECT catalogue_item_key_snapshot, name_snapshot, category_snapshot, quantity,
              unit_one_off_cost, unit_monthly_cost, currency, options_snapshot
       FROM service_request_items
       WHERE request_id = $1
       ORDER BY created_at, id`,
      [row.id],
    )

    return c.json({
      ...approvalListItem(row),
      canDecide: row.approval_status === 'Pending',
      request: {
        ...approvalListItem(row).request,
        description: row.description || '',
        requestInformation: asArray(row.request_information),
        submittedFields: asObject(row.submitted_fields),
        items: items.rows.map((item) => ({
          id: item.catalogue_item_key_snapshot,
          name: item.name_snapshot,
          category: item.category_snapshot,
          quantity: Number(item.quantity || 1),
          unitOneOffCost: Number(item.unit_one_off_cost || 0),
          unitMonthlyCost: Number(item.unit_monthly_cost || 0),
          currency: item.currency || row.currency || 'GBP',
          options: asArray(item.options_snapshot),
        })),
      },
    })
  })
}
