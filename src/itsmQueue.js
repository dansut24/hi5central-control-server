import { pool } from './db.js'
import { registerItsmActionRoutes } from './itsmActions.js'
import { resolveSession } from './session.js'
import { originMatchesTenant } from './deploymentConfig.js'

const allowedTypes = new Set(['Incident', 'Service Request', 'Problem', 'Change'])

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireTechnician(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician access is required.' }, 403) }
  return { session }
}

export function registerItsmQueueRoutes(app) {
  app.get('/api/v1/itsm-queue', async (c) => {
    const auth = await requireTechnician(c)
    if (auth.error) return auth.error

    const recordType = text(c.req.query('type'), 40)
    if (recordType && !allowedTypes.has(recordType)) return c.json({ error: 'Invalid record type.' }, 400)
    const status = text(c.req.query('status'), 80)
    const priority = text(c.req.query('priority'), 40)
    const team = text(c.req.query('team'), 160)
    const assignee = text(c.req.query('assignee'), 180)
    const service = text(c.req.query('service'), 160)
    const search = text(c.req.query('search'), 240)
    const limit = Math.max(1, Math.min(100, Number(c.req.query('limit') || 25)))
    const offset = Math.max(0, Number(c.req.query('offset') || 0))

    const values = [auth.session.tenant_id]
    const filters = []
    const add = (expression, value) => {
      values.push(value)
      filters.push(expression.replace('?', `$${values.length}`))
    }
    if (recordType) add('record_type = ?', recordType)
    if (status && status !== 'All') add('status = ?', status)
    if (priority && priority !== 'All') add('priority = ?', priority)
    if (team && team !== 'All') add('team = ?', team)
    if (assignee && assignee !== 'All') add('assignee = ?', assignee)
    if (service && service !== 'All') add('service = ?', service)
    if (search) {
      values.push(`%${search.toLowerCase()}%`)
      const p = `$${values.length}`
      filters.push(`lower(reference || ' ' || title || ' ' || requester || ' ' || service || ' ' || team || ' ' || assignee || ' ' || status) LIKE ${p}`)
    }

    const filterSql = filters.length ? `WHERE ${filters.join(' AND ')}` : ''
    const baseSql = `
      WITH queue AS (
        SELECT
          r.reference,
          r.record_type,
          r.title,
          COALESCE(r.requester_snapshot->>'name','') AS requester,
          r.service,
          r.category,
          r.priority,
          r.status,
          COALESCE(r.assignment_team_snapshot->>'name','') AS team,
          COALESCE(r.assignee_snapshot->>'name','Unassigned') AS assignee,
          r.updated_at,
          r.created_at,
          r.record_data AS detail
        FROM itsm_records r
        WHERE r.tenant_id = $1

        UNION ALL

        SELECT
          s.reference,
          'Service Request'::text AS record_type,
          s.title,
          COALESCE(s.requester_snapshot->>'name','') AS requester,
          s.service,
          COALESCE(s.catalogue_item_title_snapshot,'') AS category,
          s.priority,
          s.status,
          COALESCE(s.fulfilment_team_snapshot->>'name','') AS team,
          COALESCE(p.name,'Unassigned') AS assignee,
          s.updated_at,
          s.created_at,
          jsonb_build_object(
            'oneOffCost', s.one_off_cost,
            'monthlyCost', s.monthly_cost,
            'currency', s.currency,
            'catalogueItemTitle', s.catalogue_item_title_snapshot,
            'source', s.source
          ) AS detail
        FROM service_requests s
        LEFT JOIN organisation_people p ON p.id = s.assigned_person_id
        WHERE s.tenant_id = $1
      )`

    const countResult = await pool.query(`${baseSql} SELECT count(*)::int AS total FROM queue ${filterSql}`, values)
    const queryValues = [...values, limit, offset]
    const rows = await pool.query(
      `${baseSql}
       SELECT * FROM queue ${filterSql}
       ORDER BY updated_at DESC, reference DESC
       LIMIT $${queryValues.length - 1} OFFSET $${queryValues.length}`,
      queryValues,
    )

    const options = await pool.query(
      `${baseSql}
       SELECT
         array_remove(array_agg(DISTINCT status), NULL) AS statuses,
         array_remove(array_agg(DISTINCT priority), NULL) AS priorities,
         array_remove(array_agg(DISTINCT team), NULL) AS teams,
         array_remove(array_agg(DISTINCT assignee), NULL) AS assignees,
         array_remove(array_agg(DISTINCT service), NULL) AS services
       FROM queue
       ${recordType ? 'WHERE record_type = $2' : ''}`,
      recordType ? [auth.session.tenant_id, recordType] : [auth.session.tenant_id],
    )

    return c.json({
      items: rows.rows.map((row) => ({
        id: row.reference,
        type: row.record_type,
        title: row.title,
        requester: row.requester,
        service: row.service,
        category: row.category,
        priority: row.priority,
        status: row.status,
        team: row.team,
        assignee: row.assignee,
        updatedAt: row.updated_at,
        createdAt: row.created_at,
        detail: row.detail || {},
      })),
      total: countResult.rows[0]?.total || 0,
      limit,
      offset,
      filters: {
        statuses: options.rows[0]?.statuses || [],
        priorities: options.rows[0]?.priorities || [],
        teams: options.rows[0]?.teams || [],
        assignees: options.rows[0]?.assignees || [],
        services: options.rows[0]?.services || [],
      },
    })
  })

  registerItsmActionRoutes(app)
}
