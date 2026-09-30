import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { resolveSession } from './session.js'

const recordTypes = new Set(['All', 'Incident', 'Service Request', 'Problem', 'Change'])
function clean(value = '', max = 255) { return String(value ?? '').trim().slice(0, max) }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }

async function requireWorkspace(c, permission = '') {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician access is required.' }, 403) }
  if (permission && !hasPermission(session.access, permission)) {
    return { error: c.json({ error: 'You do not have permission to access this resource.' }, 403) }
  }
  return { session }
}

function savedViewAccess(session) {
  return ['itsm.records.view_all','itsm.incidents.view','itsm.requests.view','itsm.problems.view','itsm.changes.view']
    .some((permission) => hasPermission(session.access, permission))
}

function savedViewRow(row, userId) {
  return {
    id: row.id, name: row.name, recordType: row.record_type,
    visibility: row.visibility, owner: row.owner_user_id === userId ? 'You' : (row.owner_email || 'Technician'),
    query: row.query || '', filters: object(row.filters), viewStyle: row.view_style || 'table',
    columns: object(row.columns), createdAt: row.created_at, updatedAt: row.updated_at,
  }
}

export function registerItsmInsightRoutes(app) {
  app.get('/api/v1/itsm/saved-views', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    if (!savedViewAccess(auth.session)) return c.json({ error: 'You do not have permission to view ITSM queues.' }, 403)
    const recordType = clean(c.req.query('type'), 40)
    if (recordType && !recordTypes.has(recordType)) return c.json({ error: 'Invalid record type.' }, 400)
    const params = [auth.session.tenant_id, auth.session.user_id]
    let typeSql = ''
    if (recordType) { params.push(recordType); typeSql = ` AND v.record_type=$${params.length}` }
    const result = await pool.query(
      `SELECT v.*,u.email owner_email FROM itsm_saved_views v LEFT JOIN users u ON u.id=v.owner_user_id
       WHERE v.tenant_id=$1 AND (v.owner_user_id=$2 OR v.visibility='shared')${typeSql}
       ORDER BY CASE WHEN v.owner_user_id=$2 THEN 0 ELSE 1 END, lower(v.name)`,
      params,
    )
    return c.json({ items: result.rows.map((row) => savedViewRow(row, auth.session.user_id)) })
  })

  app.post('/api/v1/itsm/saved-views', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    if (!savedViewAccess(auth.session)) return c.json({ error: 'You do not have permission to save ITSM views.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const recordType = clean(body?.recordType, 40)
    const name = clean(body?.name, 80)
    const visibility = body?.visibility === 'shared' ? 'shared' : 'private'
    if (!recordTypes.has(recordType)) return c.json({ error: 'Invalid record type.' }, 400)
    if (!name) return c.json({ error: 'Saved view name is required.' }, 400)
    if (visibility === 'shared' && !hasPermission(auth.session.access, 'reports.manage')) {
      return c.json({ error: 'You do not have permission to create shared views.' }, 403)
    }
    const result = await pool.query(
      `INSERT INTO itsm_saved_views(tenant_id,owner_user_id,record_type,name,visibility,query,filters,view_style,columns)
       VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb)
       ON CONFLICT (tenant_id,owner_user_id,record_type,lower(name))
       DO UPDATE SET visibility=EXCLUDED.visibility,query=EXCLUDED.query,filters=EXCLUDED.filters,
         view_style=EXCLUDED.view_style,columns=EXCLUDED.columns,updated_at=now()
       RETURNING *`,
      [auth.session.tenant_id, auth.session.user_id, recordType, name, visibility,
       clean(body?.query, 240), JSON.stringify(object(body?.filters)),
       ['table','compact','cards'].includes(body?.viewStyle) ? body.viewStyle : 'table',
       JSON.stringify(object(body?.columns))],
    )
    return c.json(savedViewRow(result.rows[0], auth.session.user_id), 201)
  })
  app.delete('/api/v1/itsm/saved-views/:viewId', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      'DELETE FROM itsm_saved_views WHERE id=$1 AND tenant_id=$2 AND owner_user_id=$3 RETURNING id',
      [c.req.param('viewId'), auth.session.tenant_id, auth.session.user_id],
    )
    if (!result.rowCount) return c.json({ error: 'Saved view not found or not owned by you.' }, 404)
    return c.json({ deleted: true })
  })

  app.get('/api/v1/itsm/reports/summary', async (c) => {
    const auth = await requireWorkspace(c, 'reports.view')
    if (auth.error) return auth.error
    const result = await pool.query(
      `WITH records AS (
         SELECT record_type,type_ref.reference,status,priority,created_at,first_response_at,response_due_at,
                resolution_due_at,resolved_at,
                COALESCE(assignment_team_snapshot->>'name','Unassigned') team,
                COALESCE(assignee_snapshot->>'name','Unassigned') assignee
           FROM itsm_records type_ref WHERE tenant_id=$1
         UNION ALL
         SELECT 'Service Request',s.reference,s.status,s.priority,s.created_at,s.first_response_at,s.response_due_at,
                s.resolution_due_at,s.resolved_at,
                COALESCE(s.fulfilment_team_snapshot->>'name','Unassigned'),
                COALESCE(p.name,'Unassigned')
           FROM service_requests s
           LEFT JOIN organisation_people p ON p.id=s.assigned_person_id
           WHERE s.tenant_id=$1
       )
       SELECT
         count(*)::int total,
         count(*) FILTER (WHERE status NOT IN ('Resolved','Closed','Completed','Complete','Cancelled'))::int open,
         count(*) FILTER (WHERE resolved_at IS NOT NULL OR status IN ('Resolved','Closed','Completed','Complete'))::int resolved,
         count(*) FILTER (WHERE resolution_due_at IS NOT NULL AND resolved_at IS NOT NULL AND resolved_at<=resolution_due_at)::int sla_met,
         count(*) FILTER (WHERE resolution_due_at IS NOT NULL AND COALESCE(resolved_at,now())>resolution_due_at)::int sla_breached,
         count(*) FILTER (WHERE response_due_at IS NOT NULL AND COALESCE(first_response_at,now())>response_due_at)::int response_breached
       FROM records`,
      [auth.session.tenant_id],
    )
    const [types, statuses, priorities, workload, trend] = await Promise.all([
      pool.query(`WITH q AS (
        SELECT record_type type FROM itsm_records WHERE tenant_id=$1
        UNION ALL SELECT 'Service Request' FROM service_requests WHERE tenant_id=$1)
        SELECT type,count(*)::int count FROM q GROUP BY type ORDER BY type`, [auth.session.tenant_id]),
      pool.query(`WITH q AS (
        SELECT status FROM itsm_records WHERE tenant_id=$1
        UNION ALL SELECT status FROM service_requests WHERE tenant_id=$1)
        SELECT status,count(*)::int count FROM q GROUP BY status ORDER BY count DESC,status`, [auth.session.tenant_id]),
      pool.query(`WITH q AS (
        SELECT priority FROM itsm_records WHERE tenant_id=$1
        UNION ALL SELECT priority FROM service_requests WHERE tenant_id=$1)
        SELECT priority,count(*)::int count FROM q GROUP BY priority ORDER BY count DESC,priority`, [auth.session.tenant_id]),
      pool.query(`WITH q AS (
        SELECT COALESCE(assignee_snapshot->>'name','Unassigned') assignee,status FROM itsm_records WHERE tenant_id=$1
        UNION ALL
        SELECT COALESCE(p.name,'Unassigned'),s.status FROM service_requests s
        LEFT JOIN organisation_people p ON p.id=s.assigned_person_id WHERE s.tenant_id=$1)
        SELECT assignee,count(*) FILTER (WHERE status NOT IN ('Resolved','Closed','Completed','Complete','Cancelled'))::int open
        FROM q GROUP BY assignee ORDER BY open DESC,assignee LIMIT 12`, [auth.session.tenant_id]),
      pool.query(`WITH q AS (
        SELECT created_at FROM itsm_records WHERE tenant_id=$1
        UNION ALL SELECT created_at FROM service_requests WHERE tenant_id=$1)
        SELECT to_char(date_trunc('day',created_at),'YYYY-MM-DD') AS "day",count(*)::int count
        FROM q WHERE created_at>=now()-interval '29 days' GROUP BY 1 ORDER BY 1`, [auth.session.tenant_id]),
    ])
    const row = result.rows[0] || {}
    return c.json({
      total: row.total || 0, open: row.open || 0, resolved: row.resolved || 0,
      sla: { met: row.sla_met || 0, breached: row.sla_breached || 0, responseBreached: row.response_breached || 0 },
      byType: Object.fromEntries(types.rows.map((item) => [item.type, item.count])),
      byStatus: Object.fromEntries(statuses.rows.map((item) => [item.status, item.count])),
      byPriority: Object.fromEntries(priorities.rows.map((item) => [item.priority, item.count])),
      workload: workload.rows, trend: trend.rows,
    })
  })
}