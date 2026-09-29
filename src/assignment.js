import { hasPermission, permissionMatches } from './access.js'
import { pool } from './db.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

const recordPermissions = {
  Incident: {
    view: ['itsm.records.view_all', 'itsm.incidents.view'],
    work: ['itsm.incidents.edit', 'itsm.incidents.resolve'],
  },
  'Service Request': {
    view: ['itsm.records.view_all', 'itsm.requests.view'],
    work: ['itsm.requests.edit', 'itsm.requests.fulfil', 'itsm.tasks.manage'],
  },
  Problem: {
    view: ['itsm.records.view_all', 'itsm.problems.view'],
    work: ['itsm.problems.edit', 'itsm.problems.resolve'],
  },
  Change: {
    view: ['itsm.records.view_all', 'itsm.changes.view'],
    work: ['itsm.changes.edit', 'itsm.changes.implement'],
  },
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value || {}, key)
}

function grantsPermission(grants = [], permission) {
  return grants.some((grant) => permissionMatches(String(grant || ''), permission))
}

function eligibleGrants(grants, recordType) {
  const rules = recordPermissions[recordType]
  if (!rules) return false
  if (!grantsPermission(grants, 'workspace.access')) return false
  const canView = rules.view.some((permission) => grantsPermission(grants, permission))
  const canWork = rules.work.some((permission) => grantsPermission(grants, permission))
  return canView && canWork
}

function sessionCanView(session, recordType) {
  const rules = recordPermissions[recordType]
  if (!rules) return false
  return rules.view.some((permission) => hasPermission(session.access, permission))
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireWorkspace(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, 'workspace.access')) {
    return { error: c.json({ error: 'Workspace access is required.' }, 403) }
  }
  return { session }
}

async function assignmentRows(db, tenantId) {
  const result = await db.query(
    `SELECT
       t.id AS team_database_id,
       t.external_key AS team_external_key,
       t.name AS team_name,
       p.id AS person_database_id,
       p.external_key AS person_external_key,
       p.user_id,
       p.name AS person_name,
       p.email AS person_email,
       p.job_title,
       p.availability,
       tm.role AS team_role,
       tm.is_primary,
       m.status AS membership_status,
       COALESCE(array_agg(DISTINCT permission_grant.permission) FILTER (WHERE permission_grant.permission IS NOT NULL), '{}'::text[]) AS permissions
     FROM organisation_teams t
     LEFT JOIN organisation_team_memberships tm
       ON tm.tenant_id = t.tenant_id AND tm.team_id = t.id
     LEFT JOIN organisation_people p
       ON p.tenant_id = t.tenant_id AND p.id = tm.person_id AND p.active = true AND p.user_id IS NOT NULL
     LEFT JOIN tenant_memberships m
       ON m.tenant_id = t.tenant_id AND m.user_id = p.user_id
     LEFT JOIN access_user_roles aur
       ON aur.tenant_id = t.tenant_id AND aur.user_id = p.user_id
     LEFT JOIN access_roles ar
       ON ar.tenant_id = t.tenant_id AND ar.id = aur.role_id AND ar.active = true
     LEFT JOIN LATERAL unnest(ar.permissions) AS permission_grant(permission) ON true
     WHERE t.tenant_id = $1 AND t.active = true
     GROUP BY
       t.id,t.external_key,t.name,
       p.id,p.external_key,p.user_id,p.name,p.email,p.job_title,p.availability,
       tm.role,tm.is_primary,m.status
     ORDER BY t.name,p.name`,
    [tenantId],
  )
  return result.rows
}

export async function assignmentDirectory(db, tenantId, recordType) {
  const rows = await assignmentRows(db, tenantId)
  const teams = []
  const byTeam = new Map()
  const people = new Map()

  for (const row of rows) {
    let team = byTeam.get(row.team_database_id)
    if (!team) {
      team = {
        id: row.team_external_key,
        databaseId: row.team_database_id,
        name: row.team_name,
        members: [],
      }
      byTeam.set(row.team_database_id, team)
      teams.push(team)
    }

    if (!row.person_database_id || row.membership_status !== 'active') continue
    const grants = Array.isArray(row.permissions) ? row.permissions : []
    if (!eligibleGrants(grants, recordType)) continue

    const person = {
      id: row.person_external_key,
      databaseId: row.person_database_id,
      userId: row.user_id,
      name: row.person_name,
      email: row.person_email,
      jobTitle: row.job_title || '',
      availability: row.availability || 'Available',
      teamRole: row.team_role || 'member',
      isPrimary: Boolean(row.is_primary),
    }
    team.members.push(person)
    if (!people.has(row.person_database_id)) people.set(row.person_database_id, person)
  }

  return { recordType, teams, people: [...people.values()] }
}

async function teamByValue(db, tenantId, value) {
  const query = text(value, 180)
  if (!query) return null
  const result = await db.query(
    `SELECT id,external_key,name
     FROM organisation_teams
     WHERE tenant_id=$1 AND active=true
       AND (id::text=$2 OR external_key=$2 OR lower(name)=lower($2))
     LIMIT 1`,
    [tenantId, query],
  )
  return result.rows[0] || null
}

async function personByValue(db, tenantId, value) {
  const query = text(value, 254)
  if (!query || query === 'Unassigned') return null
  const result = await db.query(
    `SELECT p.id,p.external_key,p.user_id,p.name,p.email,p.job_title,p.availability,m.role AS legacy_role,m.status AS membership_status
     FROM organisation_people p
     LEFT JOIN tenant_memberships m ON m.tenant_id=p.tenant_id AND m.user_id=p.user_id
     WHERE p.tenant_id=$1 AND p.active=true
       AND (p.id::text=$2 OR p.external_key=$2 OR lower(p.name)=lower($2) OR lower(p.email)=lower($2))
     LIMIT 1`,
    [tenantId, query],
  )
  return result.rows[0] || null
}

async function grantsForUser(db, tenantId, userId) {
  if (!userId) return []
  const result = await db.query(
    `SELECT DISTINCT permission_grant.permission
     FROM access_user_roles aur
     JOIN access_roles ar ON ar.tenant_id=aur.tenant_id AND ar.id=aur.role_id AND ar.active=true
     CROSS JOIN LATERAL unnest(ar.permissions) AS permission_grant(permission)
     WHERE aur.tenant_id=$1 AND aur.user_id=$2`,
    [tenantId, userId],
  )
  return result.rows.map((row) => row.permission)
}

async function personIsMember(db, tenantId, personId, teamId) {
  const result = await db.query(
    `SELECT 1
     FROM organisation_team_memberships
     WHERE tenant_id=$1 AND person_id=$2 AND team_id=$3
     LIMIT 1`,
    [tenantId, personId, teamId],
  )
  return result.rowCount > 0
}

async function validateAssignee(db, tenantId, recordType, team, person) {
  if (!person) return null
  if (!team) {
    const error = new Error('Choose an assignment team before selecting an assignee.')
    error.status = 400
    throw error
  }
  if (!person.user_id || person.membership_status !== 'active') {
    const error = new Error('The selected person is not an active Hi5Central workspace user.')
    error.status = 422
    throw error
  }
  if (!(await personIsMember(db, tenantId, person.id, team.id))) {
    const error = new Error(`${person.name} is not a member of ${team.name}. Choose a member of the selected team.`)
    error.status = 422
    throw error
  }
  const grants = await grantsForUser(db, tenantId, person.user_id)
  if (!eligibleGrants(grants, recordType)) {
    const error = new Error(`${person.name} does not have the workspace permissions required to work ${recordType} records.`)
    error.status = 422
    throw error
  }
  return person
}

async function currentGeneric(db, tenantId, reference) {
  const result = await db.query(
    `SELECT assignment_team_id AS team_id,assigned_person_id AS person_id,record_type,version
     FROM itsm_records
     WHERE tenant_id=$1 AND upper(reference)=upper($2)
     LIMIT 1`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

async function currentRequest(db, tenantId, reference) {
  const result = await db.query(
    `SELECT fulfilment_team_id AS team_id,assigned_person_id AS person_id,'Service Request'::text AS record_type,id
     FROM service_requests
     WHERE tenant_id=$1 AND upper(reference)=upper($2)
     LIMIT 1`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

async function currentTask(db, tenantId, reference, taskKey) {
  const request = await currentRequest(db, tenantId, reference)
  if (!request) return null
  const result = await db.query(
    `SELECT team_id,assignee_person_id AS person_id,'Service Request'::text AS record_type
     FROM service_request_tasks
     WHERE tenant_id=$1 AND request_id=$2 AND external_key=$3
     LIMIT 1`,
    [tenantId, request.id, text(taskKey, 160)],
  )
  return result.rows[0] || null
}

async function currentTeam(db, tenantId, teamId) {
  if (!teamId) return null
  const result = await db.query(
    `SELECT id,external_key,name FROM organisation_teams WHERE tenant_id=$1 AND id=$2 AND active=true LIMIT 1`,
    [tenantId, teamId],
  )
  return result.rows[0] || null
}

async function currentPerson(db, tenantId, personId) {
  if (!personId) return null
  const result = await db.query(
    `SELECT p.id,p.external_key,p.user_id,p.name,p.email,p.job_title,p.availability,m.role AS legacy_role,m.status AS membership_status
     FROM organisation_people p
     LEFT JOIN tenant_memberships m ON m.tenant_id=p.tenant_id AND m.user_id=p.user_id
     WHERE p.tenant_id=$1 AND p.id=$2 AND p.active=true
     LIMIT 1`,
    [tenantId, personId],
  )
  return result.rows[0] || null
}

async function validateAssignmentMutation(db, tenantId, recordType, current, body) {
  const teamChanged = hasOwn(body, 'team') || hasOwn(body, 'teamId')
  const assigneeChanged = hasOwn(body, 'assignee') || hasOwn(body, 'assigneeId')
  if (!teamChanged && !assigneeChanged) return

  const teamValue = body.teamId ?? body.team
  const assigneeValue = body.assigneeId ?? body.assignee
  const team = teamChanged ? await teamByValue(db, tenantId, teamValue) : await currentTeam(db, tenantId, current?.team_id)
  if (teamChanged && text(teamValue) && !team) {
    const error = new Error('Choose an active assignment team from this tenant.')
    error.status = 400
    throw error
  }

  const person = assigneeChanged ? await personByValue(db, tenantId, assigneeValue) : await currentPerson(db, tenantId, current?.person_id)
  if (assigneeChanged && text(assigneeValue) && text(assigneeValue) !== 'Unassigned' && !person) {
    const error = new Error('Choose an active assignee from this tenant.')
    error.status = 400
    throw error
  }

  if (person) {
    try {
      await validateAssignee(db, tenantId, recordType, team, person)
    } catch (error) {
      if (teamChanged && !assigneeChanged && error.status === 422) {
        error.status = 409
        error.message = `${error.message} Choose a new assignee or set the record to Unassigned when changing team.`
      }
      throw error
    }
  }
}

function responseHeaders(response) {
  const headers = new Headers(response.headers)
  headers.set('content-type', 'application/json; charset=UTF-8')
  headers.delete('content-length')
  return headers
}

async function enrichLifecycleResponse(c, session) {
  if (!c.res || c.res.status < 200 || c.res.status >= 300) return
  const contentType = c.res.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) return
  let payload
  try { payload = await c.res.clone().json() } catch { return }
  if (!payload?.type || !recordPermissions[payload.type]) return
  const directory = await assignmentDirectory(pool, session.tenant_id, payload.type)
  payload.options = {
    ...object(payload.options),
    assignmentPeople: directory.people,
    assignmentTeams: directory.teams,
  }
  c.res = new Response(JSON.stringify(payload), {
    status: c.res.status,
    statusText: c.res.statusText,
    headers: responseHeaders(c.res),
  })
}

function versionMatches(current, body) {
  const supplied = Number(body?.version)
  if (!Number.isInteger(supplied) || !Number.isInteger(Number(current?.version))) return true
  return supplied === Number(current.version)
}

async function requestBodyClone(c) {
  try { return await c.req.raw.clone().json() } catch { return null }
}

export function registerAssignmentRoutes(app) {
  app.get('/api/v1/assignment/options', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const recordType = text(c.req.query('recordType'), 80)
    if (!recordPermissions[recordType]) return c.json({ error: 'Choose a supported record type.' }, 400)
    if (!sessionCanView(auth.session, recordType)) return c.json({ error: `You do not have permission to view ${recordType} records.` }, 403)
    return c.json(await assignmentDirectory(pool, auth.session.tenant_id, recordType))
  })

  app.get('/api/v1/assignment/queue', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const requestedType = text(c.req.query('recordType'), 80)
    if (requestedType && !recordPermissions[requestedType]) return c.json({ error: 'Choose a supported record type.' }, 400)
    const allowedTypes = Object.keys(recordPermissions).filter((type) => sessionCanView(auth.session, type))
    if (requestedType && !allowedTypes.includes(requestedType)) return c.json({ error: `You do not have permission to view ${requestedType} records.` }, 403)
    const recordTypes = requestedType ? [requestedType] : allowedTypes
    const scope = ['all', 'my', 'team', 'unassigned'].includes(c.req.query('scope')) ? c.req.query('scope') : 'all'

    const personResult = await pool.query(
      `SELECT id FROM organisation_people WHERE tenant_id=$1 AND user_id=$2 AND active=true LIMIT 1`,
      [auth.session.tenant_id, auth.session.user_id],
    )
    const personId = personResult.rows[0]?.id || null
    const teamResult = personId
      ? await pool.query(`SELECT team_id FROM organisation_team_memberships WHERE tenant_id=$1 AND person_id=$2`, [auth.session.tenant_id, personId])
      : { rows: [] }
    const teamIds = teamResult.rows.map((row) => row.team_id)

    const result = await pool.query(
      `WITH work AS (
         SELECT r.reference,r.record_type,r.title,r.status,r.priority,
                r.assignment_team_id AS team_id,COALESCE(r.assignment_team_snapshot->>'name','') AS team,
                r.assigned_person_id AS person_id,COALESCE(r.assignee_snapshot->>'name','Unassigned') AS assignee,
                r.updated_at
         FROM itsm_records r
         WHERE r.tenant_id=$1
         UNION ALL
         SELECT s.reference,'Service Request'::text,s.title,s.status,s.priority,
                s.fulfilment_team_id AS team_id,COALESCE(s.fulfilment_team_snapshot->>'name','') AS team,
                s.assigned_person_id AS person_id,COALESCE(p.name,'Unassigned') AS assignee,
                s.updated_at
         FROM service_requests s
         LEFT JOIN organisation_people p ON p.tenant_id=s.tenant_id AND p.id=s.assigned_person_id
         WHERE s.tenant_id=$1
       )
       SELECT * FROM work
       WHERE record_type=ANY($2::text[])
         AND (
           $3='all'
           OR ($3='my' AND $4::uuid IS NOT NULL AND person_id=$4::uuid)
           OR ($3='team' AND cardinality($5::uuid[]) > 0 AND team_id=ANY($5::uuid[]))
           OR ($3='unassigned' AND person_id IS NULL)
         )
       ORDER BY updated_at DESC
       LIMIT 500`,
      [auth.session.tenant_id, recordTypes, scope, personId, teamIds],
    )

    return c.json({
      scope,
      recordTypes,
      viewer: { personId, teamIds },
      items: result.rows.map((row) => ({
        reference: row.reference,
        type: row.record_type,
        title: row.title,
        status: row.status,
        priority: row.priority,
        team: row.team,
        assignee: row.assignee,
        updatedAt: row.updated_at,
      })),
    })
  })

  app.use('/api/v1/itsm-lifecycle/*', async (c, next) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    if (c.req.method === 'PATCH') {
      const body = await requestBodyClone(c)
      if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
      const reference = c.req.path.match(/\/itsm-lifecycle\/([^/]+)\/?$/i)?.[1]
      const current = reference ? await currentGeneric(pool, auth.session.tenant_id, decodeURIComponent(reference)) : null
      if (current && versionMatches(current, body)) {
        try { await validateAssignmentMutation(pool, auth.session.tenant_id, current.record_type, current, body) }
        catch (error) { return c.json({ error: error.message }, error.status || 400) }
      }
    }
    await next()
    await enrichLifecycleResponse(c, auth.session)
  })

  app.use('/api/v1/itsm-actions/*', async (c, next) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    if (c.req.method === 'POST' && /\/reassign\/?$/i.test(c.req.path)) {
      const body = await requestBodyClone(c)
      if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
      const match = c.req.path.match(/\/itsm-actions\/([^/]+)\/reassign\/?$/i)
      const current = match ? await currentGeneric(pool, auth.session.tenant_id, decodeURIComponent(match[1])) : null
      if (current && versionMatches(current, body)) {
        try { await validateAssignmentMutation(pool, auth.session.tenant_id, current.record_type, current, body) }
        catch (error) { return c.json({ error: error.message }, error.status || 400) }
      }
    }
    await next()
  })

  app.use('/api/v1/service-requests/*', async (c, next) => {
    if (c.req.method !== 'PATCH') return next()
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const body = await requestBodyClone(c)
    if (!body) return c.json({ error: 'A valid JSON request body is required.' }, 400)
    const taskMatch = c.req.path.match(/\/service-requests\/([^/]+)\/tasks\/([^/]+)\/?$/i)
    const requestMatch = c.req.path.match(/\/service-requests\/([^/]+)\/?$/i)
    const current = taskMatch
      ? await currentTask(pool, auth.session.tenant_id, decodeURIComponent(taskMatch[1]), decodeURIComponent(taskMatch[2]))
      : requestMatch
        ? await currentRequest(pool, auth.session.tenant_id, decodeURIComponent(requestMatch[1]))
        : null
    if (current) {
      try { await validateAssignmentMutation(pool, auth.session.tenant_id, 'Service Request', current, body) }
      catch (error) { return c.json({ error: error.message }, error.status || 400) }
    }
    await next()
  })
}
