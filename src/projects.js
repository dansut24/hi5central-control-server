import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { resolveSession } from './session.js'

const projectStatuses = new Set(['Planned', 'In Progress', 'On Hold', 'Complete', 'Cancelled'])
const projectHealth = new Set(['On Track', 'At Risk', 'Blocked', 'Complete'])
const priorities = new Set(['Low', 'Medium', 'High', 'Critical'])
const taskStatuses = new Set(['Backlog', 'To Do', 'In Progress', 'Blocked', 'Done'])
const milestoneStatuses = new Set(['Planned', 'In Progress', 'Complete'])
const riskStatuses = new Set(['Open', 'Mitigating', 'Closed'])
const riskKinds = new Set(['Risk', 'Issue'])
const defaultProjectTargetDays = { Critical: 14, High: 30, Medium: 60, Low: 90 }

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function array(value) {
  return Array.isArray(value) ? value : []
}

function dateText(value) {
  if (!value) return null
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString().slice(0, 10)
  const raw = String(value).trim()
  const matched = raw.match(/^\d{4}-\d{2}-\d{2}/)
  if (matched) return matched[0]
  const parsed = new Date(raw)
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString().slice(0, 10)
}

function dateValue(value) {
  const normalised = dateText(value)
  if (!normalised) return null
  const parsed = new Date(`${normalised}T12:00:00Z`)
  return Number.isNaN(parsed.getTime()) ? null : normalised
}

function plusDays(value, days) {
  const normalised = dateText(value)
  const start = normalised ? new Date(`${normalised}T12:00:00Z`) : new Date()
  start.setUTCDate(start.getUTCDate() + Number(days || 0))
  return start.toISOString().slice(0, 10)
}

function personSnapshot(person) {
  if (!person) return {}
  return {
    id: person.id,
    externalKey: person.external_key,
    name: person.name,
    email: person.email,
    userId: person.user_id,
  }
}

function teamSnapshot(team) {
  if (!team) return {}
  return { id: team.id, externalKey: team.external_key, name: team.name }
}

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireProjectPermission(c, permission) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, permission)) {
    return { error: c.json({ error: 'You do not have permission to manage projects.', permission }, 403) }
  }
  return { session }
}

async function actorContext(db, session) {
  const result = await db.query(
    `SELECT p.* FROM organisation_people p
     WHERE p.tenant_id=$1 AND p.user_id=$2 LIMIT 1`,
    [session.tenant_id, session.user_id],
  )
  const person = result.rows[0] || null
  return {
    person,
    snapshot: personSnapshot(person) || {
      name: session.name,
      email: session.email,
      userId: session.user_id,
    },
  }
}

async function activeTechnician(db, tenantId, key) {
  const value = text(key, 180)
  if (!value) return null
  const result = await db.query(
    `SELECT p.*,m.role tenant_role,m.status membership_status
     FROM organisation_people p
     JOIN tenant_memberships m ON m.tenant_id=p.tenant_id AND m.user_id=p.user_id
     WHERE p.tenant_id=$1 AND p.active=true AND m.status='active' AND m.role<>'requester'
       AND (p.external_key=$2 OR lower(p.email)=lower($2) OR lower(p.name)=lower($2))
     ORDER BY CASE WHEN p.external_key=$2 THEN 0 WHEN lower(p.email)=lower($2) THEN 1 ELSE 2 END
     LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

async function activeTeam(db, tenantId, key) {
  const value = text(key, 160)
  if (!value) return null
  const result = await db.query(
    `SELECT * FROM organisation_teams
     WHERE tenant_id=$1 AND active=true
       AND (external_key=$2 OR lower(name)=lower($2))
     LIMIT 1`,
    [tenantId, value],
  )
  return result.rows[0] || null
}

async function projectFor(db, tenantId, reference, lock = false) {
  const result = await db.query(
    `SELECT * FROM projects
     WHERE tenant_id=$1 AND upper(reference)=upper($2)
     LIMIT 1${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, text(reference, 80)],
  )
  return result.rows[0] || null
}

async function nextProjectReference(db, tenantId) {
  const result = await db.query(
    `INSERT INTO project_reference_sequences(tenant_id,next_value)
     VALUES($1,2)
     ON CONFLICT(tenant_id) DO UPDATE
       SET next_value=project_reference_sequences.next_value+1
     RETURNING next_value-1 AS value`,
    [tenantId],
  )
  return `PRJ-${String(result.rows[0].value).padStart(5, '0')}`
}

async function configurationFor(db, tenantId) {
  const result = await db.query(
    'SELECT configuration,onboarding_data FROM tenant_settings WHERE tenant_id=$1 LIMIT 1',
    [tenantId],
  )
  const row = result.rows[0] || {}
  return row.configuration && Object.keys(row.configuration).length ? row.configuration : (row.onboarding_data || {})
}

function projectTargetDays(priority, configuration) {
  const configured = Number(object(object(object(configuration).itsm).projectSlaTargets?.[priority])?.targetDays)
  return Number.isFinite(configured) && configured > 0 && configured <= 3650
    ? configured
    : defaultProjectTargetDays[priority] || defaultProjectTargetDays.Medium
}

function deadlineDateMs(value, endOfDay = false) {
  if (!value) return Number.NaN
  if (value instanceof Date) {
    const copy = new Date(value)
    if (endOfDay) copy.setUTCHours(23, 59, 59, 999)
    else copy.setUTCHours(0, 0, 0, 0)
    return copy.getTime()
  }
  const date = String(value).slice(0, 10)
  return new Date(`${date}T${endOfDay ? '23:59:59.999' : '00:00:00'}Z`).getTime()
}

function deadlineMetric(startDate, targetDate, completedAt, status) {
  if (!targetDate) return null
  const start = deadlineDateMs(startDate || targetDate)
  const due = deadlineDateMs(targetDate, true)
  if (!Number.isFinite(start) || !Number.isFinite(due)) return null
  const end = completedAt ? new Date(completedAt).getTime() : Date.now()
  const total = Math.max(1, due - start)
  const elapsed = Math.max(0, end - start)
  const percent = Math.max(0, Math.min(999, Math.round((elapsed / total) * 100)))
  const breached = end > due
  return {
    dueAt: new Date(due).toISOString(),
    completedAt: completedAt || null,
    percent,
    breached,
    state: status === 'On Hold' ? 'paused'
      : completedAt ? (breached ? 'breached' : 'met')
        : breached ? 'breached' : percent >= 80 ? 'warning' : 'on_track',
  }
}
async function addProjectActivity(db, { session, project, actor, kind = 'update', bodyText, metadata = {} }) {
  await db.query(
    `INSERT INTO project_activities(
       tenant_id,project_id,kind,body_text,actor_user_id,actor_person_id,actor_snapshot,metadata
     ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)`,
    [
      session.tenant_id,
      project.id,
      text(kind, 60) || 'update',
      text(bodyText, 20000),
      session.user_id,
      actor?.person?.id || null,
      JSON.stringify(actor?.snapshot || {}),
      JSON.stringify(metadata || {}),
    ],
  )
}

async function createDomainEvent(db, { tenantId, eventType, projectReference, actorUserId, payload = {} }) {
  const result = await db.query(
    `INSERT INTO domain_events(tenant_id,event_type,aggregate_type,aggregate_reference,actor_user_id,payload)
     VALUES($1,$2,'Project',$3,$4,$5::jsonb)
     RETURNING id`,
    [tenantId, eventType, projectReference, actorUserId || null, JSON.stringify(payload || {})],
  )
  return result.rows[0].id
}

async function notifyPerson(db, { tenantId, person, eventId, eventType, projectReference, title, body, metadata = {} }) {
  if (!person?.user_id) return
  await db.query(
    `SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,'Project',$7,$8::jsonb)`,
    [
      tenantId,
      person.user_id,
      eventId,
      eventType,
      text(title, 240),
      text(body, 2000),
      projectReference,
      JSON.stringify(metadata || {}),
    ],
  )
}

async function notifyUniquePeople(db, { tenantId, people, eventId, eventType, projectReference, title, body, metadata }) {
  const seen = new Set()
  for (const person of people.filter(Boolean)) {
    if (!person.user_id || seen.has(person.user_id)) continue
    seen.add(person.user_id)
    await notifyPerson(db, { tenantId, person, eventId, eventType, projectReference, title, body, metadata })
  }
}

async function nextChildKey(db, table, project, suffix) {
  const result = await db.query(
    `SELECT count(*)::int + 1 AS value FROM ${table} WHERE project_id=$1`,
    [project.id],
  )
  return `${project.reference}-${suffix}${String(result.rows[0].value).padStart(2, '0')}`
}

async function payloadForProject(db, row) {
  const [members, milestones, tasks, risks, activities] = await Promise.all([
    db.query(
      `SELECT p.external_key,p.name,p.email,pm.role
       FROM project_members pm JOIN organisation_people p ON p.id=pm.person_id
       WHERE pm.project_id=$1 ORDER BY pm.created_at,p.name`,
      [row.id],
    ),
    db.query(
      `SELECT * FROM project_milestones WHERE project_id=$1 ORDER BY due_date NULLS LAST,created_at`,
      [row.id],
    ),
    db.query(
      `SELECT pt.*,pm.external_key milestone_external_key
       FROM project_tasks pt
       LEFT JOIN project_milestones pm ON pm.id=pt.milestone_id
       WHERE pt.project_id=$1 ORDER BY pt.created_at`,
      [row.id],
    ),
    db.query(
      `SELECT * FROM project_risks WHERE project_id=$1 ORDER BY
       CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
       created_at`,
      [row.id],
    ),
    db.query(
      `SELECT * FROM project_activities WHERE project_id=$1 ORDER BY created_at DESC,id DESC LIMIT 250`,
      [row.id],
    ),
  ])

  const owner = object(row.owner_snapshot)
  const sponsor = object(row.sponsor_snapshot)
  const team = object(row.team_snapshot)
  return {
    id: row.reference,
    version: Number(row.version || 1),
    name: row.name,
    description: row.description,
    summary: row.summary,
    status: row.status,
    health: row.health,
    priority: row.priority,
    ownerId: owner.externalKey || '',
    owner: owner.name || 'Unassigned',
    ownerEmail: owner.email || '',
    sponsorId: sponsor.externalKey || '',
    sponsor: sponsor.name || 'Unassigned',
    team: team.name || '',
    teamId: team.externalKey || '',
    startDate: dateText(row.start_date),
    targetDate: dateText(row.target_date),
    completedAt: row.completed_at,
    sla: deadlineMetric(row.start_date, row.target_date, row.completed_at, row.status),
    memberIds: members.rows.map((item) => item.external_key),
    members: members.rows.map((item) => ({ id: item.external_key, name: item.name, email: item.email, role: item.role })),
    linkedRecords: [...new Set(tasks.rows.map((task) => task.linked_record).filter(Boolean))],
    milestones: milestones.rows.map((milestone) => ({
      id: milestone.external_key,
      title: milestone.title,
      dueDate: dateText(milestone.due_date),
      status: milestone.status,
      completedAt: milestone.completed_at,
      sla: deadlineMetric(row.start_date, milestone.due_date, milestone.completed_at, milestone.status === 'Complete' ? 'Complete' : row.status),
    })),
    tasks: tasks.rows.map((task) => {
      const assignee = object(task.assignee_snapshot)
      return {
        id: task.external_key,
        title: task.title,
        status: task.status,
        priority: task.priority,
        assigneeId: assignee.externalKey || '',
        assignee: assignee.name || 'Unassigned',
        assigneeEmail: assignee.email || '',
        startDate: dateText(task.start_date),
        dueDate: dateText(task.due_date),
        plannedHours: Number(task.planned_hours || 0),
        milestoneId: task.milestone_external_key || '',
        dependsOn: task.dependencies || [],
        linkedRecord: task.linked_record || '',
        completedAt: task.completed_at,
        sla: deadlineMetric(task.start_date || row.start_date, task.due_date, task.completed_at, task.status === 'Done' ? 'Complete' : task.status === 'Blocked' ? 'On Hold' : row.status),
      }
    }),
    risks: risks.rows.map((risk) => {
      const ownerSnapshot = object(risk.owner_snapshot)
      return {
        id: risk.external_key,
        kind: risk.kind,
        title: risk.title,
        severity: risk.severity,
        status: risk.status,
        response: risk.response,
        ownerId: ownerSnapshot.externalKey || '',
        owner: ownerSnapshot.name || 'Unassigned',
        closedAt: risk.closed_at,
      }
    }),
    activity: activities.rows.map((activity) => ({
      id: activity.id,
      actor: object(activity.actor_snapshot).name || 'Hi5Central User',
      action: activity.body_text,
      kind: activity.kind,
      meta: activity.created_at,
      createdAt: activity.created_at,
      metadata: activity.metadata || {},
    })),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

async function personFromSnapshotOrId(db, tenantId, personId, snapshot) {
  if (personId) {
    const result = await db.query(
      'SELECT * FROM organisation_people WHERE tenant_id=$1 AND id=$2 LIMIT 1',
      [tenantId, personId],
    )
    if (result.rowCount) return result.rows[0]
  }
  const snap = object(snapshot)
  return snap.externalKey ? activeTechnician(db, tenantId, snap.externalKey) : null
}

async function touchProject(db, projectId) {
  await db.query('UPDATE projects SET version=version+1,updated_at=now() WHERE id=$1', [projectId])
}

export function registerProjectRoutes(app) {
  app.get('/api/v1/projects', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.view')
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT * FROM projects WHERE tenant_id=$1 ORDER BY updated_at DESC,created_at DESC`,
      [auth.session.tenant_id],
    )
    const items = []
    for (const row of result.rows) items.push(await payloadForProject(pool, row))
    return c.json({ items })
  })

  app.get('/api/v1/projects/calendar', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.view')
    if (auth.error) return auth.error
    const projects = await pool.query(
      `SELECT id,reference,name,status,start_date,target_date FROM projects
       WHERE tenant_id=$1 AND status<>'Cancelled' ORDER BY start_date,target_date`,
      [auth.session.tenant_id],
    )
    const milestones = await pool.query(
      `SELECT p.reference,p.name,m.external_key,m.title,m.due_date,m.status
       FROM project_milestones m JOIN projects p ON p.id=m.project_id
       WHERE m.tenant_id=$1 AND p.status<>'Cancelled' AND m.due_date IS NOT NULL`,
      [auth.session.tenant_id],
    )
    const tasks = await pool.query(
      `SELECT p.reference,p.name,t.external_key,t.title,t.due_date,t.status,op.external_key assignee_id,op.name assignee_name
       FROM project_tasks t JOIN projects p ON p.id=t.project_id
       LEFT JOIN organisation_people op ON op.id=t.assignee_person_id
       WHERE t.tenant_id=$1 AND p.status<>'Cancelled' AND t.due_date IS NOT NULL`,
      [auth.session.tenant_id],
    )
    const items = []
    for (const project of projects.rows) {
      if (project.start_date) items.push({ id: `${project.reference}-start`, projectId: project.reference, type: 'project-start', title: `${project.reference} · ${project.name} starts`, date: project.start_date, status: project.status })
      if (project.target_date) items.push({ id: `${project.reference}-target`, projectId: project.reference, type: 'project-target', title: `${project.reference} · ${project.name} target`, date: project.target_date, status: project.status })
    }
    for (const milestone of milestones.rows) items.push({ id: milestone.external_key, projectId: milestone.reference, type: 'project-milestone', title: milestone.title, date: milestone.due_date, status: milestone.status })
    for (const task of tasks.rows) items.push({ id: task.external_key, projectId: task.reference, type: 'project-task', title: task.title, date: task.due_date, status: task.status, assigneeId: task.assignee_id || '', assignee: task.assignee_name || 'Unassigned' })
    return c.json({ items })
  })

  app.post('/api/v1/projects', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const name = text(body?.name, 180)
    if (!name) return c.json({ error: 'Project name is required.' }, 400)
    const priority = priorities.has(body?.priority) ? body.priority : 'Medium'
    const startDate = dateValue(body?.startDate) || new Date().toISOString().slice(0, 10)

    const created = await withTransaction(async (client) => {
      const configuration = await configurationFor(client, auth.session.tenant_id)
      const targetDate = dateValue(body?.targetDate) || plusDays(startDate, projectTargetDays(priority, configuration))
      if (targetDate < startDate) return { invalidDates: true }

      const owner = body?.ownerId ? await activeTechnician(client, auth.session.tenant_id, body.ownerId) : null
      if (body?.ownerId && !owner) return { invalidOwner: true }
      const sponsor = body?.sponsorId
        ? await activeTechnician(client, auth.session.tenant_id, body.sponsorId)
        : owner
      if (body?.sponsorId && !sponsor) return { invalidSponsor: true }
      const team = body?.team || body?.teamId
        ? await activeTeam(client, auth.session.tenant_id, body.teamId || body.team)
        : null
      if ((body?.team || body?.teamId) && !team) return { invalidTeam: true }

      const actor = await actorContext(client, auth.session)
      const reference = await nextProjectReference(client, auth.session.tenant_id)
      const inserted = await client.query(
        `INSERT INTO projects(
           tenant_id,reference,name,description,summary,status,health,priority,
           owner_person_id,owner_snapshot,sponsor_person_id,sponsor_snapshot,
           team_id,team_snapshot,start_date,target_date,created_by_user_id,created_by_snapshot
         ) VALUES($1,$2,$3,$4,$5,'Planned','On Track',$6,$7,$8::jsonb,$9,$10::jsonb,$11,$12::jsonb,$13,$14,$15,$16::jsonb)
         RETURNING *`,
        [
          auth.session.tenant_id,
          reference,
          name,
          text(body?.description, 12000),
          text(body?.summary, 12000) || 'Project created. Confirm the delivery plan, milestones and first tasks.',
          priority,
          owner?.id || null,
          JSON.stringify(personSnapshot(owner)),
          sponsor?.id || null,
          JSON.stringify(personSnapshot(sponsor)),
          team?.id || null,
          JSON.stringify(teamSnapshot(team)),
          startDate,
          targetDate,
          auth.session.user_id,
          JSON.stringify(actor.snapshot),
        ],
      )
      const project = inserted.rows[0]

      for (const person of [owner, sponsor].filter(Boolean)) {
        await client.query(
          `INSERT INTO project_members(tenant_id,project_id,person_id,role)
           VALUES($1,$2,$3,$4)
           ON CONFLICT(project_id,person_id) DO UPDATE SET role=EXCLUDED.role`,
          [auth.session.tenant_id, project.id, person.id, person.id === owner?.id ? 'Owner' : 'Sponsor'],
        )
      }

      const milestoneKey = `${reference}-MS01`
      await client.query(
        `INSERT INTO project_milestones(tenant_id,project_id,external_key,title,due_date,status)
         VALUES($1,$2,$3,'Delivery complete',$4,'Planned')`,
        [auth.session.tenant_id, project.id, milestoneKey, targetDate],
      )
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'created',
        bodyText: 'created the project',
        metadata: { event: 'project.created' },
      })

      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'project.created',
        projectReference: reference,
        actorUserId: auth.session.user_id,
        payload: { name, owner: personSnapshot(owner), team: teamSnapshot(team), targetDate },
      })
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: [owner],
        eventId,
        eventType: 'project.created',
        projectReference: reference,
        title: `${reference} · ${name}`,
        body: `Project created with target date ${targetDate}.`,
        metadata: { action: 'created' },
      })
      return { project }
    })

    if (created.invalidDates) return c.json({ error: 'Target date must be on or after the project start date.' }, 400)
    if (created.invalidOwner) return c.json({ error: 'Choose an active technician as project owner.' }, 400)
    if (created.invalidSponsor) return c.json({ error: 'Choose an active technician as project sponsor.' }, 400)
    if (created.invalidTeam) return c.json({ error: 'Choose an active project team.' }, 400)
    return c.json(await payloadForProject(pool, created.project), 201)
  })

  app.get('/api/v1/projects/:reference', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.view')
    if (auth.error) return auth.error
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    if (!project) return c.json({ error: 'Project not found.' }, 404)
    return c.json(await payloadForProject(pool, project))
  })

  app.patch('/api/v1/projects/:reference', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const result = await withTransaction(async (client) => {
      const current = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!current) return { notFound: true }
      const actor = await actorContext(client, auth.session)

      const nextStatus = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : current.status
      const nextHealth = Object.prototype.hasOwnProperty.call(body, 'health') ? body.health : current.health
      const nextPriority = Object.prototype.hasOwnProperty.call(body, 'priority') ? body.priority : current.priority
      if (!projectStatuses.has(nextStatus)) return { invalidStatus: true }
      if (!projectHealth.has(nextHealth)) return { invalidHealth: true }
      if (!priorities.has(nextPriority)) return { invalidPriority: true }

      let owner = await personFromSnapshotOrId(client, auth.session.tenant_id, current.owner_person_id, current.owner_snapshot)
      if (Object.prototype.hasOwnProperty.call(body, 'ownerId')) {
        owner = body.ownerId ? await activeTechnician(client, auth.session.tenant_id, body.ownerId) : null
        if (body.ownerId && !owner) return { invalidOwner: true }
      }
      let sponsor = await personFromSnapshotOrId(client, auth.session.tenant_id, current.sponsor_person_id, current.sponsor_snapshot)
      if (Object.prototype.hasOwnProperty.call(body, 'sponsorId')) {
        sponsor = body.sponsorId ? await activeTechnician(client, auth.session.tenant_id, body.sponsorId) : null
        if (body.sponsorId && !sponsor) return { invalidSponsor: true }
      }
      let team = current.team_id
        ? (await client.query('SELECT * FROM organisation_teams WHERE tenant_id=$1 AND id=$2 LIMIT 1', [auth.session.tenant_id, current.team_id])).rows[0]
        : null
      if (Object.prototype.hasOwnProperty.call(body, 'team') || Object.prototype.hasOwnProperty.call(body, 'teamId')) {
        const value = body.teamId || body.team
        team = value ? await activeTeam(client, auth.session.tenant_id, value) : null
        if (value && !team) return { invalidTeam: true }
      }

      const startDate = Object.prototype.hasOwnProperty.call(body, 'startDate') ? dateValue(body.startDate) : dateText(current.start_date)
      const targetDate = Object.prototype.hasOwnProperty.call(body, 'targetDate') ? dateValue(body.targetDate) : dateText(current.target_date)
      if (startDate && targetDate && targetDate < startDate) return { invalidDates: true }

      const name = Object.prototype.hasOwnProperty.call(body, 'name') ? text(body.name, 180) : current.name
      if (!name) return { invalidName: true }
      const statusChanged = nextStatus !== current.status
      const ownerChanged = (owner?.id || null) !== (current.owner_person_id || null)
      const completedAt = nextStatus === 'Complete'
        ? (current.completed_at || new Date())
        : current.status === 'Complete' && nextStatus !== 'Complete' ? null : current.completed_at

      const updated = await client.query(
        `UPDATE projects SET
           name=$2,description=$3,summary=$4,status=$5,health=$6,priority=$7,
           owner_person_id=$8,owner_snapshot=$9::jsonb,
           sponsor_person_id=$10,sponsor_snapshot=$11::jsonb,
           team_id=$12,team_snapshot=$13::jsonb,start_date=$14,target_date=$15,
           completed_at=$16,version=version+1,updated_at=now()
         WHERE id=$1 RETURNING *`,
        [
          current.id,
          name,
          Object.prototype.hasOwnProperty.call(body, 'description') ? text(body.description, 12000) : current.description,
          Object.prototype.hasOwnProperty.call(body, 'summary') ? text(body.summary, 12000) : current.summary,
          nextStatus,
          nextHealth,
          nextPriority,
          owner?.id || null,
          JSON.stringify(personSnapshot(owner)),
          sponsor?.id || null,
          JSON.stringify(personSnapshot(sponsor)),
          team?.id || null,
          JSON.stringify(teamSnapshot(team)),
          startDate,
          targetDate,
          completedAt,
        ],
      )
      const project = updated.rows[0]
      for (const person of [owner, sponsor].filter(Boolean)) {
        await client.query(
          `INSERT INTO project_members(tenant_id,project_id,person_id,role)
           VALUES($1,$2,$3,$4)
           ON CONFLICT(project_id,person_id) DO UPDATE SET role=EXCLUDED.role`,
          [auth.session.tenant_id, project.id, person.id, person.id === owner?.id ? 'Owner' : 'Sponsor'],
        )
      }

      const changes = []
      if (ownerChanged) changes.push(`owner → ${owner?.name || 'Unassigned'}`)
      if (statusChanged) changes.push(`status ${current.status} → ${nextStatus}`)
      if (nextHealth !== current.health) changes.push(`health ${current.health} → ${nextHealth}`)
      if (nextPriority !== current.priority) changes.push(`priority ${current.priority} → ${nextPriority}`)
      if (String(targetDate || '') !== String(current.target_date || '')) changes.push(`target → ${targetDate || 'None'}`)
      await addProjectActivity(client, {
        session: auth.session,
        project,
        actor,
        kind: ownerChanged ? 'assignment' : statusChanged ? 'status' : 'update',
        bodyText: changes.length ? changes.join(', ') : 'updated the project',
        metadata: { event: ownerChanged ? 'project.assigned' : statusChanged ? 'project.status_changed' : 'project.updated', changes },
      })
      const eventType = ownerChanged ? 'project.assigned' : statusChanged ? 'project.status_changed' : 'project.updated'
      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType,
        projectReference: project.reference,
        actorUserId: auth.session.user_id,
        payload: { changes, owner: personSnapshot(owner), status: nextStatus },
      })
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: ownerChanged ? [owner] : [owner, sponsor],
        eventId,
        eventType,
        projectReference: project.reference,
        title: `${project.reference} · ${project.name}`,
        body: changes.length ? changes.join(', ') : 'Project updated.',
        metadata: { changes },
      })
      return { project }
    })

    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.invalidStatus) return c.json({ error: 'Unsupported project status.' }, 400)
    if (result.invalidHealth) return c.json({ error: 'Unsupported project health.' }, 400)
    if (result.invalidPriority) return c.json({ error: 'Unsupported project priority.' }, 400)
    if (result.invalidOwner) return c.json({ error: 'Choose an active technician as project owner.' }, 400)
    if (result.invalidSponsor) return c.json({ error: 'Choose an active technician as project sponsor.' }, 400)
    if (result.invalidTeam) return c.json({ error: 'Choose an active project team.' }, 400)
    if (result.invalidDates) return c.json({ error: 'Target date must be on or after the project start date.' }, 400)
    if (result.invalidName) return c.json({ error: 'Project name is required.' }, 400)
    return c.json(await payloadForProject(pool, result.project))
  })

  app.post('/api/v1/projects/:reference/tasks', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const title = text(body?.title, 240)
    if (!title) return c.json({ error: 'Task title is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const priority = priorities.has(body?.priority) ? body.priority : 'Medium'
      const status = taskStatuses.has(body?.status) ? body.status : 'To Do'
      const assignee = body?.assigneeId ? await activeTechnician(client, auth.session.tenant_id, body.assigneeId) : null
      if (body?.assigneeId && !assignee) return { invalidAssignee: true }
      let milestone = null
      if (body?.milestoneId) {
        const milestoneResult = await client.query(
          'SELECT * FROM project_milestones WHERE project_id=$1 AND external_key=$2 LIMIT 1',
          [project.id, text(body.milestoneId, 100)],
        )
        milestone = milestoneResult.rows[0] || null
        if (!milestone) return { invalidMilestone: true }
      }
      const startDate = dateValue(body?.startDate) || project.start_date
      const dueDate = dateValue(body?.dueDate) || project.target_date
      if (startDate && dueDate && String(dueDate) < String(startDate)) return { invalidDates: true }
      const actor = await actorContext(client, auth.session)
      const externalKey = await nextChildKey(client, 'project_tasks', project, 'T')
      const inserted = await client.query(
        `INSERT INTO project_tasks(
           tenant_id,project_id,external_key,title,status,priority,assignee_person_id,assignee_snapshot,
           start_date,due_date,planned_hours,milestone_id,dependencies,linked_record,completed_at,created_by_user_id
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13::text[],$14,$15,$16)
         RETURNING *`,
        [
          auth.session.tenant_id,
          project.id,
          externalKey,
          title,
          status,
          priority,
          assignee?.id || null,
          JSON.stringify(personSnapshot(assignee)),
          startDate,
          dueDate,
          Math.max(0, Number(body?.plannedHours || 0)),
          milestone?.id || null,
          array(body?.dependsOn).map((item) => text(item, 100)).filter(Boolean),
          text(body?.linkedRecord, 120),
          status === 'Done' ? new Date() : null,
          auth.session.user_id,
        ],
      )
      if (assignee) {
        await client.query(
          `INSERT INTO project_members(tenant_id,project_id,person_id,role)
           VALUES($1,$2,$3,'Member') ON CONFLICT(project_id,person_id) DO NOTHING`,
          [auth.session.tenant_id, project.id, assignee.id],
        )
      }
      await touchProject(client, project.id)
      await addProjectActivity(client, {
        session: auth.session,
        project,
        actor,
        kind: 'task',
        bodyText: `added project task “${title}”${assignee ? ` assigned to ${assignee.name}` : ''}`,
        metadata: { event: 'project.task_created', taskId: externalKey },
      })
      const eventType = assignee ? 'project.task_assigned' : 'project.task_created'
      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType,
        projectReference: project.reference,
        actorUserId: auth.session.user_id,
        payload: { taskId: externalKey, title, assignee: personSnapshot(assignee), dueDate },
      })
      const owner = await personFromSnapshotOrId(client, auth.session.tenant_id, project.owner_person_id, project.owner_snapshot)
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: [assignee, owner],
        eventId,
        eventType,
        projectReference: project.reference,
        title: `${project.reference} · ${title}`,
        body: assignee ? `Task assigned to ${assignee.name}. Due ${dueDate || 'not set'}.` : 'New project task created.',
        metadata: { taskId: externalKey, dueDate },
      })
      return { projectId: project.id, task: inserted.rows[0] }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.invalidAssignee) return c.json({ error: 'Choose an active technician as task assignee.' }, 400)
    if (result.invalidMilestone) return c.json({ error: 'Choose a milestone from this project.' }, 400)
    if (result.invalidDates) return c.json({ error: 'Task due date must be on or after its start date.' }, 400)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project), 201)
  })

  app.patch('/api/v1/projects/:reference/tasks/:taskKey', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const taskResult = await client.query(
        'SELECT * FROM project_tasks WHERE project_id=$1 AND external_key=$2 LIMIT 1 FOR UPDATE',
        [project.id, text(c.req.param('taskKey'), 100)],
      )
      if (!taskResult.rowCount) return { taskNotFound: true }
      const current = taskResult.rows[0]
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : current.status
      const priority = Object.prototype.hasOwnProperty.call(body, 'priority') ? body.priority : current.priority
      if (!taskStatuses.has(status)) return { invalidStatus: true }
      if (!priorities.has(priority)) return { invalidPriority: true }

      let assignee = await personFromSnapshotOrId(client, auth.session.tenant_id, current.assignee_person_id, current.assignee_snapshot)
      if (Object.prototype.hasOwnProperty.call(body, 'assigneeId')) {
        assignee = body.assigneeId ? await activeTechnician(client, auth.session.tenant_id, body.assigneeId) : null
        if (body.assigneeId && !assignee) return { invalidAssignee: true }
      }
      let milestoneId = current.milestone_id
      if (Object.prototype.hasOwnProperty.call(body, 'milestoneId')) {
        milestoneId = null
        if (body.milestoneId) {
          const milestoneResult = await client.query(
            'SELECT id FROM project_milestones WHERE project_id=$1 AND external_key=$2 LIMIT 1',
            [project.id, text(body.milestoneId, 100)],
          )
          if (!milestoneResult.rowCount) return { invalidMilestone: true }
          milestoneId = milestoneResult.rows[0].id
        }
      }
      const startDate = Object.prototype.hasOwnProperty.call(body, 'startDate') ? dateValue(body.startDate) : dateText(current.start_date)
      const dueDate = Object.prototype.hasOwnProperty.call(body, 'dueDate') ? dateValue(body.dueDate) : dateText(current.due_date)
      if (startDate && dueDate && dueDate < startDate) return { invalidDates: true }

      const assigneeChanged = (assignee?.id || null) !== (current.assignee_person_id || null)
      const statusChanged = status !== current.status
      const updated = await client.query(
        `UPDATE project_tasks SET
           title=$2,status=$3,priority=$4,assignee_person_id=$5,assignee_snapshot=$6::jsonb,
           start_date=$7,due_date=$8,planned_hours=$9,milestone_id=$10,dependencies=$11::text[],
           linked_record=$12,completed_at=$13,updated_at=now()
         WHERE id=$1 RETURNING *`,
        [
          current.id,
          Object.prototype.hasOwnProperty.call(body, 'title') ? text(body.title, 240) : current.title,
          status,
          priority,
          assignee?.id || null,
          JSON.stringify(personSnapshot(assignee)),
          startDate,
          dueDate,
          Object.prototype.hasOwnProperty.call(body, 'plannedHours') ? Math.max(0, Number(body.plannedHours || 0)) : current.planned_hours,
          milestoneId,
          Object.prototype.hasOwnProperty.call(body, 'dependsOn') ? array(body.dependsOn).map((item) => text(item, 100)).filter(Boolean) : current.dependencies,
          Object.prototype.hasOwnProperty.call(body, 'linkedRecord') ? text(body.linkedRecord, 120) : current.linked_record,
          status === 'Done' ? (current.completed_at || new Date()) : current.status === 'Done' && status !== 'Done' ? null : current.completed_at,
        ],
      )
      if (assignee) {
        await client.query(
          `INSERT INTO project_members(tenant_id,project_id,person_id,role)
           VALUES($1,$2,$3,'Member') ON CONFLICT(project_id,person_id) DO NOTHING`,
          [auth.session.tenant_id, project.id, assignee.id],
        )
      }
      await touchProject(client, project.id)
      const actor = await actorContext(client, auth.session)
      const changes = []
      if (assigneeChanged) changes.push(`assignee → ${assignee?.name || 'Unassigned'}`)
      if (statusChanged) changes.push(`status ${current.status} → ${status}`)
      if (String(dueDate || '') !== String(current.due_date || '')) changes.push(`due → ${dueDate || 'None'}`)
      await addProjectActivity(client, {
        session: auth.session,
        project,
        actor,
        kind: 'task',
        bodyText: `updated “${updated.rows[0].title}”${changes.length ? `: ${changes.join(', ')}` : ''}`,
        metadata: { event: assigneeChanged ? 'project.task_assigned' : statusChanged ? 'project.task_status_changed' : 'project.task_updated', taskId: current.external_key, changes },
      })
      const eventType = assigneeChanged ? 'project.task_assigned' : statusChanged ? 'project.task_status_changed' : 'project.task_updated'
      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType,
        projectReference: project.reference,
        actorUserId: auth.session.user_id,
        payload: { taskId: current.external_key, changes, status, assignee: personSnapshot(assignee) },
      })
      const owner = await personFromSnapshotOrId(client, auth.session.tenant_id, project.owner_person_id, project.owner_snapshot)
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: [assignee, owner],
        eventId,
        eventType,
        projectReference: project.reference,
        title: `${project.reference} · ${updated.rows[0].title}`,
        body: changes.length ? changes.join(', ') : 'Project task updated.',
        metadata: { taskId: current.external_key, changes },
      })
      return { project }
    })

    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.taskNotFound) return c.json({ error: 'Project task not found.' }, 404)
    if (result.invalidStatus) return c.json({ error: 'Unsupported task status.' }, 400)
    if (result.invalidPriority) return c.json({ error: 'Unsupported task priority.' }, 400)
    if (result.invalidAssignee) return c.json({ error: 'Choose an active technician as task assignee.' }, 400)
    if (result.invalidMilestone) return c.json({ error: 'Choose a milestone from this project.' }, 400)
    if (result.invalidDates) return c.json({ error: 'Task due date must be on or after its start date.' }, 400)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project))
  })

  app.post('/api/v1/projects/:reference/milestones', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const title = text(body?.title, 240)
    if (!title) return c.json({ error: 'Milestone title is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const status = milestoneStatuses.has(body?.status) ? body.status : 'Planned'
      const dueDate = dateValue(body?.dueDate) || project.target_date
      const externalKey = await nextChildKey(client, 'project_milestones', project, 'MS')
      await client.query(
        `INSERT INTO project_milestones(tenant_id,project_id,external_key,title,due_date,status,completed_at)
         VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [auth.session.tenant_id, project.id, externalKey, title, dueDate, status, status === 'Complete' ? new Date() : null],
      )
      await touchProject(client, project.id)
      const actor = await actorContext(client, auth.session)
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'milestone',
        bodyText: `added milestone “${title}”`,
        metadata: { event: 'project.milestone_created', milestoneId: externalKey },
      })
      return { project }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project), 201)
  })

  app.patch('/api/v1/projects/:reference/milestones/:milestoneKey', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const milestoneResult = await client.query(
        'SELECT * FROM project_milestones WHERE project_id=$1 AND external_key=$2 LIMIT 1 FOR UPDATE',
        [project.id, text(c.req.param('milestoneKey'), 100)],
      )
      if (!milestoneResult.rowCount) return { milestoneNotFound: true }
      const current = milestoneResult.rows[0]
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : current.status
      if (!milestoneStatuses.has(status)) return { invalidStatus: true }
      const dueDate = Object.prototype.hasOwnProperty.call(body, 'dueDate') ? dateValue(body.dueDate) : current.due_date
      const title = Object.prototype.hasOwnProperty.call(body, 'title') ? text(body.title, 240) : current.title
      if (!title) return { invalidTitle: true }
      await client.query(
        `UPDATE project_milestones SET title=$2,due_date=$3,status=$4,
         completed_at=$5,updated_at=now() WHERE id=$1`,
        [
          current.id,
          title,
          dueDate,
          status,
          status === 'Complete' ? (current.completed_at || new Date()) : current.status === 'Complete' && status !== 'Complete' ? null : current.completed_at,
        ],
      )
      await touchProject(client, project.id)
      const actor = await actorContext(client, auth.session)
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'milestone',
        bodyText: `${status === 'Complete' && current.status !== 'Complete' ? 'completed' : status !== 'Complete' && current.status === 'Complete' ? 'reopened' : 'updated'} milestone “${title}”`,
        metadata: { event: 'project.milestone_updated', milestoneId: current.external_key, status },
      })
      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'project.milestone_updated',
        projectReference: project.reference,
        actorUserId: auth.session.user_id,
        payload: { milestoneId: current.external_key, title, status, dueDate },
      })
      const owner = await personFromSnapshotOrId(client, auth.session.tenant_id, project.owner_person_id, project.owner_snapshot)
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: [owner],
        eventId,
        eventType: 'project.milestone_updated',
        projectReference: project.reference,
        title: `${project.reference} · ${title}`,
        body: `Milestone is now ${status}.`,
        metadata: { milestoneId: current.external_key, status },
      })
      return { project }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.milestoneNotFound) return c.json({ error: 'Project milestone not found.' }, 404)
    if (result.invalidStatus) return c.json({ error: 'Unsupported milestone status.' }, 400)
    if (result.invalidTitle) return c.json({ error: 'Milestone title is required.' }, 400)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project))
  })

  app.post('/api/v1/projects/:reference/risks', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const title = text(body?.title, 240)
    if (!title) return c.json({ error: 'Risk or issue title is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const kind = riskKinds.has(body?.kind) ? body.kind : 'Risk'
      const severity = priorities.has(body?.severity) ? body.severity : 'Medium'
      const status = riskStatuses.has(body?.status) ? body.status : 'Open'
      const owner = body?.ownerId ? await activeTechnician(client, auth.session.tenant_id, body.ownerId) : null
      if (body?.ownerId && !owner) return { invalidOwner: true }
      const externalKey = await nextChildKey(client, 'project_risks', project, kind === 'Issue' ? 'I' : 'R')
      await client.query(
        `INSERT INTO project_risks(
           tenant_id,project_id,external_key,kind,title,severity,status,response,owner_person_id,owner_snapshot,closed_at
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
        [
          auth.session.tenant_id, project.id, externalKey, kind, title, severity, status,
          text(body?.response, 12000), owner?.id || null, JSON.stringify(personSnapshot(owner)),
          status === 'Closed' ? new Date() : null,
        ],
      )
      if (owner) {
        await client.query(
          `INSERT INTO project_members(tenant_id,project_id,person_id,role)
           VALUES($1,$2,$3,'Member') ON CONFLICT(project_id,person_id) DO NOTHING`,
          [auth.session.tenant_id, project.id, owner.id],
        )
      }
      await touchProject(client, project.id)
      const actor = await actorContext(client, auth.session)
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'risk',
        bodyText: `added ${kind.toLowerCase()} “${title}”`,
        metadata: { event: 'project.risk_created', riskId: externalKey, severity },
      })
      return { project }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.invalidOwner) return c.json({ error: 'Choose an active technician as owner.' }, 400)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project), 201)
  })

  app.patch('/api/v1/projects/:reference/risks/:riskKey', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const riskResult = await client.query(
        'SELECT * FROM project_risks WHERE project_id=$1 AND external_key=$2 LIMIT 1 FOR UPDATE',
        [project.id, text(c.req.param('riskKey'), 100)],
      )
      if (!riskResult.rowCount) return { riskNotFound: true }
      const current = riskResult.rows[0]
      const kind = Object.prototype.hasOwnProperty.call(body, 'kind') ? body.kind : current.kind
      const severity = Object.prototype.hasOwnProperty.call(body, 'severity') ? body.severity : current.severity
      const status = Object.prototype.hasOwnProperty.call(body, 'status') ? body.status : current.status
      if (!riskKinds.has(kind)) return { invalidKind: true }
      if (!priorities.has(severity)) return { invalidSeverity: true }
      if (!riskStatuses.has(status)) return { invalidStatus: true }
      let owner = await personFromSnapshotOrId(client, auth.session.tenant_id, current.owner_person_id, current.owner_snapshot)
      if (Object.prototype.hasOwnProperty.call(body, 'ownerId')) {
        owner = body.ownerId ? await activeTechnician(client, auth.session.tenant_id, body.ownerId) : null
        if (body.ownerId && !owner) return { invalidOwner: true }
      }
      const title = Object.prototype.hasOwnProperty.call(body, 'title') ? text(body.title, 240) : current.title
      if (!title) return { invalidTitle: true }
      await client.query(
        `UPDATE project_risks SET kind=$2,title=$3,severity=$4,status=$5,response=$6,
         owner_person_id=$7,owner_snapshot=$8::jsonb,closed_at=$9,updated_at=now()
         WHERE id=$1`,
        [
          current.id, kind, title, severity, status,
          Object.prototype.hasOwnProperty.call(body, 'response') ? text(body.response, 12000) : current.response,
          owner?.id || null, JSON.stringify(personSnapshot(owner)),
          status === 'Closed' ? (current.closed_at || new Date()) : current.status === 'Closed' && status !== 'Closed' ? null : current.closed_at,
        ],
      )
      await touchProject(client, project.id)
      const actor = await actorContext(client, auth.session)
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'risk',
        bodyText: `${status === 'Closed' && current.status !== 'Closed' ? 'closed' : 'updated'} ${kind.toLowerCase()} “${title}”`,
        metadata: { event: 'project.risk_updated', riskId: current.external_key, status, severity },
      })
      return { project }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    if (result.riskNotFound) return c.json({ error: 'Project risk or issue not found.' }, 404)
    if (result.invalidKind) return c.json({ error: 'Unsupported risk type.' }, 400)
    if (result.invalidSeverity) return c.json({ error: 'Unsupported risk severity.' }, 400)
    if (result.invalidStatus) return c.json({ error: 'Unsupported risk status.' }, 400)
    if (result.invalidOwner) return c.json({ error: 'Choose an active technician as owner.' }, 400)
    if (result.invalidTitle) return c.json({ error: 'Risk or issue title is required.' }, 400)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project))
  })

  app.post('/api/v1/projects/:reference/activity', async (c) => {
    const auth = await requireProjectPermission(c, 'projects.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const note = text(body?.text || body?.body, 20000)
    if (!note) return c.json({ error: 'Project update text is required.' }, 400)

    const result = await withTransaction(async (client) => {
      const project = await projectFor(client, auth.session.tenant_id, c.req.param('reference'), true)
      if (!project) return { notFound: true }
      const actor = await actorContext(client, auth.session)
      await addProjectActivity(client, {
        session: auth.session, project, actor, kind: 'update', bodyText: note,
        metadata: { event: 'project.update_added' },
      })
      await touchProject(client, project.id)
      const eventId = await createDomainEvent(client, {
        tenantId: auth.session.tenant_id,
        eventType: 'project.update_added',
        projectReference: project.reference,
        actorUserId: auth.session.user_id,
        payload: { text: note },
      })
      const owner = await personFromSnapshotOrId(client, auth.session.tenant_id, project.owner_person_id, project.owner_snapshot)
      const sponsor = await personFromSnapshotOrId(client, auth.session.tenant_id, project.sponsor_person_id, project.sponsor_snapshot)
      await notifyUniquePeople(client, {
        tenantId: auth.session.tenant_id,
        people: [owner, sponsor],
        eventId,
        eventType: 'project.update_added',
        projectReference: project.reference,
        title: `${project.reference} · project update`,
        body: note,
        metadata: { action: 'update_added' },
      })
      return { project }
    })
    if (result.notFound) return c.json({ error: 'Project not found.' }, 404)
    const project = await projectFor(pool, auth.session.tenant_id, c.req.param('reference'))
    return c.json(await payloadForProject(pool, project), 201)
  })
}