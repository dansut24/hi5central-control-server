import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { resolveSession } from './session.js'

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  return { session }
}

async function profileSnapshot(session) {
  const personResult = await pool.query(
    `SELECT
       p.id,
       p.external_key,
       p.name,
       p.email,
       p.phone,
       p.job_title,
       p.availability,
       p.access_profile,
       p.directory_source,
       p.active,
       team.name AS primary_team,
       department.name AS department,
       site.name AS site,
       site.city AS city,
       manager.name AS manager_name,
       manager.email AS manager_email
     FROM organisation_people p
     LEFT JOIN organisation_teams team
       ON team.tenant_id=p.tenant_id AND team.id=p.primary_team_id
     LEFT JOIN organisation_departments department
       ON department.tenant_id=p.tenant_id AND department.id=p.department_id
     LEFT JOIN organisation_sites site
       ON site.tenant_id=p.tenant_id AND site.id=p.site_id
     LEFT JOIN organisation_people manager
       ON manager.tenant_id=p.tenant_id AND manager.id=p.manager_id
     WHERE p.tenant_id=$1
       AND (p.user_id=$2 OR (p.user_id IS NULL AND lower(p.email)=lower($3)))
     ORDER BY CASE WHEN p.user_id=$2 THEN 0 ELSE 1 END, p.updated_at DESC
     LIMIT 1`,
    [session.tenant_id, session.user_id, session.email],
  )

  const teamResult = personResult.rowCount
    ? await pool.query(
        `SELECT t.name,m.role,m.is_primary
         FROM organisation_team_memberships m
         JOIN organisation_teams t
           ON t.tenant_id=m.tenant_id AND t.id=m.team_id
         WHERE m.tenant_id=$1 AND m.person_id=$2
         ORDER BY m.is_primary DESC,t.name`,
        [session.tenant_id, personResult.rows[0].id],
      )
    : { rows: [] }

  const person = personResult.rows[0]
  return {
    user: {
      id: session.user_id,
      name: session.name,
      email: session.email,
      tenantRole: session.tenant_role,
    },
    access: {
      roles: session.access?.roles || [],
      roleKeys: session.access?.roleKeys || [],
      permissions: session.access?.permissions || [],
      effectivePermissions: session.access?.effectivePermissions || [],
      workspaceAccess: Boolean(session.access?.workspaceAccess),
      portalAccess: Boolean(session.access?.portalAccess),
    },
    tenant: {
      id: session.tenant_id,
      slug: session.slug,
      companyName: session.company_name,
      modules: session.modules || {},
    },
    security: {
      mfaVerified: Boolean(session.mfa_verified_at),
    },
    person: person ? {
      id: person.external_key,
      name: person.name,
      email: person.email,
      phone: person.phone,
      jobTitle: person.job_title,
      availability: person.availability,
      accessProfile: person.access_profile,
      directorySource: person.directory_source || {},
      active: Boolean(person.active),
      primaryTeam: person.primary_team || '',
      department: person.department || '',
      site: person.site || '',
      city: person.city || '',
      managerName: person.manager_name || '',
      managerEmail: person.manager_email || '',
    } : null,
    teams: teamResult.rows.map((row) => ({
      name: row.name,
      role: row.role,
      isPrimary: Boolean(row.is_primary),
    })),
  }
}

export function registerProfileRoutes(app) {
  app.get('/api/v1/profile', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    return c.json(await profileSnapshot(auth.session))
  })
}
