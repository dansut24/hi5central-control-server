import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import {
  compatibilityTenantRole,
  effectiveAccessForUser,
  hasPermission,
  permissionDefinitions,
  roleKeyFromName,
  validatePermissionSelection,
} from './access.js'
import { resolveSession } from './session.js'

function workspaceOrigin(c, session) { return originMatchesTenant(c.req.header('origin'), session.slug) }

async function requireAccess(c, permission) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!workspaceOrigin(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, permission)) return { error: c.json({ error: 'You do not have permission to perform this action.', permission }, 403) }
  return { session }
}

function roleJson(row) {
  return {
    id: row.id,
    key: row.role_key,
    name: row.name,
    description: row.description,
    permissions: Array.isArray(row.permissions) ? row.permissions : [],
    systemKey: row.system_key,
    isDefault: Boolean(row.is_default),
    isProtected: Boolean(row.is_protected),
    active: Boolean(row.active),
    assignedUsers: Number(row.assigned_users || 0),
  }
}

async function syncCompatibilityRole(db, tenantId, userId) {
  const membership = await db.query('SELECT role FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 LIMIT 1', [tenantId, userId])
  if (!membership.rowCount) return null
  const currentRole = membership.rows[0].role
  const access = await effectiveAccessForUser(db, tenantId, userId, currentRole)
  const compatibilityRole = compatibilityTenantRole(access, currentRole, 'workspace')
  if (compatibilityRole !== currentRole) {
    await db.query('UPDATE tenant_memberships SET role=$3 WHERE tenant_id=$1 AND user_id=$2', [tenantId, userId, compatibilityRole])
  }
  return { access, compatibilityRole }
}

async function rolesForTenant(tenantId) {
  const result = await pool.query(
    `SELECT r.*,(SELECT count(*) FROM access_user_roles ur WHERE ur.tenant_id=r.tenant_id AND ur.role_id=r.id)::int AS assigned_users
     FROM access_roles r WHERE r.tenant_id=$1 ORDER BY r.is_protected DESC,r.is_default DESC,r.name`,
    [tenantId],
  )
  return result.rows.map(roleJson)
}

async function usersForTenant(tenantId) {
  const result = await pool.query(
    `SELECT u.id AS user_id,u.name,u.email,m.role AS compatibility_role,m.status,
            p.external_key AS person_key,p.job_title,p.active AS person_active
     FROM tenant_memberships m
     JOIN users u ON u.id=m.user_id
     LEFT JOIN organisation_people p ON p.tenant_id=m.tenant_id AND p.user_id=m.user_id
     WHERE m.tenant_id=$1 ORDER BY u.name,u.email`,
    [tenantId],
  )
  const users = []
  for (const row of result.rows) {
    const access = await effectiveAccessForUser(pool, tenantId, row.user_id, row.compatibility_role)
    users.push({
      id: row.user_id,
      name: row.name,
      email: row.email,
      compatibilityRole: row.compatibility_role,
      status: row.status,
      personKey: row.person_key || '',
      jobTitle: row.job_title || '',
      personActive: row.person_active !== false,
      roles: access.roles,
      roleIds: access.roles.map((role) => role.id),
      effective: {
        permissions: access.effectivePermissions,
        workspaceAccess: access.workspaceAccess,
        portalAccess: access.portalAccess,
      },
    })
  }
  return users
}

export function registerAccessRoutes(app) {
  app.get('/api/v1/access/catalog', async (c) => {
    const auth = await requireAccess(c, 'access.roles.view')
    if (auth.error) return auth.error
    const groups = [...new Set(permissionDefinitions.map((item) => item.group))].map((group) => ({ group, permissions: permissionDefinitions.filter((item) => item.group === group) }))
    return c.json({ permissions: permissionDefinitions, groups })
  })

  app.get('/api/v1/access/roles', async (c) => {
    const auth = await requireAccess(c, 'access.roles.view')
    if (auth.error) return auth.error
    return c.json({ roles: await rolesForTenant(auth.session.tenant_id) })
  })

  app.post('/api/v1/access/roles', async (c) => {
    const auth = await requireAccess(c, 'access.roles.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const name = String(body?.name || '').trim().slice(0, 120)
    const description = String(body?.description || '').trim().slice(0, 1000)
    const requestedKey = roleKeyFromName(body?.key || name)
    const permissions = validatePermissionSelection(body?.permissions)
    if (name.length < 2) return c.json({ error: 'Role name must be at least 2 characters.' }, 400)
    if (!requestedKey) return c.json({ error: 'Choose a valid role name.' }, 400)
    if (!permissions.length) return c.json({ error: 'Select at least one permission.' }, 400)
    try {
      const result = await pool.query(
        `INSERT INTO access_roles (tenant_id,role_key,name,description,permissions,created_by_user_id)
         VALUES ($1,$2,$3,$4,$5::text[],$6) RETURNING *`,
        [auth.session.tenant_id, requestedKey, name, description, permissions, auth.session.user_id],
      )
      return c.json(roleJson(result.rows[0]), 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'A role with that name/key already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/v1/access/roles/:roleId', async (c) => {
    const auth = await requireAccess(c, 'access.roles.manage')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const current = await pool.query('SELECT * FROM access_roles WHERE tenant_id=$1 AND id=$2 LIMIT 1', [auth.session.tenant_id, c.req.param('roleId')])
    if (!current.rowCount) return c.json({ error: 'Role not found.' }, 404)
    const row = current.rows[0]
    if (row.is_protected) return c.json({ error: 'The Owner role is protected and cannot be changed.' }, 409)

    const name = body?.name === undefined ? row.name : String(body.name || '').trim().slice(0, 120)
    const description = body?.description === undefined ? row.description : String(body.description || '').trim().slice(0, 1000)
    const permissions = body?.permissions === undefined ? row.permissions : validatePermissionSelection(body.permissions)
    const active = body?.active === undefined ? row.active : Boolean(body.active)
    if (name.length < 2) return c.json({ error: 'Role name must be at least 2 characters.' }, 400)
    if (!permissions.length) return c.json({ error: 'Select at least one permission.' }, 400)

    const updated = await withTransaction(async (client) => {
      const result = await client.query(
        `UPDATE access_roles SET name=$3,description=$4,permissions=$5::text[],active=$6,updated_at=now()
         WHERE tenant_id=$1 AND id=$2 RETURNING *`,
        [auth.session.tenant_id, row.id, name, description, permissions, active],
      )
      const assigned = await client.query('SELECT user_id FROM access_user_roles WHERE tenant_id=$1 AND role_id=$2', [auth.session.tenant_id, row.id])
      for (const assignment of assigned.rows) await syncCompatibilityRole(client, auth.session.tenant_id, assignment.user_id)
      return result.rows[0]
    })
    return c.json(roleJson(updated))
  })

  app.get('/api/v1/access/users', async (c) => {
    const auth = await requireAccess(c, 'access.roles.view')
    if (auth.error) return auth.error
    return c.json({ users: await usersForTenant(auth.session.tenant_id) })
  })

  app.put('/api/v1/access/users/:userId/roles', async (c) => {
    const auth = await requireAccess(c, 'access.roles.assign')
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const roleIds = [...new Set((Array.isArray(body?.roleIds) ? body.roleIds : []).map(String).filter(Boolean))]
    if (!roleIds.length) return c.json({ error: 'Assign at least one role.' }, 400)

    const membership = await pool.query('SELECT role,status FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 LIMIT 1', [auth.session.tenant_id, c.req.param('userId')])
    if (!membership.rowCount) return c.json({ error: 'Tenant user not found.' }, 404)
    const validRoles = await pool.query('SELECT id,system_key,is_protected FROM access_roles WHERE tenant_id=$1 AND id=ANY($2::uuid[]) AND active=true', [auth.session.tenant_id, roleIds])
    if (validRoles.rowCount !== roleIds.length) return c.json({ error: 'One or more selected roles are unavailable.' }, 400)

    const currentOwner = await pool.query(
      `SELECT 1 FROM access_user_roles ur JOIN access_roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
       WHERE ur.tenant_id=$1 AND ur.user_id=$2 AND r.system_key='owner' LIMIT 1`,
      [auth.session.tenant_id, c.req.param('userId')],
    )
    const selectedOwner = validRoles.rows.some((role) => role.system_key === 'owner')
    if (currentOwner.rowCount && !selectedOwner) return c.json({ error: 'The tenant Owner role cannot be removed from the owner account.' }, 409)
    if (!currentOwner.rowCount && selectedOwner) return c.json({ error: 'The protected Owner role can only belong to the tenant owner.' }, 409)

    const effective = await withTransaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`access:${auth.session.tenant_id}:${c.req.param('userId')}`])
      await client.query('DELETE FROM access_user_roles WHERE tenant_id=$1 AND user_id=$2', [auth.session.tenant_id, c.req.param('userId')])
      for (const roleId of roleIds) {
        await client.query('INSERT INTO access_user_roles (tenant_id,user_id,role_id,assigned_by_user_id) VALUES ($1,$2,$3,$4)', [auth.session.tenant_id, c.req.param('userId'), roleId, auth.session.user_id])
      }
      const synced = await syncCompatibilityRole(client, auth.session.tenant_id, c.req.param('userId'))
      return synced.access
    })

    await pool.query(
      `UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()),revoked_reason=COALESCE(revoked_reason,'roles_changed')
       WHERE tenant_id=$1 AND user_id=$2 AND user_id<>$3 AND revoked_at IS NULL`,
      [auth.session.tenant_id, c.req.param('userId'), auth.session.user_id],
    ).catch(() => {})

    return c.json({
      userId: c.req.param('userId'),
      roleIds: effective.roles.map((role) => role.id),
      roles: effective.roles,
      effective: {
        permissions: effective.effectivePermissions,
        workspaceAccess: effective.workspaceAccess,
        portalAccess: effective.portalAccess,
      },
    })
  })
}
