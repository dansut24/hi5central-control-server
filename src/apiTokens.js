import { createHash, randomBytes } from 'node:crypto'
import { expandedPermissions, hasPermission, permissionKeys } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { resolveSession } from './session.js'

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex')
}

function clean(value = '', max = 120) {
  return String(value ?? '').trim().slice(0, max)
}

async function requireTokenManagement(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (session.api_token_id) {
    return { error: c.json({ error: 'API tokens cannot create or manage other API tokens.' }, 403) }
  }
  if (!hasPermission(session.access, 'integrations.manage')) {
    return { error: c.json({ error: 'You do not have permission to manage API access.' }, 403) }
  }
  return { session }
}

function tokenRow(row) {
  return {
    id: row.id,
    name: row.name,
    prefix: row.token_prefix,
    scopes: Array.isArray(row.scopes) ? row.scopes : [],
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
  }
}

export function registerApiTokenRoutes(app) {
  app.get('/api/v1/integrations/api-tokens', async (c) => {
    const auth = await requireTokenManagement(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id,name,token_prefix,scopes,created_at,expires_at,last_used_at,revoked_at
       FROM api_tokens
       WHERE tenant_id=$1 AND user_id=$2
       ORDER BY revoked_at NULLS FIRST,created_at DESC`,
      [auth.session.tenant_id, auth.session.user_id],
    )
    return c.json({
      tokens: result.rows.map(tokenRow),
      availableScopes: expandedPermissions(auth.session.access),
    })
  })

  app.post('/api/v1/integrations/api-tokens', async (c) => {
    const auth = await requireTokenManagement(c)
    if (auth.error) return auth.error

    let body
    try { body = await c.req.json() } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const name = clean(body?.name)
    if (name.length < 2) return c.json({ error: 'Token name must be at least 2 characters.' }, 400)

    const allowed = new Set(expandedPermissions(auth.session.access))
    const requested = [...new Set((Array.isArray(body?.scopes) ? body.scopes : [])
      .map((item) => clean(item, 160))
      .filter(Boolean))]

    const unknown = requested.filter((scope) => !permissionKeys.has(scope))
    if (unknown.length) return c.json({ error: 'One or more API scopes are invalid.', invalidScopes: unknown }, 400)

    const denied = requested.filter((scope) => !allowed.has(scope))
    if (denied.length) {
      return c.json({
        error: 'An API token cannot be granted permissions the issuing user does not currently have.',
        deniedScopes: denied,
      }, 403)
    }

    const scopes = requested.length ? requested : [...allowed]
    if (allowed.has('workspace.access') && !scopes.includes('workspace.access')) scopes.unshift('workspace.access')
    if (!scopes.length) return c.json({ error: 'No API scopes are available for this account.' }, 400)

    const days = body?.expiresInDays === null
      ? null
      : Math.max(1, Math.min(3650, Number(body?.expiresInDays || 90)))
    if (days !== null && !Number.isFinite(days)) {
      return c.json({ error: 'expiresInDays must be a number between 1 and 3650, or null.' }, 400)
    }

    const prefixRandom = randomBytes(6).toString('hex')
    const token = `hi5_pat_${prefixRandom}_${randomBytes(32).toString('base64url')}`
    const prefix = `hi5_pat_${prefixRandom}`

    const result = await pool.query(
      `INSERT INTO api_tokens
         (tenant_id,user_id,name,token_prefix,token_hash,scopes,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6::text[],
         CASE WHEN $7::int IS NULL THEN NULL ELSE now()+make_interval(days=>$7::int) END)
       RETURNING id,name,token_prefix,scopes,created_at,expires_at,last_used_at,revoked_at`,
      [auth.session.tenant_id, auth.session.user_id, name, prefix, hashToken(token), scopes, days],
    )

    return c.json({
      ...tokenRow(result.rows[0]),
      token,
      warning: 'Store this token now. Hi5Central stores only its SHA-256 hash and cannot show it again.',
    }, 201)
  })

  app.delete('/api/v1/integrations/api-tokens/:tokenId', async (c) => {
    const auth = await requireTokenManagement(c)
    if (auth.error) return auth.error

    const result = await pool.query(
      `UPDATE api_tokens
       SET revoked_at=COALESCE(revoked_at,now()),updated_at=now()
       WHERE id=$1 AND tenant_id=$2 AND user_id=$3
       RETURNING id`,
      [c.req.param('tokenId'), auth.session.tenant_id, auth.session.user_id],
    )
    if (!result.rowCount) return c.json({ error: 'API token not found.' }, 404)
    return c.json({ revoked: true, id: result.rows[0].id })
  })
}
