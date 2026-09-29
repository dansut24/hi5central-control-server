import { createHash, randomBytes } from 'node:crypto'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { attachAccess, effectiveAccessForUser } from './access.js'
import { deployment, portalRequestFromHeaders } from './deploymentConfig.js'
import { pool } from './db.js'
import { mfaRequiredFor, sessionNeedsMfa, sessionTtlSeconds } from './securityPolicy.js'

const COOKIE_NAME = 'hi5central_session'
const PORTAL_COOKIE_NAME = 'hi5central_portal_session'
const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 12

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex')
}

function portalRequest(c) {
  const origin = String(c.req.header('origin') || '').toLowerCase()
  const referer = String(c.req.header('referer') || '').toLowerCase()
  return portalRequestFromHeaders(origin, referer)
}

function requestCookieName(c) {
  return portalRequest(c) ? PORTAL_COOKIE_NAME : COOKIE_NAME
}

function cookieOptions(extra = {}) {
  const options = { secure: true, sameSite: 'Lax', path: '/', ...extra }
  if (deployment.cookieDomain) options.domain = deployment.cookieDomain
  return options
}

async function sessionPolicy(client, tenantId, userId) {
  const result = await client.query(
    `SELECT ts.onboarding_completed_at,ts.onboarding_data,ts.configuration,m.role AS tenant_role
     FROM tenant_settings ts
     JOIN tenant_memberships m ON m.tenant_id=ts.tenant_id AND m.user_id=$2
     WHERE ts.tenant_id=$1 LIMIT 1`,
    [tenantId, userId],
  )
  return result.rows[0] || null
}

async function hasPortalApprovalAssignment(client, tenantId, userId) {
  const result = await client.query(
    `SELECT 1
     FROM service_request_approvals a
     LEFT JOIN organisation_people p
       ON p.tenant_id = a.tenant_id
      AND p.id = a.approver_person_id
      AND p.active = true
     WHERE a.tenant_id = $1
       AND (a.approver_user_id = $2 OR p.user_id = $2)
     LIMIT 1`,
    [tenantId, userId],
  )
  return result.rowCount > 0
}

export async function createSession(client, {
  tenantId,
  userId,
  mfaVerified = false,
  ttlSeconds = null,
  surface = 'workspace',
}) {
  const policy = await sessionPolicy(client, tenantId, userId)
  if (!policy) throw new Error('Could not resolve the tenant session policy.')

  const access = await effectiveAccessForUser(client, tenantId, userId, policy.tenant_role)
  const approvalPortalAccess = surface === 'portal' && !access.portalAccess
    ? await hasPortalApprovalAssignment(client, tenantId, userId)
    : false
  const accessAllowed = surface === 'portal' ? (access.portalAccess || approvalPortalAccess) : access.workspaceAccess
  if (!accessAllowed) {
    const error = new Error(surface === 'portal'
      ? 'Your Hi5Central roles do not include access to the requester portal.'
      : 'Your Hi5Central roles do not include access to this workspace. Use the requester portal instead.')
    error.code = 'ACCESS_DENIED'
    error.status = 403
    throw error
  }

  if (mfaRequiredFor(policy) && !mfaVerified) {
    const error = new Error('Multi-factor authentication is required for this account.')
    error.code = 'MFA_REQUIRED'
    error.status = 403
    throw error
  }

  const resolvedTtl = Math.max(60 * 60, Math.min(60 * 60 * 24, Number(ttlSeconds || sessionTtlSeconds(policy) || DEFAULT_SESSION_TTL_SECONDS)))
  const token = randomBytes(32).toString('base64url')
  const tokenHash = hashToken(token)
  await client.query(
    `INSERT INTO auth_sessions (tenant_id,user_id,token_hash,expires_at,mfa_verified_at)
     VALUES ($1,$2,$3,now()+make_interval(secs=>$4::int),CASE WHEN $5 THEN now() ELSE NULL END)`,
    [tenantId, userId, tokenHash, resolvedTtl, Boolean(mfaVerified)],
  )
  return token
}

function writeCookie(c, name, token, maxAge) {
  const resolvedMaxAge = Math.max(60 * 60, Math.min(60 * 60 * 24, Number(maxAge || DEFAULT_SESSION_TTL_SECONDS)))
  setCookie(c, name, token, cookieOptions({ httpOnly: true, maxAge: resolvedMaxAge }))
}

function deleteNamedCookie(c, name) { deleteCookie(c, name, cookieOptions()) }

export function setSessionCookie(c, token, maxAge = DEFAULT_SESSION_TTL_SECONDS) { writeCookie(c, COOKIE_NAME, token, maxAge) }
export function setPortalSessionCookie(c, token, maxAge = DEFAULT_SESSION_TTL_SECONDS) { writeCookie(c, PORTAL_COOKIE_NAME, token, maxAge) }
export function clearSessionCookie(c) { deleteNamedCookie(c, COOKIE_NAME) }
export function clearPortalSessionCookie(c) { deleteNamedCookie(c, PORTAL_COOKIE_NAME) }

export async function resolveSession(c) {
  const token = getCookie(c, requestCookieName(c))
  if (!token) return null
  const tokenHash = hashToken(token)
  const result = await pool.query(
    `SELECT s.id AS session_id,s.tenant_id,s.user_id,s.expires_at,s.created_at AS session_created_at,s.mfa_verified_at,
            t.slug,t.company_name,t.status AS tenant_status,u.email,u.name,m.role AS tenant_role,m.status AS membership_status,
            ts.modules,ts.onboarding_step,ts.onboarding_completed_at,ts.onboarding_data,ts.configuration,ts.tenant_url,ts.portal_url,ts.rmm_url,
            up.preferences AS user_preferences
     FROM auth_sessions s
     JOIN tenants t ON t.id=s.tenant_id
     JOIN users u ON u.id=s.user_id
     JOIN tenant_memberships m ON m.tenant_id=s.tenant_id AND m.user_id=s.user_id
     JOIN tenant_settings ts ON ts.tenant_id=s.tenant_id
     LEFT JOIN user_preferences up ON up.tenant_id=s.tenant_id AND up.user_id=s.user_id
     WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()
     LIMIT 1`,
    [tokenHash],
  )
  if (!result.rowCount) return null
  const session = result.rows[0]
  if (session.tenant_status !== 'active' || session.membership_status !== 'active') return null
  if (sessionNeedsMfa(session)) {
    pool.query('UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1', [session.session_id]).catch(() => {})
    return null
  }
  const surface = portalRequest(c) ? 'portal' : 'workspace'
  const access = await effectiveAccessForUser(pool, session.tenant_id, session.user_id, session.tenant_role)
  if (surface === 'portal' && !access.portalAccess && !await hasPortalApprovalAssignment(pool, session.tenant_id, session.user_id)) return null
  if (surface === 'workspace' && !access.workspaceAccess) return null
  const resolved = attachAccess(session, access, surface)
  pool.query('UPDATE auth_sessions SET last_seen_at=now() WHERE id=$1', [session.session_id]).catch(() => {})
  return resolved
}

export async function revokeCurrentSession(c) {
  const cookieName = requestCookieName(c)
  const token = getCookie(c, cookieName)
  if (token) await pool.query('UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1', [hashToken(token)])
  deleteNamedCookie(c, cookieName)
}

export function sessionPayload(session) {
  const configuration = session.configuration && Object.keys(session.configuration).length ? session.configuration : session.onboarding_data || {}
  const access = session.access || { roles: [], roleKeys: [], permissions: [], effectivePermissions: [], workspaceAccess: false, portalAccess: false }
  return {
    authenticated: true,
    user: {
      id: session.user_id,
      name: session.name,
      email: session.email,
      tenantRole: session.tenant_role,
      legacyTenantRole: session.legacy_tenant_role || session.tenant_role,
    },
    access: {
      roles: access.roles || [],
      roleKeys: access.roleKeys || [],
      permissions: access.permissions || [],
      effectivePermissions: access.effectivePermissions || [],
      workspaceAccess: Boolean(access.workspaceAccess),
      portalAccess: Boolean(access.portalAccess),
    },
    tenant: {
      id: session.tenant_id,
      slug: session.slug,
      companyName: session.company_name,
      tenantUrl: session.tenant_url,
      portalUrl: session.portal_url,
      rmmUrl: session.rmm_url,
      modules: session.modules || {},
    },
    onboarding: { step: session.onboarding_step, completedAt: session.onboarding_completed_at, data: session.onboarding_data || {} },
    security: { mfaVerified: Boolean(session.mfa_verified_at) },
    preferences: session.user_preferences || null,
    settings: configuration,
  }
}
